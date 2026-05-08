/* lua_debugger_watch.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Watch panel: row model, drag-reorder tree, inline editor, presenter,
 * and the controller that orchestrates evaluation and persistence.
 */

#include "lua_debugger_watch.h"
#include "ui_lua_debugger_dialog.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMimeData>
#include <QMouseEvent>
#include <QPainter>
#include <QPalette>
#include <QSet>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStringList>
#include <QStyle>
#include <QStyleOptionViewItem>
#include <QTimer>
#include <QToolButton>
#include <QTreeView>
#include <QVariant>
#include <QVariantList>
#include <QVBoxLayout>
#include <QVector>

#include <algorithm>
#include <utility>
#include <glib.h>

#include "lua_debugger_code_editor.h"
#include "lua_debugger_dialog.h"
#include "lua_debugger_settings.h"
#include "lua_debugger_stack.h"
#include "lua_debugger_variables.h"
#include "widgets/collapsible_section.h"
#include <epan/wslua/wslua_debugger.h>

using namespace LuaDebuggerItems;
using namespace LuaDebuggerPath;

/* ===== watch_widgets ===== */

namespace
{

QStandardItem *itemFromTreeIndex(const QTreeView *tree, const QModelIndex &index)
{
    auto *m = qobject_cast<QStandardItemModel *>(tree ? tree->model() : nullptr);
    return m ? m->itemFromIndex(index) : nullptr;
}

} // namespace

bool LuaDbgWatchItemModel::dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column,
                                        const QModelIndex &parent)
{
    int c = column;
    QModelIndex p = parent;
    if (!p.isValid())
    {
        c = WatchColumn::Spec;
    }
    else if (!p.parent().isValid() && p.column() != WatchColumn::Spec)
    {
        p = p.sibling(p.row(), WatchColumn::Spec);
    }
    return QStandardItemModel::dropMimeData(data, action, row, c, p);
}

LuaDbgWatchTreeWidget::LuaDbgWatchTreeWidget(LuaDebuggerFontPolicy *fontPolicy, QWidget *parent)
    : QTreeView(parent), fontPolicy_(fontPolicy)
{
}

void LuaDbgWatchTreeWidget::startDrag(Qt::DropActions supportedActions)
{
    const QModelIndexList list = selectedIndexes();
    for (const QModelIndex &ix : list)
    {
        if (ix.isValid() && ix.parent().isValid())
        {
            return;
        }
    }
    QTreeView::startDrag(supportedActions);
}

void LuaDbgWatchTreeWidget::dragMoveEvent(QDragMoveEvent *event)
{
    QTreeView::dragMoveEvent(event);
    if (!event->isAccepted())
    {
        return;
    }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const QPoint pos = event->position().toPoint();
#else
    const QPoint pos = event->pos();
#endif
    const QModelIndex idx = indexAt(pos);
    if (idx.isValid() && idx.parent().isValid())
    {
        event->ignore();
    }
}

void LuaDbgWatchTreeWidget::dropEvent(QDropEvent *event)
{
    if (dragDropMode() == QAbstractItemView::InternalMove &&
        (event->source() != this || !(event->possibleActions() & Qt::MoveAction)))
    {
        return;
    }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const QPoint pos = event->position().toPoint();
#else
    const QPoint pos = event->pos();
#endif
    const QModelIndex raw = indexAt(pos);
    if (raw.isValid() && raw.parent().isValid())
    {
        event->ignore();
        return;
    }
    if (raw.isValid() && !raw.parent().isValid() && dropIndicatorPosition() == QAbstractItemView::OnItem)
    {
        if (auto *m = qobject_cast<QStandardItemModel *>(model()))
        {
            const int destRow = raw.row();
            if (m->dropMimeData(event->mimeData(), Qt::MoveAction, destRow, 0, QModelIndex()))
            {
                event->setDropAction(Qt::MoveAction);
                event->accept();
            }
            else
            {
                event->ignore();
            }
        }
        else
        {
            event->ignore();
        }
        stopAutoScroll();
        setState(QAbstractItemView::NoState);
        if (viewport())
        {
            viewport()->update();
        }
        if (event->isAccepted() && fontPolicy_)
        {
            LuaDebuggerFontPolicy *const p = fontPolicy_;
            QTimer::singleShot(0, this, [p]() { p->applyToPanels(); });
        }
        return;
    }
    QTreeView::dropEvent(event);
    if (event->isAccepted() && fontPolicy_)
    {
        LuaDebuggerFontPolicy *const p = fontPolicy_;
        QTimer::singleShot(0, this, [p]() { p->applyToPanels(); });
    }
}

void LuaDbgWatchTreeWidget::mouseDoubleClickEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton)
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        const QPoint pos = event->position().toPoint();
#else
        const QPoint pos = event->pos();
#endif
        if (!indexAt(pos).isValid())
        {
            emit requestNewRow();
            event->accept();
            return;
        }
    }
    QTreeView::mouseDoubleClickEvent(event);
}

void LuaDbgWatchTreeWidget::keyPressEvent(QKeyEvent *event)
{
    auto *m = qobject_cast<QStandardItemModel *>(model());
    if (!m)
    {
        QTreeView::keyPressEvent(event);
        return;
    }

    const QKeySequence pressed = luaDbgSeqFromKeyEvent(event);

    if (pressed.matches(kLuaDbgCtxWatchRemoveAll) == QKeySequence::ExactMatch && m->rowCount() > 0)
    {
        emit requestRemoveAll();
        event->accept();
        return;
    }

    const QModelIndex curIx = currentIndex();
    QStandardItem *const cur = m->itemFromIndex(curIx.sibling(curIx.row(), 0));
    if (cur && pressed.matches(kLuaDbgCtxWatchCopyValue) == QKeySequence::ExactMatch)
    {
        emit requestCopyValue(cur, curIx);
        event->accept();
        return;
    }

    /* All remaining shortcuts only apply to top-level watch rows; bail
     * before anything we'd otherwise consume on child rows. */
    if (!cur || cur->parent() != nullptr)
    {
        QTreeView::keyPressEvent(event);
        return;
    }

    if (pressed.matches(kLuaDbgCtxWatchDuplicate) == QKeySequence::ExactMatch)
    {
        emit requestDuplicateRoot(cur);
        event->accept();
        return;
    }

    if (pressed.matches(QKeySequence::Delete) == QKeySequence::ExactMatch ||
        pressed.matches(Qt::Key_Backspace) == QKeySequence::ExactMatch)
    {
        QList<QStandardItem *> del;
        if (selectionModel())
        {
            for (const QModelIndex &six : selectionModel()->selectedIndexes())
            {
                if (six.column() != WatchColumn::Spec)
                {
                    continue;
                }
                QStandardItem *it = m->itemFromIndex(six);
                if (it && it->parent() == nullptr)
                {
                    del.append(it);
                }
            }
        }
        if (del.isEmpty())
        {
            del.append(cur);
        }
        emit requestDeleteRows(del);
        event->accept();
        return;
    }

    if (pressed.matches(kLuaDbgCtxWatchEdit) == QKeySequence::ExactMatch)
    {
        const QModelIndex editIx = m->indexFromItem(cur);
        if (editIx.isValid())
        {
            edit(editIx);
        }
        event->accept();
        return;
    }

    QTreeView::keyPressEvent(event);
}

QWidget *LuaDbgVariablesReadOnlyDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                                       const QModelIndex &index) const
{
    Q_UNUSED(parent);
    Q_UNUSED(option);
    Q_UNUSED(index);
    return nullptr;
}

void LuaDbgWatchValueColumnDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                                           const QModelIndex &index) const
{
    QStyleOptionViewItem opt = option;
    initStyleOption(&opt, index);
    const QString full = index.data(Qt::DisplayRole).toString();
    const int avail = qMax(opt.rect.width() - 8, 1);
    opt.text = opt.fontMetrics.elidedText(full, Qt::ElideMiddle, avail);
    const QWidget *w = opt.widget;
    QStyle *style = w ? w->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, w);
}

QWidget *LuaDbgWatchValueColumnDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                                      const QModelIndex &index) const
{
    Q_UNUSED(parent);
    Q_UNUSED(option);
    Q_UNUSED(index);
    return nullptr;
}

LuaDbgWatchRootDelegate::LuaDbgWatchRootDelegate(QTreeView *tree, CommitFn commit, QObject *parent)
    : QStyledItemDelegate(parent), tree_(tree), commit_(std::move(commit))
{
}

QWidget *LuaDbgWatchRootDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                               const QModelIndex &index) const
{
    Q_UNUSED(option);
    if (!tree_ || !index.isValid() || index.column() != WatchColumn::Spec)
    {
        return nullptr;
    }
    QStandardItem *it = itemFromTreeIndex(tree_, index);
    if (!it || it->parent() != nullptr)
    {
        return nullptr;
    }
    QLineEdit *editor = new QLineEdit(parent);
    editor->setAttribute(Qt::WA_MacShowFocusRect, false);
    return editor;
}

void LuaDbgWatchRootDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    auto *le = qobject_cast<QLineEdit *>(editor);
    if (!le || !tree_)
    {
        return;
    }
    QStandardItem *it = itemFromTreeIndex(tree_, index);
    if (!it)
    {
        return;
    }
    QString s = it->data(WatchSpecRole).toString();
    if (s.isEmpty())
    {
        s = it->text();
    }
    le->setText(s);
}

void LuaDbgWatchRootDelegate::setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const
{
    Q_UNUSED(model);
    auto *le = qobject_cast<QLineEdit *>(editor);
    if (!le || !commit_ || !tree_)
    {
        return;
    }
    QStandardItem *it = itemFromTreeIndex(tree_, index);
    if (!it)
    {
        return;
    }
    commit_(it, le->text());
}

/* ===== watch_row_presenter ===== */

LuaDebuggerWatchRowPresenter::LuaDebuggerWatchRowPresenter(QObject *parent, QTreeView *tree, QStandardItemModel *model,
                                                           LuaDebuggerChangeHighlightTracker &tracker)
    : QObject(parent), tree_(tree), model_(model), tracker_(&tracker)
{
}

void LuaDebuggerWatchRowPresenter::applyEmpty(QStandardItem *item, const QString &muted, const QString &watchTipExtra)
{
    if (!model_)
    {
        return;
    }
    clearWatchFilterErrorChrome(item, tree_);
    setText(model_, item, WatchColumn::Value, muted);
    item->setToolTip(watchTipExtra);
    /* Explain the muted em dash instead of leaving an empty tooltip: a blank
     * row has no variable path to evaluate, so there is nothing to show in
     * the Value column. */
    LuaDebuggerItems::setToolTip(model_, item, WatchColumn::Value,
                                 capWatchTooltipText(tr("Enter a variable path (e.g. Locals.x, Globals.t.k) or "
                                                        "a Lua expression in the Watch column to see a "
                                                        "value here.")));
    tracker_->applyChangedVisuals(parent(), item, /*changed=*/false);
    while (item->rowCount() > 0)
    {
        item->removeRow(0);
    }
}

void LuaDebuggerWatchRowPresenter::applyNoLiveContext(QStandardItem *item, const QString &muted,
                                                      const QString &watchTipExtra)
{
    if (!model_ || !tree_)
    {
        return;
    }
    setText(model_, item, WatchColumn::Value, muted);
    LuaDebuggerItems::setForeground(model_, item, WatchColumn::Value, tree_->palette().brush(QPalette::PlaceholderText));
    /* Replace the previous `muted \n Type: muted` tooltip (which just
     * repeated the em dash) with a short explanation so the user knows
     * *why* there is no value: watches are only evaluated while the
     * debugger is paused. */
    const QString mutedReason = wslua_debugger_is_enabled() ? tr("Value shown only while the debugger is paused.")
                                                            : tr("Value shown only while the debugger is paused. "
                                                                 "The debugger is currently disabled.");
    const QString ttSuf = tr("Type: %1").arg(muted);
    item->setToolTip(
        capWatchTooltipText(QStringLiteral("%1\n%2\n%3").arg(item->text(), mutedReason, ttSuf) + watchTipExtra));
    LuaDebuggerItems::setToolTip(model_, item, WatchColumn::Value, capWatchTooltipText(mutedReason));
    /* Clear the accent/bold/flash but do NOT touch the baseline maps:
     * bold-on-change must survive resume → pause cycles so the next pause
     * can compare against the value displayed at the end of this pause.
     * applyChangedVisuals(false) only unbolds; it leaves the caller's
     * foreground / background intact, so the placeholder brush set above
     * and the normal column-0 text stay as the caller wants. */
    tracker_->applyChangedVisuals(parent(), item, /*changed=*/false);
    /* A previous pause may have left the Watch-column (col 0) foreground
     * set to the accent. Reset it to the default text color so the spec
     * looks normal while unpaused. */
    LuaDebuggerItems::setForeground(model_, item, WatchColumn::Spec,
                                    tree_->palette().brush(QPalette::Text));
    if (item->parent() == nullptr)
    {
        while (item->rowCount() > 0)
        {
            item->removeRow(0);
        }
    }
}

void LuaDebuggerWatchRowPresenter::applyError(QStandardItem *item, const QString &errStr, const QString &watchTipExtra)
{
    if (!model_)
    {
        return;
    }
    applyWatchFilterErrorChrome(item, tree_);
    /* The cell text shows a tidied error: for expression watches the
     * synthetic "watch:N: " prefix is stripped (the row's red chrome
     * already says "watch failed", and the chunk is always one line);
     * path-watch errors pass through unchanged. The tooltip below keeps
     * the full untouched string for diagnostics. */
    const QString cellErrStr = stripWatchExpressionErrorPrefix(errStr);
    setText(model_, item, WatchColumn::Value, cellErrStr);
    const QString ttSuf = tr("Type: %1").arg(tr("error"));
    item->setToolTip(capWatchTooltipText(QStringLiteral("%1\n%2").arg(item->text(), ttSuf) + watchTipExtra));
    /* "Could not evaluate watch" works for both flavors: a path watch
     * fails to resolve or an expression watch fails to compile / runs
     * into a Lua error. The detailed @a errStr below carries the
     * specific reason (e.g. "Path not found", "watch:1: ...") so the
     * generic header just acknowledges that a value could not be read. */
    LuaDebuggerItems::setToolTip(
        model_, item, WatchColumn::Value,
        capWatchTooltipText(QStringLiteral("%1\n%2\n%3").arg(tr("Could not evaluate watch."), errStr, ttSuf)));
    tracker_->applyChangedVisuals(parent(), item, /*changed=*/false);
    /* An error invalidates the comparison: drop baselines for this root so
     * the next successful evaluation does not flag a change vs the pre-error
     * value. */
    if (item->parent() == nullptr)
    {
        const QString spec = item->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            tracker_->clearChangeBaselinesForWatchSpec(spec);
        }
    }
    while (item->rowCount() > 0)
    {
        item->removeRow(0);
    }
}

void LuaDebuggerWatchRowPresenter::applySuccess(QStandardItem *item, const QString &spec, const char *val,
                                                const char *typ, bool can_expand, const QString &watchTipExtra,
                                                int stackLevel, bool changeHighlightAllowed)
{
    if (item->parent() == nullptr)
    {
        watchRootSetVariablePathRoleFromSpec(item, spec);
    }
    if (!model_)
    {
        return;
    }
    const QString v = val ? QString::fromUtf8(val) : QString();
    const QString typStr = typ ? QString::fromUtf8(typ) : QString();
    setText(model_, item, WatchColumn::Value, v);
    const QString ttSuf = typStr.isEmpty() ? QString() : tr("Type: %1").arg(typStr);
    item->setToolTip(capWatchTooltipText(
        (ttSuf.isEmpty() ? item->text() : QStringLiteral("%1\n%2").arg(item->text(), ttSuf)) + watchTipExtra));
    LuaDebuggerItems::setToolTip(model_, item, WatchColumn::Value,
                                 capWatchTooltipText(ttSuf.isEmpty() ? v : QStringLiteral("%1\n%2").arg(v, ttSuf)));
    /* Only watch roots are routed through applySuccess; children go
     * through applyWatchChildRowTextAndTooltip + applyChangedVisuals inside
     * fillPathChildren. The Globals branch is excluded from
     * changeHighlightAllowed because it is anchored to level=-1 and
     * therefore stays comparable across stack-frame switches. */
    const bool isGlobal = watchSpecIsGlobalScoped(spec);
    const int level = isGlobal ? -1 : stackLevel;
    const QString rk = changeKey(level, spec);
    const bool baselineChanged = tracker_->observeWatchRootValue(rk, v);
    tracker_->applyChangedVisuals(parent(), item, (isGlobal || changeHighlightAllowed) && baselineChanged);

    if (can_expand)
    {
        if (item->rowCount() == 0)
        {
            QStandardItem *const placeholderSpec = new QStandardItem();
            QStandardItem *const placeholderValue = new QStandardItem();
            placeholderSpec->setFlags(Qt::ItemIsEnabled);
            placeholderValue->setFlags(Qt::ItemIsEnabled);
            item->appendRow({placeholderSpec, placeholderValue});
        }
    }
    else
    {
        while (item->rowCount() > 0)
        {
            item->removeRow(0);
        }
    }
}

void LuaDebuggerWatchRowPresenter::applyExpression(QStandardItem *item, const QString &spec, const char *val,
                                                   const char *typ, bool can_expand, const QString &watchTipExtra,
                                                   int stackLevel, bool changeHighlightAllowed)
{
    if (item->parent() == nullptr)
    {
        /* Expression watches have no Variables-tree counterpart; clear
         * the role so leftover state from a prior path-style spec on the
         * same row does not leak into Variables-tree selection sync. */
        item->setData(QVariant(), VariablePathRole);
    }
    if (!model_)
    {
        return;
    }
    const QString v = val ? QString::fromUtf8(val) : QString();
    const QString typStr = typ ? QString::fromUtf8(typ) : QString();
    setText(model_, item, WatchColumn::Value, v);

    const QString exprNote = tr("Expression — re-evaluated on every pause.");
    const QString ttSuf = typStr.isEmpty() ? QString() : tr("Type: %1").arg(typStr);

    QString specTooltip = item->text();
    if (!ttSuf.isEmpty())
    {
        specTooltip = QStringLiteral("%1\n%2").arg(specTooltip, ttSuf);
    }
    specTooltip = QStringLiteral("%1\n%2").arg(specTooltip, exprNote);
    item->setToolTip(capWatchTooltipText(specTooltip + watchTipExtra));

    QString valueTooltip = v;
    if (!ttSuf.isEmpty())
    {
        valueTooltip = QStringLiteral("%1\n%2").arg(valueTooltip, ttSuf);
    }
    valueTooltip = QStringLiteral("%1\n%2").arg(valueTooltip, exprNote);
    LuaDebuggerItems::setToolTip(model_, item, WatchColumn::Value, capWatchTooltipText(valueTooltip));

    /* Change tracking — same scheme as path roots, but expression specs
     * are not Globals-anchored (watchSpecIsGlobalScoped returns false on
     * non-path specs), so the cue is fully gated on changeHighlightAllowed. */
    const QString rk = changeKey(stackLevel, spec);
    const bool baselineChanged = tracker_->observeWatchRootValue(rk, v);
    tracker_->applyChangedVisuals(parent(), item, changeHighlightAllowed && baselineChanged);

    if (can_expand)
    {
        if (item->rowCount() == 0)
        {
            QStandardItem *const placeholderSpec = new QStandardItem();
            QStandardItem *const placeholderValue = new QStandardItem();
            placeholderSpec->setFlags(Qt::ItemIsEnabled);
            placeholderValue->setFlags(Qt::ItemIsEnabled);
            item->appendRow({placeholderSpec, placeholderValue});
        }
    }
    else
    {
        while (item->rowCount() > 0)
        {
            item->removeRow(0);
        }
    }
}

/* ===== watch_controller ===== */

using namespace LuaDebuggerItems;
using namespace LuaDebuggerPath;

namespace
{

/** Pointers into the context menu built by buildWatchContextMenu(). */
struct WatchContextMenuActions
{
    QAction *addWatch = nullptr;
    QAction *copyValue = nullptr;
    QAction *duplicate = nullptr;
    QAction *editWatch = nullptr;
    QAction *remove = nullptr;
    QAction *removeAllWatches = nullptr;
};

void buildWatchContextMenu(QMenu &menu, QStandardItem *item, WatchContextMenuActions *acts,
                           const QStandardItemModel *watchModel, const QKeySequence &addWatchShortcut,
                           LuaDebuggerDialog *host)
{
    acts->addWatch = menu.addAction(host->tr("Add Watch"));
    if (!addWatchShortcut.isEmpty())
    {
        acts->addWatch->setShortcut(addWatchShortcut);
    }
    if (!item)
    {
        if (watchModel && watchModel->rowCount() > 0)
        {
            menu.addSeparator();
            acts->removeAllWatches = menu.addAction(host->tr("Remove All Watches"));
            acts->removeAllWatches->setShortcut(kLuaDbgCtxWatchRemoveAll);
        }
        return;
    }

    if (item->parent() == nullptr)
    {
        acts->duplicate = menu.addAction(host->tr("Duplicate Watch"));
        acts->duplicate->setShortcut(kLuaDbgCtxWatchDuplicate);
        acts->editWatch = menu.addAction(host->tr("Edit Watch"));
        acts->editWatch->setShortcut(kLuaDbgCtxWatchEdit);
        menu.addSeparator();
    }

    acts->copyValue = menu.addAction(host->tr("Copy Value"));
    acts->copyValue->setShortcut(kLuaDbgCtxWatchCopyValue);

    if (item->parent() != nullptr)
    {
        return;
    }

    menu.addSeparator();
    acts->remove = menu.addAction(host->tr("Remove"));
    acts->remove->setShortcut(QKeySequence::Delete);
    if (watchModel->rowCount() > 0)
    {
        acts->removeAllWatches = menu.addAction(host->tr("Remove All Watches"));
        acts->removeAllWatches->setShortcut(kLuaDbgCtxWatchRemoveAll);
    }
}

} // namespace

void LuaDebuggerWatchController::attach(QTreeView *tree, QStandardItemModel *model)
{
    tree_ = tree;
    model_ = model;
    /* Build the row presenter once both Qt collaborators are known.
     * Ownership stays here (parented to this); the dialog's change-highlight
     * tracker is borrowed by reference and must outlive the presenter. */
    if (!rowPresenter_)
    {
        rowPresenter_ = new LuaDebuggerWatchRowPresenter(this, tree_, model_, host_->changeHighlight());
    }

    if (!tree_ || !model_)
    {
        return;
    }

    connect(tree_, &QTreeView::expanded, this, &LuaDebuggerWatchController::onExpanded);
    connect(tree_, &QTreeView::collapsed, this, &LuaDebuggerWatchController::onCollapsed);
    tree_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tree_, &QTreeView::customContextMenuRequested, this, &LuaDebuggerWatchController::showContextMenu);

    tree_->setItemDelegateForColumn(
        WatchColumn::Spec,
        new LuaDbgWatchRootDelegate(
            tree_, [this](QStandardItem *item, const QString &text) { commitWatchRootSpec(item, text); }, tree_));
    tree_->setItemDelegateForColumn(WatchColumn::Value, new LuaDbgWatchValueColumnDelegate(tree_));

    /* Watch-local mouse / keyboard gestures live in LuaDbgWatchTreeWidget; the
     * widget emits semantic signals here so the controller stays the single
     * sink for row-level operations. The dialog's app-wide event filter still
     * claims ShortcutOverride for the keys that overlap main-window actions
     * (Ctrl+Shift+C / Ctrl+Shift+D); Qt then re-delivers as KeyPress to the
     * focused widget, where the override below routes it to the controller. */
    if (auto *const watchTreeTyped = qobject_cast<LuaDbgWatchTreeWidget *>(tree_))
    {
        connect(watchTreeTyped, &LuaDbgWatchTreeWidget::requestNewRow, this,
                [this]() { insertNewRow(QString(), true); });
        connect(watchTreeTyped, &LuaDbgWatchTreeWidget::requestRemoveAll, this,
                &LuaDebuggerWatchController::removeAllTopLevelItems);
        connect(watchTreeTyped, &LuaDbgWatchTreeWidget::requestCopyValue, this,
                &LuaDebuggerWatchController::copyValueForItem);
        connect(watchTreeTyped, &LuaDbgWatchTreeWidget::requestDuplicateRoot, this,
                &LuaDebuggerWatchController::duplicateRootItem);
        connect(watchTreeTyped, &LuaDbgWatchTreeWidget::requestDeleteRows, this,
                &LuaDebuggerWatchController::deleteRows);
    }

    if (QItemSelectionModel *sel = tree_->selectionModel())
    {
        connect(sel, &QItemSelectionModel::selectionChanged, this, [this]() { updateHeaderButtonState(); });
    }
    connect(model_, &QAbstractItemModel::rowsInserted, this, [this]() { updateHeaderButtonState(); });
    connect(model_, &QAbstractItemModel::rowsRemoved, this, [this]() { updateHeaderButtonState(); });
    connect(model_, &QAbstractItemModel::modelReset, this, [this]() { updateHeaderButtonState(); });
    updateHeaderButtonState();
}

void LuaDebuggerWatchController::attachHeaderButtons(QToolButton *remove, QToolButton *removeAll)
{
    removeButton_ = remove;
    removeAllButton_ = removeAll;

    if (removeButton_)
    {
        connect(removeButton_, &QToolButton::clicked, this,
                [this]()
                {
                    const QList<QStandardItem *> del = selectedRootItemsForRemove();
                    if (!del.isEmpty())
                    {
                        deleteRows(del);
                    }
                });
    }
    if (removeAllButton_)
    {
        connect(removeAllButton_, &QToolButton::clicked, this, &LuaDebuggerWatchController::removeAllTopLevelItems);
    }
    updateHeaderButtonState();
}

void LuaDebuggerWatchController::updateHeaderButtonState()
{
    if (removeButton_)
    {
        removeButton_->setEnabled(!selectedRootItemsForRemove().isEmpty());
    }
    if (removeAllButton_)
    {
        removeAllButton_->setEnabled(model_ && model_->rowCount() > 0);
    }
}

LuaDebuggerWatchController::LuaDebuggerWatchController(LuaDebuggerDialog *host) : QObject(host), host_(host) {}

void LuaDebuggerWatchController::configureColumns() const
{
    if (!tree_ || !tree_->header())
    {
        return;
    }
    QHeaderView *header = tree_->header();
    header->setStretchLastSection(true);
    header->setSectionsMovable(false);
    header->setSectionResizeMode(0, QHeaderView::Interactive);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    header->resizeSection(0, 200);
}

QStringList LuaDebuggerWatchController::expandedSubpathsForSpec(const QString &rootSpec) const
{
    return luaDbgTreeSectionExpandedSubpaths(expansion_, rootSpec);
}

void LuaDebuggerWatchController::pruneExpansionMap()
{
    if (!tree_ || !model_ || expansion_.isEmpty())
    {
        return;
    }
    QSet<QString> liveSpecs;
    const int n = model_->rowCount();
    for (int i = 0; i < n; ++i)
    {
        const QStandardItem *it = model_->item(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            liveSpecs.insert(spec);
        }
    }
    for (auto it = expansion_.begin(); it != expansion_.end();)
    {
        if (!liveSpecs.contains(it.key()))
        {
            it = expansion_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void LuaDebuggerWatchController::refillChildren(QStandardItem *item)
{
    if (!item)
    {
        return;
    }
    while (item->rowCount() > 0)
    {
        item->removeRow(0);
    }

    const QStandardItem *const rootWatch = luaDbgWatchRootItem(item);
    if (!rootWatch)
    {
        return;
    }
    const QString rootSpec = rootWatch->data(WatchSpecRole).toString();

    if (watchSpecUsesPathResolution(rootSpec))
    {
        QString path = item->data(VariablePathRole).toString();
        if (path.isEmpty())
        {
            path = watchResolvedVariablePathForTooltip(rootSpec);
            if (path.isEmpty())
            {
                path = watchVariablePathForSpec(rootSpec);
            }
        }
        fillPathChildren(item, path);
        return;
    }

    /* Expression watch: descendants are addressed by a Lua-style subpath
     * relative to the expression's root value, stored in WatchSubpathRole.
     * The subpath of the root itself is empty — children of the root then
     * fan out through expressionWatchChildSubpath() in fillExprChildren(). */
    const QString subpath = item->parent() == nullptr ? QString() : item->data(WatchSubpathRole).toString();
    fillExprChildren(item, rootSpec, subpath);
}

void LuaDebuggerWatchController::restoreExpansionState()
{
    if (!tree_ || !model_)
    {
        return;
    }
    /* Re-apply each root's expansion from the runtime map. After a fresh load
     * from lua_debugger.json the map is empty (rows open collapsed). */
    for (int i = 0; i < model_->rowCount(); ++i)
    {
        QStandardItem *root = model_->item(i);
        const QString spec = root->data(WatchSpecRole).toString();
        bool rootExpanded = false;
        QStringList subpaths;
        const auto it = expansion_.constFind(spec);
        if (it != expansion_.cend())
        {
            rootExpanded = it->rootExpanded;
            subpaths = it->subpaths;
        }
        if (rootExpanded != isExpanded(tree_, model_, root))
        {
            setExpanded(tree_, model_, root, rootExpanded);
        }
        if (rootExpanded)
        {
            reexpandTreeDescendantsByPathKeys(tree_, model_, root, subpaths, findWatchItemBySubpathOrPathKey);
        }
    }
}

void LuaDebuggerWatchController::onExpanded(const QModelIndex &index)
{
    if (!model_ || !index.isValid())
    {
        return;
    }
    QStandardItem *item = model_->itemFromIndex(index.sibling(index.row(), 0));
    if (!item)
    {
        return;
    }
    const QStandardItem *const rootWatch = luaDbgWatchRootItem(item);
    const QString rootSpec = rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    if (!item->parent())
    {
        luaDbgRecordTreeSectionRootExpansion(expansion_, rootSpec, true);
    }
    else
    {
        luaDbgRecordTreeSectionSubpathExpansion(expansion_, rootSpec, watchItemExpansionKey(item), true);
    }

    if (item->rowCount() == 1)
    {
        const QModelIndex parentIx = model_->indexFromItem(item);
        const QModelIndex firstChildIx = model_->index(0, WatchColumn::Spec, parentIx);
        const QString specText = rowColumnDisplayText(firstChildIx, WatchColumn::Spec);
        const QString valueText = rowColumnDisplayText(firstChildIx, WatchColumn::Value);
        if (specText.isEmpty() && valueText.isEmpty())
        {
            item->removeRow(0);
        }
        else
        {
            return;
        }
    }
    else if (item->rowCount() > 0)
    {
        return;
    }

    refillChildren(item);
}

void LuaDebuggerWatchController::onCollapsed(const QModelIndex &index)
{
    if (!model_ || !index.isValid())
    {
        return;
    }
    QStandardItem *item = model_->itemFromIndex(index.sibling(index.row(), 0));
    if (!item)
    {
        return;
    }
    const QStandardItem *const rootWatch = luaDbgWatchRootItem(item);
    const QString rootSpec = rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    if (!item->parent())
    {
        luaDbgRecordTreeSectionRootExpansion(expansion_, rootSpec, false);
    }
    else
    {
        luaDbgRecordTreeSectionSubpathExpansion(expansion_, rootSpec, watchItemExpansionKey(item), false);
    }
}

void LuaDebuggerWatchController::showContextMenu(const QPoint &pos)
{
    if (!tree_ || !model_)
    {
        return;
    }

    const QModelIndex ix = tree_->indexAt(pos);
    QStandardItem *item = nullptr;
    if (ix.isValid())
    {
        item = model_->itemFromIndex(ix.sibling(ix.row(), 0));
    }

    QMenu menu(host_);
    WatchContextMenuActions acts;
    buildWatchContextMenu(menu, item, &acts, model_, host_->addWatchShortcut(), host_);

    QAction *chosen = menu.exec(tree_->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }

    if (chosen == acts.addWatch)
    {
        insertNewRow(QString(), true);
        return;
    }
    if (chosen == acts.removeAllWatches)
    {
        removeAllTopLevelItems();
        return;
    }
    if (!item)
    {
        return;
    }

    if (chosen == acts.copyValue)
    {
        copyValueForItem(item, ix);
        return;
    }

    if (item->parent() != nullptr)
    {
        return;
    }

    if (chosen == acts.editWatch)
    {
        QTimer::singleShot(0, host_,
                           [this, item]()
                           {
                               if (!model_ || !tree_)
                               {
                                   return;
                               }
                               const QModelIndex editIx = model_->indexFromItem(item);
                               if (!editIx.isValid())
                               {
                                   return;
                               }
                               tree_->scrollTo(editIx);
                               tree_->setCurrentIndex(editIx);
                               tree_->edit(editIx);
                           });
        return;
    }

    if (chosen == acts.remove)
    {
        QList<QStandardItem *> del;
        for (const QModelIndex &six : tree_->selectionModel()->selectedRows(0))
        {
            QStandardItem *it = model_->itemFromIndex(six);
            if (it && it->parent() == nullptr)
            {
                del.append(it);
            }
        }
        if (del.isEmpty())
        {
            del.append(item);
        }
        deleteRows(del);
        return;
    }

    if (chosen == acts.duplicate)
    {
        duplicateRootItem(item);
    }
}

QList<QStandardItem *> LuaDebuggerWatchController::selectedRootItemsForRemove() const
{
    QList<QStandardItem *> del;
    if (!model_ || !tree_ || !tree_->selectionModel())
    {
        return del;
    }
    for (const QModelIndex &six : tree_->selectionModel()->selectedRows(0))
    {
        QStandardItem *it = model_->itemFromIndex(six);
        if (it && it->parent() == nullptr)
        {
            del.append(it);
        }
    }
    /* Intentionally no QTreeView::currentIndex fallback: after a remove the
     * selection can be empty while current still points at a row, which would
     * leave the header button enabled and the next click would remove the
     * wrong (non-selected) entry. The context menu and Del key have their
     * own item/current handling. */
    return del;
}

void LuaDebuggerWatchController::deleteRows(const QList<QStandardItem *> &items)
{
    if (!model_ || items.isEmpty())
    {
        return;
    }
    QVector<int> indices;
    indices.reserve(items.size());
    for (QStandardItem *it : items)
    {
        if (!it || it->parent() != nullptr)
        {
            continue;
        }
        indices.append(it->row());
    }
    if (indices.isEmpty())
    {
        return;
    }
    /* Delete highest-index first so earlier indices remain valid. */
    std::sort(indices.begin(), indices.end(), std::greater<int>());
    for (int idx : indices)
    {
        model_->removeRow(idx);
    }
    /* After deletion, drop baselines for specs that are no longer present
     * in the tree so a later "Add Watch" of the same spec starts clean. */
    host_->changeHighlight().pruneChangeBaselinesToLiveWatchSpecs(model_);
    refreshDisplay();
}

void LuaDebuggerWatchController::removeAllTopLevelItems()
{
    if (!model_)
    {
        return;
    }
    QList<QStandardItem *> all;
    for (int i = 0; i < model_->rowCount(); ++i)
    {
        if (QStandardItem *r = model_->item(i, WatchColumn::Spec))
        {
            all.append(r);
        }
    }
    if (all.isEmpty())
    {
        return;
    }

    /* Confirmation dialog. Mirrors LuaDebuggerBreakpointsController::clearAll(): the destructive
     * "wipe everything" gesture is reachable from the header button, the
     * Ctrl+Shift+W keyboard shortcut and the watch context menu, so the
     * prompt lives here (instead of at each call site) to guarantee the
     * user always gets one chance to back out. Default is No so a stray
     * Enter on a focused dialog does not silently delete the user's
     * watch list. */
    const int count = static_cast<int>(all.size());
    QMessageBox::StandardButton reply = QMessageBox::question(
        host_, host_->tr("Clear All Watches"), host_->tr("Are you sure you want to remove %Ln watch(es)?", "", count),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
    {
        return;
    }

    deleteRows(all);
}

void LuaDebuggerWatchController::copyValueForItem(QStandardItem *item, const QModelIndex &ix)
{
    auto copyToClipboard = [](const QString &s)
    {
        if (QClipboard *c = QGuiApplication::clipboard())
        {
            c->setText(s);
        }
    };
    QString value;
    if (item && host_->isDebuggerPaused() && wslua_debugger_is_enabled() && wslua_debugger_is_paused())
    {
        const QStandardItem *const rootWatch = luaDbgWatchRootItem(item);
        const QString rootSpec = rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();

        char *val = nullptr;
        char *err = nullptr;
        bool ok = false;

        if (watchSpecUsesPathResolution(rootSpec))
        {
            /* Path-style: prefer the row's resolved Variables-tree path so
             * children copy the correct nested value, not the root. */
            const QString varPath = item->data(VariablePathRole).toString();
            if (!varPath.isEmpty())
            {
                ok = wslua_debugger_read_variable_value_full(varPath.toUtf8().constData(), &val, &err);
            }
        }
        else if (!rootSpec.isEmpty())
        {
            /* Expression-style: re-evaluate against the root spec, then
             * walk the row's stored subpath (empty for the root itself). */
            const QString subpath = item->parent() == nullptr ? QString() : item->data(WatchSubpathRole).toString();
            const QByteArray rootSpecUtf8 = rootSpec.toUtf8();
            const QByteArray subpathUtf8 = subpath.toUtf8();
            ok = wslua_debugger_watch_expr_read_full(rootSpecUtf8.constData(),
                                                     subpath.isEmpty() ? nullptr : subpathUtf8.constData(), &val, &err);
        }

        if (ok)
        {
            value = QString::fromUtf8(val ? val : "");
        }
        g_free(val);
        g_free(err);
    }
    if (value.isNull())
    {
        value = rowColumnDisplayText(ix, 1);
    }
    copyToClipboard(value);
}

void LuaDebuggerWatchController::duplicateRootItem(QStandardItem *item)
{
    if (!model_ || !item || item->parent() != nullptr)
    {
        return;
    }
    auto *specCopy = new QStandardItem();
    auto *valueCopy = new QStandardItem();
    specCopy->setFlags(specCopy->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled | Qt::ItemIsSelectable |
                       Qt::ItemIsDragEnabled);
    valueCopy->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    specCopy->setText(item->text());
    {
        const QModelIndex srcRowSpec = model_->indexFromItem(item);
        setText(model_, specCopy, WatchColumn::Value,
                rowColumnDisplayText(srcRowSpec, WatchColumn::Value));
    }
    for (int r = WatchSpecRole; r <= WatchPendingNewRole; ++r)
    {
        specCopy->setData(item->data(r), r);
    }
    specCopy->setData(false, WatchPendingNewRole);
    specCopy->setData(item->data(VariablePathRole), VariablePathRole);
    specCopy->setData(item->data(VariableTypeRole), VariableTypeRole);
    specCopy->setData(item->data(VariableCanExpandRole), VariableCanExpandRole);
    /* The duplicate is a brand-new row: it has no baseline yet, so the
     * first refresh will not show it as "changed". No per-item role data
     * to clear — baselines live on the dialog, keyed by spec+level, and
     * the copy shares the spec of its source. */
    {
        auto *placeholderSpec = new QStandardItem();
        auto *placeholderValue = new QStandardItem();
        placeholderSpec->setFlags(Qt::ItemIsEnabled);
        placeholderValue->setFlags(Qt::ItemIsEnabled);
        specCopy->appendRow({placeholderSpec, placeholderValue});
    }
    model_->insertRow(item->row() + 1, {specCopy, valueCopy});
    refreshDisplay();
}

void LuaDebuggerWatchController::insertNewRow(const QString &initialSpec, bool openEditor)
{
    if (!tree_ || !model_)
    {
        return;
    }

    const QString init = initialSpec.trimmed();
    for (int i = 0; i < model_->rowCount(); ++i)
    {
        if (QStandardItem *r = model_->item(i, WatchColumn::Spec))
        {
            if (r->data(WatchSpecRole).toString() == init)
            {
                const QModelIndex wix = model_->indexFromItem(r);
                tree_->scrollTo(wix);
                tree_->setCurrentIndex(wix);
                return;
            }
        }
    }
    /* Both path watches and expression watches are accepted; the watch
     * panel decides how to evaluate. */

    auto *specItem = new QStandardItem();
    auto *valueItem = new QStandardItem();
    specItem->setFlags(specItem->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled | Qt::ItemIsSelectable |
                       Qt::ItemIsDragEnabled);
    valueItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    specItem->setData(init, WatchSpecRole);
    specItem->setText(init);
    specItem->setData(QString(), WatchSubpathRole);
    specItem->setData(QVariant(init.isEmpty()), WatchPendingNewRole);
    if (!init.isEmpty())
    {
        watchRootSetVariablePathRoleFromSpec(specItem, init);
    }
    {
        auto *placeholderSpec = new QStandardItem();
        auto *placeholderValue = new QStandardItem();
        placeholderSpec->setFlags(Qt::ItemIsEnabled);
        placeholderValue->setFlags(Qt::ItemIsEnabled);
        specItem->appendRow({placeholderSpec, placeholderValue});
    }
    model_->appendRow({specItem, valueItem});
    refreshDisplay();

    if (openEditor)
    {
        QTimer::singleShot(0, host_,
                           [this, specItem]()
                           {
                               const QModelIndex editIx = model_->indexFromItem(specItem);
                               tree_->scrollTo(editIx);
                               tree_->setCurrentIndex(editIx);
                               tree_->edit(editIx);
                           });
    }
}

void LuaDebuggerWatchController::commitWatchRootSpec(QStandardItem *item, const QString &text)
{
    if (!tree_ || !model_ || !item || item->parent() != nullptr)
    {
        return;
    }

    const QString t = text.trimmed();
    if (t.isEmpty())
    {
        /* Clearing the text of a brand-new row discards it (no persisted
         * entry ever existed); clearing an existing row removes it. */
        if (item->data(WatchPendingNewRole).toBool())
        {
            model_->removeRow(item->row());
            refreshDisplay();
        }
        else
        {
            deleteRows({item});
        }
        return;
    }

    if (t.size() > WATCH_EXPR_MAX_CHARS)
    {
        QMessageBox::warning(tree_, tr("Lua Debugger"),
                             tr("Watch expression is too long (maximum %Ln characters).", "",
                                static_cast<qlonglong>(WATCH_EXPR_MAX_CHARS)));
        return;
    }

    /* Both path watches (Locals.x, Globals.t.k) and expression watches
     * (any Lua expression — pinfo.src:tostring(), #packets, t[i] + 1)
     * are accepted; the watch panel decides how to evaluate based on
     * whether @c t validates as a Variables-tree path. */

    /* Editing a spec invalidates baselines for both old and new specs:
     * the old spec no longer applies to this row, and the new spec has
     * never been evaluated on this row before (so the first refresh must
     * not flag it as "changed" against an unrelated old value). */
    const QString oldSpec = item->data(WatchSpecRole).toString();
    if (!oldSpec.isEmpty() && oldSpec != t)
    {
        host_->changeHighlight().clearChangeBaselinesForWatchSpec(oldSpec);
    }
    host_->changeHighlight().clearChangeBaselinesForWatchSpec(t);

    item->setData(t, WatchSpecRole);
    item->setText(t);
    item->setData(false, WatchPendingNewRole);
    watchRootSetVariablePathRoleFromSpec(item, t);
    if (item->rowCount() == 0)
    {
        auto *placeholderSpec = new QStandardItem();
        auto *placeholderValue = new QStandardItem();
        placeholderSpec->setFlags(Qt::ItemIsEnabled);
        placeholderValue->setFlags(Qt::ItemIsEnabled);
        item->appendRow({placeholderSpec, placeholderValue});
    }
    refreshDisplay();
}

void LuaDebuggerWatchController::fillPathChildren(QStandardItem *parent, const QString &path)
{
    if (!model_ || !tree_)
    {
        return;
    }
    /* Path watches drill down with wslua_debugger_get_variables (same tree as
     * Variables); expression watches use wslua_debugger_watch_* elsewhere. */
    if (watchSubpathBoundaryCount(path) >= WSLUA_WATCH_MAX_PATH_SEGMENTS)
    {
        auto *sentinelSpec = new QStandardItem(QStringLiteral("\u2026"));
        auto *sentinelValue = new QStandardItem(host_->tr("Maximum watch depth reached"));
        sentinelSpec->setFlags(Qt::ItemIsEnabled);
        sentinelValue->setFlags(Qt::ItemIsEnabled);
        LuaDebuggerItems::setForeground(model_, sentinelSpec, WatchColumn::Value,
                                        tree_->palette().brush(QPalette::PlaceholderText));
        LuaDebuggerItems::setToolTip(model_, sentinelSpec, WatchColumn::Value,
                                     capWatchTooltipText(host_->tr("Maximum watch depth reached.")));
        parent->appendRow({sentinelSpec, sentinelValue});
        return;
    }

    int32_t variableCount = 0;
    wslua_variable_t *variables =
        wslua_debugger_get_variables(path.isEmpty() ? NULL : path.toUtf8().constData(), &variableCount);

    if (!variables)
    {
        return;
    }

    const QStandardItem *const rootWatch = luaDbgWatchRootItem(parent);
    const QString rootSpec = rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    const bool rootIsGlobal = watchSpecIsGlobalScoped(rootSpec);
    const int rootLevel = rootIsGlobal ? -1 : host_->stackController().selectionLevel();
    const QString rootKey = changeKey(rootLevel, rootSpec);
    /* Globals-scoped roots are anchored to level=-1 and stay comparable
     * across stack-frame switches; everything else is suppressed when the
     * user has navigated away from the pause-entry frame (see
     * changeHighlightAllowed()). */
    const bool highlightAllowed = rootIsGlobal || host_->changeHighlightAllowed();
    /* "First-time expansion" guard, mirror of the one in updateVariables():
     * a child absent from baseline is only meaningfully "new" if the
     * parent @p path was painted at the previous pause. The tracker
     * records visited-parent identity via a companion set; scanning the
     * value baseline by prefix cannot tell "collapsed last pause" apart
     * from "expanded last pause with no children yet", so the FIRST
     * child to appear under a parent that has always been empty (an
     * empty table just got its first key) would otherwise never flash. */
    const bool parentVisitedInBaseline = host_->changeHighlight().observeWatchChildParent(rootKey, path);

    for (int32_t variableIndex = 0; variableIndex < variableCount; ++variableIndex)
    {
        auto *nameItem = new QStandardItem();
        auto *valueItem = new QStandardItem();

        const VariableRowFields f = readVariableRowFields(variables[variableIndex], path);

        nameItem->setText(f.name);
        nameItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        nameItem->setData(f.type, VariableTypeRole);
        nameItem->setData(f.canExpand, VariableCanExpandRole);
        nameItem->setData(f.childPath, VariablePathRole);

        parent->appendRow({nameItem, valueItem});

        applyWatchChildRowTextAndTooltip(nameItem, f.value, f.type);

        /* flashNew=parentVisitedInBaseline: a child key that appeared
         * since the previous pause inside an already-visited watch path
         * is a legitimate change (e.g. a new key inserted into a table)
         * and gets the cue. But when the user expands a parent for the
         * first time, the parent itself was never painted at the previous
         * pause, so lighting up the whole subtree as "new" is misleading. The whole
         * comparison is also gated on highlightAllowed (see above) to
         * suppress the cue when the user is browsing a different stack
         * frame than the pause was entered at — Globals-scoped roots are
         * exempt and stay comparable. */
        const bool baselineChanged = host_->changeHighlight().observeWatchChildValue(
            rootKey, f.childPath, f.value, /*parentVisited=*/parentVisitedInBaseline);
        host_->applyChangedVisuals(nameItem, highlightAllowed && baselineChanged);

        applyVariableExpansionIndicator(nameItem, f.canExpand,
                                        /*enabledOnlyPlaceholder=*/true,
                                        /*columnCount=*/WatchColumn::Count);
    }

    if (variableChildrenShouldSortByName(path))
    {
        parent->sortChildren(WatchColumn::Spec, Qt::AscendingOrder);
    }

    wslua_debugger_free_variables(variables, variableCount);
}

void LuaDebuggerWatchController::fillExprChildren(QStandardItem *parent, const QString &rootSpec, const QString &subpath)
{
    if (!model_ || !tree_)
    {
        return;
    }
    /* The depth cap mirrors the path-based variant: deeply nested
     * expression children would otherwise grow without bound and we want
     * a recognizable sentinel rather than a runaway tree. */
    if (watchSubpathBoundaryCount(subpath) >= WSLUA_WATCH_MAX_PATH_SEGMENTS)
    {
        auto *sentinelSpec = new QStandardItem(QStringLiteral("\u2026"));
        auto *sentinelValue = new QStandardItem(host_->tr("Maximum watch depth reached"));
        sentinelSpec->setFlags(Qt::ItemIsEnabled);
        sentinelValue->setFlags(Qt::ItemIsEnabled);
        LuaDebuggerItems::setForeground(model_, sentinelSpec, WatchColumn::Value,
                                        tree_->palette().brush(QPalette::PlaceholderText));
        LuaDebuggerItems::setToolTip(model_, sentinelSpec, WatchColumn::Value,
                                     capWatchTooltipText(host_->tr("Maximum watch depth reached.")));
        parent->appendRow({sentinelSpec, sentinelValue});
        return;
    }

    if (rootSpec.trimmed().isEmpty())
    {
        return;
    }

    char *err = nullptr;
    wslua_variable_t *variables = nullptr;
    int32_t variableCount = 0;
    const QByteArray rootSpecUtf8 = rootSpec.toUtf8();
    const QByteArray subpathUtf8 = subpath.toUtf8();
    const bool ok = wslua_debugger_watch_expr_get_variables(rootSpecUtf8.constData(),
                                                            subpath.isEmpty() ? nullptr : subpathUtf8.constData(),
                                                            &variables, &variableCount, &err);
    g_free(err);
    if (!ok || !variables)
    {
        return;
    }

    /* Expression watches have no Globals anchor, so changes are only
     * highlighted under changeHighlightAllowed() (i.e. on the same stack
     * frame as the pause entered at). */
    const QString rootKey = changeKey(host_->stackController().selectionLevel(), rootSpec);
    /* The subpath is the parent key for change tracking; it doubles as the
     * "visited parent" identity. Empty subpath = the expression result
     * itself, which is the same identity as the root row. */
    const bool parentVisitedInBaseline = host_->changeHighlight().observeWatchChildParent(rootKey, subpath);
    const bool highlightAllowed = host_->changeHighlightAllowed();

    for (int32_t i = 0; i < variableCount; ++i)
    {
        auto *nameItem = new QStandardItem();
        auto *valueItem = new QStandardItem();

        const QString name = QString::fromUtf8(variables[i].name ? variables[i].name : "");
        const QString value = QString::fromUtf8(variables[i].value ? variables[i].value : "");
        const QString type = QString::fromUtf8(variables[i].type ? variables[i].type : "");
        const bool canExpand = variables[i].can_expand ? true : false;
        const QString childSub = expressionWatchChildSubpath(subpath, name);

        nameItem->setText(name);
        nameItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        nameItem->setData(type, VariableTypeRole);
        nameItem->setData(canExpand, VariableCanExpandRole);
        nameItem->setData(childSub, WatchSubpathRole);
        /* VariablePathRole is intentionally left empty: expression
         * children have no Variables-tree counterpart, so any sync against
         * it would mismatch a real path watch with the same composed name. */

        parent->appendRow({nameItem, valueItem});

        applyWatchChildRowTextAndTooltip(nameItem, value, type);

        const bool baselineChanged = host_->changeHighlight().observeWatchChildValue(
            rootKey, childSub, value, /*parentVisited=*/parentVisitedInBaseline);
        host_->applyChangedVisuals(nameItem, highlightAllowed && baselineChanged);

        applyVariableExpansionIndicator(nameItem, canExpand,
                                        /*enabledOnlyPlaceholder=*/true,
                                        /*columnCount=*/WatchColumn::Count);
    }

    wslua_debugger_free_variables(variables, variableCount);
}

void LuaDebuggerWatchController::refreshDisplay()
{
    if (!tree_ || !model_)
    {
        return;
    }
    const bool liveContext = wslua_debugger_is_enabled() && host_->isDebuggerPaused() && wslua_debugger_is_paused();
    const QString muted = QStringLiteral("\u2014");
    const int n = model_->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *root = model_->item(i);
        applyItemState(root, liveContext, muted);
        if (liveContext && root && LuaDebuggerItems::isExpanded(tree_, model_, root))
        {
            refreshBranch(root);
        }
    }
}

void LuaDebuggerWatchController::refreshBranch(QStandardItem *item)
{
    if (!item || !tree_ || !model_ || !LuaDebuggerItems::isExpanded(tree_, model_, item))
    {
        return;
    }
    /* refillChildren() deletes and re-creates every descendant, so the
     * tree alone cannot remember which sub-elements were expanded. Instead,
     * consult the controller's runtime expansion map (expansion_), which
     * is kept up to date by the watch tree's expanded / collapsed
     * handlers and survives both refills and the children-clearing that
     * happens while the debugger is not paused. This lets deep subtrees
     * survive stepping, pause / resume, and Variables tree refreshes
     * without being tied to transient QStandardItem lifetimes. */
    const QStandardItem *const rootWatch = luaDbgWatchRootItem(item);
    const QString rootSpec = rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    refillChildren(item);
    reexpandWatchDescendantsByPathKeys(tree_, model_, item, expandedSubpathsForSpec(rootSpec));
}

void LuaDebuggerWatchController::applyItemState(QStandardItem *item, bool liveContext, const QString &muted)
{
    if (!item || !model_ || !tree_ || !rowPresenter_)
    {
        return;
    }

    const QString spec = item->data(WatchSpecRole).toString();
    const QString watchTipExtra = watchPathOriginSuffix(item, spec);

    if (item->parent() == nullptr && spec.isEmpty())
    {
        rowPresenter_->applyEmpty(item, muted, watchTipExtra);
        return;
    }

    clearWatchFilterErrorChrome(item, tree_);
    LuaDebuggerItems::setForeground(model_, item, WatchColumn::Value, tree_->palette().brush(QPalette::Text));

    if (!liveContext)
    {
        rowPresenter_->applyNoLiveContext(item, muted, watchTipExtra);
        return;
    }

    const bool isPathSpec = watchSpecUsesPathResolution(spec);

    char *val = nullptr;
    char *typ = nullptr;
    bool can_expand = false;
    char *err = nullptr;

    const bool ok = isPathSpec
                        ? wslua_debugger_watch_read_root(spec.toUtf8().constData(), &val, &typ, &can_expand, &err)
                        : wslua_debugger_watch_expr_read_root(spec.toUtf8().constData(), &val, &typ, &can_expand, &err);
    if (!ok)
    {
        const QString errStr = err ? QString::fromUtf8(err) : muted;
        rowPresenter_->applyError(item, errStr, watchTipExtra);
        g_free(err);
        return;
    }

    /* The presenter wants the dialog-side liveness gates as parameters
     * so it can stay decoupled from LuaDebuggerDialog: the stack level
     * routes into the (level, spec) change key, and changeHighlightAllowed
     * gates the bold-on-change cue when the user is browsing a stack
     * frame other than the pause entry. */
    const int stackLevel = host_->stackController().selectionLevel();
    const bool highlightAllowed = host_->changeHighlightAllowed();
    if (isPathSpec)
    {
        rowPresenter_->applySuccess(item, spec, val, typ, can_expand, watchTipExtra, stackLevel, highlightAllowed);
    }
    else
    {
        rowPresenter_->applyExpression(item, spec, val, typ, can_expand, watchTipExtra, stackLevel, highlightAllowed);
    }
    g_free(val);
    g_free(typ);
}

void LuaDebuggerWatchController::serializeTo(QVariantMap &settingsMap)
{
    if (!model_)
    {
        return;
    }
    /* On disk, "watches" is a flat array of canonical watch spec strings in
     * visual order. Per-row expansion, editor origin, and other runtime state
     * are tracked in QStandardItem data roles only and are not persisted. */
    QStringList specs;
    const int n = model_->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *it = model_->item(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(WatchSpecRole).toString();
        if (spec.isEmpty())
        {
            continue;
        }
        specs.append(spec);
    }
    settingsMap[LuaDebuggerSettingsKeys::Watches] = specs;
    /* The runtime expansion map is keyed by root spec; drop entries for
     * specs that no longer exist in the tree. serializeTo() only runs when
     * the dialog is closing, which is also the last chance to avoid
     * persisting stale expansion data for specs that have since been
     * deleted or renamed. */
    pruneExpansionMap();
}

void LuaDebuggerWatchController::restoreFrom(const QVariantMap &settingsMap)
{
    if (!tree_ || !model_)
    {
        return;
    }
    model_->removeRows(0, model_->rowCount());
    /* The tree is being repopulated from settings; any stale baselines for
     * specs that end up in the tree will be rebuilt naturally on the next
     * refresh. Wipe everything so a fresh session starts with no "changed"
     * flags. Variables baselines are kept because they are not tied to
     * watch specs. */
    host_->changeHighlight().clearWatchBaselines();
    /* The watch list on disk is a flat array of canonical spec strings.
     * Both path watches (resolved against the Variables tree) and
     * expression watches (re-evaluated as Lua on every pause) round-trip
     * through this list; only empty / container entries are dropped. */
    const QVariantList rawList = settingsMap.value(QString::fromUtf8(LuaDebuggerSettingsKeys::Watches)).toList();
    for (const QVariant &entry : rawList)
    {
        /* Container QVariants (QVariantMap / QVariantList) toString() to an
         * empty string and are dropped here. Scalar-like values (numbers,
         * booleans) convert to a non-empty string and are kept as
         * expression watches; they will simply produce a Lua error on
         * evaluation if they are not valid expressions. */
        const QString spec = entry.toString();
        if (spec.isEmpty())
        {
            continue;
        }
        auto *specItem = new QStandardItem();
        auto *valueItem = new QStandardItem();
        setupWatchRootItemFromSpec(specItem, valueItem, spec);
        model_->appendRow({specItem, valueItem});
    }
    refreshDisplay();
    restoreExpansionState();
}

void LuaDebuggerWatchController::invalidatePlaceholder()
{
    ++placeholderEpoch_;
}

void LuaDebuggerWatchController::scheduleDeferredPlaceholder()
{
    /* Bump the epoch and capture the new value; the deferred lambda
     * checks both that the dialog is still alive and not paused, and
     * that no later schedule / pause has bumped the epoch out from
     * under us. Without the epoch the typical fast single-step would
     * blank every Watch row to "—" before the imminent re-pause
     * repaints the same value, producing a visible value→—→value
     * blink in every row. */
    const qint32 epoch = ++placeholderEpoch_;
    QPointer<LuaDebuggerDialog> guard(host_);
    QPointer<LuaDebuggerWatchController> self(this);
    QTimer::singleShot(WATCH_PLACEHOLDER_DEFER_MS, this,
                       [guard = std::move(guard), self = std::move(self), epoch]()
                       {
                           if (!guard || !self || guard->isDebuggerPaused() || self->placeholderEpoch_ != epoch)
                           {
                               return;
                           }
                           self->refreshDisplay();
                       });
}

/* ===== dialog_watch (LuaDebuggerDialog members) ===== */

CollapsibleSection *LuaDebuggerDialog::createWatchSection(QWidget *parent)
{
    /*
     * Watch panel: two columns; formats, expansion persistence, depth cap
     * WSLUA_WATCH_MAX_PATH_SEGMENTS, drag reorder, error styling, muted em dash
     * when no live value.
     */
    watchSection = new CollapsibleSection(tr("Watch"), parent);
    watchSection->setToolTip(tr("<p>Each row is either a <b>Variables-tree path</b> or a "
                                "<b>Lua expression</b>; the panel auto-detects which based on "
                                "the syntax you type.</p>"
                                "<p><b>Path watches</b> &mdash; resolved against the paused "
                                "frame's locals, upvalues, and globals:</p>"
                                "<ul>"
                                "<li>Section-qualified: <code>Locals.<i>name</i></code>, "
                                "<code>Upvalues.<i>name</i></code>, "
                                "<code>Globals.<i>name</i></code>.</li>"
                                "<li>Section root alone: <code>Locals</code>, "
                                "<code>Upvalues</code>, <code>Globals</code> "
                                "(<code>_G</code> is an alias for <code>Globals</code>).</li>"
                                "<li>Unqualified name: resolved in "
                                "<b>Locals &rarr; Upvalues &rarr; Globals</b> order; the row "
                                "tooltip shows which section matched.</li>"
                                "</ul>"
                                "<p>After the first segment, chain <code>.field</code> or "
                                "bracket keys &mdash; integer "
                                "(<code>[1]</code>, <code>[-1]</code>, <code>[0x1F]</code>), "
                                "boolean (<code>[true]</code>), or short-literal string "
                                "(<code>[\"key\"]</code>, <code>['k']</code>). Depth is capped "
                                "at 32 segments.</p>"
                                "<p><b>Expression watches</b> &mdash; anything that is not a "
                                "plain path (operators, function/method calls, table "
                                "constructors, length <code>#</code>, comparisons, &hellip;) is "
                                "evaluated as Lua against the same locals/upvalues/globals. "
                                "<b>You do not need a leading <code>=</code> or <code>return</code></b>; "
                                "value-returning expressions auto-return their value. "
                                "Examples: <code>#packets</code>, <code>tbl[i + 1]</code>, "
                                "<code>obj:method()</code>, <code>a == b</code>, "
                                "<code>{x, y}</code>. Tables produced by an expression are "
                                "expandable, and children re-resolve on every pause.</p>"
                                "<p>Values are only read while the debugger is "
                                "<b>paused</b>; otherwise the Value column shows a muted "
                                "em dash. Values that differ from the previous pause are "
                                "drawn in a <b>bold accent color</b>, and briefly flash on "
                                "the pause that introduced the change.</p>"
                                "<p>Double-click or press <b>F2</b> to edit a row; "
                                "<b>Delete</b> removes it; drag rows to reorder. Use the "
                                "<b>Evaluate</b> panel below to run statements with side "
                                "effects (assignments, blocks, loops).</p>"));
    /* Parent is intentionally @c nullptr — the widget is reparented when added
     * to @c watchWrap's layout below. */
    watchTree = new LuaDbgWatchTreeWidget(/*fontPolicy=*/&fontPolicy_, /*parent=*/nullptr);
    watchModel = new LuaDbgWatchItemModel(this);
    watchModel->setColumnCount(WatchColumn::Count);
    watchModel->setHorizontalHeaderLabels({tr("Watch"), tr("Value")});
    watchTree->setModel(watchModel);
    watchTree->setRootIsDecorated(true);
    watchTree->setDragDropMode(QAbstractItemView::InternalMove);
    watchTree->setDefaultDropAction(Qt::MoveAction);
    /* Row selection + full-row focus: horizontal drop line spans all columns. */
    watchTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    watchTree->setAllColumnsShowFocus(true);
    watchTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    watchTree->setUniformRowHeights(true);
    watchTree->setWordWrap(false);
    {
        auto *watchWrap = new QWidget();
        auto *watchOuter = new QVBoxLayout(watchWrap);
        watchOuter->setContentsMargins(0, 0, 0, 0);
        watchOuter->setSpacing(4);
        watchOuter->addWidget(watchTree, 1);
        watchSection->setContentWidget(watchWrap);
    }
    {
        const int hdrH = watchSection->titleButtonHeight();
        const QFont hdrTitleFont = watchSection->titleButtonFont();
        auto *const watchHeaderBtnRow = new QWidget(watchSection);
        auto *const watchHeaderBtnLayout = new QHBoxLayout(watchHeaderBtnRow);
        watchHeaderBtnLayout->setContentsMargins(0, 0, 0, 0);
        watchHeaderBtnLayout->setSpacing(4);
        watchHeaderBtnLayout->setAlignment(Qt::AlignVCenter);
        QToolButton *const watchAddBtn = new QToolButton(watchHeaderBtnRow);
        styleLuaDebuggerHeaderPlusMinusButton(watchAddBtn, hdrH, hdrTitleFont);
        watchAddBtn->setText(kLuaDbgHeaderPlus);
        watchAddBtn->setAutoRaise(true);
        watchAddBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        /* Compute tooltip directly from the action's shortcut so this block
         * does not depend on actionAddWatch's tooltip having already been set. */
        watchAddBtn->setToolTip(
            tr("Add Watch (%1)").arg(ui->actionAddWatch->shortcut().toString(QKeySequence::NativeText)));
        connect(watchAddBtn, &QToolButton::clicked, ui->actionAddWatch, &QAction::trigger);
        QToolButton *const watchRemBtn = new QToolButton(watchHeaderBtnRow);
        styleLuaDebuggerHeaderPlusMinusButton(watchRemBtn, hdrH, hdrTitleFont);
        watchRemBtn->setText(kLuaDbgHeaderMinus);
        watchRemBtn->setAutoRaise(true);
        watchRemBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        watchRemBtn->setEnabled(false);
        watchRemBtn->setToolTip(
            tr("Remove Watch (%1)").arg(QKeySequence(QKeySequence::Delete).toString(QKeySequence::NativeText)));
        QToolButton *const watchRemAllBtn = new QToolButton(watchHeaderBtnRow);
        {
            QIcon icon = luaDbgPaintedGlyphButtonIcon(kLuaDbgHeaderRemoveAll, hdrH, devicePixelRatioF(),
                                                     hdrTitleFont, palette(), /*margin=*/2);
            watchRemAllBtn->setIcon(icon);
        }
        styleLuaDebuggerHeaderIconOnlyButton(watchRemAllBtn, hdrH);
        watchRemAllBtn->setAutoRaise(true);
        watchRemAllBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        watchRemAllBtn->setEnabled(false);
        watchRemAllBtn->setToolTip(
            tr("Remove All Watches (%1)").arg(kLuaDbgCtxWatchRemoveAll.toString(QKeySequence::NativeText)));
        watchHeaderBtnLayout->addWidget(watchAddBtn);
        watchHeaderBtnLayout->addWidget(watchRemBtn);
        watchHeaderBtnLayout->addWidget(watchRemAllBtn);
        watchController_.attachHeaderButtons(watchRemBtn, watchRemAllBtn);
        watchSection->setHeaderTrailingWidget(watchHeaderBtnRow);
    }
    watchSection->setExpanded(true);
    return watchSection;
}

void LuaDebuggerDialog::wireWatchPanel()
{
    /* Watch-internal wiring (delegates, expand/collapse, context menu,
     * typed gestures, header-button enable state) lives on the controller.
     * The dialog only owns the cross-panel current-row sync between Watch
     * and Variables. */
    watchController_.attach(watchTree, watchModel);
    connect(watchTree->selectionModel(), &QItemSelectionModel::currentChanged, this,
            &LuaDebuggerDialog::onWatchCurrentItemChanged);
}

QStandardItem *LuaDebuggerDialog::findVariablesItemByPath(const QString &path) const
{
    return variablesController_.findItemByPath(path);
}

QStandardItem *LuaDebuggerDialog::findWatchRootForVariablePath(const QString &path) const
{
    if (!watchTree || path.isEmpty())
    {
        return nullptr;
    }
    const int n = watchModel->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *w = watchModel->item(i, WatchColumn::Spec);
        const QString spec = w->data(WatchSpecRole).toString();
        QString vp = watchResolvedVariablePathForTooltip(spec);
        if (vp.isEmpty())
        {
            vp = watchVariablePathForSpec(spec);
        }
        if (!vp.isEmpty() && vp == path)
        {
            return w;
        }
        if (w->data(VariablePathRole).toString() == path)
        {
            return w;
        }
    }
    return nullptr;
}

void LuaDebuggerDialog::expandAncestorsOf(QTreeView *tree, QStandardItemModel *model, QStandardItem *item)
{
    if (!tree || !model || !item)
    {
        return;
    }
    QList<QStandardItem *> chain;
    for (QStandardItem *p = item->parent(); p; p = p->parent())
    {
        chain.prepend(p);
    }
    for (QStandardItem *a : chain)
    {
        const QModelIndex ix = model->indexFromItem(a);
        if (ix.isValid())
        {
            tree->setExpanded(ix, true);
        }
    }
}

void LuaDebuggerDialog::onVariablesCurrentItemChanged(const QModelIndex &current, const QModelIndex &previous)
{
    Q_UNUSED(previous);
    if (syncWatchVariablesSelection_ || !watchTree || !watchModel || !variablesTree || !variablesModel ||
        !current.isValid())
    {
        return;
    }
    QStandardItem *curItem = variablesModel->itemFromIndex(current.sibling(current.row(), 0));
    QStandardItem *watch = nullptr;
    if (curItem)
    {
        const QString path = curItem->data(VariablePathRole).toString();
        if (!path.isEmpty())
        {
            watch = findWatchRootForVariablePath(path);
        }
    }
    syncWatchVariablesSelection_ = true;
    if (watch)
    {
        const QModelIndex wix = watchModel->indexFromItem(watch);
        watchTree->setCurrentIndex(wix);
        watchTree->scrollTo(wix);
    }
    else if (QItemSelectionModel *sm = watchTree->selectionModel())
    {
        /* No matching watch for this Variables row — clear the stale
         * Watch selection so the two trees stay in sync. */
        sm->clearSelection();
        sm->setCurrentIndex(QModelIndex(), QItemSelectionModel::Clear);
    }
    syncWatchVariablesSelection_ = false;
}

void LuaDebuggerDialog::syncVariablesTreeToCurrentWatch()
{
    if (syncWatchVariablesSelection_ || !watchTree || !variablesTree)
    {
        return;
    }
    const QModelIndex curIx = watchTree->currentIndex();
    QStandardItem *const cur = watchModel ? watchModel->itemFromIndex(curIx.sibling(curIx.row(), 0)) : nullptr;
    QStandardItem *v = nullptr;
    if (cur && cur->parent() == nullptr)
    {
        const QString spec = cur->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            QString path = cur->data(VariablePathRole).toString();
            if (path.isEmpty())
            {
                path = watchResolvedVariablePathForTooltip(spec);
                if (path.isEmpty())
                {
                    path = watchVariablePathForSpec(spec);
                }
            }
            if (!path.isEmpty())
            {
                v = findVariablesItemByPath(path);
            }
        }
    }
    syncWatchVariablesSelection_ = true;
    if (v)
    {
        expandAncestorsOf(variablesTree, variablesModel, v);
        const QModelIndex vix = variablesModel->indexFromItem(v);
        variablesTree->setCurrentIndex(vix);
        variablesTree->scrollTo(vix);
    }
    else if (QItemSelectionModel *sm = variablesTree->selectionModel())
    {
        /* No matching Variables row for the current watch — clear the
         * stale Variables selection so the two trees stay in sync. */
        sm->clearSelection();
        sm->setCurrentIndex(QModelIndex(), QItemSelectionModel::Clear);
    }
    syncWatchVariablesSelection_ = false;
}

void LuaDebuggerDialog::onWatchCurrentItemChanged(const QModelIndex &current, const QModelIndex &previous)
{
    Q_UNUSED(previous);
    if (syncWatchVariablesSelection_ || !watchTree || !watchModel || !variablesTree || !current.isValid())
    {
        return;
    }
    QStandardItem *rowItem = watchModel->itemFromIndex(current.sibling(current.row(), 0));
    const QString spec =
        (rowItem && rowItem->parent() == nullptr) ? rowItem->data(WatchSpecRole).toString() : QString();

    if (!spec.isEmpty())
    {
        const bool live = wslua_debugger_is_enabled() && debuggerPaused && wslua_debugger_is_paused();
        if (live)
        {
            const int32_t desired = wslua_debugger_find_stack_level_for_watch_spec(spec.toUtf8().constData());
            if (desired >= 0 && desired != stackController_.selectionLevel())
            {
                stackController_.setSelectionLevel(static_cast<int>(desired));
                wslua_debugger_set_variable_stack_level(desired);
                refreshVariablesForCurrentStackFrame();
                stackController_.updateFromEngine();
            }
        }
    }

    /* Always sync: when the current watch has no resolvable path, the
     * helper clears the stale Variables selection. */
    syncVariablesTreeToCurrentWatch();
}

void LuaDebuggerDialog::addWatchFromSpec(const QString &watchSpec)
{
    watchController_.insertNewRow(watchSpec, false);
}

QKeySequence LuaDebuggerDialog::addWatchShortcut() const
{
    return ui->actionAddWatch->shortcut();
}
