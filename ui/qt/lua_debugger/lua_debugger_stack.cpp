/* lua_debugger_stack.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Call-stack panel: column layout, model build, frame selection.
 */

#include "lua_debugger_stack.h"

#include <QAbstractItemView>
#include <QClipboard>
#include <QColor>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QMenu>
#include <QPalette>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTreeView>

#include "lua_debugger_code_editor.h"
#include "lua_debugger_dialog.h"
#include "widgets/collapsible_section.h"

/* ===== stack_controller ===== */

void LuaDebuggerStackController::attach(QTreeView *tree, QStandardItemModel *model)
{
    tree_ = tree;
    model_ = model;
}

LuaDebuggerStackController::LuaDebuggerStackController(LuaDebuggerDialog *host) : QObject(host), host_(host) {}

void LuaDebuggerStackController::configureColumns() const
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
    header->resizeSection(0, 150);
}

void LuaDebuggerStackController::updateFromEngine()
{
    if (!tree_ || !model_)
    {
        return;
    }

    const bool signalsWereBlocked = tree_->blockSignals(true);
    if (model_)
    {
        model_->removeRows(0, model_->rowCount());
    }

    int32_t frameCount = 0;
    wslua_stack_frame_t *stack = wslua_debugger_get_stack(&frameCount);
    QStandardItem *itemToSelect = nullptr;
    if (stack && frameCount > 0)
    {
        const int maxLevel = static_cast<int>(frameCount) - 1;
        selectionLevel_ = qBound(0, selectionLevel_, maxLevel);
        wslua_debugger_set_variable_stack_level(static_cast<int32_t>(selectionLevel_));

        for (int32_t frameIndex = 0; frameIndex < frameCount; ++frameIndex)
        {
            QStandardItem *const nameItem = new QStandardItem();
            QStandardItem *const locItem = new QStandardItem();
            nameItem->setData(static_cast<qlonglong>(frameIndex), StackItemLevelRole);
            const char *rawSource = stack[frameIndex].source;
            const bool isLuaFrame = rawSource && rawSource[0] == '@';
            const QString functionName = QString::fromUtf8(stack[frameIndex].name ? stack[frameIndex].name : "?");
            QString locationText;
            QString resolvedPath;
            if (isLuaFrame)
            {
                const QString filePath = QString::fromUtf8(rawSource + 1);
                resolvedPath = host_->normalizedFilePath(filePath);
                if (resolvedPath.isEmpty())
                {
                    resolvedPath = filePath;
                }
                const QString fileDisplayName = QFileInfo(resolvedPath).fileName();
                locationText = QStringLiteral("%1:%2")
                                   .arg(fileDisplayName.isEmpty() ? resolvedPath : fileDisplayName)
                                   .arg(stack[frameIndex].line);
                locItem->setToolTip(QStringLiteral("%1:%2").arg(resolvedPath).arg(stack[frameIndex].line));
            }
            else
            {
                locationText = QString::fromUtf8(rawSource ? rawSource : "[C]");
            }

            nameItem->setText(functionName);
            locItem->setText(locationText);

            if (isLuaFrame)
            {
                nameItem->setData(true, StackItemNavigableRole);
                nameItem->setData(resolvedPath, StackItemFileRole);
                nameItem->setData(static_cast<qlonglong>(stack[frameIndex].line), StackItemLineRole);
            }
            else
            {
                nameItem->setData(false, StackItemNavigableRole);
                QColor disabledColor = tree_->palette().color(QPalette::Disabled, QPalette::Text);
                nameItem->setForeground(disabledColor);
                locItem->setForeground(disabledColor);
            }

            model_->appendRow({nameItem, locItem});

            if (frameIndex == selectionLevel_)
            {
                itemToSelect = nameItem;
            }
        }
    }
    else
    {
        selectionLevel_ = 0;
        wslua_debugger_set_variable_stack_level(0);
    }

    if (stack)
    {
        wslua_debugger_free_stack(stack, frameCount);
    }

    if (itemToSelect && model_)
    {
        const QModelIndex ix = model_->indexFromItem(itemToSelect);
        tree_->setCurrentIndex(ix);
    }
    tree_->blockSignals(signalsWereBlocked);
}

void LuaDebuggerStackController::onCurrentItemChanged(const QModelIndex &current, const QModelIndex &previous)
{
    Q_UNUSED(previous);
    if (!tree_ || !model_ || !current.isValid() || !host_->isDebuggerPaused() || !wslua_debugger_is_paused())
    {
        return;
    }
    QStandardItem *const rowItem = model_->itemFromIndex(current.sibling(current.row(), 0));
    if (!rowItem)
    {
        return;
    }

    const int level = static_cast<int>(rowItem->data(StackItemLevelRole).toLongLong());
    if (level < 0 || level == selectionLevel_)
    {
        return;
    }

    selectionLevel_ = level;
    wslua_debugger_set_variable_stack_level(static_cast<int32_t>(level));
    host_->refreshVariablesForCurrentStackFrame();
    host_->syncVariablesTreeToCurrentWatch();
}

void LuaDebuggerStackController::onItemDoubleClicked(const QModelIndex &index)
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
    if (!item->data(StackItemNavigableRole).toBool())
    {
        return;
    }
    const QString file = item->data(StackItemFileRole).toString();
    const qint64 line = item->data(StackItemLineRole).toLongLong();
    if (file.isEmpty() || line <= 0)
    {
        return;
    }
    LuaDebuggerCodeView *view = host_->codeTabsController().loadFile(file);
    if (view)
    {
        view->moveCaretToLineStart(static_cast<qint32>(line));
    }
}

void LuaDebuggerStackController::showContextMenu(const QPoint &pos)
{
    if (!tree_ || !model_)
    {
        return;
    }
    const QModelIndex ix = tree_->indexAt(pos);
    if (!ix.isValid())
    {
        return;
    }
    QStandardItem *item = model_->itemFromIndex(ix.sibling(ix.row(), 0));
    if (!item)
    {
        return;
    }

    const bool navigable = item->data(StackItemNavigableRole).toBool();
    const QString file = item->data(StackItemFileRole).toString();
    const qint64 line = item->data(StackItemLineRole).toLongLong();

    QMenu menu(host_);
    QAction *openAct = menu.addAction(QObject::tr("Open Source"));
    openAct->setEnabled(navigable && !file.isEmpty() && line > 0);
    QAction *copyLocAct = menu.addAction(QObject::tr("Copy Location"));
    copyLocAct->setEnabled(!file.isEmpty() && line > 0);

    QAction *chosen = menu.exec(tree_->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }
    if (chosen == openAct && openAct->isEnabled())
    {
        LuaDebuggerCodeView *view = host_->codeTabsController().loadFile(file);
        if (view)
        {
            view->moveCaretToLineStart(static_cast<qint32>(line));
        }
        return;
    }
    if (chosen == copyLocAct && copyLocAct->isEnabled())
    {
        if (QClipboard *clip = QGuiApplication::clipboard())
        {
            clip->setText(QStringLiteral("%1:%2").arg(file).arg(line));
        }
    }
}

/* ===== dialog_stack (LuaDebuggerDialog members) ===== */

CollapsibleSection *LuaDebuggerDialog::createStackSection(QWidget *parent)
{
    stackSection = new CollapsibleSection(tr("Stack Trace"), parent);
    stackModel = new QStandardItemModel(this);
    stackModel->setColumnCount(StackColumn::Count);
    stackModel->setHorizontalHeaderLabels({tr("Function"), tr("Location")});
    stackTree = new QTreeView();
    stackTree->setModel(stackModel);
    stackTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    stackTree->setRootIsDecorated(true);
    stackTree->setToolTip(tr("Select a row to inspect locals and upvalues for that frame. "
                             "Double-click a Lua frame to open its source location."));
    stackSection->setContentWidget(stackTree);
    stackSection->setExpanded(true);
    return stackSection;
}

void LuaDebuggerDialog::wireStackPanel()
{
    stackController_.attach(stackTree, stackModel);
    connect(stackTree, &QTreeView::doubleClicked, &stackController_, &LuaDebuggerStackController::onItemDoubleClicked);
    connect(stackTree->selectionModel(), &QItemSelectionModel::currentChanged, &stackController_,
            &LuaDebuggerStackController::onCurrentItemChanged);
    stackTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(stackTree, &QTreeView::customContextMenuRequested, &stackController_,
            &LuaDebuggerStackController::showContextMenu);
}

void LuaDebuggerDialog::resetStackForPauseEntry()
{
    stackController_.setSelectionLevel(0);
    /* Anchor the changed-value cue to the level we're about to paint at;
     * intra-pause stack-frame switches will compare the active selection
     * level against this and suppress the cue at every other level (see
     * changeHighlightAllowed()). */
    changeHighlight_.setPauseEntryStackLevel(stackController_.selectionLevel());
    stackController_.updateFromEngine();
}

void LuaDebuggerDialog::clearStackPanel()
{
    if (stackModel)
    {
        stackModel->removeRows(0, stackModel->rowCount());
    }
}
