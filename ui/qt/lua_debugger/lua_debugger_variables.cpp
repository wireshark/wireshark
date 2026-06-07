/* lua_debugger_variables.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Variables panel: Locals / Upvalues / Globals tree, lazy expansion.
 */

#include "lua_debugger_variables.h"

#include <QClipboard>
#include <QGuiApplication>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QMenu>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTreeView>

#include <glib.h>

#include "lua_debugger_dialog.h"
#include "lua_debugger_utils.h"
#include "widgets/collapsible_section.h"
#include <epan/wslua/wslua_debugger.h>

using namespace LuaDebuggerItems;
using namespace LuaDebuggerPath;

/* ===== variables_controller ===== */

void LuaDebuggerVariablesController::attach(QTreeView *tree, QStandardItemModel *model)
{
    tree_ = tree;
    model_ = model;
}

LuaDebuggerVariablesController::LuaDebuggerVariablesController(LuaDebuggerDialog *host) : QObject(host), host_(host) {}

void LuaDebuggerVariablesController::configureColumns() const
{
    if (!tree_ || !model_ || !tree_->header())
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

void LuaDebuggerVariablesController::rebuildFromEngine()
{
    if (model_)
    {
        model_->removeRows(0, model_->rowCount());
    }
    fetchAndAppend(nullptr, QString());
    restoreExpansionState();
}

void LuaDebuggerVariablesController::fetchAndAppend(QStandardItem *parent, const QString &path)
{
    if (!model_)
    {
        return;
    }
    int32_t variableCount = 0;
    wslua_variable_t *variables =
        wslua_debugger_get_variables(path.isEmpty() ? NULL : path.toUtf8().constData(), &variableCount);

    /* "First-time expansion" guard for the new-child flash: the children
     * about to be appended belong to @p path, and a child absent from
     * baseline is only meaningfully "new" if @p path was *visited* (and
     * therefore its then-children captured) at the previous pause. The
     * tracker records visited-parent identity in a companion set that
     * rotates at pause entry. Scanning baseline value keys by prefix
     * cannot answer this question: a parent that was expanded last
     * pause but had no children to show (e.g. a function with no
     * locals yet, an empty table) would look identical to one that was
     * collapsed, so the FIRST child appearing now could never flash.
     * The level matches the one used for the child keys (Globals anchor
     * to -1, everything else follows the current stack frame). */
    const int parentChildLevel = variablesPathIsGlobalScoped(path) ? -1 : host_->stackController().selectionLevel();
    const QString parentVisitedKey = changeKey(parentChildLevel, path);
    const bool parentVisitedInBaseline = host_->changeHighlight().observeVariablesParent(parentVisitedKey);

    if (variables)
    {
        for (int32_t variableIndex = 0; variableIndex < variableCount; ++variableIndex)
        {
            auto *nameItem = new QStandardItem();
            auto *valueItem = new QStandardItem();
            auto *typeItem = new QStandardItem();

            const VariableRowFields f = readVariableRowFields(variables[variableIndex], path);

            nameItem->setText(f.name);
            valueItem->setText(f.value);
            typeItem->setText(f.type);

            const QString tooltipSuffix = f.type.isEmpty() ? QString() : QObject::tr("Type: %1").arg(f.type);
            nameItem->setToolTip(tooltipSuffix.isEmpty() ? f.name
                                                         : QStringLiteral("%1\n%2").arg(f.name, tooltipSuffix));
            valueItem->setToolTip(tooltipSuffix.isEmpty() ? f.value
                                                          : QStringLiteral("%1\n%2").arg(f.value, tooltipSuffix));
            typeItem->setToolTip(tooltipSuffix.isEmpty() ? f.type
                                                         : QStringLiteral("%1\n%2").arg(f.type, tooltipSuffix));
            nameItem->setData(f.type, VariableTypeRole);
            nameItem->setData(f.canExpand, VariableCanExpandRole);
            nameItem->setData(f.childPath, VariablePathRole);

            for (QStandardItem *cell : {nameItem, valueItem, typeItem})
            {
                cell->setFlags(cell->flags() & ~Qt::ItemIsEditable);
            }

            if (parent)
            {
                parent->appendRow({nameItem, valueItem, typeItem});
            }
            else
            {
                model_->appendRow({nameItem, valueItem, typeItem});
            }

            /* Scope Globals watchers by level=-1 so changing the selected
             * stack frame does not invalidate a Globals baseline. All other
             * paths are scoped by the current stack level. */
            const bool isGlobal = variablesPathIsGlobalScoped(f.childPath);
            const int level = isGlobal ? -1 : host_->stackController().selectionLevel();
            const QString vk = changeKey(level, f.childPath);
            /* flashNew=parentVisitedInBaseline: a variable absent from
             * the previous pause's snapshot but present now is "new" (e.g.
             * a fresh local binding, a key added to a table, a new upvalue)
             * and gets the same visual cue as a value change — but ONLY
             * when @p path itself was painted at the previous pause.
             * Otherwise this is a first-time expansion and treating every
             * child as "new" would be visual noise, not information.
             *
             * Non-Globals comparisons are also gated on
             * changeHighlightAllowed(): walking to a different stack frame
             * inside the same pause shows locals/upvalues from an unrelated
             * scope where comparing against the pause-entry baseline at the
             * same numeric level would either flag every variable as "new"
             * or compare against an unrelated previous-pause snapshot. The
             * cue resumes automatically when the user navigates back to the
             * pause-entry frame. Globals are anchored to level=-1 and stay
             * comparable across frames, so they keep their highlight. */
            const bool baselineChanged = host_->changeHighlight().observeVariablesValue(
                vk, f.value, /*parentVisited=*/parentVisitedInBaseline);
            const bool changed = (isGlobal || host_->changeHighlightAllowed()) && baselineChanged;
            host_->applyChangedVisuals(nameItem, changed);

            applyVariableExpansionIndicator(nameItem, f.canExpand,
                                            /*enabledOnlyPlaceholder=*/false);
        }
        // Sort Globals alphabetically; preserve declaration order for
        // Locals and Upvalues since that is more natural for debugging.
        if (variableChildrenShouldSortByName(path))
        {
            if (parent)
            {
                parent->sortChildren(0, Qt::AscendingOrder);
            }
            else
            {
                model_->sort(0, Qt::AscendingOrder);
            }
        }

        wslua_debugger_free_variables(variables, variableCount);
    }
}

void LuaDebuggerVariablesController::restoreExpansionState() const
{
    if (!tree_ || !model_)
    {
        return;
    }
    for (int i = 0; i < model_->rowCount(); ++i)
    {
        QStandardItem *root = model_->item(i);
        const QString section = root->data(VariablePathRole).toString();
        if (section.isEmpty())
        {
            continue;
        }
        bool rootExpanded = false;
        QStringList subpaths;
        const auto it = expansion_.constFind(section);
        if (it == expansion_.cend())
        {
            if (section == QLatin1String("Locals"))
            {
                rootExpanded = true;
            }
        }
        else
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
            reexpandTreeDescendantsByPathKeys(tree_, model_, root, subpaths, findVariableTreeItemByPathKey);
        }
    }
}

QStandardItem *LuaDebuggerVariablesController::findItemByPath(const QString &path) const
{
    if (!tree_ || path.isEmpty())
    {
        return nullptr;
    }
    const int top = model_->rowCount();
    for (int i = 0; i < top; ++i)
    {
        QStandardItem *r = findVariableItemByPathRecursive(model_->item(i, VariablesColumn::Name), path);
        if (r)
        {
            return r;
        }
    }
    return nullptr;
}

void LuaDebuggerVariablesController::showContextMenu(const QPoint &pos)
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
    QStandardItem *item = model_->itemFromIndex(ix.sibling(ix.row(), VariablesColumn::Name));
    if (!item)
    {
        return;
    }

    const QString nameText = item->text();
    const QString valueText = text(model_, item, VariablesColumn::Value);
    const QString bothText = valueText.isEmpty() ? nameText : QObject::tr("%1 = %2").arg(nameText, valueText);

    const QString varPath = item->data(VariablePathRole).toString();

    QMenu menu(host_);
    QAction *copyName = menu.addAction(QObject::tr("Copy Name"));
    QAction *copyValue = menu.addAction(QObject::tr("Copy Value"));
    QAction *copyPath = nullptr;
    if (!varPath.isEmpty())
    {
        copyPath = menu.addAction(QObject::tr("Copy Path"));
    }
    QAction *copyNameValue = menu.addAction(QObject::tr("Copy Name && Value"));

    auto copyToClipboard = [](const QString &text)
    {
        if (QClipboard *clipboard = QGuiApplication::clipboard())
        {
            clipboard->setText(text);
        }
    };

    QObject::connect(copyName, &QAction::triggered, host_,
                     [copyToClipboard, nameText]() { copyToClipboard(nameText); });
    QObject::connect(copyValue, &QAction::triggered, host_,
                     [copyToClipboard, valueText]() { copyToClipboard(valueText); });
    if (copyPath)
    {
        QObject::connect(copyPath, &QAction::triggered, host_,
                         [copyToClipboard, varPath]() { copyToClipboard(varPath); });
    }
    QObject::connect(copyNameValue, &QAction::triggered, host_,
                     [copyToClipboard, bothText]() { copyToClipboard(bothText); });

    menu.addSeparator();
    if (!varPath.isEmpty())
    {
        QAction *addWatch =
            menu.addAction(QObject::tr("Add Watch: \"%1\"")
                               .arg(varPath.length() > 48 ? varPath.left(48) + QStringLiteral("…") : varPath));
        QObject::connect(addWatch, &QAction::triggered, host_,
                         [host = host_, varPath]() { host->addWatchFromSpec(varPath); });
    }

    menu.exec(tree_->viewport()->mapToGlobal(pos));
}

void LuaDebuggerVariablesController::onExpanded(const QModelIndex &index)
{
    if (!model_ || !index.isValid())
    {
        return;
    }
    QStandardItem *item = model_->itemFromIndex(index.sibling(index.row(), VariablesColumn::Name));
    if (!item)
    {
        return;
    }
    const QString section = variableSectionRootKeyFromItem(item);
    if (!item->parent())
    {
        luaDbgRecordTreeSectionRootExpansion(expansion_, section, true);
    }
    else
    {
        const QString key = item->data(VariablePathRole).toString();
        luaDbgRecordTreeSectionSubpathExpansion(expansion_, section, key, true);
    }

    if (item->rowCount() == 1 && item->child(0) && item->child(0)->text().isEmpty())
    {
        item->removeRow(0);

        QString varPath = item->data(VariablePathRole).toString();
        fetchAndAppend(item, varPath);
    }
}

void LuaDebuggerVariablesController::onCollapsed(const QModelIndex &index)
{
    if (!model_ || !index.isValid())
    {
        return;
    }
    QStandardItem *item = model_->itemFromIndex(index.sibling(index.row(), VariablesColumn::Name));
    if (!item)
    {
        return;
    }
    const QString section = variableSectionRootKeyFromItem(item);
    if (!item->parent())
    {
        luaDbgRecordTreeSectionRootExpansion(expansion_, section, false);
    }
    else
    {
        const QString key = item->data(VariablePathRole).toString();
        luaDbgRecordTreeSectionSubpathExpansion(expansion_, section, key, false);
    }
}

/* ===== dialog_variables (LuaDebuggerDialog members) ===== */

CollapsibleSection *LuaDebuggerDialog::createVariablesSection(QWidget *parent)
{
    variablesSection = new CollapsibleSection(tr("Variables"), parent);
    variablesSection->setToolTip(tr("<p><b>Locals</b><br/>"
                                    "Parameters and local variables for the selected stack frame.</p>"
                                    "<p><b>Upvalues</b><br/>"
                                    "Outer variables that this function actually uses from surrounding code. "
                                    "Anything the function does not reference does not appear here.</p>"
                                    "<p><b>Globals</b><br/>"
                                    "Names from the global environment table.</p>"
                                    "<p>Values that differ from the previous pause are drawn in a "
                                    "<b>bold accent color</b>, and briefly flash on the pause that "
                                    "introduced the change.</p>"));
    variablesModel = new QStandardItemModel(this);
    variablesModel->setColumnCount(VariablesColumn::Count);
    variablesModel->setHorizontalHeaderLabels({tr("Name"), tr("Value"), tr("Type")});
    variablesTree = new QTreeView();
    variablesTree->setModel(variablesModel);
    /* Type is folded into Name/Value tooltips; keep the column for model data. */
    variablesTree->setColumnHidden(VariablesColumn::Type, true);
    variablesTree->setItemDelegate(new LuaDbgVariablesReadOnlyDelegate(variablesTree));
    variablesTree->setUniformRowHeights(true);
    variablesTree->setWordWrap(false);
    variablesSection->setContentWidget(variablesTree);
    variablesSection->setExpanded(true);
    return variablesSection;
}

void LuaDebuggerDialog::wireVariablesPanel()
{
    variablesController_.attach(variablesTree, variablesModel);
    connect(variablesTree, &QTreeView::expanded, &variablesController_, &LuaDebuggerVariablesController::onExpanded);
    connect(variablesTree, &QTreeView::collapsed, &variablesController_, &LuaDebuggerVariablesController::onCollapsed);
    variablesTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(variablesTree, &QTreeView::customContextMenuRequested, &variablesController_,
            &LuaDebuggerVariablesController::showContextMenu);
    connect(variablesTree->selectionModel(), &QItemSelectionModel::currentChanged, this,
            &LuaDebuggerDialog::onVariablesCurrentItemChanged);
}

void LuaDebuggerDialog::refreshVariablesForCurrentStackFrame()
{
    if (!variablesTree || !debuggerPaused || !wslua_debugger_is_paused())
    {
        return;
    }
    variablesController_.rebuildFromEngine();
    watchController_.refreshDisplay();
}
