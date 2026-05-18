/* lua_debugger_variables.h
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

#ifndef LUA_DEBUGGER_VARIABLES_H
#define LUA_DEBUGGER_VARIABLES_H

#include <QHash>
#include <QObject>
#include <QString>

#include "lua_debugger_utils.h"

class LuaDebuggerDialog;
class QModelIndex;
class QPoint;
class QStandardItem;
class QStandardItemModel;
class QTreeView;

/** @brief Column indices for the Variables tree model. */
namespace VariablesColumn
{
constexpr int Name = 0;
constexpr int Value = 1;
constexpr int Type = 2;
constexpr int Count = 3;
} // namespace VariablesColumn

/**
 * @brief Variables panel: column sizing, expansion persistence, lazy child
 *        fill on expand, context menu, and selection helpers.
 */
class LuaDebuggerVariablesController : public QObject
{
    Q_OBJECT

  public:
    /**
     * @brief Constructs a new LuaDebuggerVariablesController object.
     * @param host Pointer to the hosting Lua debugger dialog.
     */
    explicit LuaDebuggerVariablesController(LuaDebuggerDialog *host);

    /**
     * @brief Attaches the controller to the given tree view and model.
     * @param tree Pointer to the tree view for displaying variables.
     * @param model Pointer to the item model for variables.
     */
    void attach(QTreeView *tree, QStandardItemModel *model);

    /**
     * @brief Configures the tree view columns for the variables panel.
     */
    void configureColumns() const;

    /**
     * @brief Re-expand Locals/Globals/Upvalues after a variables refresh.
     */
    void restoreExpansionState() const;

    /**
     * @brief Clear the model, re-fetch Locals/Globals/Upvalues from the engine,
     *  and re-apply persisted expansion.
     */
    void rebuildFromEngine();

    /**
     * @brief Append children of @p path under @p parent (or as new top-level
     *  rows when @p parent is null). Used by @ref rebuildFromEngine for the
     *  initial Locals/Globals/Upvalues fetch and by @ref onExpanded for
     *  lazy descent into nested tables. Reaches back to the dialog for
     *  change-highlight baselines and the active stack frame.
     * @param parent The parent standard item to append to, or nullptr for top-level.
     * @param path The path string indicating the variable to fetch.
     */
    void fetchAndAppend(QStandardItem *parent, const QString &path);

    /**
     * @brief Finds a tree item based on its path.
     * @param path The path of the item to find.
     * @return Pointer to the found QStandardItem, or nullptr if not found.
     */
    QStandardItem *findItemByPath(const QString &path) const;

    /**
     * @brief Retrieves the mutable expansion state map.
     * @return Reference to the hash map storing tree section expansion states.
     */
    QHash<QString, LuaDbgTreeSectionExpansionState> &expansionMap() { return expansion_; }

    /**
     * @brief Retrieves the read-only expansion state map.
     * @return Const reference to the hash map storing tree section expansion states.
     */
    const QHash<QString, LuaDbgTreeSectionExpansionState> &expansionMap() const { return expansion_; }

  public slots:
    /**
     * @brief Displays the context menu for the variables tree.
     * @param pos The point where the context menu should be displayed.
     */
    void showContextMenu(const QPoint &pos);

    /**
     * @brief Handles the event when a tree node is expanded.
     * @param index The model index of the expanded item.
     */
    void onExpanded(const QModelIndex &index);

    /**
     * @brief Handles the event when a tree node is collapsed.
     * @param index The model index of the collapsed item.
     */
    void onCollapsed(const QModelIndex &index);

  private:
    /** @brief Pointer to the hosting Lua debugger dialog. */
    LuaDebuggerDialog *host_ = nullptr;

    /** @brief Pointer to the variables tree view. */
    QTreeView *tree_ = nullptr;

    /** @brief Pointer to the variables item model. */
    QStandardItemModel *model_ = nullptr;

    /** @brief Hash map storing the expansion state of tree nodes. */
    QHash<QString, LuaDbgTreeSectionExpansionState> expansion_;
};

#endif
