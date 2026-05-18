/* lua_debugger_stack.h
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

#ifndef LUA_DEBUGGER_STACK_H
#define LUA_DEBUGGER_STACK_H

#include <QObject>

#include "lua_debugger_utils.h"

class LuaDebuggerDialog;
class QModelIndex;
class QPoint;
class QStandardItemModel;
class QTreeView;

/** @brief Column indices for the Stack Trace tree model. */
namespace StackColumn
{
constexpr int Function = 0;
constexpr int Location = 1;
constexpr int Count = 2;
} // namespace StackColumn

/**
 * @brief Stack trace panel: column layout, rebuild from the engine, selection
 *        → variables frame, open-source gestures, and context menu.
 */
class LuaDebuggerStackController : public QObject
{
    Q_OBJECT

  public:
    /**
     * @brief Constructs a new LuaDebuggerStackController object.
     * @param host Pointer to the hosting Lua debugger dialog.
     */
    explicit LuaDebuggerStackController(LuaDebuggerDialog *host);

    /**
     * @brief Attaches the controller to the given tree view and model.
     * @param tree Pointer to the tree view displaying the stack.
     * @param model Pointer to the item model storing the stack data.
     */
    void attach(QTreeView *tree, QStandardItemModel *model);

    /**
     * @brief Configures the tree view columns for the stack trace panel.
     */
    void configureColumns() const;

    /** @brief Rebuild rows from @c wslua_debugger_get_stack. */
    void updateFromEngine();

    /** @brief Stack frame index whose locals/upvalues currently drive the
     *  Variables and Watch panels (0 = topmost / paused frame). Owned here
     *  because every panel that needs it is downstream of stack selection.
     *  @return The currently selected stack level.
     */
    int selectionLevel() const { return selectionLevel_; }

    /** @brief Update the active stack frame index. Does not refresh anything;
     *  callers are expected to follow up with the appropriate variable/watch
     *  refresh.
     *  @param level The new stack selection level.
     */
    void setSelectionLevel(int level) { selectionLevel_ = level; }

  public slots:
    /**
     * @brief Handles the event when the current item in the stack tree changes.
     * @param current The newly selected model index.
     * @param previous The previously selected model index.
     */
    void onCurrentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Handles the event when an item in the stack tree is double-clicked.
     * @param index The model index of the double-clicked item.
     */
    void onItemDoubleClicked(const QModelIndex &index);

    /**
     * @brief Displays the context menu for the stack tree.
     * @param pos The point where the context menu should be displayed.
     */
    void showContextMenu(const QPoint &pos);

  private:
    /** @brief Pointer to the hosting Lua debugger dialog. */
    LuaDebuggerDialog *host_ = nullptr;

    /** @brief Pointer to the stack trace tree view. */
    QTreeView *tree_ = nullptr;

    /** @brief Pointer to the stack trace item model. */
    QStandardItemModel *model_ = nullptr;

    /** @brief The currently selected stack frame index. */
    int selectionLevel_ = 0;
};

#endif
