/* lua_debugger.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Public entry points for the Lua debugger UI. The only header consumed
 * outside the lua_debugger module.
 */

#ifndef LUA_DEBUGGER_H
#define LUA_DEBUGGER_H

class QWidget;
class QCloseEvent;

namespace LuaDebugger
{

/** Open (creating on first call) the Lua debugger dialog and bring it to the front. */
void open(QWidget *parent);

/** If the debugger is paused or owns unsaved scripts, defer the supplied
 *  main-window close event so the Lua C stack can unwind first.
 *  @return @c true when the close was deferred (caller should return without
 *          further teardown), @c false to let the main window proceed normally. */
bool tryDeferMainWindowClose(QCloseEvent *event);

/** Force the debugger off while the Preferences dialog is open, the same way
 *  as during a live capture, and restore the user's choice when it closes.
 *  @param suppressed @c true when the dialog opens, @c false when it closes. */
void setSuppressedByPreferences(bool suppressed);

} // namespace LuaDebugger

#endif
