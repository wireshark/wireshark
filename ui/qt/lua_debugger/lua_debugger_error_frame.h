/* lua_debugger_error_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Inline error details bar for the Lua debugger code editor.
 */

#ifndef LUA_DEBUGGER_ERROR_FRAME_H
#define LUA_DEBUGGER_ERROR_FRAME_H

#include <QFrame>

namespace Ui
{
class LuaDebuggerErrorFrame;
}

class QKeyEvent;

/**
 * @brief Inline error details bar for paused break-on-error states.
 */
class LuaDebuggerErrorFrame : public QFrame
{
    Q_OBJECT

  public:
    explicit LuaDebuggerErrorFrame(QWidget *parent = nullptr);
    ~LuaDebuggerErrorFrame() override;

    void setErrorMessage(const QString &message);
    void setEditorStyleFont(const QFont &font);
    void clearErrorContent();

    /** @brief After show(), move focus to the text box. */
    void schedulePrimaryFocus();

  protected:
    void keyPressEvent(QKeyEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void showEvent(QShowEvent *event) override;

  private:
    Ui::LuaDebuggerErrorFrame *ui_;

    void focusPrimaryControl();
    void updateCompactHeight();
};

#endif // LUA_DEBUGGER_ERROR_FRAME_H
