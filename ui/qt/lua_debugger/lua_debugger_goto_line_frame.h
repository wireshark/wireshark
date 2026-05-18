/* lua_debugger_goto_line_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Inline go-to-line bar for the Lua debugger code editor.
 */

#ifndef LUA_DEBUGGER_GOTO_LINE_FRAME_H
#define LUA_DEBUGGER_GOTO_LINE_FRAME_H

#include <QPointer>

#include "accordion_frame.h"

class QKeyEvent;
class QPlainTextEdit;

namespace Ui
{
class LuaDebuggerGoToLineFrame;
}

/**
 * @brief Inline "go to line" bar for the Lua debugger code editor (AccordionFrame).
 */
class LuaDebuggerGoToLineFrame : public AccordionFrame
{
    Q_OBJECT

  public:
    /**
     * @brief Constructs a new LuaDebuggerGoToLineFrame object.
     * @param parent The parent widget.
     */
    explicit LuaDebuggerGoToLineFrame(QWidget *parent = nullptr);

    /**
     * @brief Destroys the LuaDebuggerGoToLineFrame object.
     */
    ~LuaDebuggerGoToLineFrame() override;

    /**
     * @brief Sets the target editor for the go to line frame.
     * @param editor Pointer to the target QPlainTextEdit.
     */
    void setTargetEditor(QPlainTextEdit *editor);

    /** @brief Set the line field from the current editor cursor (before animatedShow). */
    void syncLineFieldFromEditor();

    /** @brief After animatedShow(), move focus to the line field (call from dialog). */
    void scheduleLineFieldFocus();

  protected:
    /**
     * @brief Handles key press events for the frame.
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event) override;

  private:
    /** @brief Pointer to the UI object for this frame. */
    Ui::LuaDebuggerGoToLineFrame *ui_;

    /** @brief Pointer to the active target code editor. */
    QPointer<QPlainTextEdit> editor_;

    /**
     * @brief Focuses the line input field.
     */
    void focusLineField();

  private slots:
    /**
     * @brief Handles the event when the go button is clicked.
     */
    void on_goButton_clicked();

    /**
     * @brief Handles the event when the cancel button is clicked.
     */
    void on_cancelButton_clicked();
};

#endif // LUA_DEBUGGER_GOTO_LINE_FRAME_H
