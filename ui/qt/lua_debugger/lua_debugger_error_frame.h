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
    /**
     * @brief Constructs the error frame with an empty error state.
     * @param parent Optional parent widget.
     */
    explicit LuaDebuggerErrorFrame(QWidget *parent = nullptr);

    /**
     * @brief Destroys the error frame and releases all owned resources.
     */
    ~LuaDebuggerErrorFrame() override;

    /**
     * @brief Displays @p message as the current Lua error text.
     * @param message Error string to show in the error text box.
     */
    void setErrorMessage(const QString &message);

    /**
     * @brief Synchronises the error text box font with the Lua editor.
     * @param font Font currently in use by the Lua editor widget.
     */
    void setEditorStyleFont(const QFont &font);

    /**
     * @brief Clears the displayed error message and resets the frame to its empty state.
     */
    void clearErrorContent();

    /**
     * @brief After show(), move focus to the text box.
     */
    void schedulePrimaryFocus();

protected:
    /**
     * @brief Handles key-press events; closes the frame on Escape.
     * @param event The key-press event to process.
     */
    void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Recalculates the compact height of the frame when its width changes.
     * @param event The resize event containing the new size.
     */
    void resizeEvent(QResizeEvent *event) override;

    /**
     * @brief Schedules focus transfer to the primary control when the frame becomes visible.
     * @param event The show event.
     */
    void showEvent(QShowEvent *event) override;

private:
    Ui::LuaDebuggerErrorFrame *ui_; /**< Qt Designer-generated UI object. */

    /**
     * @brief Transfers keyboard focus to the error text box.
     */
    void focusPrimaryControl();

    /**
     * @brief Adjusts the frame's fixed height to the minimum needed to display
     *        the current error text without a scrollbar at the current width.
     */
    void updateCompactHeight();
};

#endif // LUA_DEBUGGER_ERROR_FRAME_H
