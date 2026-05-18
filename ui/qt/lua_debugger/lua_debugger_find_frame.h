/* lua_debugger_find_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Inline find / replace bar for the Lua debugger code editor.
 */

#ifndef LUA_DEBUGGER_FIND_FRAME_H
#define LUA_DEBUGGER_FIND_FRAME_H

#include <QPointer>

#include "accordion_frame.h"

class QEvent;
class QKeyEvent;
class QPlainTextEdit;

namespace Ui
{
class LuaDebuggerFindFrame;
}

/**
 * @brief Inline find/replace bar for the Lua debugger code editor (AccordionFrame).
 */
class LuaDebuggerFindFrame : public AccordionFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the find/replace bar.
     * @param parent The parent widget.
     */
    explicit LuaDebuggerFindFrame(QWidget *parent = nullptr);

    /**
     * @brief Destroys the find/replace bar.
     */
    ~LuaDebuggerFindFrame() override;

    /**
     * @brief Sets the code editor that find/replace operations act upon.
     * @param editor The target QPlainTextEdit, or nullptr to detach.
     */
    void setTargetEditor(QPlainTextEdit *editor);

    /**
     * @brief After animatedShow(), move focus to the find field (call from dialog).
     */
    void scheduleFindFieldFocus();

protected:
    /**
     * @brief Intercepts events on watched objects to handle editor-side keyboard shortcuts.
     * @param watched The object whose events are being monitored.
     * @param event   The event to inspect.
     * @return True if the event was consumed, false to allow normal processing.
     */
    bool eventFilter(QObject *watched, QEvent *event) override;

    /**
     * @brief Handles key presses within the bar (e.g. Enter to find next, Escape to close).
     * @param event The key press event.
     */
    void keyPressEvent(QKeyEvent *event) override;

private:
    /** @brief Qt Designer-generated UI members. */
    Ui::LuaDebuggerFindFrame *ui_;

    /** @brief Weak reference to the target editor; cleared automatically if the editor is destroyed. */
    QPointer<QPlainTextEdit> editor_;

    /**
     * @brief Moves keyboard focus to the find input field.
     */
    void focusFindField();

    /**
     * @brief Searches the target editor for the current find text.
     * @param backward If true, searches backward from the current cursor position.
     */
    void findNext(bool backward);

    /**
     * @brief Checks whether the editor's current selection matches the find text.
     * @return True if the selection equals the current find text (respecting match options).
     */
    bool selectionMatchesFind() const;

    /**
     * @brief Replaces all occurrences of the find text with the replacement text in the editor.
     */
    void replaceAll();

private slots:
    /**
     * @brief Handles the Find Next button click, advancing to the next match.
     */
    void on_findNextButton_clicked();

    /**
     * @brief Handles the Find Previous button click, retreating to the previous match.
     */
    void on_findPreviousButton_clicked();

    /**
     * @brief Handles the Replace button click, replacing the current match and advancing.
     */
    void on_replaceButton_clicked();

    /**
     * @brief Handles the Replace All button click, replacing every match in the editor.
     */
    void on_replaceAllButton_clicked();

    /**
     * @brief Handles the Close button click, hiding the find/replace bar.
     */
    void on_closeButton_clicked();
};

#endif // LUA_DEBUGGER_FIND_FRAME_H
