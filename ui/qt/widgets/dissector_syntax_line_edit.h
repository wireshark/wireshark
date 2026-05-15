/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISSECTOR_SYNTAX_LINEEDIT_H
#define DISSECTOR_SYNTAX_LINEEDIT_H

#include <ui/qt/widgets/syntax_line_edit.h>

class QEvent;
class StockIconToolButton;

/**
 * @brief A line edit widget that provides syntax validation and auto-completion for dissector names.
 */
class DissectorSyntaxLineEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DissectorSyntaxLineEdit widget.
     * @param parent The parent widget, defaults to 0.
     */
    explicit DissectorSyntaxLineEdit(QWidget *parent = 0);

    /**
     * @brief Updates the internal list of available dissector names used for validation and completion.
     */
    void updateDissectorNames();

    /**
     * @brief Sets the default placeholder text for the line edit widget.
     */
    void setDefaultPlaceholderText();

protected:
    /**
     * @brief Handles key press events, forwarding them to the auto-completion logic.
     * @param event The key press event.
     */
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }

    /**
     * @brief Handles focus in events, forwarding them to the auto-completion logic.
     * @param event The focus event.
     */
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }

public slots:
    /**
     * @brief Validates the syntax of the provided dissector name string.
     * @param dissector The dissector name string to check.
     */
    void checkDissectorName(const QString &dissector);

private slots:
    /**
     * @brief Handles general state change events for the widget.
     * @param event The state change event.
     */
    void changeEvent(QEvent* event);

private:
    /** The placeholder text displayed when the line edit is empty. */
    QString placeholder_text_;

    /**
     * @brief Builds the list of auto-completion suggestions.
     * @param field_word The word currently being typed.
     * @param preamble The text preceding the current word.
     */
    void buildCompletionList(const QString &field_word, const QString &preamble);
};

#endif // DISSECTOR_SYNTAX_LINEEDIT_H
