/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIELDFILTEREDIT_H
#define FIELDFILTEREDIT_H

#include <ui/qt/widgets/syntax_line_edit.h>

class QEvent;
class StockIconToolButton;

/**
 * @brief A specialized line edit for entering and validating field filters with auto-completion.
 */
class FieldFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new FieldFilterEdit.
     * @param parent The parent widget, defaults to 0.
     */
    explicit FieldFilterEdit(QWidget *parent = 0);

protected:
    /**
     * @brief Handles key press events, routing them to completion logic.
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event) override { completionKeyPressEvent(event); }

    /**
     * @brief Handles focus in events, triggering completion logic if necessary.
     * @param event The focus event.
     */
    void focusInEvent(QFocusEvent *event) override { completionFocusInEvent(event); }

    /**
     * @brief Handles focus out events.
     * @param event The focus event.
     */
    void focusOutEvent(QFocusEvent *event) override;

public slots:
    /**
     * @brief Checks the validity of the current filter text.
     * @return True if the filter is valid, false otherwise.
     */
    bool checkFilter();

private slots:
    /**
     * @brief Checks the validity of a specific filter string.
     * @param filter_text The filter text to validate.
     */
    void checkFilter(const QString &filter_text);

    /**
     * @brief Handles widget state change events.
     * @param event The change event.
     */
    void changeEvent(QEvent* event) override;

private:
    /** The default placeholder text displayed when the line edit is empty. */
    QString placeholder_text_;

    /**
     * @brief Sets the default placeholder text for the line edit.
     */
    void setDefaultPlaceholderText();

    /**
     * @brief Builds the auto-completion list based on the current input.
     * @param field_word The current word being typed.
     * @param preamble The text preceding the current word.
     */
    void buildCompletionList(const QString &field_word, const QString &preamble) override;

signals:
    /**
     * @brief Signal emitted to display a syntax status message.
     * @param status The status message string.
     */
    void pushFilterSyntaxStatus(const QString& status);

    /**
     * @brief Signal emitted to remove or pop the current syntax status message.
     */
    void popFilterSyntaxStatus();

    /**
     * @brief Signal emitted to display a syntax warning message.
     * @param warning The warning message string.
     */
    void pushFilterSyntaxWarning(const QString& warning);
};

#endif // FIELDFILTEREDIT_H
