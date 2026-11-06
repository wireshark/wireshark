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

    /**
     * @brief Switches between single field mode (default) and list mode.
     *
     * In list mode the text is a comma separated list of fields or protocol
     * names; each one is validated and completed separately.
     * @param enabled True for list mode.
     */
    void setFieldListMode(bool enabled);

    /**
     * @brief Sets the maximum number of fields accepted in list mode.
     * @param max_fields The limit, 0 for no limit.
     */
    void setMaxFields(int max_fields);

    /**
     * @brief Returns the entered fields.
     * @return In list mode the non-empty, trimmed tokens; in single mode the
     * trimmed text, or an empty list when it is empty.
     */
    QStringList fieldList() const;

    /**
     * @brief Returns the message of the last list mode check.
     * @return The error or deprecation message, empty when the list is
     * valid or empty.
     */
    QString fieldListMessage() const { return list_message_; }

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

    /** True when the text is a comma separated list of fields. */
    bool list_mode_ = false;

    /** The field limit in list mode, 0 for no limit. */
    int max_fields_ = 0;

    /** The message of the last list mode check. */
    QString list_message_;

    /**
     * @brief Splits list mode text at commas.
     * @param text The line edit text.
     * @return An empty list for blank text, else all trimmed tokens, empty ones included.
     */
    static QStringList splitFieldList(const QString &text);

    /**
     * @brief Validates the list mode text and updates the syntax state and message.
     * @param filter_text The line edit text.
     */
    void checkFieldList(const QString &filter_text);

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
