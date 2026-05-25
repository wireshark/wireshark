/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_APPLY_LINE_EDIT_H_
#define UI_QT_APPLY_LINE_EDIT_H_

#include <QLineEdit>
#include <QString>

#include <ui/qt/widgets/stock_icon_tool_button.h>

/**
 * @brief A QLineEdit with an embedded apply button and optional regex validation.
 */
class ApplyLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    /**
     * @brief Construct an ApplyLineEdit.
     * @param linePlaceholderText Placeholder text displayed when the field is empty.
     * @param parent The parent widget.
     */
    explicit ApplyLineEdit(QString linePlaceholderText, QWidget *parent = 0);

    /** @brief Destroy the ApplyLineEdit and its embedded apply button. */
    ~ApplyLineEdit();

    /** @brief The regular expression pattern used to validate input text. */
    Q_PROPERTY(QString regex READ regex WRITE setRegEx)

    /** @brief Whether an empty string is considered a valid value. */
    Q_PROPERTY(bool emptyAllowed READ emptyAllowed WRITE setEmptyAllowed)

    /**
     * @brief Return the current validation regex pattern.
     * @return The regex string, or an empty string if none is set.
     */
    QString regex();

    /**
     * @brief Set the validation regex pattern.
     * @param regex The regular expression pattern to apply.
     */
    void setRegEx(QString regex);

    /**
     * @brief Return whether an empty string is accepted as valid input.
     * @return true if empty input is allowed; false if it is rejected.
     */
    bool emptyAllowed();

    /**
     * @brief Set whether empty input is accepted as valid.
     * @param emptyAllowed true to allow empty input; false to require at
     *                     least one character.
     */
    void setEmptyAllowed(bool emptyAllowed);

signals:
    /**
     * @brief Emitted when the user applies the current (valid) text.
     */
    void textApplied();

protected:
    /**
     * @brief Reposition the embedded apply button when the widget is resized.
     * @param event The resize event.
     */
    void resizeEvent(QResizeEvent *event) override;

private:
    QString regex_;              /**< Validation regex pattern; empty means no pattern check. */
    bool emptyAllowed_;          /**< Whether empty text is considered valid. */
    StockIconToolButton *apply_button_; /**< Inline apply button rendered inside the line edit. */

    /**
     * @brief Test whether @p text passes the current validation rules.
     * @param text             The text to validate.
     * @param ignoreEmptyCheck If true, skip the empty-text check and only
     *                         evaluate the regex constraint.
     * @return true if @p text is valid.
     */
    bool isValidText(QString &text, bool ignoreEmptyCheck = false);

    /**
     * @brief Update the apply button's enabled state based on @p newText.
     * @param newText The current line edit text to validate.
     */
    void handleValidation(QString newText);

private slots:
    /**
     * @brief Validate the text and update the apply button when the user types.
     * @param text The current text after the edit.
     */
    void onTextEdited(const QString &text);

    /**
     * @brief Respond to programmatic or user-driven text changes.
     * @param text The new text value.
     */
    void onTextChanged(const QString &text);

    /**
     * @brief Apply the current text if it is valid and emit textApplied().
     */
    void onSubmitContent();
};

#endif /* UI_QT_APPLY_LINE_EDIT_H_ */
