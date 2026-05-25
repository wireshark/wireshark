/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_TOOLBAR_LINEEDIT_H
#define INTERFACE_TOOLBAR_LINEEDIT_H

#include <QLineEdit>
#include <QRegularExpression>

class StockIconToolButton;

/**
 * @brief A custom line edit for interface toolbars, featuring regex validation and an integrated apply button.
 */
class InterfaceToolbarLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new InterfaceToolbarLineEdit.
     * @param parent The parent widget, defaults to 0.
     * @param validation_regex The regular expression used to validate the input text (defaults to an empty string).
     * @param is_required True if the input cannot be left empty to be considered valid (defaults to false).
     */
    explicit InterfaceToolbarLineEdit(QWidget *parent = 0, QString validation_regex = QString(), bool is_required = false);

    /**
     * @brief Disables the embedded apply button, preventing the user from triggering an apply action.
     */
    void disableApplyButton();

protected:
    /**
     * @brief Handles resize events to adjust the position and size of the embedded apply button.
     */
    void resizeEvent(QResizeEvent *) override;

signals:
    /**
     * @brief Signal emitted when the edited text is valid and successfully applied.
     */
    void editedTextApplied();

private slots:
    /**
     * @brief Slot triggered to validate the current text content.
     */
    void validateText();

    /**
     * @brief Slot triggered to validate the text content after it has been edited by the user.
     */
    void validateEditedText();

    /**
     * @brief Slot triggered when the apply button is clicked to process the edited text.
     */
    void applyEditedText();

private:
    /**
     * @brief Checks if the current text satisfies the validation regex and required constraints.
     * @return True if the text is valid, false otherwise.
     */
    bool isValid();

    /**
     * @brief Updates the stylesheet of the line edit to visually indicate its validation state.
     * @param is_valid True to apply the valid style, false to apply the invalid/error style.
     */
    void updateStyleSheet(bool is_valid);

    /** Pointer to the embedded apply button. */
    StockIconToolButton *apply_button_;

    /** The regular expression used for validating input text. */
    QRegularExpression regex_expr_;

    /** Flag indicating whether the field must not be empty. */
    bool is_required_;

    /** Flag tracking whether the user has actively edited the text. */
    bool text_edited_;
};

#endif // INTERFACE_TOOLBAR_LINEEDIT_H
