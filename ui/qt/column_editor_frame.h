/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLUMN_EDITOR_FRAME_H
#define COLUMN_EDITOR_FRAME_H

#include "accordion_frame.h"

namespace Ui {
class ColumnEditorFrame;
}

/**
 * @brief An accordion frame for editing packet list column properties.
 */
class ColumnEditorFrame : public AccordionFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ColumnEditorFrame.
     * @param parent The parent widget, defaults to nullptr.
     */
    explicit ColumnEditorFrame(QWidget *parent = nullptr);

    /**
     * @brief Destroys the ColumnEditorFrame.
     */
    ~ColumnEditorFrame();

    /**
     * @brief Sets up the editor for a specific column index.
     * @param column The index of the column to edit.
     */
    void editColumn(int column);

signals:
    /**
     * @brief Signal emitted when a column's properties have been successfully edited.
     */
    void columnEdited();

protected:
    /**
     * @brief Handles the show event for the frame.
     * @param event The show event details.
     */
    virtual void showEvent(QShowEvent *event);

    /**
     * @brief Handles key press events, typically for accepting/rejecting the dialog.
     * @param event The key press event details.
     */
    virtual void keyPressEvent(QKeyEvent *event);

private slots:
    /**
     * @brief Slot triggered when a column type is activated in the combo box.
     * @param index The index of the selected column type.
     */
    void on_typeComboBox_activated(int index);

    /**
     * @brief Slot triggered when the fields name line edit text is edited.
     * @param fields The new fields string.
     */
    void on_fieldsNameLineEdit_textEdited(const QString &fields);

    /**
     * @brief Slot triggered when the occurrence line edit text is edited.
     * @param occurrence The new occurrence string.
     */
    void on_occurrenceLineEdit_textEdited(const QString &occurrence);

    /**
     * @brief Slot triggered when the dialog's button box is rejected (e.g., canceled).
     */
    void on_buttonBox_rejected();

    /**
     * @brief Slot triggered when the dialog's button box is accepted (e.g., applied).
     */
    void on_buttonBox_accepted();

    /**
     * @brief Checks if the currently entered column field can be resolved.
     */
    void checkCanResolve(void);

private:
    /**
     * @brief Validates the syntax of the entered field names.
     * @return True if the syntax is valid, false otherwise.
     */
    bool syntaxIsValid(void);

    /** Pointer to the generated UI elements. */
    Ui::ColumnEditorFrame *ui;

    /** The index of the column currently being edited. */
    int cur_column_;

    /** The previously saved field names string to allow for reversion. */
    QString saved_fields_;

    /** The previously saved occurrence string to allow for reversion. */
    QString saved_occurrence_;

    /**
     * @brief Populates the fields line edit based on the selected column type.
     * @param index The index of the selected column type.
     */
    void setFields(int index);

    /**
     * @brief Handles UI adjustments when the column type is changed.
     * @param index The index of the newly selected column type.
     */
    void typeChanged(int index);
};

#endif // COLUMN_EDITOR_FRAME_H
