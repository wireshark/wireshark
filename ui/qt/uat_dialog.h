/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UAT_DIALOG_H
#define UAT_DIALOG_H

#include <config.h>

#include "geometry_state_dialog.h"
#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

class QComboBox;
class QPushButton;
class QItemSelection;

struct epan_uat;

namespace Ui {
class UatDialog;
}

/**
 * @brief Dialog for viewing and editing User Accessible Tables (UATs).
 */
class UatDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the UAT dialog.
     * @param parent Parent widget, or nullptr for a top-level window.
     * @param uat    The UAT to display and edit, or NULL to leave unset.
     */
    explicit UatDialog(QWidget *parent = 0, struct epan_uat *uat = NULL);

    /**
     * @brief Destroys the UAT dialog.
     */
    ~UatDialog();

    /**
     * @brief Switches the dialog to display and edit a different UAT.
     * @param uat The UAT to load, or NULL to clear the current table.
     */
    void setUat(struct epan_uat *uat = NULL);

private slots:
    /**
     * @brief Populates the table by copying records from an external profile file.
     * @param filename Path to the profile file to copy from.
     */
    void copyFromProfile(QString filename);

    /**
     * @brief Responds to data changes in the model, updating UI state as needed.
     * @param topLeft Index of the top-left cell of the changed region.
     */
    void modelDataChanged(const QModelIndex &topLeft);

    /**
     * @brief Responds to rows being removed from the model.
     */
    void modelRowsRemoved();

    /**
     * @brief Responds to the model being reset, refreshing the view.
     */
    void modelRowsReset();

    /**
     * @brief Responds to selection changes in the UAT tree view.
     * @param selected   Newly selected items.
     * @param deselected Previously selected items that are now deselected.
     */
    void uatTreeViewSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);

    /**
     * @brief Responds to the current item changing in the UAT tree view.
     * @param current  Index of the newly current item.
     * @param previous Index of the previously current item.
     */
    void on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Commits all pending changes to the UAT and closes the dialog.
     */
    void acceptChanges();

    /**
     * @brief Discards all pending changes and closes the dialog.
     */
    void rejectChanges();

    /**
     * @brief Handles the New button click, adding a blank record to the table.
     */
    void on_newToolButton_clicked();

    /**
     * @brief Handles the Delete button click, removing the selected record.
     */
    void on_deleteToolButton_clicked();

    /**
     * @brief Handles the Copy button click, duplicating the selected record.
     */
    void on_copyToolButton_clicked();

    /**
     * @brief Handles the Move Up button click, shifting the selected record up one position.
     */
    void on_moveUpToolButton_clicked();

    /**
     * @brief Handles the Move Down button click, shifting the selected record down one position.
     */
    void on_moveDownToolButton_clicked();

    /**
     * @brief Handles the Clear button click, removing all records from the table.
     */
    void on_clearToolButton_clicked();

    /**
     * @brief Opens the context-sensitive help page for the current UAT.
     */
    void on_buttonBox_helpRequested();

private:
    /** @brief Qt Designer-generated UI members. */
    Ui::UatDialog *ui;

    /** @brief Model providing data from the underlying UAT. */
    UatModel *uat_model_;

    /** @brief Delegate handling custom editing of UAT fields. */
    UatDelegate *uat_delegate_;

    /** @brief The dialog's OK button, enabled only when the table is error-free. */
    QPushButton *ok_button_;

    /** @brief The dialog's Help button. */
    QPushButton *help_button_;

    /** @brief The raw UAT structure being edited. */
    struct epan_uat *uat_;

    /**
     * @brief Updates the error hint area based on validation state of the current and previous items.
     * @param current  Index of the currently selected item.
     * @param previous Index of the previously selected item.
     */
    void checkForErrorHint(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Attempts to populate the error hint from the validation error of a specific field.
     * @param index Model index of the field to inspect.
     * @return True if an error hint was found and displayed, false otherwise.
     */
    bool trySetErrorHintFromField(const QModelIndex &index);

    /**
     * @brief Writes all in-memory UAT edits back to the underlying data structures.
     */
    void applyChanges();

    /**
     * @brief Adds a new record to the UAT, optionally cloning the currently selected one.
     * @param copy_from_current If true, duplicates the selected record; otherwise inserts a blank row.
     */
    void addRecord(bool copy_from_current = false);

    /**
     * @brief Resizes all tree view columns to fit their current contents.
     */
    void resizeColumns();
};

#endif // UAT_DIALOG_H
