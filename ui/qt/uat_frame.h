/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UAT_FRAME_H
#define UAT_FRAME_H

#include <QFrame>

#include <ui/qt/geometry_state_dialog.h>
#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

class QItemSelection;

namespace Ui {
class UatFrame;
}

/**
 * @brief UI frame for editing User Accessible Tables (UAT).
 */
class UatFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new UatFrame object.
     * @param parent The parent widget.
     */
    explicit UatFrame(QWidget *parent = NULL);

    /**
     * @brief Destroys the UatFrame object.
     */
    ~UatFrame();

    /**
     * @brief Sets the UAT structure to be edited.
     * @param uat Pointer to the UAT structure.
     */
    void setUat(struct epan_uat *uat);

    /**
     * @brief Accepts and applies the pending changes.
     */
    void acceptChanges();

    /**
     * @brief Rejects and discards the pending changes.
     */
    void rejectChanges();

protected:
    /**
     * @brief Handles the show event for the frame.
     */
    void showEvent(QShowEvent *);

private:
    /** @brief Pointer to the UI object for this frame. */
    Ui::UatFrame *ui;

    /** @brief Pointer to the UAT data model. */
    UatModel *uat_model_;

    /** @brief Pointer to the delegate for UAT fields. */
    UatDelegate *uat_delegate_;

    /** @brief Pointer to the underlying UAT structure. */
    struct epan_uat *uat_;

    /**
     * @brief Checks and displays an error hint based on item changes.
     * @param current The current model index.
     * @param previous The previous model index.
     */
    void checkForErrorHint(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Attempts to set an error hint from a specific field.
     * @param index The model index of the field.
     * @return True if an error hint was set, false otherwise.
     */
    bool trySetErrorHintFromField(const QModelIndex &index);

    /**
     * @brief Adds a new record to the UAT.
     * @param copy_from_current True to copy data from the currently selected record, false otherwise.
     */
    void addRecord(bool copy_from_current = false);

    /**
     * @brief Applies the current changes to the UAT.
     */
    void applyChanges();

    /**
     * @brief Resizes the tree view columns to fit their contents.
     */
    void resizeColumns();

private slots:
    /**
     * @brief Copies a UAT file from a specified profile.
     * @param filename The name of the file to copy.
     */
    void copyFromProfile(QString filename);

    /**
     * @brief Handles changes in the model data.
     * @param topLeft The top-left index of the changed data.
     */
    void modelDataChanged(const QModelIndex &topLeft);

    /**
     * @brief Handles the removal of rows from the model.
     */
    void modelRowsRemoved();

    /**
     * @brief Handles the resetting of rows in the model.
     */
    void modelRowsReset();

    /**
     * @brief Handles selection changes in the UAT tree view.
     * @param selected The newly selected items.
     * @param deselected The newly deselected items.
     */
    void uatTreeViewSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);

    /**
     * @brief Handles changes to the current item in the tree view.
     * @param current The current model index.
     * @param previous The previous model index.
     */
    void on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Handles clicks on the "New" tool button.
     */
    void on_newToolButton_clicked();

    /**
     * @brief Handles clicks on the "Delete" tool button.
     */
    void on_deleteToolButton_clicked();

    /**
     * @brief Handles clicks on the "Copy" tool button.
     */
    void on_copyToolButton_clicked();

    /**
     * @brief Handles clicks on the "Move Up" tool button.
     */
    void on_moveUpToolButton_clicked();

    /**
     * @brief Handles clicks on the "Move Down" tool button.
     */
    void on_moveDownToolButton_clicked();

    /**
     * @brief Handles clicks on the "Clear" tool button.
     */
    void on_clearToolButton_clicked();
};

#endif // UAT_FRAME_H
