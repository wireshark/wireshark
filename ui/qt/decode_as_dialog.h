/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DECODE_AS_DIALOG_H
#define DECODE_AS_DIALOG_H

#include <config.h>

#include <epan/cfile.h>
#include <ui/qt/models/decode_as_model.h>
#include <ui/qt/models/decode_as_delegate.h>

#include "geometry_state_dialog.h"
#include <QMap>
#include <QAbstractButton>

class QComboBox;

namespace Ui {
class DecodeAsDialog;
}

/**
 * @brief A dialog allowing users to configure "Decode As" rules for protocols.
 */
class DecodeAsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DecodeAsDialog.
     * @param parent The parent widget, defaults to 0.
     * @param cf Pointer to the capture file, defaults to NULL.
     * @param create_new True to automatically initiate creation of a new rule upon opening, defaults to false.
     */
    explicit DecodeAsDialog(QWidget *parent = 0, capture_file *cf = NULL, bool create_new = false);

    /**
     * @brief Destroys the DecodeAsDialog.
     */
    ~DecodeAsDialog();

private:
    /** Pointer to the generated UI elements. */
    Ui::DecodeAsDialog *ui;

    /** Model managing the "Decode As" rules. */
    DecodeAsModel* model_;

    /** Delegate for rendering and editing rule entries in the view. */
    DecodeAsDelegate* delegate_;

    /**
     * @brief Adds a new "Decode As" record to the model.
     * @param copy_from_current True to copy the currently selected record's values, false for a blank record.
     */
    void addRecord(bool copy_from_current = false);

    /**
     * @brief Applies the changes made in the dialog to the underlying Wireshark core.
     */
    void applyChanges();

    /**
     * @brief Fills the table model with the current "Decode As" rules.
     */
    void fillTable();

    /**
     * @brief Resizes the tree view columns to fit their contents.
     */
    void resizeColumns();

public slots:
    /**
     * @brief Slot triggered when the model's rows have been reset.
     */
    void modelRowsReset();

private slots:
    /**
     * @brief Copies "Decode As" rules from a specified profile file.
     * @param filename The path to the profile file.
     */
    void copyFromProfile(QString filename);

    /**
     * @brief Slot triggered when the current item in the tree view changes.
     * @param current The newly selected model index.
     * @param previous The previously selected model index.
     */
    void on_decodeAsTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Slot triggered when the "New" tool button is clicked.
     */
    void on_newToolButton_clicked();

    /**
     * @brief Slot triggered when the "Delete" tool button is clicked.
     */
    void on_deleteToolButton_clicked();

    /**
     * @brief Slot triggered when the "Copy" tool button is clicked.
     */
    void on_copyToolButton_clicked();

    /**
     * @brief Slot triggered when the "Clear" tool button is clicked.
     */
    void on_clearToolButton_clicked();

    /**
     * @brief Slot triggered when a button in the dialog's button box is clicked.
     * @param button The abstract button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);
};

#endif // DECODE_AS_DIALOG_H
