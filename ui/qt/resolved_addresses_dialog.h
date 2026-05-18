/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RESOLVED_ADDRESSES_DIALOG_H
#define RESOLVED_ADDRESSES_DIALOG_H

#include "geometry_state_dialog.h"

#include <QMenu>

#include <wiretap/wtap.h>

class CaptureFile;
class AStringListListSortFilterProxyModel;

namespace Ui {
class ResolvedAddressesDialog;
}

/**
 * @brief Dialog for displaying resolved addresses.
 */
class ResolvedAddressesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ResolvedAddressesDialog object.
     * @param parent The parent widget.
     * @param captureFile The name of the capture file.
     * @param wth Pointer to the wiretap context.
     */
    explicit ResolvedAddressesDialog(QWidget *parent, QString captureFile, wtap* wth);

    /**
     * @brief Destroys the ResolvedAddressesDialog object.
     */
    ~ResolvedAddressesDialog();

protected slots:
    /**
     * @brief Handles the data type combo box index change.
     * @param index The new index.
     */
    void on_cmbDataType_currentIndexChanged(int index);

    /**
     * @brief Handles text changes in the search filter.
     * @param text The new search text.
     */
    void on_txtSearchFilter_textChanged(QString text);

    /**
     * @brief Handles the port filter type combo box index change.
     * @param index The new index.
     */
    void on_cmbPortFilterType_currentIndexChanged(int index);

    /**
     * @brief Handles text changes in the port filter.
     * @param text The new filter text.
     */
    void on_txtPortFilter_textChanged(QString text);

    /**
     * @brief Handles state change events.
     * @param event The event object.
     */
    void changeEvent(QEvent* event);

private:
    /** @brief Pointer to the user interface object for this dialog. */
    Ui::ResolvedAddressesDialog *ui;

    /** @brief The capture file name. */
    QString file_name_;

    /** @brief A comment associated with the resolved addresses. */
    QString comment_;

    /** @brief Button to copy the data. */
    QPushButton *copy_bt_;

    /** @brief Button to save the data. */
    QPushButton *save_bt_;

    /** @brief Model for sorting Ethernet addresses. */
    AStringListListSortFilterProxyModel * ethSortModel;

    /** @brief Model for filtering Ethernet types. */
    AStringListListSortFilterProxyModel * ethTypeModel;

    /** @brief Model for sorting port numbers. */
    AStringListListSortFilterProxyModel * portSortModel;

    /** @brief Model for filtering port types. */
    AStringListListSortFilterProxyModel * portTypeModel;

    /**
     * @brief Fills the data blocks for the dialog.
     */
    void fillBlocks();

private slots:
    /**
     * @brief Handles tab changes in the dialog.
     * @param index The new tab index.
     */
    void tabChanged(int index);

    /**
     * @brief Opens a dialog to save the resolved addresses to a file.
     */
    void saveAs();
};

#endif // RESOLVED_ADDRESSES_DIALOG_H
