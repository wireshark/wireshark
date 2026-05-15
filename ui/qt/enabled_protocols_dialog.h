/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ENABLED_PROTOCOLS_DIALOG_H
#define ENABLED_PROTOCOLS_DIALOG_H

#include "geometry_state_dialog.h"
#include "wireshark_dialog.h"
#include <ui/qt/models/enabled_protocols_model.h>

namespace Ui {
class EnabledProtocolsDialog;
}

/**
 * @brief A dialog window for viewing, searching, and toggling enabled protocols.
 */
class EnabledProtocolsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new EnabledProtocolsDialog.
     * @param parent The parent widget.
     */
    explicit EnabledProtocolsDialog(QWidget *parent);

    /**
     * @brief Destroys the EnabledProtocolsDialog.
     */
    virtual ~EnabledProtocolsDialog();

private slots:
    /**
     * @brief Slot triggered when the "Invert" button is clicked.
     */
    void on_invert_button__clicked();

    /**
     * @brief Slot triggered when the "Enable All" button is clicked.
     */
    void on_enable_all_button__clicked();

    /**
     * @brief Slot triggered when the "Disable All" button is clicked.
     */
    void on_disable_all_button__clicked();

    /**
     * @brief Slot triggered when the text in the search line edit changes.
     */
    void on_search_line_edit__textChanged(const QString &);

    /**
     * @brief Slot triggered when the selected item in the search type combo box changes.
     */
    void on_cmbSearchType_currentIndexChanged(int);

    /**
     * @brief Slot triggered when the selected item in the protocol type combo box changes.
     */
    void on_cmbProtocolType_currentIndexChanged(int);

    /**
     * @brief Slot triggered when the dialog is accepted.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Populates the tree widget with data from the model.
     */
    void fillTree();

private:
    /** Pointer to the generated UI elements. */
    Ui::EnabledProtocolsDialog *ui;

    /** Model representing the actual protocol enabling state data. */
    EnabledProtocolsModel* enabled_protocols_model_;

    /** Proxy model managing search, filtering, and sorting over the base model. */
    EnabledProtocolsProxyModel* proxyModel_;

    /**
     * @brief Updates the proxy model filter when search parameters change.
     */
    void searchFilterChange();
};

#endif // ENABLED_PROTOCOLS_DIALOG_H
