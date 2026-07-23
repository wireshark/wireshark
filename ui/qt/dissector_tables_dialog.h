/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISSECTOR_TABLES_DIALOG_H
#define DISSECTOR_TABLES_DIALOG_H

#include <ui/qt/geometry_state_dialog.h>
#include <ui/qt/models/dissector_tables_model.h>

namespace Ui {
class DissectorTablesDialog;
}

/**
 * @brief A dialog window for viewing and searching registered dissector tables.
 */
class DissectorTablesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DissectorTablesDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit DissectorTablesDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the DissectorTablesDialog.
     */
    ~DissectorTablesDialog();

private slots:
    /**
     * @brief Slot triggered when the text in the search line edit changes.
     * @param search_re The new search string or regular expression.
     */
    void on_txtSearchLine_textChanged(const QString &search_re);

    void on_cmbSearchType_currentIndexChanged(int);

private:
    void searchFilterChange();

    /** Pointer to the generated UI elements. */
    Ui::DissectorTablesDialog *ui;

    /** Proxy model used for sorting and filtering the dissector tables. */
    DissectorTablesProxyModel* proxyModel_;
};

#endif // DISSECTOR_TABLES_DIALOG_H
