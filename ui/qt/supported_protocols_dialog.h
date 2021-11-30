/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SUPPORTED_PROTOCOLS_DIALOG_H
#define SUPPORTED_PROTOCOLS_DIALOG_H

#include "geometry_state_dialog.h"
#include <ui/qt/models/supported_protocols_model.h>

namespace Ui {
class SupportedProtocolsDialog;
}

class SupportedProtocolsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit SupportedProtocolsDialog(QWidget *parent = 0);
    ~SupportedProtocolsDialog();

private:
    Ui::SupportedProtocolsDialog *ui;

    SupportedProtocolsModel* supported_protocols_model_;
    SupportedProtocolsProxyModel* proxyModel_;
    QTimer *searchLineEditTimer;
    QString searchLineEditText;

    void updateStatistics();

private slots:
    void fillTree();

    /**
     * Update search results from the searchLineEdit field
     *
     * This is performed separately from on_searchLineEdit_textChanged
     * to support debouncing.
     */
    void updateSearchLineEdit();
    void on_searchLineEdit_textChanged(const QString &search_re);
};

#endif // SUPPORTED_PROTOCOLS_DIALOG_H
