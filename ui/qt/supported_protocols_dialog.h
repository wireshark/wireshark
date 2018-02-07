/* supported_protocols_dialog.h
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

    void updateStatistics();

private slots:
    void fillTree();

    void on_searchLineEdit_textChanged(const QString &search_re);
};

#endif // SUPPORTED_PROTOCOLS_DIALOG_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
