/* enabled_protocols_dialog.h
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

class EnabledProtocolsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit EnabledProtocolsDialog(QWidget *parent);
    virtual ~EnabledProtocolsDialog();

private slots:
    void on_invert_button__clicked();
    void on_enable_all_button__clicked();
    void on_disable_all_button__clicked();
    void on_search_line_edit__textChanged(const QString &);
    void on_cmbSearchType_currentIndexChanged(int);
    void on_cmbProtocolType_currentIndexChanged(int);
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();
    void fillTree();

private:
    Ui::EnabledProtocolsDialog *ui;

    EnabledProtocolsModel* enabled_protocols_model_;
    EnabledProtocolsProxyModel* proxyModel_;

    void searchFilterChange();
};

#endif // ENABLED_PROTOCOLS_DIALOG_H

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
