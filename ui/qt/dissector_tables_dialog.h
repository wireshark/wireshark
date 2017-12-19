/* dissector_tables_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef DISSECTOR_TABLES_DIALOG_H
#define DISSECTOR_TABLES_DIALOG_H

#include "geometry_state_dialog.h"
#include <ui/qt/models/dissector_tables_model.h>

namespace Ui {
class DissectorTablesDialog;
}

class QTreeWidgetItem;

class DissectorTablesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit DissectorTablesDialog(QWidget *parent = 0);
    ~DissectorTablesDialog();

private slots:
    void on_search_line_edit__textChanged(const QString &search_re);
    void fillTree();

private:
    Ui::DissectorTablesDialog *ui;

    DissectorTablesModel* dissector_tables_model_;
    DissectorTablesProxyModel* proxyModel_;
};

#endif // DISSECTOR_TABLES_DIALOG_H

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
