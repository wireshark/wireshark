/* dissector_tables_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 #include "config.h"

#include <ui/qt/dissector_tables_dialog.h>
#include <ui_dissector_tables_dialog.h>

#include "wireshark_application.h"

DissectorTablesDialog::DissectorTablesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::DissectorTablesDialog)
{
    ui->setupUi(this);

    if (parent)
        loadGeometry(parent->width() * 3 / 4, parent->height() * 3 / 4);

    setAttribute(Qt::WA_DeleteOnClose, true);
    setWindowTitle(wsApp->windowTitleString(tr("Dissector Tables")));

    proxyModel_ = new DissectorTablesProxyModel(this);
    proxyModel_->setSourceModel(new DissectorTablesModel(this));
    //it's recommended to sort after list is populated
    proxyModel_->sort(DissectorTablesModel::colTableName);

    ui->tableTree->setModel(proxyModel_);

    //expand the "type" tables
    ui->tableTree->expandToDepth(0);
    ui->tableTree->resizeColumnToContents(DissectorTablesModel::colTableName);
}

DissectorTablesDialog::~DissectorTablesDialog()
{
    delete ui;
}

void DissectorTablesDialog::on_txtSearchLine_textChanged(const QString &search_re)
{
    proxyModel_->setFilter(search_re);
    /* If items are filtered out, then filtered back in, the tree remains collapsed
       Force an expansion */
    ui->tableTree->expandToDepth(0);
}

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
