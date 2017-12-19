/* dissector_tables_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

 #include "config.h"

#include "dissector_tables_dialog.h"
#include <ui_dissector_tables_dialog.h>

#include <QElapsedTimer>

#include "wireshark_application.h"

DissectorTablesDialog::DissectorTablesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::DissectorTablesDialog),
    dissector_tables_model_(new DissectorTablesModel()),
    proxyModel_(new DissectorTablesProxyModel(this))
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 3 / 4, parent->height() * 3 / 4);
    setAttribute(Qt::WA_DeleteOnClose, true);
    setWindowTitle(wsApp->windowTitleString(tr("Dissector Tables")));

    proxyModel_->setSourceModel(dissector_tables_model_);
    ui->tableTree->setModel(proxyModel_);

    QTimer::singleShot(0, this, SLOT(fillTree()));
}

DissectorTablesDialog::~DissectorTablesDialog()
{
    delete ui;
    delete proxyModel_;
    delete dissector_tables_model_;
}

void DissectorTablesDialog::fillTree()
{
    dissector_tables_model_->populate();

    //it's recommended to sort after list is populated
    proxyModel_->sort(DissectorTablesModel::colTableName);

    //expand the "type" tables
    for (int row = 0; row < proxyModel_->rowCount(); row++) {
        ui->tableTree->setExpanded(proxyModel_->index(row, DissectorTablesModel::colTableName), true);
    }

    ui->tableTree->resizeColumnToContents(DissectorTablesModel::colTableName);
}

void DissectorTablesDialog::on_search_line_edit__textChanged(const QString &search_re)
{
    proxyModel_->setFilter(search_re);
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
