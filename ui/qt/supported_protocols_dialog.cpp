/* supported_protocols_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "supported_protocols_dialog.h"
#include <ui_supported_protocols_dialog.h>

#include <QElapsedTimer>

#include "wireshark_application.h"

SupportedProtocolsDialog::SupportedProtocolsDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::SupportedProtocolsDialog),
    supported_protocols_model_(new SupportedProtocolsModel()),
    proxyModel_(new SupportedProtocolsProxyModel(this))
{
    ui->setupUi(this);

    proxyModel_->setSourceModel(supported_protocols_model_);
    ui->supportedProtocolsTreeView->setModel(proxyModel_);

    //always sort by protocol/field name
    proxyModel_->sort(SupportedProtocolsModel::colName);

    if (parent)
        loadGeometry(parent->width() * 3 / 4, parent->height());
    setAttribute(Qt::WA_DeleteOnClose, true);

    setWindowTitle(wsApp->windowTitleString(tr("Supported Protocols")));

    // Some of our names are unreasonably long.
    int one_em = fontMetrics().height();
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colName, one_em * 15);
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colFilter, one_em * 10);
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colType, one_em * 12);
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colDescription, one_em * 30);

    QTimer::singleShot(0, this, SLOT(fillTree()));
}

SupportedProtocolsDialog::~SupportedProtocolsDialog()
{
    delete ui;
    delete supported_protocols_model_;
    delete proxyModel_;
}

void SupportedProtocolsDialog::updateStatistics()
{
    QLocale locale = QLocale::system();
    QString hint = tr("%1 protocols, %2 fields.")
            .arg(locale.toString(supported_protocols_model_->rowCount()))
            .arg(locale.toString(supported_protocols_model_->fieldCount()));
    ui->hintLabel->setText(hint);
}

void SupportedProtocolsDialog::fillTree()
{
    supported_protocols_model_->populate();
    updateStatistics();
}

void SupportedProtocolsDialog::on_searchLineEdit_textChanged(const QString &search_re)
{
    proxyModel_->setFilter(search_re);
}
