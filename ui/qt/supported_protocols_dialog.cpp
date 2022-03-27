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

#include "main_application.h"

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

    setWindowTitle(mainApp->windowTitleString(tr("Supported Protocols")));

    // Some of our names are unreasonably long.
    int one_em = fontMetrics().height();
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colName, one_em * 15);
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colFilter, one_em * 10);
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colType, one_em * 12);
    ui->supportedProtocolsTreeView->setColumnWidth(SupportedProtocolsModel::colDescription, one_em * 30);

    QTimer::singleShot(0, this, SLOT(fillTree()));

    /* Create a single-shot timer for debouncing calls to
     * updateSearchLineEdit() */
    searchLineEditTimer = new QTimer(this);
    searchLineEditTimer->setSingleShot(true);
    connect(searchLineEditTimer, &QTimer::timeout, this, &SupportedProtocolsDialog::updateSearchLineEdit);
}

SupportedProtocolsDialog::~SupportedProtocolsDialog()
{
    delete searchLineEditTimer;
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

void SupportedProtocolsDialog::updateSearchLineEdit()
{
    proxyModel_->setFilter(searchLineEditText);
}

void SupportedProtocolsDialog::on_searchLineEdit_textChanged(const QString &search_re)
{
    /* As filtering the list of protocols takes a noticeable amount
     * of time and so would introduce significant lag while typing a string
     * into the Search box, we instead debounce the call to
     * proxyModel_->setFilter(), so that it doesn't run until a set amount of
     * time has elapsed with no updates to the Search field.
     *
     * If the user types something before the timer elapses, the timer restarts
     * the countdown.
     */
    searchLineEditText = search_re;
    searchLineEditTimer->start(1000);
}
