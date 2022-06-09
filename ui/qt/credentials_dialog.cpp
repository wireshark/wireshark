/*
 * credentials_dialog.c
 *
 * Copyright 2019 - Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "file.h"

#include "credentials_dialog.h"
#include <ui_credentials_dialog.h>
#include <ui/tap-credentials.h>
#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include "ui/qt/models/credentials_model.h"
#include <ui/qt/models/url_link_delegate.h>

#include <QClipboard>
#include <QMessageBox>
#include <QPushButton>
#include <QTextCursor>
#include <QSortFilterProxyModel>

class CredentialsUrlDelegate : public UrlLinkDelegate
{
public:

    CredentialsUrlDelegate(QObject * parent) : UrlLinkDelegate(parent) {}

    virtual void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        bool ok = false;
        int val = index.data(Qt::UserRole).toInt(&ok);
        if (!ok || val <= 0)
            QStyledItemDelegate::paint(painter, option, index);
        else
            UrlLinkDelegate::paint(painter, option, index);
    }

};

CredentialsDialog::CredentialsDialog(QWidget &parent, CaptureFile &cf, PacketList *packet_list) :
    WiresharkDialog(parent, cf),
    ui(new Ui::CredentialsDialog)
{
    ui->setupUi(this);
    packet_list_ = packet_list;

    model_ = new CredentialsModel(this);
    QSortFilterProxyModel *proxyModel = new QSortFilterProxyModel(this);

    proxyModel->setSourceModel(model_);
    ui->auths->setModel(proxyModel);

    setWindowSubtitle(tr("Credentials"));

    ui->auths->setRootIsDecorated(false);
    ui->auths->setItemDelegateForColumn(CredentialsModel::COL_NUM, new CredentialsUrlDelegate(this));
    ui->auths->setItemDelegateForColumn(CredentialsModel::COL_USERNAME, new CredentialsUrlDelegate(this));

    ui->auths->resizeColumnToContents(CredentialsModel::COL_NUM);
    ui->auths->resizeColumnToContents(CredentialsModel::COL_PROTO);
    ui->auths->resizeColumnToContents(CredentialsModel::COL_USERNAME);

    ui->auths->setSortingEnabled(true);
    ui->auths->sortByColumn(CredentialsModel::COL_NUM, Qt::AscendingOrder);

    connect(ui->auths, &QTreeView::clicked, this, &CredentialsDialog::actionGoToPacket);

    registerTapListener("credentials", this, "", 0, tapReset, tapPacket, Q_NULLPTR);
    cf.retapPackets();
}

CredentialsDialog::~CredentialsDialog()
{
    delete ui;
}

void CredentialsDialog::tapReset(void *tapdata)
{
    CredentialsDialog * d = (CredentialsDialog*) tapdata;
    d->model_->clear();
}

tap_packet_status CredentialsDialog::tapPacket(void *tapdata, _packet_info *, epan_dissect *, const void *data, tap_flags_t)
{
    CredentialsDialog * d = (CredentialsDialog*) tapdata;
    d->model_->addRecord((const tap_credential_t*)data);
    return TAP_PACKET_REDRAW;
}

void CredentialsDialog::actionGoToPacket(const QModelIndex& idx)
{
    if (!idx.isValid())
        return;

    QVariant packet_data = idx.data(Qt::UserRole);
    QVariant hf_id = idx.data(CredentialsModel::ColumnHFID);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    if (!hf_id.canConvert<int>())
        hf_id = QVariant::fromValue(0);

    if (packet_data.canConvert<int>())
        packet_list_->goToPacket(packet_data.toInt(), hf_id.toInt());
#else
    if (!hf_id.canConvert(QVariant::Int))
        hf_id = QVariant::fromValue(0);

    if (packet_data.canConvert(QVariant::Int))
        packet_list_->goToPacket(packet_data.toInt(), hf_id.toInt());
#endif
}
