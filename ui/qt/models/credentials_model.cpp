/*
 * credentials_model.h
 *
 * Copyright 2019 - Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "credentials_model.h"

#include <file.h>
#include <log.h>

CredentialsModel::CredentialsModel(QObject *parent, CaptureFile& cf)
    :QAbstractListModel(parent)
{
}

int CredentialsModel::rowCount(const QModelIndex &) const
{
    return credentials_.count();
}

int CredentialsModel::columnCount(const QModelIndex &) const
{
    return COL_INFO + 1;
}

QVariant CredentialsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    tap_credential_t * auth = credentials_.at(index.row());
    if (!auth)
        return QVariant();


    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case COL_NUM:
                return qVariantFromValue(auth->num);
            case COL_PROTO:
                return QString(auth->proto);
            case COL_USERNAME:
                return QString(auth->username);
            case COL_INFO:
                return QString(auth->info);
            default:
                return QVariant();
        }
    }

    if (role == Qt::UserRole) {
        switch (index.column()) {
            case COL_NUM:
                if (auth->num > 0)
                    return qVariantFromValue(auth->num);
                break;
            case COL_USERNAME:
                if (auth->username_num > 0)
                    return qVariantFromValue(auth->username_num);
                break;
            default:
                return QVariant();
        }
    }

    if (role == CredentialsModel::ColumnHFID)
        return qVariantFromValue(auth->password_hf_id);

    if (role == Qt::ToolTipRole) {
        const QString select_msg(tr("Click to select the packet"));
        switch (index.column()) {
            case COL_NUM:
                if (auth->num > 0)
                    return select_msg;
                break;
            case  COL_USERNAME:
                if (auth->username_num > 0) {
                    if (auth->username_num != auth->num)
                        return QString(tr("Click to select the packet with username"));
                    else
                        return select_msg;
                } else {
                    return QString(tr("Username not available"));
                }
                break;
            default:
                return QVariant();
        }
    }

    return QVariant();
}



void CredentialsModel::addRecord(tap_credential_t* auth)
{
    emit beginInsertRows(QModelIndex(), rowCount(), rowCount() + 1);
    credentials_.append(auth);
    emit endInsertRows();
}

void CredentialsModel::clear()
{
    emit beginRemoveRows(QModelIndex(), 0, rowCount());
    credentials_.clear();
    emit endInsertRows();
}

QVariant CredentialsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole)
        return QVariant();

    if (orientation == Qt::Horizontal) {
        switch (section) {
            case COL_NUM:
                return QString(tr("Packet No."));
            case COL_PROTO:
                return QString(tr("Protocol"));
            case COL_USERNAME:
                return QString(tr("Username"));
            case COL_INFO:
                return QString(tr("Additional Info"));
        }
    }

    return QVariant();
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
