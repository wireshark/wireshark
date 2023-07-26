/*
 * manuf_table_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "manuf_table_model.h"

ManufTableModel::ManufTableModel(QObject *parent) : QAbstractTableModel(parent)
{
}

ManufTableModel::~ManufTableModel()
{
    clear();
}

int ManufTableModel::rowCount(const QModelIndex &) const
{
    return static_cast<int>(rows_.count());
}

int ManufTableModel::columnCount(const QModelIndex &) const
{
    return NUM_COLS;
}

QVariant ManufTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    if (index.row() >= rows_.size())
        return QVariant();

    QStringList *list = rows_.at(index.row());
    if (index.column() >= list->size())
        return QVariant();

    if (role == Qt::DisplayRole) {
        return list->at(index.column());
    }

    return QVariant();
}

void ManufTableModel::addRecord(QString prefix, QString short_name, QString long_name)
{
    emit beginInsertRows(QModelIndex(), rowCount(), rowCount());

    QStringList *cols = new QStringList;
    cols->append(prefix);
    cols->append(short_name);
    cols->append(long_name);
    rows_.append(cols);

    emit endInsertRows();
}

void ManufTableModel::clear()
{
    if (!rows_.isEmpty()) {
        emit beginRemoveRows(QModelIndex(), 0, rowCount() - 1);
        qDeleteAll(rows_.begin(), rows_.end());
        rows_.clear();
        emit endRemoveRows();
    }
}

QVariant ManufTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole)
        return QVariant();

    if (orientation == Qt::Horizontal) {
        switch (section) {
            case COL_OUI_PREFIX:
                return QString(tr("Address Block"));
            case COL_SHORT_NAME:
                return QString(tr("Short Name"));
            case COL_VENDOR_NAME:
                return QString(tr("Vendor Name"));
        }
    }

    return QVariant();
}
