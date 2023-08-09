/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MANUF_TABLE_MODEL_H
#define MANUF_TABLE_MODEL_H

#include <QSortFilterProxyModel>
#include <QAbstractTableModel>
#include <QList>

#include <wireshark.h>
#include <epan/manuf.h>

class ManufTableItem
{
public:
    ManufTableItem(struct ws_manuf *ptr);
    ~ManufTableItem();

    QByteArray block_bytes_;
    QString block_name_;
    QString short_name_;
    QString long_name_;
};

class ManufTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    ManufTableModel(QObject *parent);
    ~ManufTableModel();
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const ;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    void addRecord(struct ws_manuf *ptr);

    void clear();

    enum {
        COL_MAC_PREFIX,
        COL_SHORT_NAME,
        COL_VENDOR_NAME,
        NUM_COLS,
    };

private:
    QList<ManufTableItem *> rows_;
};

class ManufSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    enum ManufProxyFilterType
    {
        FilterEmpty = 0,
        FilterByAddress,
        FilterByName,
    };
    Q_ENUM(ManufProxyFilterType)

    ManufSortFilterProxyModel(QObject *parent);

    virtual bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const;

public slots:
    void setFilterAddress(const QByteArray&);
    void setFilterName(QRegularExpression&);
    void clearFilter();

private:
    ManufProxyFilterType filter_type_;
    QByteArray filter_bytes_;
    QRegularExpression filter_name_;

    bool filterAddressAcceptsRow(int source_row, const QModelIndex& source_parent) const;
    bool filterNameAcceptsRow(int source_row, const QModelIndex& source_parent) const;
};

#endif
