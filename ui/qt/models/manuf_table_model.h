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

#include <QAbstractTableModel>
#include <QList>

#include <wireshark.h>

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

    void addRecord(QString prefix, QString short_name, QString long_name);

    void clear();

    enum {
        COL_OUI_PREFIX,
        COL_SHORT_NAME,
        COL_VENDOR_NAME,
        NUM_COLS,
    };

private:
    QList<QStringList *> rows_;
};

#endif
