/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RESOLVED_ADDRESSES_MODELS_H
#define RESOLVED_ADDRESSES_MODELS_H

#include <ui/qt/models/astringlist_list_model.h>

#include <QAbstractListModel>
#include <QSortFilterProxyModel>

class EthernetAddressModel : public AStringListListModel
{
    Q_OBJECT

public:
    EthernetAddressModel(QObject * parent = Q_NULLPTR);

    QStringList filterValues() const;

protected:
    QStringList headerColumns() const override;
    void populate();

};

enum PortsModelColumns
{
    PORTS_COL_NAME,
    PORTS_COL_PORT,
    PORTS_COL_PROTOCOL
};

class PortsModel : public AStringListListModel
{
    Q_OBJECT

public:
    PortsModel(QObject * parent = Q_NULLPTR);

    QStringList filterValues() const;

protected:
    QStringList headerColumns() const override;
    void populate();

};

#endif // RESOLVED_ADDRESSES_MODELS_H
