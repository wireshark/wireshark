/** @file
 *
 * Model caching interface changes before sending them to global storage
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_TREE_CACHE_MODEL_H_
#define INTERFACE_TREE_CACHE_MODEL_H_

#include <ui/qt/models/interface_tree_model.h>

#include <QMap>
#include <QAbstractItemModel>
#include <QIdentityProxyModel>

class InterfaceTreeCacheModel : public QIdentityProxyModel
{
    Q_OBJECT

public:
    explicit InterfaceTreeCacheModel(QObject *parent);
    ~InterfaceTreeCacheModel();

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data (const QModelIndex &index, int role = Qt::DisplayRole) const;

    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);
    Qt::ItemFlags flags(const QModelIndex &index) const;

    QVariant getColumnContent(int idx, int col, int role = Qt::DisplayRole);

#ifdef HAVE_LIBPCAP
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const;

    void reset(int row);
    void save();

    void addDevice(const interface_t * newDevice);
    void deleteDevice(const QModelIndex &index);
#endif

#ifdef HAVE_PCAP_REMOTE
    bool isRemote(const QModelIndex &index) const;
#endif

private:
    InterfaceTreeModel * sourceModel;

#ifdef HAVE_LIBPCAP
    QList<interface_t> newDevices;

    void saveNewDevices();
#endif
    QMap<int, QSharedPointer<QMap<InterfaceTreeColumns, QVariant> > > * storage;
    QList<InterfaceTreeColumns> editableColumns;
    QList<InterfaceTreeColumns> checkableColumns;

#ifdef HAVE_LIBPCAP
    const interface_t * lookup(const QModelIndex &index) const;
#endif

    bool changeIsAllowed(InterfaceTreeColumns col) const;
    bool isAvailableField(const QModelIndex &index) const;
    bool isAllowedToBeEdited(const QModelIndex &index) const;

};
#endif /* INTERFACE_TREE_CACHE_MODEL_H_ */
