/* interface_tree_cache_model.h
 * Model caching interface changes before sending them to global storage
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef INTERFACE_TREE_CACHE_MODEL_H_
#define INTERFACE_TREE_CACHE_MODEL_H_

#include "ui/qt/interface_tree_model.h"

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

private:
    InterfaceTreeModel * sourceModel;

#ifdef HAVE_LIBPCAP
    QList<interface_t> newDevices;

    void saveNewDevices();
#endif
    QMap<int, QMap<InterfaceTreeColumns, QVariant> *> * storage;
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

