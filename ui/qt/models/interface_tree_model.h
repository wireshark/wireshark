/* interface_tree_model.h
 * Model for the interface data for display in the interface frame
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

#ifndef INTERFACE_TREE_MODEL_H
#define INTERFACE_TREE_MODEL_H

#include <config.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#include "ui/capture_globals.h"
#endif

#include <glib.h>

#include <QAbstractTableModel>
#include <QList>
#include <QMap>
#include <QItemSelection>

typedef QList<int> PointList;

enum InterfaceTreeColumns
{
#ifdef HAVE_EXTCAP
    IFTREE_COL_EXTCAP,
    IFTREE_COL_EXTCAP_PATH,
#endif
    IFTREE_COL_NAME,
    IFTREE_COL_INTERFACE_NAME,
    IFTREE_COL_INTERFACE_COMMENT,
    IFTREE_COL_HIDDEN,
    IFTREE_COL_DLT,
    IFTREE_COL_PROMISCUOUSMODE,
    IFTREE_COL_TYPE,
    IFTREE_COL_STATS,
    IFTREE_COL_SNAPLEN,
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    IFTREE_COL_BUFFERLEN,
#endif
#ifdef HAVE_PCAP_CREATE
    IFTREE_COL_MONITOR_MODE,
#endif
    IFTREE_COL_CAPTURE_FILTER,
    IFTREE_COL_PIPE_PATH,
    IFTREE_COL_MAX /* is not being displayed, it is the definition for the maximum numbers of columns */
};

class InterfaceTreeModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    InterfaceTreeModel(QObject *parent);
    ~InterfaceTreeModel();

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data (const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    void updateStatistic(unsigned int row);
#ifdef HAVE_LIBPCAP
    void stopStatistic();
#endif

    QString interfaceError();
    QItemSelection selectedDevices();
    bool updateSelectedDevices(QItemSelection sourceSelection);

    QVariant getColumnContent(int idx, int col, int role = Qt::DisplayRole);

#ifdef HAVE_PCAP_REMOTE
    bool isRemote(int idx);
#endif

    static const QString DefaultNumericValue;

public slots:
    void getPoints(int idx, PointList *pts);

protected slots:
    void interfaceListChanged();

private:
    QVariant toolTipForInterface(int idx) const;
    QMap<QString, PointList> points;

#ifdef HAVE_LIBPCAP
    if_stat_cache_t *stat_cache_;
#endif // HAVE_LIBPCAP
};

#endif // INTERFACE_TREE_MODEL_H

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
