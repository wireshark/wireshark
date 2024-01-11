/** @file
 *
 * Model for the interface data for display in the interface frame
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_TREE_MODEL_H
#define INTERFACE_TREE_MODEL_H

#include <config.h>
#include <wireshark.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#include "ui/capture_globals.h"
#endif

#include <QAbstractTableModel>
#include <QList>
#include <QMap>
#include <QItemSelection>

typedef QList<int> PointList;

/*
 * When sorting, QSortFilterProxyModel creates its own mapping instead
 * of using the QModelIndex mapping with mapToSource to determine which
 * column in the proxy model maps to which column in the source. Its own
 * mapping is always done in order; this means that it's easier if all
 * the Views of this model keep the columns in the same relative order,
 * but can omit columns. (If you really need to change the order,
 * QHeaderView::swapSections() can be used.)
 */
enum InterfaceTreeColumns
{
    IFTREE_COL_EXTCAP,         // InterfaceFrame interfaceTree
    IFTREE_COL_EXTCAP_PATH,
    IFTREE_COL_HIDDEN,         // ManageInterfaceDialog localView
    IFTREE_COL_DISPLAY_NAME,   // InterfaceFrame interfaceTree
    IFTREE_COL_DESCRIPTION,    // ManageInterfaceDialog localView
    IFTREE_COL_NAME,           // ManageInterfaceDialog localView
    IFTREE_COL_COMMENT,        // ManageInterfaceDialog localView
    IFTREE_COL_STATS,          // InterfaceFrame interfaceTree
    IFTREE_COL_DLT,
    IFTREE_COL_PROMISCUOUSMODE,
    IFTREE_COL_TYPE,
    IFTREE_COL_ACTIVE,
    IFTREE_COL_SNAPLEN,
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    IFTREE_COL_BUFFERLEN,
#endif
#ifdef HAVE_PCAP_CREATE
    IFTREE_COL_MONITOR_MODE,
#endif
    IFTREE_COL_CAPTURE_FILTER,
    IFTREE_COL_PIPE_PATH,      // ManageInterfaceDialog pipeView
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
    void setCache(if_stat_cache_t *stat_cache);
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
    void interfaceListChanged();

private:
    QVariant toolTipForInterface(int idx) const;
    QMap<QString, PointList> points;
    QMap<QString, bool> active;

#ifdef HAVE_LIBPCAP
    if_stat_cache_t *stat_cache_;
#endif // HAVE_LIBPCAP
};

#endif // INTERFACE_TREE_MODEL_H
