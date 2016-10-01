/* interface_tree_model.cpp
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

#include "config.h"

#include "interface_tree_model.h"

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#include "caputils/capture-pcap-util.h"
#include "capture_opts.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#endif

#include "wsutil/filesystem.h"

#include "qt_ui_utils.h"
#include "stock_icon.h"
#include "wireshark_application.h"

/* Needed for the meta type declaration of QList<int>* */
#include "sparkline_delegate.h"

#ifdef HAVE_EXTCAP
#include "extcap.h"
#endif

/**
 * This is the data model for interface trees. It implies, that the index within
 * global_capture_opts.all_ifaces is identical to the row. This is always the case, even
 * when interfaces are hidden by the proxy model. But for this to work, every access
 * to the index from within the view, has to be filtered through the proxy model.
 */
InterfaceTreeModel::InterfaceTreeModel(QObject *parent) :
    QAbstractTableModel(parent)
#ifdef HAVE_LIBPCAP
    ,stat_cache_(NULL)
#endif
{
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(interfaceListChanged()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(interfaceListChanged()));
}

InterfaceTreeModel::~InterfaceTreeModel(void)
{
#ifdef HAVE_LIBPCAP
    if (stat_cache_) {
        capture_stat_stop(stat_cache_);
        stat_cache_ = NULL;
    }
#endif // HAVE_LIBPCAP
}

int InterfaceTreeModel::rowCount(const QModelIndex & parent _U_) const
{
    return (global_capture_opts.all_ifaces ? global_capture_opts.all_ifaces->len : 0);
}

int InterfaceTreeModel::columnCount(const QModelIndex & parent _U_) const
{
    /* IFTREE_COL_MAX is not being displayed, it is the definition for the maximum numbers of columns */
    return ((int) IFTREE_COL_MAX);
}

QVariant InterfaceTreeModel::data(const QModelIndex &index, int role) const
{
    bool interfacesLoaded = true;
    if ( ! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len == 0 )
        interfacesLoaded = false;

    if ( !index.isValid() )
        return QVariant();

    int row = index.row();
    int col = index.column();

    /* Data for display in cell */
    if ( role == Qt::DisplayRole )
    {
        if ( interfacesLoaded )
        {
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, row);
            /* Only the name is being displayed */
            if ( col == IFTREE_COL_NAME )
            {
                return QString(device.display_name);
            }

        }

        /* Return empty string for every other DisplayRole */
        return QVariant();
    }
    /* Used by SparkLineDelegate for loading the data for the statistics line */
    else if ( role == Qt::UserRole && col == IFTREE_COL_STATS && interfacesLoaded )
    {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, row);
        if ( points.contains(device.name) )
            return qVariantFromValue(points[device.name]);
    }
#ifdef HAVE_EXTCAP
    /* Displays the configuration icon for extcap interfaces */
    else if ( role == Qt::DecorationRole && interfacesLoaded )
    {
        if ( col == IFTREE_COL_EXTCAP )
        {
            QIcon extcap_icon(StockIcon("x-capture-options"));
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, row);
            if ( device.if_info.type == IF_EXTCAP )
                return extcap_icon;
        }
    }
    else if ( role == Qt::TextAlignmentRole)
    {
        if ( col == IFTREE_COL_EXTCAP )
        {
            return Qt::AlignRight;
        }
    }
#endif
    /* Displays the tooltip for each row */
    else if ( role == Qt::ToolTipRole )
    {
        return toolTipForInterface(row);
    }

    return QVariant();
}

/**
 * The interface list has changed. global_capture_opts.all_ifaces may have been reloaded
 * or changed with current data. beginResetModel() and endResetModel() will signalize the
 * proxy model and the view, that the data has changed and the view has to reload
 */
void InterfaceTreeModel::interfaceListChanged()
{
    emit beginResetModel();

    foreach(QString key, points.keys())
        points[key]->clear();
    points.clear();

    emit endResetModel();
}

/*
 * Displays the tooltip code for the given device index.
 */
QVariant InterfaceTreeModel::toolTipForInterface(int idx) const
{
    if ( ! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len <= (guint) idx)
        return QVariant();

    interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

    QString tt_str = "<p>";
    if ( device.no_addresses > 0 )
    {
        tt_str += QString("%1: %2")
                .arg(device.no_addresses > 1 ? tr("Addresses") : tr("Address"))
                .arg(html_escape(device.addresses))
                .replace('\n', ", ");
    }
#ifdef HAVE_EXTCAP
    else if ( device.if_info.type == IF_EXTCAP )
    {
        tt_str = QString(tr("Extcap interface: %1")).arg(get_basename(device.if_info.extcap));
    }
#endif
    else
    {
        tt_str = tr("No addresses");
    }
    tt_str += "<br/>";

    QString cfilter = device.cfilter;
    if ( cfilter.isEmpty() )
    {
        tt_str += tr("No capture filter");
    }
    else
    {
        tt_str += QString("%1: %2")
                .arg(tr("Capture filter"))
                .arg(html_escape(cfilter));
    }
    tt_str += "</p>";

    return tt_str;
}

#ifdef HAVE_LIBPCAP
void InterfaceTreeModel::stopStatistic()
{
    if ( stat_cache_ )
    {
        capture_stat_stop(stat_cache_);
        stat_cache_ = NULL;
    }
}
#endif

void InterfaceTreeModel::updateStatistic(unsigned int idx)
{
    guint diff;

    if ( ! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len <= (guint) idx )
        return;

    interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

    if ( device.if_info.type == IF_PIPE )
        return;

#ifdef HAVE_LIBPCAP
    if ( !stat_cache_ )
    {
        // Start gathering statistics using dumpcap
        // We crash (on OS X at least) if we try to do this from ::showEvent.
        stat_cache_ = capture_stat_start(&global_capture_opts);
    }
    if ( !stat_cache_ )
        return;
#endif

    struct pcap_stat stats;

    if ( !points.contains(device.name) )
        points.insert(device.name, new PointList());

    diff = 0;
    if ( capture_stats(stat_cache_, device.name, &stats) )
    {
        if ( (int)(stats.ps_recv - device.last_packets) >= 0 )
        {
            diff = stats.ps_recv - device.last_packets;
            device.packet_diff = diff;
        }
        device.last_packets = stats.ps_recv;

        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, idx);
        g_array_insert_val(global_capture_opts.all_ifaces, idx, device);
    }

    points[device.name]->append(diff);
    emit dataChanged(index(idx, IFTREE_COL_STATS), index(idx, IFTREE_COL_STATS));
}

void InterfaceTreeModel::getPoints(int idx, PointList *pts)
{
    if ( ! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len <= (guint) idx )
        return;

    interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, idx);
    if ( points.contains(device.name) )
        pts->append(*points[device.name]);
}
