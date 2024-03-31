/* interface_tree_model.cpp
 * Model for the interface data for display in the interface frame
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/interface_tree_model.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#include "capture/capture-pcap-util.h"
#include "capture_opts.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#endif

#include "wsutil/filesystem.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/stock_icon.h>
#include "main_application.h"

/* Needed for the meta type declaration of QList<int>* */
#include <ui/qt/models/sparkline_delegate.h>

#include "extcap.h"

const QString InterfaceTreeModel::DefaultNumericValue = QObject::tr("default");

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
    connect(mainApp, &MainApplication::appInitialized, this, &InterfaceTreeModel::interfaceListChanged);
    connect(mainApp, &MainApplication::localInterfaceListChanged, this, &InterfaceTreeModel::interfaceListChanged);
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

QString InterfaceTreeModel::interfaceError()
{
#ifdef HAVE_LIBPCAP
    //
    // First, see if there was an error fetching the interfaces.
    // If so, report it.
    //
    if (global_capture_opts.ifaces_err != 0)
    {
        return tr(global_capture_opts.ifaces_err_info);
    }

    //
    // Otherwise, if there are no rows, there were no interfaces
    // found.
    //
    if (rowCount() == 0)
    {
        return tr("No interfaces found.");
    }

    //
    // No error.  Return an empty string.
    //
    return "";
#else
    //
    // We were built without pcap support, so we have no notion of
    // local interfaces.
    //
    return tr("This version of Wireshark was built without packet capture support.");
#endif
}

int InterfaceTreeModel::rowCount(const QModelIndex &) const
{
#ifdef HAVE_LIBPCAP
    return (global_capture_opts.all_ifaces ? global_capture_opts.all_ifaces->len : 0);
#else
    /* Currently no interfaces available for libpcap-less builds */
    return 0;
#endif
}

int InterfaceTreeModel::columnCount(const QModelIndex &) const
{
    /* IFTREE_COL_MAX is not being displayed, it is the definition for the maximum numbers of columns */
    return ((int) IFTREE_COL_MAX);
}

QVariant InterfaceTreeModel::data(const QModelIndex &index, int role) const
{
#ifdef HAVE_LIBPCAP
    bool interfacesLoaded = true;
    if (! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len == 0)
        interfacesLoaded = false;

    if (!index.isValid())
        return QVariant();

    int row = index.row();
    InterfaceTreeColumns col = (InterfaceTreeColumns) index.column();

    if (interfacesLoaded)
    {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, row);

        /* Data for display in cell */
        if (role == Qt::DisplayRole)
        {
            /* Only the name is being displayed */
            if (col == IFTREE_COL_NAME)
            {
                return QString(device->name);
            }
            else if (col == IFTREE_COL_DESCRIPTION)
            {
                return QString(device->if_info.friendly_name);
            }
            else if (col == IFTREE_COL_DISPLAY_NAME)
            {
                return QString(device->display_name);
            }
            else if (col == IFTREE_COL_PIPE_PATH)
            {
                return QString(device->if_info.name);
            }
            else if (col == IFTREE_COL_CAPTURE_FILTER)
            {
                if (device->cfilter && strlen(device->cfilter) > 0)
                    return html_escape(QString(device->cfilter));
            }
            else if (col == IFTREE_COL_EXTCAP_PATH)
            {
                return QString(device->if_info.extcap);
            }
            else if (col == IFTREE_COL_SNAPLEN)
            {
                return device->has_snaplen ? QString::number(device->snaplen) : DefaultNumericValue;
            }
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
            else if (col == IFTREE_COL_BUFFERLEN)
            {
                return QString::number(device->buffer);
            }
#endif
            else if (col == IFTREE_COL_TYPE)
            {
                return QVariant::fromValue((int)device->if_info.type);
            }
            else if (col == IFTREE_COL_COMMENT)
            {
                QString comment = gchar_free_to_qstring(capture_dev_user_descr_find(device->name));
                if (comment.length() > 0)
                    return comment;
                else
                    return QString(device->if_info.vendor_description);
            }
            else if (col == IFTREE_COL_DLT)
            {
                // XXX - this is duplicated in
                // InterfaceTreeWidgetItem::updateInterfaceColumns;
                // it should be done in common code somewhere.
                QString linkname;
                if (device->active_dlt == -1)
                    linkname = "Unknown";
                else {
                    linkname = QObject::tr("DLT %1").arg(device->active_dlt);
                    for (GList *list = device->links; list != Q_NULLPTR; list = gxx_list_next(list)) {
                        link_row *linkr = gxx_list_data(link_row *, list);
                        if (linkr->dlt == device->active_dlt) {
                            linkname = linkr->name;
                            break;
                        }
                    }
                }

                return linkname;
            }
            else
            {
                /* Return empty string for every other DisplayRole */
                return QVariant();
            }
        }
        else if (role == Qt::CheckStateRole)
        {
            if (col == IFTREE_COL_HIDDEN)
            {
                /* Hidden is a de-selection, therefore inverted logic here */
                return device->hidden ? Qt::Unchecked : Qt::Checked;
            }
            else if (col == IFTREE_COL_PROMISCUOUSMODE)
            {
                return device->pmode ? Qt::Checked : Qt::Unchecked;
            }
#ifdef HAVE_PCAP_CREATE
            else if (col == IFTREE_COL_MONITOR_MODE)
            {
                return device->monitor_mode_enabled ? Qt::Checked : Qt::Unchecked;
            }
#endif
        }
        /* Used by SparkLineDelegate for loading the data for the statistics line */
        else if (role == Qt::UserRole)
        {
            if (col == IFTREE_COL_STATS)
            {
                if ((active.contains(device->name) && active[device->name]) && points.contains(device->name))
                    return QVariant::fromValue(points[device->name]);
            }
            else if (col == IFTREE_COL_ACTIVE)
            {
                if (active.contains(device->name))
                    return QVariant::fromValue(active[device->name]);
            }
            else if (col == IFTREE_COL_HIDDEN)
            {
                return QVariant::fromValue((bool)device->hidden);
            }
        }
        /* Displays the configuration icon for extcap interfaces */
        else if (role == Qt::DecorationRole)
        {
            if (col == IFTREE_COL_EXTCAP)
            {
                if (device->if_info.type == IF_EXTCAP)
                    return QIcon(StockIcon("x-capture-options"));
            }
        }
        else if (role == Qt::TextAlignmentRole)
        {
            if (col == IFTREE_COL_EXTCAP)
            {
                return Qt::AlignRight;
            }
        }
        /* Displays the tooltip for each row */
        else if (role == Qt::ToolTipRole)
        {
            return toolTipForInterface(row);
        }
    }
#else
    Q_UNUSED(index)
    Q_UNUSED(role)
#endif

    return QVariant();
}

QVariant InterfaceTreeModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal)
    {
        if (role == Qt::DisplayRole)
        {
            if (section == IFTREE_COL_HIDDEN)
            {
                return tr("Show");
            }
            else if (section == IFTREE_COL_NAME)
            {
                return tr("Interface Name");
            }
            else if (section == IFTREE_COL_DESCRIPTION)
            {
                return tr("Friendly Name");
            }
            else if (section == IFTREE_COL_DISPLAY_NAME)
            {
                return tr("Friendly Name");
            }
            else if (section == IFTREE_COL_PIPE_PATH)
            {
                return tr("Local Pipe Path");
            }
            else if (section == IFTREE_COL_COMMENT)
            {
                return tr("Comment");
            }
            else if (section == IFTREE_COL_DLT)
            {
                return tr("Link-Layer Header");
            }
            else if (section == IFTREE_COL_PROMISCUOUSMODE)
            {
                return tr("Promiscuous");
            }
            else if (section == IFTREE_COL_SNAPLEN)
            {
                return tr("Snaplen (B)");
            }
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
            else if (section == IFTREE_COL_BUFFERLEN)
            {
                return tr("Buffer (MB)");
            }
#endif
#ifdef HAVE_PCAP_CREATE
            else if (section == IFTREE_COL_MONITOR_MODE)
            {
                return tr("Monitor Mode");
            }
#endif
            else if (section == IFTREE_COL_CAPTURE_FILTER)
            {
                return tr("Capture Filter");
            }
        }
    }

    return QVariant();
}

QVariant InterfaceTreeModel::getColumnContent(int idx, int col, int role)
{
    return InterfaceTreeModel::data(index(idx, col), role);
}

#ifdef HAVE_PCAP_REMOTE
bool InterfaceTreeModel::isRemote(int idx)
{
    interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, idx);
    if (device->remote_opts.src_type == CAPTURE_IFREMOTE)
        return true;
    return false;
}
#endif

/**
 * The interface list has changed. global_capture_opts.all_ifaces may have been reloaded
 * or changed with current data. beginResetModel() and endResetModel() will signalize the
 * proxy model and the view, that the data has changed and the view has to reload
 */
void InterfaceTreeModel::interfaceListChanged()
{
    beginResetModel();

    points.clear();
    active.clear();

    endResetModel();
}

/*
 * Displays the tooltip code for the given device index.
 */
QVariant InterfaceTreeModel::toolTipForInterface(int idx) const
{
#ifdef HAVE_LIBPCAP
    if (! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len <= (unsigned) idx)
        return QVariant();

    interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

    QString tt_str = "<p>";
    if (device->no_addresses > 0)
    {
        tt_str += QString("%1: %2")
                .arg(device->no_addresses > 1 ? tr("Addresses") : tr("Address"))
                .arg(html_escape(device->addresses))
                .replace('\n', ", ");
    }
    else if (device->if_info.type == IF_EXTCAP)
    {
        tt_str = QString(tr("Extcap interface: %1")).arg(get_basename(device->if_info.extcap));
    }
    else
    {
        tt_str = tr("No addresses");
    }
    tt_str += "<br/>";

    QString cfilter = device->cfilter;
    if (cfilter.isEmpty())
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
#else
    Q_UNUSED(idx)

    return QVariant();
#endif
}

#ifdef HAVE_LIBPCAP
void InterfaceTreeModel::setCache(if_stat_cache_t *stat_cache)
{
    stopStatistic();
    stat_cache_ = stat_cache;
}

void InterfaceTreeModel::stopStatistic()
{
    if (stat_cache_)
    {
        capture_stat_stop(stat_cache_);
        stat_cache_ = NULL;
    }
}
#endif

void InterfaceTreeModel::updateStatistic(unsigned int idx)
{
#ifdef HAVE_LIBPCAP
    if (! global_capture_opts.all_ifaces || global_capture_opts.all_ifaces->len <= (unsigned) idx)
        return;

    interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

    if (device->if_info.type == IF_PIPE || device->if_info.type == IF_EXTCAP)
        return;

    if (!stat_cache_)
    {
        // Start gathering statistics using dumpcap
        //
        // The stat cache will only properly configure if it has the list
        // of interfaces in global_capture_opts->all_ifaces.
        // We crash if we try to do this from InterfaceFrame::showEvent,
        // because main.cpp calls mainw->show() before capture_opts_init().
        stat_cache_ = capture_stat_start(&global_capture_opts);
    }

    struct pcap_stat stats;
    unsigned diff = 0;
    bool isActive = false;

    if (capture_stats(stat_cache_, device->name, &stats))
    {
        if ( (int) stats.ps_recv > 0 )
            isActive = true;

        if ((int)(stats.ps_recv - device->last_packets) >= 0)
        {
            diff = stats.ps_recv - device->last_packets;
            device->packet_diff = diff;
        }
        device->last_packets = stats.ps_recv;
    }

    points[device->name].append(diff);

    if (active[device->name] != isActive)
    {
        emit layoutAboutToBeChanged();
        active[device->name] = isActive;
        emit layoutChanged();
    }

    emit dataChanged(index(idx, IFTREE_COL_STATS), index(idx, IFTREE_COL_STATS));

#else
    Q_UNUSED(idx)
#endif
}

QItemSelection InterfaceTreeModel::selectedDevices()
{
    QItemSelection mySelection;
#ifdef HAVE_LIBPCAP
    for (int idx = 0; idx < rowCount(); idx++)
    {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, idx);

        if (device->selected)
        {
            QModelIndex selectIndex = index(idx, 0);
            mySelection.merge(
                    QItemSelection(selectIndex, index(selectIndex.row(), columnCount() - 1)),
                    QItemSelectionModel::SelectCurrent
                    );
        }
    }
#endif
    return mySelection;
}

bool InterfaceTreeModel::updateSelectedDevices(QItemSelection sourceSelection)
{
    bool selectionHasChanged = false;
#ifdef HAVE_LIBPCAP
    QList<int> selectedIndices;

    QItemSelection::const_iterator it = sourceSelection.constBegin();
    while (it != sourceSelection.constEnd())
    {
        QModelIndexList indeces = ((QItemSelectionRange) (*it)).indexes();

        QModelIndexList::const_iterator cit = indeces.constBegin();
        while (cit != indeces.constEnd())
        {
            QModelIndex index = (QModelIndex) (*cit);
            if (! selectedIndices.contains(index.row()))
            {
                selectedIndices.append(index.row());
            }
            ++cit;
        }
        ++it;
    }

    global_capture_opts.num_selected = 0;

    for (unsigned int idx = 0; idx < global_capture_opts.all_ifaces->len; idx++)
    {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, idx);
        if (selectedIndices.contains(idx))
        {
            if (! device->selected)
                selectionHasChanged = true;
            device->selected = true;
            global_capture_opts.num_selected++;
        } else {
            if (device->selected)
                selectionHasChanged = true;
            device->selected = false;
        }
    }
#else
    Q_UNUSED(sourceSelection)
#endif
    return selectionHasChanged;
}
