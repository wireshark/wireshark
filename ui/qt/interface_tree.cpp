/* interface_tree.cpp
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

#include "interface_tree.h"

#include "epan/prefs.h"

#ifdef HAVE_LIBPCAP
#include "ui/capture_globals.h"
#endif
#include "ui/iface_lists.h"
#include "ui/utf8_entities.h"
#include "ui/ui_util.h"

#include "qt_ui_utils.h"
#include "sparkline_delegate.h"
#include "stock_icon.h"
#include "wireshark_application.h"

#ifdef HAVE_EXTCAP
#include "extcap.h"
#endif

#include <QLabel>
#include <QHeaderView>
#include <QTimer>

const int stat_update_interval_ = 1000; // ms

InterfaceTree::InterfaceTree(QWidget *parent) :
    QTreeWidget(parent)
#ifdef HAVE_LIBPCAP
    ,stat_cache_(NULL)
    ,stat_timer_(NULL)
#endif // HAVE_LIBPCAP
{
    QTreeWidgetItem *ti;

    qRegisterMetaType< PointList >( "PointList" );

    header()->setVisible(false);
    setRootIsDecorated(false);
    setUniformRowHeights(true);
    /* Seems to have no effect, still the default value (2) is being used, as it
     * was set in the .ui file. But better safe, then sorry. */
    resetColumnCount();
    setSelectionMode(QAbstractItemView::ExtendedSelection);
    setAccessibleName(tr("Welcome screen list"));

    setItemDelegateForColumn(IFTREE_COL_STATS, new SparkLineDelegate());
    setDisabled(true);

    ti = new QTreeWidgetItem();
    ti->setText(IFTREE_COL_NAME, tr("Waiting for startup%1").arg(UTF8_HORIZONTAL_ELLIPSIS));
    addTopLevelItem(ti);
    resizeColumnToContents(IFTREE_COL_NAME);

    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(getInterfaceList()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(interfaceListChanged()));
    connect(this, SIGNAL(itemSelectionChanged()), this, SLOT(updateSelectedInterfaces()));
}

InterfaceTree::~InterfaceTree() {
#ifdef HAVE_LIBPCAP
    QTreeWidgetItemIterator iter(this);

    if (stat_cache_) {
      capture_stat_stop(stat_cache_);
      stat_cache_ = NULL;
    }

    while (*iter) {
        QList<int> *points;

        points = (*iter)->data(IFTREE_COL_STATS, Qt::UserRole).value<QList<int> *>();
        delete(points);
        ++iter;
    }
#endif // HAVE_LIBPCAP
}

/* Resets the column count to the maximum colum count
 *
 * This is necessary, because the treeview may have more columns than
 * the default value (2).
 */
void InterfaceTree::resetColumnCount()
{
    setColumnCount(IFTREE_COL_MAX);
}

void InterfaceTree::hideEvent(QHideEvent *) {
#ifdef HAVE_LIBPCAP
    if (stat_timer_) stat_timer_->stop();
    if (stat_cache_) {
        capture_stat_stop(stat_cache_);
        stat_cache_ = NULL;
    }
#endif // HAVE_LIBPCAP
}

void InterfaceTree::showEvent(QShowEvent *) {
#ifdef HAVE_LIBPCAP
    if (stat_timer_) stat_timer_->start(stat_update_interval_);
#endif // HAVE_LIBPCAP
}

#include <QDebug>
void InterfaceTree::resizeEvent(QResizeEvent *)
{
    int max_if_width = width() * 2 / 3; // Arbitrary

    setUpdatesEnabled(false);
    resizeColumnToContents(IFTREE_COL_NAME);
    if (columnWidth(IFTREE_COL_NAME) > max_if_width) {
        setColumnWidth(IFTREE_COL_NAME, max_if_width);
    }

    setUpdatesEnabled(true);
}

void InterfaceTree::display()
{
#ifdef HAVE_LIBPCAP
    interface_t device;
#if HAVE_EXTCAP
    QIcon extcap_icon(StockIcon("x-capture-options"));
#endif

    setDisabled(false);
    clear();

    if (global_capture_opts.all_ifaces->len == 0) {
        // Error,or just no interfaces?
        QTreeWidgetItem *ti = new QTreeWidgetItem();
        QLabel *err_label;

        if (global_capture_opts.ifaces_err == 0) {
            err_label = new QLabel("No interfaces found");
        } else {
            err_label = new QLabel(global_capture_opts.ifaces_err_info);
        }
        err_label->setWordWrap(true);

        setColumnCount(1);
        addTopLevelItem(ti);
        setItemWidget(ti, 0, err_label);
        resizeColumnToContents(0);
        return;
    }

    /* when no interfaces were available initially and an update of the
       interface list called this function, the column count is set to 1
       reset it to ensure that the interface list is properly displayed */
    resetColumnCount();

    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        QList<int> *points;

        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

        /* Continue if capture device is hidden */
        if (device.hidden) {
            continue;
        }

        QTreeWidgetItem *ti = new QTreeWidgetItem();
        ti->setText(IFTREE_COL_NAME, QString().fromUtf8(device.display_name));
        ti->setData(IFTREE_COL_NAME, Qt::UserRole, QString(device.name));
        points = new QList<int>();
        ti->setData(IFTREE_COL_STATS, Qt::UserRole, qVariantFromValue(points));
#if HAVE_EXTCAP
        if ( device.if_info.type == IF_EXTCAP )
        {
            if ( extcap_has_configuration((const char *)(device.name)) )
            {
                ti->setIcon(IFTREE_COL_EXTCAP, extcap_icon);
                ti->setData(IFTREE_COL_EXTCAP, Qt::UserRole, QString(device.if_info.extcap));

                if ( !(device.external_cap_args_settings != 0 &&
                        g_hash_table_size(device.external_cap_args_settings ) > 0) )
                {
                    QFont ti_font = ti->font(IFTREE_COL_NAME);
                    ti_font.setItalic(true);
                    ti->setFont(IFTREE_COL_NAME, ti_font );
                }
            }
        }
#endif
        addTopLevelItem(ti);
        // XXX Add other device information
        resizeColumnToContents(IFTREE_COL_NAME);
        resizeColumnToContents(IFTREE_COL_STATS);

#if HAVE_EXTCAP
        resizeColumnToContents(IFTREE_COL_EXTCAP);
#endif

        if (strstr(prefs.capture_device, device.name) != NULL) {
            device.selected = TRUE;
            global_capture_opts.num_selected++;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
        if (device.selected) {
            ti->setSelected(true);
        }
    }
#else
    QTreeWidgetItem *ti = new QTreeWidgetItem();

    clear();
    setColumnCount(1);
    ti->setText(0, tr("Interface information not available"));
    addTopLevelItem(ti);
    resizeColumnToContents(0);
#endif // HAVE_LIBPCAP
}

void InterfaceTree::getInterfaceList()
{
    display();
    resizeEvent(NULL);

#ifdef HAVE_LIBPCAP
    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
#endif
}

void InterfaceTree::getPoints(int row, PointList *pts)
{
    QTreeWidgetItemIterator iter(this);
    //qDebug("iter;..!");

    for (int i = 0; (*iter); i++)
    {
        if (row == i)
        {
            //qDebug("found! row:%d", row);
            QList<int> *punkt = (*iter)->data(IFTREE_COL_STATS, Qt::UserRole).value<QList<int> *>();
            for (int j = 0; j < punkt->length(); j++)
            {
                pts->append(punkt->at(j));
            }
            //pts = new QList<int>(*punkt);
            //pts->operator =(punkt);
            //pts = punkt;
            //pts->append(150);
            //qDebug("done");
            return;
        }
        iter++;
    }
}

void InterfaceTree::updateStatistics(void) {
#ifdef HAVE_LIBPCAP
    interface_t device;
    guint diff, if_idx;
    struct pcap_stat stats;

    if (!stat_cache_) {
        // Start gathering statistics using dumpcap
        // We crash (on OS X at least) if we try to do this from ::showEvent.
        stat_cache_ = capture_stat_start(&global_capture_opts);
    }
    if (!stat_cache_) return;

    QTreeWidgetItemIterator iter(this);
    while (*iter) {
        QList<int> *points;

        for (if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
            QString device_name = (*iter)->data(IFTREE_COL_NAME, Qt::UserRole).value<QString>();

            if (device_name.compare(device.name) || device.hidden || device.type == IF_PIPE)
                continue;

            diff = 0;
            if (capture_stats(stat_cache_, device.name, &stats)) {
                if ((int)(stats.ps_recv - device.last_packets) >= 0) {
                    diff = stats.ps_recv - device.last_packets;
                    device.packet_diff = diff;
                }
                device.last_packets = stats.ps_recv;
            }

            points = (*iter)->data(IFTREE_COL_STATS, Qt::UserRole).value<QList<int> *>();

            points->append(diff);
            update(indexFromItem((*iter), IFTREE_COL_STATS));
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, if_idx);
            g_array_insert_val(global_capture_opts.all_ifaces, if_idx, device);
        }
        iter++;
    }
#endif // HAVE_LIBPCAP
}

void InterfaceTree::updateSelectedInterfaces()
{
#ifdef HAVE_LIBPCAP
    QTreeWidgetItemIterator iter(this);

    global_capture_opts.num_selected = 0;

    while (*iter) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            QString device_name = (*iter)->data(IFTREE_COL_NAME, Qt::UserRole).value<QString>();
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device_name.compare(QString().fromUtf8(device.name)) == 0) {
                if (!device.locked) {
                    if ((*iter)->isSelected()) {
                        device.selected = TRUE;
                        global_capture_opts.num_selected++;
                    } else {
                        device.selected = FALSE;
                    }
                    device.locked = TRUE;
                    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                    g_array_insert_val(global_capture_opts.all_ifaces, i, device);

                    emit interfaceUpdated(device.name, device.selected);

                    device.locked = FALSE;
                    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
                }
                break;
            }
        }
        iter++;
    }
#endif // HAVE_LIBPCAP
}

void InterfaceTree::setSelectedInterfaces()
{
#ifdef HAVE_LIBPCAP
    interface_t device;
    QTreeWidgetItemIterator iter(this);

    while (*iter) {
        QString device_name = (*iter)->data(IFTREE_COL_NAME, Qt::UserRole).value<QString>();
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device_name.compare(QString().fromUtf8(device.name)) == 0) {
                (*iter)->setSelected(device.selected);
                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                g_array_insert_val(global_capture_opts.all_ifaces, i, device);
                break;
            }
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
        iter++;
    }
#endif // HAVE_LIBPCAP
}

void InterfaceTree::interfaceListChanged()
{
#ifdef HAVE_LIBPCAP
    display();
#endif
}

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
