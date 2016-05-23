/* interface_tree.cpp
 * Display of interface names, traffic sparklines, and, if available,
 * extcap options
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
#include <wsutil/utf8_entities.h>
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

// The interface list and capture filter editor in the main window and
// the capture interfaces dialog should have the following behavior:
//
// - The global capture options are the source of truth for selected
//   interfaces.
// - The global capture options are the source of truth for the capture
//   filter for an interface.
// - If multiple interfaces with different filters are selected, the
//   CaptureFilterEdit should be cleared and show a corresponding
//   placeholder message. Device cfilters should not be changed.
// - Entering a filter in a CaptureFilterEdit should update the device
//   cfilter for each selected interface. This should happen even when
//   conflicting filters are selected, as described above.
// - Interface selections and cfilter changes in CaptureInterfacesDialog
//   should be reflected in MainWelcome.

#ifdef HAVE_LIBPCAP
const int stat_update_interval_ = 1000; // ms
#endif

InterfaceTree::InterfaceTree(QWidget *parent) :
    QTreeWidget(parent)
#ifdef HAVE_LIBPCAP
    ,stat_cache_(NULL)
    ,stat_timer_(NULL)
#endif // HAVE_LIBPCAP
{
    QTreeWidgetItem *ti;

    qRegisterMetaType< PointList >("PointList");

    header()->setVisible(false);
    setRootIsDecorated(false);
    setUniformRowHeights(true);
    /* Seems to have no effect, still the default value (2) is being used, as it
     * was set in the .ui file. But better safe, then sorry. */
    resetColumnCount();
    setSelectionMode(QAbstractItemView::ExtendedSelection);
    setAccessibleName(tr("Welcome screen list"));

    setItemDelegateForColumn(IFTREE_COL_STATS, new SparkLineDelegate(this));
    setDisabled(true);

    ti = new QTreeWidgetItem();
    ti->setText(IFTREE_COL_NAME, tr("Waiting for startup%1").arg(UTF8_HORIZONTAL_ELLIPSIS));
    addTopLevelItem(ti);
    resizeColumnToContents(IFTREE_COL_NAME);

    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(getInterfaceList()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(interfaceListChanged()));
    connect(this, SIGNAL(itemSelectionChanged()), this, SLOT(selectedInterfaceChanged()));
}

InterfaceTree::~InterfaceTree() {
#ifdef HAVE_LIBPCAP
    if (stat_cache_) {
      capture_stat_stop(stat_cache_);
      stat_cache_ = NULL;
    }
#endif // HAVE_LIBPCAP
}

class InterfaceTreeWidgetItem : public QTreeWidgetItem
{
public:
    InterfaceTreeWidgetItem() : QTreeWidgetItem()  {}
    QList<int> points;
};

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

void InterfaceTree::resizeEvent(QResizeEvent *evt)
{
    int max_if_width = width() * 2 / 3; // Arbitrary

    setUpdatesEnabled(false);
    resizeColumnToContents(IFTREE_COL_NAME);
    if (columnWidth(IFTREE_COL_NAME) > max_if_width) {
        setColumnWidth(IFTREE_COL_NAME, max_if_width);
    }

    setUpdatesEnabled(true);

    QTreeWidget::resizeEvent(evt);
}

void InterfaceTree::display()
{
#ifdef HAVE_LIBPCAP
    interface_t device;
#ifdef HAVE_EXTCAP
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

    // List physical interfaces first. Alternatively we could sort them by
    // traffic, interface name, or most recently used.
    QList<QTreeWidgetItem *> phys_ifaces;
    QList<QTreeWidgetItem *> virt_ifaces;

    global_capture_opts.num_selected = 0;
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

        /* Continue if capture device is hidden */
        if (device.hidden) {
            continue;
        }

        InterfaceTreeWidgetItem *ti = new InterfaceTreeWidgetItem();
        QString if_name = device.display_name;
        ti->setText(IFTREE_COL_NAME, if_name);
        ti->setData(IFTREE_COL_NAME, Qt::AccessibleTextRole, if_name);

        ti->setData(IFTREE_COL_NAME, Qt::UserRole, QString(device.name));
        ti->setData(IFTREE_COL_STATS, Qt::UserRole, qVariantFromValue(&ti->points));

#ifdef HAVE_EXTCAP
        if (device.if_info.type == IF_EXTCAP) {
            if (extcap_has_configuration((const char *)(device.name), FALSE)) {
                ti->setIcon(IFTREE_COL_EXTCAP, extcap_icon);
                ti->setData(IFTREE_COL_EXTCAP, Qt::UserRole, QString(device.if_info.extcap));

                if (!(device.external_cap_args_settings != 0 &&
                      g_hash_table_size(device.external_cap_args_settings) > 0))
                {
                    QFont ti_font = ti->font(IFTREE_COL_NAME);
                    ti_font.setItalic(true);
                    ti->setFont(IFTREE_COL_NAME, ti_font);
                }
            }
            virt_ifaces << ti;
        } else
#endif
        {
            phys_ifaces << ti;
        }

        // XXX Need to handle interfaces passed from the command line.
        if (strstr(prefs.capture_device, device.name) != NULL) {
            device.selected = TRUE;
            global_capture_opts.num_selected++;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
    }

    if (!phys_ifaces.isEmpty()) addTopLevelItems(phys_ifaces);
    if (!virt_ifaces.isEmpty()) addTopLevelItems(virt_ifaces);
    updateSelectedInterfaces();
    updateToolTips();

    // XXX Add other device information
    resizeColumnToContents(IFTREE_COL_NAME);
    resizeColumnToContents(IFTREE_COL_STATS);

#ifdef HAVE_EXTCAP
    resizeColumnToContents(IFTREE_COL_EXTCAP);
#endif

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
        ++iter;
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
        ++iter;
    }
#endif // HAVE_LIBPCAP
}

// Update our global device selections based on the given TreeWidget.
// This is shared with CaptureInterfacesDialog.
// Column name_col UserRole data MUST be set to the interface name.
void InterfaceTree::updateGlobalDeviceSelections(QTreeWidget *if_tree, int name_col)
{
#ifdef HAVE_LIBPCAP
    if (!if_tree) return;
    QTreeWidgetItemIterator iter(if_tree);

    global_capture_opts.num_selected = 0;

    while (*iter) {
        QString device_name = (*iter)->data(name_col, Qt::UserRole).value<QString>();
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
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

                    device.locked = FALSE;
                    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
                }
                break;
            }
        }
        ++iter;
    }
#else // HAVE_LIBPCAP
    Q_UNUSED(if_tree)
    Q_UNUSED(name_col)
#endif // HAVE_LIBPCAP
}

// Update selected interfaces based on the global interface list..
// Must not change any interface data.
// Must not emit itemSelectionChanged.
void InterfaceTree::updateSelectedInterfaces()
{
#ifdef HAVE_LIBPCAP
    interface_t *device;
    QTreeWidgetItemIterator iter(this);
    bool blocking = blockSignals(true);

    while (*iter) {
        QString device_name = (*iter)->data(IFTREE_COL_NAME, Qt::UserRole).value<QString>();
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device_name.compare(QString().fromUtf8(device->name)) == 0) {
                (*iter)->setSelected(device->selected);
                break;
            }
        }
        ++iter;
    }
    blockSignals(blocking);
#endif // HAVE_LIBPCAP
}

// Update the tooltip for each interface based on the global interface list..
// Must not change any interface data.
void InterfaceTree::updateToolTips()
{
#ifdef HAVE_LIBPCAP
    QTreeWidgetItemIterator iter(this);

    while (*iter) {
        QString device_name = (*iter)->data(IFTREE_COL_NAME, Qt::UserRole).value<QString>();
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device_name.compare(QString().fromUtf8(device.name)) == 0) {
                // To do:
                // - Sync with code in CaptureInterfacesDialog.
                // - Add more information to the tooltip.
                QString tt_str = "<p>";
                if (device.no_addresses > 0) {
                    tt_str += QString("%1: %2").arg(device.no_addresses > 1 ? tr("Addresses") : tr("Address")).arg(device.addresses);
                    tt_str.replace('\n', ", ");
                } else {
                    tt_str = tr("No addresses");
                }
                tt_str += "<br/>";
                QString cfilter = device.cfilter;
                if (cfilter.isEmpty()) {
                    tt_str += tr("No capture filter");
                } else {
                    tt_str += QString("%1: %2")
                            .arg(tr("Capture filter"))
                            .arg(cfilter);
                }
                tt_str += "</p>";

                for (int col = 0; col < columnCount(); col++) {
                    (*iter)->setToolTip(col, tt_str);
                }
            }
        }
        ++iter;
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
