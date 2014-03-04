/* capture_interfaces_dialog.cpp
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

#include <glib.h>

#include "capture_interfaces_dialog.h"
#include "ui_capture_interfaces_dialog.h"

#include "wireshark_application.h"

#ifdef HAVE_LIBPCAP

#include <QTimer>

#include "capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"

#include "ui/ui_util.h"
#include "ui/utf8_entities.h"

#include <cstdio>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/addr_resolv.h>

#include "sparkline_delegate.h"

const int stat_update_interval_ = 1000; // ms

CaptureInterfacesDialog::CaptureInterfacesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CaptureInterfacesDialog)
{
    ui->setupUi(this);

    stat_timer_ = NULL;
    stat_cache_ = NULL;

    // XXX - Enable / disable as needed
    start_bt_ = ui->buttonBox->addButton(tr("Start"), QDialogButtonBox::YesRole);
    connect(start_bt_, SIGNAL(clicked()), this, SLOT(on_bStart_clicked()));

    stop_bt_ = ui->buttonBox->addButton(tr("Stop"), QDialogButtonBox::NoRole);
    stop_bt_->setEnabled(false);
    connect(stop_bt_, SIGNAL(clicked()), this, SLOT(on_bStop_clicked()));

    //connect(ui->tbInterfaces,SIGNAL(itemPressed(QTableWidgetItem *)),this,SLOT(tableItemPressed(QTableWidgetItem *)));
    connect(ui->tbInterfaces,SIGNAL(itemClicked(QTableWidgetItem *)),this,SLOT(tableItemClicked(QTableWidgetItem *)));
}

void CaptureInterfacesDialog::tableItemClicked(QTableWidgetItem * item)
{
    Q_UNUSED(item)

    interface_t device;
    global_capture_opts.num_selected = 0;

    for (int row = 0; row < ui->tbInterfaces->rowCount(); row++)
    {
        bool checked = (ui->tbInterfaces->item(row, 0)->checkState() == Qt::Checked) ? true : false;
        QString interface_name = ui->tbInterfaces->item(row, 1)->text();

        device = g_array_index(global_capture_opts.all_ifaces, interface_t, row);

        if (checked == true)
        {
            device.selected = TRUE;
            global_capture_opts.num_selected++;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, row);
            g_array_insert_val(global_capture_opts.all_ifaces, row, device);
        }
        else
        {
            device.selected = FALSE;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, row);
            g_array_insert_val(global_capture_opts.all_ifaces, row, device);
        }
    }
}

CaptureInterfacesDialog::~CaptureInterfacesDialog()
{
    delete ui;
}

void CaptureInterfacesDialog::SetTab(int index)
{
    ui->tabWidget->setCurrentIndex(index);
}

void CaptureInterfacesDialog::on_capturePromModeCheckBox_toggled(bool checked)
{
    prefs.capture_prom_mode = checked;
}

void CaptureInterfacesDialog::on_gbStopCaptureAuto_toggled(bool checked)
{
    global_capture_opts.has_file_duration = checked;
}

void CaptureInterfacesDialog::on_gbNewFileAuto_toggled(bool checked)
{
    global_capture_opts.multi_files_on = checked;
}

void CaptureInterfacesDialog::on_cbUpdatePacketsRT_toggled(bool checked)
{
    global_capture_opts.real_time_mode = checked;
}

void CaptureInterfacesDialog::on_cbAutoScroll_toggled(bool checked)
{
    Q_UNUSED(checked)
    //global_capture_opts.has_file_duration = checked;
}

void CaptureInterfacesDialog::on_cbExtraCaptureInfo_toggled(bool checked)
{
    global_capture_opts.show_info = checked;
}

void CaptureInterfacesDialog::on_cbResolveMacAddresses_toggled(bool checked)
{
    gbl_resolv_flags.mac_name = checked;
}

void CaptureInterfacesDialog::on_cbResolveNetworkNames_toggled(bool checked)
{
    gbl_resolv_flags.network_name = checked;
}

void CaptureInterfacesDialog::on_cbResolveTransportNames_toggled(bool checked)
{
    gbl_resolv_flags.transport_name = checked;
}

void CaptureInterfacesDialog::on_bStart_clicked()
{
    qDebug("Starting capture");

    emit startCapture();

    accept();
}

void CaptureInterfacesDialog::on_bStop_clicked()
{
    qDebug("Stop capture");

    emit stopCapture();
}

// Not sure why we have to do this manually.
void CaptureInterfacesDialog::on_buttonBox_rejected()
{
    reject();
}

void CaptureInterfacesDialog::on_buttonBox_helpRequested()
{
    // Probably the wrong URL.
    wsApp->helpTopicAction(HELP_CAPTURE_INTERFACES_DIALOG);
}

void CaptureInterfacesDialog::UpdateInterfaces()
{
    if(prefs.capture_pcap_ng) {
        ui->rbPcapng->setChecked(true);
    } else {
        ui->rbPcap->setChecked(true);
    }
    ui->capturePromModeCheckBox->setChecked(prefs.capture_prom_mode);

    ui->gbStopCaptureAuto->setChecked(global_capture_opts.has_file_duration);
    ui->gbNewFileAuto->setChecked(global_capture_opts.multi_files_on);

    ui->cbUpdatePacketsRT->setChecked(global_capture_opts.real_time_mode);
    ui->cbAutoScroll->setChecked(true);
    ui->cbExtraCaptureInfo->setChecked(global_capture_opts.show_info);

    ui->cbResolveMacAddresses->setChecked(gbl_resolv_flags.mac_name);
    ui->cbResolveNetworkNames->setChecked(gbl_resolv_flags.network_name);
    ui->cbResolveTransportNames->setChecked(gbl_resolv_flags.transport_name);

    ui->tbInterfaces->setRowCount(0);

    GList *if_list;
    int err;
    gchar *err_str = NULL;
    GList        *list;
    char         *snaplen_string, *linkname;
    //guint         i;
    link_row     *linkr = NULL;
    //interface_t   device;
  #if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    gint          buffer;
  #endif
    gint          snaplen;
    gboolean      hassnap, pmode;

    if_list = capture_interface_list(&err, &err_str,main_window_update);
    if_list = g_list_sort(if_list, if_list_comparator_alph);

    // XXX Do we need to check for this? capture_interface_list returns an error if the length is 0.
    if (g_list_length(if_list) > 0) {
        interface_t device;
        //setDisabled(false);

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            QList<int> *points;

            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            /* Continue if capture device is hidden */
            if (device.hidden) {
                continue;
            }

            QString output;

            ui->tbInterfaces->setRowCount(ui->tbInterfaces->rowCount() + 1);

            QTableWidgetItem *cbSelected = new QTableWidgetItem();
            cbSelected->setCheckState(device.selected ? Qt::Checked : Qt::Unchecked);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, CAPTURE, cbSelected);

            // traffic lines
            ui->tbInterfaces->setItemDelegateForColumn(TRAFFIC, new SparkLineDelegate());
            points = new QList<int>();
            QTableWidgetItem *ti = new QTableWidgetItem();
            ti->setData(Qt::UserRole, qVariantFromValue(points));
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, TRAFFIC, ti);

            output = QString(device.display_name);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, INTERFACE, new QTableWidgetItem(output));

            linkname = NULL;
            if(capture_dev_user_linktype_find(device.name) != -1) {
              device.active_dlt = capture_dev_user_linktype_find(device.name);
            }
            for (list = device.links; list != NULL; list = g_list_next(list)) {
              linkr = (link_row*)(list->data);
              if (linkr->dlt == device.active_dlt) {
                linkname = g_strdup(linkr->name);
                break;
              }
            }

            if (!linkname)
                linkname = g_strdup("unknown");
            pmode = capture_dev_user_pmode_find(device.name);
            if (pmode != -1) {
              device.pmode = pmode;
            }
            hassnap = capture_dev_user_hassnap_find(device.name);
            snaplen = capture_dev_user_snaplen_find(device.name);
            if(snaplen != -1 && hassnap != -1) {
              /* Default snap length set in preferences */
              device.snaplen = snaplen;
              device.has_snaplen = hassnap;
            } else {
              /* No preferences set yet, use default values */
              device.snaplen = WTAP_MAX_PACKET_SIZE;
              device.has_snaplen = FALSE;
            }

            if (device.has_snaplen) {
              snaplen_string = g_strdup_printf("%d", device.snaplen);
            } else {
              snaplen_string = g_strdup("default");
            }

      #if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
            if (capture_dev_user_buffersize_find(device.name) != -1) {
              buffer = capture_dev_user_buffersize_find(device.name);
              device.buffer = buffer;
            } else {
              device.buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
            }
      #endif

            output = QString(linkname);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, LINK, new QTableWidgetItem(output));

            output = QString(device.pmode ? "true" : "false");
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, PMODE, new QTableWidgetItem(output));

            output = QString(snaplen_string);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, SNAPLEN, new QTableWidgetItem(output));

            output = QString().sprintf("%d", device.buffer);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, BUFFER, new QTableWidgetItem(output));

#if defined (HAVE_PCAP_CREATE)
            output = QString(device.monitor_mode_enabled ? "true" : "false");
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, MONITOR, new QTableWidgetItem(output));
#else
            ui->tbInterfaces->setColumnHidden(BUFFER+1, true);
#endif

            if (strstr(prefs.capture_device, device.name) != NULL) {
                device.selected = TRUE;
                global_capture_opts.num_selected++;
                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                g_array_insert_val(global_capture_opts.all_ifaces, i, device);
            }
            if (device.selected) {
                ui->tbInterfaces->item(ui->tbInterfaces->rowCount()-1, 0)->setSelected(true);
            }
        }
    }
    free_interface_list(if_list);
    resizeEvent(NULL);

    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
}

void CaptureInterfacesDialog::updateStatistics(void)
{
    //guint diff;
    QList<int> *points = NULL;


    if (!stat_cache_) {
        // Start gathering statistics using dumpcap
        // We crash (on OS X at least) if we try to do this from ::showEvent.
        stat_cache_ = capture_stat_start(&global_capture_opts);
    }
    if (!stat_cache_) return;


    for (int row = 0; row < ui->tbInterfaces->rowCount(); row++)
    {
        //bool checked = (ui->tbInterfaces->item(row, 0)->checkState() == Qt::Checked) ? true : false;

        //points = new QList<int>();

//        for (if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
//            device = g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
//            QString device_name = ui->tbInterfaces->item(row, INTERFACE)->text();
//            if (device_name.compare(device.name) || device.hidden || device.type == IF_PIPE)
//                continue;

            //diff = 0;
//            if (capture_stats(stat_cache_, device.name, &stats)) {
//                if ((int)(stats.ps_recv - device.last_packets) >= 0) {
//                    diff = stats.ps_recv - device.last_packets;
//                }
//                device.last_packets = stats.ps_recv;
//            }

            points = ui->tbInterfaces->item(row, TRAFFIC)->data(Qt::UserRole).value<QList<int> *>();
            emit getPoints(row, points);
            //ui->tbInterfaces->item

            //ui->tbInterfaces->setItemDelegateForColumn(TRAFFIC, new SparkLineDelegate());
            //points = new QList<int>();
            //QTableWidgetItem *ti = new QTableWidgetItem();
            //ti->setData(Qt::UserRole, qVariantFromValue(points));

            QTableWidgetItem *ti = ui->tbInterfaces->item(ui->tbInterfaces->rowCount()-1, TRAFFIC);
            ti->setData(Qt::UserRole, qVariantFromValue(points));
            //ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, TRAFFIC, ti);

            //points->append(diff);
            ui->tbInterfaces->viewport()->update();
//            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, if_idx);
//            g_array_insert_val(global_capture_opts.all_ifaces, if_idx, device);

    }
}

/*
void CaptureInterfacesDialog::on_tbInterfaces_hideEvent(QHideEvent *evt)
{
    Q_UNUSED(evt);
    if (stat_timer_) stat_timer_->stop();
    if (stat_cache_) {
        capture_stat_stop(stat_cache_);
        stat_cache_ = NULL;
    }
}

void CaptureInterfacesDialog::on_tbInterfaces_showEvent(QShowEvent *evt)
{
    Q_UNUSED(evt);
    if (stat_timer_) stat_timer_->start(stat_update_interval_);
}
*/
#endif /* HAVE_LIBPCAP */

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
