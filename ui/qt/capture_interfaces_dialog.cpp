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
#include "capture_filter_combo.h"
#include "ui_capture_interfaces_dialog.h"
#include "compiled_filter_output.h"

#include "wireshark_application.h"

#ifdef HAVE_LIBPCAP

#include <QTimer>
#include <QMessageBox>

#include "capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"

#include "ui/ui_util.h"
#include "ui/utf8_entities.h"
#include "ui/preference_utils.h"

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

    start_bt_->setEnabled((global_capture_opts.num_selected > 0)? true: false);
    connect(start_bt_, SIGNAL(clicked(bool)), this, SLOT(start_button_clicked()));

    connect(ui->tbInterfaces,SIGNAL(itemClicked(QTableWidgetItem *)),this,SLOT(tableItemClicked(QTableWidgetItem *)));
    connect(ui->tbInterfaces, SIGNAL(itemSelectionChanged()), this, SLOT(tableSelected()));
    connect(ui->allFilterComboBox, SIGNAL(captureFilterSyntaxChanged(bool)), this, SLOT(allFilterChanged()));
    connect(this, SIGNAL(interfacesChanged()), ui->allFilterComboBox, SIGNAL(interfacesChanged()));
}

void CaptureInterfacesDialog::allFilterChanged()
{
    QList<QTableWidgetItem*> selected = ui->tbInterfaces->selectedItems();
    for (int row = 0; row < ui->tbInterfaces->rowCount(); row++)
    {
        QTableWidgetItem *it = ui->tbInterfaces->item(row, FILTER);
        if (selected.contains(it)) {
            QString str = ui->allFilterComboBox->currentText();
            it->setText(str);
        }
    }
}

void CaptureInterfacesDialog::tableSelected()
{
    interface_t device;

    if (!ui->tbInterfaces->selectedItems().size()) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            device.selected = false;
            device.locked = true;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
        global_capture_opts.num_selected = 0;
        start_bt_->setEnabled(false);
        emit setSelectedInterfaces();
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            device.locked = false;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
    }
}

void CaptureInterfacesDialog::tableItemClicked(QTableWidgetItem * item)
{
    Q_UNUSED(item)

    interface_t device;
    guint i;
    global_capture_opts.num_selected = 0;

    QString filter = ui->allFilterComboBox->currentText();
    QList<QTableWidgetItem*> selected = ui->tbInterfaces->selectedItems();
    for (int row = 0; row < ui->tbInterfaces->rowCount(); row++)
    {
        QTableWidgetItem *it = ui->tbInterfaces->item(row, INTERFACE);
        QString interface_name = it->text();

        for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (interface_name.compare(device.display_name)) {
                continue;
            } else {
                break;
            }
        }
        if (selected.contains(it)) {
            device.selected = true;
            global_capture_opts.num_selected++;
        } else {
            device.selected = false;
        }
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        g_array_insert_val(global_capture_opts.all_ifaces, i, device);

        start_bt_->setEnabled((global_capture_opts.num_selected > 0)? true: false);

        if (filter.compare(QString(""))) {
            emit interfacesChanged();
        }
        emit setSelectedInterfaces();
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
    interface_t device;
    prefs.capture_prom_mode = checked;
    for (int row = 0; row < ui->tbInterfaces->rowCount(); row++){
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
        QString device_name = ui->tbInterfaces->item(row, INTERFACE)->text();
        device.pmode = checked;
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, deviceMap[row]);
        g_array_insert_val(global_capture_opts.all_ifaces, deviceMap[row], device);
        QTableWidgetItem *it = ui->tbInterfaces->item(row, PMODE);
        it->setText(checked? tr("enabled"):tr("disabled"));
    }
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

void CaptureInterfacesDialog::start_button_clicked()
{
    qDebug("Starting capture");

    saveOptionsToPreferences();
    emit setFilterValid(true);

    accept();
}

// Not sure why we have to do this manually.
void CaptureInterfacesDialog::on_buttonBox_rejected()
{
    saveOptionsToPreferences();
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

    GList        *list;
    char         *snaplen_string, *linkname;
    link_row     *linkr = NULL;
  #if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    gint          buffer;
  #endif
    gint          snaplen;
    gboolean      hassnap, pmode;

    if (global_capture_opts.all_ifaces->len > 0) {
        interface_t device;

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            QList<int> *points;

            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            /* Continue if capture device is hidden */
            if (device.hidden) {
                continue;
            }
            deviceMap[ui->tbInterfaces->rowCount()] = i;
            QString output;

            ui->tbInterfaces->setRowCount(ui->tbInterfaces->rowCount() + 1);

            // traffic lines
            ui->tbInterfaces->setItemDelegateForColumn(TRAFFIC, new SparkLineDelegate());
            points = new QList<int>();
            QTableWidgetItem *ti = new QTableWidgetItem();
            ti->setFlags(Qt::NoItemFlags);
            ti->setData(Qt::UserRole, qVariantFromValue(points));
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, TRAFFIC, ti);

            ui->tbInterfaces->setItemDelegateForColumn(INTERFACE, &combobox_item_delegate_);
            output = QString(device.display_name);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, INTERFACE, new QTableWidgetItem(output));
            if (strcmp(device.addresses,""))
                ui->tbInterfaces->item(ui->tbInterfaces->rowCount()-1, INTERFACE)->setToolTip(tr("Addresses:\n%1").arg(device.addresses));
            else
                ui->tbInterfaces->item(ui->tbInterfaces->rowCount()-1, INTERFACE)->setToolTip(tr("no address"));

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

            combobox_item_delegate_.setTable(ui->tbInterfaces);
            ui->tbInterfaces->setColumnWidth(LINK, 100);
            ui->tbInterfaces->setItemDelegateForColumn(LINK, &combobox_item_delegate_);
            output = QString(linkname);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, LINK, new QTableWidgetItem(output));

            ui->tbInterfaces->setItemDelegateForColumn(PMODE, &combobox_item_delegate_);
            output = QString(device.pmode ? tr("enabled") : tr("disabled"));
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, PMODE, new QTableWidgetItem(output));

            ui->tbInterfaces->setItemDelegateForColumn(SNAPLEN, &combobox_item_delegate_);
            output = QString(snaplen_string);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, SNAPLEN, new QTableWidgetItem(output));
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
            ui->tbInterfaces->setItemDelegateForColumn(BUFFER, &combobox_item_delegate_);
            output = QString().sprintf("%d", device.buffer);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, BUFFER, new QTableWidgetItem(output));
#else
            ui->tbInterfaces->setColumnHidden(SNAPLEN+1, true);
#endif
#if defined (HAVE_PCAP_CREATE)
            ui->tbInterfaces->setItemDelegateForColumn(MONITOR, &combobox_item_delegate_);
            output = QString(device.monitor_mode_supported? (device.monitor_mode_enabled ? tr("enabled") : tr("disabled")) : tr("n/a"));
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, MONITOR, new QTableWidgetItem(output));
#elif defined (_WIN32)
            ui->tbInterfaces->setColumnHidden(BUFFER+1, true);
#else
            ui->tbInterfaces->setColumnHidden(SNAPLEN+2, true);
#endif
            ui->tbInterfaces->setItemDelegateForColumn(FILTER, &combobox_item_delegate_);
            gchar* prefFilter = capture_dev_user_cfilter_find(device.name);
            if (prefFilter) {
                device.cfilter = g_strdup(prefFilter);
            }
            output = QString(device.cfilter);
            ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, FILTER, new QTableWidgetItem(output));

            if (strstr(prefs.capture_device, device.name) != NULL) {
                device.selected = TRUE;
                global_capture_opts.num_selected++;
            }
            if (device.selected) {
                for (int j = 0; j < NUM_COLUMNS; j++) {
                    if (ui->tbInterfaces->isColumnHidden(j))
                        continue;
                    else
                        ui->tbInterfaces->item(ui->tbInterfaces->rowCount()-1, j)->setSelected(true);
                }
            }
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
    }
    resizeEvent(NULL);
    start_bt_->setEnabled((global_capture_opts.num_selected > 0)? true: false);

    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
}

void CaptureInterfacesDialog::updateStatistics(void)
{
    QList<int> *points = NULL;
    interface_t device;

    for (int row = 0; row < ui->tbInterfaces->rowCount(); row++) {

        for (guint if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
            QTableWidgetItem *ti;
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
            QString device_name = ui->tbInterfaces->item(row, INTERFACE)->text();
            if (device_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
                continue;
            }
            points = ui->tbInterfaces->item(row, TRAFFIC)->data(Qt::UserRole).value<QList<int> *>();
            points->append(device.packet_diff);
            ti = ui->tbInterfaces->item(row, TRAFFIC);
            ti->setData(Qt::UserRole, qVariantFromValue(points));
            ui->tbInterfaces->viewport()->update();
        }
    }
}

void CaptureInterfacesDialog::on_compileBPF_clicked()
{
    QString filter = ui->allFilterComboBox->currentText();
    if (!filter.compare(QString(""))) {
        QMessageBox::warning(this, tr("Error"),
                             tr("Set a filter string to compile."));
        return;
    }
    QList<QTableWidgetItem*> selected = ui->tbInterfaces->selectedItems();
    if (selected.length() == 0) {
        QMessageBox::warning(this, tr("Error"),
                             tr("No interfaces selected."));
        return;
    }
    QStringList *interfaces = new QStringList();
    for (int row = 0; row < ui->tbInterfaces->rowCount(); row++)
    {
        QTableWidgetItem *it = ui->tbInterfaces->item(row, INTERFACE);
        if (selected.contains(it)) {
            QString str = it->text();
            interfaces->append(it->text());
        }
    }

    CompiledFilterOutput *cfo = new CompiledFilterOutput(this, interfaces, filter);

    cfo->show();
}

void CaptureInterfacesDialog::saveOptionsToPreferences()
{
    interface_t device;
    gchar *new_prefs, *tmp_prefs;

    for (int col = LINK; col <= FILTER; col++){
        if (ui->tbInterfaces->isColumnHidden(col)) {
            continue;
        }
        /* All entries are separated by comma. There is also one before the first interface to be able to identify
           word boundaries. As 'lo' is part of 'nflog' an exact match is necessary. */
        switch (col) {
        case LINK:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->tbInterfaces->rowCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (device.active_dlt == -1) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%d)", device.name, device.active_dlt);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_linktypes);
            prefs.capture_devices_linktypes = new_prefs;
            break;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        case BUFFER:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->tbInterfaces->rowCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (device.buffer == -1) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%d)", device.name, device.buffer);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_buffersize);
            prefs.capture_devices_buffersize = new_prefs;
            break;
#endif
        case SNAPLEN:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->tbInterfaces->rowCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s:%d(%d)", device.name, device.has_snaplen, (device.has_snaplen?device.snaplen:WTAP_MAX_PACKET_SIZE));
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_snaplen);
            prefs.capture_devices_snaplen = new_prefs;
            break;
        case PMODE:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->tbInterfaces->rowCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (device.pmode == -1) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%d)", device.name, device.pmode);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_pmode);
            prefs.capture_devices_pmode = new_prefs;
            break;
#ifdef HAVE_PCAP_CREATE
        case MONITOR:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->tbInterfaces->rowCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (!device.monitor_mode_supported || (device.monitor_mode_supported && !device.monitor_mode_enabled)) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s", device.name);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_monitor_mode);
            prefs.capture_devices_monitor_mode = new_prefs;
            break;
#endif
        case FILTER:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->tbInterfaces->rowCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (!device.cfilter) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%s)", device.name, device.cfilter);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_filter);
            prefs.capture_devices_filter = new_prefs;
            break;
        }
    }
    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }
}


#include <QComboBox>

TbInterfacesDelegate::TbInterfacesDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}


TbInterfacesDelegate::~TbInterfacesDelegate()
{
}


QWidget* TbInterfacesDelegate::createEditor( QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index ) const
{
    Q_UNUSED(option);
    QWidget *w = NULL;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    gint buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
#endif
    guint snap = WTAP_MAX_PACKET_SIZE;
    GList *links = NULL;

    if (index.column() > 1) {
        interface_t device;
        QTableWidgetItem *it = table->item(index.row(), INTERFACE);
        QString interface_name = it->text();
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
            buffer = device.buffer;
#endif
            snap = device.snaplen;
            links = device.links;
            if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
                continue;
            } else {
                break;
            }
        }
        switch (index.column()) {
        case INTERFACE:
            break;
        case LINK:
        {
            GList *list;
            link_row *temp;
            QComboBox *cb = new QComboBox(parent);
            for (list=links; list!=NULL; list=g_list_next(list)) {
                temp = (link_row*)(list->data);
                cb->addItem(QString("%1").arg(temp->name));
            }
            connect(cb, SIGNAL(currentIndexChanged(QString)), this, SLOT(link_changed(QString)));
            w = (QWidget*) cb;
            break;
        }
        case PMODE:
        {
        // Create the combobox and populate it
            QComboBox *cb = new QComboBox(parent);
            cb->addItem(QString(tr("enabled")));
            cb->addItem(QString(tr("disabled")));
            connect(cb, SIGNAL(currentIndexChanged(QString)), this, SLOT(pmode_changed(QString)));
            w = (QWidget*) cb;
            break;
        }
#if defined (HAVE_PCAP_CREATE)
        case MONITOR:
        {
             if (index.data().toString().compare(QString("n/a"))) {
                QComboBox *cb = new QComboBox(parent);
                cb->addItem(QString(tr("enabled")));
                cb->addItem(QString(tr("disabled")));
                connect(cb, SIGNAL(currentIndexChanged(QString)), this, SLOT(monitor_changed(QString)));
                w = (QWidget*) cb;
             }
             break;
        }
#endif
        case SNAPLEN:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(1, 65535);
            sb->setValue(snap);
            sb->setWrapping(true);
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(snaplen_changed(int)));
            w = (QWidget*) sb;
            break;
        }
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        case BUFFER:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(1, 65535);
            sb->setValue(buffer);
            sb->setWrapping(true);
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(buffer_changed(int)));
            w = (QWidget*) sb;
            break;
        }
#endif
        case FILTER:
        {
            CaptureFilterCombo *cf = new CaptureFilterCombo(parent);
            w = (QWidget*) cf;
        }
        }
    }
    return w;
}

bool TbInterfacesDelegate::eventFilter(QObject *object, QEvent *event)
{
    QComboBox * comboBox = dynamic_cast<QComboBox*>(object);
    if (comboBox) {
        if (event->type() == QEvent::MouseButtonRelease) {
            comboBox->showPopup();
            return true;
        }
    } else {
        return QStyledItemDelegate::eventFilter( object, event );
    }
    return false;
}

void TbInterfacesDelegate::pmode_changed(QString index)
{
    interface_t device;
    guint i;
    QTableWidgetItem *it = table->item(table->currentRow(), INTERFACE);
    QString interface_name = it->text();
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    if (!index.compare(QString(tr("enabled")))) {
        device.pmode = true;
    } else {
        device.pmode = false;
    }

    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}

#if defined (HAVE_PCAP_CREATE)
void TbInterfacesDelegate::monitor_changed(QString index)
{
    interface_t device;
    guint i;
    QTableWidgetItem *it = table->item(table->currentRow(), INTERFACE);
    QString interface_name = it->text();
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    if (!index.compare(QString(tr("enabled")))) {
        device.monitor_mode_enabled = true;
    } else {
        device.monitor_mode_enabled = false;
    }
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}
#endif

void TbInterfacesDelegate::link_changed(QString index)
{
    GList *list;
    link_row *temp;
    interface_t device;
    guint i;

    QTableWidgetItem *it = table->item(table->currentRow(), INTERFACE);
    QString interface_name = it->text();
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    for (list = device.links; list != NULL; list = g_list_next(list)) {
        temp = (link_row*) (list->data);
        if (!index.compare(temp->name)) {
            device.active_dlt = temp->dlt;
        }
    }
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}

void TbInterfacesDelegate::snaplen_changed(int value)
{
    interface_t device;
    guint i;
    QTableWidgetItem *it = table->item(table->currentRow(), INTERFACE);
    QString interface_name = it->text();
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    if (value != WTAP_MAX_PACKET_SIZE) {
        device.has_snaplen = true;
        device.snaplen = value;
    } else {
        device.has_snaplen = false;
        device.snaplen = WTAP_MAX_PACKET_SIZE;
    }
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}

void TbInterfacesDelegate::buffer_changed(int value)
{
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    interface_t device;
    guint i;
    QTableWidgetItem *it = table->item(table->currentRow(), INTERFACE);
    QString interface_name = it->text();
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    device.buffer = value;
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
#endif
}

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
