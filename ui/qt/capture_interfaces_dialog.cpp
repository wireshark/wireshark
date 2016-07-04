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
#include <ui_capture_interfaces_dialog.h>
#include "compiled_filter_output.h"
#include "manage_interfaces_dialog.h"

#include "wireshark_application.h"

#ifdef HAVE_LIBPCAP

#include <QAbstractItemModel>
#include <QFileDialog>
#include <QMessageBox>
#include <QTimer>

#include "ringbuffer.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"
#include "ui/last_open_dir.h"

#include "ui/ui_util.h"
#include "ui/util.h"
#include <wsutil/utf8_entities.h>
#include "ui/preference_utils.h"

#include <cstdio>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/addr_resolv.h>
#include <wsutil/filesystem.h>

#include "qt_ui_utils.h"
#include "sparkline_delegate.h"

// To do:
// - Set a size hint for item delegates.
// - Make promiscuous and monitor mode checkboxes.
// - Fix InterfaceTreeDelegate method names.
// - You can edit filters via the main CaptureFilterCombo and via each
//   individual interface row. We should probably do one or the other.

const int stat_update_interval_ = 1000; // ms

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
#define SHOW_BUFFER_COLUMN 1
#endif

#if defined(HAVE_PCAP_CREATE)
#define SHOW_MONITOR_COLUMN 1
#endif

/*
 * Symbolic names for column indices.
 */
enum
{
    col_interface_ = 0,
    col_traffic_,
    col_link_,
    col_pmode_,
    col_snaplen_,
    col_buffer_,
    col_monitor_,
    col_filter_,
    col_num_columns_
};

static interface_t *find_device_by_if_name(const QString &interface_name)
{
    interface_t *device;
    guint i;
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!interface_name.compare(device->display_name) && !device->hidden && device->type != IF_PIPE) {
            return device;
        }
    }
    return NULL;
}

class InterfaceTreeWidgetItem : public QTreeWidgetItem
{
public:
    InterfaceTreeWidgetItem(QTreeWidget *tree) : QTreeWidgetItem(tree) {}
    bool operator< (const QTreeWidgetItem &other) const;
    QList<int> points;

    void updateInterfaceColumns(interface_t *device)
    {
        if (!device) return;

        QString default_str = QObject::tr("default");

        QString linkname = QObject::tr("DLT %1").arg(device->active_dlt);
        for (GList *list = device->links; list != NULL; list = g_list_next(list)) {
            link_row *linkr = (link_row*)(list->data);
            // XXX ...and if they're both -1?
            if (linkr->dlt == device->active_dlt) {
                linkname = linkr->name;
                break;
            }
        }
        setText(col_link_, linkname);

#ifdef HAVE_EXTCAP
        if (device->if_info.type == IF_EXTCAP) {
            /* extcap interfaces does not have this settings */
            setApplicable(col_pmode_, false);

            setApplicable(col_snaplen_, false);
#ifdef SHOW_BUFFER_COLUMN
            setApplicable(col_buffer_, false);
#endif
        } else {
#endif
            setApplicable(col_pmode_, true);
            setCheckState(col_pmode_, device->pmode ? Qt::Checked : Qt::Unchecked);

            QString snaplen_string = device->has_snaplen ? QString::number(device->snaplen) : default_str;
            setText(col_snaplen_, snaplen_string);
#ifdef SHOW_BUFFER_COLUMN
            setText(col_buffer_, QString::number(device->buffer));
#endif
#ifdef HAVE_EXTCAP
        }
#endif
        setText(col_filter_, device->cfilter);

#ifdef SHOW_MONITOR_COLUMN
        if (device->monitor_mode_supported) {
            setApplicable(col_monitor_, true);
            setCheckState(col_monitor_, device->monitor_mode_enabled ? Qt::Checked : Qt::Unchecked);
        } else {
            setApplicable(col_monitor_, false);
        }
#endif
    }

    void setApplicable(int column, bool applicable = false) {
        QPalette palette = wsApp->palette();

        if (applicable) {
            setText(column, QString());
        } else {
            setData(column, Qt::CheckStateRole, QVariant());
            palette.setCurrentColorGroup(QPalette::Disabled);
            setText(column, UTF8_EM_DASH);
        }
        setTextColor(column, palette.text().color());
    }

};

CaptureInterfacesDialog::CaptureInterfacesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::CaptureInterfacesDialog)
{
    ui->setupUi(this);
    loadGeometry();
    setWindowTitle(wsApp->windowTitleString(tr("Capture Interfaces")));

    stat_timer_ = NULL;
    stat_cache_ = NULL;

    // XXX - Enable / disable as needed
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Start"));

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled((global_capture_opts.num_selected > 0)? true: false);

    // Start out with the list *not* sorted, so they show up in the order
    // in which they were provided
    ui->interfaceTree->sortByColumn(-1, Qt::AscendingOrder);
    ui->interfaceTree->setItemDelegateForColumn(col_interface_, &interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_traffic_, new SparkLineDelegate());
    ui->interfaceTree->setItemDelegateForColumn(col_link_, &interface_item_delegate_);

    ui->interfaceTree->setItemDelegateForColumn(col_snaplen_, &interface_item_delegate_);
#ifdef SHOW_BUFFER_COLUMN
    ui->interfaceTree->setItemDelegateForColumn(col_buffer_, &interface_item_delegate_);
#else
    ui->interfaceTree->setColumnHidden(col_buffer_, true);
#endif
#ifndef SHOW_MONITOR_COLUMN
    ui->interfaceTree->setColumnHidden(col_monitor_, true);
#endif
    ui->interfaceTree->setItemDelegateForColumn(col_filter_, &interface_item_delegate_);

    interface_item_delegate_.setTree(ui->interfaceTree);

#if QT_VERSION >= QT_VERSION_CHECK(4, 7, 0)
    ui->filenameLineEdit->setPlaceholderText(tr("Leave blank to use a temporary file"));
#endif

    // Changes in interface selections or capture filters should be propagated
    // to the main welcome screen where they will be applied to the global
    // capture options.
    connect(this, SIGNAL(interfacesChanged()), ui->captureFilterComboBox, SIGNAL(interfacesChanged()));
    connect(ui->captureFilterComboBox, SIGNAL(captureFilterSyntaxChanged(bool)), this, SLOT(updateWidgets()));
    connect(ui->captureFilterComboBox->lineEdit(), SIGNAL(textEdited(QString)),
            this, SLOT(filterEdited()));
    connect(ui->captureFilterComboBox->lineEdit(), SIGNAL(textEdited(QString)),
            this, SIGNAL(captureFilterTextEdited(QString)));
    connect(&interface_item_delegate_, SIGNAL(filterChanged(QString)),
            ui->captureFilterComboBox->lineEdit(), SLOT(setText(QString)));
    connect(&interface_item_delegate_, SIGNAL(filterChanged(QString)),
            this, SIGNAL(captureFilterTextEdited(QString)));
    connect(this, SIGNAL(ifsChanged()), this, SLOT(refreshInterfaceList()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(updateLocalInterfaces()));
    connect(ui->browseButton, SIGNAL(clicked()), this, SLOT(browseButtonClicked()));
}

void CaptureInterfacesDialog::interfaceSelected()
{
    InterfaceTree::updateGlobalDeviceSelections(ui->interfaceTree, col_interface_);

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled((global_capture_opts.num_selected > 0) ? true: false);

    emit interfacesChanged();

    updateSelectedFilter();

    updateWidgets();
}

void CaptureInterfacesDialog::filterEdited()
{
    QList<QTreeWidgetItem*> si = ui->interfaceTree->selectedItems();

    foreach (QTreeWidgetItem *ti, si) {
        ti->setText(col_filter_, ui->captureFilterComboBox->lineEdit()->text());
    }

    if (si.count() > 0) {
        QModelIndex col_filter_idx = ui->interfaceTree->model()->index(ui->interfaceTree->indexOfTopLevelItem(si[0]), col_filter_);
        ui->interfaceTree->scrollTo(col_filter_idx);
    }
}

void CaptureInterfacesDialog::updateWidgets()
{
    SyntaxLineEdit *sle = qobject_cast<SyntaxLineEdit *>(ui->captureFilterComboBox->lineEdit());
    if (!sle) {
        return;
    }

    bool can_capture = false;

    if (ui->interfaceTree->selectedItems().count() > 0 && sle->syntaxState() != SyntaxLineEdit::Invalid) {
        can_capture = true;
    }

    ui->compileBPF->setEnabled(can_capture);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(can_capture);
}

CaptureInterfacesDialog::~CaptureInterfacesDialog()
{
    delete ui;
}

void CaptureInterfacesDialog::setTab(int index)
{
    ui->tabWidget->setCurrentIndex(index);
}

void CaptureInterfacesDialog::on_capturePromModeCheckBox_toggled(bool checked)
{
    interface_t *device;
    prefs.capture_prom_mode = checked;
    for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
        InterfaceTreeWidgetItem *ti = dynamic_cast<InterfaceTreeWidgetItem *>(ui->interfaceTree->topLevelItem(row));
        if (!ti) continue;

        QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
        device = getDeviceByName(device_name);
        if (!device) continue;
        device->pmode = checked;
        ti->updateInterfaceColumns(device);
    }
}

void CaptureInterfacesDialog::browseButtonClicked()
{
    char *open_dir = NULL;

    switch (prefs.gui_fileopen_style) {

    case FO_STYLE_LAST_OPENED:
        open_dir = get_last_open_dir();
        break;

    case FO_STYLE_SPECIFIED:
        if (prefs.gui_fileopen_dir[0] != '\0')
            open_dir = prefs.gui_fileopen_dir;
        break;
    }
    QString file_name = QFileDialog::getSaveFileName(this, tr("Specify a Capture File"), open_dir);
    ui->filenameLineEdit->setText(file_name);
}

void CaptureInterfacesDialog::interfaceItemChanged(QTreeWidgetItem *item, int column)
{
    QWidget* editor = ui->interfaceTree->indexWidget(ui->interfaceTree->currentIndex());
    if (editor) {
        ui->interfaceTree->closePersistentEditor(item, ui->interfaceTree->currentColumn());
    }

    InterfaceTreeWidgetItem *ti = dynamic_cast<InterfaceTreeWidgetItem *>(item);
    if (!ti) return;

    interface_t *device;
    QString interface_name = ti->text(col_interface_);
    device = find_device_by_if_name(interface_name);
    if (!device) return;

    switch(column) {

    case col_pmode_:
        device->pmode = item->checkState(col_pmode_) == Qt::Checked ? TRUE : FALSE;
        ti->updateInterfaceColumns(device);
        break;

#ifdef SHOW_MONITOR_COLUMN
    case col_monitor_:
    {
        gboolean monitor_mode = FALSE;
        if (ti->checkState(col_monitor_) == Qt::Checked) monitor_mode = TRUE;

        if_capabilities_t *caps;
        char *auth_str = NULL;
        QString active_dlt_name;

        set_active_dlt(device, global_capture_opts.default_options.linktype);

    #ifdef HAVE_PCAP_REMOTE
        if (device->remote_opts.remote_host_opts.auth_type == CAPTURE_AUTH_PWD) {
            auth_str = g_strdup_printf("%s:%s", device->remote_opts.remote_host_opts.auth_username,
                                       device->remote_opts.remote_host_opts.auth_password);
        }
    #endif
        caps = capture_get_if_capabilities(device->name, monitor_mode, auth_str, NULL, main_window_update);
        g_free(auth_str);

        if (caps != NULL) {

            for (int i = (gint)g_list_length(device->links)-1; i >= 0; i--) {
                GList* rem = g_list_nth(device->links, i);
                device->links = g_list_remove_link(device->links, rem);
                g_list_free_1(rem);
            }
            device->active_dlt = -1;
            device->monitor_mode_supported = caps->can_set_rfmon;
            device->monitor_mode_enabled = monitor_mode;

            for (GList *lt_entry = caps->data_link_types; lt_entry != NULL; lt_entry = g_list_next(lt_entry)) {
                link_row *linkr = (link_row *)g_malloc(sizeof(link_row));
                data_link_info_t *data_link_info = (data_link_info_t *)lt_entry->data;
                /*
                 * For link-layer types libpcap/WinPcap doesn't know about, the
                 * name will be "DLT n", and the description will be null.
                 * We mark those as unsupported, and don't allow them to be
                 * used - capture filters won't work on them, for example.
                 */
                if (data_link_info->description != NULL) {
                    linkr->dlt = data_link_info->dlt;
                    if (active_dlt_name.isEmpty()) {
                        device->active_dlt = data_link_info->dlt;
                        active_dlt_name = data_link_info->description;
                    }
                    linkr->name = g_strdup(data_link_info->description);
                } else {
                    gchar *str;
                    /* XXX - should we just omit them? */
                    str = g_strdup_printf("%s (not supported)", data_link_info->name);
                    linkr->dlt = -1;
                    linkr->name = g_strdup(str);
                    g_free(str);
                }
                device->links = g_list_append(device->links, linkr);
            }
            free_if_capabilities(caps);
        } else {
            /* We don't know whether this supports monitor mode or not;
               don't ask for monitor mode. */
            device->monitor_mode_enabled = FALSE;
            device->monitor_mode_supported = FALSE;
        }

        ti->updateInterfaceColumns(device);

        break;
    }
#endif // SHOW_MONITOR_COLUMN
    default:
        break;
    }
}

void CaptureInterfacesDialog::on_gbStopCaptureAuto_toggled(bool checked)
{
    global_capture_opts.has_file_duration = checked;
}

void CaptureInterfacesDialog::on_gbNewFileAuto_toggled(bool checked)
{
    global_capture_opts.multi_files_on = checked;
    ui->stopMBCheckBox->setEnabled(checked?false:true);
    ui->stopMBSpinBox->setEnabled(checked?false:true);
    ui->stopMBComboBox->setEnabled(checked?false:true);
}

void CaptureInterfacesDialog::on_cbUpdatePacketsRT_toggled(bool checked)
{
    global_capture_opts.real_time_mode = checked;
}

void CaptureInterfacesDialog::on_cbAutoScroll_toggled(bool checked)
{
    auto_scroll_live = checked;
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

void CaptureInterfacesDialog::on_buttonBox_accepted()
{
    if (saveOptionsToPreferences()) {
        emit setFilterValid(true, ui->captureFilterComboBox->lineEdit()->text());
        accept();
    }
}

// Not sure why we have to do this manually.
void CaptureInterfacesDialog::on_buttonBox_rejected()
{
    if (saveOptionsToPreferences()) {
        reject();
    }
}

void CaptureInterfacesDialog::on_buttonBox_helpRequested()
{
    // Probably the wrong URL.
    wsApp->helpTopicAction(HELP_CAPTURE_INTERFACES_DIALOG);
}

void CaptureInterfacesDialog::updateInterfaces()
{
    if(prefs.capture_pcap_ng) {
        ui->rbPcapng->setChecked(true);
    } else {
        ui->rbPcap->setChecked(true);
    }
    ui->capturePromModeCheckBox->setChecked(prefs.capture_prom_mode);

    if (global_capture_opts.saving_to_file) {
        ui->filenameLineEdit->setText(QString(global_capture_opts.orig_save_file));
    }

    ui->gbNewFileAuto->setChecked(global_capture_opts.multi_files_on);
    ui->MBCheckBox->setChecked(global_capture_opts.has_autostop_filesize);
    ui->SecsCheckBox->setChecked(global_capture_opts.has_file_duration);
    if (global_capture_opts.has_autostop_filesize) {
        int value = global_capture_opts.autostop_filesize;
        if (value > 1000000) {
            if (global_capture_opts.multi_files_on) {
                ui->MBSpinBox->setValue(value / 1000000);
                ui->MBComboBox->setCurrentIndex(2);
            } else {
                ui->stopMBCheckBox->setChecked(true);
                ui->stopMBSpinBox->setValue(value / 1000000);
                ui->stopMBComboBox->setCurrentIndex(2);
            }
        } else if (value > 1000 && value % 1000 == 0) {
            if (global_capture_opts.multi_files_on) {
                ui->MBSpinBox->setValue(value / 1000);
                ui->MBComboBox->setCurrentIndex(1);
            } else {
                ui->stopMBCheckBox->setChecked(true);
                ui->stopMBSpinBox->setValue(value / 1000);
                ui->stopMBComboBox->setCurrentIndex(1);
            }
        } else {
            if (global_capture_opts.multi_files_on) {
                ui->MBSpinBox->setValue(value);
                ui->MBComboBox->setCurrentIndex(0);
            } else {
                ui->stopMBCheckBox->setChecked(true);
                ui->stopMBSpinBox->setValue(value);
                ui->stopMBComboBox->setCurrentIndex(0);
            }
        }
    }
    if (global_capture_opts.has_file_duration) {
        int value = global_capture_opts.file_duration;
        if (value > 3600 && value % 3600 == 0) {
            ui->SecsSpinBox->setValue(value / 3600);
            ui->SecsComboBox->setCurrentIndex(2);
        } else if (value > 60 && value % 60 == 0) {
            ui->SecsSpinBox->setValue(value / 60);
            ui->SecsComboBox->setCurrentIndex(1);
        } else {
            ui->SecsSpinBox->setValue(value);
            ui->SecsComboBox->setCurrentIndex(0);
        }
    }

    if (global_capture_opts.has_ring_num_files) {
        ui->RbSpinBox->setValue(global_capture_opts.ring_num_files);
        ui->RbCheckBox->setCheckState(Qt::Checked);
    }

    if (global_capture_opts.has_autostop_duration) {
        ui->stopSecsCheckBox->setChecked(true);
        int value = global_capture_opts.file_duration;
        if (value > 3600 && value % 3600 == 0) {
            ui->stopSecsSpinBox->setValue(value / 3600);
            ui->stopSecsComboBox->setCurrentIndex(2);
        } else if (value > 60 && value % 60 == 0) {
            ui->stopSecsSpinBox->setValue(value / 60);
            ui->stopSecsComboBox->setCurrentIndex(1);
        } else {
            ui->stopSecsSpinBox->setValue(value);
            ui->stopSecsComboBox->setCurrentIndex(0);
        }
    }

    if (global_capture_opts.has_autostop_packets) {
        ui->stopPktCheckBox->setChecked(true);
        ui->stopPktSpinBox->setValue(global_capture_opts.autostop_packets);
    }

    if (global_capture_opts.has_autostop_files) {
        ui->stopFilesCheckBox->setChecked(true);
        ui->stopFilesSpinBox->setValue(global_capture_opts.autostop_files);
    }

    ui->cbUpdatePacketsRT->setChecked(global_capture_opts.real_time_mode);
    ui->cbAutoScroll->setChecked(true);
    ui->cbExtraCaptureInfo->setChecked(global_capture_opts.show_info);

    ui->cbResolveMacAddresses->setChecked(gbl_resolv_flags.mac_name);
    ui->cbResolveNetworkNames->setChecked(gbl_resolv_flags.network_name);
    ui->cbResolveTransportNames->setChecked(gbl_resolv_flags.transport_name);

    // Rebuild the interface list without disturbing the main welcome screen.
    disconnect(ui->interfaceTree, SIGNAL(itemSelectionChanged()), this, SLOT(interfaceSelected()));
    ui->interfaceTree->clear();

#ifdef SHOW_BUFFER_COLUMN
    gint          buffer;
#endif
    gint          snaplen;
    gboolean      hassnap, pmode;
    QList<QTreeWidgetItem *> selected_interfaces;

    disconnect(ui->interfaceTree, SIGNAL(itemChanged(QTreeWidgetItem*,int)), this, SLOT(interfaceItemChanged(QTreeWidgetItem*,int)));

    if (global_capture_opts.all_ifaces->len > 0) {
        interface_t *device;

        for (guint device_idx = 0; device_idx < global_capture_opts.all_ifaces->len; device_idx++) {
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, device_idx);

            /* Continue if capture device is hidden */
            if (device->hidden) {
                continue;
            }

            // Traffic sparklines
            InterfaceTreeWidgetItem *ti = new InterfaceTreeWidgetItem(ui->interfaceTree);
            ti->setFlags(ti->flags() | Qt::ItemIsEditable);
            ti->setData(col_interface_, Qt::UserRole, QString(device->name));
            ti->setData(col_traffic_, Qt::UserRole, qVariantFromValue(&ti->points));

            ti->setText(col_interface_, device->display_name);
            if (device->no_addresses > 0) {
                QString addr_str = tr("%1: %2").arg(device->no_addresses > 1 ? tr("Addresses") : tr("Address")).arg(device->addresses);
                QTreeWidgetItem *addr_ti = new QTreeWidgetItem(ti);

                addr_str.replace('\n', ", ");
                addr_ti->setText(0, addr_str);
                addr_ti->setFlags(addr_ti->flags() ^ Qt::ItemIsSelectable);
                addr_ti->setFirstColumnSpanned(true);
                addr_ti->setToolTip(col_interface_, QString("<span>%1</span>").arg(addr_str));
                ti->setToolTip(col_interface_, QString("<span>%1</span>").arg(addr_str));
            } else {
                ti->setToolTip(col_interface_, tr("no addresses"));
            }

            if (capture_dev_user_pmode_find(device->name, &pmode)) {
                device->pmode = pmode;
            }
            if (capture_dev_user_snaplen_find(device->name, &hassnap, &snaplen)) {
                /* Default snap length set in preferences */
                device->snaplen = snaplen;
                device->has_snaplen = hassnap;
            } else {
                /* No preferences set yet, use default values */
                device->snaplen = WTAP_MAX_PACKET_SIZE;
                device->has_snaplen = FALSE;
            }

#ifdef SHOW_BUFFER_COLUMN
            if (capture_dev_user_buffersize_find(device->name) != -1) {
                buffer = capture_dev_user_buffersize_find(device->name);
                device->buffer = buffer;
            } else {
                device->buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
            }
#endif
            ti->updateInterfaceColumns(device);

            if (device->selected) {
                selected_interfaces << ti;
            }
        }
    }

    connect(ui->interfaceTree, SIGNAL(itemChanged(QTreeWidgetItem*,int)), this, SLOT(interfaceItemChanged(QTreeWidgetItem*,int)));

    foreach (QTreeWidgetItem *ti, selected_interfaces) {
        ti->setSelected(true);
    }
    connect(ui->interfaceTree, SIGNAL(itemSelectionChanged()), this, SLOT(interfaceSelected()));
    updateSelectedFilter();

    // Manually or automatically size some columns as needed.
    int one_em = fontMetrics().height();
    for (int col = 0; col < ui->interfaceTree->topLevelItemCount(); col++) {
        switch (col) {
        case col_pmode_:
            ui->interfaceTree->setColumnWidth(col, one_em * 3.25);
            break;
        case col_snaplen_:
            ui->interfaceTree->setColumnWidth(col, one_em * 4.25);
            break;
        case col_buffer_:
            ui->interfaceTree->setColumnWidth(col, one_em * 4.25);
            break;
        case col_monitor_:
            ui->interfaceTree->setColumnWidth(col, one_em * 3.25);
            break;
        default:
            ui->interfaceTree->resizeColumnToContents(col);
        }

    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled((global_capture_opts.num_selected > 0)? true: false);

    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
}

void CaptureInterfacesDialog::showEvent(QShowEvent *)
{
    updateInterfaces();
}

void CaptureInterfacesDialog::refreshInterfaceList()
{
    updateInterfaces();
    emit interfaceListChanged();
}

void CaptureInterfacesDialog::updateLocalInterfaces()
{
    updateInterfaces();
}

void CaptureInterfacesDialog::updateStatistics(void)
{
    interface_t *device;

    for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {

        for (guint if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
            QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
            if (!ti) {
                continue;
            }
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
            QString device_name = ti->text(col_interface_);
            if (device_name.compare(device->display_name) || device->hidden || device->type == IF_PIPE) {
                continue;
            }
            QList<int> *points = ti->data(col_traffic_, Qt::UserRole).value<QList<int> *>();
            points->append(device->packet_diff);
            ti->setData(col_traffic_, Qt::UserRole, qVariantFromValue(points));
        }
    }
    ui->interfaceTree->viewport()->update();
}

void CaptureInterfacesDialog::on_compileBPF_clicked()
{
    QStringList interfaces;
    foreach (QTreeWidgetItem *ti, ui->interfaceTree->selectedItems()) {
        interfaces.append(ti->text(col_interface_));
    }

    QString filter = ui->captureFilterComboBox->currentText();
    CompiledFilterOutput *cfo = new CompiledFilterOutput(this, interfaces, filter);

    cfo->show();
}

bool CaptureInterfacesDialog::saveOptionsToPreferences()
{
    if (ui->rbPcapng->isChecked()) {
        global_capture_opts.use_pcapng = true;
        prefs.capture_pcap_ng = true;
    } else {
        global_capture_opts.use_pcapng = false;
        prefs.capture_pcap_ng = false;
    }

    QString filename = ui->filenameLineEdit->text();
    if (filename.length() > 0) {
        /* User specified a file to which the capture should be written. */
        global_capture_opts.saving_to_file = true;
        global_capture_opts.save_file = qstring_strdup(filename);
        global_capture_opts.orig_save_file = qstring_strdup(filename);
        /* Save the directory name for future file dialogs. */
        set_last_open_dir(get_dirname(filename.toUtf8().data()));
    } else {
        /* User didn't specify a file; save to a temporary file. */
        global_capture_opts.save_file = NULL;
    }

    global_capture_opts.has_ring_num_files = ui->RbCheckBox->isChecked();

    if (global_capture_opts.has_ring_num_files) {
        global_capture_opts.ring_num_files = ui->RbSpinBox->value();
        if (global_capture_opts.ring_num_files > RINGBUFFER_MAX_NUM_FILES)
            global_capture_opts.ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
        else if (global_capture_opts.ring_num_files < RINGBUFFER_MIN_NUM_FILES)
            global_capture_opts.ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif
    }
    global_capture_opts.multi_files_on = ui->gbNewFileAuto->isChecked();
    if (global_capture_opts.multi_files_on) {
        global_capture_opts.has_file_duration = ui->SecsCheckBox->isChecked();
        if (global_capture_opts.has_file_duration) {
            global_capture_opts.file_duration = ui->SecsSpinBox->value();
            int index = ui->SecsComboBox->currentIndex();
            switch (index) {
            case 1: global_capture_opts.file_duration *= 60;
                break;
            case 2: global_capture_opts.file_duration *= 3600;
                break;
            }
         }
         global_capture_opts.has_autostop_filesize = ui->MBCheckBox->isChecked();
         if (global_capture_opts.has_autostop_filesize) {
             global_capture_opts.autostop_filesize = ui->MBSpinBox->value();
             int index = ui->MBComboBox->currentIndex();
             switch (index) {
             case 1: if (global_capture_opts.autostop_filesize > 2000) {
                 QMessageBox::warning(this, tr("Error"),
                                          tr("Multiple files: Requested filesize too large! The filesize cannot be greater than 2 GiB."));
                 return false;
                 } else {
                     global_capture_opts.autostop_filesize *= 1000;
                 }
                 break;
             case 2: if (global_capture_opts.autostop_filesize > 2) {
                     QMessageBox::warning(this, tr("Error"),
                                              tr("Multiple files: Requested filesize too large! The filesize cannot be greater than 2 GiB."));
                     return false;
                     } else {
                         global_capture_opts.autostop_filesize *= 1000000;
                     }
                 break;
             }
         }
         /* test if the settings are ok for a ringbuffer */
         if (global_capture_opts.save_file == NULL) {
             QMessageBox::warning(this, tr("Error"),
                                      tr("Multiple files: No capture file name given! You must specify a filename if you want to use multiple files."));
             return false;
         } else if (!global_capture_opts.has_autostop_filesize && !global_capture_opts.has_file_duration) {
             QMessageBox::warning(this, tr("Error"),
                                      tr("Multiple files: No file limit given! You must specify a file size or duration at which is switched to the next capture file\n if you want to use multiple files."));
             g_free(global_capture_opts.save_file);
             global_capture_opts.save_file = NULL;
             return false;
         }
    } else {
        global_capture_opts.has_autostop_filesize = ui->stopMBCheckBox->isChecked();
        if (global_capture_opts.has_autostop_filesize) {
            global_capture_opts.autostop_filesize = ui->stopMBSpinBox->value();
            int index = ui->stopMBComboBox->currentIndex();
            switch (index) {
            case 1: if (global_capture_opts.autostop_filesize > 2000) {
                QMessageBox::warning(this, tr("Error"),
                                         tr("Multiple files: Requested filesize too large! The filesize cannot be greater than 2 GiB."));
                return false;
                } else {
                    global_capture_opts.autostop_filesize *= 1000;
                }
                break;
            case 2: if (global_capture_opts.autostop_filesize > 2) {
                    QMessageBox::warning(this, tr("Error"),
                                             tr("Multiple files: Requested filesize too large! The filesize cannot be greater than 2 GiB."));
                    return false;
                    } else {
                        global_capture_opts.autostop_filesize *= 1000000;
                    }
                break;
            }
        }
    }

    global_capture_opts.has_autostop_duration = ui->stopSecsCheckBox->isChecked();
    if (global_capture_opts.has_autostop_duration) {
        global_capture_opts.autostop_duration = ui->stopSecsSpinBox->value();
        int index = ui->stopSecsComboBox->currentIndex();
        switch (index) {
        case 1: global_capture_opts.autostop_duration *= 60;
            break;
        case 2: global_capture_opts.autostop_duration *= 3600;
            break;
        }
    }

    global_capture_opts.has_autostop_packets = ui->stopPktCheckBox->isChecked();
    if (global_capture_opts.has_autostop_packets) {
        global_capture_opts.autostop_packets = ui->stopPktSpinBox->value();
    }

    global_capture_opts.has_autostop_files = ui->stopFilesCheckBox->isChecked();
    if (global_capture_opts.has_autostop_files) {
        global_capture_opts.autostop_files = ui->stopFilesSpinBox->value();
    }

    interface_t *device;

    for (int col = col_link_; col <= col_filter_; col++) {
        if (ui->interfaceTree->isColumnHidden(col)) {
            continue;
        }
        /* All entries are separated by comma. There is also one before the first interface to be able to identify
           word boundaries. As 'lo' is part of 'nflog' an exact match is necessary. */
        switch (col) {
        case col_link_:
        {
            QStringList link_list;

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
                QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
                device = getDeviceByName(device_name);
                if (!device || device->active_dlt == -1) {
                    continue;
                }
                link_list << QString("%1(%2)").arg(device->name).arg(device->active_dlt);
            }
            g_free(prefs.capture_devices_linktypes);
            prefs.capture_devices_linktypes = qstring_strdup(link_list.join(","));
            break;
        }
#ifdef SHOW_BUFFER_COLUMN
        case col_buffer_:
        {
            QStringList buffer_size_list;

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
                QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
                device = getDeviceByName(device_name);
                if (!device || device->buffer == -1) {
                    continue;
                }
                buffer_size_list << QString("%1(%2)").arg(device->name).arg(device->buffer);
            }
            g_free(prefs.capture_devices_buffersize);
            prefs.capture_devices_buffersize = qstring_strdup(buffer_size_list.join(","));
            break;
        }
#endif // HAVE_BUFFER_SETTING
        case col_snaplen_:
        {
            QStringList snaplen_list;

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
                QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
                device = getDeviceByName(device_name);
                if (!device) continue;
                snaplen_list << QString("%1:%2(%3)")
                                .arg(device->name)
                                .arg(device->has_snaplen)
                                .arg(device->has_snaplen ? device->snaplen : WTAP_MAX_PACKET_SIZE);
            }
            g_free(prefs.capture_devices_snaplen);
            prefs.capture_devices_snaplen = qstring_strdup(snaplen_list.join(","));
            break;
        }
        case col_pmode_:
        {
            QStringList pmode_list;

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
                QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
                device = getDeviceByName(device_name);
                if (!device || device->pmode == -1) {
                    continue;
                }
                pmode_list << QString("%1(%2)").arg(device->name).arg(device->pmode);
            }
            g_free(prefs.capture_devices_pmode);
            prefs.capture_devices_pmode = qstring_strdup(pmode_list.join(","));
            break;
        }

#ifdef SHOW_MONITOR_COLUMN
        case col_monitor_:
        {
            QStringList monitor_list;

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
                QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
                device = getDeviceByName(device_name);
                if (!device || !device->monitor_mode_supported || (device->monitor_mode_supported && !device->monitor_mode_enabled)) {
                    continue;
                }
                monitor_list << device->name;
            }
            g_free(prefs.capture_devices_monitor_mode);
            prefs.capture_devices_monitor_mode = qstring_strdup(monitor_list.join(","));
            break;
        }
#endif // HAVE_MONITOR_SETTING

#if 0
            // The device cfilter should have been applied at this point.
            // We shouldn't change it here.
        case col_filter_:
        {
            // XXX Update selected interfaces only?
            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
                QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
                device = getDeviceByName(device_name);
                if (!device) continue;
                g_free(device->cfilter);
                if (ti->text(col_filter_).isEmpty()) {
                    device->cfilter = NULL;
                } else {
                    device->cfilter = qstring_strdup(ti->text(col_filter_));
                }
            }
        }
#endif
        }
    }
    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }
    return true;
}

void CaptureInterfacesDialog::updateSelectedFilter()
{
    // Should match MainWelcome::interfaceSelected.
    QPair <const QString, bool> sf_pair = CaptureFilterEdit::getSelectedFilter();
    const QString user_filter = sf_pair.first;
    bool conflict = sf_pair.second;

    if (conflict) {
        ui->captureFilterComboBox->lineEdit()->clear();
        ui->captureFilterComboBox->setConflict(true);
    } else {
        ui->captureFilterComboBox->lineEdit()->setText(user_filter);
    }
}

void CaptureInterfacesDialog::on_manageButton_clicked()
{
    if (saveOptionsToPreferences()) {
        ManageInterfacesDialog *dlg = new ManageInterfacesDialog(this);
        dlg->show();
    }
}

void CaptureInterfacesDialog::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}

interface_t *CaptureInterfacesDialog::getDeviceByName(const QString device_name)
{
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device_name.compare(QString().fromUtf8(device->name)) == 0) {
            return device;
        }
    }
    return NULL;
}

//
// InterfaceTreeItem
//
bool InterfaceTreeWidgetItem::operator< (const QTreeWidgetItem &other) const {
    if (treeWidget()->sortColumn() == col_traffic_) {
        QList<int> *points = data(col_traffic_, Qt::UserRole).value<QList<int> *>();
        QList<int> *other_points = other.data(col_traffic_, Qt::UserRole).value<QList<int> *>();
        double avg = 0, other_avg = 0;
        foreach (int point, *points) {
            avg += (double) point / points->length();
        }
        foreach (int point, *other_points) {
            other_avg += (double) point / other_points->length();
        }
        return avg < other_avg;
    }
    return QTreeWidgetItem::operator<(other);
}


//
// InterfaceTreeDelegate
//

#include <QComboBox>

InterfaceTreeDelegate::InterfaceTreeDelegate(QObject *parent)
    : QStyledItemDelegate(parent), tree_(NULL)
{
}


InterfaceTreeDelegate::~InterfaceTreeDelegate()
{
}


QWidget* InterfaceTreeDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &, const QModelIndex &index) const
{
    QWidget *w = NULL;
#ifdef SHOW_BUFFER_COLUMN
    gint buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
#endif
    guint snap = WTAP_MAX_PACKET_SIZE;
    GList *links = NULL;

    if (index.column() > 1 && index.data().toString().compare(UTF8_EM_DASH)) {
        QTreeWidgetItem *ti = tree_->topLevelItem(index.row());
        QString interface_name = ti->text(col_interface_);
        interface_t *device = find_device_by_if_name(interface_name);

        if (device) {
#ifdef SHOW_BUFFER_COLUMN
            buffer = device->buffer;
#endif
            snap = device->snaplen;
            links = device->links;
        }
        switch (index.column()) {
        case col_interface_:
        case col_traffic_:
            break;
        case col_link_:
        {
            GList *list;
            link_row *linkr;
            QStringList valid_link_types;

            // XXX The GTK+ UI fills in all link types, valid or not. We add
            // only the valid ones. If we *do* wish to include invalid link
            // types we'll have to jump through the hoops necessary to disable
            // QComboBox items.

            for (list = links; list != NULL; list = g_list_next(list)) {
                linkr = (link_row*)(list->data);
                if (linkr->dlt >= 0) {
                    valid_link_types << linkr->name;
                }
            }

            if (valid_link_types.size() < 2) {
                break;
            }
            QComboBox *cb = new QComboBox(parent);
            cb->addItems(valid_link_types);

            connect(cb, SIGNAL(currentIndexChanged(QString)), this, SLOT(linkTypeChanged(QString)));
            w = (QWidget*) cb;
            break;
        }
        case col_snaplen_:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(1, 65535);
            sb->setValue(snap);
            sb->setWrapping(true);
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(snapshotLengthChanged(int)));
            w = (QWidget*) sb;
            break;
        }
#ifdef SHOW_BUFFER_COLUMN
        case col_buffer_:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(1, 65535);
            sb->setValue(buffer);
            sb->setWrapping(true);
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(bufferSizeChanged(int)));
            w = (QWidget*) sb;
            break;
        }
#endif
        case col_filter_:
        {
            CaptureFilterCombo *cf = new CaptureFilterCombo(parent, true);
            connect(cf->lineEdit(), SIGNAL(textEdited(QString)), this, SIGNAL(filterChanged(QString)));
            w = (QWidget*) cf;
        }
        default:
            break;
        }
//        if (w) {
//            ti->setSizeHint(index.column(), w->sizeHint());
//        }
    }
    return w;
}

bool InterfaceTreeDelegate::eventFilter(QObject *object, QEvent *event)
{
    QComboBox * comboBox = dynamic_cast<QComboBox*>(object);
    if (comboBox) {
        if (event->type() == QEvent::MouseButtonRelease) {
            comboBox->showPopup();
            return true;
        }
    } else {
        return QStyledItemDelegate::eventFilter(object, event);
    }
    return false;
}

void InterfaceTreeDelegate::linkTypeChanged(QString selected_link_type)
{
    GList *list;
    link_row *temp;
    interface_t *device;

    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    device = find_device_by_if_name(interface_name);
    if (!device) {
        return;
    }
    for (list = device->links; list != NULL; list = g_list_next(list)) {
        temp = (link_row*) (list->data);
        if (!selected_link_type.compare(temp->name)) {
            device->active_dlt = temp->dlt;
        }
    }
    // XXX We might want to verify that active_dlt is valid at this point.
}

void InterfaceTreeDelegate::snapshotLengthChanged(int value)
{
    interface_t *device;
    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    device = find_device_by_if_name(interface_name);
    if (!device) {
        return;
    }
    if (value != WTAP_MAX_PACKET_SIZE) {
        device->has_snaplen = true;
        device->snaplen = value;
    } else {
        device->has_snaplen = false;
        device->snaplen = WTAP_MAX_PACKET_SIZE;
    }
}

void InterfaceTreeDelegate::bufferSizeChanged(int value)
{
#ifdef SHOW_BUFFER_COLUMN
    interface_t *device;
    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    device = find_device_by_if_name(interface_name);
    if (!device) {
        return;
    }
    device->buffer = value;
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
