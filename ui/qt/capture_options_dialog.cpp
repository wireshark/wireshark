/* capture_options_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wireshark.h>

#include "capture_options_dialog.h"
#include <ui/qt/widgets/capture_filter_combo.h>
#include <ui_capture_options_dialog.h>
#include "compiled_filter_output.h"
#include "manage_interfaces_dialog.h"

#include "main_application.h"

#include "extcap.h"

#ifdef HAVE_LIBPCAP

#include <QAbstractItemModel>
#include <QMessageBox>
#include <QTimer>

#include "ringbuffer.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"
#include "ui/file_dialog.h"

#include "ui/ws_ui_util.h"
#include "ui/util.h"
#include <wsutil/utf8_entities.h>
#include "ui/preference_utils.h"
#include "ui/recent.h"

#include <cstdio>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/addr_resolv.h>
#include <wsutil/filesystem.h>

#include <wiretap/wtap.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/models/sparkline_delegate.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

// To do:
// - Set a size hint for item delegates.
// - Make promiscuous and monitor mode checkboxes.
// - Fix InterfaceTreeDelegate method names.
// - You can edit filters via the main CaptureFilterCombo and via each
//   individual interface row. We should probably do one or the other.
// - There might be a point in having the separate combo boxes in the
//   individual interface row, if their CaptureFilterCombos actually
//   called recent_get_cfilter_list with the interface name to get the
//   separate list of recent capture filters for that interface, but
//   they don't.

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
    col_extcap_ = 0,
    col_interface_,
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
    unsigned i;
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!interface_name.compare(device->display_name) && !device->hidden && device->if_info.type != IF_PIPE) {
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
    QVariant data(int column, int role) const;
    void setData(int column, int role, const QVariant &value);
    QList<int> points;

    void updateInterfaceColumns(interface_t *device)
    {
        if (!device) return;

        // Prevent infinite recursive signal loop
        // itemChanged->interfaceItemChanged->updateInterfaceColumns
        treeWidget()->blockSignals(true);
        QString default_str = QObject::tr("default");

        // XXX - this is duplicated in InterfaceTreeModel::data;
        // it should be done in common code somewhere.
        QString linkname;
        if (device->active_dlt == -1)
            linkname = "Unknown";
        else {
            linkname = QObject::tr("DLT %1").arg(device->active_dlt);
            for (GList *list = device->links; list != NULL; list = gxx_list_next(list)) {
                link_row *linkr = gxx_list_data(link_row *, list);
                if (linkr->dlt == device->active_dlt) {
                    linkname = linkr->name;
                    break;
                }
            }
        }
        setText(col_link_, linkname);

        if (device->if_info.type == IF_EXTCAP) {
            /* extcap interfaces does not have this settings */
            setApplicable(col_pmode_, false);

            setApplicable(col_snaplen_, false);
#ifdef SHOW_BUFFER_COLUMN
            setApplicable(col_buffer_, false);
#endif
        } else {
            setApplicable(col_pmode_, true);
            setCheckState(col_pmode_, device->pmode ? Qt::Checked : Qt::Unchecked);

            QString snaplen_string = device->has_snaplen ? QString::number(device->snaplen) : default_str;
            setText(col_snaplen_, snaplen_string);
#ifdef SHOW_BUFFER_COLUMN
            setText(col_buffer_, QString::number(device->buffer));
#endif
        }
        setText(col_filter_, device->cfilter);

#ifdef SHOW_MONITOR_COLUMN
        if (device->monitor_mode_supported) {
            setApplicable(col_monitor_, true);
            setCheckState(col_monitor_, device->monitor_mode_enabled ? Qt::Checked : Qt::Unchecked);
        } else {
            setApplicable(col_monitor_, false);
        }
#endif
        treeWidget()->blockSignals(false);
    }

    void setApplicable(int column, bool applicable = false) {
        QPalette palette = mainApp->palette();

        if (applicable) {
            setText(column, QString());
        } else {
            setData(column, Qt::CheckStateRole, QVariant());
            palette.setCurrentColorGroup(QPalette::Disabled);
            setText(column, UTF8_EM_DASH);
        }
        setForeground(column, palette.text().color());
    }

};

CaptureOptionsDialog::CaptureOptionsDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::CaptureOptionsDialog)
{
    ui->setupUi(this);
    loadGeometry();
    setWindowTitle(mainApp->windowTitleString(tr("Capture Options")));

    stat_timer_ = NULL;
    stat_cache_ = NULL;

    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Start"));

    // Start out with the list *not* sorted, so they show up in the order
    // in which they were provided
    ui->interfaceTree->sortByColumn(-1, Qt::AscendingOrder);
    ui->interfaceTree->setItemDelegateForColumn(col_extcap_, &interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_interface_, &interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_traffic_, new SparkLineDelegate(this));
    ui->interfaceTree->setItemDelegateForColumn(col_link_, &interface_item_delegate_);

    ui->interfaceTree->setItemDelegateForColumn(col_snaplen_, &interface_item_delegate_);
#ifdef SHOW_BUFFER_COLUMN
    ui->interfaceTree->setItemDelegateForColumn(col_buffer_, &interface_item_delegate_);
#else
    ui->interfaceTree->setColumnHidden(col_buffer_, true);
#endif
#ifndef SHOW_MONITOR_COLUMN
    ui->interfaceTree->setColumnHidden(col_monitor_, true);
    ui->captureMonitorModeCheckBox->setVisible(false);
#endif
    ui->interfaceTree->setItemDelegateForColumn(col_filter_, &interface_item_delegate_);

    interface_item_delegate_.setTree(ui->interfaceTree);

    ui->filenameLineEdit->setPlaceholderText(tr("Leave blank to use a temporary file"));

    ui->rbCompressionNone->setChecked(true);
    ui->rbTimeNum->setChecked(true);

    ui->tempDirLineEdit->setPlaceholderText(g_get_tmp_dir());
    ui->tempDirLineEdit->setText(global_capture_opts.temp_dir);

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
    connect(mainApp, SIGNAL(localInterfaceListChanged()), this, SLOT(updateLocalInterfaces()));
    connect(ui->browseButton, SIGNAL(clicked()), this, SLOT(browseButtonClicked()));
    connect(ui->interfaceTree, SIGNAL(itemClicked(QTreeWidgetItem*,int)), this, SLOT(itemClicked(QTreeWidgetItem*,int)));
    connect(ui->interfaceTree, SIGNAL(itemDoubleClicked(QTreeWidgetItem*,int)), this, SLOT(itemDoubleClicked(QTreeWidgetItem*,int)));
    connect(ui->tempDirBrowseButton, SIGNAL(clicked()), this, SLOT(tempDirBrowseButtonClicked()));

    // Ring buffer minimums (all 1 except # of files)
    ui->PktSpinBox->setMinimum(1);
    ui->MBSpinBox->setMinimum(1);
    ui->SecsSpinBox->setMinimum(1);
    ui->IntervalSecsSpinBox->setMinimum(1);
    ui->RbSpinBox->setMinimum(2);

    // Autostop minimums
    ui->stopPktSpinBox->setMinimum(1);
    ui->stopFilesSpinBox->setMinimum(1);
    ui->stopMBSpinBox->setMinimum(1);
    ui->stopSecsSpinBox->setMinimum(1);

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    connect(ui->MBComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &CaptureOptionsDialog::MBComboBoxIndexChanged);
    connect(ui->stopMBComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &CaptureOptionsDialog::stopMBComboBoxIndexChanged);
#else
    connect(ui->MBComboBox, &QComboBox::currentIndexChanged, this, &CaptureOptionsDialog::MBComboBoxIndexChanged);
    connect(ui->stopMBComboBox, &QComboBox::currentIndexChanged, this, &CaptureOptionsDialog::stopMBComboBoxIndexChanged);
#endif

    ui->tabWidget->setCurrentIndex(0);

    updateWidgets();
}

CaptureOptionsDialog::~CaptureOptionsDialog()
{
    delete ui;
}

/* Update global device selections based on the TreeWidget selection. */
void CaptureOptionsDialog::updateGlobalDeviceSelections()
{
#ifdef HAVE_LIBPCAP
    QTreeWidgetItemIterator iter(ui->interfaceTree);

    global_capture_opts.num_selected = 0;

    while (*iter) {
        QString device_name = (*iter)->data(col_interface_, Qt::UserRole).value<QString>();
        for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device_name.compare(QString().fromUtf8(device->name)) == 0) {
                if ((*iter)->isSelected()) {
                    device->selected = true;
                    global_capture_opts.num_selected++;
                } else {
                    device->selected = false;
                }
                break;
            }
        }
        ++iter;
    }
#endif
}

/* Update TreeWidget selection based on global device selections. */
void CaptureOptionsDialog::updateFromGlobalDeviceSelections()
{
#ifdef HAVE_LIBPCAP
    QTreeWidgetItemIterator iter(ui->interfaceTree);

    // Prevent recursive interface interfaceSelected signals
    ui->interfaceTree->blockSignals(true);

    while (*iter) {
        QString device_name = (*iter)->data(col_interface_, Qt::UserRole).value<QString>();
        for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device_name.compare(QString().fromUtf8(device->name)) == 0) {
                if ((bool)device->selected != (*iter)->isSelected()) {
                    (*iter)->setSelected(device->selected);
                }
                break;
            }
        }
        ++iter;
    }

    ui->interfaceTree->blockSignals(false);
#endif
}

void CaptureOptionsDialog::interfaceSelected()
{
    if (sender() == ui->interfaceTree) {
        // Local changes, propagate our changes
        updateGlobalDeviceSelections();
        emit interfacesChanged();
    } else {
        // Changes from the welcome screen, adjust to its state.
        updateFromGlobalDeviceSelections();
    }

    updateSelectedFilter();

    updateWidgets();
}

void CaptureOptionsDialog::filterEdited()
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

void CaptureOptionsDialog::updateWidgets()
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

void CaptureOptionsDialog::on_capturePromModeCheckBox_toggled(bool checked)
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

void CaptureOptionsDialog::on_captureMonitorModeCheckBox_toggled(bool checked)
{
    interface_t *device;
    prefs.capture_monitor_mode = checked;
    for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
        InterfaceTreeWidgetItem *ti = dynamic_cast<InterfaceTreeWidgetItem *>(ui->interfaceTree->topLevelItem(row));
        if (!ti) continue;

        QString device_name = ti->data(col_interface_, Qt::UserRole).toString();
        device = getDeviceByName(device_name);
        if (!device) continue;
        if (device->monitor_mode_supported) {
            device->monitor_mode_enabled = checked;
            ti->updateInterfaceColumns(device);
        }
    }
}

void CaptureOptionsDialog::browseButtonClicked()
{
    QString file_name = WiresharkFileDialog::getSaveFileName(this, tr("Specify a Capture File"), get_open_dialog_initial_dir());
    ui->filenameLineEdit->setText(file_name);
}

void CaptureOptionsDialog::tempDirBrowseButtonClicked()
{
    QString specified_dir = WiresharkFileDialog::getExistingDirectory(this, tr("Specify temporary directory"));
    ui->tempDirLineEdit->setText(specified_dir);
}

void CaptureOptionsDialog::interfaceItemChanged(QTreeWidgetItem *item, int column)
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
        device->pmode = item->checkState(col_pmode_) == Qt::Checked ? true : false;
        ti->updateInterfaceColumns(device);
        break;

#ifdef SHOW_MONITOR_COLUMN
    case col_monitor_:
    {
        bool monitor_mode = false;
        if (ti->checkState(col_monitor_) == Qt::Checked) monitor_mode = true;

        if_capabilities_t *caps;
        char *auth_str = NULL;
        QString active_dlt_name;

        set_active_dlt(device, global_capture_opts.default_options.linktype);

    #ifdef HAVE_PCAP_REMOTE
        if (device->remote_opts.remote_host_opts.auth_type == CAPTURE_AUTH_PWD) {
            auth_str = ws_strdup_printf("%s:%s", device->remote_opts.remote_host_opts.auth_username,
                                       device->remote_opts.remote_host_opts.auth_password);
        }
    #endif
        caps = capture_get_if_capabilities(device->name, monitor_mode, auth_str, NULL, NULL, main_window_update);
        g_free(auth_str);

        if (caps != Q_NULLPTR) {

            for (int i = static_cast<int>(g_list_length(device->links)) - 1; i >= 0; i--) {
                GList* rem = g_list_nth(device->links, static_cast<unsigned>(i));
                device->links = g_list_remove_link(device->links, rem);
                g_list_free_1(rem);
            }
            device->active_dlt = -1;
            device->monitor_mode_supported = caps->can_set_rfmon;
            device->monitor_mode_enabled = monitor_mode && caps->can_set_rfmon;
            GList *lt_list = device->monitor_mode_enabled ? caps->data_link_types_rfmon : caps->data_link_types;

            for (GList *lt_entry = lt_list; lt_entry != Q_NULLPTR; lt_entry = gxx_list_next(lt_entry)) {
                link_row *linkr = new link_row();
                data_link_info_t *data_link_info = gxx_list_data(data_link_info_t *, lt_entry);
                /*
                 * For link-layer types libpcap/WinPcap/Npcap doesn't know
                 * about, the name will be "DLT n", and the description will
                 * be null.
                 * We mark those as unsupported, and don't allow them to be
                 * used - capture filters won't work on them, for example.
                 */
                if (data_link_info->description != Q_NULLPTR) {
                    linkr->dlt = data_link_info->dlt;
                    if (active_dlt_name.isEmpty()) {
                        device->active_dlt = data_link_info->dlt;
                        active_dlt_name = data_link_info->description;
                    }
                    linkr->name = g_strdup(data_link_info->description);
                } else {
                    char *str;
                    /* XXX - should we just omit them? */
                    str = ws_strdup_printf("%s (not supported)", data_link_info->name);
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
            device->monitor_mode_enabled = false;
            device->monitor_mode_supported = false;
        }

        ti->updateInterfaceColumns(device);

        break;
    }
#endif // SHOW_MONITOR_COLUMN
    default:
        break;
    }
}

void CaptureOptionsDialog::itemClicked(QTreeWidgetItem *item, int column)
{
    InterfaceTreeWidgetItem *ti = dynamic_cast<InterfaceTreeWidgetItem *>(item);
    if (!ti) return;

#ifdef HAVE_LIBPCAP
    interface_t *device;
    QString interface_name = ti->text(col_interface_);
    device = find_device_by_if_name(interface_name);
    if (!device) return;

    switch(column) {

    case col_extcap_:
        if (device->if_info.type == IF_EXTCAP) {
            /* this checks if configuration is required and not yet provided or saved via prefs */
            QString device_name = ti->data(col_extcap_, Qt::UserRole).value<QString>();
            if (extcap_has_configuration((const char *)(device_name.toStdString().c_str())))
            {
                emit showExtcapOptions(device_name, false);
                return;
            }
        }
        break;

    default:
        break;
    }
#endif /* HAVE_LIBPCAP */
}

void CaptureOptionsDialog::itemDoubleClicked(QTreeWidgetItem *item, int column)
{
    InterfaceTreeWidgetItem *ti = dynamic_cast<InterfaceTreeWidgetItem *>(item);
    if (!ti) return;

    switch(column) {

    // Double click starts capture just on columns which are not editable
    case col_interface_:
    case col_traffic_:
    {
#ifdef HAVE_LIBPCAP
        interface_t *device;
        QString interface_name = ti->text(col_interface_);
        device = find_device_by_if_name(interface_name);
        if (!device) return;

        if (device->if_info.type == IF_EXTCAP) {
            /* this checks if configuration is required and not yet provided or saved via prefs */
            QString device_name = ti->data(col_extcap_, Qt::UserRole).value<QString>();
            if (extcap_requires_configuration((const char *)(device_name.toStdString().c_str())))
            {
                emit showExtcapOptions(device_name, true);
                return;
            }
        }
#endif /* HAVE_LIBPCAP */
        emit startCapture();
        close();
        break;
    }

    default:
        break;
    }
}

void CaptureOptionsDialog::MBComboBoxIndexChanged(int index)
{
    switch (index) {
    case 0: // kilobytes
        ui->MBSpinBox->setMaximum(2000000000);
        break;
    case 1: // megabytes
        ui->MBSpinBox->setMaximum(2000000);
        break;
    case 2: // gigabytes
        ui->MBSpinBox->setMaximum(2000);
        break;
    }
}

void CaptureOptionsDialog::stopMBComboBoxIndexChanged(int index)
{
    switch (index) {
    case 0: // kilobytes
        ui->stopMBSpinBox->setMaximum(2000000000);
        break;
    case 1: // megabytes
        ui->stopMBSpinBox->setMaximum(2000000);
        break;
    case 2: // gigabytes
        ui->stopMBSpinBox->setMaximum(2000);
        break;
    }
}

void CaptureOptionsDialog::on_gbStopCaptureAuto_toggled(bool checked)
{
    global_capture_opts.has_file_interval = checked;
}

void CaptureOptionsDialog::on_gbNewFileAuto_toggled(bool checked)
{
    global_capture_opts.multi_files_on = checked;
    ui->stopMBCheckBox->setEnabled(checked?false:true);
    ui->stopMBSpinBox->setEnabled(checked?false:true);
    ui->stopMBComboBox->setEnabled(checked?false:true);
    ui->gbCompression->setEnabled(checked);
    ui->rbCompressionNone->setEnabled(checked);
#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG)
    ui->rbCompressionGzip->setEnabled(checked);
#else
    ui->rbCompressionGzip->setEnabled(false);
#endif
}

void CaptureOptionsDialog::on_cbUpdatePacketsRT_toggled(bool checked)
{
    global_capture_opts.real_time_mode = checked;
}

void CaptureOptionsDialog::on_cbAutoScroll_toggled(bool checked)
{
    recent.capture_auto_scroll = checked;
}

void CaptureOptionsDialog::on_cbExtraCaptureInfo_toggled(bool checked)
{
    global_capture_opts.show_info = checked;
}

void CaptureOptionsDialog::on_cbResolveMacAddresses_toggled(bool checked)
{
    gbl_resolv_flags.mac_name = checked;
}

void CaptureOptionsDialog::on_cbResolveNetworkNames_toggled(bool checked)
{
    gbl_resolv_flags.network_name = checked;
}

void CaptureOptionsDialog::on_cbResolveTransportNames_toggled(bool checked)
{
    gbl_resolv_flags.transport_name = checked;
}

void CaptureOptionsDialog::on_buttonBox_accepted()
{
    if (saveOptionsToPreferences()) {

#ifdef HAVE_LIBPCAP
        InterfaceTreeWidgetItem *ti = dynamic_cast<InterfaceTreeWidgetItem *>(ui->interfaceTree->currentItem());
        if (ti) {
            interface_t *device;

            QString interface_name = ti->text(col_interface_);
            device = find_device_by_if_name(interface_name);
            if (device && device->if_info.type == IF_EXTCAP) {
                /* this checks if configuration is required and not yet provided or saved via prefs */
                QString device_name = ti->data(col_extcap_, Qt::UserRole).value<QString>();
                if (extcap_requires_configuration((const char *)(device_name.toStdString().c_str())))
                {
                    emit showExtcapOptions(device_name, true);
                    return;
                }
            }
        }
#endif /* HAVE_LIBPCAP */

        emit setFilterValid(true, ui->captureFilterComboBox->lineEdit()->text());
        accept();
    }
}

// Not sure why we have to do this manually.
void CaptureOptionsDialog::on_buttonBox_rejected()
{
    if (saveOptionsToPreferences()) {
        reject();
    }
}

void CaptureOptionsDialog::on_buttonBox_helpRequested()
{
    // Probably the wrong URL.
    mainApp->helpTopicAction(HELP_CAPTURE_OPTIONS_DIALOG);
}

void CaptureOptionsDialog::updateInterfaces()
{
    if (prefs.capture_pcap_ng) {
        ui->rbPcapng->setChecked(true);
    } else {
        ui->rbPcap->setChecked(true);
    }
    ui->capturePromModeCheckBox->setChecked(prefs.capture_prom_mode);
    ui->captureMonitorModeCheckBox->setChecked(prefs.capture_monitor_mode);
    ui->captureMonitorModeCheckBox->setEnabled(false);

    if (global_capture_opts.saving_to_file) {
        ui->filenameLineEdit->setText(QString(global_capture_opts.orig_save_file));
    }

    ui->gbNewFileAuto->setChecked(global_capture_opts.multi_files_on);
    ui->PktCheckBox->setChecked(global_capture_opts.has_file_packets);
    if (global_capture_opts.has_file_packets) {
        ui->PktSpinBox->setValue(global_capture_opts.file_packets);
    }
    ui->MBCheckBox->setChecked(global_capture_opts.has_autostop_filesize);
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

    ui->SecsCheckBox->setChecked(global_capture_opts.has_file_duration);
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

    ui->IntervalSecsCheckBox->setChecked(global_capture_opts.has_file_interval);
    if (global_capture_opts.has_file_interval) {
        int value = global_capture_opts.file_interval;
        if (value > 3600 && value % 3600 == 0) {
            ui->IntervalSecsSpinBox->setValue(value / 3600);
            ui->IntervalSecsComboBox->setCurrentIndex(2);
        } else if (value > 60 && value % 60 == 0) {
            ui->IntervalSecsSpinBox->setValue(value / 60);
            ui->IntervalSecsComboBox->setCurrentIndex(1);
        } else {
            ui->IntervalSecsSpinBox->setValue(value);
            ui->IntervalSecsComboBox->setCurrentIndex(0);
        }
    }

    if (global_capture_opts.has_ring_num_files) {
        ui->RbSpinBox->setValue(global_capture_opts.ring_num_files);
        ui->RbCheckBox->setCheckState(Qt::Checked);
    }

    if (global_capture_opts.has_autostop_duration) {
        ui->stopSecsCheckBox->setChecked(true);
        int value = global_capture_opts.autostop_duration;
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
    ui->cbAutoScroll->setChecked(recent.capture_auto_scroll);
    ui->cbExtraCaptureInfo->setChecked(global_capture_opts.show_info);

    ui->cbResolveMacAddresses->setChecked(gbl_resolv_flags.mac_name);
    ui->cbResolveNetworkNames->setChecked(gbl_resolv_flags.network_name);
    ui->cbResolveTransportNames->setChecked(gbl_resolv_flags.transport_name);

    // Rebuild the interface list without disturbing the main welcome screen.
    disconnect(ui->interfaceTree, SIGNAL(itemSelectionChanged()), this, SLOT(interfaceSelected()));
    ui->interfaceTree->clear();

#ifdef SHOW_BUFFER_COLUMN
    int           buffer;
#endif
    int           snaplen;
    bool          hassnap, pmode;
    QList<QTreeWidgetItem *> selected_interfaces;

    disconnect(ui->interfaceTree, SIGNAL(itemChanged(QTreeWidgetItem*,int)), this, SLOT(interfaceItemChanged(QTreeWidgetItem*,int)));

    if (global_capture_opts.all_ifaces->len > 0) {
        interface_t *device;

        for (unsigned device_idx = 0; device_idx < global_capture_opts.all_ifaces->len; device_idx++) {
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, device_idx);

            /* Continue if capture device is hidden */
            if (device->hidden) {
                continue;
            }

            // Traffic sparklines
            InterfaceTreeWidgetItem *ti = new InterfaceTreeWidgetItem(ui->interfaceTree);
            ti->setFlags(ti->flags() | Qt::ItemIsEditable);

            if (device->if_info.type == IF_EXTCAP) {
              ti->setIcon(col_extcap_,  QIcon(StockIcon("x-capture-options")));
              ti->setData(col_extcap_, Qt::UserRole, QString(device->if_info.name));
              ti->setToolTip(col_extcap_, QString("Extcap interface settings"));
            }

            ti->setText(col_interface_, device->display_name);
            ti->setData(col_interface_, Qt::UserRole, QString(device->name));
            if (device->if_info.type != IF_EXTCAP)
                ti->setData(col_traffic_, Qt::UserRole, QVariant::fromValue(ti->points));

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
                device->has_snaplen = snaplen == WTAP_MAX_PACKET_SIZE_STANDARD ? false : hassnap;
            } else {
                /* No preferences set yet, use default values */
                device->snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
                device->has_snaplen = false;
            }

#ifdef SHOW_BUFFER_COLUMN
            if (capture_dev_user_buffersize_find(device->name) != -1) {
                buffer = capture_dev_user_buffersize_find(device->name);
                device->buffer = buffer;
            } else {
                device->buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
            }
#endif
#ifdef SHOW_MONITOR_COLUMN
            if (device->monitor_mode_supported) {
                ui->captureMonitorModeCheckBox->setEnabled(true);
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

    updateWidgets();

    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
}

void CaptureOptionsDialog::showEvent(QShowEvent *)
{
    updateInterfaces();
}

void CaptureOptionsDialog::refreshInterfaceList()
{
    updateInterfaces();
    emit interfaceListChanged();
}

void CaptureOptionsDialog::updateLocalInterfaces()
{
    updateInterfaces();
}

void CaptureOptionsDialog::updateStatistics(void)
{
    interface_t *device;

    disconnect(ui->interfaceTree, SIGNAL(itemChanged(QTreeWidgetItem*,int)), this, SLOT(interfaceItemChanged(QTreeWidgetItem*,int)));
    for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {

        for (unsigned if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
            QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
            if (!ti) {
                continue;
            }
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
            QString device_name = ti->text(col_interface_);
            if (device_name.compare(device->display_name) || device->hidden || device->if_info.type == IF_PIPE) {
                continue;
            }
            QList<int> points = ti->data(col_traffic_, Qt::UserRole).value<QList<int> >();
            points.append(device->packet_diff);
            ti->setData(col_traffic_, Qt::UserRole, QVariant::fromValue(points));
        }
    }
    connect(ui->interfaceTree, SIGNAL(itemChanged(QTreeWidgetItem*,int)), this, SLOT(interfaceItemChanged(QTreeWidgetItem*,int)));
    ui->interfaceTree->viewport()->update();
}

void CaptureOptionsDialog::on_compileBPF_clicked()
{
    QList<InterfaceFilter> interfaces;
    foreach (QTreeWidgetItem *ti, ui->interfaceTree->selectedItems()) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        interfaces.emplaceBack(ti->text(col_interface_), ti->text(col_filter_));
#else
        interfaces.append(InterfaceFilter(ti->text(col_interface_), ti->text(col_filter_)));
#endif
    }

    QString filter = ui->captureFilterComboBox->currentText();
    CompiledFilterOutput *cfo = new CompiledFilterOutput(this, interfaces);

    cfo->show();
}

bool CaptureOptionsDialog::saveOptionsToPreferences()
{
    if (ui->rbPcapng->isChecked()) {
        global_capture_opts.use_pcapng = true;
        prefs.capture_pcap_ng = true;
    } else {
        global_capture_opts.use_pcapng = false;
        prefs.capture_pcap_ng = false;
    }

    g_free(global_capture_opts.save_file);
    g_free(global_capture_opts.orig_save_file);

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
        global_capture_opts.saving_to_file = false;
        global_capture_opts.save_file = NULL;
        global_capture_opts.orig_save_file = NULL;
    }

    QString tempdir = ui->tempDirLineEdit->text();
    if (tempdir.length() > 0) {
        global_capture_opts.temp_dir = qstring_strdup(tempdir);
    }
    else {
        global_capture_opts.temp_dir = NULL;
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
        global_capture_opts.has_file_interval = ui->IntervalSecsCheckBox->isChecked();
        if (global_capture_opts.has_file_interval) {
            global_capture_opts.file_interval = ui->IntervalSecsSpinBox->value();
            int index = ui->IntervalSecsComboBox->currentIndex();
            switch (index) {
            case 1: global_capture_opts.file_interval *= 60;
                break;
            case 2: global_capture_opts.file_interval *= 3600;
                break;
            }
         }
         global_capture_opts.has_file_packets = ui->PktCheckBox->isChecked();
         if (global_capture_opts.has_file_packets) {
             global_capture_opts.file_packets = ui->PktSpinBox->value();
         }
         global_capture_opts.has_autostop_filesize = ui->MBCheckBox->isChecked();
         if (global_capture_opts.has_autostop_filesize) {
             global_capture_opts.autostop_filesize = ui->MBSpinBox->value();
             int index = ui->MBComboBox->currentIndex();
             switch (index) {
             case 1: if (global_capture_opts.autostop_filesize > 2000000) {
                 QMessageBox::warning(this, tr("Error"),
                                          tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
                 return false;
                 } else {
                     global_capture_opts.autostop_filesize *= 1000;
                 }
                 break;
             case 2: if (global_capture_opts.autostop_filesize > 2000) {
                     QMessageBox::warning(this, tr("Error"),
                                              tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
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
                                      tr("Multiple files: No capture file name given. You must specify a filename if you want to use multiple files."));
             return false;
         } else if (!global_capture_opts.has_autostop_filesize &&
                    !global_capture_opts.has_file_interval &&
                    !global_capture_opts.has_file_duration &&
                    !global_capture_opts.has_file_packets) {
             QMessageBox::warning(this, tr("Error"),
                                      tr("Multiple files: No file limit given. You must specify a file size, interval, or number of packets for each file."));
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
            case 1: if (global_capture_opts.autostop_filesize > 2000000) {
                QMessageBox::warning(this, tr("Error"),
                                         tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
                return false;
                } else {
                    global_capture_opts.autostop_filesize *= 1000;
                }
                break;
            case 2: if (global_capture_opts.autostop_filesize > 2000) {
                    QMessageBox::warning(this, tr("Error"),
                                             tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
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
                                .arg(device->has_snaplen ? device->snaplen : WTAP_MAX_PACKET_SIZE_STANDARD);
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
                if (!device || !device->pmode) {
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

    g_free(global_capture_opts.compress_type);

    if (ui->rbCompressionNone->isChecked() )  {
        global_capture_opts.compress_type = NULL;
    } else if (ui->rbCompressionGzip->isChecked() )  {
        global_capture_opts.compress_type = qstring_strdup("gzip");
    }  else {
        global_capture_opts.compress_type = NULL;
    }

    if (ui->rbTimeNum->isChecked() )  {
        global_capture_opts.has_nametimenum = true;
    } else if (ui->rbNumTime->isChecked() )  {
        global_capture_opts.has_nametimenum = false;
    }  else {
        global_capture_opts.has_nametimenum = false;
    }

    prefs_main_write();
    return true;
}

void CaptureOptionsDialog::updateSelectedFilter()
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

void CaptureOptionsDialog::on_manageButton_clicked()
{
    if (saveOptionsToPreferences()) {
        ManageInterfacesDialog *dlg = new ManageInterfacesDialog(this);
        dlg->show();
    }
}

void CaptureOptionsDialog::changeEvent(QEvent* event)
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

interface_t *CaptureOptionsDialog::getDeviceByName(const QString device_name)
{
    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
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
        QList<int> points = data(col_traffic_, Qt::UserRole).value<QList<int> >();
        QList<int> other_points = other.data(col_traffic_, Qt::UserRole).value<QList<int> >();
        double avg = 0, other_avg = 0;
        foreach (int point, points) {
            avg += (double) point / points.length();
        }
        foreach (int point, other_points) {
            other_avg += (double) point / other_points.length();
        }
        return avg < other_avg;
    }
    return QTreeWidgetItem::operator<(other);
}

QVariant InterfaceTreeWidgetItem::data(int column, int role) const
{
    // See setData for the special col_traffic_ treatment.
    if (column == col_traffic_ && role == Qt::UserRole) {
        return QVariant::fromValue(points);
    }

    if (column == col_snaplen_ && role == Qt::DisplayRole) {
        QVariant data = QTreeWidgetItem::data(column, role);
        if (data.toInt() == WTAP_MAX_PACKET_SIZE_STANDARD || data.toInt() == 0) {
            return InterfaceTreeDelegate::tr("default");
        }
        return data;
    }
    return QTreeWidgetItem::data(column, role);
}

void InterfaceTreeWidgetItem::setData(int column, int role, const QVariant &value)
{
    // Workaround for closing editors on updates to the points list: normally
    // QTreeWidgetItem::setData emits dataChanged when the value (list) changes.
    // We could store a pointer to the list, or just have this hack that does
    // not emit dataChanged.
    if (column == col_traffic_ && role == Qt::UserRole) {
        points = value.value<QList<int> >();
        return;
    }

    QTreeWidgetItem::setData(column, role, value);
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


QWidget* InterfaceTreeDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &, const QModelIndex &idx) const
{
    QWidget *w = NULL;
#ifdef SHOW_BUFFER_COLUMN
    int buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
#endif
    unsigned snap = WTAP_MAX_PACKET_SIZE_STANDARD;
    GList *links = NULL;

    if (idx.column() > 1 && idx.data().toString().compare(UTF8_EM_DASH)) {
        QTreeWidgetItem *ti = tree_->topLevelItem(idx.row());
        QString interface_name = ti->text(col_interface_);
        interface_t *device = find_device_by_if_name(interface_name);

        if (device) {
#ifdef SHOW_BUFFER_COLUMN
            buffer = device->buffer;
#endif
            snap = device->snaplen;
            links = device->links;
        }
        switch (idx.column()) {
        case col_extcap_:
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

            for (list = links; list != Q_NULLPTR; list = gxx_list_next(list)) {
                linkr = gxx_list_data(link_row*, list);
                if (linkr->dlt >= 0) {
                    valid_link_types << linkr->name;
                }
            }

            if (valid_link_types.size() < 2) {
                break;
            }
            QComboBox *cb = new QComboBox(parent);
            cb->addItems(valid_link_types);

            connect(cb, &QComboBox::currentTextChanged, this, &InterfaceTreeDelegate::linkTypeChanged);
            w = (QWidget*) cb;
            break;
        }
        case col_snaplen_:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(0, WTAP_MAX_PACKET_SIZE_STANDARD);
            sb->setValue(snap);
            sb->setWrapping(true);
            sb->setSpecialValueText(tr("default"));
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(snapshotLengthChanged(int)));
            w = (QWidget*) sb;
            break;
        }
#ifdef SHOW_BUFFER_COLUMN
        case col_buffer_:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(1, WTAP_MAX_PACKET_SIZE_STANDARD);
            sb->setValue(buffer);
            sb->setWrapping(true);
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(bufferSizeChanged(int)));
            w = (QWidget*) sb;
            break;
        }
#endif
        case col_filter_:
        {
            // XXX: Should this take the interface name, so that the history
            // list is taken from the interface-specific recent cfilter list?
            CaptureFilterCombo *cf = new CaptureFilterCombo(parent, true);
            connect(cf->lineEdit(), SIGNAL(textEdited(QString)), this, SIGNAL(filterChanged(QString)));
            w = (QWidget*) cf;
        }
        default:
            break;
        }
    }
    if (w)
        w->setAutoFillBackground(true);
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

void InterfaceTreeDelegate::linkTypeChanged(const QString selected_link_type)
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
    for (list = device->links; list != Q_NULLPTR; list = gxx_list_next(list)) {
        temp = gxx_list_data(link_row*, list);
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
    if (value != WTAP_MAX_PACKET_SIZE_STANDARD && value != 0) {
        device->has_snaplen = true;
        device->snaplen = value;
    } else {
        device->has_snaplen = false;
        device->snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
    }
}

#ifdef SHOW_BUFFER_COLUMN
void InterfaceTreeDelegate::bufferSizeChanged(int value)
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
    device->buffer = value;
}
#endif

#endif /* HAVE_LIBPCAP */
