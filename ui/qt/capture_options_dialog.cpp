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
#include <ui/qt/widgets/capture_filter_entry.h>
#include <ui/qt/widgets/filter_edit.h>
#include <ui/qt/models/capture_filter_validator.h>
#include <ui_capture_options_dialog.h>
#include "compiled_filter_output.h"
#include "manage_interfaces_dialog.h"

#include "main_application.h"
#include <ui/qt/main_window.h>
#include <ui/qt/manager/interface_list_manager.h>
#include <ui/qt/manager/interface_statistics.h>

#include "extcap.h"

#ifdef HAVE_LIBPCAP

#include <QAbstractItemModel>
#include <QComboBox>
#include <QSpinBox>
#include <QMessageBox>

#include "ringbuffer.h"
#include "ui/capture_opts.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"

#include "ui/ws_ui_util.h"
#include "ui/util.h"
#include <wsutil/utf8_entities.h>
#include "ui/preference_utils.h"
#include <wsutil/process_lookup.h>
#include "ui/recent.h"

#include <cstdio>
#include <epan/prefs.h>
#include <app/application_flavor.h>
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
// - You can edit filters via the main capture-filter field and via each
//   individual interface row. We should probably do one or the other.
// - There might be a point in having the separate per-interface row editors,
//   if they actually called recent_get_cfilter_list with the interface name to
//   get the separate list of recent capture filters for that interface, but
//   they don't.

static interface_t *getDeviceByName(const QString &device_name)
{
    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device_name.compare(QString().fromUtf8(device->name)) == 0) {
            return device;
        }
    }
    return NULL;
}

/*
 * Resolves a proxy model index to the interface_t it displays by reading
 * the row's system name (IFTREE_COL_NAME) straight from the cache model,
 * bypassing whichever columns happen to be configured as visible.
 */
static interface_t *deviceForIndex(InterfaceTreeCacheModel *cache_model, InterfaceSortFilterModel *proxy_model, const QModelIndex &proxyIndex)
{
    if (!proxyIndex.isValid())
        return NULL;

    int row = proxy_model->mapToSource(proxyIndex).row();
    QString device_name = cache_model->data(cache_model->index(row, IFTREE_COL_NAME)).toString();
    return getDeviceByName(device_name);
}

CaptureOptionsDialog::CaptureOptionsDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::CaptureOptionsDialog)
{
    ui->setupUi(this);
    loadGeometry();
    setWindowTitle(mainApp->windowTitleString(tr("Capture Options")));

    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Start"));

    ui->processInfoComboBox->addItem(tr("Don't record processes"), CAPTURE_PROCESS_INFO_NONE);
    ui->processInfoComboBox->addItem(tr("Record process IDs and names"), CAPTURE_PROCESS_INFO_BASIC);
    ui->processInfoComboBox->addItem(tr("Record process IDs, names, paths, command lines and users"), CAPTURE_PROCESS_INFO_FULL);
    connect(ui->processInfoComboBox, &QComboBox::currentIndexChanged, this, &CaptureOptionsDialog::updateProcessInfoWidgets);
    connect(ui->rbPcapng, &QRadioButton::toggled, this, &CaptureOptionsDialog::updateProcessInfoWidgets);

    cache_model_ = new InterfaceTreeCacheModel(this);
    proxy_model_ = new InterfaceSortFilterModel(this);
    source_model_ = cache_model_->interfaceModel();

    QList<InterfaceTreeColumns> columns;
    columns << IFTREE_COL_EXTCAP
            << IFTREE_COL_DISPLAY_NAME
            << IFTREE_COL_STATS
            << IFTREE_COL_DLT
            << IFTREE_COL_PROMISCUOUSMODE
            << IFTREE_COL_SNAPLEN
            << IFTREE_COL_BUFFERLEN
            << IFTREE_COL_MONITOR_MODE
            << IFTREE_COL_OPTIMIZE
            << IFTREE_COL_CAPTURE_FILTER;
    proxy_model_->setColumns(columns);
    proxy_model_->setSourceModel(cache_model_);
    proxy_model_->setFilterHidden(true);
    proxy_model_->setFilterByType(false);
#ifdef HAVE_PCAP_REMOTE
    proxy_model_->setRemoteDisplay(true);
#endif

    col_extcap_ = proxy_model_->mapSourceToColumn(IFTREE_COL_EXTCAP);
    col_interface_ = proxy_model_->mapSourceToColumn(IFTREE_COL_DISPLAY_NAME);
    col_traffic_ = proxy_model_->mapSourceToColumn(IFTREE_COL_STATS);
    col_link_ = proxy_model_->mapSourceToColumn(IFTREE_COL_DLT);
    col_pmode_ = proxy_model_->mapSourceToColumn(IFTREE_COL_PROMISCUOUSMODE);
    col_snaplen_ = proxy_model_->mapSourceToColumn(IFTREE_COL_SNAPLEN);
    col_buffer_ = proxy_model_->mapSourceToColumn(IFTREE_COL_BUFFERLEN);
    col_monitor_ = proxy_model_->mapSourceToColumn(IFTREE_COL_MONITOR_MODE);
    col_optimize_ = proxy_model_->mapSourceToColumn(IFTREE_COL_OPTIMIZE);
    col_filter_ = proxy_model_->mapSourceToColumn(IFTREE_COL_CAPTURE_FILTER);

    ui->interfaceTree->setModel(proxy_model_);

    // Start out with the list *not* sorted, so they show up in the order
    // in which they were provided
    ui->interfaceTree->header()->setSortIndicator(-1, Qt::AscendingOrder);
    ui->interfaceTree->setSortingEnabled(true);

    interface_item_delegate_ = new InterfaceTreeDelegate(cache_model_, proxy_model_, this);
    ui->interfaceTree->setItemDelegateForColumn(col_link_, interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_snaplen_, interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_buffer_, interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_filter_, interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_traffic_, new SparkLineDelegate(this));

    ui->filenameLineEdit->setPlaceholderText(tr("Leave blank to use a temporary file"));

    ui->rbCompressionNone->setChecked(true);
#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG)
    ui->rbCompressionGzip->setEnabled(true);
#else
    ui->rbCompressionGzip->setEnabled(false);
#endif
#if defined(HAVE_LZ4FRAME_H)
    ui->rbCompressionLZ4->setEnabled(true);
#else
    ui->rbCompressionLZ4->setEnabled(false);
#endif
    ui->rbTimeNum->setChecked(true);

    ui->tempDirLineEdit->setPlaceholderText(g_get_tmp_dir());
    ui->tempDirLineEdit->setText(global_capture_opts.temp_dir);

    // Changes in interface selections or capture filters should be propagated
    // to the main welcome screen where they will be applied to the global
    // capture options.
    connect(this, &CaptureOptionsDialog::interfacesChanged, ui->captureFilterComboBox, &CaptureFilterEntry::recheck);
    connect(ui->captureFilterComboBox, &CaptureFilterEntry::captureFilterSyntaxChanged, this, &CaptureOptionsDialog::updateWidgets);
    connect(ui->captureFilterComboBox, &QLineEdit::textEdited, this, &CaptureOptionsDialog::filterEdited);
    connect(ui->captureFilterComboBox, &QLineEdit::textEdited, this, &CaptureOptionsDialog::captureFilterTextEdited);
    connect(interface_item_delegate_, &InterfaceTreeDelegate::filterChanged, ui->captureFilterComboBox, &QLineEdit::setText);
    connect(interface_item_delegate_, &InterfaceTreeDelegate::filterChanged, this, &CaptureOptionsDialog::captureFilterTextEdited);
    connect(mainApp, &MainApplication::interfaceListChanged, this, &CaptureOptionsDialog::refreshInterfaceList);

    mainApp->whenInitialized(this, [this]() { connectInterfaceListManager(); });
    connect(ui->browseButton, &QPushButton::clicked, this, &CaptureOptionsDialog::browseButtonClicked);
    connect(ui->interfaceTree, &QTreeView::clicked, this, &CaptureOptionsDialog::itemClicked);
    connect(ui->interfaceTree, &QTreeView::doubleClicked, this, &CaptureOptionsDialog::itemDoubleClicked);
    connect(ui->interfaceTree->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &CaptureOptionsDialog::interfaceSelected);
    connect(ui->tempDirBrowseButton, &QPushButton::clicked, this, &CaptureOptionsDialog::tempDirBrowseButtonClicked);

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

    // Capture size maximum depends on units. Initial unit is kB.
    ui->MBSpinBox->setMaximum(2000000000);
    ui->stopMBSpinBox->setMaximum(2000000000);

    connect(ui->MBComboBox, &QComboBox::currentIndexChanged, this, &CaptureOptionsDialog::MBComboBoxIndexChanged);
    connect(ui->stopMBComboBox, &QComboBox::currentIndexChanged, this, &CaptureOptionsDialog::stopMBComboBoxIndexChanged);

    ui->tabWidget->setCurrentIndex(0);

    updateWidgets();
}

CaptureOptionsDialog::~CaptureOptionsDialog()
{
    delete ui;
}

/* Update global device selections based on the view's selection. */
void CaptureOptionsDialog::updateGlobalDeviceSelections()
{
    QItemSelection viewSelection = ui->interfaceTree->selectionModel()->selection();
    QItemSelection sourceSelection = cache_model_->mapSelectionToSource(proxy_model_->mapSelectionToSource(viewSelection));

    // Also sets global_capture_opts.num_selected.
    source_model_->updateSelectedDevices(sourceSelection);
}

/* Update the view's selection based on global device selections. */
void CaptureOptionsDialog::updateFromGlobalDeviceSelections()
{
    QItemSelection sourceSelection = source_model_->selectedDevices();
    QItemSelection viewSelection = proxy_model_->mapSelectionFromSource(cache_model_->mapSelectionFromSource(sourceSelection));

    // Prevent recursive interfaceSelected signals
    ui->interfaceTree->selectionModel()->blockSignals(true);
    ui->interfaceTree->selectionModel()->select(viewSelection, QItemSelectionModel::ClearAndSelect);
    ui->interfaceTree->selectionModel()->blockSignals(false);
}

void CaptureOptionsDialog::interfaceSelected()
{
    if (sender() == ui->interfaceTree->selectionModel()) {
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
    QModelIndexList selected_rows = ui->interfaceTree->selectionModel()->selectedRows();

    foreach (const QModelIndex &row, selected_rows) {
        QModelIndex filter_idx = proxy_model_->mapToSource(row.sibling(row.row(), col_filter_));
        cache_model_->setData(filter_idx, ui->captureFilterComboBox->text(), Qt::EditRole);
    }

    if (selected_rows.count() > 0) {
        ui->interfaceTree->scrollTo(selected_rows.first().sibling(selected_rows.first().row(), col_filter_));
    }
}

void CaptureOptionsDialog::updateWidgets()
{
    bool can_capture = false;

    if (ui->interfaceTree->selectionModel()->selectedRows().count() > 0 &&
        ui->captureFilterComboBox->state() != FilterEdit::SyntaxState::Invalid) {
        can_capture = true;
    }

    ui->compileBPF->setEnabled(can_capture);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(can_capture);
}

void CaptureOptionsDialog::on_capturePromModeCheckBox_toggled(bool checked)
{
    prefs.capture_prom_mode = checked;
    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        cache_model_->setData(cache_model_->index(i, IFTREE_COL_PROMISCUOUSMODE), checked ? Qt::Checked : Qt::Unchecked, Qt::CheckStateRole);
    }
}

void CaptureOptionsDialog::on_captureMonitorModeCheckBox_toggled(bool checked)
{
    prefs.capture_monitor_mode = checked;
    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device->monitor_mode_supported)
            continue;
        cache_model_->setData(cache_model_->index(i, IFTREE_COL_MONITOR_MODE), checked ? Qt::Checked : Qt::Unchecked, Qt::CheckStateRole);
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

void CaptureOptionsDialog::itemClicked(const QModelIndex &index)
{
    if (index.column() != col_extcap_)
        return;

    interface_t *device = deviceForIndex(cache_model_, proxy_model_, index);
    if (!device || device->if_info.type != IF_EXTCAP)
        return;

    /* this checks if configuration is required and not yet provided or saved via prefs */
    QString device_name(device->if_info.name);
    if (extcap_has_configuration((const char *)(device_name.toStdString().c_str())))
    {
        emit showExtcapOptions(device_name, false);
    }
}

void CaptureOptionsDialog::itemDoubleClicked(const QModelIndex &index)
{
    // Double click starts capture just on columns which are not editable
    if (index.column() != col_interface_ && index.column() != col_traffic_)
        return;

    interface_t *device = deviceForIndex(cache_model_, proxy_model_, index);
    if (!device)
        return;

    if (device->if_info.type == IF_EXTCAP) {
        /* this checks if configuration is required and not yet provided or saved via prefs */
        QString device_name(device->if_info.name);
        if (extcap_requires_configuration((const char *)(device_name.toStdString().c_str())))
        {
            emit showExtcapOptions(device_name, true);
            return;
        }
    }

    emit startCapture();
    close();
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
    // Flush any pending per-row edits (filter, DLT, snaplen, buffer, ...) into
    // the real interface_t structs before anything reads them below.
    cache_model_->save();
    cache_model_->reset(-1);

    if (saveOptionsToPreferences(&global_capture_opts)) {

        interface_t *device = deviceForIndex(cache_model_, proxy_model_, ui->interfaceTree->currentIndex());
        if (device && device->if_info.type == IF_EXTCAP) {
            /* this checks if configuration is required and not yet provided or saved via prefs */
            QString device_name(device->if_info.name);
            if (extcap_requires_configuration((const char *)(device_name.toStdString().c_str())))
            {
                emit showExtcapOptions(device_name, true);
                return;
            }
        }

        emit setFilterValid(true, ui->captureFilterComboBox->text());
        accept();
    }
}

// Not sure why we have to do this manually.
void CaptureOptionsDialog::on_buttonBox_rejected()
{
    // Discard any pending per-row edits; nothing in the interface list should
    // stick from a cancelled dialog.
    cache_model_->reset(-1);

    if (saveOptionsToPreferences(&global_capture_opts)) {
        reject();
    }
}

void CaptureOptionsDialog::updateProcessInfoWidgets()
{
    bool possible = ws_process_lookup_supported() && ui->rbPcapng->isChecked();

    if (!application_flavor_is_wireshark()) {
        /* Stratoshark captures system calls, which have no sockets to look up. */
        ui->processInfoWidget->setVisible(false);
        return;
    }
    ui->labelProcessInfo->setEnabled(possible);
    ui->processInfoComboBox->setEnabled(possible);
    if (!ws_process_lookup_supported()) {
        ui->processInfoComboBox->setToolTip(tr("Not supported on this platform."));
    } else if (!ui->rbPcapng->isChecked()) {
        ui->processInfoComboBox->setToolTip(tr("Process information can only be recorded in pcapng files."));
    } else {
        ui->processInfoComboBox->setToolTip(tr("<html><head/><body><p>Record which processes on this computer sent or received each packet, "
            "for the packets of TCP and UDP sockets. Which processes can be identified depends on your privileges, "
            "and the packets of very short-lived sockets can be missed.</p></body></html>"));
    }
    ui->processInfoWarningLabel->setVisible(possible &&
        ui->processInfoComboBox->currentData().toInt() == CAPTURE_PROCESS_INFO_FULL);
}

void CaptureOptionsDialog::on_buttonBox_helpRequested()
{
    // Probably the wrong URL.
    mainApp->helpTopicAction(HELP_CAPTURE_OPTIONS_DIALOG);
}

void CaptureOptionsDialog::updateInterfaces(capture_options* capture_opts)
{
    if (prefs.capture_pcap_ng) {
        ui->rbPcapng->setChecked(true);
    } else {
        ui->rbPcap->setChecked(true);
    }
    ui->processInfoComboBox->setCurrentIndex(ui->processInfoComboBox->findData(prefs.capture_process_info));
    updateProcessInfoWidgets();
    ui->capturePromModeCheckBox->setChecked(prefs.capture_prom_mode);
    ui->captureMonitorModeCheckBox->setChecked(prefs.capture_monitor_mode);
    ui->captureMonitorModeCheckBox->setEnabled(false);

    if (capture_opts->saving_to_file) {
        ui->filenameLineEdit->setText(QString(capture_opts->orig_save_file));
    }

    ui->gbNewFileAuto->setChecked(capture_opts->multi_files_on);
    ui->PktCheckBox->setChecked(capture_opts->has_file_packets);
    if (capture_opts->has_file_packets) {
        ui->PktSpinBox->setValue(capture_opts->file_packets);
    }
    ui->MBCheckBox->setChecked(capture_opts->has_autostop_filesize);
    if (capture_opts->has_autostop_filesize) {
        int value = capture_opts->autostop_filesize;
        if (value > 1000000) {
            if (capture_opts->multi_files_on) {
                ui->MBSpinBox->setValue(value / 1000000);
                ui->MBComboBox->setCurrentIndex(2);
            } else {
                ui->stopMBCheckBox->setChecked(true);
                ui->stopMBSpinBox->setValue(value / 1000000);
                ui->stopMBComboBox->setCurrentIndex(2);
            }
        } else if (value > 1000 && value % 1000 == 0) {
            if (capture_opts->multi_files_on) {
                ui->MBSpinBox->setValue(value / 1000);
                ui->MBComboBox->setCurrentIndex(1);
            } else {
                ui->stopMBCheckBox->setChecked(true);
                ui->stopMBSpinBox->setValue(value / 1000);
                ui->stopMBComboBox->setCurrentIndex(1);
            }
        } else {
            if (capture_opts->multi_files_on) {
                ui->MBSpinBox->setValue(value);
                ui->MBComboBox->setCurrentIndex(0);
            } else {
                ui->stopMBCheckBox->setChecked(true);
                ui->stopMBSpinBox->setValue(value);
                ui->stopMBComboBox->setCurrentIndex(0);
            }
        }
    }

    ui->SecsCheckBox->setChecked(capture_opts->has_file_duration);
    if (capture_opts->has_file_duration) {
        int value = capture_opts->file_duration;
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

    ui->IntervalSecsCheckBox->setChecked(capture_opts->has_file_interval);
    if (capture_opts->has_file_interval) {
        int value = capture_opts->file_interval;
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

    if (capture_opts->has_ring_num_files) {
        ui->RbSpinBox->setValue(capture_opts->ring_num_files);
        ui->RbCheckBox->setCheckState(Qt::Checked);
    }

    if (capture_opts->has_autostop_duration) {
        ui->stopSecsCheckBox->setChecked(true);
        int value = capture_opts->autostop_duration;
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

    if (capture_opts->has_autostop_packets) {
        ui->stopPktCheckBox->setChecked(true);
        ui->stopPktSpinBox->setValue(capture_opts->autostop_packets);
    }

    if (capture_opts->has_autostop_files) {
        ui->stopFilesCheckBox->setChecked(true);
        ui->stopFilesSpinBox->setValue(capture_opts->autostop_files);
    }

    ui->cbUpdatePacketsRT->setChecked(capture_opts->real_time_mode);
    ui->cbAutoScroll->setChecked(recent.capture_auto_scroll);
    ui->cbExtraCaptureInfo->setChecked(capture_opts->show_info);

    ui->cbResolveMacAddresses->setChecked(gbl_resolv_flags.mac_name);
    ui->cbResolveNetworkNames->setChecked(gbl_resolv_flags.network_name);
    ui->cbResolveTransportNames->setChecked(gbl_resolv_flags.transport_name);

    int           buffer;
    int           snaplen;
    bool          hassnap, pmode;

    if (capture_opts->all_ifaces->len > 0) {
        interface_t *device;

        for (unsigned device_idx = 0; device_idx < capture_opts->all_ifaces->len; device_idx++) {
            device = &g_array_index(capture_opts->all_ifaces, interface_t, device_idx);

            /* Continue if capture device is hidden */
            if (device->hidden) {
                continue;
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

            if (capture_dev_user_buffersize_find(device->name) != -1) {
                buffer = capture_dev_user_buffersize_find(device->name);
                device->buffer = buffer;
            } else {
                device->buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
            }
            if (device->monitor_mode_supported) {
                ui->captureMonitorModeCheckBox->setEnabled(true);
            }
        }
    }

    // Let the model pick up the (possibly changed) global interface list.
    source_model_->interfaceListChanged();

    updateFromGlobalDeviceSelections();
    updateSelectedFilter();

    // Manually or automatically size some columns as needed.
    int one_em = fontMetrics().height();
    ui->interfaceTree->setColumnWidth(col_pmode_, one_em * 3.25);
    ui->interfaceTree->setColumnWidth(col_snaplen_, one_em * 4.25);
    ui->interfaceTree->setColumnWidth(col_buffer_, one_em * 4.25);
    ui->interfaceTree->setColumnWidth(col_monitor_, one_em * 3.25);
    ui->interfaceTree->setColumnWidth(col_optimize_, one_em * 3.25);
    ui->interfaceTree->resizeColumnToContents(col_extcap_);
    ui->interfaceTree->resizeColumnToContents(col_interface_);
    ui->interfaceTree->resizeColumnToContents(col_traffic_);
    ui->interfaceTree->resizeColumnToContents(col_link_);

    updateWidgets();
}

void CaptureOptionsDialog::showEvent(QShowEvent *)
{
    updateInterfaces(&global_capture_opts);
}

void CaptureOptionsDialog::refreshInterfaceList()
{
    updateInterfaces(&global_capture_opts);
}

void CaptureOptionsDialog::connectInterfaceListManager()
{
    MainWindow *mainWindow = mainApp->mainWindow();
    if (!mainWindow || !mainWindow->interfaceListManager())
        return;

    InterfaceListManager *manager = mainWindow->interfaceListManager();
    // The facade owns the dumpcap -S stream; the model renders the
    // sparklines/activity straight from it once wired up here.
    if (InterfaceStatistics *stats = manager->statistics()) {
        source_model_->setStatistics(stats);
    }
}

void CaptureOptionsDialog::on_compileBPF_clicked()
{
    InterfaceList interfaces;
    QModelIndexList selected_rows = ui->interfaceTree->selectionModel()->selectedRows();
    foreach (const QModelIndex &row, selected_rows) {
        interface_t *device = deviceForIndex(cache_model_, proxy_model_, row);
        if (!device) continue;
        interfaces.emplaceBack(device);
    }

    CompiledFilterOutput *cfo = new CompiledFilterOutput(this, interfaces);

    cfo->show();
}

bool CaptureOptionsDialog::saveOptionsToPreferences(capture_options* capture_opts)
{
    if (ui->rbPcapng->isChecked()) {
        capture_opts->use_pcapng = true;
        prefs.capture_pcap_ng = true;
    } else {
        capture_opts->use_pcapng = false;
        prefs.capture_pcap_ng = false;
    }
    /* What is chosen is remembered even while it can't be done, e.g. for a pcap file. */
    prefs.capture_process_info = (capture_process_info_e)ui->processInfoComboBox->currentData().toInt();
    capture_opts_set_process_info(capture_opts, prefs.capture_process_info);

    g_free(capture_opts->save_file);
    g_free(capture_opts->orig_save_file);

    QString filename = ui->filenameLineEdit->text();
    if (filename.length() > 0) {
        /* User specified a file to which the capture should be written. */
        capture_opts->saving_to_file = true;
        capture_opts->save_file = qstring_strdup(filename);
        capture_opts->orig_save_file = qstring_strdup(filename);
        /* Save the directory name for future file dialogs. */
        set_last_open_dir(get_dirname(filename.toUtf8().data()));
    } else {
        /* User didn't specify a file; save to a temporary file. */
        capture_opts->saving_to_file = false;
        capture_opts->save_file = NULL;
        capture_opts->orig_save_file = NULL;
    }

    QString tempdir = ui->tempDirLineEdit->text();
    if (tempdir.length() > 0) {
        capture_opts->temp_dir = qstring_strdup(tempdir);
    }
    else {
        capture_opts->temp_dir = NULL;
    }

    capture_opts->has_ring_num_files = ui->RbCheckBox->isChecked();

    if (capture_opts->has_ring_num_files) {
        capture_opts->ring_num_files = ui->RbSpinBox->value();
        if (capture_opts->ring_num_files > RINGBUFFER_MAX_NUM_FILES)
            capture_opts->ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
        else if (capture_opts->ring_num_files < RINGBUFFER_MIN_NUM_FILES)
            capture_opts->ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif
    }
    capture_opts->multi_files_on = ui->gbNewFileAuto->isChecked();
    if (capture_opts->multi_files_on) {
        capture_opts->has_file_duration = ui->SecsCheckBox->isChecked();
        if (capture_opts->has_file_duration) {
            capture_opts->file_duration = ui->SecsSpinBox->value();
            int index = ui->SecsComboBox->currentIndex();
            switch (index) {
            case 1: capture_opts->file_duration *= 60;
                break;
            case 2: capture_opts->file_duration *= 3600;
                break;
            }
         }
        capture_opts->has_file_interval = ui->IntervalSecsCheckBox->isChecked();
        if (capture_opts->has_file_interval) {
            capture_opts->file_interval = ui->IntervalSecsSpinBox->value();
            int index = ui->IntervalSecsComboBox->currentIndex();
            switch (index) {
            case 1: capture_opts->file_interval *= 60;
                break;
            case 2: capture_opts->file_interval *= 3600;
                break;
            }
         }
        capture_opts->has_file_packets = ui->PktCheckBox->isChecked();
         if (capture_opts->has_file_packets) {
             capture_opts->file_packets = ui->PktSpinBox->value();
         }
         capture_opts->has_autostop_filesize = ui->MBCheckBox->isChecked();
         if (capture_opts->has_autostop_filesize) {
             capture_opts->autostop_filesize = ui->MBSpinBox->value();
             int index = ui->MBComboBox->currentIndex();
             switch (index) {
             case 1: if (capture_opts->autostop_filesize > 2000000) {
                 QMessageBox::warning(this, tr("Error"),
                                          tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
                 return false;
                 } else {
                     capture_opts->autostop_filesize *= 1000;
                 }
                 break;
             case 2: if (capture_opts->autostop_filesize > 2000) {
                     QMessageBox::warning(this, tr("Error"),
                                              tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
                     return false;
                     } else {
                         capture_opts->autostop_filesize *= 1000000;
                     }
                 break;
             }
         }
         /* test if the settings are ok for a ringbuffer */
         if (capture_opts->save_file == NULL) {
             QMessageBox::warning(this, tr("Error"),
                                      tr("Multiple files: No capture file name given. You must specify a filename if you want to use multiple files."));
             return false;
         } else if (!capture_opts->has_autostop_filesize &&
                    !capture_opts->has_file_interval &&
                    !capture_opts->has_file_duration &&
                    !capture_opts->has_file_packets) {
             QMessageBox::warning(this, tr("Error"),
                                      tr("Multiple files: No file limit given. You must specify a file size, interval, or number of packets for each file."));
             g_free(capture_opts->save_file);
             capture_opts->save_file = NULL;
             return false;
         }
    } else {
        capture_opts->has_autostop_filesize = ui->stopMBCheckBox->isChecked();
        if (capture_opts->has_autostop_filesize) {
            capture_opts->autostop_filesize = ui->stopMBSpinBox->value();
            int index = ui->stopMBComboBox->currentIndex();
            switch (index) {
            case 1: if (capture_opts->autostop_filesize > 2000000) {
                QMessageBox::warning(this, tr("Error"),
                                         tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
                return false;
                } else {
                    capture_opts->autostop_filesize *= 1000;
                }
                break;
            case 2: if (capture_opts->autostop_filesize > 2000) {
                    QMessageBox::warning(this, tr("Error"),
                                             tr("Multiple files: Requested filesize too large. The filesize cannot be greater than 2 TB."));
                    return false;
                    } else {
                        capture_opts->autostop_filesize *= 1000000;
                    }
                break;
            }
        }
    }

    capture_opts->has_autostop_duration = ui->stopSecsCheckBox->isChecked();
    if (capture_opts->has_autostop_duration) {
        capture_opts->autostop_duration = ui->stopSecsSpinBox->value();
        int index = ui->stopSecsComboBox->currentIndex();
        switch (index) {
        case 1: capture_opts->autostop_duration *= 60;
            break;
        case 2: capture_opts->autostop_duration *= 3600;
            break;
        }
    }

    capture_opts->has_autostop_packets = ui->stopPktCheckBox->isChecked();
    if (capture_opts->has_autostop_packets) {
        capture_opts->autostop_packets = ui->stopPktSpinBox->value();
    }

    capture_opts->has_autostop_files = ui->stopFilesCheckBox->isChecked();
    if (capture_opts->has_autostop_files) {
        capture_opts->autostop_files = ui->stopFilesSpinBox->value();
    }

    // These preference strings are derived straight from the (by now
    // up to date, thanks to cache_model_->save() in on_buttonBox_accepted())
    // interface_t structs, one entry per interface.
    QStringList link_list, buffer_size_list, snaplen_list, pmode_list, monitor_list;

    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);

        if (device->active_dlt != -1)
            link_list << QStringLiteral("%1(%2)").arg(device->name).arg(device->active_dlt);

        if (device->buffer != -1)
            buffer_size_list << QStringLiteral("%1(%2)").arg(device->name).arg(device->buffer);

        snaplen_list << QStringLiteral("%1:%2(%3)")
                        .arg(device->name)
                        .arg(device->has_snaplen)
                        .arg(device->has_snaplen ? device->snaplen : WTAP_MAX_PACKET_SIZE_STANDARD);

        if (device->pmode)
            pmode_list << QStringLiteral("%1(%2)").arg(device->name).arg(device->pmode);

        if (device->monitor_mode_supported && device->monitor_mode_enabled)
            monitor_list << device->name;
    }

    wmem_free(wmem_epan_scope(), prefs.capture_devices_linktypes);
    prefs.capture_devices_linktypes = wmem_strdup(wmem_epan_scope(), link_list.join(",").toUtf8().constData());

    wmem_free(wmem_epan_scope(), prefs.capture_devices_buffersize);
    prefs.capture_devices_buffersize = wmem_strdup(wmem_epan_scope(), buffer_size_list.join(",").toUtf8().constData());

    wmem_free(wmem_epan_scope(), prefs.capture_devices_snaplen);
    prefs.capture_devices_snaplen = wmem_strdup(wmem_epan_scope(), snaplen_list.join(",").toUtf8().constData());

    wmem_free(wmem_epan_scope(), prefs.capture_devices_pmode);
    prefs.capture_devices_pmode = wmem_strdup(wmem_epan_scope(), pmode_list.join(",").toUtf8().constData());

    wmem_free(wmem_epan_scope(), prefs.capture_devices_monitor_mode);
    prefs.capture_devices_monitor_mode = wmem_strdup(wmem_epan_scope(), monitor_list.join(",").toUtf8().constData());

    // We don't save the "Optimize" or per-interface "Capture Filter" columns
    // to preferences (they're rarely changed, and the filter should already
    // have been applied to device->cfilter by cache_model_->save()).

    g_free(capture_opts->compress_type);

    if (ui->rbCompressionNone->isChecked() )  {
        capture_opts->compress_type = NULL;
    } else if (ui->rbCompressionGzip->isChecked() )  {
        capture_opts->compress_type = qstring_strdup("gzip");
    } else if (ui->rbCompressionLZ4->isChecked() )  {
        capture_opts->compress_type = qstring_strdup("lz4");
    } else {
        capture_opts->compress_type = NULL;
    }

    if (ui->rbTimeNum->isChecked() )  {
        capture_opts->has_nametimenum = true;
    } else if (ui->rbNumTime->isChecked() )  {
        capture_opts->has_nametimenum = false;
    }  else {
        capture_opts->has_nametimenum = false;
    }

    prefs_main_write();
    return true;
}

void CaptureOptionsDialog::updateSelectedFilter()
{
    // Should match MainWelcome::interfaceSelected.
    QPair <const QString, bool> sf_pair = CaptureFilterEntry::getSelectedFilter();
    const QString user_filter = sf_pair.first;
    bool conflict = sf_pair.second;

    if (conflict) {
        ui->captureFilterComboBox->clear();
        ui->captureFilterComboBox->setConflict(true);
    } else {
        ui->captureFilterComboBox->setText(user_filter);
    }
}

void CaptureOptionsDialog::on_manageButton_clicked()
{
    cache_model_->save();
    cache_model_->reset(-1);

    if (saveOptionsToPreferences(&global_capture_opts)) {
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

//
// InterfaceTreeDelegate
//

InterfaceTreeDelegate::InterfaceTreeDelegate(InterfaceTreeCacheModel *cache_model, InterfaceSortFilterModel *proxy_model, QObject *parent)
    : QStyledItemDelegate(parent), cache_model_(cache_model), proxy_model_(proxy_model)
{
}

QWidget* InterfaceTreeDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &, const QModelIndex &idx) const
{
    QWidget *w = NULL;

    interface_t *device = deviceForIndex(cache_model_, proxy_model_, idx);
    if (!device)
        return NULL;

    int col_link = proxy_model_->mapSourceToColumn(IFTREE_COL_DLT);
    int col_snaplen = proxy_model_->mapSourceToColumn(IFTREE_COL_SNAPLEN);
    int col_buffer = proxy_model_->mapSourceToColumn(IFTREE_COL_BUFFERLEN);
    int col_filter = proxy_model_->mapSourceToColumn(IFTREE_COL_CAPTURE_FILTER);

    if (idx.column() == col_link) {
        GList *list;
        link_row *linkr;
        QStringList valid_link_types;

        for (list = device->links; list != Q_NULLPTR; list = gxx_list_next(list)) {
            linkr = gxx_list_data(link_row*, list);
            if (linkr->dlt >= 0) {
                valid_link_types << linkr->name;
            }
        }

        if (valid_link_types.size() < 2) {
            return NULL;
        }
        QComboBox *cb = new QComboBox(parent);
        cb->addItems(valid_link_types);
        w = (QWidget*) cb;
    } else if (idx.column() == col_snaplen) {
        QSpinBox *sb = new QSpinBox(parent);
        sb->setRange(0, WTAP_MAX_PACKET_SIZE_STANDARD);
        sb->setValue(device->snaplen);
        sb->setWrapping(true);
        sb->setSpecialValueText(tr("default"));
        w = (QWidget*) sb;
    } else if (idx.column() == col_buffer) {
        QSpinBox *sb = new QSpinBox(parent);
        sb->setRange(1, WTAP_MAX_PACKET_SIZE_STANDARD);
        sb->setValue(device->buffer);
        sb->setWrapping(true);
        w = (QWidget*) sb;
    } else if (idx.column() == col_filter) {
        // A plain (chrome-less) capture-filter edit: validity tinting via the
        // capture validator, but none of the bookmark/history in-line actions
        // the main field has, since this is an inline table-cell editor.
        FilterEdit *cf = new FilterEdit(parent);
        cf->setValidator(new CaptureFilterValidator(cf));
        cf->setText(QString(device->cfilter));
        connect(cf, &QLineEdit::textEdited, this, &InterfaceTreeDelegate::filterChanged);
        w = (QWidget*) cf;
    }

    if (w)
        w->setAutoFillBackground(true);
    return w;
}

void InterfaceTreeDelegate::setEditorData(QWidget *, const QModelIndex &) const
{
    // createEditor() already populated the editor directly from the
    // live interface_t, since the cache model doesn't (yet) surface
    // Qt::EditRole for these columns. Nothing further to do here, and
    // doing nothing avoids clobbering that with an invalid QVariant.
}

void InterfaceTreeDelegate::setModelData(QWidget *editor, QAbstractItemModel *, const QModelIndex &idx) const
{
    QModelIndex cacheIdx = proxy_model_->mapToSource(idx);

    int col_link = proxy_model_->mapSourceToColumn(IFTREE_COL_DLT);
    int col_snaplen = proxy_model_->mapSourceToColumn(IFTREE_COL_SNAPLEN);
    int col_filter = proxy_model_->mapSourceToColumn(IFTREE_COL_CAPTURE_FILTER);

    if (idx.column() == col_link) {
        if (QComboBox *cb = qobject_cast<QComboBox *>(editor))
            cache_model_->setData(cacheIdx, cb->currentText(), Qt::EditRole);
    } else if (idx.column() == col_filter) {
        if (FilterEdit *cf = qobject_cast<FilterEdit *>(editor))
            cache_model_->setData(cacheIdx, cf->text(), Qt::EditRole);
    } else if (idx.column() == col_snaplen) {
        if (QSpinBox *sb = qobject_cast<QSpinBox *>(editor)) {
            int value = sb->value();
            // The spinbox's minimum (0) is its "default" special value;
            // InterfaceTreeCacheModel::save() keys off
            // WTAP_MAX_PACKET_SIZE_STANDARD instead.
            if (value == 0)
                value = WTAP_MAX_PACKET_SIZE_STANDARD;
            cache_model_->setData(cacheIdx, value, Qt::EditRole);
        }
    } else if (QSpinBox *sb = qobject_cast<QSpinBox *>(editor)) {
        cache_model_->setData(cacheIdx, sb->value(), Qt::EditRole);
    }
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

#endif /* HAVE_LIBPCAP */
