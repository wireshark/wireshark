/* wireless_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wireless_frame.h"
#include <ui_wireless_frame.h>

#include "config.h"

#include <capture/capture_session.h>
#include <capture/capture_sync.h>

#include <capture/ws80211_utils.h>

#include "ui/ws_ui_util.h"
#include <wsutil/utf8_entities.h>
#include <wsutil/802_11-utils.h>
#include "main_application.h"
#include "utils/qt_ui_utils.h"

#include <QProcess>
#include <QAbstractItemView>

// To do:
// - Disable or hide invalid channel types.
// - Push more status messages ("switched to...") to the status bar.
// - Add a "Decrypt in the driver" checkbox?
// - Check for frequency and channel type changes.
// - Find something appropriate to run from the helperToolButton on Linux.

// Questions:
// - From our perspective, what's the difference between "NOHT" and "HT20"?

const int update_interval_ = 1500; // ms

WirelessFrame::WirelessFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::WirelessFrame),
    interfaces_(NULL),
    capture_in_progress_(false),
    iface_timer_id_(-1)
{
    ui->setupUi(this);

    ui->helperToolButton->hide();

    if (ws80211_init() == WS80211_INIT_OK) {
        ui->stackedWidget->setEnabled(true);
        ui->stackedWidget->setCurrentWidget(ui->interfacePage);

#ifdef HAVE_AIRPCAP
        // We should arguably add ws80211_get_helper_name and ws80211_get_helper_tooltip.
        // This works for now and is translatable.
        ui->helperToolButton->setText(tr("AirPcap Control Panel"));
        ui->helperToolButton->setToolTip(tr("Open the AirPcap Control Panel"));
        ui->helperToolButton->show();
        ui->helperToolButton->setEnabled(ws80211_get_helper_path() != NULL);
#endif

    } else {
        ui->stackedWidget->setEnabled(false);
        ui->stackedWidget->setCurrentWidget(ui->noWirelessPage);
    }

    ui->fcsFilterFrame->setVisible(ws80211_has_fcs_filter());

    updateInterfaceList();
    connect(mainApp, &MainApplication::localInterfaceEvent,
            this, &WirelessFrame::handleInterfaceEvent);
}

WirelessFrame::~WirelessFrame()
{
    ws80211_free_interfaces(interfaces_);
    delete ui;
}

void WirelessFrame::setCaptureInProgress(bool capture_in_progress)
{
    capture_in_progress_ = capture_in_progress;
    updateWidgets();
}


int WirelessFrame::startTimer(int interval)
{
    if (iface_timer_id_ != -1) {
        killTimer(iface_timer_id_);
        iface_timer_id_ = -1;
    }
    iface_timer_id_ = QFrame::startTimer(interval);
    return iface_timer_id_;
}

void WirelessFrame::handleInterfaceEvent(const char *ifname _U_, int added, int up _U_)
{
    if (!added) {
        // Unfortunately when an interface removed event is received the network
        // interface is still present for a while in the system.
        // To overcome this update the interface list after a while.
        startTimer(update_interval_);
    } else {
        updateInterfaceList();
    }
}

void WirelessFrame::timerEvent(QTimerEvent *event)
{
    if (event->timerId() != iface_timer_id_) {
        QFrame::timerEvent(event);
        return;
    }
    killTimer(iface_timer_id_);
    iface_timer_id_ = -1;
    updateInterfaceList();
}

// Check to see if the ws80211 interface list matches the one in our
// combobox. Rebuild ours if necessary and select the first interface if
// the current selection goes away.
void WirelessFrame::updateInterfaceList()
{
    ws80211_free_interfaces(interfaces_);
    interfaces_ = ws80211_find_interfaces();
    const QString old_iface = ui->interfaceComboBox->currentText();
    unsigned iface_count = 0;
    bool list_changed = false;

    // Don't interfere with user activity.
    if (ui->interfaceComboBox->view()->isVisible()
        || ui->channelComboBox->view()->isVisible()
        || ui->channelTypeComboBox->view()->isVisible()
        || ui->fcsComboBox->view()->isVisible()) {
        startTimer(update_interval_);
        return;
    }

    if (interfaces_ && interfaces_->len > 0) {
        iface_count = interfaces_->len;
    }

    if ((int) iface_count != ui->interfaceComboBox->count()) {
        list_changed = true;
    } else {
        for (unsigned i = 0; i < iface_count; i++) {
            struct ws80211_interface *iface = g_array_index(interfaces_, struct ws80211_interface *, i);
            if (ui->interfaceComboBox->itemText(i).compare(iface->ifname) != 0) {
                list_changed = true;
                break;
            }
        }
    }

    if (list_changed) {
        ui->interfaceComboBox->clear();
        for (unsigned i = 0; i < iface_count; i++) {
            struct ws80211_interface *iface = g_array_index(interfaces_, struct ws80211_interface *, i);
            ui->interfaceComboBox->addItem(iface->ifname);
            if (old_iface.compare(iface->ifname) == 0) {
                ui->interfaceComboBox->setCurrentIndex(ui->interfaceComboBox->count() - 1);
            }
        }
    }

    if (ui->interfaceComboBox->currentText().compare(old_iface) != 0) {
        getInterfaceInfo();
    }
}

void WirelessFrame::updateWidgets()
{
    bool enable_interface = false;
    bool enable_channel = false;
    bool enable_offset = false;
    bool enable_show_fcs = false;

    if (ui->interfaceComboBox->count() > 0) {
        enable_interface = true;
        enable_show_fcs = true;
    }

    if (enable_interface && ui->channelComboBox->count() > 0) {
        enable_channel = true;
    }

    if (enable_channel && ui->channelTypeComboBox->count() > 1) {
        enable_offset = true;
    }

    ui->interfaceComboBox->setEnabled(enable_interface);
    ui->channelComboBox->setEnabled(enable_channel);
    ui->channelTypeComboBox->setEnabled(enable_offset);
    ui->fcsComboBox->setEnabled(!capture_in_progress_ && enable_show_fcs);
}

void WirelessFrame::on_helperToolButton_clicked()
{
    const QString helper_path = ws80211_get_helper_path();
    if (helper_path.isEmpty()) return;

    QString command = QString("\"%1\"").arg(helper_path);
    QProcess::startDetached(command, QStringList());
}

void WirelessFrame::on_prefsToolButton_clicked()
{
    emit showWirelessPreferences("wlan");
}

void WirelessFrame::getInterfaceInfo()
{
    const QString cur_iface = ui->interfaceComboBox->currentText();

    ui->channelComboBox->clear();
    ui->channelTypeComboBox->clear();
    ui->fcsComboBox->clear();

    if (cur_iface.isEmpty()) {
        updateWidgets();
        return;
    }

    for (unsigned i = 0; i < interfaces_->len; i++) {
        struct ws80211_interface *iface = g_array_index(interfaces_, struct ws80211_interface *, i);
        if (cur_iface.compare(iface->ifname) == 0) {
            struct ws80211_iface_info iface_info;
            QString units = " GHz";

            ws80211_get_iface_info(iface->ifname, &iface_info);

            for (unsigned j = 0; j < iface->frequencies->len; j++) {
                uint32_t frequency = g_array_index(iface->frequencies, uint32_t, j);
                double ghz = frequency / 1000.0;
                QString chan_str = QString("%1 " UTF8_MIDDLE_DOT " %2%3")
                        .arg(ieee80211_mhz_to_chan(frequency))
                        .arg(ghz, 0, 'f', 3)
                        .arg(units);
                ui->channelComboBox->addItem(chan_str, frequency);
                if ((int)frequency == iface_info.current_freq) {
                    ui->channelComboBox->setCurrentIndex(ui->channelComboBox->count() - 1);
                }
                units = QString();
            }
            // XXX - Do we need to make a distinction between WS80211_CHAN_NO_HT
            // and WS80211_CHAN_HT20? E.g. is there a driver that won't capture
            // HT frames if you use WS80211_CHAN_NO_HT?
            ui->channelTypeComboBox->addItem("20 MHz", WS80211_CHAN_NO_HT);
            if (iface_info.current_chan_type == WS80211_CHAN_NO_HT || iface_info.current_chan_type == WS80211_CHAN_HT20) {
                ui->channelTypeComboBox->setCurrentIndex(0);
            }
            if (iface->channel_types & (1 << WS80211_CHAN_HT40MINUS)) {
                ui->channelTypeComboBox->addItem("HT 40-", WS80211_CHAN_HT40MINUS);
                if (iface_info.current_chan_type == WS80211_CHAN_HT40MINUS) {
                    ui->channelTypeComboBox->setCurrentIndex(ui->channelTypeComboBox->count() - 1);
                }
            }
            if (iface->channel_types & (1 << WS80211_CHAN_HT40PLUS)) {
                ui->channelTypeComboBox->addItem("HT 40+", WS80211_CHAN_HT40PLUS);
                if (iface_info.current_chan_type == WS80211_CHAN_HT40PLUS) {
                    ui->channelTypeComboBox->setCurrentIndex(ui->channelTypeComboBox->count() - 1);
                }
            }
            if (iface->channel_types & (1 << WS80211_CHAN_VHT80)) {
                ui->channelTypeComboBox->addItem("VHT 80", WS80211_CHAN_VHT80);
                if (iface_info.current_chan_type == WS80211_CHAN_VHT80) {
                    ui->channelTypeComboBox->setCurrentIndex(ui->channelTypeComboBox->count() - 1);
                }
            }
            if (iface->channel_types & (1 << WS80211_CHAN_VHT160)) {
                ui->channelTypeComboBox->addItem("VHT 160", WS80211_CHAN_VHT160);
                if (iface_info.current_chan_type == WS80211_CHAN_VHT160) {
                    ui->channelTypeComboBox->setCurrentIndex(ui->channelTypeComboBox->count() - 1);
                }
            }

            if (ws80211_has_fcs_filter()) {
                ui->fcsComboBox->setCurrentIndex(iface_info.current_fcs_validation);
            }
        }
    }

    updateWidgets();
}

void WirelessFrame::setInterfaceInfo()
{
    QString cur_iface = ui->interfaceComboBox->currentText();
    int cur_chan_idx = ui->channelComboBox->currentIndex();
    int cur_type_idx = ui->channelTypeComboBox->currentIndex();
    int cur_fcs_idx = ui->fcsComboBox->currentIndex();

    if (cur_iface.isEmpty() || cur_chan_idx < 0 || cur_type_idx < 0) return;

    QString err_str;

#if defined(HAVE_LIBNL) && defined(HAVE_NL80211) && defined(HAVE_LIBPCAP)
    int frequency = ui->channelComboBox->itemData(cur_chan_idx).toInt();
    int chan_type = ui->channelTypeComboBox->itemData(cur_type_idx).toInt();
    int bandwidth = getBandwidthFromChanType(chan_type);
    int center_freq = getCenterFrequency(frequency, bandwidth);
    const char *chan_type_s = ws80211_chan_type_to_str(chan_type);
    char *center_freq_s = NULL;
    char *data, *primary_msg, *secondary_msg;
    int ret;

    if (frequency < 0 || chan_type < 0) return;

    if (center_freq != -1) {
        center_freq_s = qstring_strdup(QString::number(center_freq));
    }

    ret = sync_interface_set_80211_chan(cur_iface.toUtf8().constData(),
                                        QString::number(frequency).toUtf8().constData(), chan_type_s,
                                        center_freq_s, NULL,
                                        &data, &primary_msg, &secondary_msg, main_window_update);

    g_free(center_freq_s);
    g_free(data);
    g_free(primary_msg);
    g_free(secondary_msg);

    /* Parse the error msg */
    if (ret) {
        err_str = tr("Unable to set channel or offset.");
    }
#elif defined(HAVE_AIRPCAP)
    int frequency = ui->channelComboBox->itemData(cur_chan_idx).toInt();
    int chan_type = ui->channelTypeComboBox->itemData(cur_type_idx).toInt();
    if (frequency < 0 || chan_type < 0) return;

    if (ws80211_set_freq(cur_iface.toUtf8().constData(), frequency, chan_type, -1, -1) != 0) {
        err_str = tr("Unable to set channel or offset.");
    }
#endif

    if (cur_fcs_idx >= 0) {
        if (ws80211_set_fcs_validation(cur_iface.toUtf8().constData(), (enum ws80211_fcs_validation) cur_fcs_idx) != 0) {
            err_str = tr("Unable to set FCS validation behavior.");
        }
    }

    if (!err_str.isEmpty()) {
        mainApp->pushStatus(MainApplication::TemporaryStatus, err_str);
    }

    getInterfaceInfo();
}

int WirelessFrame::getCenterFrequency(int control_frequency, int bandwidth)
{
    if (bandwidth < 80 || control_frequency < 5180)
        return -1;

    return ((control_frequency - 5180) / bandwidth) * bandwidth + 5180 + (bandwidth / 2) - 10;
}

int WirelessFrame::getBandwidthFromChanType(int chan_type)
{
    switch (chan_type) {
    case WS80211_CHAN_VHT80:
        return 80;
    case WS80211_CHAN_VHT160:
        return 160;
    default:
        return -1;
    }
}

void WirelessFrame::on_interfaceComboBox_activated(int)
{
    getInterfaceInfo();
}

void WirelessFrame::on_channelComboBox_activated(int)
{
    setInterfaceInfo();
}

void WirelessFrame::on_channelTypeComboBox_activated(int)
{
    setInterfaceInfo();
}

void WirelessFrame::on_fcsComboBox_activated(int)
{
    setInterfaceInfo();
}
