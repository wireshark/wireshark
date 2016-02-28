/* wlan_statistics_dialog.cpp
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

#include "wlan_statistics_dialog.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tap.h>

#include <epan/dissectors/packet-ieee80211.h>

#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "percent_bar_delegate.h"
#include "qt_ui_utils.h"
#include "wireshark_application.h"

// To do:
// - Add the name resolution checkbox
// - Add the "Only show defined networks" checkbox

enum {
    col_bssid_,
    col_channel_,
    col_ssid_,
    col_pct_packets_,
    col_beacons_,
    col_data_packets_,
    col_probe_reqs_,
    col_probe_resps_,
    col_auths_,
    col_deauths_,
    col_others_,
    col_protection_
};

enum {
    wlan_network_row_type_ = 1000,
    wlan_station_row_type_
};

class WlanStationTreeWidgetItem : public QTreeWidgetItem
{
public:
    WlanStationTreeWidgetItem(address *addr) :
        QTreeWidgetItem (wlan_station_row_type_),
        packets_(0),
        sent_(0),
        received_(0),
        probe_req_(0),
        probe_resp_(0),
        auth_(0),
        deauth_(0),
        other_(0)
    {
        copy_address(&addr_, addr);
        setText(col_bssid_, address_to_qstring(&addr_));
    }
    bool isMatch(address *addr) {
        return addresses_equal(&addr_, addr);
    }
    void update(wlan_hdr_t *wlan_hdr) {
        bool is_sender = addresses_equal(&addr_, &wlan_hdr->src);

        // XXX Should we count received probes and auths? This is what the
        // GTK+ UI does, but it seems odd.
        switch (wlan_hdr->type) {
        case MGT_PROBE_REQ:
            probe_req_++;
            break;
        case MGT_PROBE_RESP:
            probe_resp_++;
            break;
        case MGT_BEACON:
            // Skip
            break;
        case MGT_AUTHENTICATION:
            auth_++;
            break;
        case MGT_DEAUTHENTICATION:
            deauth_++;
            break;
        case DATA:
        case DATA_CF_ACK:
        case DATA_CF_POLL:
        case DATA_CF_ACK_POLL:
        case DATA_QOS_DATA:
        case DATA_QOS_DATA_CF_ACK:
        case DATA_QOS_DATA_CF_POLL:
        case DATA_QOS_DATA_CF_ACK_POLL:
            if (is_sender) {
                sent_++;
            } else {
                received_++;
            }
            break;
        default:
            other_++;
            break;
        }
        if (wlan_hdr->type != MGT_BEACON) packets_++;
    }
    void draw(address *bssid, int num_packets) {
        setData(col_pct_packets_, Qt::UserRole, QVariant::fromValue<double>(packets_ * 100.0 / num_packets));
        setText(col_beacons_, QString::number(sent_));
        setText(col_data_packets_, QString::number(received_));
        setText(col_probe_reqs_, QString::number(probe_req_));
        setText(col_probe_resps_, QString::number(probe_resp_));
        setText(col_auths_, QString::number(auth_));
        setText(col_deauths_, QString::number(deauth_));
        setText(col_others_, QString::number(other_));

        if (!is_broadcast_bssid(bssid) && addresses_data_equal(&addr_, bssid)) {
            setText(col_protection_, QObject::tr("Base station"));
        }
    }
    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != wlan_station_row_type_) return QTreeWidgetItem::operator< (other);
        const WlanStationTreeWidgetItem *other_row = static_cast<const WlanStationTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case col_bssid_:
            return cmp_address(&addr_, &other_row->addr_) < 0;
        case col_pct_packets_:
            return packets_ < other_row->packets_;
        case col_beacons_:
            return sent_ < other_row->sent_;
        case col_data_packets_:
            return received_ < other_row->received_;
        case col_probe_reqs_:
            return probe_req_ < other_row->probe_req_;
        case col_probe_resps_:
            return probe_resp_ < other_row->probe_resp_;
        case col_auths_:
            return auth_ < other_row->auth_;
        case col_deauths_:
            return deauth_ < other_row->deauth_;
        case col_others_:
            return other_ < other_row->other_;
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }
    QList<QVariant> rowData() {
        return QList<QVariant>()
                << address_to_qstring(&addr_)
                << data(col_pct_packets_, Qt::UserRole).toDouble()
                << sent_ << received_ << probe_req_ << probe_resp_
                << auth_ << deauth_ << other_ << text(col_protection_);
    }
    const QString filterExpression() {
        QString filter_expr = QString("wlan.addr==%1")
                .arg(address_to_qstring(&addr_));
        return filter_expr;
    }

private:
    address addr_;
    int packets_;
    int sent_;
    int received_;
    int probe_req_;
    int probe_resp_;
    int auth_;
    int deauth_;
    int other_;
};

class WlanNetworkTreeWidgetItem : public QTreeWidgetItem
{
public:
    WlanNetworkTreeWidgetItem(QTreeWidget *parent, wlan_hdr_t *wlan_hdr) :
        QTreeWidgetItem (parent, wlan_network_row_type_),
        beacon_(0),
        data_packet_(0),
        probe_req_(0),
        probe_resp_(0),
        auth_(0),
        deauth_(0),
        other_(0),
        packets_(0)
    {
        updateBssid(wlan_hdr);
        channel_ = wlan_hdr->stats.channel;
        ssid_ = QByteArray::fromRawData((const char *)wlan_hdr->stats.ssid, wlan_hdr->stats.ssid_len);
        QString ssid_text;

        if (wlan_hdr->stats.ssid_len == 0) {
            ssid_text = QObject::tr("<Broadcast>");
        } else if (wlan_hdr->stats.ssid_len == 1 && wlan_hdr->stats.ssid[0] == 0) {
            ssid_text = QObject::tr("<Hidden>");
        } else {
            ssid_text = format_text(wlan_hdr->stats.ssid, wlan_hdr->stats.ssid_len);
        }

        setText(col_ssid_, ssid_text);
    }

    bool isMatch(wlan_hdr_t *wlan_hdr) {
        bool is_bssid_match = false;
        bool is_ssid_match = false;
        bool update_bssid = false;
        bool update_ssid = false;
        // We want (but might not have) a unicast BSSID and a named SSID. Try
        // to match the current packet and update our information if possible.

        if (addresses_equal(&bssid_, &wlan_hdr->bssid)) {
            is_bssid_match = true;
        }

        if ((wlan_hdr->stats.ssid_len > 0) && (wlan_hdr->stats.ssid[0] != 0)) {
            QByteArray hdr_ssid = QByteArray::fromRawData((const char *)wlan_hdr->stats.ssid, wlan_hdr->stats.ssid_len);
            if (ssid_ == hdr_ssid) {
                is_ssid_match = true;
            }
        }

        if (is_bssid_match && is_ssid_match) return true;

        // Probe requests.
        if (wlan_hdr->type == MGT_PROBE_REQ) {
            // Probes with visible SSIDs. Unicast or broadcast.
            if (is_ssid_match) {
                if (is_broadcast_ && !is_broadcast_bssid(&wlan_hdr->bssid)) {
                    update_bssid = true;
                }
            // Probes with hidden SSIDs. Unicast.
            } else if ((wlan_hdr->stats.ssid_len == 1) && (wlan_hdr->stats.ssid[0] == 0)) {
                if (!is_broadcast_ && addresses_equal(&bssid_, &wlan_hdr->bssid)) {
                    is_bssid_match = true;
                    update_ssid = true;
                }
            // Probes with no SSID. Broadcast.
            } else if (ssid_.isEmpty() && wlan_hdr->stats.ssid_len < 1) {
                if (is_broadcast_ && is_broadcast_bssid(&wlan_hdr->bssid)) {
                    return true;
                }
            }
        // Non-probe requests (responses, beacons, etc)
        } else {
            if (is_ssid_match) {
                if (is_broadcast_ && !is_broadcast_bssid(&wlan_hdr->bssid)) {
                    update_bssid = true;
                }
            } else if (wlan_hdr->stats.ssid_len < 1) {
                // No SSID.
                is_ssid_match = true;
            }
            if (is_bssid_match) {
                if ((ssid_.isEmpty() || ssid_[0] == '\0') && (wlan_hdr->stats.ssid_len > 0) && (wlan_hdr->stats.ssid[0] != 0)) {
                    update_ssid = true;
                }
            }
        }

        if (update_bssid) {
            updateBssid(wlan_hdr);
            is_bssid_match = true;
        }

        if (update_ssid) {
            ssid_ = QByteArray::fromRawData((const char *)wlan_hdr->stats.ssid, wlan_hdr->stats.ssid_len);
            setText(col_ssid_, format_text(wlan_hdr->stats.ssid, wlan_hdr->stats.ssid_len));
            is_ssid_match = true;
        }

        return is_bssid_match && is_ssid_match;
    }

    void update(wlan_hdr_t *wlan_hdr) {
        if (channel_ == 0 && wlan_hdr->stats.channel != 0) {
            channel_ = wlan_hdr->stats.channel;
        }
        if (text(col_protection_).isEmpty() && wlan_hdr->stats.protection[0] != 0) {
            setText(col_protection_, wlan_hdr->stats.protection);
        }
        switch (wlan_hdr->type) {
        case MGT_PROBE_REQ:
            probe_req_++;
            break;
        case MGT_PROBE_RESP:
            probe_resp_++;
            break;
        case MGT_BEACON:
            beacon_++;
            break;
        case MGT_AUTHENTICATION:
            auth_++;
            break;
        case MGT_DEAUTHENTICATION:
            deauth_++;
            break;
        case DATA:
        case DATA_CF_ACK:
        case DATA_CF_POLL:
        case DATA_CF_ACK_POLL:
        case DATA_QOS_DATA:
        case DATA_QOS_DATA_CF_ACK:
        case DATA_QOS_DATA_CF_POLL:
        case DATA_QOS_DATA_CF_ACK_POLL:
            data_packet_++;
            break;
        default:
            other_++;
            break;
        }
        packets_++;

        WlanStationTreeWidgetItem* sender_ws_ti = NULL;
        WlanStationTreeWidgetItem* receiver_ws_ti = NULL;
        foreach (QTreeWidgetItem *cur_ti, stations_) {
            WlanStationTreeWidgetItem *cur_ws_ti = dynamic_cast<WlanStationTreeWidgetItem *>(cur_ti);
            if (cur_ws_ti->isMatch(&wlan_hdr->src)) sender_ws_ti = cur_ws_ti;
            if (cur_ws_ti->isMatch(&wlan_hdr->dst)) receiver_ws_ti = cur_ws_ti;
            if (sender_ws_ti && receiver_ws_ti) break;
        }
        if (!sender_ws_ti) {
            sender_ws_ti = new WlanStationTreeWidgetItem(&wlan_hdr->src);
            stations_ << sender_ws_ti;
        }
        if (!receiver_ws_ti) {
            receiver_ws_ti = new WlanStationTreeWidgetItem(&wlan_hdr->dst);
            stations_ << receiver_ws_ti;
        }
        sender_ws_ti->update(wlan_hdr);
        receiver_ws_ti->update(wlan_hdr);
    }

    void draw(int num_packets) {
        if (channel_ > 0) setText(col_channel_, QString::number(channel_));
        setData(col_pct_packets_, Qt::UserRole, QVariant::fromValue<double>(packets_ * 100.0 / num_packets));
        setText(col_beacons_, QString::number(beacon_));
        setText(col_data_packets_, QString::number(data_packet_));
        setText(col_probe_reqs_, QString::number(probe_req_));
        setText(col_probe_resps_, QString::number(probe_resp_));
        setText(col_auths_, QString::number(auth_));
        setText(col_deauths_, QString::number(deauth_));
        setText(col_others_, QString::number(other_));
    }

    void addStations() {
        foreach (QTreeWidgetItem *cur_ti, stations_) {
            WlanStationTreeWidgetItem *cur_ws_ti = dynamic_cast<WlanStationTreeWidgetItem *>(cur_ti);
            cur_ws_ti->draw(&bssid_, packets_ - beacon_);
            for (int col = 0; col < treeWidget()->columnCount(); col++) {
                cur_ws_ti->setTextAlignment(col, treeWidget()->headerItem()->textAlignment(col));
            }
        }

        addChildren(stations_);
        stations_.clear();
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != wlan_network_row_type_) return QTreeWidgetItem::operator< (other);
        const WlanNetworkTreeWidgetItem *other_row = static_cast<const WlanNetworkTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case col_bssid_:
            return cmp_address(&bssid_, &other_row->bssid_) < 0;
        case col_channel_:
            return channel_ < other_row->channel_;
        case col_ssid_:
            return ssid_ < other_row->ssid_;
        case col_pct_packets_:
            return packets_ < other_row->packets_;
        case col_beacons_:
            return beacon_ < other_row->beacon_;
        case col_data_packets_:
            return data_packet_ < other_row->data_packet_;
        case col_probe_reqs_:
            return probe_req_ < other_row->probe_req_;
        case col_probe_resps_:
            return probe_resp_ < other_row->probe_resp_;
        case col_auths_:
            return auth_ < other_row->auth_;
        case col_deauths_:
            return deauth_ < other_row->deauth_;
        case col_others_:
            return other_ < other_row->other_;
        case col_protection_:
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }
    QList<QVariant> rowData() {
        return QList<QVariant>()
                << address_to_qstring(&bssid_) << channel_ << text(col_ssid_)
                << data(col_pct_packets_, Qt::UserRole).toDouble()
                << beacon_ << data_packet_ << probe_req_ << probe_resp_
                << auth_ << deauth_ << other_ << text(col_protection_);
    }

    const QString filterExpression() {
        QString filter_expr = QString("(wlan.bssid==%1")
                .arg(address_to_qstring(&bssid_));
        if (!ssid_.isEmpty() && ssid_[0] != '\0') {
            filter_expr += QString(" || wlan_mgt.ssid==\"%1\"")
                    .arg(ssid_.constData());
        }
        filter_expr += ")";
        return filter_expr;
    }

private:
    address bssid_;
    bool is_broadcast_;
    int channel_;
    QByteArray ssid_;
    int beacon_;
    int data_packet_;
    int probe_req_;
    int probe_resp_;
    int auth_;
    int deauth_;
    int other_;
    int packets_;

    // Adding items one at a time is slow. Gather up the stations in a list
    // and add them all at once later.
    QList<QTreeWidgetItem *>stations_;

    void updateBssid(wlan_hdr_t *wlan_hdr) {
        copy_address(&bssid_, &wlan_hdr->bssid);
        is_broadcast_ = is_broadcast_bssid(&bssid_);
        setText(col_bssid_, address_to_qstring(&bssid_));
    }
};

static const QString network_col_0_title_ = QObject::tr("BSSID");
static const QString network_col_4_title_ = QObject::tr("Beacons");
static const QString network_col_5_title_ = QObject::tr("Data Pkts");
static const QString network_col_11_title_ = QObject::tr("Protection");

static const QString node_col_0_title_ = QObject::tr("Address");
static const QString node_col_4_title_ = QObject::tr("Pkts Sent");
static const QString node_col_5_title_ = QObject::tr("Pkts Received");
static const QString node_col_11_title_ = QObject::tr("Comment");

WlanStatisticsDialog::WlanStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter) :
    TapParameterDialog(parent, cf, HELP_STATS_WLAN_TRAFFIC_DIALOG),
    packet_count_(0)
{
    setWindowSubtitle(tr("Wireless LAN Statistics"));
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4, "WlanStatisticsDialog");

    QStringList header_labels = QStringList()
            << "" << tr("Channel") << tr("SSID") << tr("Percent Packets") << "" << ""
            << tr("Probe Reqs") << tr("Probe Resp") << tr("Auths")
            << tr("Deauths") << tr("Other");
    statsTreeWidget()->setHeaderLabels(header_labels);
    updateHeaderLabels();
    statsTreeWidget()->setItemDelegateForColumn(col_pct_packets_, new PercentBarDelegate());
    statsTreeWidget()->sortByColumn(col_bssid_, Qt::AscendingOrder);

    // resizeColumnToContents doesn't work well here, so set sizes manually.
    int one_em = fontMetrics().height();
    for (int col = 0; col < statsTreeWidget()->columnCount() - 1; col++) {
        switch (col) {
        case col_bssid_:
            statsTreeWidget()->setColumnWidth(col, one_em * 11);
            break;
        case col_ssid_:
            statsTreeWidget()->setColumnWidth(col, one_em * 8);
            break;
        case col_pct_packets_:
        case col_protection_:
            statsTreeWidget()->setColumnWidth(col, one_em * 6);
            break;
        default:
            // The rest are numeric
            statsTreeWidget()->setColumnWidth(col, one_em * 4);
            statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
            break;
        }
    }

    addFilterActions();

    if (filter) {
        setDisplayFilter(filter);
    }

    connect(statsTreeWidget(), SIGNAL(itemSelectionChanged()),
            this, SLOT(updateHeaderLabels()));
}

WlanStatisticsDialog::~WlanStatisticsDialog()
{
}

void WlanStatisticsDialog::tapReset(void *ws_dlg_ptr)
{
    WlanStatisticsDialog *ws_dlg = static_cast<WlanStatisticsDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    ws_dlg->statsTreeWidget()->clear();
    ws_dlg->packet_count_ = 0;
}

gboolean WlanStatisticsDialog::tapPacket(void *ws_dlg_ptr, _packet_info *, epan_dissect *, const void *wlan_hdr_ptr)
{
    WlanStatisticsDialog *ws_dlg = static_cast<WlanStatisticsDialog *>(ws_dlg_ptr);
    wlan_hdr_t *wlan_hdr  = (wlan_hdr_t *)wlan_hdr_ptr;
    if (!ws_dlg || !wlan_hdr) return FALSE;

    guint16 frame_type = wlan_hdr->type & 0xff0;
    if (!((frame_type == 0x0) || (frame_type == 0x20) || (frame_type == 0x30))
        || ((frame_type == 0x20) && DATA_FRAME_IS_NULL(wlan_hdr->type))) {
        /* Not a management or non null data or extension frame; let's skip it */
        return FALSE;
    }

    ws_dlg->packet_count_++;

    WlanNetworkTreeWidgetItem *wn_ti = NULL;
    for (int i = 0; i < ws_dlg->statsTreeWidget()->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ws_dlg->statsTreeWidget()->topLevelItem(i);
        if (ti->type() != wlan_network_row_type_) continue;
        WlanNetworkTreeWidgetItem *cur_wn_ti = static_cast<WlanNetworkTreeWidgetItem*>(ti);

        if (cur_wn_ti->isMatch(wlan_hdr)) {
            wn_ti = cur_wn_ti;
            break;
        }
    }

    if (!wn_ti) {
        wn_ti = new WlanNetworkTreeWidgetItem(ws_dlg->statsTreeWidget(), wlan_hdr);
        for (int col = 0; col < ws_dlg->statsTreeWidget()->columnCount(); col++) {
            wn_ti->setTextAlignment(col, ws_dlg->statsTreeWidget()->headerItem()->textAlignment(col));
        }
    }

    wn_ti->update(wlan_hdr);
    return TRUE;
}

void WlanStatisticsDialog::tapDraw(void *ws_dlg_ptr)
{
    WlanStatisticsDialog *ws_dlg = static_cast<WlanStatisticsDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    for (int i = 0; i < ws_dlg->statsTreeWidget()->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ws_dlg->statsTreeWidget()->topLevelItem(i);
        if (ti->type() != wlan_network_row_type_) continue;

        WlanNetworkTreeWidgetItem *wn_ti = static_cast<WlanNetworkTreeWidgetItem*>(ti);
        wn_ti->draw(ws_dlg->packet_count_);
    }
}

const QString WlanStatisticsDialog::filterExpression()
{
    QString filter_expr;
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];

        if (ti->type() == wlan_network_row_type_) {
            WlanNetworkTreeWidgetItem *wn_ti = static_cast<WlanNetworkTreeWidgetItem*>(ti);
            filter_expr = wn_ti->filterExpression();
        } else if (ti->type() == wlan_station_row_type_) {
            WlanStationTreeWidgetItem *ws_ti = static_cast<WlanStationTreeWidgetItem*>(ti);
            filter_expr = ws_ti->filterExpression();
        }
    }
    return filter_expr;
}

void WlanStatisticsDialog::fillTree()
{
    if (!registerTapListener("wlan",
                             this,
                             NULL,
                             TL_REQUIRES_NOTHING,
                             tapReset,
                             tapPacket,
                             tapDraw)) {
        reject();
        return;
    }

    cap_file_.retapPackets();
    tapDraw(this);
    removeTapListeners();

    for (int i = 0; i < statsTreeWidget()->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = statsTreeWidget()->topLevelItem(i);
        if (ti->type() != wlan_network_row_type_) continue;

        WlanNetworkTreeWidgetItem *wn_ti = static_cast<WlanNetworkTreeWidgetItem*>(ti);
        wn_ti->addStations();
    }
}

void WlanStatisticsDialog::updateHeaderLabels()
{
    if (statsTreeWidget()->selectedItems().count() > 0 && statsTreeWidget()->selectedItems()[0]->type() == wlan_station_row_type_) {
        statsTreeWidget()->headerItem()->setText(col_bssid_, node_col_0_title_);
        statsTreeWidget()->headerItem()->setText(col_beacons_, node_col_4_title_);
        statsTreeWidget()->headerItem()->setText(col_data_packets_, node_col_5_title_);
        statsTreeWidget()->headerItem()->setText(col_protection_, node_col_11_title_);
    } else {
        statsTreeWidget()->headerItem()->setText(col_bssid_, network_col_0_title_);
        statsTreeWidget()->headerItem()->setText(col_beacons_, network_col_4_title_);
        statsTreeWidget()->headerItem()->setText(col_data_packets_, network_col_5_title_);
        statsTreeWidget()->headerItem()->setText(col_protection_, network_col_11_title_);
    }
}

void WlanStatisticsDialog::captureFileClosing()
{
    remove_tap_listener(this);
    updateWidgets();

    WiresharkDialog::captureFileClosing();
}

// Stat command + args

static void
wlan_statistics_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    QByteArray filter;
    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    wsApp->emitStatCommandSignal("WlanStatistics", filter.constData(), NULL);
}

static stat_tap_ui wlan_statistics_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "wlan,stat",
    wlan_statistics_init,
    0,
    NULL
};

extern "C" {
void
register_tap_listener_qt_wlan_statistics(void)
{
    register_stat_tap_ui(&wlan_statistics_ui, NULL);
}
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
