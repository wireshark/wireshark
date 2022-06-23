/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>

#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/maxmind_db.h>
#include <epan/addr_resolv.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/nstime.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/main_application.h>
#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/models/timeline_delegate.h>

#include <QSize>
#include <QVariant>
#include <QWidget>
#include <QDateTime>

static QString formatString(qlonglong value)
{
    return QLocale::system().formattedDataSize(value, QLocale::DataSizeSIFormat);
}

ATapDataModel::ATapDataModel(dataModelType type, int protoId, QString filter, QObject *parent):
    QAbstractListModel(parent)
{
    hash_.conv_array = nullptr;
    hash_.hashtable = nullptr;
    hash_.user_data = this;

    storage_ = nullptr;
    _resolveNames = false;
    _absoluteTime = false;
    _nanoseconds = false;

    _protoId = protoId;
    _filter = filter;

    _minRelStartTime = 0;
    _maxRelStopTime = 0;

    _type = type;
    _disableTap = true;

    QString _tap(proto_get_protocol_filter_name(protoId));
}

ATapDataModel::~ATapDataModel()
{
    remove_tap_listener(hash());
}

int ATapDataModel::protoId() const
{
    return _protoId;
}

QString ATapDataModel::tap() const
{
    return proto_get_protocol_filter_name(_protoId);
}

#ifdef HAVE_MAXMINDDB
bool ATapDataModel::hasGeoIPData()
{
    bool coordsFound = false;
    int row = 0;
    int count = rowCount();
    while (!coordsFound && row < count)
    {
        QModelIndex idx = index(row, 0);
        if (_type == ATapDataModel::DATAMODEL_ENDPOINT)
            coordsFound = qobject_cast<EndpointDataModel *>(this)->data(idx, ATapDataModel::GEODATA_AVAILABLE).toBool();
        else if (_type == ATapDataModel::DATAMODEL_CONVERSATION)
            coordsFound = qobject_cast<ConversationDataModel *>(this)->data(idx, ATapDataModel::GEODATA_AVAILABLE).toBool();
        row++;
    }

    return coordsFound;
}
#endif

bool ATapDataModel::enableTap()
{
    /* We can't reenable a tap, so just return */
    if (! _disableTap)
        return true;

    _disableTap = false;

    /* The errorString is ignored. If this is not working, there is nothing really the user may do about
     * it, so the error is only interesting to the developer.*/
    GString * errorString = register_tap_listener(tap().toUtf8().constData(), hash(), _filter.toUtf8().constData(),
        TL_IGNORE_DISPLAY_FILTER, &ATapDataModel::tapReset, conversationPacketHandler(), &ATapDataModel::tapDraw, nullptr);
    if (errorString && errorString->len > 0) {
        _disableTap = true;
        emit tapListenerChanged(false);
        return false;
    }

    if (errorString)
        g_string_free(errorString, TRUE);

    emit tapListenerChanged(true);

    return true;
}

void ATapDataModel::disableTap()
{
    /* Only remove the tap if we come from a enabled model */
    if (!_disableTap)
        remove_tap_listener(hash());
    _disableTap = true;
    emit tapListenerChanged(false);
}

int ATapDataModel::rowCount(const QModelIndex &) const
{
    return storage_ ? (int) storage_->len : 0;
}

void ATapDataModel::tapReset(void *tapdata) {
    if (! tapdata)
        return;

    conv_hash_t *hash = (conv_hash_t*)tapdata;
    ATapDataModel * dataModel = qobject_cast<ATapDataModel *>((ATapDataModel *)hash->user_data);

    dataModel->resetData();
}

void ATapDataModel::tapDraw(void *tapdata)
{
    if (! tapdata)
        return;

    conv_hash_t *hash = (conv_hash_t*)tapdata;
    ATapDataModel * dataModel = qobject_cast<ATapDataModel *>((ATapDataModel *)hash->user_data);

    dataModel->updateData(hash->conv_array);
}

conv_hash_t * ATapDataModel::hash()
{
    return &hash_;
}

register_ct_t * ATapDataModel::registerTable() const
{
    if (_protoId > -1)
        return get_conversation_by_proto_id(_protoId);

    return nullptr;
}

tap_packet_cb ATapDataModel::conversationPacketHandler()
{
    register_ct_t* table = registerTable();
    if (table) {
        if (_type == ATapDataModel::DATAMODEL_ENDPOINT)
            return get_hostlist_packet_func(table);
        else if (_type == ATapDataModel::DATAMODEL_CONVERSATION)
            return get_conversation_packet_func(table);
    }

    return nullptr;
}

void ATapDataModel::resetData()
{
    if (_disableTap)
        return;

    beginResetModel();
    storage_ = nullptr;
    if (_type == ATapDataModel::DATAMODEL_ENDPOINT)
        reset_hostlist_table_data(&hash_);
    else if (_type == ATapDataModel::DATAMODEL_CONVERSATION)
        reset_conversation_table_data(&hash_);

    _minRelStartTime = 0;
    _maxRelStopTime = 0;

    endResetModel();
}

void ATapDataModel::updateData(GArray * newData)
{
    if (_disableTap)
        return;

    beginResetModel();
    storage_ = newData;
    endResetModel();

    if (_type == ATapDataModel::DATAMODEL_CONVERSATION)
        ((ConversationDataModel *)(this))->doDataUpdate();
}

bool ATapDataModel::resolveNames() const
{
    return _resolveNames;
}

void ATapDataModel::setResolveNames(bool resolve)
{
    if (_resolveNames == resolve)
        return;

    beginResetModel();
    _resolveNames = resolve;
    endResetModel();
}

bool ATapDataModel::allowsNameResolution() const
{
    if (_protoId < 0)
        return false;

    QStringList mac_protos = QStringList() << "eth" << "tr"<< "wlan";
    QStringList net_protos = QStringList() << "ip" << "ipv6" << "jxta"
                                           << "mptcp" << "rsvp" << "sctp"
                                           << "tcp" << "udp";

    QString table_proto = proto_get_protocol_filter_name(_protoId);

    if (mac_protos.contains(table_proto) && gbl_resolv_flags.mac_name)
        return true;
    if (net_protos.contains(table_proto) && gbl_resolv_flags.network_name)
        return true;

    return false;
}

void ATapDataModel::useAbsoluteTime(bool absolute)
{
    if (absolute == _absoluteTime)
        return;

    beginResetModel();
    _absoluteTime = absolute;
    endResetModel();
}

void ATapDataModel::useNanosecondTimestamps(bool nanoseconds)
{
    if (_nanoseconds == nanoseconds)
        return;

    beginResetModel();
    _nanoseconds = nanoseconds;
    endResetModel();
}

void ATapDataModel::setFilter(QString filter)
{
    if (_disableTap)
        return;

    _filter = filter;
    GString * errorString = set_tap_dfilter(&hash_, !_filter.isEmpty() ? _filter.toUtf8().constData() : nullptr);
    if (errorString && errorString->len > 0) {
        /* If this fails, chances are that the main system failed as well. Silently exiting as the
         * user cannot react to it */
        disableTap();
    }

    if (errorString)
        g_string_free(errorString, TRUE);
}

QString ATapDataModel::filter() const
{
    return _filter;
}

ATapDataModel::dataModelType ATapDataModel::modelType() const
{
    return _type;
}

bool ATapDataModel::portsAreHidden() const
{
    return (get_conversation_hide_ports(registerTable()));
}

bool ATapDataModel::showTotalColumn() const
{
    /* Implemented to ensure future changes may be done more easily */
    return _filter.length() > 0;
}

EndpointDataModel::EndpointDataModel(int protoId, QString filter, QObject *parent) :
    ATapDataModel(ATapDataModel::DATAMODEL_ENDPOINT, protoId, filter, parent)
{}

int EndpointDataModel::columnCount(const QModelIndex &) const
{
    return ENDP_NUM_COLUMNS;
}

QVariant EndpointDataModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Vertical)
        return QVariant();

    if (role == Qt::DisplayRole) {
        switch (section) {
            case ENDP_COLUMN_ADDR:
                return tr("Address"); break;
            case ENDP_COLUMN_PORT:
                return tr("Port"); break;
            case ENDP_COLUMN_PACKETS:
                return tr("Packets"); break;
            case ENDP_COLUMN_BYTES:
                return tr("Bytes"); break;
            case ENDP_COLUMN_PACKETS_TOTAL:
                return tr("Total Packets"); break;
            case ENDP_COLUMN_BYTES_TOTAL:
                return tr("Percent Filtered"); break;
            case ENDP_COLUMN_PKT_AB:
                return tr("Tx Packets"); break;
            case ENDP_COLUMN_BYTES_AB:
                return tr("Tx Bytes"); break;
            case ENDP_COLUMN_PKT_BA:
                return tr("Rx Packets"); break;
            case ENDP_COLUMN_BYTES_BA:
                return tr("Rx Bytes"); break;
            case ENDP_COLUMN_GEO_COUNTRY:
                return tr("Country"); break;
            case ENDP_COLUMN_GEO_CITY:
                return tr("City"); break;
            case ENDP_COLUMN_GEO_AS_NUM:
                return tr("AS Number"); break;
            case ENDP_COLUMN_GEO_AS_ORG:
                return tr("AS Organization"); break;
        }
    } else if (role == Qt::TextAlignmentRole) {
        if (section == ENDP_COLUMN_ADDR)
            return Qt::AlignLeft;
        return Qt::AlignRight;
    }

    return QVariant();
}

QVariant EndpointDataModel::data(const QModelIndex &idx, int role) const
{
    if (! idx.isValid())
        return QVariant();

    // Column text cooked representation.
    hostlist_talker_t *item = &g_array_index(storage_, hostlist_talker_t, idx.row());
    const mmdb_lookup_t *mmdb_lookup = nullptr;
#ifdef HAVE_MAXMINDDB
    char addr[WS_INET6_ADDRSTRLEN];
    if (item->myaddress.type == AT_IPv4) {
        const ws_in4_addr * ip4 = (const ws_in4_addr *) item->myaddress.data;
        mmdb_lookup = maxmind_db_lookup_ipv4(ip4);
        ws_inet_ntop4(ip4, addr, sizeof(addr));
    } else if (item->myaddress.type == AT_IPv6) {
        const ws_in6_addr * ip6 = (const ws_in6_addr *) item->myaddress.data;
        mmdb_lookup = maxmind_db_lookup_ipv6(ip6);
        ws_inet_ntop6(ip6, addr, sizeof(addr));
    }
    QString ipAddress(addr);
#endif

    if (role == Qt::DisplayRole || role == ATapDataModel::UNFORMATTED_DISPLAYDATA) {
        switch (idx.column()) {
        case ENDP_COLUMN_ADDR: {
            char* addr_str = get_conversation_address(NULL, &item->myaddress, _resolveNames);
            QString q_addr_str(addr_str);
            wmem_free(NULL, addr_str);
            return q_addr_str;
        }
        case ENDP_COLUMN_PORT:
            if (_resolveNames) {
                char* port_str = get_conversation_port(NULL, item->port, item->etype, _resolveNames);
                QString q_port_str(port_str);
                wmem_free(NULL, port_str);
                return q_port_str;
            } else {
                return quint32(item->port);
            }
        case ENDP_COLUMN_PACKETS:
        {
            qlonglong packets = (qlonglong)(item->tx_frames + item->rx_frames);
            return role == Qt::DisplayRole ? formatString(packets) : (QVariant)packets;
        }
        case ENDP_COLUMN_BYTES:
            return role == Qt::DisplayRole ? formatString((qlonglong)(item->tx_bytes + item->rx_bytes)) :
                QVariant((qlonglong)(item->tx_bytes + item->rx_bytes));
        case ENDP_COLUMN_PACKETS_TOTAL:
        {
            qlonglong packets = 0;
            if (showTotalColumn())
                packets = item->tx_frames_total + item->rx_frames_total;
            return role == Qt::DisplayRole ? QString("%L1").arg(packets) : (QVariant)packets;
        }
        case ENDP_COLUMN_BYTES_TOTAL:
        {
            double percent = 0;
            if (showTotalColumn()) {
                qlonglong totalPackets = (qlonglong)(item->tx_frames_total + item->rx_frames_total);
                qlonglong packets = (qlonglong)(item->tx_frames + item->rx_frames);
                percent = totalPackets == 0 ? 0 : (double) packets * 100 / (double) totalPackets;
                return QString::number(percent, 'f', 2) + "%";
            }
            return role == Qt::DisplayRole ? QString::number(percent, 'f', 2) + "%" : (QVariant)percent;
        }
        case ENDP_COLUMN_PKT_AB:
            return role == Qt::DisplayRole ? formatString((qlonglong)item->tx_frames) : QVariant((qlonglong) item->tx_frames);
        case ENDP_COLUMN_BYTES_AB:
            return role == Qt::DisplayRole ? formatString((qlonglong)item->tx_bytes) : QVariant((qlonglong)item->tx_bytes);
        case ENDP_COLUMN_PKT_BA:
            return role == Qt::DisplayRole ? formatString((qlonglong)item->rx_frames) : QVariant((qlonglong) item->rx_frames);
        case ENDP_COLUMN_BYTES_BA:
            return role == Qt::DisplayRole ? formatString((qlonglong)item->rx_bytes) : QVariant((qlonglong)item->rx_bytes);
        case ENDP_COLUMN_GEO_COUNTRY:
            if (mmdb_lookup && mmdb_lookup->found && mmdb_lookup->country) {
                return QVariant(mmdb_lookup->country);
            }
            return QVariant();
        case ENDP_COLUMN_GEO_CITY:
            if (mmdb_lookup && mmdb_lookup->found && mmdb_lookup->city) {
                return QVariant(mmdb_lookup->city);
            }
            return QVariant();
        case ENDP_COLUMN_GEO_AS_NUM:
            if (mmdb_lookup && mmdb_lookup->found && mmdb_lookup->as_number) {
                return QVariant(mmdb_lookup->as_number);
            }
            return QVariant();
        case ENDP_COLUMN_GEO_AS_ORG:
            if (mmdb_lookup && mmdb_lookup->found && mmdb_lookup->as_org) {
                return QVariant(mmdb_lookup->as_org);
            }
            return QVariant();
        default:
            return QVariant();
        }
    } else if (role == Qt::TextAlignmentRole) {
        if (idx.column() == ENDP_COLUMN_ADDR)
            return Qt::AlignLeft;
        return Qt::AlignRight;
    } else if (role == ATapDataModel::DISPLAY_FILTER) {
        return QString(get_hostlist_filter(item));
    } else if (role == ATapDataModel::ROW_IS_FILTERED) {
        return (bool)item->filtered && showTotalColumn();
    }
#ifdef HAVE_MAXMINDDB
    else if (role == ATapDataModel::GEODATA_AVAILABLE) {
        return (bool)(mmdb_lookup && maxmind_db_has_coords(mmdb_lookup));
    } else if (role == ATapDataModel::GEODATA_LOOKUPTABLE) {
        return VariantPointer<const mmdb_lookup_t>::asQVariant(mmdb_lookup);
    } else if (role == ATapDataModel::GEODATA_ADDRESS) {
        return ipAddress;
    }
#endif
    else if (role == ATapDataModel::DATA_ADDRESS_TYPE) {
        if (idx.column() == EndpointDataModel::ENDP_COLUMN_ADDR)
            return (int)item->myaddress.type;
        return (int) AT_NONE;
    } else if (role == ATapDataModel::DATA_IPV4_INTEGER || role == ATapDataModel::DATA_IPV6_LIST) {
        if (idx.column() == EndpointDataModel::ENDP_COLUMN_ADDR) {
            if (role == ATapDataModel::DATA_IPV4_INTEGER && item->myaddress.type == AT_IPv4) {
                const ws_in4_addr * ip4 = (const ws_in4_addr *) item->myaddress.data;
                return (quint32) GUINT32_FROM_BE(*ip4);
            }
            else if (role == ATapDataModel::DATA_IPV6_LIST && item->myaddress.type == AT_IPv6) {
                const ws_in6_addr * ip6 = (const ws_in6_addr *) item->myaddress.data;
                QList<quint8> result;
                result.reserve(16);
                std::copy(ip6->bytes + 0, ip6->bytes + 16, std::back_inserter(result));
                return QVariant::fromValue(result);
            }
        }
    }

    return QVariant();
}

ConversationDataModel::ConversationDataModel(int protoId, QString filter, QObject *parent) :
    ATapDataModel(ATapDataModel::DATAMODEL_CONVERSATION, protoId, filter, parent)
{}

void ConversationDataModel::doDataUpdate()
{
    _minRelStartTime = 0;
    _maxRelStopTime = 0;

    for (int row = 0; row < rowCount(); row ++) {
        conv_item_t *conv_item = &g_array_index(storage_, conv_item_t, row);

        if (row == 0) {
            _minRelStartTime = nstime_to_sec(&(conv_item->start_time));
            _maxRelStopTime = nstime_to_sec(&(conv_item->stop_time));
        } else {
            double item_rel_start = nstime_to_sec(&(conv_item->start_time));
            if (item_rel_start < _minRelStartTime) {
                _minRelStartTime = item_rel_start;
            }

            double item_rel_stop = nstime_to_sec(&(conv_item->stop_time));
            if (item_rel_stop > _maxRelStopTime) {
                _maxRelStopTime = item_rel_stop;
            }
        }
    }
}

int ConversationDataModel::columnCount(const QModelIndex &) const
{
    return CONV_NUM_COLUMNS;
}

QVariant ConversationDataModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Vertical)
        return QVariant();

    if (role == Qt::DisplayRole) {
        switch (section) {
        case CONV_COLUMN_SRC_ADDR:
            return tr("Address A"); break;
        case CONV_COLUMN_SRC_PORT:
            return tr("Port A"); break;
        case CONV_COLUMN_DST_ADDR:
            return tr("Address B"); break;
        case CONV_COLUMN_DST_PORT:
            return tr("Port B"); break;
        case CONV_COLUMN_PACKETS:
            return tr("Packets"); break;
        case CONV_COLUMN_BYTES:
            return tr("Bytes"); break;
        case CONV_COLUMN_CONV_ID:
            return tr("Stream ID"); break;
        case CONV_COLUMN_PACKETS_TOTAL:
            return tr("Total Packets"); break;
        case CONV_COLUMN_BYTES_TOTAL:
            return tr("Percent Filtered"); break;
        case CONV_COLUMN_PKT_AB:
            return tr("Packets A " UTF8_RIGHTWARDS_ARROW " B"); break;
        case CONV_COLUMN_BYTES_AB:
            return tr("Bytes A " UTF8_RIGHTWARDS_ARROW " B"); break;
        case CONV_COLUMN_PKT_BA:
            return tr("Packets A " UTF8_RIGHTWARDS_ARROW " B"); break;
        case CONV_COLUMN_BYTES_BA:
            return tr("Bytes B " UTF8_RIGHTWARDS_ARROW " A"); break;
        case CONV_COLUMN_START:
            return _absoluteTime ? tr("Abs Start") : tr("Rel Start"); break;
        case CONV_COLUMN_DURATION:
            return tr("Duration"); break;
        case CONV_COLUMN_BPS_AB:
            return tr("Bits/s A " UTF8_RIGHTWARDS_ARROW " B"); break;
        case CONV_COLUMN_BPS_BA:
            return tr("Bits/s B " UTF8_RIGHTWARDS_ARROW " A"); break;
        }
    } else if (role == Qt::TextAlignmentRole) {
        if (section == CONV_COLUMN_SRC_ADDR || section == CONV_COLUMN_DST_ADDR)
            return Qt::AlignLeft;
        return Qt::AlignRight;
    }

    return QVariant();
}

static const double min_bw_calc_duration_ = 5 / 1000.0; // seconds

QVariant ConversationDataModel::data(const QModelIndex &idx, int role) const
{
    if (! idx.isValid())
        return QVariant();

    // Column text cooked representation.
    conv_item_t *conv_item = (conv_item_t *)&g_array_index(storage_, conv_item_t,idx.row());

    double duration = nstime_to_sec(&conv_item->stop_time) - nstime_to_sec(&conv_item->start_time);
    double bps_ab = 0, bps_ba = 0;
    bool bpsCalculated = false;
    if (duration > min_bw_calc_duration_) {
        bps_ab = conv_item->tx_bytes * 8 / duration;
        bps_ba = conv_item->rx_bytes * 8 / duration;
        bpsCalculated = true;
    }

    if (role == Qt::DisplayRole || role == ATapDataModel::UNFORMATTED_DISPLAYDATA) {
        switch(idx.column()) {
        case CONV_COLUMN_SRC_ADDR:
            {
            char* addr_str = get_conversation_address(NULL, &conv_item->src_address, _resolveNames);
            QString q_addr_str(addr_str);
            wmem_free(NULL, addr_str);
            return q_addr_str;
            }
        case CONV_COLUMN_SRC_PORT:
            if (_resolveNames) {
                char* port_str = get_conversation_port(NULL, conv_item->src_port, conv_item->etype, _resolveNames);
                QString q_port_str(port_str);
                wmem_free(NULL, port_str);
                return q_port_str;
            } else {
                return quint32(conv_item->src_port);
            }
        case CONV_COLUMN_DST_ADDR:
            {
            char* addr_str = get_conversation_address(NULL, &conv_item->dst_address, _resolveNames);
            QString q_addr_str(addr_str);
            wmem_free(NULL, addr_str);
            return q_addr_str;
            }
        case CONV_COLUMN_DST_PORT:
            if (_resolveNames) {
                char* port_str = get_conversation_port(NULL, conv_item->dst_port, conv_item->etype, _resolveNames);
                QString q_port_str(port_str);
                wmem_free(NULL, port_str);
                return q_port_str;
            } else {
                return quint32(conv_item->dst_port);
            }
        case CONV_COLUMN_PACKETS:
        {
            qlonglong packets = conv_item->tx_frames + conv_item->rx_frames;
            return role == Qt::DisplayRole ? QString("%L1").arg(packets) : (QVariant)packets;
        }
        case CONV_COLUMN_BYTES:
            return role == Qt::DisplayRole ? formatString((qlonglong)conv_item->tx_bytes + conv_item->rx_bytes) :
                QVariant((qlonglong)conv_item->tx_bytes + conv_item->rx_bytes);
        case CONV_COLUMN_CONV_ID:
            return (int) conv_item->conv_id;
        case CONV_COLUMN_PACKETS_TOTAL:
        {
            qlonglong packets = 0;
            if (showTotalColumn())
                packets = conv_item->tx_frames_total + conv_item->rx_frames_total;

            return role == Qt::DisplayRole ? QString("%L1").arg(packets) : (QVariant)packets;
        }
        case CONV_COLUMN_BYTES_TOTAL:
        {
            double percent = 0;
            if (showTotalColumn()) {
                qlonglong totalPackets = (qlonglong)(conv_item->tx_frames_total + conv_item->rx_frames_total);
                qlonglong packets = (qlonglong)(conv_item->tx_frames + conv_item->rx_frames);
                percent = totalPackets == 0 ? 0 : (double) packets * 100 / (double) totalPackets;
            }
            return role == Qt::DisplayRole ? QString::number(percent, 'f', 2) + "%" : (QVariant)percent;
        }
        case CONV_COLUMN_PKT_AB:
        {
            qlonglong packets = conv_item->tx_frames;
            return role == Qt::DisplayRole ? QString("%L1").arg(packets) : (QVariant)packets;
        }
        case CONV_COLUMN_BYTES_AB:
            return role == Qt::DisplayRole ? formatString((qlonglong)conv_item->tx_bytes) : QVariant((qlonglong)conv_item->tx_bytes);
        case CONV_COLUMN_PKT_BA:
        {
            qlonglong packets = conv_item->rx_frames;
            return role == Qt::DisplayRole ? QString("%L1").arg(packets) : (QVariant)packets;
        }
        case CONV_COLUMN_BYTES_BA:
            return role == Qt::DisplayRole ? formatString((qlonglong)conv_item->rx_bytes) : QVariant((qlonglong)conv_item->rx_bytes);
        case CONV_COLUMN_START:
        {
            int width = _nanoseconds ? 9 : 6;

            if (_absoluteTime) {
                nstime_t *abs_time = &conv_item->start_abs_time;
                QDateTime abs_dt = QDateTime::fromMSecsSinceEpoch(nstime_to_msec(abs_time));
                return role == Qt::DisplayRole ? abs_dt.toString("hh:mm:ss.zzzz") : (QVariant)abs_dt;
            } else {
                return role == Qt::DisplayRole ?
                    QString::number(nstime_to_sec(&conv_item->start_time), 'f', width) :
                    (QVariant)((double) nstime_to_sec(&conv_item->start_time));
            }
        }
        case CONV_COLUMN_DURATION:
        {
            int width = _nanoseconds ? 6 : 4;
            return role == Qt::DisplayRole ? QString::number(duration, 'f', width) : (QVariant)duration;
        }
        case CONV_COLUMN_BPS_AB:
            return bpsCalculated ? (role == Qt::DisplayRole ? formatString(bps_ab) : QVariant((qlonglong)bps_ab)): QVariant();
        case CONV_COLUMN_BPS_BA:
            return bpsCalculated ? (role == Qt::DisplayRole ? formatString(bps_ba) : QVariant((qlonglong)bps_ba)): QVariant();
        }
    } else if (role == Qt::ToolTipRole) {
        if (idx.column() == CONV_COLUMN_START || idx.column() == CONV_COLUMN_DURATION)
            return QObject::tr("Bars show the relative timeline for each conversation.");
    } else if (role == Qt::TextAlignmentRole) {
        if (idx.column() == CONV_COLUMN_SRC_ADDR || idx.column() == CONV_COLUMN_DST_ADDR)
            return Qt::AlignLeft;
        return Qt::AlignRight;
    } else if (role == ATapDataModel::TIMELINE_DATA) {
        struct timeline_span span_data;
        span_data.minRelTime = _minRelStartTime;
        span_data.maxRelTime = _maxRelStopTime;
        span_data.startTime = nstime_to_sec(&conv_item->start_time);
        span_data.stopTime = nstime_to_sec(&conv_item->stop_time);
        span_data.colStart = CONV_COLUMN_START;
        span_data.colDuration = CONV_COLUMN_DURATION;

        if ((_maxRelStopTime - _minRelStartTime) > 0) {
            return QVariant::fromValue(span_data);
        }
    } else if (role == ATapDataModel::ENDPOINT_DATATYPE) {
        return (int)(conv_item->etype);
    } else if (role == ATapDataModel::CONVERSATION_ID) {
        return (int)(conv_item->conv_id);
    } else if (role == ATapDataModel::ROW_IS_FILTERED) {
        return (bool)conv_item->filtered && showTotalColumn();
    } else if (role == ATapDataModel::DATA_ADDRESS_TYPE) {
        if (idx.column() == ConversationDataModel::CONV_COLUMN_SRC_ADDR || idx.column() == ConversationDataModel::CONV_COLUMN_DST_ADDR) {
            address tst_address = idx.column() == ConversationDataModel::CONV_COLUMN_SRC_ADDR ? conv_item->src_address : conv_item->dst_address;
            return (int)tst_address.type;
        }
        return (int) AT_NONE;
    } else if (role == ATapDataModel::DATA_IPV4_INTEGER || role == ATapDataModel::DATA_IPV6_LIST) {
        if (idx.column() == ConversationDataModel::CONV_COLUMN_SRC_ADDR || idx.column() == ConversationDataModel::CONV_COLUMN_DST_ADDR) {
            address tst_address = idx.column() == ConversationDataModel::CONV_COLUMN_SRC_ADDR ? conv_item->src_address : conv_item->dst_address;
            if (role == ATapDataModel::DATA_IPV4_INTEGER && tst_address.type == AT_IPv4) {
                const ws_in4_addr * ip4 = (const ws_in4_addr *) tst_address.data;
                return (quint32) GUINT32_FROM_BE(*ip4);
            }
            else if (role == ATapDataModel::DATA_IPV6_LIST && tst_address.type == AT_IPv6) {
                const ws_in6_addr * ip6 = (const ws_in6_addr *) tst_address.data;
                QList<quint8> result;
                result.reserve(16);
                std::copy(ip6->bytes + 0, ip6->bytes + 16, std::back_inserter(result));
                return QVariant::fromValue(result);
            }
        }
    }

    return QVariant();
}

conv_item_t * ConversationDataModel::itemForRow(int row)
{
    if (row < 0 || row >= rowCount())
        return nullptr;
    return (conv_item_t *)&g_array_index(storage_, conv_item_t, row);
}

bool ConversationDataModel::showConversationId(int row) const
{
    if (!storage_ || row >= (int) storage_->len)
        return false;

    conv_item_t *conv_item = (conv_item_t *)&g_array_index(storage_, conv_item_t, row);
    if (conv_item && (conv_item->etype == ENDPOINT_TCP || conv_item->etype == ENDPOINT_UDP))
        return true;
    return false;
}
