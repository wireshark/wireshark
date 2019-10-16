/* voip_calls_info_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "voip_calls_info_model.h"
#include <wsutil/utf8_entities.h>
#include <ui/qt/utils/qt_ui_utils.h>

#include <QDateTime>

VoipCallsInfoModel::VoipCallsInfoModel(QObject *parent) :
    QAbstractTableModel(parent),
    mTimeOfDay_(false)
{
}

voip_calls_info_t *VoipCallsInfoModel::indexToCallInfo(const QModelIndex &index)
{
    return VariantPointer<voip_calls_info_t>::asPtr(index.data(Qt::UserRole));
}

QVariant VoipCallsInfoModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return QVariant();
    }

    // call_info will be non-NULL since the index is valid
    voip_calls_info_t *call_info = static_cast<voip_calls_info_t *>(callinfos_[index.row()]);

    if (role == Qt::UserRole) {
        return VariantPointer<voip_calls_info_t>::asQVariant(call_info);
    }

    if (role != Qt::DisplayRole) {
        return QVariant();
    }

    switch ((Column) index.column()) {
    case StartTime:
        return timeData(&(call_info->start_fd->abs_ts), &(call_info->start_rel_ts));
    case StopTime:
        return timeData(&(call_info->stop_fd->abs_ts), &(call_info->stop_rel_ts));
    case InitialSpeaker:
        return address_to_display_qstring(&(call_info->initial_speaker));
    case From:
        return call_info->from_identity;
    case To:
        return call_info->to_identity;
    case Protocol:
        return ((call_info->protocol == VOIP_COMMON) && call_info->protocol_name) ?
            call_info->protocol_name : voip_protocol_name[call_info->protocol];
    case Duration:
    {
        guint callDuration = nstime_to_sec(&(call_info->stop_fd->abs_ts)) - nstime_to_sec(&(call_info->start_fd->abs_ts));
        return QString("%1:%2:%3").arg(callDuration / 3600, 2, 10, QChar('0')).arg((callDuration % 3600) / 60, 2, 10, QChar('0')).arg(callDuration % 60, 2, 10, QChar('0'));
    }
    case Packets:
        return call_info->npackets;
    case State:
        return QString(voip_call_state_name[call_info->call_state]);
    case Comments:
        /* Add comments based on the protocol */
        switch (call_info->protocol) {
        case VOIP_ISUP:
        {
            isup_calls_info_t *isup_info = (isup_calls_info_t *)call_info->prot_info;
            return QString("%1-%2 %3 %4-%5")
                    .arg(isup_info->ni)
                    .arg(isup_info->opc)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(isup_info->ni)
                    .arg(isup_info->dpc);
        }
            break;
        case VOIP_H323:
        {
            h323_calls_info_t *h323_info = (h323_calls_info_t *)call_info->prot_info;
            gboolean flag = FALSE;
            static const QString on_str = tr("On");
            static const QString off_str = tr("Off");
            if (call_info->call_state == VOIP_CALL_SETUP) {
                flag = h323_info->is_faststart_Setup;
            } else {
                if ((h323_info->is_faststart_Setup) && (h323_info->is_faststart_Proc)) {
                    flag = TRUE;
                }
            }
            return tr("Tunneling: %1  Fast Start: %2")
                    .arg(h323_info->is_h245Tunneling ? on_str : off_str)
                    .arg(flag ? on_str : off_str);
        }
            break;
        case VOIP_COMMON:
        default:
            return call_info->call_comment;
        }
    case ColumnCount:
        g_assert_not_reached();
    }
    return QVariant();
}

QVariant VoipCallsInfoModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        switch ((Column) section) {
        case StartTime:
           return tr("Start Time");
        case StopTime:
           return tr("Stop Time");
        case InitialSpeaker:
           return tr("Initial Speaker");
        case From:
           return tr("From");
        case To:
           return tr("To");
        case Protocol:
           return tr("Protocol");
        case Duration:
           return tr("Duration");
        case Packets:
           return tr("Packets");
        case State:
           return tr("State");
        case Comments:
           return tr("Comments");
        case ColumnCount:
            g_assert_not_reached();
        }
    }
    return QVariant();
}

int VoipCallsInfoModel::rowCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return callinfos_.size();
}

int VoipCallsInfoModel::columnCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return ColumnCount;
}

QVariant VoipCallsInfoModel::timeData(nstime_t *abs_ts, nstime_t *rel_ts) const
{
    if (mTimeOfDay_) {
        return QDateTime::fromTime_t(nstime_to_sec(abs_ts)).toTimeSpec(Qt::LocalTime).toString("yyyy-MM-dd hh:mm:ss");
    } else {
        // XXX Pull digit count from capture file precision
        return QString::number(nstime_to_sec(rel_ts), 'f', 6);
    }
}

void VoipCallsInfoModel::setTimeOfDay(bool timeOfDay)
{
    mTimeOfDay_ = timeOfDay;
    if (rowCount() > 0) {
        // Update both the start and stop column in all rows.
        emit dataChanged(index(0, StartTime), index(rowCount() - 1, StopTime));
    }
}

bool VoipCallsInfoModel::timeOfDay() const
{
    return mTimeOfDay_;
}

void VoipCallsInfoModel::updateCalls(GQueue *callsinfos)
{
    if (callsinfos) {
        GList *cur_call = g_queue_peek_nth_link(callsinfos, rowCount());
        guint extra = g_list_length(cur_call);
        if (extra > 0) {
            beginInsertRows(QModelIndex(), rowCount(), rowCount() + extra - 1);
            while (cur_call && cur_call->data) {
                voip_calls_info_t *call_info = gxx_list_data(voip_calls_info_t*, cur_call);
                callinfos_.push_back(call_info);
                cur_call = gxx_list_next(cur_call);
            }
            endInsertRows();
        }
    }
}


// Proxy model that allows columns to be sorted.
VoipCallsInfoSortedModel::VoipCallsInfoSortedModel(QObject *parent) :
    QSortFilterProxyModel(parent)
{
}

bool VoipCallsInfoSortedModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    voip_calls_info_t *a = VoipCallsInfoModel::indexToCallInfo(source_left);
    voip_calls_info_t *b = VoipCallsInfoModel::indexToCallInfo(source_right);

    if (a && b) {
        switch (source_left.column()) {
        case VoipCallsInfoModel::StartTime:
            return nstime_cmp(&(a->start_rel_ts), &(b->start_rel_ts)) < 0;
        case VoipCallsInfoModel::StopTime:
            return nstime_cmp(&(a->stop_rel_ts), &(b->stop_rel_ts)) < 0;
        case VoipCallsInfoModel::InitialSpeaker:
            return cmp_address(&(a->initial_speaker), &(b->initial_speaker)) < 0;
        }
    }

    // fallback to string cmp on other fields
    return QSortFilterProxyModel::lessThan(source_left, source_right);
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
