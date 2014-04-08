/* lbm_lbtrm_transport_dialog.cpp
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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

#include "lbm_lbtrm_transport_dialog.h"
#include "ui_lbm_lbtrm_transport_dialog.h"

#include "file.h"

#include "wireshark_application.h"

#include <QClipboard>
#include <QMessageBox>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QMenu>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/wmem/wmem.h>
#include <epan/dissectors/packet-lbm.h>
#include <wsutil/nstime.h>

#include <QDebug>

namespace
{
    static const int Source_AddressTransport_Column = 0;
    static const int Source_DataFrames_Column = 1;
    static const int Source_DataBytes_Column = 2;
    static const int Source_DataFramesBytes_Column = 3;
    static const int Source_DataRate_Column = 4;
    static const int Source_RXDataFrames_Column = 5;
    static const int Source_RXDataBytes_Column = 6;
    static const int Source_RXDataFramesBytes_Column = 7;
    static const int Source_RXDataRate_Column = 8;
    static const int Source_NCFFrames_Column = 9;
    static const int Source_NCFCount_Column = 10;
    static const int Source_NCFBytes_Column = 11;
    static const int Source_NCFFramesBytes_Column = 12;
    static const int Source_NCFCountBytes_Column = 13;
    static const int Source_NCFFramesCount_Column = 14;
    static const int Source_NCFFramesCountBytes_Column = 15;
    static const int Source_NCFRate_Column = 16;
    static const int Source_SMFrames_Column = 17;
    static const int Source_SMBytes_Column = 18;
    static const int Source_SMFramesBytes_Column = 19;
    static const int Source_SMRate_Column = 20;

    static const int Receiver_AddressTransport_Column = 0;
    static const int Receiver_NAKFrames_Column = 1;
    static const int Receiver_NAKCount_Column = 2;
    static const int Receiver_NAKBytes_Column = 3;
    static const int Receiver_NAKRate_Column = 4;

    static const int Detail_SQN_Column = 0;
    static const int Detail_Count_Column = 1;
    static const int Detail_Frame_Column = 2;

    static const double OneKilobit = 1000.0;
    static const double OneMegabit = OneKilobit * OneKilobit;
    static const double OneGigabit = OneMegabit * OneKilobit;
}

static QString format_rate(const nstime_t & elapsed, guint64 bytes)
{
    QString result;
    double elapsed_sec;
    double rate;

    if (((elapsed.secs == 0) && (elapsed.nsecs == 0)) || (bytes == 0))
    {
        return (QString("0"));
    }

    elapsed_sec = elapsed.secs + (((double)elapsed.nsecs) / 1000000000.0);
    rate = ((double)(bytes * 8)) / elapsed_sec;

    // Currently rate is in bps
    if (rate >= OneGigabit)
    {
        rate /= OneGigabit;
        result = QString("%1G").arg(rate, 0, 'f', 2);
    }
    else if (rate >= OneMegabit)
    {
        rate /= OneMegabit;
        result = QString("%1M").arg(rate, 0, 'f', 2);
    }
    else if (rate >= OneKilobit)
    {
        rate /= OneKilobit;
        result = QString("%1K").arg(rate, 0, 'f', 2);
    }
    else
    {
        result = QString("%1").arg(rate, 0, 'f', 2);
    }
    return (result);
}

// Note:
// LBMLBTRMFrameEntry, LBMLBTRMSQNEntry, LBMLBTRMNCFReasonEntry, LBMLBTRMNCFSQNEntry, LBMLBTRMSourceTransportEntry, LBMLBTRMSourceEntry,
// LBMLBTRMReceiverTransportEntry, and LBMLBTRMReceiverEntry are all derived from  a QTreeWidgetItem. Each instantiation can exist
// in two places: in a QTreeWidget, and in a containing QMap.
//
// For example:
// - LBMLBTRMTransportDialogInfo contains a QMap of the sources (LBMLBTRMSourceEntry) and receivers (LBMLBTRMReceiverEntry)
// - A source (LBMLBTRMSourceEntry) contains a QMap of the source transports originating from it (LBMLBTRMSourceTransportEntry)
// - A source transport (LBMLBTRMSourceTransportEntry) contains QMaps of data, RX data, and SM SQNs (LBMLBTRMSQNEntry) and NCF SQNs
//   (LBMLBTRMNCFSQNEntry)
// - A data SQN (LBMLBTRMSQNEntry) contains a QMap of the frames (LBMLBTRMFrameEntry) in which that SQN appears
//
// Not all of the entries actually appear in a QTreeWidget at one time. For example, in the source details, if no specific source
// transport is selected, nothing is in the source details tree. If Data SQNs is selected, then those details appear in the source
// details tree. Switching to RX Data SQNs removes whatever is currently in the source details tree, and adds the RX details for
// the selected transport.
//
// The actual owner of one of the above QTreeWidgetItem-derived items is the QMap container in its parent. The item is "loaned" to
// the QTreeWidget for display.
//
// All of this is to explain why
// 1) we are frequently adding things to a QTreeWidget
// 2) things are removed (takeTopLevelItem) from a QTreeWidget
// 3) destruction involves removing all items from all QTreeWidgets (rather than letting QTreeWidget delete them)
// 4) the destructor for each item has the form
//    <for each QMap container>
//      for (XXXMapIterator it = m_xxx.begin(); it != m_xxx.end(); it++)
//      {
//          delete *it;
//      }
//      m_xxx.clear();
//    The for-loop calls the destructor for each item, while the clear() cleans up the space used by the QMap itself.

// A frame entry
class LBMLBTRMFrameEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRMFrameEntry(guint32 frame);
        virtual ~LBMLBTRMFrameEntry(void) { }
        guint32 getFrame(void) { return (m_frame); }

    private:
        LBMLBTRMFrameEntry(void) { }
        guint32 m_frame;
};

LBMLBTRMFrameEntry::LBMLBTRMFrameEntry(guint32 frame) :
    QTreeWidgetItem(),
    m_frame(frame)
{
    setText(Detail_SQN_Column, QString(" "));
    setText(Detail_Count_Column, QString(" "));
    setText(Detail_Frame_Column, QString("%1").arg(m_frame));
}

typedef QMap<guint32, LBMLBTRMFrameEntry *> LBMLBTRMFrameMap;
typedef QMap<guint32, LBMLBTRMFrameEntry *>::iterator LBMLBTRMFrameMapIterator;

// A SQN (SeQuence Number) entry
class LBMLBTRMSQNEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRMSQNEntry(guint32 sqn);
        virtual ~LBMLBTRMSQNEntry(void);
        void processFrame(guint32 frame);

    private:
        LBMLBTRMSQNEntry(void);
        guint32 m_sqn;
        guint32 m_count;
        LBMLBTRMFrameMap m_frames;
};

LBMLBTRMSQNEntry::LBMLBTRMSQNEntry(guint32 sqn) :
    QTreeWidgetItem(),
    m_sqn(sqn),
    m_count(0),
    m_frames()
{
    setText(Detail_SQN_Column, QString("%1").arg(m_sqn));
    setTextAlignment(Detail_SQN_Column, Qt::AlignRight);
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRMSQNEntry::~LBMLBTRMSQNEntry(void)
{
    for (LBMLBTRMFrameMapIterator it = m_frames.begin(); it != m_frames.end(); it++)
    {
        delete *it;
    }
    m_frames.clear();
}

void LBMLBTRMSQNEntry::processFrame(guint32 frame)
{
    LBMLBTRMFrameMapIterator it;

    it = m_frames.find(frame);
    if (m_frames.end() == it)
    {
        LBMLBTRMFrameEntry * entry = new LBMLBTRMFrameEntry(frame);
        m_frames.insert(frame, entry);
        addChild(entry);
        sortChildren(Detail_Frame_Column, Qt::AscendingOrder);
    }
    m_count++;
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
}

// An NCF (Nak ConFirmation) Reason entry
class LBMLBTRMNCFReasonEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRMNCFReasonEntry(guint8 reason);
        virtual ~LBMLBTRMNCFReasonEntry(void);
        void processFrame(guint32 frame);

    private:
        LBMLBTRMNCFReasonEntry(void);
        guint8 m_reason;
        QString m_reason_string;
        guint32 m_count;
        LBMLBTRMFrameMap m_frames;
};

LBMLBTRMNCFReasonEntry::LBMLBTRMNCFReasonEntry(guint8 reason) :
    QTreeWidgetItem(),
    m_reason(reason),
    m_reason_string(),
    m_count(0),
    m_frames()
{
    switch (m_reason)
    {
        case LBTRM_NCF_REASON_NO_RETRY:
            m_reason_string = "No Retry";
            break;
        case LBTRM_NCF_REASON_IGNORED:
            m_reason_string = "Ignored";
            break;
        case LBTRM_NCF_REASON_RX_DELAY:
            m_reason_string = "Retransmit Delay";
            break;
        case LBTRM_NCF_REASON_SHED:
            m_reason_string = "Shed";
            break;
        default:
            m_reason_string = QString("Unknown (%1)").arg(m_reason);
            break;
    }
    setText(Detail_SQN_Column, m_reason_string);
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRMNCFReasonEntry::~LBMLBTRMNCFReasonEntry(void)
{
    for (LBMLBTRMFrameMapIterator it = m_frames.begin(); it != m_frames.end(); it++)
    {
        delete *it;
    }
    m_frames.clear();
}

void LBMLBTRMNCFReasonEntry::processFrame(guint32 frame)
{
    LBMLBTRMFrameMapIterator it;

    it = m_frames.find(frame);
    if (m_frames.end() == it)
    {
        LBMLBTRMFrameEntry * entry = new LBMLBTRMFrameEntry(frame);
        m_frames.insert(frame, entry);
        addChild(entry);
        sortChildren(Detail_Frame_Column, Qt::AscendingOrder);
    }
    m_count++;
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
}

typedef QMap<guint32, LBMLBTRMNCFReasonEntry *> LBMLBTRMNCFReasonMap;
typedef QMap<guint32, LBMLBTRMNCFReasonEntry *>::iterator LBMLBTRMNCFReasonMapIterator;

// An NCF SQN entry
class LBMLBTRMNCFSQNEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRMNCFSQNEntry(guint32 sqn);
        virtual ~LBMLBTRMNCFSQNEntry(void);
        void processFrame(guint8 reason, guint32 frame);

    private:
        LBMLBTRMNCFSQNEntry(void);
        guint32 m_sqn;
        guint32 m_count;
        LBMLBTRMNCFReasonMap m_reasons;
};

LBMLBTRMNCFSQNEntry::LBMLBTRMNCFSQNEntry(guint32 sqn) :
    QTreeWidgetItem(),
    m_sqn(sqn),
    m_count(0),
    m_reasons()
{
    setText(Detail_SQN_Column, QString("%1").arg(m_sqn));
    setTextAlignment(Detail_SQN_Column, Qt::AlignRight);
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRMNCFSQNEntry::~LBMLBTRMNCFSQNEntry(void)
{
    for (LBMLBTRMNCFReasonMapIterator it = m_reasons.begin(); it != m_reasons.end(); it++)
    {
        delete *it;
    }
    m_reasons.clear();
}

void LBMLBTRMNCFSQNEntry::processFrame(guint8 reason, guint32 frame)
{
    LBMLBTRMNCFReasonMapIterator it;
    LBMLBTRMNCFReasonEntry * entry = NULL;

    it = m_reasons.find(reason);
    if (m_reasons.end() == it)
    {
        entry = new LBMLBTRMNCFReasonEntry(reason);
        m_reasons.insert(reason, entry);
        addChild(entry);
        sortChildren(Detail_Frame_Column, Qt::AscendingOrder);
    }
    else
    {
        entry = it.value();
    }
    m_count++;
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    entry->processFrame(frame);
}

typedef QMap<guint32, LBMLBTRMSQNEntry *> LBMLBTRMSQNMap;
typedef QMap<guint32, LBMLBTRMSQNEntry *>::iterator LBMLBTRMSQNMapIterator;
typedef QMap<guint32, LBMLBTRMNCFSQNEntry *> LBMLBTRMNCFSQNMap;
typedef QMap<guint32, LBMLBTRMNCFSQNEntry *>::iterator LBMLBTRMNCFSQNMapIterator;

// A source transport entry
class LBMLBTRMSourceTransportEntry : public QTreeWidgetItem
{
        friend class LBMLBTRMTransportDialog;

    public:
        LBMLBTRMSourceTransportEntry(const QString & transport);
        virtual ~LBMLBTRMSourceTransportEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info);

    protected:
        QString m_transport;

    private:
        LBMLBTRMSourceTransportEntry(void) { }
        void fillItem(void);
        guint64 m_data_frames;
        guint64 m_data_bytes;
        guint64 m_rx_data_frames;
        guint64 m_rx_data_bytes;
        guint64 m_ncf_frames;
        guint64 m_ncf_count;
        guint64 m_ncf_bytes;
        guint64 m_sm_frames;
        guint64 m_sm_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;

    protected:
        LBMLBTRMSQNMap m_data_sqns;
        LBMLBTRMSQNMap m_rx_data_sqns;
        LBMLBTRMNCFSQNMap m_ncf_sqns;
        LBMLBTRMSQNMap m_sm_sqns;
};

LBMLBTRMSourceTransportEntry::LBMLBTRMSourceTransportEntry(const QString & transport) :
    QTreeWidgetItem(),
    m_transport(transport),
    m_data_frames(0),
    m_data_bytes(0),
    m_rx_data_frames(0),
    m_rx_data_bytes(0),
    m_ncf_frames(0),
    m_ncf_count(0),
    m_ncf_bytes(0),
    m_sm_frames(0),
    m_sm_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_data_sqns(),
    m_rx_data_sqns(),
    m_ncf_sqns(),
    m_sm_sqns()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Source_AddressTransport_Column, m_transport);
}

LBMLBTRMSourceTransportEntry::~LBMLBTRMSourceTransportEntry(void)
{
    for (LBMLBTRMSQNMapIterator it = m_data_sqns.begin(); it != m_data_sqns.end(); it++)
    {
        delete *it;
    }
    m_data_sqns.clear();

    for (LBMLBTRMSQNMapIterator it = m_rx_data_sqns.begin(); it != m_rx_data_sqns.end(); it++)
    {
        delete *it;
    }
    m_rx_data_sqns.clear();

    for (LBMLBTRMNCFSQNMapIterator it = m_ncf_sqns.begin(); it != m_ncf_sqns.end(); it++)
    {
        delete *it;
    }
    m_ncf_sqns.clear();

    for (LBMLBTRMSQNMapIterator it = m_sm_sqns.begin(); it != m_sm_sqns.end(); it++)
    {
        delete *it;
    }
    m_sm_sqns.clear();
}

void LBMLBTRMSourceTransportEntry::processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info)
{
    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->fd->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->fd->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->fd->abs_ts));
    }
    if (tap_info->type == LBTRM_PACKET_TYPE_DATA)
    {
        LBMLBTRMSQNEntry * sqn = NULL;
        LBMLBTRMSQNMapIterator it;

        if (tap_info->retransmission)
        {
            m_rx_data_frames++;
            m_rx_data_bytes += pinfo->fd->pkt_len;
            it = m_rx_data_sqns.find(tap_info->sqn);
            if (m_rx_data_sqns.end() == it)
            {
                sqn = new LBMLBTRMSQNEntry(tap_info->sqn);
                m_rx_data_sqns.insert(tap_info->sqn, sqn);
            }
            else
            {
                sqn = it.value();
            }
        }
        else
        {
            m_data_frames++;
            m_data_bytes += pinfo->fd->pkt_len;
            it = m_data_sqns.find(tap_info->sqn);
            if (m_data_sqns.end() == it)
            {
                sqn = new LBMLBTRMSQNEntry(tap_info->sqn);
                m_data_sqns.insert(tap_info->sqn, sqn);
            }
            else
            {
                sqn = it.value();
            }
        }
        sqn->processFrame(pinfo->fd->num);
    }
    else if (tap_info->type == LBTRM_PACKET_TYPE_NCF)
    {
        guint16 idx;
        LBMLBTRMNCFSQNMapIterator it;
        LBMLBTRMNCFSQNEntry * sqn = NULL;

        m_ncf_frames++;
        m_ncf_bytes += pinfo->fd->pkt_len;
        m_ncf_count += (guint64)tap_info->num_sqns;
        for (idx = 0; idx < tap_info->num_sqns; idx++)
        {
            it = m_ncf_sqns.find(tap_info->sqns[idx]);
            if (m_ncf_sqns.end() == it)
            {
                sqn = new LBMLBTRMNCFSQNEntry(tap_info->sqns[idx]);
                m_ncf_sqns.insert(tap_info->sqns[idx], sqn);
            }
            else
            {
                sqn = it.value();
            }
            sqn->processFrame(tap_info->ncf_reason, pinfo->fd->num);
        }
    }
    else if (tap_info->type == LBTRM_PACKET_TYPE_SM)
    {
        LBMLBTRMSQNEntry * sqn = NULL;
        LBMLBTRMSQNMapIterator it;

        m_sm_frames++;
        m_sm_bytes += pinfo->fd->pkt_len;
        it = m_sm_sqns.find(tap_info->sqn);
        if (m_sm_sqns.end() == it)
        {
            sqn = new LBMLBTRMSQNEntry(tap_info->sqn);
            m_sm_sqns.insert(tap_info->sqn, sqn);
        }
        else
        {
            sqn = it.value();
        }
        sqn->processFrame(pinfo->fd->num);
    }
    else
    {
        return;
    }
    fillItem();
}

void LBMLBTRMSourceTransportEntry::fillItem(void)
{
    nstime_t delta;

    nstime_delta(&delta, &m_last_frame_timestamp, &m_first_frame_timestamp);
    setText(Source_DataFrames_Column, QString("%1").arg(m_data_frames));
    setTextAlignment(Source_DataFrames_Column, Qt::AlignRight);
    setText(Source_DataBytes_Column, QString("%1").arg(m_data_bytes));
    setTextAlignment(Source_DataBytes_Column, Qt::AlignRight);
    setText(Source_DataFramesBytes_Column, QString("%1/%2").arg(m_data_frames).arg(m_data_bytes));
    setTextAlignment(Source_DataFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_DataRate_Column, format_rate(delta, m_data_bytes));
    setTextAlignment(Source_DataRate_Column, Qt::AlignRight);
    setText(Source_RXDataFrames_Column, QString("%1").arg(m_rx_data_frames));
    setTextAlignment(Source_RXDataFrames_Column, Qt::AlignRight);
    setText(Source_RXDataBytes_Column, QString("%1").arg(m_rx_data_bytes));
    setTextAlignment(Source_RXDataBytes_Column, Qt::AlignRight);
    setText(Source_RXDataFramesBytes_Column, QString("%1/%2").arg(m_rx_data_frames).arg(m_rx_data_bytes));
    setTextAlignment(Source_RXDataFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_RXDataRate_Column, format_rate(delta, m_rx_data_bytes));
    setTextAlignment(Source_RXDataRate_Column, Qt::AlignRight);
    setText(Source_NCFFrames_Column, QString("%1").arg(m_ncf_frames));
    setTextAlignment(Source_NCFFrames_Column, Qt::AlignRight);
    setText(Source_NCFCount_Column, QString("%1").arg(m_ncf_count));
    setTextAlignment(Source_NCFCount_Column, Qt::AlignRight);
    setText(Source_NCFBytes_Column, QString("%1").arg(m_ncf_bytes));
    setTextAlignment(Source_NCFBytes_Column, Qt::AlignRight);
    setText(Source_NCFFramesBytes_Column, QString("%1/%2").arg(m_ncf_frames).arg(m_ncf_bytes));
    setTextAlignment(Source_NCFFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_NCFCountBytes_Column, QString("%1/%2").arg(m_ncf_count).arg(m_ncf_bytes));
    setTextAlignment(Source_NCFCountBytes_Column, Qt::AlignHCenter);
    setText(Source_NCFFramesCount_Column, QString("%1/%2").arg(m_ncf_count).arg(m_ncf_count));
    setTextAlignment(Source_NCFFramesCount_Column, Qt::AlignHCenter);
    setText(Source_NCFFramesCountBytes_Column, QString("%1/%2/%3").arg(m_ncf_frames).arg(m_ncf_count).arg(m_ncf_bytes));
    setTextAlignment(Source_NCFFramesCountBytes_Column, Qt::AlignHCenter);
    setText(Source_NCFRate_Column, format_rate(delta, m_ncf_bytes));
    setTextAlignment(Source_NCFRate_Column, Qt::AlignRight);
    setText(Source_SMFrames_Column, QString("%1").arg(m_sm_frames));
    setTextAlignment(Source_SMFrames_Column, Qt::AlignRight);
    setText(Source_SMBytes_Column, QString("%1").arg(m_sm_bytes));
    setTextAlignment(Source_SMBytes_Column, Qt::AlignRight);
    setText(Source_SMFramesBytes_Column, QString("%1/%2").arg(m_sm_frames).arg(m_sm_bytes));
    setTextAlignment(Source_SMFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_SMRate_Column, format_rate(delta, m_sm_bytes));
    setTextAlignment(Source_SMRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRMSourceTransportEntry *> LBMLBTRMSourceTransportMap;
typedef QMap<QString, LBMLBTRMSourceTransportEntry *>::iterator LBMLBTRMSourceTransportMapIterator;

// A source (address) entry
class LBMLBTRMSourceEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRMSourceEntry(const QString & source_address);
        virtual ~LBMLBTRMSourceEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info);

    private:
        LBMLBTRMSourceEntry(void) { }
        void fillItem(void);
        QString m_address;
        QString m_transport;
        guint64 m_data_frames;
        guint64 m_data_bytes;
        guint64 m_rx_data_frames;
        guint64 m_rx_data_bytes;
        guint64 m_ncf_frames;
        guint64 m_ncf_count;
        guint64 m_ncf_bytes;
        guint64 m_sm_frames;
        guint64 m_sm_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;
        LBMLBTRMSourceTransportMap m_transports;
};

LBMLBTRMSourceEntry::LBMLBTRMSourceEntry(const QString & source_address) :
    QTreeWidgetItem(),
    m_address(source_address),
    m_data_frames(0),
    m_data_bytes(0),
    m_rx_data_frames(0),
    m_rx_data_bytes(0),
    m_ncf_frames(0),
    m_ncf_count(0),
    m_ncf_bytes(0),
    m_sm_frames(0),
    m_sm_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_transports()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Source_AddressTransport_Column, m_address);
}

LBMLBTRMSourceEntry::~LBMLBTRMSourceEntry(void)
{
    for (LBMLBTRMSourceTransportMapIterator it = m_transports.begin(); it != m_transports.end(); it++)
    {
        delete *it;
    }
    m_transports.clear();
}

void LBMLBTRMSourceEntry::processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info)
{
    LBMLBTRMSourceTransportEntry * transport = NULL;
    LBMLBTRMSourceTransportMapIterator it;

    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->fd->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->fd->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->fd->abs_ts));
    }
    if (tap_info->type == LBTRM_PACKET_TYPE_DATA)
    {
        if (tap_info->retransmission)
        {
            m_rx_data_frames++;
            m_rx_data_bytes += pinfo->fd->pkt_len;
        }
        else
        {
            m_data_frames++;
            m_data_bytes += pinfo->fd->pkt_len;
        }
    }
    else if (tap_info->type == LBTRM_PACKET_TYPE_NCF)
    {
        m_ncf_frames++;
        m_ncf_bytes += pinfo->fd->pkt_len;
        m_ncf_count += tap_info->num_sqns;
    }
    else if (tap_info->type == LBTRM_PACKET_TYPE_SM)
    {
        m_sm_frames++;
        m_sm_bytes += pinfo->fd->pkt_len;
    }

    it = m_transports.find(tap_info->transport);
    if (m_transports.end() == it)
    {
        transport = new LBMLBTRMSourceTransportEntry(tap_info->transport);
        m_transports.insert(tap_info->transport, transport);
        addChild(transport);
        sortChildren(Source_AddressTransport_Column, Qt::AscendingOrder);
    }
    else
    {
        transport = it.value();
    }
    fillItem();
    transport->processPacket(pinfo, tap_info);
}

void LBMLBTRMSourceEntry::fillItem(void)
{
    nstime_t delta;

    nstime_delta(&delta, &m_last_frame_timestamp, &m_first_frame_timestamp);
    setText(Source_DataFrames_Column, QString("%1").arg(m_data_frames));
    setTextAlignment(Source_DataFrames_Column, Qt::AlignRight);
    setText(Source_DataBytes_Column, QString("%1").arg(m_data_bytes));
    setTextAlignment(Source_DataBytes_Column, Qt::AlignRight);
    setText(Source_DataFramesBytes_Column, QString("%1/%2").arg(m_data_frames).arg(m_data_bytes));
    setTextAlignment(Source_DataFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_DataRate_Column, format_rate(delta, m_data_bytes));
    setTextAlignment(Source_DataRate_Column, Qt::AlignRight);
    setText(Source_RXDataFrames_Column, QString("%1").arg(m_rx_data_frames));
    setTextAlignment(Source_RXDataFrames_Column, Qt::AlignRight);
    setText(Source_RXDataBytes_Column, QString("%1").arg(m_rx_data_bytes));
    setTextAlignment(Source_RXDataBytes_Column, Qt::AlignRight);
    setText(Source_RXDataFramesBytes_Column, QString("%1/%2").arg(m_rx_data_frames).arg(m_rx_data_bytes));
    setTextAlignment(Source_RXDataFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_RXDataRate_Column, format_rate(delta, m_rx_data_bytes));
    setTextAlignment(Source_RXDataRate_Column, Qt::AlignRight);
    setText(Source_NCFFrames_Column, QString("%1").arg(m_ncf_frames));
    setTextAlignment(Source_NCFFrames_Column, Qt::AlignRight);
    setText(Source_NCFCount_Column, QString("%1").arg(m_ncf_count));
    setTextAlignment(Source_NCFCount_Column, Qt::AlignRight);
    setText(Source_NCFBytes_Column, QString("%1").arg(m_ncf_bytes));
    setTextAlignment(Source_NCFBytes_Column, Qt::AlignRight);
    setText(Source_NCFFramesBytes_Column, QString("%1/%2").arg(m_ncf_frames).arg(m_ncf_bytes));
    setTextAlignment(Source_NCFFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_NCFCountBytes_Column, QString("%1/%2").arg(m_ncf_count).arg(m_ncf_bytes));
    setTextAlignment(Source_NCFCountBytes_Column, Qt::AlignHCenter);
    setText(Source_NCFFramesCount_Column, QString("%1/%2").arg(m_ncf_frames).arg(m_ncf_count));
    setTextAlignment(Source_NCFFramesCount_Column, Qt::AlignHCenter);
    setText(Source_NCFFramesCountBytes_Column, QString("%1/%2/%3").arg(m_ncf_frames).arg(m_ncf_count).arg(m_ncf_bytes));
    setTextAlignment(Source_NCFFramesCountBytes_Column, Qt::AlignHCenter);
    setText(Source_NCFRate_Column, format_rate(delta, m_ncf_bytes));
    setTextAlignment(Source_NCFRate_Column, Qt::AlignRight);
    setText(Source_SMFrames_Column, QString("%1").arg(m_sm_frames));
    setTextAlignment(Source_SMFrames_Column, Qt::AlignRight);
    setText(Source_SMBytes_Column, QString("%1").arg(m_sm_bytes));
    setTextAlignment(Source_SMBytes_Column, Qt::AlignRight);
    setText(Source_SMFramesBytes_Column, QString("%1/%2").arg(m_sm_frames).arg(m_sm_bytes));
    setTextAlignment(Source_SMFramesBytes_Column, Qt::AlignRight);
    setText(Source_SMRate_Column, format_rate(delta, m_sm_bytes));
    setTextAlignment(Source_SMRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRMSourceEntry *> LBMLBTRMSourceMap;
typedef QMap<QString, LBMLBTRMSourceEntry *>::iterator LBMLBTRMSourceMapIterator;

// A receiver transport entry
class LBMLBTRMReceiverTransportEntry : public QTreeWidgetItem
{
        friend class LBMLBTRMTransportDialog;

    public:
        LBMLBTRMReceiverTransportEntry(const QString & transport);
        virtual ~LBMLBTRMReceiverTransportEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info);

    private:
        LBMLBTRMReceiverTransportEntry(void) { }
        void fillItem(void);
        QString m_transport;
        guint64 m_nak_frames;
        guint64 m_nak_count;
        guint64 m_nak_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;

    protected:
        LBMLBTRMSQNMap m_nak_sqns;
};

LBMLBTRMReceiverTransportEntry::LBMLBTRMReceiverTransportEntry(const QString & transport) :
    QTreeWidgetItem(),
    m_transport(transport),
    m_nak_frames(0),
    m_nak_count(0),
    m_nak_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_nak_sqns()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Receiver_AddressTransport_Column, m_transport);
}

LBMLBTRMReceiverTransportEntry::~LBMLBTRMReceiverTransportEntry(void)
{
    for (LBMLBTRMSQNMapIterator it = m_nak_sqns.begin(); it != m_nak_sqns.end(); it++)
    {
        delete *it;
    }
    m_nak_sqns.clear();
}

void LBMLBTRMReceiverTransportEntry::processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info)
{
    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->fd->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->fd->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->fd->abs_ts));
    }
    if (tap_info->type == LBTRM_PACKET_TYPE_NAK)
    {
        guint16 idx;
        LBMLBTRMSQNEntry * sqn = NULL;
        LBMLBTRMSQNMapIterator it;

        m_nak_frames++;
        m_nak_bytes += pinfo->fd->pkt_len;
        m_nak_count += tap_info->num_sqns;
        for (idx = 0; idx < tap_info->num_sqns; idx++)
        {
            it = m_nak_sqns.find(tap_info->sqns[idx]);
            if (m_nak_sqns.end() == it)
            {
                sqn = new LBMLBTRMSQNEntry(tap_info->sqns[idx]);
                m_nak_sqns.insert(tap_info->sqns[idx], sqn);
            }
            else
            {
                sqn = it.value();
            }
            sqn->processFrame(pinfo->fd->num);
        }
    }
    else
    {
        return;
    }
    fillItem();
}

void LBMLBTRMReceiverTransportEntry::fillItem(void)
{
    nstime_t delta;

    nstime_delta(&delta, &m_last_frame_timestamp, &m_first_frame_timestamp);
    setText(Receiver_NAKFrames_Column, QString("%1").arg(m_nak_frames));
    setTextAlignment(Receiver_NAKFrames_Column, Qt::AlignRight);
    setText(Receiver_NAKCount_Column, QString("%1").arg(m_nak_count));
    setTextAlignment(Receiver_NAKCount_Column, Qt::AlignRight);
    setText(Receiver_NAKBytes_Column, QString("%1").arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKBytes_Column, Qt::AlignRight);
    setText(Receiver_NAKRate_Column, format_rate(delta, m_nak_bytes));
    setTextAlignment(Receiver_NAKRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRMReceiverTransportEntry *> LBMLBTRMReceiverTransportMap;
typedef QMap<QString, LBMLBTRMReceiverTransportEntry *>::iterator LBMLBTRMReceiverTransportMapIterator;

// A receiver (address) entry
class LBMLBTRMReceiverEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRMReceiverEntry(const QString & receiver_address);
        virtual ~LBMLBTRMReceiverEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info);

    private:
        LBMLBTRMReceiverEntry(void);
        void fillItem(void);
        QString m_address;
        QString m_transport;
        guint64 m_nak_frames;
        guint64 m_nak_count;
        guint64 m_nak_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;
        LBMLBTRMReceiverTransportMap m_transports;
};

LBMLBTRMReceiverEntry::LBMLBTRMReceiverEntry(const QString & receiver_address) :
    QTreeWidgetItem(),
    m_address(receiver_address),
    m_nak_frames(0),
    m_nak_count(0),
    m_nak_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_transports()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Receiver_AddressTransport_Column, m_address);
}

LBMLBTRMReceiverEntry::~LBMLBTRMReceiverEntry(void)
{
    for (LBMLBTRMReceiverTransportMapIterator it = m_transports.begin(); it != m_transports.end(); it++)
    {
        delete *it;
    }
    m_transports.clear();
}

void LBMLBTRMReceiverEntry::processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info)
{
    LBMLBTRMReceiverTransportEntry * transport = NULL;
    LBMLBTRMReceiverTransportMapIterator it;

    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->fd->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->fd->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->fd->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->fd->abs_ts));
    }
    if (tap_info->type == LBTRM_PACKET_TYPE_NAK)
    {
        m_nak_frames++;
        m_nak_bytes += pinfo->fd->pkt_len;
        m_nak_count += tap_info->num_sqns;
    }

    it = m_transports.find(tap_info->transport);
    if (m_transports.end() == it)
    {
        transport = new LBMLBTRMReceiverTransportEntry(tap_info->transport);
        m_transports.insert(tap_info->transport, transport);
        addChild(transport);
        sortChildren(Receiver_AddressTransport_Column, Qt::AscendingOrder);
    }
    else
    {
        transport = it.value();
    }
    fillItem();
    transport->processPacket(pinfo, tap_info);
}

void LBMLBTRMReceiverEntry::fillItem(void)
{
    nstime_t delta;

    nstime_delta(&delta, &m_last_frame_timestamp, &m_first_frame_timestamp);
    setText(Receiver_NAKFrames_Column, QString("%1").arg(m_nak_frames));
    setTextAlignment(Receiver_NAKFrames_Column, Qt::AlignRight);
    setText(Receiver_NAKCount_Column, QString("%1").arg(m_nak_count));
    setTextAlignment(Receiver_NAKCount_Column, Qt::AlignRight);
    setText(Receiver_NAKBytes_Column, QString("%1").arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKBytes_Column, Qt::AlignRight);
    setText(Receiver_NAKRate_Column, format_rate(delta, m_nak_bytes));
    setTextAlignment(Receiver_NAKRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRMReceiverEntry *> LBMLBTRMReceiverMap;
typedef QMap<QString, LBMLBTRMReceiverEntry *>::iterator LBMLBTRMReceiverMapIterator;

class LBMLBTRMTransportDialogInfo
{
    public:
        LBMLBTRMTransportDialogInfo(void);
        ~LBMLBTRMTransportDialogInfo(void);
        void setDialog(LBMLBTRMTransportDialog * dialog);
        LBMLBTRMTransportDialog * getDialog(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info);
        void clearMaps(void);

    private:
        LBMLBTRMTransportDialog * m_dialog;
        LBMLBTRMSourceMap m_sources;
        LBMLBTRMReceiverMap m_receivers;
};

LBMLBTRMTransportDialogInfo::LBMLBTRMTransportDialogInfo(void) :
    m_dialog(NULL),
    m_sources(),
    m_receivers()
{
}

LBMLBTRMTransportDialogInfo::~LBMLBTRMTransportDialogInfo(void)
{
    clearMaps();
}

void LBMLBTRMTransportDialogInfo::setDialog(LBMLBTRMTransportDialog * dialog)
{
    m_dialog = dialog;
}

LBMLBTRMTransportDialog * LBMLBTRMTransportDialogInfo::getDialog(void)
{
    return (m_dialog);
}

void LBMLBTRMTransportDialogInfo::processPacket(const packet_info * pinfo, const lbm_lbtrm_tap_info_t * tap_info)
{
    switch (tap_info->type)
    {
        case LBTRM_PACKET_TYPE_DATA:
        case LBTRM_PACKET_TYPE_SM:
        case LBTRM_PACKET_TYPE_NCF:
            {
                LBMLBTRMSourceEntry * source = NULL;
                LBMLBTRMSourceMapIterator it;
                QString src_address = QString(address_to_str(wmem_packet_scope(), &(pinfo->src)));

                it = m_sources.find(src_address);
                if (m_sources.end() == it)
                {
                    QTreeWidgetItem * parent = NULL;
                    Ui::LBMLBTRMTransportDialog * ui = NULL;

                    source = new LBMLBTRMSourceEntry(src_address);
                    it = m_sources.insert(src_address, source);
                    ui = m_dialog->getUI();
                    ui->sources_TreeWidget->addTopLevelItem(source);
                    parent = ui->sources_TreeWidget->invisibleRootItem();
                    parent->sortChildren(Source_AddressTransport_Column, Qt::AscendingOrder);
                    ui->sources_TreeWidget->resizeColumnToContents(Source_AddressTransport_Column);
                }
                else
                {
                    source = it.value();
                }
                source->processPacket(pinfo, tap_info);
            }
            break;
        case LBTRM_PACKET_TYPE_NAK:
            {
                LBMLBTRMReceiverEntry * receiver = NULL;
                LBMLBTRMReceiverMapIterator it;
                QString src_address = QString(address_to_str(wmem_packet_scope(), &(pinfo->src)));

                it = m_receivers.find(src_address);
                if (m_receivers.end() == it)
                {
                    QTreeWidgetItem * parent = NULL;
                    Ui::LBMLBTRMTransportDialog * ui = NULL;

                    receiver = new LBMLBTRMReceiverEntry(src_address);
                    it = m_receivers.insert(src_address, receiver);
                    ui = m_dialog->getUI();
                    ui->receivers_TreeWidget->addTopLevelItem(receiver);
                    parent = ui->receivers_TreeWidget->invisibleRootItem();
                    parent->sortChildren(Receiver_AddressTransport_Column, Qt::AscendingOrder);
                    ui->receivers_TreeWidget->resizeColumnToContents(Receiver_AddressTransport_Column);
                }
                else
                {
                    receiver = it.value();
                }
                receiver->processPacket(pinfo, tap_info);
            }
            break;
        default:
            break;
    }
}

void LBMLBTRMTransportDialogInfo::clearMaps(void)
{
    for (LBMLBTRMSourceMapIterator it = m_sources.begin(); it != m_sources.end(); it++)
    {
        delete *it;
    }
    m_sources.clear();

    for (LBMLBTRMReceiverMapIterator it = m_receivers.begin(); it != m_receivers.end(); it++)
    {
        delete *it;
    }
    m_receivers.clear();
}

LBMLBTRMTransportDialog::LBMLBTRMTransportDialog(QWidget * parent, capture_file * cfile) :
    QDialog(parent),
    m_ui(new Ui::LBMLBTRMTransportDialog),
    m_dialog_info(NULL),
    m_capture_file(cfile),
    m_current_source_transport(NULL),
    m_current_receiver_transport(NULL),
    m_source_context_menu(NULL),
    m_source_header(NULL)
{
    m_ui->setupUi(this);
    m_dialog_info = new LBMLBTRMTransportDialogInfo();

    m_ui->tabWidget->setCurrentIndex(0);
    m_ui->sources_detail_ComboBox->setCurrentIndex(0);
    m_ui->sources_detail_transport_Label->setText(QString(" "));
    m_ui->receivers_detail_transport_Label->setText(QString(" "));
    m_ui->stackedWidget->setCurrentIndex(0);

    m_source_header = m_ui->sources_TreeWidget->header();
    m_source_context_menu = new QMenu(m_source_header);

    m_source_context_menu->addAction(m_ui->action_SourceAutoResizeColumns);
    connect(m_ui->action_SourceAutoResizeColumns, SIGNAL(triggered()), this, SLOT(actionSourceAutoResizeColumns_triggered()));
    m_source_context_menu->addSeparator();

    m_ui->action_SourceDataFrames->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceDataFrames);
    connect(m_ui->action_SourceDataFrames, SIGNAL(triggered(bool)), this, SLOT(actionSourceDataFrames_triggered(bool)));
    m_ui->action_SourceDataBytes->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceDataBytes);
    connect(m_ui->action_SourceDataBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceDataBytes_triggered(bool)));
    m_ui->action_SourceDataFramesBytes->setChecked(false);
    m_source_context_menu->addAction(m_ui->action_SourceDataFramesBytes);
    connect(m_ui->action_SourceDataFramesBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceDataFramesBytes_triggered(bool)));
    m_ui->action_SourceDataRate->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceDataRate);
    connect(m_ui->action_SourceDataRate, SIGNAL(triggered(bool)), this, SLOT(actionSourceDataRate_triggered(bool)));

    m_ui->action_SourceRXDataFrames->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceRXDataFrames);
    connect(m_ui->action_SourceRXDataFrames, SIGNAL(triggered(bool)), this, SLOT(actionSourceRXDataFrames_triggered(bool)));
    m_ui->action_SourceRXDataBytes->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceRXDataBytes);
    connect(m_ui->action_SourceRXDataBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceRXDataBytes_triggered(bool)));
    m_ui->action_SourceRXDataFramesBytes->setChecked(false);
    m_source_context_menu->addAction(m_ui->action_SourceRXDataFramesBytes);
    connect(m_ui->action_SourceRXDataFramesBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceRXDataFramesBytes_triggered(bool)));
    m_ui->action_SourceRXDataRate->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceRXDataRate);
    connect(m_ui->action_SourceRXDataRate, SIGNAL(triggered(bool)), this, SLOT(actionSourceRXDataRate_triggered(bool)));

    m_ui->action_SourceNCFFrames->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceNCFFrames);
    connect(m_ui->action_SourceNCFFrames, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFFrames_triggered(bool)));
    m_ui->action_SourceNCFCount->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceNCFCount);
    connect(m_ui->action_SourceNCFCount, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFCount_triggered(bool)));
    m_ui->action_SourceNCFBytes->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceNCFBytes);
    connect(m_ui->action_SourceNCFBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFBytes_triggered(bool)));
    m_ui->action_SourceNCFFramesBytes->setChecked(false);
    m_source_context_menu->addAction(m_ui->action_SourceNCFFramesBytes);
    connect(m_ui->action_SourceNCFFramesBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFFramesBytes_triggered(bool)));
    m_ui->action_SourceNCFCountBytes->setChecked(false);
    m_source_context_menu->addAction(m_ui->action_SourceNCFCountBytes);
    connect(m_ui->action_SourceNCFCountBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFCountBytes_triggered(bool)));
    m_ui->action_SourceNCFFramesCount->setChecked(false);
    m_source_context_menu->addAction(m_ui->action_SourceNCFFramesCount);
    connect(m_ui->action_SourceNCFFramesCount, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFFramesCount_triggered(bool)));
    m_ui->action_SourceNCFFramesCountBytes->setChecked(false);
    m_source_context_menu->addAction(m_ui->action_SourceNCFFramesCountBytes);
    connect(m_ui->action_SourceNCFFramesCountBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFFramesCountBytes_triggered(bool)));
    m_ui->action_SourceNCFRate->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceNCFRate);
    connect(m_ui->action_SourceNCFRate, SIGNAL(triggered(bool)), this, SLOT(actionSourceNCFRate_triggered(bool)));

    m_ui->action_SourceSMFrames->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceSMFrames);
    connect(m_ui->action_SourceSMFrames, SIGNAL(triggered(bool)), this, SLOT(actionSourceSMFrames_triggered(bool)));
    m_ui->action_SourceSMBytes->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceSMBytes);
    connect(m_ui->action_SourceSMBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceSMBytes_triggered(bool)));
    m_ui->action_SourceSMFramesBytes->setChecked(false);
    m_source_context_menu->addAction(m_ui->action_SourceSMFramesBytes);
    connect(m_ui->action_SourceSMFramesBytes, SIGNAL(triggered(bool)), this, SLOT(actionSourceSMFramesBytes_triggered(bool)));
    m_ui->action_SourceSMRate->setChecked(true);
    m_source_context_menu->addAction(m_ui->action_SourceSMRate);
    connect(m_ui->action_SourceSMRate, SIGNAL(triggered(bool)), this, SLOT(actionSourceSMRate_triggered(bool)));

    m_source_header->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_source_header, SIGNAL(customContextMenuRequested(const QPoint &)), this, SLOT(custom_source_context_menuRequested(const QPoint &)));

    m_ui->sources_TreeWidget->setColumnHidden(Source_DataFramesBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataFramesBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFCountBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCount_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCountBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMFramesBytes_Column, true);

    connect(this, SIGNAL(accepted()), this, SLOT(closeDialog()));
    connect(this, SIGNAL(rejected()), this, SLOT(closeDialog()));
    fillTree();
}

LBMLBTRMTransportDialog::~LBMLBTRMTransportDialog(void)
{
    resetSourcesDetail();
    resetSources();
    resetReceiversDetail();
    resetReceivers();
    if (m_dialog_info != NULL)
    {
        delete m_dialog_info;
        m_dialog_info = NULL;
    }
    delete m_source_context_menu;
    m_source_context_menu = NULL;
    delete m_ui;
    m_ui = NULL;
    m_capture_file = NULL;
}

void LBMLBTRMTransportDialog::setCaptureFile(capture_file * cfile)
{
    if (cfile == NULL) // We only want to know when the file closes.
    {
        m_capture_file = NULL;
        m_ui->displayFilterLineEdit->setEnabled(false);
        m_ui->applyFilterButton->setEnabled(false);
    }
}

void LBMLBTRMTransportDialog::resetSources(void)
{
    while (m_ui->sources_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
}

void LBMLBTRMTransportDialog::resetReceivers(void)
{
    while (m_ui->receivers_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
}

void LBMLBTRMTransportDialog::resetSourcesDetail(void)
{
    while (m_ui->sources_detail_sqn_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    while (m_ui->sources_detail_ncf_sqn_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    m_ui->sources_detail_transport_Label->setText(QString(" "));
    m_current_source_transport = NULL;
}

void LBMLBTRMTransportDialog::resetReceiversDetail(void)
{
    while (m_ui->receivers_detail_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    m_ui->receivers_detail_transport_Label->setText(QString(" "));
    m_current_receiver_transport = NULL;
}

void LBMLBTRMTransportDialog::fillTree(void)
{
    GString * error_string;

    if (m_capture_file == NULL)
    {
        return;
    }
    m_dialog_info->setDialog(this);

    error_string = register_tap_listener("lbtrm",
        (void *)m_dialog_info,
        m_ui->displayFilterLineEdit->text().toUtf8().constData(),
        TL_REQUIRES_COLUMNS,
        resetTap,
        tapPacket,
        drawTreeItems);
    if (error_string)
    {
        QMessageBox::critical(this, tr("LBT-RM Statistics failed to attach to tap"),
            error_string->str);
        g_string_free(error_string, TRUE);
        reject();
    }

    cf_retap_packets(m_capture_file);
    drawTreeItems(&m_dialog_info);
    remove_tap_listener((void *)m_dialog_info);
}

void LBMLBTRMTransportDialog::resetTap(void * tap_data)
{
    LBMLBTRMTransportDialogInfo * info = (LBMLBTRMTransportDialogInfo *) tap_data;
    LBMLBTRMTransportDialog * dialog = info->getDialog();
    if (dialog == NULL)
    {
        return;
    }
    dialog->resetSourcesDetail();
    dialog->resetSources();
    dialog->resetReceiversDetail();
    dialog->resetReceivers();
    info->clearMaps();
}

gboolean LBMLBTRMTransportDialog::tapPacket(void * tap_data, packet_info * pinfo, epan_dissect_t * edt, const void * tap_info)
{
    Q_UNUSED(edt)

    if (pinfo->fd->flags.passed_dfilter == 1)
    {
        const lbm_lbtrm_tap_info_t * tapinfo = (const lbm_lbtrm_tap_info_t *)tap_info;
        LBMLBTRMTransportDialogInfo * info = (LBMLBTRMTransportDialogInfo *)tap_data;

        info->processPacket(pinfo, tapinfo);
    }
    return (TRUE);
}

void LBMLBTRMTransportDialog::drawTreeItems(void * tap_data)
{
    Q_UNUSED(tap_data)
}

void LBMLBTRMTransportDialog::on_applyFilterButton_clicked(void)
{
    fillTree();
}

void LBMLBTRMTransportDialog::closeDialog(void)
{
    delete this;
}

void LBMLBTRMTransportDialog::sourcesDetailCurrentChanged(int index)
{
    // Index 0: Data
    // Index 1: RX data
    // Index 2: NCF
    // Index 3: SM
    switch (index)
    {
        case 0:
        case 1:
        case 3:
            m_ui->stackedWidget->setCurrentIndex(0);
            break;
        case 2:
            m_ui->stackedWidget->setCurrentIndex(1);
            break;
        default:
            return;
    }
    sourcesItemClicked(m_current_source_transport, 0);
}

void LBMLBTRMTransportDialog::sourcesItemClicked(QTreeWidgetItem * item, int column)
{
    Q_UNUSED(column)

    LBMLBTRMSourceTransportEntry * transport = dynamic_cast<LBMLBTRMSourceTransportEntry *>(item);

    resetSourcesDetail();
    if (transport == NULL)
    {
        // Must be a source item, ignore it?
        return;
    }
    m_current_source_transport = transport;
    m_ui->sources_detail_transport_Label->setText(transport->m_transport);
    int cur_idx = m_ui->sources_detail_ComboBox->currentIndex();
    switch (cur_idx)
    {
        case 0:
            loadSourceDataDetails(transport);
            break;
        case 1:
            loadSourceRXDataDetails(transport);
            break;
        case 2:
            loadSourceNCFDetails(transport);
            break;
        case 3:
            loadSourceSMDetails(transport);
            break;
        default:
            break;
    }
}

void LBMLBTRMTransportDialog::loadSourceDataDetails(LBMLBTRMSourceTransportEntry * transport)
{
    for (LBMLBTRMSQNMapIterator it = transport->m_data_sqns.begin(); it != transport->m_data_sqns.end(); it++)
    {
        LBMLBTRMSQNEntry * sqn = it.value();
        m_ui->sources_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRMTransportDialog::loadSourceRXDataDetails(LBMLBTRMSourceTransportEntry * transport)
{
    for (LBMLBTRMSQNMapIterator it = transport->m_rx_data_sqns.begin(); it != transport->m_rx_data_sqns.end(); it++)
    {
        LBMLBTRMSQNEntry * sqn = it.value();
        m_ui->sources_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRMTransportDialog::loadSourceNCFDetails(LBMLBTRMSourceTransportEntry * transport)
{
    for (LBMLBTRMNCFSQNMapIterator it = transport->m_ncf_sqns.begin(); it != transport->m_ncf_sqns.end(); it++)
    {
        LBMLBTRMNCFSQNEntry * sqn = it.value();
        m_ui->sources_detail_ncf_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRMTransportDialog::loadSourceSMDetails(LBMLBTRMSourceTransportEntry * transport)
{
    for (LBMLBTRMSQNMapIterator it = transport->m_sm_sqns.begin(); it != transport->m_sm_sqns.end(); it++)
    {
        LBMLBTRMSQNEntry * sqn = it.value();
        m_ui->sources_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRMTransportDialog::receiversItemClicked(QTreeWidgetItem * item, int column)
{
    Q_UNUSED(column)

    LBMLBTRMReceiverTransportEntry * transport = dynamic_cast<LBMLBTRMReceiverTransportEntry *>(item);

    resetReceiversDetail();
    if (transport == NULL)
    {
        // Must be a receiver item, ignore it?
        return;
    }
    m_current_receiver_transport = transport;
    m_ui->receivers_detail_transport_Label->setText(transport->m_transport);
    loadReceiverNAKDetails(transport);
}

void LBMLBTRMTransportDialog::loadReceiverNAKDetails(LBMLBTRMReceiverTransportEntry * transport)
{
    for (LBMLBTRMSQNMapIterator it = transport->m_nak_sqns.begin(); it != transport->m_nak_sqns.end(); it++)
    {
        LBMLBTRMSQNEntry * sqn = it.value();
        m_ui->receivers_detail_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRMTransportDialog::sourcesDetailItemDoubleClicked(QTreeWidgetItem * item, int column)
{
    Q_UNUSED(column)

    LBMLBTRMFrameEntry * frame = dynamic_cast<LBMLBTRMFrameEntry *>(item);
    if (frame == NULL)
    {
        // Must have double-clicked on something other than an expanded frame entry
        return;
    }
    emit goToPacket((int)frame->getFrame());
}

void LBMLBTRMTransportDialog::receiversDetailItemDoubleClicked(QTreeWidgetItem * item, int column)
{
    Q_UNUSED(column)

    LBMLBTRMFrameEntry * frame = dynamic_cast<LBMLBTRMFrameEntry *>(item);
    if (frame == NULL)
    {
        // Must have double-clicked on something other than an expanded frame entry
        return;
    }
    emit goToPacket((int)frame->getFrame());
}

void LBMLBTRMTransportDialog::custom_source_context_menuRequested(const QPoint & pos)
{
    m_source_context_menu->exec(m_source_header->mapToGlobal(pos));
}

void LBMLBTRMTransportDialog::actionSourceDataFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataFrames_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceDataBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceDataFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataFramesBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceDataRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataRate_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceRXDataFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataFrames_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceRXDataBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceRXDataFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataFramesBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceRXDataRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataRate_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFrames_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFCount_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFCount_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFrames_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFCountBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFCountBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFFramesCount_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCount_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFFramesCountBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCountBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceNCFRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFRate_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceSMFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMFrames_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceSMBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceSMFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMFramesBytes_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceSMRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMRate_Column, !checked);
}

void LBMLBTRMTransportDialog::actionSourceAutoResizeColumns_triggered(void)
{
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_AddressTransport_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_DataFrames_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_DataBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_DataFramesBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_DataRate_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RXDataFrames_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RXDataBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RXDataFramesBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RXDataRate_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFFrames_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFCount_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFFramesBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFCountBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFFramesCount_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFFramesCountBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_NCFRate_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_SMFrames_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_SMBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_SMFramesBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_SMRate_Column);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
