/* lbm_lbtru_transport_dialog.cpp
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "lbm_lbtru_transport_dialog.h"
#include <ui_lbm_lbtru_transport_dialog.h>

#include "file.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"

#include <QClipboard>
#include <QMessageBox>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QMenu>
#include <QTreeWidgetItem>

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/to_str.h>
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
    static const int Source_RSTFrames_Column = 21;
    static const int Source_RSTBytes_Column = 22;
    static const int Source_RSTFramesBytes_Column = 23;
    static const int Source_RSTRate_Column = 24;

    static const int Receiver_AddressTransport_Column = 0;
    static const int Receiver_NAKFrames_Column = 1;
    static const int Receiver_NAKCount_Column = 2;
    static const int Receiver_NAKBytes_Column = 3;
    static const int Receiver_NAKFramesCount_Column = 4;
    static const int Receiver_NAKCountBytes_Column = 5;
    static const int Receiver_NAKFramesBytes_Column = 6;
    static const int Receiver_NAKFramesCountBytes_Column = 7;
    static const int Receiver_NAKRate_Column = 8;
    static const int Receiver_ACKFrames_Column = 9;
    static const int Receiver_ACKBytes_Column = 10;
    static const int Receiver_ACKFramesBytes_Column = 11;
    static const int Receiver_ACKRate_Column = 12;
    static const int Receiver_CREQFrames_Column = 13;
    static const int Receiver_CREQBytes_Column = 14;
    static const int Receiver_CREQFramesBytes_Column = 15;
    static const int Receiver_CREQRate_Column = 16;

    static const int Detail_SQNReasonType_Column = 0;
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
// LBMLBTRUFrameEntry, LBMLBTRUSQNEntry, LBMLBTRUNCFReasonEntry, LBMLBTRUNCFSQNEntry, LBMLBTRURSTReasonEntry, LBMLBTRUCREQRequestEntry,
// LBMLBTRUSourceTransportEntry, LBMLBTRUSourceEntry, LBMLBTRUReceiverTransportEntry, and LBMLBTRUReceiverEntry are all derived from
// a QTreeWidgetItem. Each instantiation can exist in two places: in a QTreeWidget, and in a containing QMap.
//
// For example:
// - LBMLBTRUTransportDialogInfo contains a QMap of the sources (LBMLBTRUSourceEntry) and receivers (LBMLBTRUReceiverEntry)
// - A source (LBMLBTRUSourceEntry) contains a QMap of the source transports originating from it (LBMLBTRUSourceTransportEntry)
// - A source transport (LBMLBTRUSourceTransportEntry) contains QMaps of data, RX data, and SM SQNs (LBMLBTRUSQNEntry), NCF SQNs
//   (LBMLBTRUNCFSQNEntry), and RST reasons (LBMLBTRURSTReasonEntry)
// - A data SQN (LBMLBTRUSQNEntry) contains a QMap of the frames (LBMLBTRUFrameEntry) in which that SQN appears
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
//      for (XXXMapIterator it = m_xxx.begin(); it != m_xxx.end(); ++it)
//      {
//          delete *it;
//      }
//      m_xxx.clear();
//    The for-loop calls the destructor for each item, while the clear() cleans up the space used by the QMap itself.

// A frame entry
class LBMLBTRUFrameEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRUFrameEntry(guint32 frame);
        virtual ~LBMLBTRUFrameEntry(void) { }
        guint32 getFrame(void) { return (m_frame); }

    private:
        guint32 m_frame;
};

LBMLBTRUFrameEntry::LBMLBTRUFrameEntry(guint32 frame) :
    QTreeWidgetItem(),
    m_frame(frame)
{
    setText(Detail_SQNReasonType_Column, QString(" "));
    setText(Detail_Count_Column, QString(" "));
    setText(Detail_Frame_Column, QString("%1").arg(m_frame));
}

typedef QMap<guint32, LBMLBTRUFrameEntry *> LBMLBTRUFrameMap;
typedef QMap<guint32, LBMLBTRUFrameEntry *>::iterator LBMLBTRUFrameMapIterator;

// An SQN (SeQuence Number) entry
class LBMLBTRUSQNEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRUSQNEntry(guint32 sqn);
        virtual ~LBMLBTRUSQNEntry(void);
        void processFrame(guint32 frame);

    private:
        LBMLBTRUSQNEntry(void);
        guint32 m_sqn;
        guint32 m_count;
        LBMLBTRUFrameMap m_frames;
};

LBMLBTRUSQNEntry::LBMLBTRUSQNEntry(guint32 sqn) :
    QTreeWidgetItem(),
    m_sqn(sqn),
    m_count(0),
    m_frames()
{
    setText(Detail_SQNReasonType_Column, QString("%1").arg(m_sqn));
    setTextAlignment(Detail_SQNReasonType_Column, Qt::AlignRight);
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRUSQNEntry::~LBMLBTRUSQNEntry(void)
{
    for (LBMLBTRUFrameMapIterator it = m_frames.begin(); it != m_frames.end(); ++it)
    {
        delete *it;
    }
    m_frames.clear();
}

void LBMLBTRUSQNEntry::processFrame(guint32 frame)
{
    LBMLBTRUFrameMapIterator it;

    it = m_frames.find(frame);
    if (m_frames.end() == it)
    {
        LBMLBTRUFrameEntry * entry = new LBMLBTRUFrameEntry(frame);
        m_frames.insert(frame, entry);
        addChild(entry);
        sortChildren(Detail_Frame_Column, Qt::AscendingOrder);
    }
    m_count++;
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
}

// An NCF (Nak ConFirmation) Reason entry
class LBMLBTRUNCFReasonEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRUNCFReasonEntry(guint8 reason);
        virtual ~LBMLBTRUNCFReasonEntry(void);
        void processFrame(guint32 frame);

    private:
        LBMLBTRUNCFReasonEntry(void);
        guint8 m_reason;
        guint32 m_count;
        LBMLBTRUFrameMap m_frames;
};

LBMLBTRUNCFReasonEntry::LBMLBTRUNCFReasonEntry(guint8 reason) :
    QTreeWidgetItem(),
    m_reason(reason),
    m_count(0),
    m_frames()
{
    switch (m_reason)
    {
        case LBTRU_NCF_REASON_NO_RETRY:
            setText(Detail_SQNReasonType_Column, QString("No Retry"));
            break;
        case LBTRU_NCF_REASON_IGNORED:
            setText(Detail_SQNReasonType_Column, QString("Ignored"));
            break;
        case LBTRU_NCF_REASON_RX_DELAY:
            setText(Detail_SQNReasonType_Column, QString("Retransmit Delay"));
            break;
        case LBTRU_NCF_REASON_SHED:
            setText(Detail_SQNReasonType_Column, QString("Shed"));
            break;
        default:
            setText(Detail_SQNReasonType_Column, QString("Unknown"));
            break;
    }
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRUNCFReasonEntry::~LBMLBTRUNCFReasonEntry(void)
{
    for (LBMLBTRUFrameMapIterator it = m_frames.begin(); it != m_frames.end(); ++it)
    {
        delete *it;
    }
    m_frames.clear();
}

void LBMLBTRUNCFReasonEntry::processFrame(guint32 frame)
{
    LBMLBTRUFrameMapIterator it;

    it = m_frames.find(frame);
    if (m_frames.end() == it)
    {
        LBMLBTRUFrameEntry * entry = new LBMLBTRUFrameEntry(frame);
        m_frames.insert(frame, entry);
        addChild(entry);
        sortChildren(Detail_Frame_Column, Qt::AscendingOrder);
    }
    m_count++;
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
}

typedef QMap<guint8, LBMLBTRUNCFReasonEntry *> LBMLBTRUNCFReasonMap;
typedef QMap<guint8, LBMLBTRUNCFReasonEntry *>::iterator LBMLBTRUNCFReasonMapIterator;

// An NCF SQN entry
class LBMLBTRUNCFSQNEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRUNCFSQNEntry(guint32 sqn);
        virtual ~LBMLBTRUNCFSQNEntry(void);
        void processFrame(guint8 reason, guint32 frame);

    private:
        LBMLBTRUNCFSQNEntry(void);
        guint32 m_sqn;
        guint32 m_count;
        LBMLBTRUNCFReasonMap m_reasons;
};

LBMLBTRUNCFSQNEntry::LBMLBTRUNCFSQNEntry(guint32 sqn) :
    QTreeWidgetItem(),
    m_sqn(sqn),
    m_count(0),
    m_reasons()
{
    setText(Detail_SQNReasonType_Column, QString("%1").arg(m_sqn));
    setTextAlignment(Detail_SQNReasonType_Column, Qt::AlignRight);
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRUNCFSQNEntry::~LBMLBTRUNCFSQNEntry(void)
{
    for (LBMLBTRUNCFReasonMapIterator it = m_reasons.begin(); it != m_reasons.end(); ++it)
    {
        delete *it;
    }
    m_reasons.clear();
}

void LBMLBTRUNCFSQNEntry::processFrame(guint8 reason, guint32 frame)
{
    LBMLBTRUNCFReasonMapIterator it;
    LBMLBTRUNCFReasonEntry * entry = NULL;

    it = m_reasons.find(reason);
    if (m_reasons.end() == it)
    {
        entry = new LBMLBTRUNCFReasonEntry(reason);
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

// An RST (ReSeT) Reason entry
class LBMLBTRURSTReasonEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRURSTReasonEntry(guint32 reason);
        virtual ~LBMLBTRURSTReasonEntry(void);
        void processFrame(guint32 frame);

    private:
        LBMLBTRURSTReasonEntry(void);
        guint32 m_reason;
        QString m_reason_string;
        guint32 m_count;
        LBMLBTRUFrameMap m_frames;
};

LBMLBTRURSTReasonEntry::LBMLBTRURSTReasonEntry(guint32 reason) :
    QTreeWidgetItem(),
    m_reason(reason),
    m_reason_string(),
    m_count(0),
    m_frames()
{
    switch (m_reason)
    {
        case LBTRU_RST_REASON_DEFAULT:
            m_reason_string = "Default";
            break;
        default:
            m_reason_string = QString("Unknown (%1)").arg(m_reason);
            break;
    }
    setText(Detail_SQNReasonType_Column, m_reason_string);
    setTextAlignment(Detail_SQNReasonType_Column, Qt::AlignLeft);
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRURSTReasonEntry::~LBMLBTRURSTReasonEntry(void)
{
    for (LBMLBTRUFrameMapIterator it = m_frames.begin(); it != m_frames.end(); ++it)
    {
        delete *it;
    }
    m_frames.clear();
}

void LBMLBTRURSTReasonEntry::processFrame(guint32 frame)
{
    LBMLBTRUFrameMapIterator it;

    it = m_frames.find(frame);
    if (m_frames.end() == it)
    {
        LBMLBTRUFrameEntry * entry = new LBMLBTRUFrameEntry(frame);
        m_frames.insert(frame, entry);
        addChild(entry);
        sortChildren(Detail_Frame_Column, Qt::AscendingOrder);
    }
    m_count++;
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
}

// A CREQ (Connection REQuest) Request entry
class LBMLBTRUCREQRequestEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRUCREQRequestEntry(guint32 request);
        virtual ~LBMLBTRUCREQRequestEntry(void);
        void processFrame(guint32 frame);

    private:
        LBMLBTRUCREQRequestEntry(void);
        guint32 m_request;
        QString m_request_string;
        guint32 m_count;
        LBMLBTRUFrameMap m_frames;
};

LBMLBTRUCREQRequestEntry::LBMLBTRUCREQRequestEntry(guint32 request) :
    QTreeWidgetItem(),
    m_request(request),
    m_request_string(),
    m_count(0),
    m_frames()
{
    switch (m_request)
    {
        case LBTRU_CREQ_REQUEST_SYN:
            m_request_string = "SYN";
            break;
        default:
            m_request_string = QString("Unknown (%1)").arg(m_request);
            break;
    }
    setText(Detail_SQNReasonType_Column, m_request_string);
    setTextAlignment(Detail_SQNReasonType_Column, Qt::AlignLeft);
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
    setText(Detail_Frame_Column, QString(" "));
}

LBMLBTRUCREQRequestEntry::~LBMLBTRUCREQRequestEntry(void)
{
    for (LBMLBTRUFrameMapIterator it = m_frames.begin(); it != m_frames.end(); ++it)
    {
        delete *it;
    }
    m_frames.clear();
}

void LBMLBTRUCREQRequestEntry::processFrame(guint32 frame)
{
    LBMLBTRUFrameMapIterator it;

    it = m_frames.find(frame);
    if (m_frames.end() == it)
    {
        LBMLBTRUFrameEntry * entry = new LBMLBTRUFrameEntry(frame);
        m_frames.insert(frame, entry);
        addChild(entry);
        sortChildren(Detail_Frame_Column, Qt::AscendingOrder);
    }
    m_count++;
    setText(Detail_Count_Column, QString("%1").arg(m_count));
    setTextAlignment(Detail_Count_Column, Qt::AlignRight);
}

typedef QMap<guint32, LBMLBTRUSQNEntry *> LBMLBTRUSQNMap;
typedef QMap<guint32, LBMLBTRUSQNEntry *>::iterator LBMLBTRUSQNMapIterator;
typedef QMap<guint32, LBMLBTRUNCFSQNEntry *> LBMLBTRUNCFSQNMap;
typedef QMap<guint32, LBMLBTRUNCFSQNEntry *>::iterator LBMLBTRUNCFSQNMapIterator;
typedef QMap<guint32, LBMLBTRURSTReasonEntry *> LBMLBTRURSTReasonMap;
typedef QMap<guint32, LBMLBTRURSTReasonEntry *>::iterator LBMLBTRURSTReasonMapIterator;
typedef QMap<guint32, LBMLBTRUCREQRequestEntry *> LBMLBTRUCREQRequestMap;
typedef QMap<guint32, LBMLBTRUCREQRequestEntry *>::iterator LBMLBTRUCREQRequestMapIterator;

// A source transport entry
class LBMLBTRUSourceTransportEntry : public QTreeWidgetItem
{
        friend class LBMLBTRUTransportDialog;

    public:
        LBMLBTRUSourceTransportEntry(const QString & transport);
        virtual ~LBMLBTRUSourceTransportEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info);

    protected:
        QString m_transport;

    private:
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
        guint64 m_rst_frames;
        guint64 m_rst_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;

    protected:
        LBMLBTRUSQNMap m_data_sqns;
        LBMLBTRUSQNMap m_rx_data_sqns;
        LBMLBTRUNCFSQNMap m_ncf_sqns;
        LBMLBTRUSQNMap m_sm_sqns;
        LBMLBTRURSTReasonMap m_rst_reasons;
};

LBMLBTRUSourceTransportEntry::LBMLBTRUSourceTransportEntry(const QString & transport) :
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
    m_rst_frames(0),
    m_rst_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_data_sqns(),
    m_rx_data_sqns(),
    m_ncf_sqns(),
    m_sm_sqns(),
    m_rst_reasons()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Source_AddressTransport_Column, m_transport);
}

LBMLBTRUSourceTransportEntry::~LBMLBTRUSourceTransportEntry(void)
{
    for (LBMLBTRUSQNMapIterator it = m_data_sqns.begin(); it != m_data_sqns.end(); ++it)
    {
        delete *it;
    }
    m_data_sqns.clear();

    for (LBMLBTRUSQNMapIterator it = m_rx_data_sqns.begin(); it != m_rx_data_sqns.end(); ++it)
    {
        delete *it;
    }
    m_rx_data_sqns.clear();

    for (LBMLBTRUNCFSQNMapIterator it = m_ncf_sqns.begin(); it != m_ncf_sqns.end(); ++it)
    {
        delete *it;
    }
    m_ncf_sqns.clear();

    for (LBMLBTRUSQNMapIterator it = m_sm_sqns.begin(); it != m_sm_sqns.end(); ++it)
    {
        delete *it;
    }
    m_sm_sqns.clear();

    for (LBMLBTRURSTReasonMapIterator it = m_rst_reasons.begin(); it != m_rst_reasons.end(); ++it)
    {
        delete *it;
    }
    m_rst_reasons.clear();
}

void LBMLBTRUSourceTransportEntry::processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info)
{
    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->abs_ts));
    }
    if (tap_info->type == LBTRU_PACKET_TYPE_DATA)
    {
        LBMLBTRUSQNEntry * sqn = NULL;
        LBMLBTRUSQNMapIterator it;

        if (tap_info->retransmission)
        {
            m_rx_data_frames++;
            m_rx_data_bytes += pinfo->fd->pkt_len;
            it = m_rx_data_sqns.find(tap_info->sqn);
            if (m_rx_data_sqns.end() == it)
            {
                sqn = new LBMLBTRUSQNEntry(tap_info->sqn);
                m_rx_data_sqns.insert(tap_info->sqn, sqn);
            }
            else
            {
                sqn = it.value();
            }
            sqn->processFrame(pinfo->num);
        }
        else
        {
            m_data_frames++;
            m_data_bytes += pinfo->fd->pkt_len;
            it = m_data_sqns.find(tap_info->sqn);
            if (m_data_sqns.end() == it)
            {
                sqn = new LBMLBTRUSQNEntry(tap_info->sqn);
                m_data_sqns.insert(tap_info->sqn, sqn);
            }
            else
            {
                sqn = it.value();
            }
        }
        sqn->processFrame(pinfo->num);
    }
    else if (tap_info->type == LBTRU_PACKET_TYPE_NCF)
    {
        guint16 idx;
        LBMLBTRUNCFSQNMapIterator it;
        LBMLBTRUNCFSQNEntry * sqn = NULL;

        m_ncf_frames++;
        m_ncf_bytes += pinfo->fd->pkt_len;
        m_ncf_count += (guint64)tap_info->num_sqns;
        for (idx = 0; idx < tap_info->num_sqns; idx++)
        {
            it = m_ncf_sqns.find(tap_info->sqns[idx]);
            if (m_ncf_sqns.end() == it)
            {
                sqn = new LBMLBTRUNCFSQNEntry(tap_info->sqns[idx]);
                m_ncf_sqns.insert(tap_info->sqns[idx], sqn);
            }
            else
            {
                sqn = it.value();
            }
            sqn->processFrame(tap_info->ncf_reason, pinfo->num);
        }
    }
    else if (tap_info->type == LBTRU_PACKET_TYPE_SM)
    {
        LBMLBTRUSQNEntry * sqn = NULL;
        LBMLBTRUSQNMapIterator it;

        m_sm_frames++;
        m_sm_bytes += pinfo->fd->pkt_len;
        it = m_sm_sqns.find(tap_info->sqn);
        if (m_sm_sqns.end() == it)
        {
            sqn = new LBMLBTRUSQNEntry(tap_info->sqn);
            m_sm_sqns.insert(tap_info->sqn, sqn);
        }
        else
        {
            sqn = it.value();
        }
        sqn->processFrame(pinfo->num);
    }
    else if (tap_info->type == LBTRU_PACKET_TYPE_RST)
    {
        LBMLBTRURSTReasonEntry * reason = NULL;
        LBMLBTRURSTReasonMapIterator it;

        m_rst_frames++;
        m_rst_bytes += pinfo->fd->pkt_len;
        it = m_rst_reasons.find(tap_info->rst_type);
        if (m_rst_reasons.end() == it)
        {
            reason = new LBMLBTRURSTReasonEntry(tap_info->rst_type);
            m_rst_reasons.insert((unsigned int) tap_info->rst_type, reason);
        }
        else
        {
            reason = it.value();
        }
        reason->processFrame(pinfo->num);
    }
    else
    {
        return;
    }
    fillItem();
}

void LBMLBTRUSourceTransportEntry::fillItem(void)
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
    setText(Source_RSTFrames_Column, QString("%1").arg(m_rst_frames));
    setTextAlignment(Source_RSTFrames_Column, Qt::AlignRight);
    setText(Source_RSTBytes_Column, QString("%1").arg(m_rst_bytes));
    setTextAlignment(Source_RSTBytes_Column, Qt::AlignRight);
    setText(Source_RSTFramesBytes_Column, QString("%1/%2").arg(m_rst_frames).arg(m_rst_bytes));
    setTextAlignment(Source_RSTFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_RSTRate_Column, format_rate(delta, m_rst_bytes));
    setTextAlignment(Source_RSTRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRUSourceTransportEntry *> LBMLBTRUSourceTransportMap;
typedef QMap<QString, LBMLBTRUSourceTransportEntry *>::iterator LBMLBTRUSourceTransportMapIterator;

// A source (address) entry
class LBMLBTRUSourceEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRUSourceEntry(const QString & source_address);
        virtual ~LBMLBTRUSourceEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info);

    private:
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
        guint64 m_rst_frames;
        guint64 m_rst_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;
        LBMLBTRUSourceTransportMap m_transports;
};

LBMLBTRUSourceEntry::LBMLBTRUSourceEntry(const QString & source_address) :
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
    m_rst_frames(0),
    m_rst_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_transports()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Source_AddressTransport_Column, m_address);
}

LBMLBTRUSourceEntry::~LBMLBTRUSourceEntry(void)
{
    for (LBMLBTRUSourceTransportMapIterator it = m_transports.begin(); it != m_transports.end(); ++it)
    {
        delete *it;
    }
    m_transports.clear();
}

void LBMLBTRUSourceEntry::processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info)
{
    LBMLBTRUSourceTransportEntry * transport = NULL;
    LBMLBTRUSourceTransportMapIterator it;

    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->abs_ts));
    }
    switch (tap_info->type)
    {
        case LBTRU_PACKET_TYPE_DATA:
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
            break;
        case LBTRU_PACKET_TYPE_NCF:
            m_ncf_frames++;
            m_ncf_bytes += pinfo->fd->pkt_len;
            m_ncf_count += tap_info->num_sqns;
            break;
        case LBTRU_PACKET_TYPE_SM:
            m_sm_frames++;
            m_sm_bytes += pinfo->fd->pkt_len;
            break;
        case LBTRU_PACKET_TYPE_RST:
            m_rst_frames++;
            m_rst_bytes += pinfo->fd->pkt_len;
            break;
    }

    it = m_transports.find(tap_info->transport);
    if (m_transports.end() == it)
    {
        transport = new LBMLBTRUSourceTransportEntry(tap_info->transport);
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

void LBMLBTRUSourceEntry::fillItem(void)
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
    setText(Source_RSTFrames_Column, QString("%1").arg(m_rst_frames));
    setTextAlignment(Source_RSTFrames_Column, Qt::AlignRight);
    setText(Source_RSTBytes_Column, QString("%1").arg(m_rst_bytes));
    setTextAlignment(Source_RSTBytes_Column, Qt::AlignRight);
    setText(Source_RSTFramesBytes_Column, QString("%1/%2").arg(m_rst_frames).arg(m_rst_bytes));
    setTextAlignment(Source_RSTFramesBytes_Column, Qt::AlignHCenter);
    setText(Source_RSTRate_Column, format_rate(delta, m_rst_bytes));
    setTextAlignment(Source_RSTRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRUSourceEntry *> LBMLBTRUSourceMap;
typedef QMap<QString, LBMLBTRUSourceEntry *>::iterator LBMLBTRUSourceMapIterator;

// A receiver transport entry
class LBMLBTRUReceiverTransportEntry : public QTreeWidgetItem
{
        friend class LBMLBTRUTransportDialog;

    public:
        LBMLBTRUReceiverTransportEntry(const QString & transport);
        virtual ~LBMLBTRUReceiverTransportEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info);

    private:
        void fillItem(void);
        QString m_transport;
        guint64 m_nak_frames;
        guint64 m_nak_count;
        guint64 m_nak_bytes;
        guint64 m_ack_frames;
        guint64 m_ack_bytes;
        guint64 m_creq_frames;
        guint64 m_creq_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;

    protected:
        LBMLBTRUSQNMap m_nak_sqns;
        LBMLBTRUSQNMap m_ack_sqns;
        LBMLBTRUCREQRequestMap m_creq_requests;
};

LBMLBTRUReceiverTransportEntry::LBMLBTRUReceiverTransportEntry(const QString & transport) :
    QTreeWidgetItem(),
    m_transport(transport),
    m_nak_frames(0),
    m_nak_count(0),
    m_nak_bytes(0),
    m_ack_frames(0),
    m_ack_bytes(0),
    m_creq_frames(0),
    m_creq_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_nak_sqns(),
    m_ack_sqns(),
    m_creq_requests()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Receiver_AddressTransport_Column, m_transport);
}

LBMLBTRUReceiverTransportEntry::~LBMLBTRUReceiverTransportEntry(void)
{
    for (LBMLBTRUSQNMapIterator it = m_nak_sqns.begin(); it != m_nak_sqns.end(); ++it)
    {
        delete *it;
    }
    m_nak_sqns.clear();

    for (LBMLBTRUSQNMapIterator it = m_ack_sqns.begin(); it != m_ack_sqns.end(); ++it)
    {
        delete *it;
    }
    m_ack_sqns.clear();

    for (LBMLBTRUCREQRequestMapIterator it = m_creq_requests.begin(); it != m_creq_requests.end(); ++it)
    {
        delete *it;
    }
    m_creq_requests.clear();
}

void LBMLBTRUReceiverTransportEntry::processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info)
{
    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->abs_ts));
    }
    switch (tap_info->type)
    {
        case LBTRU_PACKET_TYPE_NAK:
            {
                guint16 idx;
                LBMLBTRUSQNEntry * sqn = NULL;
                LBMLBTRUSQNMapIterator it;

                m_nak_frames++;
                m_nak_bytes += pinfo->fd->pkt_len;
                m_nak_count += tap_info->num_sqns;
                for (idx = 0; idx < tap_info->num_sqns; idx++)
                {
                    it = m_nak_sqns.find(tap_info->sqns[idx]);
                    if (m_nak_sqns.end() == it)
                    {
                        sqn = new LBMLBTRUSQNEntry(tap_info->sqns[idx]);
                        m_nak_sqns.insert(tap_info->sqns[idx], sqn);
                    }
                    else
                    {
                        sqn = it.value();
                    }
                    sqn->processFrame(pinfo->num);
                }
            }
            break;
        case LBTRU_PACKET_TYPE_ACK:
            {
                LBMLBTRUSQNEntry * sqn = NULL;
                LBMLBTRUSQNMapIterator it;

                m_ack_frames++;
                m_ack_bytes += pinfo->fd->pkt_len;
                it = m_ack_sqns.find(tap_info->sqn);
                if (m_ack_sqns.end() == it)
                {
                    sqn = new LBMLBTRUSQNEntry(tap_info->sqn);
                    m_ack_sqns.insert(tap_info->sqn, sqn);
                }
                else
                {
                    sqn = it.value();
                }
                sqn->processFrame(pinfo->num);
            }
            break;
        case LBTRU_PACKET_TYPE_CREQ:
            {
                LBMLBTRUCREQRequestEntry * req = NULL;
                LBMLBTRUCREQRequestMapIterator it;

                m_creq_frames++;
                m_creq_bytes += pinfo->fd->pkt_len;
                it = m_creq_requests.find(tap_info->creq_type);
                if (m_creq_requests.end() == it)
                {
                    req = new LBMLBTRUCREQRequestEntry(tap_info->creq_type);
                    m_creq_requests.insert(tap_info->creq_type, req);
                }
                else
                {
                    req = it.value();
                }
                req->processFrame(pinfo->num);
            }
            break;
        default:
            return;
            break;
    }
    fillItem();
}

void LBMLBTRUReceiverTransportEntry::fillItem(void)
{
    nstime_t delta;

    nstime_delta(&delta, &m_last_frame_timestamp, &m_first_frame_timestamp);
    setText(Receiver_NAKFrames_Column, QString("%1").arg(m_nak_frames));
    setTextAlignment(Receiver_NAKFrames_Column, Qt::AlignRight);
    setText(Receiver_NAKCount_Column, QString("%1").arg(m_nak_count));
    setTextAlignment(Receiver_NAKCount_Column, Qt::AlignRight);
    setText(Receiver_NAKBytes_Column, QString("%1").arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKBytes_Column, Qt::AlignRight);
    setText(Receiver_NAKFramesCount_Column, QString("%1/%2").arg(m_nak_frames).arg(m_nak_count));
    setTextAlignment(Receiver_NAKFramesCount_Column, Qt::AlignHCenter);
    setText(Receiver_NAKCountBytes_Column, QString("%1/%2").arg(m_nak_count).arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKCountBytes_Column, Qt::AlignHCenter);
    setText(Receiver_NAKFramesBytes_Column, QString("%1/%2").arg(m_nak_frames).arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKFramesBytes_Column, Qt::AlignHCenter);
    setText(Receiver_NAKFramesCountBytes_Column, QString("%1/%2/%3").arg(m_nak_frames).arg(m_nak_count).arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKFramesCountBytes_Column, Qt::AlignHCenter);
    setText(Receiver_NAKRate_Column, format_rate(delta, m_nak_bytes));
    setTextAlignment(Receiver_NAKRate_Column, Qt::AlignRight);
    setText(Receiver_ACKFrames_Column, QString("%1").arg(m_ack_frames));
    setTextAlignment(Receiver_ACKFrames_Column, Qt::AlignRight);
    setText(Receiver_ACKBytes_Column, QString("%1").arg(m_ack_bytes));
    setTextAlignment(Receiver_ACKBytes_Column, Qt::AlignRight);
    setText(Receiver_ACKFramesBytes_Column, QString("%1/%2").arg(m_ack_frames).arg(m_ack_bytes));
    setTextAlignment(Receiver_ACKFramesBytes_Column, Qt::AlignHCenter);
    setText(Receiver_ACKRate_Column, format_rate(delta, m_ack_bytes));
    setTextAlignment(Receiver_ACKRate_Column, Qt::AlignRight);
    setText(Receiver_CREQFrames_Column, QString("%1").arg(m_creq_frames));
    setTextAlignment(Receiver_CREQFrames_Column, Qt::AlignRight);
    setText(Receiver_CREQBytes_Column, QString("%1").arg(m_creq_bytes));
    setTextAlignment(Receiver_CREQBytes_Column, Qt::AlignRight);
    setText(Receiver_CREQFramesBytes_Column, QString("%1/%2").arg(m_creq_frames).arg(m_creq_bytes));
    setTextAlignment(Receiver_CREQFramesBytes_Column, Qt::AlignHCenter);
    setText(Receiver_CREQRate_Column, format_rate(delta, m_creq_bytes));
    setTextAlignment(Receiver_CREQRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRUReceiverTransportEntry *> LBMLBTRUReceiverTransportMap;
typedef QMap<QString, LBMLBTRUReceiverTransportEntry *>::iterator LBMLBTRUReceiverTransportMapIterator;

// A receiver (address) entry
class LBMLBTRUReceiverEntry : public QTreeWidgetItem
{
    public:
        LBMLBTRUReceiverEntry(const QString & receiver_address);
        virtual ~LBMLBTRUReceiverEntry(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info);

    private:
        void fillItem(void);
        QString m_address;
        QString m_transport;
        guint64 m_nak_frames;
        guint64 m_nak_count;
        guint64 m_nak_bytes;
        guint64 m_ack_frames;
        guint64 m_ack_bytes;
        guint64 m_creq_frames;
        guint64 m_creq_bytes;
        nstime_t m_first_frame_timestamp;
        bool m_first_frame_timestamp_valid;
        nstime_t m_last_frame_timestamp;
        LBMLBTRUReceiverTransportMap m_transports;
};

LBMLBTRUReceiverEntry::LBMLBTRUReceiverEntry(const QString & receiver_address) :
    QTreeWidgetItem(),
    m_address(receiver_address),
    m_nak_frames(0),
    m_nak_count(0),
    m_nak_bytes(0),
    m_ack_frames(0),
    m_ack_bytes(0),
    m_creq_frames(0),
    m_creq_bytes(0),
    m_first_frame_timestamp_valid(false),
    m_transports()
{
    m_first_frame_timestamp.secs = 0;
    m_first_frame_timestamp.nsecs = 0;
    m_last_frame_timestamp.secs = 0;
    m_last_frame_timestamp.nsecs = 0;
    setText(Receiver_AddressTransport_Column, m_address);
}

LBMLBTRUReceiverEntry::~LBMLBTRUReceiverEntry(void)
{
    for (LBMLBTRUReceiverTransportMapIterator it = m_transports.begin(); it != m_transports.end(); ++it)
    {
        delete *it;
    }
    m_transports.clear();
}

void LBMLBTRUReceiverEntry::processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info)
{
    LBMLBTRUReceiverTransportEntry * transport = NULL;
    LBMLBTRUReceiverTransportMapIterator it;

    if (m_first_frame_timestamp_valid)
    {
        if (nstime_cmp(&(pinfo->abs_ts), &m_first_frame_timestamp) < 0)
        {
            nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        }
    }
    else
    {
        nstime_copy(&(m_first_frame_timestamp), &(pinfo->abs_ts));
        m_first_frame_timestamp_valid = true;
    }
    if (nstime_cmp(&(pinfo->abs_ts), &m_last_frame_timestamp) > 0)
    {
        nstime_copy(&(m_last_frame_timestamp), &(pinfo->abs_ts));
    }
    switch (tap_info->type)
    {
        case LBTRU_PACKET_TYPE_NAK:
            m_nak_frames++;
            m_nak_bytes += pinfo->fd->pkt_len;
            m_nak_count += tap_info->num_sqns;
            break;
        case LBTRU_PACKET_TYPE_ACK:
            m_ack_frames++;
            m_ack_bytes += pinfo->fd->pkt_len;
            break;
        case LBTRU_PACKET_TYPE_CREQ:
            m_creq_frames++;
            m_creq_bytes += pinfo->fd->pkt_len;
            break;
    }

    it = m_transports.find(tap_info->transport);
    if (m_transports.end() == it)
    {
        transport = new LBMLBTRUReceiverTransportEntry(tap_info->transport);
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

void LBMLBTRUReceiverEntry::fillItem(void)
{
    nstime_t delta;

    nstime_delta(&delta, &m_last_frame_timestamp, &m_first_frame_timestamp);
    setText(Receiver_NAKFrames_Column, QString("%1").arg(m_nak_frames));
    setTextAlignment(Receiver_NAKFrames_Column, Qt::AlignRight);
    setText(Receiver_NAKCount_Column, QString("%1").arg(m_nak_count));
    setTextAlignment(Receiver_NAKCount_Column, Qt::AlignRight);
    setText(Receiver_NAKBytes_Column, QString("%1").arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKBytes_Column, Qt::AlignRight);
    setText(Receiver_NAKFramesCount_Column, QString("%1/%2").arg(m_nak_frames).arg(m_nak_count));
    setTextAlignment(Receiver_NAKFramesCount_Column, Qt::AlignHCenter);
    setText(Receiver_NAKCountBytes_Column, QString("%1/%2").arg(m_nak_count).arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKCountBytes_Column, Qt::AlignHCenter);
    setText(Receiver_NAKFramesBytes_Column, QString("%1/%2").arg(m_nak_frames).arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKFramesBytes_Column, Qt::AlignHCenter);
    setText(Receiver_NAKFramesCountBytes_Column, QString("%1/%2/%3").arg(m_nak_frames).arg(m_nak_count).arg(m_nak_bytes));
    setTextAlignment(Receiver_NAKFramesCountBytes_Column, Qt::AlignHCenter);
    setText(Receiver_NAKRate_Column, format_rate(delta, m_nak_bytes));
    setTextAlignment(Receiver_NAKRate_Column, Qt::AlignRight);
    setText(Receiver_ACKFrames_Column, QString("%1").arg(m_ack_frames));
    setTextAlignment(Receiver_ACKFrames_Column, Qt::AlignRight);
    setText(Receiver_ACKBytes_Column, QString("%1").arg(m_ack_bytes));
    setTextAlignment(Receiver_ACKBytes_Column, Qt::AlignRight);
    setText(Receiver_ACKFramesBytes_Column, QString("%1/%2").arg(m_ack_frames).arg(m_ack_bytes));
    setTextAlignment(Receiver_ACKFramesBytes_Column, Qt::AlignHCenter);
    setText(Receiver_ACKRate_Column, format_rate(delta, m_ack_bytes));
    setTextAlignment(Receiver_ACKRate_Column, Qt::AlignRight);
    setText(Receiver_CREQFrames_Column, QString("%1").arg(m_creq_frames));
    setTextAlignment(Receiver_CREQFrames_Column, Qt::AlignRight);
    setText(Receiver_CREQBytes_Column, QString("%1").arg(m_creq_bytes));
    setTextAlignment(Receiver_CREQBytes_Column, Qt::AlignRight);
    setText(Receiver_CREQFramesBytes_Column, QString("%1/%2").arg(m_creq_frames).arg(m_creq_bytes));
    setTextAlignment(Receiver_CREQFramesBytes_Column, Qt::AlignHCenter);
    setText(Receiver_CREQRate_Column, format_rate(delta, m_creq_bytes));
    setTextAlignment(Receiver_CREQRate_Column, Qt::AlignRight);
}

typedef QMap<QString, LBMLBTRUReceiverEntry *> LBMLBTRUReceiverMap;
typedef QMap<QString, LBMLBTRUReceiverEntry *>::iterator LBMLBTRUReceiverMapIterator;

class LBMLBTRUTransportDialogInfo
{
    public:
        LBMLBTRUTransportDialogInfo(void);
        ~LBMLBTRUTransportDialogInfo(void);
        void setDialog(LBMLBTRUTransportDialog * dialog);
        LBMLBTRUTransportDialog * getDialog(void);
        void processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info);
        void clearMaps(void);

    private:
        LBMLBTRUTransportDialog * m_dialog;
        LBMLBTRUSourceMap m_sources;
        LBMLBTRUReceiverMap m_receivers;
};

LBMLBTRUTransportDialogInfo::LBMLBTRUTransportDialogInfo(void) :
    m_dialog(NULL),
    m_sources(),
    m_receivers()
{
}

LBMLBTRUTransportDialogInfo::~LBMLBTRUTransportDialogInfo(void)
{
    clearMaps();
}

void LBMLBTRUTransportDialogInfo::setDialog(LBMLBTRUTransportDialog * dialog)
{
    m_dialog = dialog;
}

LBMLBTRUTransportDialog * LBMLBTRUTransportDialogInfo::getDialog(void)
{
    return (m_dialog);
}

void LBMLBTRUTransportDialogInfo::processPacket(const packet_info * pinfo, const lbm_lbtru_tap_info_t * tap_info)
{
    switch (tap_info->type)
    {
        case LBTRU_PACKET_TYPE_DATA:
        case LBTRU_PACKET_TYPE_SM:
        case LBTRU_PACKET_TYPE_NCF:
        case LBTRU_PACKET_TYPE_RST:
            {
                LBMLBTRUSourceEntry * source = NULL;
                LBMLBTRUSourceMapIterator it;
                QString src_address = address_to_qstring(&(pinfo->src));

                it = m_sources.find(src_address);
                if (m_sources.end() == it)
                {
                    QTreeWidgetItem * parent = NULL;
                    Ui::LBMLBTRUTransportDialog * ui = NULL;

                    source = new LBMLBTRUSourceEntry(src_address);
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
        case LBTRU_PACKET_TYPE_NAK:
        case LBTRU_PACKET_TYPE_ACK:
        case LBTRU_PACKET_TYPE_CREQ:
            {
                LBMLBTRUReceiverEntry * receiver = NULL;
                LBMLBTRUReceiverMapIterator it;
                QString src_address = address_to_qstring(&(pinfo->src));

                it = m_receivers.find(src_address);
                if (m_receivers.end() == it)
                {
                    QTreeWidgetItem * parent = NULL;
                    Ui::LBMLBTRUTransportDialog * ui = NULL;

                    receiver = new LBMLBTRUReceiverEntry(src_address);
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

void LBMLBTRUTransportDialogInfo::clearMaps(void)
{
    for (LBMLBTRUSourceMapIterator it = m_sources.begin(); it != m_sources.end(); ++it)
    {
        delete *it;
    }
    m_sources.clear();

    for (LBMLBTRUReceiverMapIterator it = m_receivers.begin(); it != m_receivers.end(); ++it)
    {
        delete *it;
    }
    m_receivers.clear();
}

LBMLBTRUTransportDialog::LBMLBTRUTransportDialog(QWidget * parent, capture_file * cfile) :
    QDialog(parent),
    m_ui(new Ui::LBMLBTRUTransportDialog),
    m_dialog_info(NULL),
    m_capture_file(cfile),
    m_current_source_transport(NULL),
    m_current_receiver_transport(NULL),
    m_source_context_menu(NULL),
    m_source_header(NULL)
{
    m_ui->setupUi(this);

    m_dialog_info = new LBMLBTRUTransportDialogInfo();
    m_ui->tabWidget->setCurrentIndex(0);
    m_ui->sources_detail_ComboBox->setCurrentIndex(0);
    m_ui->sources_detail_transport_Label->setText(QString(" "));
    m_ui->sources_stackedWidget->setCurrentIndex(0);
    m_ui->receivers_detail_ComboBox->setCurrentIndex(0);
    m_ui->receivers_detail_transport_Label->setText(QString(" "));
    m_ui->receivers_stackedWidget->setCurrentIndex(0);

    // Setup the source context menu
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

    // Setup the receiver context menu
    m_receiver_header = m_ui->receivers_TreeWidget->header();
    m_receiver_context_menu = new QMenu(m_receiver_header);

    m_receiver_context_menu->addAction(m_ui->action_ReceiverAutoResizeColumns);
    connect(m_ui->action_ReceiverAutoResizeColumns, SIGNAL(triggered()), this, SLOT(actionReceiverAutoResizeColumns_triggered()));
    m_receiver_context_menu->addSeparator();

    m_ui->action_ReceiverNAKFrames->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKFrames);
    connect(m_ui->action_ReceiverNAKFrames, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKFrames_triggered(bool)));
    m_ui->action_ReceiverNAKCount->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKCount);
    connect(m_ui->action_ReceiverNAKCount, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKCount_triggered(bool)));
    m_ui->action_ReceiverNAKBytes->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKBytes);
    connect(m_ui->action_ReceiverNAKBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKBytes_triggered(bool)));
    m_ui->action_ReceiverNAKFramesBytes->setChecked(false);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKFramesBytes);
    connect(m_ui->action_ReceiverNAKFramesBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKFramesBytes_triggered(bool)));
    m_ui->action_ReceiverNAKCountBytes->setChecked(false);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKCountBytes);
    connect(m_ui->action_ReceiverNAKCountBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKCountBytes_triggered(bool)));
    m_ui->action_ReceiverNAKFramesCount->setChecked(false);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKFramesCount);
    connect(m_ui->action_ReceiverNAKFramesCount, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKFramesCount_triggered(bool)));
    m_ui->action_ReceiverNAKFramesCountBytes->setChecked(false);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKFramesCountBytes);
    connect(m_ui->action_ReceiverNAKFramesCountBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKFramesCountBytes_triggered(bool)));
    m_ui->action_ReceiverNAKRate->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverNAKRate);
    connect(m_ui->action_ReceiverNAKRate, SIGNAL(triggered(bool)), this, SLOT(actionReceiverNAKRate_triggered(bool)));

    m_ui->action_ReceiverACKFrames->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverACKFrames);
    connect(m_ui->action_ReceiverACKFrames, SIGNAL(triggered(bool)), this, SLOT(actionReceiverACKFrames_triggered(bool)));
    m_ui->action_ReceiverACKBytes->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverACKBytes);
    connect(m_ui->action_ReceiverACKBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverACKBytes_triggered(bool)));
    m_ui->action_ReceiverACKFramesBytes->setChecked(false);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverACKFramesBytes);
    connect(m_ui->action_ReceiverACKFramesBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverACKFramesBytes_triggered(bool)));
    m_ui->action_ReceiverACKRate->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverACKRate);
    connect(m_ui->action_ReceiverACKRate, SIGNAL(triggered(bool)), this, SLOT(actionReceiverACKRate_triggered(bool)));

    m_ui->action_ReceiverCREQFrames->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverCREQFrames);
    connect(m_ui->action_ReceiverCREQFrames, SIGNAL(triggered(bool)), this, SLOT(actionReceiverCREQFrames_triggered(bool)));
    m_ui->action_ReceiverCREQBytes->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverCREQBytes);
    connect(m_ui->action_ReceiverCREQBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverCREQBytes_triggered(bool)));
    m_ui->action_ReceiverCREQFramesBytes->setChecked(false);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverCREQFramesBytes);
    connect(m_ui->action_ReceiverCREQFramesBytes, SIGNAL(triggered(bool)), this, SLOT(actionReceiverCREQFramesBytes_triggered(bool)));
    m_ui->action_ReceiverCREQRate->setChecked(true);
    m_receiver_context_menu->addAction(m_ui->action_ReceiverCREQRate);
    connect(m_ui->action_ReceiverCREQRate, SIGNAL(triggered(bool)), this, SLOT(actionReceiverCREQRate_triggered(bool)));

    m_receiver_header->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_receiver_header, SIGNAL(customContextMenuRequested(const QPoint &)), this, SLOT(custom_receiver_context_menuRequested(const QPoint &)));

    // Setup the source tree widget header
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataFramesBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataFramesBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFCountBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCount_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCountBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMFramesBytes_Column, true);
    m_ui->sources_TreeWidget->setColumnHidden(Source_RSTFramesBytes_Column, true);

    // Setup the receiver tree widget header
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKFramesBytes_Column, true);
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKCountBytes_Column, true);
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKFramesCount_Column, true);
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKFramesCountBytes_Column, true);
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_ACKFramesBytes_Column, true);
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_CREQFramesBytes_Column, true);

    connect(this, SIGNAL(accepted()), this, SLOT(closeDialog()));
    connect(this, SIGNAL(rejected()), this, SLOT(closeDialog()));
    fillTree();
}

LBMLBTRUTransportDialog::~LBMLBTRUTransportDialog(void)
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

void LBMLBTRUTransportDialog::setCaptureFile(capture_file * cfile)
{
    if (cfile == NULL) // We only want to know when the file closes.
    {
        m_capture_file = NULL;
        m_ui->displayFilterLineEdit->setEnabled(false);
        m_ui->applyFilterButton->setEnabled(false);
    }
}

void LBMLBTRUTransportDialog::resetSources(void)
{
    while (m_ui->sources_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
}

void LBMLBTRUTransportDialog::resetReceivers(void)
{
    while (m_ui->receivers_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
}

void LBMLBTRUTransportDialog::resetSourcesDetail(void)
{
    while (m_ui->sources_detail_sqn_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    while (m_ui->sources_detail_ncf_sqn_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    while (m_ui->sources_detail_rst_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    m_ui->sources_detail_transport_Label->setText(QString(" "));
    m_current_source_transport = NULL;
}

void LBMLBTRUTransportDialog::resetReceiversDetail(void)
{
    while (m_ui->receivers_detail_sqn_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    while (m_ui->receivers_detail_reason_TreeWidget->takeTopLevelItem(0) != NULL)
    {}
    m_ui->receivers_detail_transport_Label->setText(QString(" "));
    m_current_receiver_transport = NULL;
}

void LBMLBTRUTransportDialog::fillTree(void)
{
    GString * error_string;

    if (m_capture_file == NULL)
    {
        return;
    }
    m_dialog_info->setDialog(this);

    error_string = register_tap_listener("lbm_lbtru",
        (void *)m_dialog_info,
        m_ui->displayFilterLineEdit->text().toUtf8().constData(),
        TL_REQUIRES_COLUMNS,
        resetTap,
        tapPacket,
        drawTreeItems,
        NULL);
    if (error_string)
    {
        QMessageBox::critical(this, tr("LBT-RU Statistics failed to attach to tap"),
            error_string->str);
        g_string_free(error_string, TRUE);
        reject();
    }

    cf_retap_packets(m_capture_file);
    drawTreeItems(&m_dialog_info);
    remove_tap_listener((void *)m_dialog_info);
}

void LBMLBTRUTransportDialog::resetTap(void * tap_data)
{
    LBMLBTRUTransportDialogInfo * info = (LBMLBTRUTransportDialogInfo *)tap_data;
    LBMLBTRUTransportDialog * dialog = info->getDialog();
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

tap_packet_status LBMLBTRUTransportDialog::tapPacket(void * tap_data, packet_info * pinfo, epan_dissect_t *, const void * tap_info, tap_flags_t)
{
    if (pinfo->fd->passed_dfilter == 1)
    {
        const lbm_lbtru_tap_info_t * tapinfo = (const lbm_lbtru_tap_info_t *)tap_info;
        LBMLBTRUTransportDialogInfo * info = (LBMLBTRUTransportDialogInfo *)tap_data;

        info->processPacket(pinfo, tapinfo);
    }
    return (TAP_PACKET_REDRAW);
}

void LBMLBTRUTransportDialog::drawTreeItems(void *)
{
}

void LBMLBTRUTransportDialog::on_applyFilterButton_clicked(void)
{
    fillTree();
}

void LBMLBTRUTransportDialog::closeDialog(void)
{
    delete this;
}

void LBMLBTRUTransportDialog::sourcesDetailCurrentChanged(int index)
{
    // Index 0: Data
    // Index 1: RX data
    // Index 2: NCF
    // Index 3: SM
    // Index 4: RST
    switch (index)
    {
        case 0:
        case 1:
        case 3:
            m_ui->sources_stackedWidget->setCurrentIndex(0);
            break;
        case 2:
            m_ui->sources_stackedWidget->setCurrentIndex(2);
            break;
        case 4:
            m_ui->sources_stackedWidget->setCurrentIndex(1);
            break;
        default:
            return;
    }
    sourcesItemClicked(m_current_source_transport, 0);
}

void LBMLBTRUTransportDialog::sourcesItemClicked(QTreeWidgetItem * item, int)
{
    LBMLBTRUSourceTransportEntry * transport = dynamic_cast<LBMLBTRUSourceTransportEntry *>(item);

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
        case 4:
            loadSourceRSTDetails(transport);
            break;
        default:
            break;
    }
}

void LBMLBTRUTransportDialog::loadSourceDataDetails(LBMLBTRUSourceTransportEntry * transport)
{
    for (LBMLBTRUSQNMapIterator it = transport->m_data_sqns.begin(); it != transport->m_data_sqns.end(); ++it)
    {
        LBMLBTRUSQNEntry * sqn = it.value();
        m_ui->sources_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRUTransportDialog::loadSourceRXDataDetails(LBMLBTRUSourceTransportEntry * transport)
{
    for (LBMLBTRUSQNMapIterator it = transport->m_rx_data_sqns.begin(); it != transport->m_rx_data_sqns.end(); ++it)
    {
        LBMLBTRUSQNEntry * sqn = it.value();
        m_ui->sources_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRUTransportDialog::loadSourceNCFDetails(LBMLBTRUSourceTransportEntry * transport)
{
    for (LBMLBTRUNCFSQNMapIterator it = transport->m_ncf_sqns.begin(); it != transport->m_ncf_sqns.end(); ++it)
    {
        LBMLBTRUNCFSQNEntry * sqn = it.value();
        m_ui->sources_detail_ncf_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRUTransportDialog::loadSourceSMDetails(LBMLBTRUSourceTransportEntry * transport)
{
    for (LBMLBTRUSQNMapIterator it = transport->m_sm_sqns.begin(); it != transport->m_sm_sqns.end(); ++it)
    {
        LBMLBTRUSQNEntry * sqn = it.value();
        m_ui->sources_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRUTransportDialog::loadSourceRSTDetails(LBMLBTRUSourceTransportEntry * transport)
{
    for (LBMLBTRURSTReasonMapIterator it = transport->m_rst_reasons.begin(); it != transport->m_rst_reasons.end(); ++it)
    {
        LBMLBTRURSTReasonEntry * reason = it.value();
        m_ui->sources_detail_rst_TreeWidget->addTopLevelItem(reason);
    }
}

void LBMLBTRUTransportDialog::sourcesDetailItemDoubleClicked(QTreeWidgetItem * item, int)
{
    LBMLBTRUFrameEntry * frame = dynamic_cast<LBMLBTRUFrameEntry *>(item);
    if (frame == NULL)
    {
        // Must have double-clicked on something other than an expanded frame entry
        return;
    }
    emit goToPacket((int)frame->getFrame());
}

void LBMLBTRUTransportDialog::receiversDetailCurrentChanged(int index)
{
    // Index 0: NAK
    // Index 1: ACK
    // Index 2: CREQ
    switch (index)
    {
        case 0:
        case 1:
            m_ui->receivers_stackedWidget->setCurrentIndex(0);
            break;
        case 2:
            m_ui->receivers_stackedWidget->setCurrentIndex(1);
            break;
        default:
            return;
    }
    receiversItemClicked(m_current_receiver_transport, 0);
}

void LBMLBTRUTransportDialog::receiversItemClicked(QTreeWidgetItem * item, int)
{
    LBMLBTRUReceiverTransportEntry * transport = dynamic_cast<LBMLBTRUReceiverTransportEntry *>(item);

    resetReceiversDetail();
    if (transport == NULL)
    {
        // Must be a receiver item, ignore it?
        return;
    }
    m_current_receiver_transport = transport;
    m_ui->receivers_detail_transport_Label->setText(transport->m_transport);
    int cur_idx = m_ui->receivers_detail_ComboBox->currentIndex();
    switch (cur_idx)
    {
        case 0:
            loadReceiverNAKDetails(transport);
            break;
        case 1:
            loadReceiverACKDetails(transport);
            break;
        case 2:
            loadReceiverCREQDetails(transport);
            break;
        default:
            break;
    }
}

void LBMLBTRUTransportDialog::loadReceiverNAKDetails(LBMLBTRUReceiverTransportEntry * transport)
{
    for (LBMLBTRUSQNMapIterator it = transport->m_nak_sqns.begin(); it != transport->m_nak_sqns.end(); ++it)
    {
        LBMLBTRUSQNEntry * sqn = it.value();
        m_ui->receivers_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRUTransportDialog::loadReceiverACKDetails(LBMLBTRUReceiverTransportEntry * transport)
{
    for (LBMLBTRUSQNMapIterator it = transport->m_ack_sqns.begin(); it != transport->m_ack_sqns.end(); ++it)
    {
        LBMLBTRUSQNEntry * sqn = it.value();
        m_ui->receivers_detail_sqn_TreeWidget->addTopLevelItem(sqn);
    }
}

void LBMLBTRUTransportDialog::loadReceiverCREQDetails(LBMLBTRUReceiverTransportEntry * transport)
{
    for (LBMLBTRUCREQRequestMapIterator it = transport->m_creq_requests.begin(); it != transport->m_creq_requests.end(); ++it)
    {
        LBMLBTRUCREQRequestEntry * req = it.value();
        m_ui->receivers_detail_reason_TreeWidget->addTopLevelItem(req);
    }
}

void LBMLBTRUTransportDialog::receiversDetailItemDoubleClicked(QTreeWidgetItem * item, int)
{
    LBMLBTRUFrameEntry * frame = dynamic_cast<LBMLBTRUFrameEntry *>(item);
    if (frame == NULL)
    {
        // Must have double-clicked on something other than an expanded frame entry
        return;
    }
    emit goToPacket((int)frame->getFrame());
}

void LBMLBTRUTransportDialog::custom_source_context_menuRequested(const QPoint & pos)
{
    m_source_context_menu->popup(m_source_header->mapToGlobal(pos));
}

void LBMLBTRUTransportDialog::actionSourceDataFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceDataBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceDataFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataFramesBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceDataRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_DataRate_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceRXDataFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceRXDataBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceRXDataFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataFramesBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceRXDataRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_RXDataRate_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFCount_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFCount_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFCountBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFCountBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFFramesCount_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCount_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFFramesCountBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFFramesCountBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceNCFRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_NCFRate_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceSMFrames_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceSMBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceSMFramesBytes_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMFramesBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceSMRate_triggered(bool checked)
{
    m_ui->sources_TreeWidget->setColumnHidden(Source_SMRate_Column, !checked);
}

void LBMLBTRUTransportDialog::actionSourceAutoResizeColumns_triggered(void)
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
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RSTFrames_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RSTBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RSTFramesBytes_Column);
    m_ui->sources_TreeWidget->resizeColumnToContents(Source_RSTRate_Column);
}

void LBMLBTRUTransportDialog::custom_receiver_context_menuRequested(const QPoint & pos)
{
    m_receiver_context_menu->popup(m_receiver_header->mapToGlobal(pos));
}

void LBMLBTRUTransportDialog::actionReceiverNAKFrames_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverNAKCount_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKCount_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverNAKBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverNAKFramesCount_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKFramesCount_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverNAKCountBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKCountBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverNAKFramesBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKFramesBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverNAKFramesCountBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKFramesCountBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverNAKRate_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_NAKRate_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverACKFrames_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_ACKFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverACKBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_ACKBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverACKFramesBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_ACKFramesBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverACKRate_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_ACKRate_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverCREQFrames_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_CREQFrames_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverCREQBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_CREQBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverCREQFramesBytes_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_CREQFramesBytes_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverCREQRate_triggered(bool checked)
{
    m_ui->receivers_TreeWidget->setColumnHidden(Receiver_CREQRate_Column, !checked);
}

void LBMLBTRUTransportDialog::actionReceiverAutoResizeColumns_triggered(void)
{
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_AddressTransport_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKFrames_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKCount_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKFramesBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKCountBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKFramesCount_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKFramesCountBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_NAKRate_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_ACKFrames_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_ACKBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_ACKFramesBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_ACKRate_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_CREQFrames_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_CREQBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_CREQFramesBytes_Column);
    m_ui->receivers_TreeWidget->resizeColumnToContents(Receiver_CREQRate_Column);
}
