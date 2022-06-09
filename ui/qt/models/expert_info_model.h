/** @file
 *
 * Data model for Expert Info tap data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPERT_INFO_MODEL_H
#define EXPERT_INFO_MODEL_H

#include <config.h>

#include <QAbstractItemModel>
#include <QList>
#include <QMap>

#include <ui/qt/capture_file.h>

#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/column-utils.h>

class ExpertPacketItem
{
public:
    ExpertPacketItem(const expert_info_t& expert_info, column_info *cinfo, ExpertPacketItem* parent);
    virtual ~ExpertPacketItem();

    unsigned int packetNum() const { return packet_num_; }
    int group() const { return group_; }
    int severity() const { return severity_; }
    int hfId() const { return hf_id_; }
    QString protocol() const { return protocol_; }
    QString summary() const { return summary_; }
    QString colInfo() const { return info_; }

    static QString groupKey(bool group_by_summary, int severity, int group, QString protocol, int expert_hf);
    QString groupKey(bool group_by_summary);

    void appendChild(ExpertPacketItem* child, QString hash);
    ExpertPacketItem* child(int row);
    ExpertPacketItem* child(QString hash);
    int childCount() const;
    int row() const;
    ExpertPacketItem* parentItem();

private:
    unsigned int packet_num_;
    int group_;
    int severity_;
    int hf_id_;
    // Half-hearted attempt at conserving memory. If this isn't sufficient,
    // PacketListRecord interns column strings in a GStringChunk.
    QByteArray protocol_;
    QByteArray summary_;
    QByteArray info_;

    QList<ExpertPacketItem*> childItems_;
    ExpertPacketItem* parentItem_;
    QHash<QString, ExpertPacketItem*> hashChild_;    //optimization for insertion
};

class ExpertInfoModel : public QAbstractItemModel
{
public:
    ExpertInfoModel(CaptureFile& capture_file, QObject *parent = 0);
    virtual ~ExpertInfoModel();

    enum ExpertColumn {
        colSeverity = 0,
        colSummary,
        colGroup,
        colProtocol,
        colCount,
        colPacket,
        colHf,
        colLast
    };

    enum ExpertSeverity {
        severityError = PI_ERROR,
        severityWarn = PI_WARN,
        severityNote = PI_NOTE,
        severityChat = PI_CHAT,
        severityComment = PI_COMMENT
    };

    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;
#if 0
    Qt::ItemFlags flags(const QModelIndex &index) const;
#endif
    QVariant data(const QModelIndex &index, int role) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    int numEvents(enum ExpertSeverity severity);

    void clear();

    //GUI helpers
    void setGroupBySummary(bool group_by_summary);

    // Called from tapPacket
    void addExpertInfo(const struct expert_info_s& expert_info);

    // Callbacks for register_tap_listener
    static void tapReset(void *eid_ptr);
    static tap_packet_status tapPacket(void *eid_ptr, struct _packet_info *pinfo, struct epan_dissect *, const void *data, tap_flags_t flags);
    static void tapDraw(void *eid_ptr);

private:
    CaptureFile& capture_file_;

    ExpertPacketItem* createRootItem();

    bool group_by_summary_;
    ExpertPacketItem* root_;

    QHash<enum ExpertSeverity, int> eventCounts_;
};
#endif // EXPERT_INFO_MODEL_H
