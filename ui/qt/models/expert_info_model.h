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

/**
 * @brief Represents a single packet or group item in the expert information tree.
 */
class ExpertPacketItem
{
public:
    /**
     * @brief Constructs a new ExpertPacketItem.
     * @param expert_info The expert information structure.
     * @param cinfo The column information.
     * @param parent The parent item in the tree.
     */
    ExpertPacketItem(const expert_info_t& expert_info, column_info *cinfo, ExpertPacketItem* parent);

    /**
     * @brief Destroys the ExpertPacketItem.
     */
    virtual ~ExpertPacketItem();

    /**
     * @brief Retrieves the packet number.
     * @return The packet number.
     */
    unsigned int packetNum() const { return packet_num_; }

    /**
     * @brief Retrieves the expert group ID.
     * @return The group ID.
     */
    int group() const { return group_; }

    /**
     * @brief Retrieves the severity level.
     * @return The severity level.
     */
    int severity() const { return severity_; }

    /**
     * @brief Retrieves the header field ID.
     * @return The header field ID.
     */
    int hfId() const { return hf_id_; }

    /**
     * @brief Retrieves the protocol name.
     * @return The protocol string.
     */
    QString protocol() const { return protocol_; }

    /**
     * @brief Retrieves the summary text.
     * @return The summary string.
     */
    QString summary() const { return summary_; }

    /**
     * @brief Retrieves the column info text.
     * @return The column info string.
     */
    QString colInfo() const { return info_; }

    /**
     * @brief Generates a grouping key based on item properties.
     * @param group_by_summary True to include the summary in the grouping key.
     * @param severity The severity level.
     * @param group The group ID.
     * @param protocol The protocol string.
     * @param expert_hf The header field ID.
     * @return The generated group key string.
     */
    static QString groupKey(bool group_by_summary, int severity, int group, QString protocol, int expert_hf);

    /**
     * @brief Generates a grouping key for this specific item.
     * @param group_by_summary True to include the summary in the grouping key.
     * @return The generated group key string.
     */
    QString groupKey(bool group_by_summary);

    /**
     * @brief Appends a child item to this item.
     * @param child The child item to append.
     * @param hash The hash key to associate with the child.
     */
    void appendChild(ExpertPacketItem* child, QString hash);

    /**
     * @brief Retrieves the child item at a specific row.
     * @param row The row index of the child.
     * @return A pointer to the child ExpertPacketItem.
     */
    ExpertPacketItem* child(int row);

    /**
     * @brief Retrieves the child item associated with a specific hash.
     * @param hash The hash key of the child.
     * @return A pointer to the child ExpertPacketItem, or null if not found.
     */
    ExpertPacketItem* child(QString hash);

    /**
     * @brief Gets the number of children this item has.
     * @return The child count.
     */
    int childCount() const;

    /**
     * @brief Gets the row index of this item relative to its parent.
     * @return The row index.
     */
    int row() const;

    /**
     * @brief Retrieves the parent of this item.
     * @return A pointer to the parent ExpertPacketItem.
     */
    ExpertPacketItem* parentItem();

private:
    /** The packet number. */
    unsigned int packet_num_;

    /** The expert group ID. */
    int group_;

    /** The severity level. */
    int severity_;

    /** The header field ID. */
    int hf_id_;

    /** The row index relative to the parent. */
    int row_;

    /**
     * The protocol string.
     * Half-hearted attempt at conserving memory. If this isn't sufficient,
     * PacketListRecord interns column strings in a GStringChunk.
     */
    QByteArray protocol_;

    /** The summary text. */
    QByteArray summary_;

    /** The column info text. */
    QByteArray info_;

    /** The list of child items. */
    QList<ExpertPacketItem*> childItems_;

    /** Pointer to the parent item. */
    ExpertPacketItem* parentItem_;

    /** Optimization map for fast child insertion and lookup. */
    QHash<QString, ExpertPacketItem*> hashChild_;    //optimization for insertion
};

/**
 * @brief A model managing the expert information tree data.
 */
class ExpertInfoModel : public QAbstractItemModel
{
public:
    /**
     * @brief Constructs a new ExpertInfoModel.
     * @param capture_file The capture file containing the expert information.
     * @param parent The parent QObject, defaults to 0.
     */
    ExpertInfoModel(CaptureFile& capture_file, QObject *parent = 0);

    /**
     * @brief Destroys the ExpertInfoModel.
     */
    virtual ~ExpertInfoModel();

    /**
     * @brief Enumerates the columns in the expert info model.
     */
    enum ExpertColumn {
        colSeverity = 0, /**< Severity column. */
        colSummary,      /**< Summary text column. */
        colGroup,        /**< Group ID column. */
        colProtocol,     /**< Protocol string column. */
        colCount,        /**< Event count column. */
        colPacket,       /**< Packet number column. */
        colHf,           /**< Header field ID column. */
        colLast         /**< End of columns marker. */
    };

    /**
     * @brief Enumerates the severity levels for expert information.
     */
    enum ExpertSeverity {
        severityError = PI_ERROR,     /**< Error severity level. */
        severityWarn = PI_WARN,       /**< Warning severity level. */
        severityNote = PI_NOTE,       /**< Note severity level. */
        severityChat = PI_CHAT,       /**< Chat severity level. */
        severityComment = PI_COMMENT  /**< Comment severity level. */
    };

    /**
     * @brief Generates an index for the given row and column.
     * @param row The row index.
     * @param column The column index.
     * @param parent The parent index (defaults to an invalid QModelIndex).
     * @return The corresponding model index.
     */
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Retrieves the parent of a given index.
     * @param index The child model index.
     * @return The parent model index.
     */
    QModelIndex parent(const QModelIndex &index) const;

#if 0
    /**
     * @brief Retrieves the item flags for a given index.
     * @param index The model index.
     * @return The item flags.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const;
#endif

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested.
     * @return The data associated with the index and role.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Returns the number of rows under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Gets the total number of events for a specific severity.
     * @param severity The severity level to query.
     * @return The number of events.
     */
    int numEvents(enum ExpertSeverity severity);

    /**
     * @brief Clears all expert information data from the model.
     */
    void clear();

    //GUI helpers
    /**
     * @brief Sets whether the model groups items by summary.
     * @param group_by_summary True to group by summary, false otherwise.
     */
    void setGroupBySummary(bool group_by_summary);

    // Called from tapPacket
    /**
     * @brief Adds a new expert information entry to the model.
     * @param expert_info The expert information structure to add.
     */
    void addExpertInfo(const struct expert_info_s& expert_info);

    /**
     * @brief Callback used by register_tap_listener to reset the tap.
     * @param eid_ptr Pointer to the ExpertInfoModel instance.
     */
    static void tapReset(void *eid_ptr);

    /**
     * @brief Callback used by register_tap_listener when a packet is processed.
     * @param eid_ptr Pointer to the ExpertInfoModel instance.
     * @param pinfo Pointer to the packet info structure.
     * @param data Pointer to the expert info data.
     * @param flags Tap flags.
     * @return The status of the tap packet processing.
     */
    static tap_packet_status tapPacket(void *eid_ptr, struct _packet_info *pinfo, struct epan_dissect *, const void *data, tap_flags_t flags);

    /**
     * @brief Callback used by register_tap_listener to draw or update results.
     * @param eid_ptr Pointer to the ExpertInfoModel instance.
     */
    static void tapDraw(void *eid_ptr);

private:
    /** Reference to the associated capture file. */
    CaptureFile& capture_file_;

    /**
     * @brief Creates and returns the root item for the tree model.
     * @return Pointer to the new root ExpertPacketItem.
     */
    ExpertPacketItem* createRootItem();

    /** Flag indicating whether items are grouped by their summary. */
    bool group_by_summary_;

    /** Pointer to the root item of the model tree. */
    ExpertPacketItem* root_;

    /** Map tracking the count of events for each severity level. */
    QHash<enum ExpertSeverity, int> eventCounts_;
};
#endif // EXPERT_INFO_MODEL_H
