/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIST_MODEL_H
#define PACKET_LIST_MODEL_H

#include <config.h>

#include <stdio.h>

#include <epan/packet.h>

#include <QAbstractItemModel>
#include <QColor>
#include <QFont>
#include <QVector>

#include "packet_list_record.h"

#include <epan/cfile.h>

/**
 * @brief A Qt item model representing the list of packets in a capture file.
 *
 * There is one row for every packet appended, in frame number order (so
 * frame N is row N - 1), regardless of the display filter. Filtering and
 * sorting are done by a proxy model such as PacketListProxyModel.
 */
class PacketListModel : public QAbstractItemModel
{
    Q_OBJECT
public:

    /**
     * @brief Custom roles used for header data.
     */
    enum {
        /** Role indicating if the header can display strings. */
        HEADER_CAN_DISPLAY_STRINGS = Qt::UserRole,
        /** Role indicating if the header can display details. */
        HEADER_CAN_DISPLAY_DETAILS,
    };

    /**
     * @brief Constructs a new PacketListModel.
     * @param parent The parent QObject, defaults to 0.
     * @param cf The capture file associated with the model, defaults to NULL.
     */
    explicit PacketListModel(QObject *parent = 0, capture_file *cf = NULL);

    /**
     * @brief Destroys the PacketListModel.
     */
    ~PacketListModel();

    /**
     * @brief Sets the capture file for the model.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Returns the capture file associated with the model.
     * @return Pointer to the capture file.
     */
    capture_file *captureFile() const { return cap_file_; }

    /**
     * @brief Returns the index of the item in the model.
     * @param row The row of the item.
     * @param column The column of the item.
     * @param parent The parent index, defaults to QModelIndex().
     * @return The model index of the specified item.
     */
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the parent of the model item.
     * @return The parent model index.
     */
    QModelIndex parent(const QModelIndex &) const override;

    /**
     * @brief Retrieves the PacketListRecord for a given frame/packet
     * number regardless of whether it currently passes the display
     * filter. This looks the record up directly among physical_rows_ --
     * every packet ever appended, retained permanently in frame-number
     * order, including any not yet inserted as rows (see flushNewRows())
     * -- so callers that need a packet's data independent of the current
     * display filter (e.g. rendering a pinned row that's been filtered
     * out) can still get at it.
     * @param frame_num The frame/packet number.
     * @return The record, or nullptr if out of range.
     */
    PacketListRecord *physicalRecordForFrameNum(int frame_num) const;

    /**
     * @brief Retrieves the PacketListRecord at the given row.
     * @param row The row index (the frame number - 1).
     * @return The record, or nullptr if out of range.
     */
    PacketListRecord *physicalRecordAt(int row) const;

    /**
     * @brief Returns true if no packets have been appended.
     */
    bool isEmpty() const { return physical_rows_.isEmpty(); }

    /**
     * @brief Clears the model data.
     */
    void clear();

    /**
     * @brief Returns the number of rows under the given parent.
     * @param parent The parent model index.
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns.
     * @return The number of columns.
     */
    int columnCount(const QModelIndex & = QModelIndex()) const override;

    /**
     * @brief Returns the item flags for the given index.
     * @param index The model index.
     * @return The item flags.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Returns the data stored under the given role for the specified index.
     * @param d_index The model index.
     * @param role The display role.
     * @return The requested data as a QVariant.
     */
    QVariant data(const QModelIndex &d_index, int role) const override;

    /**
     * @brief Returns the same data data() would for a real, currently
     * visible row, but for any frame/packet number that was ever
     * appended, regardless of the current display filter -- see
     * physicalRecordForFrameNum(). Used by PinnedRowsModel so pinned
     * packets keep showing their data even after being filtered out of
     * the PacketListProxyModel it sits on.
     * @param frame_num The frame/packet number.
     * @param column The column index.
     * @param role The display role.
     * @return The requested data as a QVariant, or an invalid QVariant if
     * frame_num is unknown.
     */
    QVariant dataForFrameNum(int frame_num, int column, int role) const;

    /**
     * @brief Returns the data for the given role and section in the header.
     * @param section The header section.
     * @param orientation The header orientation.
     * @param role The display role.
     * @return The header data as a QVariant.
     */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Appends a packet to the model. The row is inserted the next
     * time flushNewRows() runs, which is scheduled automatically.
     * @param fdata Pointer to the frame data.
     * @return The row index where the packet will be inserted.
     */
    int appendPacket(frame_data *fdata);

    /**
     * @brief Invalidate any cached column strings.
     */
    void invalidateAllColumnStrings();

    /**
     * @brief Rebuild columns from settings.
     */
    void resetColumns();

    /**
     * @brief Resets the colorized state for all rows.
     */
    void resetColorized();

    /**
     * @brief Toggles the mark state for the specified frames.
     * @param indices List of model indices to toggle.
     */
    void toggleFrameMark(const QModelIndexList &indices);

    /**
     * @brief Toggles the mark state for a frame given by record, which
     * need not have a visible row (e.g., a pinned frame filtered out).
     */
    void toggleFrameMark(PacketListRecord *record);

    /**
     * @brief Sets the mark state for the given frames.
     * @param records The records of the frames to change.
     * @param set True to mark, false to unmark.
     */
    void setFrameMark(const QVector<PacketListRecord *> &records, bool set);

    /**
     * @brief Toggles the ignore state for the specified frames.
     * @param indices List of model indices to toggle.
     */
    void toggleFrameIgnore(const QModelIndexList &indices);

    /** @brief As above, for a record that need not have a visible row. */
    void toggleFrameIgnore(PacketListRecord *record);

    /**
     * @brief Sets the ignore state for the given frames.
     * @param records The records of the frames to change.
     * @param set True to ignore, false to un-ignore.
     */
    void setFrameIgnore(const QVector<PacketListRecord *> &records, bool set);

    /**
     * @brief Toggles the reference time state for the specified frames.
     * @param indices List of model indices to toggle
     */
    void toggleFrameRefTime(const QModelIndexList &indices);

    /** @brief As above, for a record that need not have a visible row. */
    void toggleFrameRefTime(PacketListRecord *record);

    /**
     * @brief Unsets the reference time state for all frames.
     */
    void unsetAllFrameRefTime();

    /**
     * @brief Adds a comment to the specified frames.
     * @param indices List of model indices to comment on.
     * @param comment The comment text as a byte array.
     */
    void addFrameComment(const QModelIndexList &indices, const QByteArray &comment);

    /** @brief As above, for a record that need not have a visible row. */
    void addFrameComment(PacketListRecord *record, const QByteArray &comment);

    /**
     * @brief Sets a specific comment on a frame.
     * @param index The model index of the frame.
     * @param comment The comment text.
     * @param c_number The comment number index.
     */
    void setFrameComment(const QModelIndex &index, const QByteArray &comment, unsigned c_number);

    /** @brief As above, for a record that need not have a visible row. */
    void setFrameComment(PacketListRecord *record, const QByteArray &comment, unsigned c_number);

    /**
     * @brief Deletes comments from the specified frames.
     * @param indices List of model indices to remove comments from.
     */
    void deleteFrameComments(const QModelIndexList &indices);

    /** @brief As above, for a record that need not have a visible row. */
    void deleteFrameComments(PacketListRecord *record);

    /**
     * @brief Deletes all frame comments from all frames.
     */
    void deleteAllFrameComments();

signals:
    /**
     * @brief Signal emitted when a packet is successfully appended.
     * @param cap_file Pointer to the capture file.
     * @param fdata Pointer to the frame data.
     * @param row The row index where the packet was added.
     */
    void packetAppended(capture_file *cap_file, frame_data *fdata, qsizetype row);

public slots:
    /**
     * @brief Inserts the rows for any packets appended since the last flush.
     */
    void flushNewRows();

private slots:
    /** Slot connected to ThemeManager::themeChanged. Refreshes the color
     *  cache and asks the view to repaint every cell's bg/fg roles. */
    void onThemeChanged();

private:
    void toggleRecordsRefTime(const QList<PacketListRecord *> &records);
    void addCommentToRecord(PacketListRecord *record, const QByteArray &comment);
    void setCommentOnRecord(PacketListRecord *record, const QByteArray &comment, unsigned c_number);
    bool deleteCommentsFromRecord(PacketListRecord *record);

    /** Cached foreground color for manually marked packets. */
    QColor marked_fg_;
    /** Cached background color for manually marked packets. */
    QColor marked_bg_;
    /** Cached foreground color for ignored packets. */
    QColor ignored_fg_;
    /** Cached background color for ignored packets (invalid = use view default). */
    QColor ignored_bg_;

    /**
     * Re-reads marked/ignored colors from ThemeManager into the cached
     * QColor members. Called from the constructor (priming) and from
     * onThemeChanged() (after a theme/mode flip).
     */
    void refreshThemeColors();

    /**
     * @brief Shared implementation behind data() and dataForFrameNum():
     * everything data() computes depends only on the record and column,
     * never on the index's row number, so both can delegate here.
     * @param record The record to read from, or nullptr (returns an
     * invalid QVariant).
     * @param column The column index.
     * @param role The display role.
     */
    QVariant dataForRecord(PacketListRecord *record, int column, int role) const;

    /** Pointer to the associated capture file. */
    capture_file *cap_file_;

    /** List of column names used in the model. */
    QList<QString> col_names_;

    /** Vector of all physical rows loaded into the model. */
    QVector<PacketListRecord *> physical_rows_;

    /** The number of physical rows inserted as model rows so far. */
    int inserted_rows_;

};

#endif // PACKET_LIST_MODEL_H
