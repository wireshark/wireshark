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
#include <QFont>
#include <QVector>

#include <ui/qt/progress_frame.h>

#include "packet_list_record.h"

#include <epan/cfile.h>

class QElapsedTimer;

/**
 * @brief A Qt item model representing the list of packets in a capture file.
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
     * @brief Converts a packet number to a row index.
     * @param packet_num The packet number.
     * @return The corresponding row index.
     */
    int packetNumberToRow(int packet_num) const;

    /**
     * @brief Recreates the list of visible rows based on filters and state.
     * @return The number of visible rows.
     */
    unsigned recreateVisibleRows();

    /**
     * @brief Flags the model as needing to recreate its visible rows.
     */
    inline void needRecreateVisibleRows() { need_recreate_visible_rows_ = !physical_rows_.isEmpty(); }

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
     * @brief Returns the data for the given role and section in the header.
     * @param section The header section.
     * @param orientation The header orientation.
     * @param role The display role.
     * @return The header data as a QVariant.
     */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Appends a packet to the model.
     * @param fdata Pointer to the frame data.
     * @return The row index where the packet was appended.
     */
    int appendPacket(frame_data *fdata);

    /**
     * @brief Retrieves the frame data for a given model index.
     * @param idx The model index.
     * @return Pointer to the frame data.
     */
    frame_data *getRowFdata(QModelIndex idx) const;

    /**
     * @brief Retrieves the frame data for a given row.
     * @param row The row index.
     * @return Pointer to the frame data.
     */
    frame_data *getRowFdata(int row) const;

    /**
     * @brief Ensures that a specific row has been colorized.
     * @param row The row index to colorize.
     */
    void ensureRowColorized(int row);

    /**
     * @brief Returns the visible index of the given frame data.
     * @param fdata Pointer to the frame data.
     * @return The visible index.
     */
    int visibleIndexOf(const frame_data *fdata) const;

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
     * @param indeces List of model indices to toggle.
     */
    void toggleFrameMark(const QModelIndexList &indeces);

    /**
     * @brief Sets the mark state for all currently displayed frames.
     * @param set True to mark, false to unmark.
     */
    void setDisplayedFrameMark(bool set);

    /**
     * @brief Toggles the ignore state for the specified frames.
     * @param indeces List of model indices to toggle.
     */
    void toggleFrameIgnore(const QModelIndexList &indeces);

    /**
     * @brief Sets the ignore state for all currently displayed frames.
     * @param set True to ignore, false to un-ignore.
     */
    void setDisplayedFrameIgnore(bool set);

    /**
     * @brief Toggles the reference time state for a specified frame.
     * @param rt_index The model index of the frame.
     */
    void toggleFrameRefTime(const QModelIndex &rt_index);

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

    /**
     * @brief Sets a specific comment on a frame.
     * @param index The model index of the frame.
     * @param comment The comment text.
     * @param c_number The comment number index.
     */
    void setFrameComment(const QModelIndex &index, const QByteArray &comment, unsigned c_number);

    /**
     * @brief Deletes comments from the specified frames.
     * @param indices List of model indices to remove comments from.
     */
    void deleteFrameComments(const QModelIndexList &indices);

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

    /**
     * @brief Signal emitted to navigate the view to a specific packet number.
     * @param packet_num The target packet number.
     */
    void goToPacket(int packet_num);

    /**
     * @brief Signal emitted to report background colorization progress.
     * @param first The first row processed.
     * @param last The last row processed.
     */
    void bgColorizationProgress(int first, int last);

public slots:
    /**
     * @brief Sorts the model based on the specified column.
     * @param column The column index to sort by.
     * @param order The sort order (ascending or descending).
     */
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

    /**
     * @brief Stops an ongoing sorting operation.
     */
    void stopSorting();

    /**
     * @brief Flushes the newly visible rows into the main visible rows view.
     */
    void flushVisibleRows();

    /**
     * @brief Performs dissection work during application idle time.
     * @param reset True to reset the idle dissection state.
     */
    void dissectIdle(bool reset = false);

private:
    /** Pointer to the associated capture file. */
    capture_file *cap_file_;

    /** List of column names used in the model. */
    QList<QString> col_names_;

    /** Vector of all physical rows loaded into the model. */
    QVector<PacketListRecord *> physical_rows_;

    /** Vector of currently visible rows. */
    QVector<PacketListRecord *> visible_rows_;

    /** Vector of new visible rows pending a flush. */
    QVector<PacketListRecord *> new_visible_rows_;

    /** Vector mapping packet numbers to their corresponding row index. */
    QVector<int> number_to_row_;

    /** Hash mapping aggregation keys to their corresponding row index. */
    QHash<QString, int> aggregation_key_row_;

    /** Flag indicating whether visible rows need to be recreated. */
    bool need_recreate_visible_rows_;

    /** The column index currently being used for sorting. */
    static int sort_column_;

    /** Flag indicating if the current sort column is numeric. */
    static int sort_column_is_numeric_;

    /** The column index used as a secondary text sort column. */
    static int text_sort_column_;

    /** The current sort order applied to the model. */
    static Qt::SortOrder sort_order_;

    /** Pointer to the capture file context used during sorting. */
    static capture_file *sort_cap_file_;

    /**
     * @brief Compare function used to sort records.
     * @param r1 The first record.
     * @param r2 The second record.
     * @return True if r1 should appear before r2, false otherwise.
     */
    static bool recordLessThan(PacketListRecord *r1, PacketListRecord *r2);

    /**
     * @brief Parses a string value from a column as a numeric double.
     * @param val The string value to parse.
     * @param ok Pointer to a boolean set to true if parsing was successful.
     * @return The parsed double value.
     */
    static double parseNumericColumn(const QString &val, bool *ok);

    /** Flag used to signal stopping a long-running operation. */
    static bool stop_flag_;

    /** Pointer to the frame displaying progress. */
    static ProgressFrame *progress_frame_;

    /** The expected number of comparisons during sorting. */
    static double exp_comps_;

    /** The actual number of comparisons performed during sorting. */
    static double comps_;

    /** Timer used for triggering idle dissection batches. */
    QElapsedTimer *idle_dissection_timer_;

    /** The current row index being processed by idle dissection. */
    int idle_dissection_row_;

    /**
     * @brief Determines if the specified column contains numeric data.
     * @param column The column index to check.
     * @return True if numeric, false otherwise.
     */
    bool isNumericColumn(int column);

    /**
     * @brief Updates the internal lists with a newly visible row.
     * @param record Pointer to the packet list record that is now visible.
     */
    void updateVisibleRows(PacketListRecord* record);

    /**
     * @brief Updates the aggregation view rows based on a newly visible record.
     * @param record Pointer to the packet list record that is now visible.
     * @return True if the aggregation view was updated, false otherwise.
     */
    bool updateVisibleAggregationViewRows(PacketListRecord* record);
};

#endif // PACKET_LIST_MODEL_H
