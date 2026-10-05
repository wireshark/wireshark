/** @file
 *
 * Proxy model that filters and sorts the packets in a PacketListModel
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIST_PROXY_MODEL_H
#define PACKET_LIST_PROXY_MODEL_H

#include <config.h>

#include <QAbstractProxyModel>
#include <QHash>
#include <QVector>

#include <epan/cfile.h>

class QElapsedTimer;
class PacketListModel;
class PacketListRecord;
class ProgressFrame;

/**
 * @brief A proxy model exposing the packets of a PacketListModel that pass
 * the display filter, in the currently selected sort order.
 *
 * The source PacketListModel has one row per packet ever appended, in
 * frame-number order; this model maps a subset of them (those that passed
 * the display filter or are time references, possibly collapsed by the
 * aggregation view) into its own rows, and reorders them when sorted.
 *
 * Like the source model, each index's internal pointer is the row's
 * PacketListRecord, so delegates and views can read the record directly
 * off an index from either model.
 */
class PacketListProxyModel : public QAbstractProxyModel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new PacketListProxyModel.
     * @param parent The parent QObject, defaults to nullptr.
     */
    explicit PacketListProxyModel(QObject *parent = nullptr);

    /**
     * @brief Destroys the PacketListProxyModel.
     */
    ~PacketListProxyModel();

    /**
     * @brief The source model, if it is a PacketListModel.
     * @return The source PacketListModel, or nullptr.
     */
    PacketListModel *packetListModel() const { return packet_list_model_; }

    /**
     * @brief Converts a packet number to a row index.
     * @param packet_num The packet number.
     * @return The corresponding row index, or -1 if the packet isn't visible.
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
    void needRecreateVisibleRows();

    /**
     * @brief Orders two frame/packet numbers the same way the primary
     * view's current sort would, regardless of whether either currently
     * passes the display filter.
     *
     * Used by PinnedRowsModel::refresh() so pinned packets that have been
     * filtered out still sort into their natural position relative to
     * the visible ones (by frame number if unsorted, or by whatever
     * column/order the user last sorted by) instead of always landing
     * after every visible pinned packet -- packetNumberToRow() (the
     * previous approach) returns -1 for a filtered-out packet, which
     * can't express a real ordering relative to visible ones.
     *
     * Deliberately does not reuse the private, static recordLessThan()
     * used by sort(): that comparator's side effects (progress bar
     * updates, a busy-timeout check, throwing SortAbort) only make sense
     * for a full bulk sort, not a handful of comparisons here. It also
     * assumes an active sort has already set sort_cap_file_ etc., which
     * isn't true until the user has explicitly sorted at least once, so
     * this falls back to plain frame-number order in that case (which
     * happens to match the model's own natural, unsorted order anyway).
     * @param frame_num_a First frame/packet number.
     * @param frame_num_b Second frame/packet number.
     * @return True if frame_num_a sorts before frame_num_b.
     */
    bool pinnedRecordLessThan(int frame_num_a, int frame_num_b) const;

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
     * @brief Sets the mark state for all currently displayed frames.
     * @param set True to mark, false to unmark.
     */
    void setDisplayedFrameMark(bool set);

    /**
     * @brief Sets the ignore state for all currently displayed frames.
     * @param set True to ignore, false to un-ignore.
     */
    void setDisplayedFrameIgnore(bool set);

    // QAbstractProxyModel
    void setSourceModel(QAbstractItemModel *source_model) override;
    QModelIndex mapToSource(const QModelIndex &proxy_index) const override;
    QModelIndex mapFromSource(const QModelIndex &source_index) const override;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &child) const override;
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    bool hasChildren(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the source model's header data.
     *
     * Overridden because QAbstractProxyModel's default maps the section
     * through a row-0 index, which doesn't exist when no packets are
     * visible (and columns are never reordered here anyway).
     */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

signals:
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
     * @brief Inserts any packets appended to the source model since the
     * last update, and the visible ones among them into this model.
     */
    void flushVisibleRows();

    /**
     * @brief Performs dissection work during application idle time.
     * @param reset True to reset the idle dissection state.
     */
    void dissectIdle(bool reset = false);

private slots:
    void sourceRowsInserted(const QModelIndex &parent, int first, int last);
    void sourceModelAboutToBeReset();
    void sourceModelReset();
    void sourceDataChanged(const QModelIndex &source_top_left, const QModelIndex &source_bottom_right,
                           const QList<int> &roles);
    void sourceHeaderDataChanged(Qt::Orientation orientation, int first, int last);

private:
    /** The source model, if it is a PacketListModel. */
    PacketListModel *packet_list_model_;

    /** Vector of currently visible rows. */
    QVector<PacketListRecord *> visible_rows_;

    /** Vector mapping packet numbers to their corresponding row index. */
    QVector<int> number_to_row_;

    /** Hash mapping aggregation keys to their corresponding row index. */
    QHash<QString, int> aggregation_key_row_;

    /** Flag indicating whether visible rows need to be recreated. */
    bool need_recreate_visible_rows_;

    /** Timer used for triggering idle dissection batches. */
    QElapsedTimer *idle_dissection_timer_;

    /** The current row index being processed by idle dissection. */
    int idle_dissection_row_;

    /** The source model's capture file, or nullptr. */
    capture_file *captureFile() const;

    /** Discards all visible rows and sort state. */
    void clearVisibleRows();

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
     * @brief The core column-comparison logic shared by recordLessThan()
     * and pinnedRecordLessThan(): given the current sort_column_/
     * text_sort_column_/sort_column_is_numeric_/sort_order_ state, decide
     * whether r1 sorts before r2. Factored out so a change to sort
     * semantics only needs to be made once; the two callers differ only in
     * side effects and preconditions layered around this (see
     * pinnedRecordLessThan()'s own comment for why it doesn't just call
     * recordLessThan() directly).
     * @param r1 The first record.
     * @param r2 The second record.
     * @return True if r1 should appear before r2, false otherwise.
     */
    static bool compareRecords(PacketListRecord *r1, PacketListRecord *r2);

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

#endif // PACKET_LIST_PROXY_MODEL_H
