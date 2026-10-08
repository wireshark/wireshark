/** @file
 *
 * Header file defining the PinnedRowsModel class
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PINNED_ROWS_MODEL_H
#define PINNED_ROWS_MODEL_H

#include <QAbstractProxyModel>
#include <QList>

class PacketListModel;
class PacketListProxyModel;

/**
 * @brief A proxy model exposing only a chosen set of "pinned" packets from
 * a PacketListModel, packed together with no gaps, ordered to match the
 * packet list's current sort order (see setSortModel()).
 *
 * Used to render the pinned-row overlay in the packet list: rather than
 * hiding thousands of individual rows in a real QTreeView on the full
 * model (which QTreeView has no way to do efficiently for an arbitrary,
 * scattered row set), this proxy simply reports N rows, one per pinned
 * frame number.
 *
 * The source PacketListModel has a row for every packet regardless of the
 * display filter, so every pinned packet always maps to a valid source
 * row, even when it is filtered out of the packet list.
 */
class PinnedRowsModel : public QAbstractProxyModel
{
    Q_OBJECT
public:
    /** Maximum number of packets that can be pinned simultaneously. */
    static const int kMaxPinnedRows = 10;

    explicit PinnedRowsModel(QObject *parent = nullptr);

    /**
     * @brief Sets the model whose sort order the pinned rows follow.
     * @param sort_model The packet list's proxy model, or nullptr to
     * order the pinned rows by frame number.
     */
    void setSortModel(PacketListProxyModel *sort_model);

    /**
     * @brief Pins a packet, if not already pinned and under the
     * kMaxPinnedRows cap.
     * @param frame_num The frame number to pin.
     * @return False if the cap was already reached.
     */
    bool pinFrame(int frame_num);

    /**
     * @brief Unpins a packet.
     * @param frame_num The frame number to unpin.
     */
    void unpinFrame(int frame_num);

    // Unpins every currently pinned packet.
    void clear();

    /**
     * @brief Re-pins the frames that were pinned when the source model was
     * last reset (e.g., by redissection), in the order they were pinned,
     * skipping any that no longer exist. Frame numbers are stable across
     * redissection, so the same packets are pinned afterward.
     * @return True if any frames were restored.
     */
    bool restoreSavedPins();

    // Forgets the pins saved by the last source model reset, e.g., because
    // the capture file was closed or replaced rather than redissected.
    void discardSavedPins() { saved_frame_nums_.clear(); }

    // Whether the given frame number is currently pinned.
    bool isPinned(int frame_num) const;

    // The number of currently pinned frames.
    int pinnedCount() const { return static_cast<int>(pinned_frame_nums_.count()); }

    /**
     * @brief The row of the given pinned frame in this model.
     * @param frame_num The frame number.
     * @return The row, or -1 if the frame isn't pinned.
     */
    int rowForFrameNum(int frame_num) const { return static_cast<int>(pinned_frame_nums_.indexOf(frame_num)); }

    /**
     * @brief Re-sorts the pinned frames to match the sort model's current
     * order (whatever column/order the user last sorted by), emitting
     * layoutChanged(). A pinned frame that's been filtered out of the
     * packet list stays pinned, in its sorted position.
     */
    void refresh();

    // QAbstractProxyModel
    void setSourceModel(QAbstractItemModel *source_model) override;
    QModelIndex mapToSource(const QModelIndex &proxy_index) const override;
    QModelIndex mapFromSource(const QModelIndex &source_index) const override;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &child) const override;
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    bool hasChildren(const QModelIndex &parent = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

private slots:
    /**
     * @brief Forwards the source model's dataChanged() for any pinned
     * frame within the changed range, translated to this proxy's own row
     * numbering. Without this, per-cell changes (e.g. toggling ignore/
     * mark, editing a comment, a theme change recoloring rows) emitted
     * only as dataChanged() on the source model never reached the pinned
     * overlay views, which only ever reacted to modelReset/layoutChanged.
     * @param source_top_left Top-left corner of the changed range, in the
     * source model's own row/column numbering.
     * @param source_bottom_right Bottom-right corner of the changed range.
     * @param roles The roles that changed, forwarded as-is.
     */
    void sourceDataChanged(const QModelIndex &source_top_left, const QModelIndex &source_bottom_right,
                           const QList<int> &roles);

    void sourceModelAboutToBeReset();
    void sourceModelReset();

private:
    QList<int> pinned_frame_nums_;
    // Pins held across a source model reset, for restoreSavedPins().
    QList<int> saved_frame_nums_;
    PacketListModel *packet_list_model_;
    PacketListProxyModel *sort_model_;
};

#endif // PINNED_ROWS_MODEL_H
