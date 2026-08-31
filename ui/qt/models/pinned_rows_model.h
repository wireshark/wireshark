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

/**
 * @brief A proxy model exposing only a chosen set of "pinned" packets from
 * a PacketListModel, packed together with no gaps, ordered to match the
 * source model's own current row order (i.e. whatever sort/filter is
 * currently active there).
 *
 * Used to render the pinned-row overlay in the packet list: rather than
 * hiding thousands of individual rows in a real QTreeView on the full
 * model (which QTreeView has no way to do efficiently for an arbitrary,
 * scattered row set), this proxy simply reports N rows, one per pinned
 * frame number, and maps each to that packet's current row in the source
 * model on demand.
 */
class PinnedRowsModel : public QAbstractProxyModel
{
    Q_OBJECT
public:
    /** Maximum number of packets that can be pinned simultaneously. */
    static const int kMaxPinnedRows = 10;

    explicit PinnedRowsModel(QObject *parent = nullptr);

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

    // Whether the given frame number is currently pinned.
    bool isPinned(int frame_num) const;

    // The number of currently pinned frames.
    int pinnedCount() const { return static_cast<int>(pinned_frame_nums_.count()); }

    /**
     * @brief Re-sorts the pinned frames to match the source model's
     * current row order (i.e. whatever sort is currently applied there),
     * and re-resolves each against the current source model state (e.g.
     * after a display filter change), emitting layoutChanged(). A pinned
     * frame that's been filtered out of the source model resolves to an
     * invalid row (see sourceRowForPinnedIndex()) but stays pinned -- it
     * reappears automatically, in its sorted position, once the filter
     * allows it again.
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

    /**
     * @brief Returns a pinned row's data regardless of whether it
     * currently passes the display filter.
     *
     * Overridden (rather than relying on QAbstractProxyModel's default,
     * which calls sourceModel()->data(mapToSource(index), role)) because
     * mapToSource() only ever resolves to a row among the source model's
     * currently *visible* (filtered-in) rows -- a pinned packet that's
     * been filtered out has no such row, so the default would return an
     * empty QVariant for it. This instead always reads the packet's data
     * from PacketListModel::dataForFrameNum(), which looks the packet up
     * directly regardless of the display filter, so pinned rows keep
     * showing their data even after being filtered out.
     * @param proxy_index The index within this proxy model.
     * @param role The display role.
     */
    QVariant data(const QModelIndex &proxy_index, int role) const override;

    /**
     * @brief Returns a pinned row's flags regardless of whether it
     * currently passes the display filter, for the same reason data() is
     * overridden -- QAbstractProxyModel's default flags() calls
     * sourceModel()->flags(mapToSource(index)), which is an invalid index
     * whenever the row is filtered out, silently diverging from what
     * data() already reports for that same row.
     * @param proxy_index The index within this proxy model.
     */
    Qt::ItemFlags flags(const QModelIndex &proxy_index) const override;

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

private:
    QList<int> pinned_frame_nums_;
    PacketListModel *packet_list_model_;

    /**
     * @brief The source model row currently backing the given pinned
     * frame number, or -1 if that frame is filtered out.
     */
    int sourceRowForPinnedIndex(int proxy_row) const;
};

#endif // PINNED_ROWS_MODEL_H
