/* pinned_rows_model.cpp
 *
 * Proxy model exposing only the currently pinned packets from a PacketListModel
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/pinned_rows_model.h>
#include <ui/qt/models/packet_list_model.h>

#include <algorithm>

PinnedRowsModel::PinnedRowsModel(QObject *parent) :
    QAbstractProxyModel(parent),
    packet_list_model_(nullptr)
{
}

void PinnedRowsModel::setSourceModel(QAbstractItemModel *source_model)
{
    QAbstractProxyModel::setSourceModel(source_model);
    packet_list_model_ = qobject_cast<PacketListModel *>(source_model);

    if (source_model) {
        connect(source_model, &QAbstractItemModel::dataChanged,
                this, &PinnedRowsModel::sourceDataChanged);
    }
}

bool PinnedRowsModel::pinFrame(int frame_num)
{
    if (pinned_frame_nums_.contains(frame_num)) {
        return true;
    }
    if (pinned_frame_nums_.count() >= kMaxPinnedRows) {
        return false;
    }

    int new_row = static_cast<int>(pinned_frame_nums_.count());
    beginInsertRows(QModelIndex(), new_row, new_row);
    pinned_frame_nums_.append(frame_num);
    endInsertRows();

    refresh();
    return true;
}

void PinnedRowsModel::unpinFrame(int frame_num)
{
    int row = static_cast<int>(pinned_frame_nums_.indexOf(frame_num));
    if (row < 0) {
        return;
    }

    beginRemoveRows(QModelIndex(), row, row);
    pinned_frame_nums_.removeAt(row);
    endRemoveRows();
}

void PinnedRowsModel::clear()
{
    if (pinned_frame_nums_.isEmpty()) {
        return;
    }

    beginRemoveRows(QModelIndex(), 0, static_cast<int>(pinned_frame_nums_.count()) - 1);
    pinned_frame_nums_.clear();
    endRemoveRows();
}

bool PinnedRowsModel::isPinned(int frame_num) const
{
    return pinned_frame_nums_.contains(frame_num);
}

void PinnedRowsModel::refresh()
{
    if (pinned_frame_nums_.isEmpty() || !packet_list_model_) {
        return;
    }

    emit layoutAboutToBeChanged();

    // Captured before sorting (frame number -> old proxy row) so any
    // QPersistentModelIndex referencing a pinned row can be remapped to
    // wherever that same frame number ends up after the sort below,
    // rather than being left silently pointing at whatever row number
    // happens to occupy that position afterward -- required by
    // QAbstractItemModel's own layoutChanged() contract (see
    // changePersistentIndexList() below).
    QList<int> old_frame_nums = pinned_frame_nums_;

    // Order pinned packets to match the primary view's current sort
    // (whatever column/order the user last sorted by, or frame-number
    // order if they haven't sorted at all), so filtered-out pinned
    // packets interleave naturally with visible ones instead of always
    // sorting after them. Using packetNumberToRow() here previously
    // meant a filtered-out packet (row -1) always sorted after every
    // visible one, since there's no real row position to compare by --
    // pinnedRecordLessThan() instead compares the underlying frame data
    // directly, which is defined regardless of filter state.
    std::stable_sort(pinned_frame_nums_.begin(), pinned_frame_nums_.end(),
        [this](int a, int b) {
            return packet_list_model_->pinnedRecordLessThan(a, b);
        });

    QModelIndexList old_persistent_indexes = persistentIndexList();
    QModelIndexList new_persistent_indexes;
    new_persistent_indexes.reserve(old_persistent_indexes.count());
    for (const QModelIndex &old_index : old_persistent_indexes) {
        int frame_num = old_frame_nums.value(old_index.row(), -1);
        int new_row = (frame_num >= 0) ? static_cast<int>(pinned_frame_nums_.indexOf(frame_num)) : -1;
        new_persistent_indexes.append(new_row >= 0 ?
            index(new_row, old_index.column(), old_index.parent()) : QModelIndex());
    }
    changePersistentIndexList(old_persistent_indexes, new_persistent_indexes);

    emit layoutChanged();
}

int PinnedRowsModel::sourceRowForPinnedIndex(int proxy_row) const
{
    if (!packet_list_model_ || proxy_row < 0 || proxy_row >= pinned_frame_nums_.count()) {
        return -1;
    }
    return packet_list_model_->packetNumberToRow(pinned_frame_nums_[proxy_row]);
}

QVariant PinnedRowsModel::data(const QModelIndex &proxy_index, int role) const
{
    if (!proxy_index.isValid() || !packet_list_model_) {
        return QVariant();
    }
    if (proxy_index.row() < 0 || proxy_index.row() >= pinned_frame_nums_.count()) {
        return QVariant();
    }
    return packet_list_model_->dataForFrameNum(pinned_frame_nums_[proxy_index.row()], proxy_index.column(), role);
}

Qt::ItemFlags PinnedRowsModel::flags(const QModelIndex &proxy_index) const
{
    if (!proxy_index.isValid() || !packet_list_model_) {
        return Qt::NoItemFlags;
    }
    if (proxy_index.row() < 0 || proxy_index.row() >= pinned_frame_nums_.count()) {
        return Qt::NoItemFlags;
    }

    // mapToSource() resolves to an invalid index whenever this pinned
    // frame is currently filtered out of the source model (see its own
    // comment), which would otherwise make QAbstractProxyModel's default
    // flags() implementation query the source model with an invalid
    // index -- diverging from what data() already correctly reports for
    // this same (filtered-out but still pinned) row. Falling back to row
    // 0 of the requested column mirrors how a real, visible row's flags
    // are queried, just resolved by frame number instead of row.
    int source_row = sourceRowForPinnedIndex(proxy_index.row());
    if (source_row < 0) {
        return sourceModel() ? sourceModel()->flags(sourceModel()->index(0, proxy_index.column())) : Qt::NoItemFlags;
    }
    return sourceModel()->flags(sourceModel()->index(source_row, proxy_index.column()));
}

void PinnedRowsModel::sourceDataChanged(const QModelIndex &source_top_left, const QModelIndex &source_bottom_right,
                                        const QList<int> &roles)
{
    if (!packet_list_model_ || pinned_frame_nums_.isEmpty()) {
        return;
    }
    if (!source_top_left.isValid() || !source_bottom_right.isValid()) {
        return;
    }

    int source_top_row = source_top_left.row();
    int source_bottom_row = source_bottom_right.row();

    // The changed range is expressed in the source model's own row
    // numbering; each pinned frame's current row there (if any -- it may
    // be filtered out, in which case it can't be part of any dataChanged()
    // range and is safely skipped) is looked up individually, since the
    // pinned rows are a scattered, non-contiguous subset of source rows
    // with no fixed relationship to this proxy's own (packed) row numbers.
    for (int proxy_row = 0; proxy_row < pinned_frame_nums_.count(); proxy_row++) {
        int source_row = sourceRowForPinnedIndex(proxy_row);
        if (source_row < source_top_row || source_row > source_bottom_row) {
            continue;
        }
        QModelIndex changed_top_left = index(proxy_row, source_top_left.column());
        QModelIndex changed_bottom_right = index(proxy_row, source_bottom_right.column());
        emit dataChanged(changed_top_left, changed_bottom_right, roles);
    }
}

QModelIndex PinnedRowsModel::mapToSource(const QModelIndex &proxy_index) const
{
    if (!proxy_index.isValid() || !packet_list_model_) {
        return QModelIndex();
    }

    int source_row = sourceRowForPinnedIndex(proxy_index.row());
    if (source_row < 0) {
        return QModelIndex();
    }

    return packet_list_model_->index(source_row, proxy_index.column());
}

QModelIndex PinnedRowsModel::mapFromSource(const QModelIndex &source_index) const
{
    if (!source_index.isValid() || !packet_list_model_) {
        return QModelIndex();
    }

    frame_data *fdata = packet_list_model_->getRowFdata(source_index.row());
    if (!fdata) {
        return QModelIndex();
    }

    int proxy_row = static_cast<int>(pinned_frame_nums_.indexOf((int)fdata->num));
    if (proxy_row < 0) {
        return QModelIndex();
    }

    return index(proxy_row, source_index.column());
}

QModelIndex PinnedRowsModel::index(int row, int column, const QModelIndex &parent) const
{
    if (parent.isValid() || row < 0 || row >= pinned_frame_nums_.count() || column < 0 || column >= columnCount()) {
        return QModelIndex();
    }
    // Attach the physical PacketListRecord directly (available regardless
    // of the display filter -- see PacketListModel::physicalRecordForFrameNum())
    // rather than leaving the internal pointer null. Delegates such as
    // MultiColorPacketDelegate read index.internalPointer() straight off
    // the index the view hands them (this proxy's own index, not a
    // source-mapped one), so a null pointer here meant they always fell
    // back to plain QStyledItemDelegate painting for every pinned row.
    PacketListRecord *record = packet_list_model_ ?
        packet_list_model_->physicalRecordForFrameNum(pinned_frame_nums_[row]) : nullptr;
    return createIndex(row, column, record);
}

QModelIndex PinnedRowsModel::parent(const QModelIndex &) const
{
    return QModelIndex();
}

int PinnedRowsModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return static_cast<int>(pinned_frame_nums_.count());
}

int PinnedRowsModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid() || !sourceModel()) {
        return 0;
    }
    return sourceModel()->columnCount();
}
