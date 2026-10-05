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
#include <ui/qt/models/packet_list_proxy_model.h>

#include <algorithm>

PinnedRowsModel::PinnedRowsModel(QObject *parent) :
    QAbstractProxyModel(parent),
    packet_list_model_(nullptr),
    sort_model_(nullptr)
{
}

void PinnedRowsModel::setSourceModel(QAbstractItemModel *source_model)
{
    beginResetModel();

    if (sourceModel()) {
        disconnect(sourceModel(), nullptr, this, nullptr);
    }

    QAbstractProxyModel::setSourceModel(source_model);
    packet_list_model_ = qobject_cast<PacketListModel *>(source_model);
    pinned_frame_nums_.clear();

    if (source_model) {
        connect(source_model, &QAbstractItemModel::dataChanged,
                this, &PinnedRowsModel::sourceDataChanged);
        connect(source_model, &QAbstractItemModel::modelAboutToBeReset,
                this, &PinnedRowsModel::sourceModelAboutToBeReset);
        connect(source_model, &QAbstractItemModel::modelReset,
                this, &PinnedRowsModel::sourceModelReset);
        // The source model's layout changes (which only announce that the
        // data for every row has changed) reach us through refresh(),
        // which the packet list calls on its own proxy model's
        // layoutChanged(), so they aren't forwarded here.
        connect(source_model, &QAbstractItemModel::headerDataChanged,
                this, &QAbstractItemModel::headerDataChanged);
    }

    endResetModel();
}

void PinnedRowsModel::setSortModel(PacketListProxyModel *sort_model)
{
    sort_model_ = sort_model;
    refresh();
}

bool PinnedRowsModel::pinFrame(int frame_num)
{
    if (pinned_frame_nums_.contains(frame_num)) {
        return true;
    }
    if (pinned_frame_nums_.count() >= kMaxPinnedRows) {
        return false;
    }
    if (!packet_list_model_ || !packet_list_model_->physicalRecordForFrameNum(frame_num)) {
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
    int row = rowForFrameNum(frame_num);
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
    if (pinned_frame_nums_.isEmpty()) {
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
    // sorting after them. pinnedRecordLessThan() compares the underlying
    // frame data directly, which is defined regardless of filter state.
    std::stable_sort(pinned_frame_nums_.begin(), pinned_frame_nums_.end(),
        [this](int a, int b) {
            return sort_model_ ? sort_model_->pinnedRecordLessThan(a, b) : a < b;
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

void PinnedRowsModel::sourceModelAboutToBeReset()
{
    // The source model is about to delete every packet, pinned or not.
    beginResetModel();
    pinned_frame_nums_.clear();
}

void PinnedRowsModel::sourceModelReset()
{
    endResetModel();
}

void PinnedRowsModel::sourceDataChanged(const QModelIndex &source_top_left, const QModelIndex &source_bottom_right,
                                        const QList<int> &roles)
{
    if (pinned_frame_nums_.isEmpty() || !source_top_left.isValid() || !source_bottom_right.isValid()) {
        return;
    }

    // The source model's rows are in frame number order (frame N is row
    // N - 1), and the pinned rows are a scattered subset of them, so each
    // pinned frame is checked against the changed range individually.
    for (int row = 0; row < pinned_frame_nums_.count(); row++) {
        int source_row = pinned_frame_nums_[row] - 1;
        if (source_row < source_top_left.row() || source_row > source_bottom_right.row()) {
            continue;
        }
        emit dataChanged(index(row, source_top_left.column()), index(row, source_bottom_right.column()), roles);
    }
}

QModelIndex PinnedRowsModel::mapToSource(const QModelIndex &proxy_index) const
{
    if (!proxy_index.isValid() || !packet_list_model_) {
        return QModelIndex();
    }
    if (proxy_index.row() < 0 || proxy_index.row() >= pinned_frame_nums_.count()) {
        return QModelIndex();
    }

    // The source model's rows are in frame number order.
    return packet_list_model_->index(pinned_frame_nums_[proxy_index.row()] - 1, proxy_index.column());
}

QModelIndex PinnedRowsModel::mapFromSource(const QModelIndex &source_index) const
{
    if (!source_index.isValid()) {
        return QModelIndex();
    }

    return index(rowForFrameNum(source_index.row() + 1), source_index.column());
}

QModelIndex PinnedRowsModel::index(int row, int column, const QModelIndex &parent) const
{
    if (parent.isValid() || row < 0 || row >= pinned_frame_nums_.count() || column < 0 || column >= columnCount()) {
        return QModelIndex();
    }
    // Attach the PacketListRecord, as the source model does, since
    // delegates such as MultiColorPacketDelegate read
    // index.internalPointer() straight off the index the view hands them.
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

bool PinnedRowsModel::hasChildren(const QModelIndex &parent) const
{
    return !parent.isValid() && rowCount() > 0;
}

QVariant PinnedRowsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (!sourceModel()) {
        return QVariant();
    }
    return sourceModel()->headerData(section, orientation, role);
}
