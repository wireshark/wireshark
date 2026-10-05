/* packet_list_proxy_model.cpp
 *
 * Proxy model that filters and sorts the packets in a PacketListModel
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <cmath>
#include <stdexcept>

#include "packet_list_proxy_model.h"
#include "packet_list_model.h"
#include "packet_list_record.h"

#include "file.h"

#include <epan/column.h>
#include <epan/prefs.h>

#include "ui/packet_list_utils.h"
#include "ui/recent.h"

#include <ui/qt/progress_frame.h>
#include "main_application.h"
#include <ui/qt/main_window.h>

#include <QElapsedTimer>
#include <QTimer>

class SortAbort : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

static PacketListProxyModel * glbl_plist_proxy_model = Q_NULLPTR;
static const int reserved_packets_ = 100000;
constexpr int buffer_size_ = reserved_packets_ / 10;

void
packet_list_recreate_visible_rows(void)
{
    if (glbl_plist_proxy_model)
        glbl_plist_proxy_model->recreateVisibleRows();
}

void
packet_list_need_recreate_visible_rows(void)
{
    if (glbl_plist_proxy_model)
        glbl_plist_proxy_model->needRecreateVisibleRows();
}

PacketListProxyModel::PacketListProxyModel(QObject *parent) :
    QAbstractProxyModel(parent),
    packet_list_model_(nullptr),
    number_to_row_(QVector<int>()),
    need_recreate_visible_rows_(false),
    idle_dissection_row_(0)
{
    Q_ASSERT(glbl_plist_proxy_model == Q_NULLPTR);
    glbl_plist_proxy_model = this;

    visible_rows_.reserve(reserved_packets_);
    number_to_row_.reserve(reserved_packets_);

    idle_dissection_timer_ = new QElapsedTimer();
}

PacketListProxyModel::~PacketListProxyModel()
{
    delete idle_dissection_timer_;
    if (glbl_plist_proxy_model == this) {
        glbl_plist_proxy_model = Q_NULLPTR;
    }
}

void PacketListProxyModel::setSourceModel(QAbstractItemModel *source_model)
{
    beginResetModel();

    if (sourceModel()) {
        disconnect(sourceModel(), nullptr, this, nullptr);
    }

    QAbstractProxyModel::setSourceModel(source_model);
    packet_list_model_ = qobject_cast<PacketListModel *>(source_model);
    clearVisibleRows();

    if (source_model) {
        connect(source_model, &QAbstractItemModel::rowsInserted,
                this, &PacketListProxyModel::sourceRowsInserted);
        connect(source_model, &QAbstractItemModel::modelAboutToBeReset,
                this, &PacketListProxyModel::sourceModelAboutToBeReset);
        connect(source_model, &QAbstractItemModel::modelReset,
                this, &PacketListProxyModel::sourceModelReset);
        connect(source_model, &QAbstractItemModel::dataChanged,
                this, &PacketListProxyModel::sourceDataChanged);
        connect(source_model, &QAbstractItemModel::headerDataChanged,
                this, &PacketListProxyModel::sourceHeaderDataChanged);
        // The source model uses layout changes to announce that the data
        // for every row has changed (see PacketListModel::invalidateAllColumnStrings());
        // its rows never actually move, so neither do ours.
        connect(source_model, &QAbstractItemModel::layoutAboutToBeChanged,
                this, [this]() { emit layoutAboutToBeChanged(); });
        connect(source_model, &QAbstractItemModel::layoutChanged,
                this, [this]() { emit layoutChanged(); });
    }

    endResetModel();
}

capture_file *PacketListProxyModel::captureFile() const
{
    return packet_list_model_ ? packet_list_model_->captureFile() : nullptr;
}

QModelIndex PacketListProxyModel::mapToSource(const QModelIndex &proxy_index) const
{
    if (!proxy_index.isValid() || !packet_list_model_)
        return QModelIndex();

    PacketListRecord *record = static_cast<PacketListRecord*>(proxy_index.internalPointer());
    if (!record || !record->frameData())
        return QModelIndex();

    // The source model's rows are in frame number order.
    return packet_list_model_->index(static_cast<int>(record->frameData()->num) - 1, proxy_index.column());
}

QModelIndex PacketListProxyModel::mapFromSource(const QModelIndex &source_index) const
{
    if (!source_index.isValid())
        return QModelIndex();

    PacketListRecord *record = static_cast<PacketListRecord*>(source_index.internalPointer());
    if (!record)
        return QModelIndex();

    return index(visibleIndexOf(record->frameData()), source_index.column());
}

// Packet list records have no children (for now, at least).
QModelIndex PacketListProxyModel::index(int row, int column, const QModelIndex &parent) const
{
    if (parent.isValid())
        return QModelIndex();

    if (row >= visible_rows_.count() || row < 0 || !captureFile() || column < 0 || column >= columnCount())
        return QModelIndex();

    PacketListRecord *record = visible_rows_[row];

    return createIndex(row, column, record);
}

// Everything is under the root.
QModelIndex PacketListProxyModel::parent(const QModelIndex &) const
{
    return QModelIndex();
}

int PacketListProxyModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;

    return static_cast<int>(visible_rows_.count());
}

int PacketListProxyModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid() || !sourceModel())
        return 0;

    return sourceModel()->columnCount();
}

bool PacketListProxyModel::hasChildren(const QModelIndex &parent) const
{
    // QAbstractProxyModel's default asks the source model, which has rows
    // even when none of them pass the display filter.
    return !parent.isValid() && rowCount() > 0;
}

QVariant PacketListProxyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (!sourceModel())
        return QVariant();

    return sourceModel()->headerData(section, orientation, role);
}

int PacketListProxyModel::packetNumberToRow(int packet_num) const
{
    // map 1-based values to 0-based row numbers. Invisible rows are stored as
    // the default value (0) and should map to -1.
    return number_to_row_.value(packet_num) - 1;
}

void PacketListProxyModel::needRecreateVisibleRows()
{
    need_recreate_visible_rows_ = packet_list_model_ && !packet_list_model_->isEmpty();
}

unsigned PacketListProxyModel::recreateVisibleRows()
{
    if (!packet_list_model_)
        return 0;

    // Have the source model insert any packets appended since its last
    // update first, so that the rebuild below includes them. Setting
    // need_recreate_visible_rows_ first keeps sourceRowsInserted() from
    // adding them separately.
    need_recreate_visible_rows_ = true;
    packet_list_model_->flushNewRows();

    beginResetModel();
    visible_rows_.resize(0);
    number_to_row_.fill(0);
    endResetModel();
    aggregation_key_row_.clear();

    int source_rows = packet_list_model_->rowCount();
    for (int row = 0; row < source_rows; row++) {
        updateVisibleRows(packet_list_model_->physicalRecordAt(row));
    }
    need_recreate_visible_rows_ = false;
    if (!visible_rows_.isEmpty()) {
        beginInsertRows(QModelIndex(), 0, static_cast<int>(visible_rows_.count()) - 1);
        endInsertRows();
    }
    idle_dissection_row_ = 0;
    return static_cast<unsigned>(visible_rows_.count());
}

void PacketListProxyModel::clearVisibleRows()
{
    visible_rows_.resize(0);
    number_to_row_.resize(0);
    aggregation_key_row_.clear();
    idle_dissection_timer_->invalidate();
    idle_dissection_row_ = 0;
    need_recreate_visible_rows_ = false;

    // sort_cap_file_ et al. are static and otherwise persist across a
    // capture file close/reopen, so pinnedRecordLessThan()'s "no sort
    // requested this session" check (sort_cap_file_ == nullptr) would
    // otherwise stay false and use stale sort state from a previous file.
    sort_cap_file_ = nullptr;
}

void PacketListProxyModel::sourceModelAboutToBeReset()
{
    beginResetModel();
    // The source model is about to delete the records we point to.
    clearVisibleRows();
}

void PacketListProxyModel::sourceModelReset()
{
    endResetModel();
}

void PacketListProxyModel::sourceRowsInserted(const QModelIndex &parent, int first, int last)
{
    if (parent.isValid() || !packet_list_model_ || need_recreate_visible_rows_)
        return;

    QVector<PacketListRecord *> new_visible_rows;
    for (int row = first; row <= last; row++) {
        PacketListRecord *record = packet_list_model_->physicalRecordAt(row);
        if (!record)
            continue;
        const frame_data *fdata = record->frameData();
        if (fdata->passed_dfilter || fdata->ref_time) {
            new_visible_rows << record;
        }
    }

    if (new_visible_rows.isEmpty())
        return;

    int pos = static_cast<int>(visible_rows_.count());
    beginInsertRows(QModelIndex(), pos, pos + static_cast<int>(new_visible_rows.count()) - 1);
    foreach (PacketListRecord *record, new_visible_rows) {
        updateVisibleRows(record);
    }
    endInsertRows();
}

void PacketListProxyModel::sourceDataChanged(const QModelIndex &source_top_left, const QModelIndex &source_bottom_right,
                                             const QList<int> &roles)
{
    if (!source_top_left.isValid() || !source_bottom_right.isValid() || visible_rows_.isEmpty())
        return;

    int first = 0;
    int last = rowCount() - 1;

    // The source rows are in frame number order, and ours generally aren't,
    // so a range of source rows maps to a scattered set of our rows. Report
    // the span covering all of them, unless the whole source model changed.
    if (source_top_left.row() > 0 || source_bottom_right.row() < sourceModel()->rowCount() - 1) {
        first = rowCount();
        last = -1;
        for (int source_row = source_top_left.row(); source_row <= source_bottom_right.row(); source_row++) {
            int row = packetNumberToRow(source_row + 1);
            if (row >= 0) {
                first = qMin(first, row);
                last = qMax(last, row);
            }
        }
        if (last < 0)
            return;
    }

    emit dataChanged(index(first, source_top_left.column()), index(last, source_bottom_right.column()), roles);
}

void PacketListProxyModel::sourceHeaderDataChanged(Qt::Orientation orientation, int first, int last)
{
    emit headerDataChanged(orientation, first, last);
}

void PacketListProxyModel::setDisplayedFrameMark(bool set)
{
    if (packet_list_model_) {
        packet_list_model_->setFrameMark(visible_rows_, set);
    }
}

void PacketListProxyModel::setDisplayedFrameIgnore(bool set)
{
    if (packet_list_model_) {
        packet_list_model_->setFrameIgnore(visible_rows_, set);
    }
}

int PacketListProxyModel::sort_column_;
int PacketListProxyModel::sort_column_is_numeric_;
int PacketListProxyModel::text_sort_column_;
Qt::SortOrder PacketListProxyModel::sort_order_;
capture_file *PacketListProxyModel::sort_cap_file_;
bool PacketListProxyModel::stop_flag_;
ProgressFrame *PacketListProxyModel::progress_frame_;
double PacketListProxyModel::comps_;
double PacketListProxyModel::exp_comps_;

static QElapsedTimer busy_timer_;
constexpr int busy_timeout_ = 65; // ms, approximately 15 fps
void PacketListProxyModel::sort(int column, Qt::SortOrder order)
{
    capture_file *cap_file = captureFile();
    if (!cap_file || visible_rows_.count() < 1) return;
    if (column < 0) return;

    QString col_title = get_column_title(column);

    /* Make sure we're actually going to sort. Note that the header
     * has no way of knowing that sorting failed, so in these cases
     * the sort indicator have the value that the user requested
     * regardless.
     */
    if (PacketListRecord::textColumn(column) >= 0 && (unsigned)visible_rows_.count() > prefs.gui_packet_list_cached_rows_max) {
        /* Column not based on frame data but by column text that requires
         * dissection, so to sort in a reasonable amount of time the column
         * text needs to be cached.
         */
        /* If the sort is being triggered because the columns were already
         * sorted and the filter is being cleared (or changed to something
         * else with more rows than fit in the cache), then the temporary
         * message will be immediately overwritten with the standard capture
         * statistics by the packets_bar_update() call after thawing the rows.
         * It will still blink yellow, and the user will get the message if
         * they then click on the header file (wondering why it didn't sort.)
         */
        if (col_title.isEmpty()) {
            col_title = tr("Column");
        }
        QString temp_msg = tr("%1 can only be sorted with %2 or fewer visible rows; increase cache size in Layout preferences").arg(col_title).arg(prefs.gui_packet_list_cached_rows_max);
        mainApp->pushStatus(MainApplication::TemporaryStatus, temp_msg);
        return;
    }

    /* If we are currently in the middle of reading the capture file, don't
     * sort. PacketList::captureFileReadFinished invalidates all the cached
     * column strings and then tries to sort again.
     * Similarly, claim the read lock because we don't want the file to
     * change out from under us while sorting, which can segfault. (Previously
     * we ignored user input, but now in order to cancel sorting we don't.)
     *
     * This also means we can't sort while still sorting. That would crash
     * too, because recordLessThan depends on the value of class private
     * variables, and so we can't change them while a previous sort is using
     * them. Maybe if we made the comparison function a closure using the
     * current values.
     */
    if (cap_file->read_lock) {
        ws_info("Refusing to sort because capture file is being read");
        /* We shouldn't have to tell the user because we're just deferring
         * the sort until PacketList::captureFileReadFinished; the case
         * where we don't sort because we're currently sorting is perhaps
         * slightly more surprising to the user, but there is a progress bar.
         * So maybe we should push a status message after all?
         */
        return;
    }
    sort_cap_file_ = cap_file;
    sort_cap_file_->read_lock = true;
    sort_order_ = order;
    sort_column_ = column;
    text_sort_column_ = PacketListRecord::textColumn(column);

    QString busy_msg;
    if (!col_title.isEmpty()) {
        busy_msg = tr("Sorting \"%1\"…").arg(col_title);
    } else {
        busy_msg = tr("Sorting …");
    }
    stop_flag_ = false;
    comps_ = 0;
    /* XXX: The expected number of comparisons is O(N log N), but this could
     * be a pretty significant overestimate of the amount of time it takes,
     * if there are lots of identical entries. (Especially with string
     * comparisons, some comparisons are faster than others.) Better to
     * overestimate?
     */
    exp_comps_ = log2(visible_rows_.count()) * visible_rows_.count();
    progress_frame_ = nullptr;
    if (MainWindow *mw = mainApp->mainWindow()) {
        progress_frame_ = mw->findChild<ProgressFrame *>();
        if (progress_frame_) {
            progress_frame_->showProgress(busy_msg, true, false, &stop_flag_, 0);
            connect(progress_frame_, &ProgressFrame::stopLoading,
                    this, &PacketListProxyModel::stopSorting);
        }
    }

    busy_timer_.start();
    sort_column_is_numeric_ = isNumericColumn(sort_column_);
    QVector<PacketListRecord *> sorted_visible_rows_ = visible_rows_;
    try {
        if (recent.aggregation_view && prefs.aggregation_fields_num > 0) {
            for (QHash<QString, int>::const_iterator it = aggregation_key_row_.constBegin();
                it != aggregation_key_row_.constEnd(); ++it) {
                sorted_visible_rows_[it.value()]->frameData()->aggregation_key = g_strdup(it.key().toUtf8());
            }
        }
        std::sort(sorted_visible_rows_.begin(), sorted_visible_rows_.end(), recordLessThan);

        // This causes the QItemSelectionModel to create persistent indexes for
        // each row (instead of just storing the top left and bottom right.)
        // XXX - layoutChanged might be slow if the user has 100 k rows selected,
        // but then again other things in the GUI with multi-select are probably
        // slow then too. We could use resetModel in such a case.
        emit layoutAboutToBeChanged(QList<QPersistentModelIndex>(), QAbstractItemModel::VerticalSortHint);
        QModelIndexList oldIndexes = persistentIndexList();
        visible_rows_.resize(0);
        number_to_row_.fill(0);
        aggregation_key_row_.clear();
        foreach (PacketListRecord *record, sorted_visible_rows_) {
            updateVisibleRows(record);
        }
        QModelIndexList newIndexes;
        for (const auto &oldIdx : oldIndexes) {
            PacketListRecord *record = static_cast<PacketListRecord*>(oldIdx.internalPointer());
            if (!record)
                continue;
            int row = visibleIndexOf(record->frameData());
            newIndexes.append(createIndex(row, oldIdx.column(), record));
        }
        changePersistentIndexList(oldIndexes, newIndexes);
        emit layoutChanged(QList<QPersistentModelIndex>(), QAbstractItemModel::VerticalSortHint);

    } catch (const SortAbort& e) {
        mainApp->pushStatus(MainApplication::TemporaryStatus, e.what());
    }

    if (progress_frame_ != nullptr) {
        progress_frame_->hide();
        disconnect(progress_frame_, &ProgressFrame::stopLoading,
                   this, &PacketListProxyModel::stopSorting);
    }
    sort_cap_file_->read_lock = false;

    // Using layoutChanged keeps the current selection but does not necessarily
    // scroll to it if it is not visible. If we have a single current frame we
    // can scroll to it. It's harder to determine what to do for multi-select.
    // If the current frame has no row of its own here (e.g., it's a pinned
    // packet that's filtered out, or aggregated into another packet's row),
    // there's nothing to scroll to, and going to it would instead select
    // another packet.
    // XXX - It might make more sense to have the PacketList connect to
    // layoutChanged and call scrollTo with the currentIndex there. That would
    // be a little lighter weight and better separation of model vs view.
    if (cap_file->current_frame && rowOfPacket(cap_file->current_frame) >= 0) {
        emit goToPacket(cap_file->current_frame->num);
    }
}

void PacketListProxyModel::stopSorting()
{
    stop_flag_ = true;
}

bool PacketListProxyModel::isNumericColumn(int column)
{
    /* XXX - Should this and ui/packet_list_utils.c right_justify_column()
     * be the same list of columns?
     */
    if (column < 0) {
        return false;
    }
    switch (sort_cap_file_->cinfo.columns[column].col_fmt) {
    case COL_CUMULATIVE_BYTES: /**< 3) Cumulative number of bytes */
    case COL_DELTA_TIME:     /**< 5) Delta time */
    case COL_DELTA_TIME_DIS: /**< 8) Delta time displayed*/
    case COL_UNRES_DST_PORT: /**< 10) Unresolved dest port */
    case COL_FREQ_CHAN:      /**< 15) IEEE 802.11 (and WiMax?) - Channel */
    case COL_RSSI:           /**< 22) IEEE 802.11 - received signal strength */
    case COL_TX_RATE:        /**< 23) IEEE 802.11 - TX rate in Mbps */
    case COL_NUMBER:         /**< 32) Packet list item number */
    case COL_NUMBER_DIS:     /**< 33) Packet list item number */
    case COL_PACKET_LENGTH:  /**< 34) Packet length in bytes */
    case COL_UNRES_SRC_PORT: /**< 42) Unresolved source port */
        return true;

    /*
     * Try to sort port numbers as number, if the numeric comparison fails (due
     * to name resolution), it will fallback to string comparison.
     * */
    case COL_RES_DST_PORT:   /**< 10) Resolved dest port */
    case COL_DEF_DST_PORT:   /**< 12) Destination port */
    case COL_DEF_SRC_PORT:   /**< 38) Source port */
    case COL_RES_SRC_PORT:   /**< 41) Resolved source port */
        return true;

    case COL_CUSTOM:
        /* handle custom columns below. */
        break;

    default:
        return false;
    }

    unsigned num_fields = g_slist_length(sort_cap_file_->cinfo.columns[column].col_custom_fields_ids);
    col_custom_t *col_custom;
    for (unsigned i = 0; i < num_fields; i++) {
        col_custom = (col_custom_t *) g_slist_nth_data(sort_cap_file_->cinfo.columns[column].col_custom_fields_ids, i);
        if (col_custom->field_id == 0) {
            ftenum_t type = dfilter_get_return_type(col_custom->dfilter);
            if (FT_IS_INTEGER(type) || FT_IS_FLOATING(type) || type == FT_BOOLEAN || type == FT_RELATIVE_TIME) {
                return true;
            }
            return false;
        }
        header_field_info *hfi = proto_registrar_get_nth(col_custom->field_id);

        /*
         * Reject a field when there is no numeric field type or when:
         * - there are (value_string) "strings"
         *   (but do accept fields which have a unit suffix).
         * - BASE_HEX or BASE_HEX_DEC (these have a constant width, string
         *   comparison is faster than conversion to double).
         * - BASE_CUSTOM (these can be formatted in any way).
         */
        if (!hfi ||
              (hfi->strings != NULL && !(hfi->display & BASE_UNIT_STRING)) ||
              !(((FT_IS_INT(hfi->type) || FT_IS_UINT(hfi->type)) &&
                 ((FIELD_DISPLAY(hfi->display) == BASE_DEC) ||
                  (FIELD_DISPLAY(hfi->display) == BASE_OCT) ||
                  (FIELD_DISPLAY(hfi->display) == BASE_DEC_HEX))) ||
                (hfi->type == FT_DOUBLE) || (hfi->type == FT_FLOAT) ||
                (hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
                (hfi->type == FT_RELATIVE_TIME))) {
            return false;
        }
    }

    return true;
}

void PacketListProxyModel::updateVisibleRows(PacketListRecord* record)
{
    const frame_data* fdata = record->frameData();
    if (!(fdata->passed_dfilter || fdata->ref_time)) {
        return;
    }
    record->setRow(static_cast<int>(visible_rows_.count()) + 1);
    if (!recent.aggregation_view || updateVisibleAggregationViewRows(record)) {
        visible_rows_ << record;
    }
    if (static_cast<uint32_t>(number_to_row_.size()) <= fdata->num) {
        number_to_row_.resize(fdata->num + buffer_size_);
    }
    number_to_row_[fdata->num] = record->row();
    if (recent.aggregation_view) {
        captureFile()->aggregation_count = static_cast<uint32_t>(visible_rows_.count());
    }
}

bool PacketListProxyModel::updateVisibleAggregationViewRows(PacketListRecord* record) {
    if (prefs.aggregation_fields_num == 0) return true;

    frame_data* fdata = record->frameData();
    if (fdata->aggregation_key == nullptr) return false; // Only packets containing the aggregation fields are displayed

    QString key = QString::fromUtf8(fdata->aggregation_key);
    frame_data_aggregation_free(fdata);
    if (!aggregation_key_row_.contains(key)) {
        aggregation_key_row_[key] = record->row() - 1;
        return true;
    }
    int row = aggregation_key_row_[key];
    frame_data* prev_frame = visible_rows_[row]->frameData();
    frame_data_aggregation_free(prev_frame);
    prev_frame->aggregated = true;
    record->setRow(row + 1);
    visible_rows_[row] = record;
    return false;
}

bool PacketListProxyModel::recordLessThan(PacketListRecord *r1, PacketListRecord *r2)
{
    comps_++;

    if (busy_timer_.elapsed() > busy_timeout_) {
        if (progress_frame_) {
            progress_frame_->setValue(static_cast<int>(comps_/exp_comps_ * 100));
        }
        // What's the least amount of processing that we can do which will draw
        // the busy indicator?
        mainApp->processEvents(QEventLoop::ExcludeSocketNotifiers, 1);
        if (stop_flag_) {
            throw SortAbort("Sorting aborted");
        }
        busy_timer_.restart();
    }

    return compareRecords(r1, r2);
}

bool PacketListProxyModel::compareRecords(PacketListRecord *r1, PacketListRecord *r2)
{
    int cmp_val;

    // Wherein we try to cram the logic of packet_list_compare_records,
    // _packet_list_compare_records, and packet_list_compare_custom from
    // gtk/packet_list_store.c into one function

    if (sort_column_ < 0) {
        // No column.
        cmp_val = frame_data_compare(sort_cap_file_->epan, r1->frameData(), r2->frameData(), COL_NUMBER);
    } else if (text_sort_column_ < 0) {
        // Column comes directly from frame data
        cmp_val = frame_data_compare(sort_cap_file_->epan, r1->frameData(), r2->frameData(), sort_cap_file_->cinfo.columns[sort_column_].col_fmt);
    } else  {
        QString r1String = r1->columnString(sort_cap_file_, sort_column_);
        QString r2String = r2->columnString(sort_cap_file_, sort_column_);
        // XXX: The naive string comparison compares Unicode code points.
        // Proper collation is more expensive
        cmp_val = r1String.compare(r2String);
        if (cmp_val != 0 && sort_column_is_numeric_) {
            // Custom column with numeric data (or something like a port number).
            // Attempt to convert to numbers.
            // XXX This is slow. Can we avoid doing this? Perhaps the actual
            // values used for sorting should be cached too as QVariant[List].
            // If so, we could consider using QCollatorSortKeys or similar
            // for strings as well.
            bool ok_r1, ok_r2;
            double num_r1 = parseNumericColumn(r1String, &ok_r1);
            double num_r2 = parseNumericColumn(r2String, &ok_r2);

            if (!ok_r1 && !ok_r2) {
                cmp_val = 0;
            } else if (!ok_r1 || (ok_r2 && num_r1 < num_r2)) {
                // either r1 is invalid (and sort it before others) or both
                // r1 and r2 are valid (sort normally)
                cmp_val = -1;
            } else if (!ok_r2 || (num_r1 > num_r2)) {
                cmp_val = 1;
            }
        }

        if (cmp_val == 0) {
            // All else being equal, compare column numbers.
            cmp_val = frame_data_compare(sort_cap_file_->epan, r1->frameData(), r2->frameData(), COL_NUMBER);
        }
    }

    if (sort_order_ == Qt::AscendingOrder) {
        return cmp_val < 0;
    } else {
        return cmp_val > 0;
    }
}

// Parses a field as a double. Handle values with suffixes ("12ms"), negative
// values ("-1.23") and fields with multiple occurrences ("1,2"). Marks values
// that do not contain any numeric value ("Unknown") as invalid.
double PacketListProxyModel::parseNumericColumn(const QString &val, bool *ok)
{
    QByteArray ba = val.toUtf8();
    const char *strval = ba.constData();
    char *end = NULL;
    double num = g_ascii_strtod(strval, &end);
    *ok = strval != end;
    return num;
}

bool PacketListProxyModel::pinnedRecordLessThan(int frame_num_a, int frame_num_b) const
{
    PacketListRecord *r1 = packet_list_model_ ? packet_list_model_->physicalRecordForFrameNum(frame_num_a) : nullptr;
    PacketListRecord *r2 = packet_list_model_ ? packet_list_model_->physicalRecordForFrameNum(frame_num_b) : nullptr;
    if (!r1 || !r2 || !r1->frameData() || !r2->frameData()) {
        // Fail safe to numeric order rather than crash on a lookup miss.
        return frame_num_a < frame_num_b;
    }

    // No sort has ever been explicitly requested this session (sort()
    // returns early for column < 0 without touching sort_cap_file_, so
    // it stays at its zero-initialized nullptr) -- fall back to plain
    // frame-number order, matching the model's own natural order.
    if (!sort_cap_file_) {
        return frame_num_a < frame_num_b;
    }

    return compareRecords(r1, r2);
}

void PacketListProxyModel::flushVisibleRows()
{
    // Rows the source model inserts are added here by sourceRowsInserted().
    if (packet_list_model_) {
        packet_list_model_->flushNewRows();
    }
}

// Fill our column string and colorization cache while the application is
// idle. Try to be as conservative with the CPU and disk as possible.
static const int idle_dissection_interval_ = 5; // ms
void PacketListProxyModel::dissectIdle(bool reset)
{
    if (reset) {
//        qDebug() << "=di reset" << idle_dissection_row_;
        idle_dissection_row_ = 0;
    } else if (!idle_dissection_timer_->isValid()) {
        return;
    }

    idle_dissection_timer_->restart();

    capture_file *cap_file = captureFile();
    if (!cap_file || cap_file->read_lock) {
        // File is in use (at worst, being rescanned). Try again later.
        QTimer::singleShot(idle_dissection_interval_, this, [=]() { dissectIdle(); });
        return;
    }

    int source_rows = sourceModel()->rowCount();
    int first = idle_dissection_row_;
    while (idle_dissection_timer_->elapsed() < idle_dissection_interval_
           && idle_dissection_row_ < source_rows) {
        ensureRowColorized(idle_dissection_row_);
        idle_dissection_row_++;
//        if (idle_dissection_row_ % 1000 == 0) qDebug() << "=di row" << idle_dissection_row_;
    }

    if (idle_dissection_row_ < source_rows) {
        QTimer::singleShot(0, this, [=]() { dissectIdle(); });
    } else {
        idle_dissection_timer_->invalidate();
    }

    // report colorization progress
    emit bgColorizationProgress(first+1, idle_dissection_row_+1);
}

frame_data *PacketListProxyModel::getRowFdata(QModelIndex idx) const
{
    if (!idx.isValid())
        return Q_NULLPTR;
    return getRowFdata(idx.row());
}

frame_data *PacketListProxyModel::getRowFdata(int row) const {
    if (row < 0 || row >= visible_rows_.count())
        return NULL;
    const PacketListRecord *record = visible_rows_[row];
    if (!record)
        return NULL;
    return record->frameData();
}

void PacketListProxyModel::ensureRowColorized(int row)
{
    if (row < 0 || row >= visible_rows_.count())
        return;
    PacketListRecord *record = visible_rows_[row];
    if (!record)
        return;
    if (!record->colorized()) {
        record->ensureColorized(captureFile());
    }
}

int PacketListProxyModel::visibleIndexOf(const frame_data *fdata) const
{
    if (fdata == nullptr) {
        return -1;
    }
    return packetNumberToRow(fdata->num);
}

int PacketListProxyModel::rowOfPacket(const frame_data *fdata) const
{
    int row = visibleIndexOf(fdata);
    return (row >= 0 && getRowFdata(row) == fdata) ? row : -1;
}
