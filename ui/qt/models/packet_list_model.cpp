/* packet_list_model.cpp
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

#include "packet_list_model.h"

#include "file.h"

#include <wsutil/nstime.h>
#include <epan/column.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "ui/packet_list_utils.h"
#include "ui/recent.h"

#include <epan/color_filters.h>
#include "frame_tvbuff.h"

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"
#include <ui/qt/main_window.h>
#include <ui/qt/main_status_bar.h>
#include <ui/qt/widgets/wireless_timeline.h>

#include <QColor>
#include <QElapsedTimer>
#include <QFontMetrics>
#include <QModelIndex>
#include <QElapsedTimer>

// Print timing information
//#define DEBUG_PACKET_LIST_MODEL 1

#ifdef DEBUG_PACKET_LIST_MODEL
#include <wsutil/time_util.h>
#endif

class SortAbort : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

static PacketListModel * glbl_plist_model = Q_NULLPTR;
static const int reserved_packets_ = 100000;

unsigned
packet_list_append(column_info *, frame_data *fdata)
{
    if (!glbl_plist_model)
        return 0;

    /* fdata should be filled with the stuff we need
     * strings are built at display time.
     */
    return glbl_plist_model->appendPacket(fdata);
}

void
packet_list_recreate_visible_rows(void)
{
    if (glbl_plist_model)
        glbl_plist_model->recreateVisibleRows();
}

PacketListModel::PacketListModel(QObject *parent, capture_file *cf) :
    QAbstractItemModel(parent),
    number_to_row_(QVector<int>()),
    max_row_height_(0),
    max_line_count_(1),
    idle_dissection_row_(0)
{
    Q_ASSERT(glbl_plist_model == Q_NULLPTR);
    glbl_plist_model = this;
    setCaptureFile(cf);

    physical_rows_.reserve(reserved_packets_);
    visible_rows_.reserve(reserved_packets_);
    new_visible_rows_.reserve(1000);
    number_to_row_.reserve(reserved_packets_);

    if (qobject_cast<MainWindow *>(mainApp->mainWindow()))
    {
            MainWindow *mw = qobject_cast<MainWindow *>(mainApp->mainWindow());
            QWidget * wtWidget = mw->findChild<WirelessTimeline *>();
            if (wtWidget && qobject_cast<WirelessTimeline *>(wtWidget))
            {
                WirelessTimeline * wt = qobject_cast<WirelessTimeline *>(wtWidget);
                connect(this, &PacketListModel::bgColorizationProgress,
                        wt, &WirelessTimeline::bgColorizationProgress);
            }

    }

    connect(this, &PacketListModel::maxLineCountChanged,
            this, &PacketListModel::emitItemHeightChanged,
            Qt::QueuedConnection);
    idle_dissection_timer_ = new QElapsedTimer();
}

PacketListModel::~PacketListModel()
{
    delete idle_dissection_timer_;
}

void PacketListModel::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
}

// Packet list records have no children (for now, at least).
QModelIndex PacketListModel::index(int row, int column, const QModelIndex &) const
{
    if (row >= visible_rows_.count() || row < 0 || !cap_file_ || column >= prefs.num_cols)
        return QModelIndex();

    PacketListRecord *record = visible_rows_[row];

    return createIndex(row, column, record);
}

// Everything is under the root.
QModelIndex PacketListModel::parent(const QModelIndex &) const
{
    return QModelIndex();
}

int PacketListModel::packetNumberToRow(int packet_num) const
{
    // map 1-based values to 0-based row numbers. Invisible rows are stored as
    // the default value (0) and should map to -1.
    return number_to_row_.value(packet_num) - 1;
}

unsigned PacketListModel::recreateVisibleRows()
{
    beginResetModel();
    visible_rows_.resize(0);
    number_to_row_.fill(0);
    endResetModel();

    foreach (PacketListRecord *record, physical_rows_) {
        frame_data *fdata = record->frameData();

        if (fdata->passed_dfilter || fdata->ref_time) {
            visible_rows_ << record;
            if (static_cast<uint32_t>(number_to_row_.size()) <= fdata->num) {
                number_to_row_.resize(fdata->num + 10000);
            }
            number_to_row_[fdata->num] = static_cast<int>(visible_rows_.count());
        }
    }
    if (!visible_rows_.isEmpty()) {
        beginInsertRows(QModelIndex(), 0, static_cast<int>(visible_rows_.count()) - 1);
        endInsertRows();
    }
    idle_dissection_row_ = 0;
    return static_cast<unsigned>(visible_rows_.count());
}

void PacketListModel::clear() {
    beginResetModel();
    qDeleteAll(physical_rows_);
    PacketListRecord::invalidateAllRecords();
    physical_rows_.resize(0);
    visible_rows_.resize(0);
    new_visible_rows_.resize(0);
    number_to_row_.resize(0);
    endResetModel();
    max_row_height_ = 0;
    max_line_count_ = 1;
    idle_dissection_timer_->invalidate();
    idle_dissection_row_ = 0;
}

void PacketListModel::invalidateAllColumnStrings()
{
    // https://bugreports.qt.io/browse/QTBUG-58580
    // https://bugreports.qt.io/browse/QTBUG-124173
    // https://codereview.qt-project.org/c/qt/qtbase/+/285280
    //
    // In Qt 6, QAbstractItemView::dataChanged determines how much of the
    // viewport rectangle is covered by the changed indices and only updates
    // that much. Unfortunately, if the number of indices is very large,
    // computing the union of the intersecting rectangle takes much longer
    // than unconditionally updating the entire viewport. It increases linearly
    // with the total number of packets in the list, unlike updating the
    // viewport, which scales with the size of the viewport but is unaffected
    // by undisplayed packets.
    //
    // In particular, if the data for all of the model is invalidated, we
    // know we want to update the entire viewport and very much do not
    // want to waste time calculating the affected area. (This can take
    // 1 s with 1.4 M packets, 9 s with 12 M packets.)
    //
    // Issuing layoutAboutToBeChanged() and layoutChanged() causes the
    // QTreeView to clear all the information for each of the view items,
    // but without clearing the current and selected items (unlike
    // [begin|end]ResetModel.)
    //
    // Theoretically this is less efficient because dataChanged() has a list
    // of what roles changed and the other signals do not; in practice,
    // neither QTreeView::dataChanged nor QAbstractItemView::dataChanged
    // actually use the roles parameter, and just reset everything.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutAboutToBeChanged();
#endif
    PacketListRecord::invalidateAllRecords();
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutChanged();
#else
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::DisplayRole);
#endif
}

void PacketListModel::resetColumns()
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutAboutToBeChanged();
#endif
    if (cap_file_) {
        PacketListRecord::resetColumns(&cap_file_->cinfo);
    }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutChanged();
#else
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
#endif
    emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1);
}

void PacketListModel::resetColorized()
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutAboutToBeChanged();
#endif
    PacketListRecord::resetColorization();
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutChanged();
#else
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
#endif
}

void PacketListModel::toggleFrameMark(const QModelIndexList &indeces)
{
    if (!cap_file_ || indeces.count() <= 0)
        return;

    int sectionMax = columnCount() - 1;

    foreach (QModelIndex index, indeces) {
        if (! index.isValid())
            continue;

        PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
        if (!record)
            continue;

        frame_data *fdata = record->frameData();
        if (!fdata)
            continue;

        if (fdata->marked)
            cf_unmark_frame(cap_file_, fdata);
        else
            cf_mark_frame(cap_file_, fdata);

        emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
                QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
    }
}

void PacketListModel::setDisplayedFrameMark(bool set)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutAboutToBeChanged();
#endif
    foreach (PacketListRecord *record, visible_rows_) {
        if (set) {
            cf_mark_frame(cap_file_, record->frameData());
        } else {
            cf_unmark_frame(cap_file_, record->frameData());
        }
    }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutChanged();
#else
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
#endif
}

void PacketListModel::toggleFrameIgnore(const QModelIndexList &indeces)
{
    if (!cap_file_ || indeces.count() <= 0)
        return;

    int sectionMax = columnCount() - 1;

    foreach (QModelIndex index, indeces) {
        if (! index.isValid())
            continue;

        PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
        if (!record)
            continue;

        frame_data *fdata = record->frameData();
        if (!fdata)
            continue;

        if (fdata->ignored)
            cf_unignore_frame(cap_file_, fdata);
        else
            cf_ignore_frame(cap_file_, fdata);

        emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
                QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
    }
}

void PacketListModel::setDisplayedFrameIgnore(bool set)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutAboutToBeChanged();
#endif
    foreach (PacketListRecord *record, visible_rows_) {
        if (set) {
            cf_ignore_frame(cap_file_, record->frameData());
        } else {
            cf_unignore_frame(cap_file_, record->frameData());
        }
    }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutChanged();
#else
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
#endif
}

void PacketListModel::toggleFrameRefTime(const QModelIndex &rt_index)
{
    if (!cap_file_ || !rt_index.isValid()) return;

    PacketListRecord *record = static_cast<PacketListRecord*>(rt_index.internalPointer());
    if (!record) return;

    frame_data *fdata = record->frameData();
    if (!fdata) return;

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutAboutToBeChanged();
#endif
    if (fdata->ref_time) {
        fdata->ref_time=0;
        cap_file_->ref_time_count--;
    } else {
        fdata->ref_time=1;
        cap_file_->ref_time_count++;
    }
    cf_reftime_packets(cap_file_);
    if (!fdata->ref_time && !fdata->passed_dfilter) {
        cap_file_->displayed_count--;
    }
    record->resetColumns(&cap_file_->cinfo);
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
}

void PacketListModel::unsetAllFrameRefTime()
{
    if (!cap_file_) return;

    /* XXX: we might need a progressbar here */

    foreach (PacketListRecord *record, physical_rows_) {
        frame_data *fdata = record->frameData();
        if (fdata->ref_time) {
            fdata->ref_time = 0;
        }
    }
    cap_file_->ref_time_count = 0;
    cf_reftime_packets(cap_file_);
    PacketListRecord::resetColumns(&cap_file_->cinfo);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    emit layoutChanged();
#else
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
#endif
}

void PacketListModel::addFrameComment(const QModelIndexList &indices, const QByteArray &comment)
{
    int sectionMax = columnCount() - 1;
    frame_data *fdata;
    if (!cap_file_) return;

    for (const auto &index : indices) {
        if (!index.isValid()) continue;

        PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
        if (!record) continue;

        fdata = record->frameData();
        wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
        wtap_block_add_string_option(pkt_block, OPT_COMMENT, comment.data(), comment.size());

        if (!cf_set_modified_block(cap_file_, fdata, pkt_block)) {
            cap_file_->packet_comment_count++;
            expert_update_comment_count(cap_file_->packet_comment_count);
        }

        // In case there are coloring rules or columns related to comments.
        // (#12519)
        //
        // XXX: "Does any active coloring rule relate to frame data"
        // could be an optimization. For columns, note that
        // "col_based_on_frame_data" only applies to built in columns,
        // not custom columns based on frame data. (Should we prevent
        // custom columns based on frame data from being created,
        // substituting them with the other columns?)
        //
        // Note that there are not currently any fields that depend on
        // whether other frames have comments, unlike with time references
        // and time shifts ("frame.time_relative", "frame.offset_shift", etc.)
        // If there were, then we'd need to reset data for all frames instead
        // of just the frames changed.
        record->invalidateColorized();
        record->invalidateRecord();
        emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
                QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
    }
}

void PacketListModel::setFrameComment(const QModelIndex &index, const QByteArray &comment, unsigned c_number)
{
    int sectionMax = columnCount() - 1;
    frame_data *fdata;
    if (!cap_file_) return;

    if (!index.isValid()) return;

    PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
    if (!record) return;

    fdata = record->frameData();

    wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
    if (comment.isEmpty()) {
        wtap_block_remove_nth_option_instance(pkt_block, OPT_COMMENT, c_number);
        if (!cf_set_modified_block(cap_file_, fdata, pkt_block)) {
            cap_file_->packet_comment_count--;
            expert_update_comment_count(cap_file_->packet_comment_count);
        }
    } else {
        wtap_block_set_nth_string_option_value(pkt_block, OPT_COMMENT, c_number, comment.data(), comment.size());
        cf_set_modified_block(cap_file_, fdata, pkt_block);
    }

    record->invalidateColorized();
    record->invalidateRecord();
    emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
}

void PacketListModel::deleteFrameComments(const QModelIndexList &indices)
{
    int sectionMax = columnCount() - 1;
    frame_data *fdata;
    if (!cap_file_) return;

    for (const auto &index : indices) {
        if (!index.isValid()) continue;

        PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
        if (!record) continue;

        fdata = record->frameData();
        wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
        unsigned n_comments = wtap_block_count_option(pkt_block, OPT_COMMENT);

        if (n_comments) {
            for (unsigned i = 0; i < n_comments; i++) {
                wtap_block_remove_nth_option_instance(pkt_block, OPT_COMMENT, 0);
            }
            if (!cf_set_modified_block(cap_file_, fdata, pkt_block)) {
                cap_file_->packet_comment_count -= n_comments;
                expert_update_comment_count(cap_file_->packet_comment_count);
            }

            record->invalidateColorized();
            record->invalidateRecord();
            emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
                    QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
        }
    }
}

void PacketListModel::deleteAllFrameComments()
{
    int row;
    int sectionMax = columnCount() - 1;
    if (!cap_file_) return;

    /* XXX: we might need a progressbar here */

    foreach (PacketListRecord *record, physical_rows_) {
        frame_data *fdata = record->frameData();
        wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
        unsigned n_comments = wtap_block_count_option(pkt_block, OPT_COMMENT);

        if (n_comments) {
            for (unsigned i = 0; i < n_comments; i++) {
                wtap_block_remove_nth_option_instance(pkt_block, OPT_COMMENT, 0);
            }
            cf_set_modified_block(cap_file_, fdata, pkt_block);

            record->invalidateColorized();
            record->invalidateRecord();
            row = packetNumberToRow(fdata->num);
            if (row > -1) {
                emit dataChanged(index(row, 0), index(row, sectionMax),
                    QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
            }
        }
    }
    cap_file_->packet_comment_count = 0;
    expert_update_comment_count(cap_file_->packet_comment_count);
}

void PacketListModel::setMaximumRowHeight(int height)
{
    max_row_height_ = height;
    // As the QTreeView uniformRowHeights documentation says,
    // "The height is obtained from the first item in the view. It is
    //  updated when the data changes on that item."
    emit dataChanged(index(0, 0), index(0, columnCount() - 1));
}

int PacketListModel::sort_column_;
int PacketListModel::sort_column_is_numeric_;
int PacketListModel::text_sort_column_;
Qt::SortOrder PacketListModel::sort_order_;
capture_file *PacketListModel::sort_cap_file_;
bool PacketListModel::stop_flag_;
ProgressFrame *PacketListModel::progress_frame_;
double PacketListModel::comps_;
double PacketListModel::exp_comps_;

QElapsedTimer busy_timer_;
const int busy_timeout_ = 65; // ms, approximately 15 fps
void PacketListModel::sort(int column, Qt::SortOrder order)
{
    if (!cap_file_ || visible_rows_.count() < 1) return;
    if (column < 0) return;

    if (physical_rows_.count() < 1)
        return;

    sort_column_ = column;
    text_sort_column_ = PacketListRecord::textColumn(column);
    sort_order_ = order;
    sort_cap_file_ = cap_file_;

    QString col_title = get_column_title(column);

    if (text_sort_column_ >= 0 && (unsigned)visible_rows_.count() > prefs.gui_packet_list_cached_rows_max) {
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
     */
    if (sort_cap_file_->read_lock) {
        ws_info("Refusing to sort because capture file is being read");
        /* We shouldn't have to tell the user because we're just deferring
         * the sort until PacketList::captureFileReadFinished
         */
        return;
    }
    sort_cap_file_->read_lock = true;

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
    if (qobject_cast<MainWindow *>(mainApp->mainWindow())) {
        MainWindow *mw = qobject_cast<MainWindow *>(mainApp->mainWindow());
        progress_frame_ = mw->findChild<ProgressFrame *>();
        if (progress_frame_) {
            progress_frame_->showProgress(busy_msg, true, false, &stop_flag_, 0);
            connect(progress_frame_, &ProgressFrame::stopLoading,
                    this, &PacketListModel::stopSorting);
        }
    }

    busy_timer_.start();
    sort_column_is_numeric_ = isNumericColumn(sort_column_);
    QVector<PacketListRecord *> sorted_visible_rows_ = visible_rows_;
    try {
        std::sort(sorted_visible_rows_.begin(), sorted_visible_rows_.end(), recordLessThan);

        beginResetModel();
        visible_rows_.resize(0);
        number_to_row_.fill(0);
        foreach (PacketListRecord *record, sorted_visible_rows_) {
            frame_data *fdata = record->frameData();

            if (fdata->passed_dfilter || fdata->ref_time) {
                visible_rows_ << record;
                if (number_to_row_.size() <= (int)fdata->num) {
                    number_to_row_.resize(fdata->num + 10000);
                }
                number_to_row_[fdata->num] = static_cast<int>(visible_rows_.count());
            }
        }
        endResetModel();
    } catch (const SortAbort& e) {
        mainApp->pushStatus(MainApplication::TemporaryStatus, e.what());
    }

    if (progress_frame_ != nullptr) {
        progress_frame_->hide();
        disconnect(progress_frame_, &ProgressFrame::stopLoading,
                   this, &PacketListModel::stopSorting);
    }
    sort_cap_file_->read_lock = false;

    if (cap_file_->current_frame) {
        emit goToPacket(cap_file_->current_frame->num);
    }
}

void PacketListModel::stopSorting()
{
    stop_flag_ = true;
}

bool PacketListModel::isNumericColumn(int column)
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
    case COL_PACKET_LENGTH:  /**< 33) Packet length in bytes */
    case COL_UNRES_SRC_PORT: /**< 41) Unresolved source port */
        return true;

    /*
     * Try to sort port numbers as number, if the numeric comparison fails (due
     * to name resolution), it will fallback to string comparison.
     * */
    case COL_RES_DST_PORT:   /**< 10) Resolved dest port */
    case COL_DEF_DST_PORT:   /**< 12) Destination port */
    case COL_DEF_SRC_PORT:   /**< 37) Source port */
    case COL_RES_SRC_PORT:   /**< 40) Resolved source port */
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
            /* XXX - We need some way to check the compiled dfilter's expected
             * return type. Best would be to use the actual field values return
             * and sort on those (we could skip expensive string conversions
             * in the numeric case, see below)
             */
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

bool PacketListModel::recordLessThan(PacketListRecord *r1, PacketListRecord *r2)
{
    int cmp_val = 0;
    comps_++;

    // Wherein we try to cram the logic of packet_list_compare_records,
    // _packet_list_compare_records, and packet_list_compare_custom from
    // gtk/packet_list_store.c into one function

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
double PacketListModel::parseNumericColumn(const QString &val, bool *ok)
{
    QByteArray ba = val.toUtf8();
    const char *strval = ba.constData();
    char *end = NULL;
    double num = g_ascii_strtod(strval, &end);
    *ok = strval != end;
    return num;
}

// ::data is const so we have to make changes here.
void PacketListModel::emitItemHeightChanged(const QModelIndex &ih_index)
{
    if (!ih_index.isValid()) return;

    PacketListRecord *record = static_cast<PacketListRecord*>(ih_index.internalPointer());
    if (!record) return;

    if (record->lineCount() > max_line_count_) {
        max_line_count_ = record->lineCount();
        emit itemHeightChanged(ih_index);
    }
}

int PacketListModel::rowCount(const QModelIndex &) const
{
    return static_cast<int>(visible_rows_.count());
}

int PacketListModel::columnCount(const QModelIndex &) const
{
    return prefs.num_cols;
}

QVariant PacketListModel::data(const QModelIndex &d_index, int role) const
{
    if (!d_index.isValid())
        return QVariant();

    PacketListRecord *record = static_cast<PacketListRecord*>(d_index.internalPointer());
    if (!record)
        return QVariant();
    const frame_data *fdata = record->frameData();
    if (!fdata)
        return QVariant();

    switch (role) {
    case Qt::TextAlignmentRole:
        switch(recent_get_column_xalign(d_index.column())) {
        case COLUMN_XALIGN_RIGHT:
            return Qt::AlignRight;
        case COLUMN_XALIGN_CENTER:
            return Qt::AlignCenter;
        case COLUMN_XALIGN_LEFT:
            return Qt::AlignLeft;
        case COLUMN_XALIGN_DEFAULT:
        default:
            if (right_justify_column(d_index.column(), cap_file_)) {
                return Qt::AlignRight;
            }
            break;
        }
        return Qt::AlignLeft;

    case Qt::BackgroundRole:
        const color_t *color;
        if (fdata->ignored) {
            color = &prefs.gui_ignored_bg;
        } else if (fdata->marked) {
            color = &prefs.gui_marked_bg;
        } else if (fdata->color_filter && recent.packet_list_colorize) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            color = &color_filter->bg_color;
        } else {
            return QVariant();
        }
        return ColorUtils::fromColorT(color);
    case Qt::ForegroundRole:
        if (fdata->ignored) {
            color = &prefs.gui_ignored_fg;
        } else if (fdata->marked) {
            color = &prefs.gui_marked_fg;
        } else if (fdata->color_filter && recent.packet_list_colorize) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            color = &color_filter->fg_color;
        } else {
            return QVariant();
        }
        return ColorUtils::fromColorT(color);
    case Qt::DisplayRole:
    {
        int column = d_index.column();
        QString column_string = record->columnString(cap_file_, column, true);
        // We don't know an item's sizeHint until we fetch its text here.
        // Assume each line count is 1. If the line count changes, emit
        // itemHeightChanged which triggers another redraw (including a
        // fetch of SizeHintRole and DisplayRole) in the next event loop.
        if (column == 0 && record->lineCountChanged() && record->lineCount() > max_line_count_) {
            emit maxLineCountChanged(d_index);
        }
        return column_string;
    }
    case Qt::SizeHintRole:
    {
        // If this is the first row and column, return the maximum row height...
        if (d_index.row() < 1 && d_index.column() < 1 && max_row_height_ > 0) {
            QSize size = QSize(-1, max_row_height_);
            return size;
        }
        // ...otherwise punt so that the item delegate can correctly calculate the item width.
        return QVariant();
    }
    default:
        return QVariant();
    }
}

QVariant PacketListModel::headerData(int section, Qt::Orientation orientation,
                                     int role) const
{
    if (!cap_file_) return QVariant();

    if (orientation == Qt::Horizontal && section < prefs.num_cols) {
        switch (role) {
        case Qt::DisplayRole:
            return QVariant::fromValue(QString(get_column_title(section)));
        case Qt::ToolTipRole:
            return QVariant::fromValue(gchar_free_to_qstring(get_column_tooltip(section)));
        case PacketListModel::HEADER_CAN_RESOLVE:
            return (bool)resolve_column(section, cap_file_);
        default:
            break;
        }
    }

    return QVariant();
}

void PacketListModel::flushVisibleRows()
{
    int pos = static_cast<int>(visible_rows_.count());

    if (new_visible_rows_.count() > 0) {
        beginInsertRows(QModelIndex(), pos, pos + static_cast<int>(new_visible_rows_.count()));
        foreach (PacketListRecord *record, new_visible_rows_) {
            frame_data *fdata = record->frameData();

            visible_rows_ << record;
            if (static_cast<unsigned int>(number_to_row_.size()) <= fdata->num) {
                number_to_row_.resize(fdata->num + 10000);
            }
            number_to_row_[fdata->num] = static_cast<int>(visible_rows_.count());
        }
        endInsertRows();
        new_visible_rows_.resize(0);
    }
}

// Fill our column string and colorization cache while the application is
// idle. Try to be as conservative with the CPU and disk as possible.
static const int idle_dissection_interval_ = 5; // ms
void PacketListModel::dissectIdle(bool reset)
{
    if (reset) {
//        qDebug() << "=di reset" << idle_dissection_row_;
        idle_dissection_row_ = 0;
    } else if (!idle_dissection_timer_->isValid()) {
        return;
    }

    idle_dissection_timer_->restart();

    int first = idle_dissection_row_;
    while (idle_dissection_timer_->elapsed() < idle_dissection_interval_
           && idle_dissection_row_ < physical_rows_.count()) {
        ensureRowColorized(idle_dissection_row_);
        idle_dissection_row_++;
//        if (idle_dissection_row_ % 1000 == 0) qDebug() << "=di row" << idle_dissection_row_;
    }

    if (idle_dissection_row_ < physical_rows_.count()) {
        QTimer::singleShot(0, this, [=]() { dissectIdle(); });
    } else {
        idle_dissection_timer_->invalidate();
    }

    // report colorization progress
    emit bgColorizationProgress(first+1, idle_dissection_row_+1);
}

// XXX Pass in cinfo from packet_list_append so that we can fill in
// line counts?
int PacketListModel::appendPacket(frame_data *fdata)
{
    PacketListRecord *record = new PacketListRecord(fdata);
    qsizetype pos = -1;

#ifdef DEBUG_PACKET_LIST_MODEL
    if (fdata->num % 10000 == 1) {
        log_resource_usage(fdata->num == 1, "%u packets", fdata->num);
    }
#endif

    physical_rows_ << record;

    if (fdata->passed_dfilter || fdata->ref_time) {
        new_visible_rows_ << record;
        if (new_visible_rows_.count() < 2) {
            // This is the first queued packet. Schedule an insertion for
            // the next UI update.
            QTimer::singleShot(0, this, &PacketListModel::flushVisibleRows);
        }
        pos = static_cast<int>( visible_rows_.count() + new_visible_rows_.count() ) - 1;
    }

    emit packetAppended(cap_file_, fdata, physical_rows_.size() - 1);

    return static_cast<int>(pos);
}

frame_data *PacketListModel::getRowFdata(QModelIndex idx) const
{
    if (!idx.isValid())
        return Q_NULLPTR;
    return getRowFdata(idx.row());
}

frame_data *PacketListModel::getRowFdata(int row) const {
    if (row < 0 || row >= visible_rows_.count())
        return NULL;
    PacketListRecord *record = visible_rows_[row];
    if (!record)
        return NULL;
    return record->frameData();
}

void PacketListModel::ensureRowColorized(int row)
{
    if (row < 0 || row >= visible_rows_.count())
        return;
    PacketListRecord *record = visible_rows_[row];
    if (!record)
        return;
    if (!record->colorized()) {
        record->ensureColorized(cap_file_);
    }
}

int PacketListModel::visibleIndexOf(frame_data *fdata) const
{
    if (fdata == nullptr) {
        return -1;
    }
    return packetNumberToRow(fdata->num);
}
