/* packet_list_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <glib.h>

#include "packet_list_model.h"

#include "file.h"

#include <wsutil/nstime.h>
#include <epan/column.h>
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

static PacketListModel * glbl_plist_model = Q_NULLPTR;
static const int reserved_packets_ = 100000;

guint
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

guint PacketListModel::recreateVisibleRows()
{
    beginResetModel();
    visible_rows_.resize(0);
    number_to_row_.fill(0);
    endResetModel();

    foreach (PacketListRecord *record, physical_rows_) {
        frame_data *fdata = record->frameData();

        if (fdata->passed_dfilter || fdata->ref_time) {
            visible_rows_ << record;
            if (static_cast<guint32>(number_to_row_.size()) <= fdata->num) {
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
    return static_cast<guint>(visible_rows_.count());
}

void PacketListModel::clear() {
    beginResetModel();
    qDeleteAll(physical_rows_);
    physical_rows_.resize(0);
    visible_rows_.resize(0);
    new_visible_rows_.resize(0);
    number_to_row_.resize(0);
    endResetModel();
    max_row_height_ = 0;
    max_line_count_ = 1;
    idle_dissection_row_ = 0;
}

void PacketListModel::invalidateAllColumnStrings()
{
    PacketListRecord::invalidateAllRecords();
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::DisplayRole);
}

void PacketListModel::resetColumns()
{
    if (cap_file_) {
        PacketListRecord::resetColumns(&cap_file_->cinfo);
    }

    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
    emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1);
}

void PacketListModel::resetColorized()
{
    PacketListRecord::resetColorization();
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
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

void PacketListModel::setDisplayedFrameMark(gboolean set)
{
    foreach (PacketListRecord *record, visible_rows_) {
        if (set) {
            cf_mark_frame(cap_file_, record->frameData());
        } else {
            cf_unmark_frame(cap_file_, record->frameData());
        }
    }
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
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

void PacketListModel::setDisplayedFrameIgnore(gboolean set)
{
    foreach (PacketListRecord *record, visible_rows_) {
        if (set) {
            cf_ignore_frame(cap_file_, record->frameData());
        } else {
            cf_unignore_frame(cap_file_, record->frameData());
        }
    }
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
}

void PacketListModel::toggleFrameRefTime(const QModelIndex &rt_index)
{
    if (!cap_file_ || !rt_index.isValid()) return;

    PacketListRecord *record = static_cast<PacketListRecord*>(rt_index.internalPointer());
    if (!record) return;

    frame_data *fdata = record->frameData();
    if (!fdata) return;

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
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
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

QElapsedTimer busy_timer_;
const int busy_timeout_ = 65; // ms, approximately 15 fps
void PacketListModel::sort(int column, Qt::SortOrder order)
{
    if (!cap_file_ || visible_rows_.count() < 1) return;
    if (column < 0) return;

    sort_column_ = column;
    text_sort_column_ = PacketListRecord::textColumn(column);
    sort_order_ = order;
    sort_cap_file_ = cap_file_;

    QString col_title = get_column_title(column);

    // XXX Use updateProgress instead. We'd have to switch from std::sort to
    // something we can interrupt.
    if (!col_title.isEmpty()) {
        QString busy_msg = tr("Sorting \"%1\"…").arg(col_title);
        mainApp->pushStatus(MainApplication::BusyStatus, busy_msg);
    }

    busy_timer_.start();
    sort_column_is_numeric_ = isNumericColumn(sort_column_);
    std::sort(physical_rows_.begin(), physical_rows_.end(), recordLessThan);

    beginResetModel();
    visible_rows_.resize(0);
    number_to_row_.fill(0);
    foreach (PacketListRecord *record, physical_rows_) {
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

    if (!col_title.isEmpty()) {
        mainApp->popStatus(MainApplication::BusyStatus);
    }

    if (cap_file_->current_frame) {
        emit goToPacket(cap_file_->current_frame->num);
    }
}

bool PacketListModel::isNumericColumn(int column)
{
    if (column < 0) {
        return false;
    }
    switch (sort_cap_file_->cinfo.columns[column].col_fmt) {
    case COL_8021Q_VLAN_ID:  /**< 0) 802.1Q vlan ID */
    case COL_CUMULATIVE_BYTES: /**< 5) Cumulative number of bytes */
    case COL_DELTA_TIME:     /**< 8) Delta time */
    case COL_DELTA_TIME_DIS: /**< 9) Delta time displayed*/
    case COL_UNRES_DST_PORT: /**< 13) Unresolved dest port */
    case COL_FREQ_CHAN:      /**< 18) IEEE 802.11 (and WiMax?) - Channel */
    case COL_RSSI:           /**< 25) IEEE 802.11 - received signal strength */
    case COL_TX_RATE:        /**< 26) IEEE 802.11 - TX rate in Mbps */
    case COL_NUMBER:         /**< 35) Packet list item number */
    case COL_PACKET_LENGTH:  /**< 36) Packet length in bytes */
    case COL_UNRES_SRC_PORT: /**< 44) Unresolved source port */
    case COL_TEI:            /**< 45) Q.921 TEI */
        return true;

    /*
     * Try to sort port numbers as number, if the numeric comparison fails (due
     * to name resolution), it will fallback to string comparison.
     * */
    case COL_RES_DST_PORT:   /**< 12) Resolved dest port */
    case COL_DEF_DST_PORT:   /**< 15) Destination port */
    case COL_DEF_SRC_PORT:   /**< 40) Source port */
    case COL_RES_SRC_PORT:   /**< 43) Resolved source port */
        return true;

    case COL_CUSTOM:
        /* handle custom columns below. */
        break;

    default:
        return false;
    }

    guint num_fields = g_slist_length(sort_cap_file_->cinfo.columns[column].col_custom_fields_ids);
    for (guint i = 0; i < num_fields; i++) {
        guint *field_idx = (guint *) g_slist_nth_data(sort_cap_file_->cinfo.columns[column].col_custom_fields_ids, i);
        header_field_info *hfi = proto_registrar_get_nth(*field_idx);

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
              !(((IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)) &&
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

    // Wherein we try to cram the logic of packet_list_compare_records,
    // _packet_list_compare_records, and packet_list_compare_custom from
    // gtk/packet_list_store.c into one function

    if (busy_timer_.elapsed() > busy_timeout_) {
        // What's the least amount of processing that we can do which will draw
        // the busy indicator?
        mainApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, 1);
        busy_timer_.restart();
    }
    if (sort_column_ < 0) {
        // No column.
        cmp_val = frame_data_compare(sort_cap_file_->epan, r1->frameData(), r2->frameData(), COL_NUMBER);
    } else if (text_sort_column_ < 0) {
        // Column comes directly from frame data
        cmp_val = frame_data_compare(sort_cap_file_->epan, r1->frameData(), r2->frameData(), sort_cap_file_->cinfo.columns[sort_column_].col_fmt);
    } else  {
        if (r1->columnString(sort_cap_file_, sort_column_).constData() == r2->columnString(sort_cap_file_, sort_column_).constData()) {
            cmp_val = 0;
        } else if (sort_column_is_numeric_) {
            // Custom column with numeric data (or something like a port number).
            // Attempt to convert to numbers.
            // XXX This is slow. Can we avoid doing this?
            bool ok_r1, ok_r2;
            double num_r1 = parseNumericColumn(r1->columnString(sort_cap_file_, sort_column_), &ok_r1);
            double num_r2 = parseNumericColumn(r2->columnString(sort_cap_file_, sort_column_), &ok_r2);

            if (!ok_r1 && !ok_r2) {
                cmp_val = 0;
            } else if (!ok_r1 || (ok_r2 && num_r1 < num_r2)) {
                // either r1 is invalid (and sort it before others) or both
                // r1 and r2 are valid (sort normally)
                cmp_val = -1;
            } else if (!ok_r2 || (num_r1 > num_r2)) {
                cmp_val = 1;
            }
        } else {
            cmp_val = r1->columnString(sort_cap_file_, sort_column_).compare(r2->columnString(sort_cap_file_, sort_column_));
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
    gchar *end = NULL;
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
            break;
        case COLUMN_XALIGN_CENTER:
            return Qt::AlignCenter;
            break;
        case COLUMN_XALIGN_LEFT:
            return Qt::AlignLeft;
            break;
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
        QTimer::singleShot(0, this, SLOT(dissectIdle()));
    } else {
        idle_dissection_timer_->invalidate();
    }

    // report colorization progress
    emit bgColorizationProgress(first+1, idle_dissection_row_+1);
}

// XXX Pass in cinfo from packet_list_append so that we can fill in
// line counts?
gint PacketListModel::appendPacket(frame_data *fdata)
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
            QTimer::singleShot(0, this, SLOT(flushVisibleRows()));
        }
        pos = static_cast<int>( visible_rows_.count() + new_visible_rows_.count() ) - 1;
    }

    return static_cast<gint>(pos);
}

frame_data *PacketListModel::getRowFdata(QModelIndex idx)
{
    if (!idx.isValid())
        return Q_NULLPTR;
    return getRowFdata(idx.row());
}

frame_data *PacketListModel::getRowFdata(int row) {
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
    int row = 0;
    foreach (PacketListRecord *record, visible_rows_) {
        if (record->frameData() == fdata) {
            return row;
        }
        row++;
    }

    return -1;
}
