/* packet_list_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_list_model.h"

#include "file.h"

#include <wsutil/nstime.h>
#include <epan/column.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "ui/packet_list_utils.h"
#include "ui/recent.h"

#include <epan/color_filters.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/main_status_bar.h>
#include <ui/qt/widgets/wireless_timeline.h>

#include <QApplication>
#include <QColor>
#include <QFontMetrics>
#include <QModelIndex>
#include <QPalette>
#include <QTimer>

// Print timing information
//#define DEBUG_PACKET_LIST_MODEL 1

#ifdef DEBUG_PACKET_LIST_MODEL
#include <wsutil/time_util.h>
#endif

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

PacketListModel::PacketListModel(QObject *parent, capture_file *cf) :
    QAbstractItemModel(parent),
    inserted_rows_(0)
{
    Q_ASSERT(glbl_plist_model == Q_NULLPTR);
    glbl_plist_model = this;
    setCaptureFile(cf);

    physical_rows_.reserve(reserved_packets_);

    refreshThemeColors();
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &PacketListModel::onThemeChanged);
}

PacketListModel::~PacketListModel()
{
    if (glbl_plist_model == this) {
        glbl_plist_model = Q_NULLPTR;
    }
}

void PacketListModel::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
}

// Packet list records have no children (for now, at least).
QModelIndex PacketListModel::index(int row, int column, const QModelIndex &parent) const
{
    if (parent.isValid())
        return QModelIndex();

    if (row >= inserted_rows_ || row < 0 || !cap_file_ || (unsigned)column >= prefs.num_cols)
        return QModelIndex();

    PacketListRecord *record = physical_rows_[row];

    return createIndex(row, column, record);
}

// Everything is under the root.
QModelIndex PacketListModel::parent(const QModelIndex &) const
{
    return QModelIndex();
}

PacketListRecord *PacketListModel::physicalRecordForFrameNum(int frame_num) const
{
    // Frame numbers are assigned sequentially starting at 1, in the same
    // order records are appended to physical_rows_ (see appendPacket()),
    // and are never reused within a capture, so frame_num - 1 is always
    // that frame's position there -- regardless of the display filter,
    // which is applied by a proxy model.
    PacketListRecord *record = physicalRecordAt(frame_num - 1);
    if (record && record->frameData() && (int)record->frameData()->num != frame_num) {
        // Should never happen given the invariant above; fail safe rather
        // than handing back the wrong packet's data.
        return nullptr;
    }
    return record;
}

PacketListRecord *PacketListModel::physicalRecordAt(int row) const
{
    if (row < 0 || row >= physical_rows_.count()) {
        return nullptr;
    }
    return physical_rows_[row];
}

void PacketListModel::clear() {
    beginResetModel();
    qDeleteAll(physical_rows_);
    PacketListRecord::invalidateAllRecords();
    physical_rows_.resize(0);
    inserted_rows_ = 0;
    endResetModel();
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
    emit layoutAboutToBeChanged();
    PacketListRecord::invalidateAllRecords();
    emit layoutChanged();
#if 0
    // TODO: Check to see if Qt 6.9.0 is faster with the old approach now that
    // QTBUG-124173 is fixed, here and in the other functions.
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::DisplayRole);
#endif
}

void PacketListModel::resetColumns()
{
    emit layoutAboutToBeChanged();
    if (cap_file_) {
        PacketListRecord::resetColumns(&cap_file_->cinfo);
    }

    emit layoutChanged();
#if 0
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
#endif
    emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1);
}

void PacketListModel::resetColorized()
{
    emit layoutAboutToBeChanged();
    PacketListRecord::resetColorization();
    emit layoutChanged();
#if 0
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
#endif
}

void PacketListModel::toggleFrameMark(const QModelIndexList &indices)
{
    if (!cap_file_ || indices.count() <= 0)
        return;

    int sectionMax = columnCount() - 1;

    foreach (QModelIndex index, indices) {
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

void PacketListModel::toggleFrameMark(PacketListRecord *record)
{
    if (!cap_file_ || !record)
        return;

    frame_data *fdata = record->frameData();
    if (!fdata)
        return;

    if (fdata->marked)
        cf_unmark_frame(cap_file_, fdata);
    else
        cf_mark_frame(cap_file_, fdata);

    record->invalidateColorized();
}

void PacketListModel::setFrameMark(const QVector<PacketListRecord *> &records, bool set)
{
    emit layoutAboutToBeChanged();
    foreach (PacketListRecord *record, records) {
        if (set) {
            cf_mark_frame(cap_file_, record->frameData());
        } else {
            cf_unmark_frame(cap_file_, record->frameData());
        }
    }
    emit layoutChanged();
#if 0
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
#endif
}

void PacketListModel::toggleFrameIgnore(const QModelIndexList &indices)
{
    if (!cap_file_ || indices.count() <= 0)
        return;

    int sectionMax = columnCount() - 1;

    foreach (QModelIndex index, indices) {
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

void PacketListModel::toggleFrameIgnore(PacketListRecord *record)
{
    if (!cap_file_ || !record)
        return;

    frame_data *fdata = record->frameData();
    if (!fdata)
        return;

    if (fdata->ignored)
        cf_unignore_frame(cap_file_, fdata);
    else
        cf_ignore_frame(cap_file_, fdata);

    record->invalidateColorized();
    record->invalidateRecord();
}

void PacketListModel::setFrameIgnore(const QVector<PacketListRecord *> &records, bool set)
{
    emit layoutAboutToBeChanged();
    foreach (PacketListRecord *record, records) {
        if (set) {
            cf_ignore_frame(cap_file_, record->frameData());
        } else {
            cf_unignore_frame(cap_file_, record->frameData());
        }
    }
    emit layoutChanged();
#if 0
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
#endif
}

void PacketListModel::toggleFrameRefTime(const QModelIndexList &indices)
{
    QList<PacketListRecord *> records;
    for (const auto &rt_index : indices) {
        if (rt_index.isValid() && rt_index.internalPointer()) {
            records << static_cast<PacketListRecord*>(rt_index.internalPointer());
        }
    }
    toggleRecordsRefTime(records);
}

void PacketListModel::toggleFrameRefTime(PacketListRecord *record)
{
    if (record) {
        toggleRecordsRefTime(QList<PacketListRecord *>() << record);
    }
}

void PacketListModel::toggleRecordsRefTime(const QList<PacketListRecord *> &records)
{
    if (!cap_file_ || records.isEmpty())
        return;

    emit layoutAboutToBeChanged();
    for (PacketListRecord *record : records) {
        frame_data *fdata = record->frameData();
        if (!fdata) continue;

        if (fdata->ref_time) {
            fdata->ref_time=0;
            cap_file_->ref_time_count--;
            if (!fdata->passed_dfilter) {
                // XXX - We might not want to change this (#10142), but we would
                // need to touch several places in the code
                cap_file_->displayed_count--;
                // XXX - recreateVisibleRows() to remove the row? That resets the
                // model, which is a bit strong. We might want a method to remove
                // one row.
            }
        } else {
            fdata->ref_time=1;
            cap_file_->ref_time_count++;
            if (!fdata->passed_dfilter) {
                // A pinned row that was filtered out can still be changed.
                cap_file_->displayed_count++;
            }
        }
    }
    cf_reftime_packets(cap_file_);
    PacketListRecord::resetColumns(&cap_file_->cinfo);
    emit layoutChanged();
#if 0
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
#endif
}

void PacketListModel::unsetAllFrameRefTime()
{
    if (!cap_file_) return;

    /* XXX: we might need a progressbar here */

    emit layoutAboutToBeChanged();
    foreach (PacketListRecord *record, physical_rows_) {
        frame_data *fdata = record->frameData();
        if (fdata->ref_time) {
            fdata->ref_time = 0;
        }
    }
    cap_file_->ref_time_count = 0;
    cf_reftime_packets(cap_file_);
    PacketListRecord::resetColumns(&cap_file_->cinfo);
    emit layoutChanged();
#if 0
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
#endif
}

void PacketListModel::addCommentToRecord(PacketListRecord *record, const QByteArray &comment)
{
    frame_data *fdata = record->frameData();
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
}

void PacketListModel::addFrameComment(const QModelIndexList &indices, const QByteArray &comment)
{
    int sectionMax = columnCount() - 1;
    if (!cap_file_) return;

    for (const auto &index : indices) {
        if (!index.isValid()) continue;

        PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
        if (!record) continue;

        addCommentToRecord(record, comment);
        emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
                QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
    }
}

void PacketListModel::addFrameComment(PacketListRecord *record, const QByteArray &comment)
{
    if (!cap_file_ || !record || !record->frameData()) return;

    addCommentToRecord(record, comment);
}

void PacketListModel::setCommentOnRecord(PacketListRecord *record, const QByteArray &comment, unsigned c_number)
{
    frame_data *fdata = record->frameData();

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
}

void PacketListModel::setFrameComment(const QModelIndex &index, const QByteArray &comment, unsigned c_number)
{
    int sectionMax = columnCount() - 1;
    if (!cap_file_) return;

    if (!index.isValid()) return;

    PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
    if (!record) return;

    setCommentOnRecord(record, comment, c_number);
    emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
            QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
}

void PacketListModel::setFrameComment(PacketListRecord *record, const QByteArray &comment, unsigned c_number)
{
    if (!cap_file_ || !record || !record->frameData()) return;

    setCommentOnRecord(record, comment, c_number);
}

bool PacketListModel::deleteCommentsFromRecord(PacketListRecord *record)
{
    frame_data *fdata = record->frameData();
    wtap_block_t pkt_block = cf_get_packet_block(cap_file_, fdata);
    unsigned n_comments = wtap_block_count_option(pkt_block, OPT_COMMENT);

    if (!n_comments)
        return false;

    for (unsigned i = 0; i < n_comments; i++) {
        wtap_block_remove_nth_option_instance(pkt_block, OPT_COMMENT, 0);
    }
    if (!cf_set_modified_block(cap_file_, fdata, pkt_block)) {
        cap_file_->packet_comment_count -= n_comments;
        expert_update_comment_count(cap_file_->packet_comment_count);
    }

    record->invalidateColorized();
    record->invalidateRecord();
    return true;
}

void PacketListModel::deleteFrameComments(const QModelIndexList &indices)
{
    int sectionMax = columnCount() - 1;
    if (!cap_file_) return;

    for (const auto &index : indices) {
        if (!index.isValid()) continue;

        PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
        if (!record) continue;

        if (deleteCommentsFromRecord(record)) {
            emit dataChanged(index.sibling(index.row(), 0), index.sibling(index.row(), sectionMax),
                    QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
        }
    }
}

void PacketListModel::deleteFrameComments(PacketListRecord *record)
{
    if (!cap_file_ || !record || !record->frameData()) return;

    deleteCommentsFromRecord(record);
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
            row = static_cast<int>(fdata->num) - 1;
            if (row < inserted_rows_) {
                emit dataChanged(index(row, 0), index(row, sectionMax),
                    QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole << Qt::DisplayRole);
            }
        }
    }
    cap_file_->packet_comment_count = 0;
    expert_update_comment_count(cap_file_->packet_comment_count);
}

int PacketListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;

    return inserted_rows_;
}

int PacketListModel::columnCount(const QModelIndex &) const
{
    return prefs.num_cols;
}

Qt::ItemFlags PacketListModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flags = QAbstractItemModel::flags(index);
    if (index.isValid()) {
        flags |= Qt::ItemNeverHasChildren;
    }
    return flags;
}

QVariant PacketListModel::data(const QModelIndex &d_index, int role) const
{
    if (!d_index.isValid())
        return QVariant();

    PacketListRecord *record = static_cast<PacketListRecord*>(d_index.internalPointer());
    return dataForRecord(record, d_index.column(), role);
}

QVariant PacketListModel::dataForFrameNum(int frame_num, int column, int role) const
{
    return dataForRecord(physicalRecordForFrameNum(frame_num), column, role);
}

QVariant PacketListModel::dataForRecord(PacketListRecord *record, int column, int role) const
{
    if (!record)
        return QVariant();
    const frame_data *fdata = record->frameData();
    if (!fdata)
        return QVariant();

    switch (role) {
    case Qt::TextAlignmentRole:
        switch(recent_get_column_xalign(column)) {
        case COLUMN_XALIGN_RIGHT:
            return Qt::AlignRight;
        case COLUMN_XALIGN_CENTER:
            return Qt::AlignCenter;
        case COLUMN_XALIGN_LEFT:
            return Qt::AlignLeft;
        case COLUMN_XALIGN_DEFAULT:
        default:
            if (right_justify_column(column, cap_file_)) {
                return Qt::AlignRight;
            }
            break;
        }
        return Qt::AlignLeft;

    case Qt::BackgroundRole:
        if (fdata->ignored) {
            return ignored_bg_;
        } else if (fdata->marked) {
            return marked_bg_;
        } else if (fdata->color_filter && recent.packet_list_colorize) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            return ColorUtils::fromColorT(&color_filter->bg_color);
        }
        return QVariant();
    case Qt::ForegroundRole:
        if (fdata->ignored) {
            return ignored_fg_;
        } else if (fdata->marked) {
            return marked_fg_;
        } else if (fdata->color_filter && recent.packet_list_colorize) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            return ColorUtils::fromColorT(&color_filter->fg_color);
        }
        return QVariant();
    case Qt::AccessibleTextRole:
    {
        if (get_column_format(column) == COL_TAG)
            return record->tagColumnString();
        return record->columnString(cap_file_, column, true);
    }
    case Qt::ToolTipRole:
    {
        if (get_column_format(column) == COL_TAG)
            return record->tagColumnTooltip();
        return QVariant();
    }
    case Qt::AccessibleDescriptionRole:
    {
        if (column > 0) {
            return QVariant();
        }

        uint32_t severity = record->expertSeverity();
        if (!fdata->marked && !fdata->ignored && !fdata->ref_time && !fdata->has_modified_block && severity == 0) {
            return QVariant();
        }

        QStringList labels;
        if (fdata->marked) labels << tr("Marked");
        if (fdata->ignored) labels << tr("Ignored");
        if (fdata->ref_time) labels << tr("Reference Time");
        if (fdata->has_modified_block) labels << tr("Modified");

        if (severity > 0) {
            const char *severity_str = val_to_str_const(severity, expert_severity_vals, NULL);
            if (severity_str) {
                labels << severity_str;
            }
        }

        return labels.join(", ");
    }
    case Qt::DisplayRole:
    {
        if (get_column_format(column) == COL_TAG)
            return record->tagColumnString();
        return record->columnString(cap_file_, column, true);
    }
    case Qt::UserRole:
    {
        if (get_column_format(column) == COL_TAG)
            return QVariant::fromValue<TagSegmentList>(record->tagColumnSegments());
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

    if ((orientation == Qt::Horizontal) && ((unsigned)section < prefs.num_cols)) {
        switch (role) {
        case Qt::DisplayRole:
        case Qt::AccessibleTextRole:
            return QVariant::fromValue(QString(get_column_title(section)));
        case Qt::ToolTipRole:
        case Qt::AccessibleDescriptionRole:
            return QVariant::fromValue(gchar_free_to_qstring(get_column_tooltip(section)));
        case PacketListModel::HEADER_CAN_DISPLAY_STRINGS:
            return (bool)display_column_strings(section, cap_file_);
        case PacketListModel::HEADER_CAN_DISPLAY_DETAILS:
            return (bool)display_column_details(section, cap_file_);
        default:
            break;
        }
    }

    return QVariant();
}

void PacketListModel::flushNewRows()
{
    int count = static_cast<int>(physical_rows_.count());

    if (count > inserted_rows_) {
        beginInsertRows(QModelIndex(), inserted_rows_, count - 1);
        inserted_rows_ = count;
        endInsertRows();
    }
}

// XXX Pass in cinfo from packet_list_append so that we can fill in
// line counts?
int PacketListModel::appendPacket(frame_data *fdata)
{
    PacketListRecord *record = new PacketListRecord(fdata);
    qsizetype pos = physical_rows_.size();

#ifdef DEBUG_PACKET_LIST_MODEL
    if (fdata->num % 10000 == 1) {
        log_resource_usage(fdata->num == 1, "%u packets", fdata->num);
    }
#endif

    physical_rows_ << record;

    if (pos == inserted_rows_) {
        // This is the first queued packet. Schedule an insertion for
        // the next UI update.
        QTimer::singleShot(0, this, &PacketListModel::flushNewRows);
    }

    emit packetAppended(cap_file_, fdata, pos);

    return static_cast<int>(pos);
}

void PacketListModel::refreshThemeColors()
{
    ThemeManager *tm = ThemeManager::instance();
    marked_bg_  = tm->color(ThemeManager::PacketsMarked);
    marked_fg_  = tm->color(ThemeManager::PacketsMarkedText);
    ignored_bg_ = tm->color(ThemeManager::PacketsIgnored);
    ignored_fg_ = tm->color(ThemeManager::PacketsIgnoredText);
}

void PacketListModel::onThemeChanged()
{
    refreshThemeColors();
    if (rowCount() > 0) {
        emit dataChanged(index(0, 0),
                         index(rowCount() - 1, columnCount() - 1),
                         QVector<int>() << Qt::BackgroundRole << Qt::ForegroundRole);
    }
}
