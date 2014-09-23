/* packet_list_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "packet_list_model.h"

#include <wsutil/nstime.h>
#include <epan/prefs.h>

#include "ui/packet_list_utils.h"
#include "ui/recent.h"

#include "color.h"
#include "color_filters.h"
#include "frame_tvbuff.h"

#include "wireshark_application.h"
#include <QColor>
#include <QFontMetrics>
#include <QModelIndex>

PacketListModel::PacketListModel(QObject *parent, capture_file *cf) :
    QAbstractItemModel(parent)
{
    setCaptureFile(cf);
}

void PacketListModel::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    resetColumns();
}

// Packet list records have no children (for now, at least).
QModelIndex PacketListModel::index(int row, int column, const QModelIndex &parent)
            const
{
    Q_UNUSED(parent);

    if (row >= visible_rows_.count() || row < 0 || !cap_file_ || column >= prefs.num_cols)
        return QModelIndex();

    PacketListRecord *record = visible_rows_[row];

    return createIndex(row, column, record);
}

// Everything is under the root.
QModelIndex PacketListModel::parent(const QModelIndex &index) const
{
    Q_UNUSED(index);
    return QModelIndex();
}

int PacketListModel::packetNumberToRow(int packet_num) const
{
    return number_to_row_.value(packet_num, -1);
}

guint PacketListModel::recreateVisibleRows()
{
    int pos = visible_rows_.count() + 1;
    PacketListRecord *record;

    beginResetModel();
    visible_rows_.clear();
    number_to_row_.clear();
    endResetModel();
    beginInsertRows(QModelIndex(), pos, pos);
    foreach (record, physical_rows_) {
        if (record->frameData()->flags.passed_dfilter || record->frameData()->flags.ref_time) {
            visible_rows_ << record;
            number_to_row_[record->frameData()->num] = visible_rows_.count() - 1;
        }
    }
    endInsertRows();
    return visible_rows_.count();
}

void PacketListModel::clear() {
    beginResetModel();
    physical_rows_.clear();
    visible_rows_.clear();
    number_to_row_.clear();
    endResetModel();
}

void PacketListModel::resetColumns()
{
    beginResetModel();
    if (cap_file_) {
        PacketListRecord::resetColumns(&cap_file_->cinfo);
    }
    endResetModel();
}

void PacketListModel::resetColorized()
{
    PacketListRecord *record;

    beginResetModel();
    foreach (record, physical_rows_) {
        record->resetColorized();
    }
    endResetModel();
}

int PacketListModel::columnTextSize(const char *str)
{
    QFontMetrics fm(mono_font_);

    return fm.width(str);
}

void PacketListModel::setMonospaceFont(const QFont &mono_font)
{
    mono_font_ = mono_font;
    recreateVisibleRows();
}

int PacketListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.column() >= prefs.num_cols)
        return 0;

    return visible_rows_.count();
}

int PacketListModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return prefs.num_cols;
}

QVariant PacketListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
    if (!record)
        return QVariant();
    frame_data *fdata = record->frameData();
    if (!fdata)
        return QVariant();

    switch (role) {
    case Qt::FontRole:
        return mono_font_;
    case Qt::TextAlignmentRole:
        switch(recent_get_column_xalign(index.column())) {
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
            if (right_justify_column(index.column(), cap_file_)) {
                return Qt::AlignRight;
            }
            break;
        }
        return Qt::AlignLeft;

    case Qt::BackgroundRole:
        const color_t *color;
        if (fdata->flags.ignored) {
            color = &prefs.gui_ignored_bg;
        } else if (fdata->flags.marked) {
            color = &prefs.gui_marked_bg;
        } else if (fdata->color_filter && recent.packet_list_colorize) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            color = &color_filter->bg_color;
        } else {
            return QVariant();
        }
        return QColor(color->red >> 8, color->green >> 8, color->blue >> 8);
    case Qt::ForegroundRole:
        if (fdata->flags.ignored) {
            color = &prefs.gui_ignored_fg;
        } else if (fdata->flags.marked) {
            color = &prefs.gui_marked_fg;
        } else if (fdata->color_filter && recent.packet_list_colorize) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            color = &color_filter->fg_color;
        } else {
            return QVariant();
        }
        return QColor(color->red >> 8, color->green >> 8, color->blue >> 8);
    case Qt::DisplayRole:
    {
        int column = index.column();
        return record->columnString(cap_file_, column);
    }
    default:
        return QVariant();
    }

    return QVariant();
}

QVariant PacketListModel::headerData(int section, Qt::Orientation orientation,
                               int role) const
{
    if (!cap_file_) return QVariant();

    if (orientation == Qt::Horizontal && section < prefs.num_cols) {
        switch (role) {
        case Qt::DisplayRole:
            return cap_file_->cinfo.col_title[section];
        default:
            break;
        }
    }

    return QVariant();
}

gint PacketListModel::appendPacket(frame_data *fdata)
{
    PacketListRecord *record = new PacketListRecord(fdata);
    gint pos = visible_rows_.count() + 1;

    physical_rows_ << record;

    if (fdata->flags.passed_dfilter || fdata->flags.ref_time) {
        beginInsertRows(QModelIndex(), pos, pos);
        visible_rows_ << record;
        number_to_row_[fdata->num] = visible_rows_.count() - 1;
        endInsertRows();
    } else {
        pos = -1;
    }
    return pos;
}

frame_data *PacketListModel::getRowFdata(int row) {
    if (row < 0 || row >= visible_rows_.size())
        return NULL;
    PacketListRecord *record = visible_rows_[row];
    if (!record)
        return NULL;
    return record->frameData();
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

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
