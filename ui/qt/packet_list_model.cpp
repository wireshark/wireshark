/* packet_list_model.cpp
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "packet_list_model.h"
#include "monospace_font.h"

#include <epan/epan_dissect.h>
#include <epan/column_info.h>
#include <epan/column.h>
#include <epan/nstime.h>
#include <epan/prefs.h>

#include "color.h"
#include "color_filters.h"

#include "globals.h"

#include <QColor>


PacketListModel::PacketListModel(QObject *parent, capture_file *cfPtr) :
    QAbstractItemModel(parent)
{
    cf = cfPtr;
}

gint PacketListModel::appendPacket(frame_data *fdata)
{
    PacketListRecord *record = new PacketListRecord(fdata);
    gint pos = visibleRows.count() + 1;

    physicalRows << record;

    if (fdata->flags.passed_dfilter || fdata->flags.ref_time) {
        beginInsertRows(QModelIndex(), pos, pos);
        visibleRows << record;
        endInsertRows();
    } else {
        pos = -1;
    }
    return pos;
}

frame_data *PacketListModel::getRowFdata(int row) {
    if (row >= visibleRows.count())
        return NULL;
    PacketListRecord *record = visibleRows[row];
    if (!record)
        return NULL;
    return record->getFdata();
}


QVariant PacketListModel::headerData(int section, Qt::Orientation orientation,
                               int role) const
{
    if (orientation == Qt::Horizontal && section < cf->cinfo.num_cols) {
        switch (role) {
        case Qt::DisplayRole:
            return cf->cinfo.col_title[section];
        default:
            break;
        }
    }

    return QVariant();
}

guint PacketListModel::recreateVisibleRows()
{
    int pos = visibleRows.count() + 1;
    PacketListRecord *record;

    beginResetModel();
    visibleRows.clear();
    endResetModel();
    beginInsertRows(QModelIndex(), pos, pos);
    foreach (record, physicalRows) {
        if (record->getFdata()->flags.passed_dfilter || record->getFdata()->flags.ref_time) {
            visibleRows << record;
        }
    }
    endInsertRows();
    return visibleRows.count();
}

int PacketListModel::visibleIndexOf(frame_data *fdata) const
{
    int row = 0;
    foreach (PacketListRecord *record, visibleRows) {
        if (record->getFdata() == fdata) {
            return row;
        }
        row++;
    }

    return -1;
}


// Packet list records have no children (for now, at least).
QModelIndex PacketListModel::index(int row, int column, const QModelIndex &parent)
            const
{
    if (row >= visibleRows.count() || row < 0 || column >= cf->cinfo.num_cols)
        return QModelIndex();

    PacketListRecord *record = visibleRows[row];

    return createIndex(row, column, record);
}

// Everything is under the root.
QModelIndex PacketListModel::parent(const QModelIndex &index) const
{
    return QModelIndex();
}

int PacketListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.column() >= cf->cinfo.num_cols)
        return 0;

    return visibleRows.count();
}

int PacketListModel::columnCount(const QModelIndex &parent) const
{
    return cf->cinfo.num_cols;
}

QVariant PacketListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
    if (!record)
        return QVariant();
    frame_data *fdata = record->getFdata();
    if (!fdata)
        return QVariant();

    switch (role) {
    case Qt::FontRole:
        return get_monospace_font();
//    case Qt::TextAlignmentRole:
    case Qt::BackgroundRole:
        const color_t *color;
        if (fdata->flags.ignored) {
            color = &prefs.gui_ignored_bg;
        } else if (fdata->flags.marked) {
            color = &prefs.gui_marked_bg;
        } else if (fdata->color_filter) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            color = &color_filter->bg_color;
        } else {
            return QVariant();
        }
//        g_log(NULL, G_LOG_LEVEL_DEBUG, "i: %d m: %d cf: %p bg: %d %d %d", fdata->flags.ignored, fdata->flags.marked, fdata->color_filter, color->red, color->green, color->blue);
        return QColor(color->red >> 8, color->green >> 8, color->blue >> 8);
    case Qt::ForegroundRole:
        if (fdata->flags.ignored) {
            color = &prefs.gui_ignored_fg;
        } else if (fdata->flags.marked) {
            color = &prefs.gui_marked_fg;
        } else if (fdata->color_filter) {
            const color_filter_t *color_filter = (const color_filter_t *) fdata->color_filter;
            color = &color_filter->fg_color;
        } else {
            return QVariant();
        }
        return QColor(color->red >> 8, color->green >> 8, color->blue >> 8);
    case Qt::DisplayRole:
        // Fall through
        break;
    default:
        return QVariant();
    }

    int col_num = index.column();
    g_log(NULL, G_LOG_LEVEL_DEBUG, "showing col %d", col_num);

    if (col_num > cf->cinfo.num_cols)
        return QVariant();

    epan_dissect_t edt;
    column_info *cinfo;
    gboolean create_proto_tree;
    union wtap_pseudo_header pseudo_header; /* Packet pseudo_header */
    guint8 pd[WTAP_MAX_PACKET_SIZE];  /* Packet data */
    gboolean dissect_columns = TRUE; // XXX - Currently only a placeholder
    gboolean dissect_color = TRUE; // XXX - Currently only a placeholder

    if (dissect_columns)
        cinfo = &cf->cinfo;
    else
        cinfo = NULL;

    if (!cf_read_frame_r(cf, fdata, &pseudo_header, pd)) {
        /*
         * Error reading the frame.
         *
         * Don't set the color filter for now (we might want
         * to colorize it in some fashion to warn that the
         * row couldn't be filled in or colorized), and
         * set the columns to placeholder values, except
         * for the Info column, where we'll put in an
         * error message.
         */
        if (dissect_columns) {
            col_fill_in_error(cinfo, fdata, FALSE, FALSE /* fill_fd_columns */);

            //            for(gint col = 0; col < cinfo->num_cols; ++col) {
            //                /* Skip columns based on frame_data because we already store those. */
            //                if (!col_based_on_frame_data(cinfo, col))
            //                    packet_list_change_record(packet_list, record->physical_pos, col, cinfo);
            //            }
            //            record->columnized = TRUE;
        }
        if (dissect_color) {
            fdata->color_filter = NULL;
            //            record->colorized = TRUE;
        }
        return QVariant();	/* error reading the frame */
    }

    create_proto_tree = (color_filters_used() && dissect_color) ||
                        (have_custom_cols(cinfo) && dissect_columns);

    epan_dissect_init(&edt,
                      create_proto_tree,
                      FALSE /* proto_tree_visible */);

    if (dissect_color)
        color_filters_prime_edt(&edt);
    if (dissect_columns)
        col_custom_prime_edt(&edt, cinfo);

    epan_dissect_run(&edt, &pseudo_header, pd, fdata, cinfo);

    if (dissect_color)
        fdata->color_filter = color_filters_colorize_packet(&edt);

    if (dissect_columns) {
        /* "Stringify" non frame_data vals */
        epan_dissect_fill_in_columns(&edt, FALSE, FALSE /* fill_fd_columns */);

        //            for(col = 0; col < cinfo->num_cols; ++col) {
        //                    /* Skip columns based on frame_data because we already store those. */
        //                    if (!col_based_on_frame_data(cinfo, col))
        //                            packet_list_change_record(packet_list, record->physical_pos, col, cinfo);
        //            }
//        g_log(NULL, G_LOG_LEVEL_DEBUG, "d_c %d: %s", col_num, cinfo->col_data[col_num]);
    }

    //    if (dissect_columns)
    //            record->columnized = TRUE;
    //    if (dissect_color)
    //            record->colorized = TRUE;

    epan_dissect_cleanup(&edt);

    g_log(NULL, G_LOG_LEVEL_DEBUG, "rd for col %d: %p", col_num, record->data(col_num, cinfo));
    return record->data(col_num, cinfo);
}

void PacketListModel::clear() {
    beginResetModel();
    physicalRows.clear();
    visibleRows.clear();
    endResetModel();
}
