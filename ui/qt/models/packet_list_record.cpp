/* packet_list_record.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_list_record.h"

#include <file.h>

#include <epan/epan_dissect.h>
#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>

#include <epan/color_filters.h>

#include "frame_tvbuff.h"

#include <ui/qt/utils/qt_ui_utils.h>

#include <QStringList>

QMap<int, int> PacketListRecord::cinfo_column_;
unsigned PacketListRecord::col_data_ver_ = 1;
unsigned PacketListRecord::rows_color_ver_ = 1;

PacketListRecord::PacketListRecord(frame_data *frameData) :
    fdata_(frameData),
    lines_(1),
    line_count_changed_(false),
    data_ver_(0),
    color_ver_(0),
    colorized_(false),
    conv_index_(0),
    read_failed_(false)
{
}

PacketListRecord::~PacketListRecord()
{
    col_text_.clear();
}

void PacketListRecord::ensureColorized(capture_file *cap_file)
{
    // packet_list_store.c:packet_list_get_value
    Q_ASSERT(fdata_);

    if (!cap_file) {
        return;
    }

    //
    // XXX - do we need to check whether the data versions match?
    // If the record's color is already correct, we shouldn't need
    // to redissect it to colorize it.
    //
    bool dissect_color = !colorized_ || ( color_ver_ != rows_color_ver_ );
    if (data_ver_ != col_data_ver_ || dissect_color) {
        dissect(cap_file, dissect_color);
    }
}

// We might want to return a const char * instead. This would keep us from
// creating excessive QByteArrays, e.g. in PacketListModel::recordLessThan.
const QString PacketListRecord::columnString(capture_file *cap_file, int column, bool colorized)
{
    // packet_list_store.c:packet_list_get_value
    Q_ASSERT(fdata_);

    if (!cap_file || column < 0 || column >= cap_file->cinfo.num_cols) {
        return QString();
    }

    //
    // XXX - do we still need to check the colorization, given that we now
    // have the ensureColorized() method to ensure that the record is
    // properly colorized?
    //
    bool dissect_color = ( colorized && !colorized_ ) || ( color_ver_ != rows_color_ver_ );
    if (column >= col_text_.count() || col_text_.at(column).isNull() || data_ver_ != col_data_ver_ || dissect_color) {
        dissect(cap_file, dissect_color);
    }

    return col_text_.at(column);
}

void PacketListRecord::resetColumns(column_info *cinfo)
{
    invalidateAllRecords();

    if (!cinfo) {
        return;
    }

    cinfo_column_.clear();
    int i, j;
    for (i = 0, j = 0; i < cinfo->num_cols; i++) {
        if (!col_based_on_frame_data(cinfo, i)) {
            cinfo_column_[i] = j;
            j++;
        }
    }
}

void PacketListRecord::dissect(capture_file *cap_file, bool dissect_color)
{
    // packet_list_store.c:packet_list_dissect_and_cache_record
    epan_dissect_t edt;
    column_info *cinfo = NULL;
    gboolean create_proto_tree;
    wtap_rec rec; /* Record metadata */
    Buffer buf;   /* Record data */

    gboolean dissect_columns = col_text_.isEmpty() || data_ver_ != col_data_ver_;

    if (!cap_file) {
        return;
    }

    if (dissect_columns) {
        cinfo = &cap_file->cinfo;
    }

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);
    if (read_failed_) {
        read_failed_ = !cf_read_record_no_alert(cap_file, fdata_, &rec, &buf);
    } else {
        read_failed_ = !cf_read_record(cap_file, fdata_, &rec, &buf);
    }

    if (read_failed_) {
        /*
         * Error reading the record.
         *
         * Don't set the color filter for now (we might want
         * to colorize it in some fashion to warn that the
         * row couldn't be filled in or colorized), and
         * set the columns to placeholder values, except
         * for the Info column, where we'll put in an
         * error message.
         */
        if (dissect_columns) {
            col_fill_in_error(cinfo, fdata_, FALSE, FALSE /* fill_fd_columns */);

            cacheColumnStrings(cinfo);
        }
        if (dissect_color) {
            fdata_->color_filter = NULL;
            colorized_ = true;
        }
        ws_buffer_free(&buf);
        wtap_rec_cleanup(&rec);
        return;    /* error reading the record */
    }

    /*
     * Determine whether we need to create a protocol tree.
     * We do if:
     *
     *    we're going to apply a color filter to this packet;
     *
     *    we're need to fill in the columns and we have custom columns
     *    (which require field values, which currently requires that
     *    we build a protocol tree).
     *
     *    XXX - field extractors?  (Not done for GTK+....)
     */
    create_proto_tree = ((dissect_color && color_filters_used()) ||
                         (dissect_columns && (have_custom_cols(cinfo) ||
                                              have_field_extractors())));

    epan_dissect_init(&edt, cap_file->epan,
                      create_proto_tree,
                      FALSE /* proto_tree_visible */);

    /* Re-color when the coloring rules are changed via the UI. */
    if (dissect_color) {
        color_filters_prime_edt(&edt);
        fdata_->need_colorize = 1;
    }
    if (dissect_columns)
        col_custom_prime_edt(&edt, cinfo);

    /*
     * XXX - need to catch an OutOfMemoryError exception and
     * attempt to recover from it.
     */
    epan_dissect_run(&edt, cap_file->cd_t, &rec,
                     frame_tvbuff_new_buffer(&cap_file->provider, fdata_, &buf),
                     fdata_, cinfo);

    if (dissect_columns) {
        /* "Stringify" non frame_data vals */
        epan_dissect_fill_in_columns(&edt, FALSE, FALSE /* fill_fd_columns */);
        cacheColumnStrings(cinfo);
    }

    if (dissect_color) {
        colorized_ = true;
        color_ver_ = rows_color_ver_;
    }
    data_ver_ = col_data_ver_;

    struct conversation * conv = find_conversation_pinfo(&edt.pi, 0);
    conv_index_ = ! conv ? 0 : conv->conv_index;

    epan_dissect_cleanup(&edt);
    ws_buffer_free(&buf);
    wtap_rec_cleanup(&rec);
}

//#define MINIMIZE_STRING_COPYING 1
void PacketListRecord::cacheColumnStrings(column_info *cinfo)
{
    // packet_list_store.c:packet_list_change_record(PacketList *packet_list, PacketListRecord *record, gint col, column_info *cinfo)
    if (!cinfo) {
        return;
    }

    col_text_.clear();
    lines_ = 1;
    line_count_changed_ = false;

    for (int column = 0; column < cinfo->num_cols; ++column) {
        int col_lines = 1;

#ifdef MINIMIZE_STRING_COPYING
        int text_col = cinfo_column_.value(column, -1);

        /* Column based on frame_data or it already contains a value */
        if (text_col < 0) {
            col_fill_in_frame_data(fdata_, cinfo, column, FALSE);
            col_text_ << QString(get_column_text(cinfo, column));
            continue;
        }

        switch (cinfo->col_fmt[column]) {
        case COL_PROTOCOL:
        case COL_INFO:
        case COL_IF_DIR:
        case COL_DCE_CALL:
        case COL_8021Q_VLAN_ID:
        case COL_EXPERT:
        case COL_FREQ_CHAN:
            const gchar *col_data = get_column_text(cinfo, column);
            if (col_data && col_data != cinfo->columns[column].col_buf) {
                /* This is a constant string, so we don't have to copy it */
                // XXX - ui/gtk/packet_list_store.c uses G_MAXUSHORT. We don't do proper UTF8
                // truncation in either case.
                int col_text_len = MIN(qstrlen(col_data) + 1, COL_MAX_INFO_LEN);
                col_text_ << QString(QByteArray::fromRawData(col_data, col_text_len));
                break;
            }
            /* !! FALL-THROUGH!! */

        case COL_DEF_SRC:
        case COL_RES_SRC:        /* COL_DEF_SRC is currently just like COL_RES_SRC */
        case COL_UNRES_SRC:
        case COL_DEF_DL_SRC:
        case COL_RES_DL_SRC:
        case COL_UNRES_DL_SRC:
        case COL_DEF_NET_SRC:
        case COL_RES_NET_SRC:
        case COL_UNRES_NET_SRC:
        case COL_DEF_DST:
        case COL_RES_DST:        /* COL_DEF_DST is currently just like COL_RES_DST */
        case COL_UNRES_DST:
        case COL_DEF_DL_DST:
        case COL_RES_DL_DST:
        case COL_UNRES_DL_DST:
        case COL_DEF_NET_DST:
        case COL_RES_NET_DST:
        case COL_UNRES_NET_DST:
        default:
            // XXX Use QContiguousCache?
            col_text_ << QString(get_column_text(cinfo, column));
            break;
        }
#else // MINIMIZE_STRING_COPYING
        QString col_str;
        int text_col = cinfo_column_.value(column, -1);
        if (text_col < 0) {
            col_fill_in_frame_data(fdata_, cinfo, column, FALSE);
        }

        col_str = QString(get_column_text(cinfo, column));
        col_text_ << col_str;
        col_lines = static_cast<int>(col_str.count('\n'));
        if (col_lines > lines_) {
            lines_ = col_lines;
            line_count_changed_ = true;
        }
#endif // MINIMIZE_STRING_COPYING
    }
}
