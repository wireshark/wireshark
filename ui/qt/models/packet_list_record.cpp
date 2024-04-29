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
#include <epan/column.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>

#include <epan/color_filters.h>

#include "frame_tvbuff.h"

#include <ui/qt/utils/qt_ui_utils.h>

#include <QStringList>

QCache<uint32_t, QStringList> PacketListRecord::col_text_cache_(500);
QMap<int, int> PacketListRecord::cinfo_column_;
unsigned PacketListRecord::rows_color_ver_ = 1;

PacketListRecord::PacketListRecord(frame_data *frameData) :
    fdata_(frameData),
    lines_(1),
    line_count_changed_(false),
    color_ver_(0),
    colorized_(false),
    conv_index_(0),
    read_failed_(false)
{
}

PacketListRecord::~PacketListRecord()
{
}

void PacketListRecord::ensureColorized(capture_file *cap_file)
{
    // packet_list_store.c:packet_list_get_value
    Q_ASSERT(fdata_);

    if (!cap_file) {
        return;
    }

    bool dissect_color = !colorized_ || ( color_ver_ != rows_color_ver_ );
    if (dissect_color) {
        /* Dissect columns only if it won't evict anything from cache */
        bool dissect_columns = col_text_cache_.totalCost() < col_text_cache_.maxCost();
        dissect(cap_file, dissect_columns, dissect_color);
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
    QStringList *col_text = nullptr;
    if (!dissect_color) {
        col_text = col_text_cache_.object(fdata_->num);
    }
    if (col_text == nullptr || column >= col_text->count() || col_text->at(column).isNull()) {
        dissect(cap_file, true, dissect_color);
        col_text = col_text_cache_.object(fdata_->num);
    }

    return col_text ? col_text->at(column) : QString();
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

void PacketListRecord::dissect(capture_file *cap_file, bool dissect_columns, bool dissect_color)
{
    // packet_list_store.c:packet_list_dissect_and_cache_record
    epan_dissect_t edt;
    column_info *cinfo = NULL;
    bool create_proto_tree;
    wtap_rec rec; /* Record metadata */
    Buffer buf;   /* Record data */

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
            col_fill_in_error(cinfo, fdata_, false, false /* fill_fd_columns */);

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
                      false /* proto_tree_visible */);

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
        epan_dissect_fill_in_columns(&edt, false, false /* fill_fd_columns */);
        cacheColumnStrings(cinfo);
    }

    if (dissect_color) {
        colorized_ = true;
        color_ver_ = rows_color_ver_;
    }

    struct conversation * conv = find_conversation_pinfo_ro(&edt.pi, 0);

    conv_index_ = ! conv ? 0 : conv->conv_index;

    epan_dissect_cleanup(&edt);
    ws_buffer_free(&buf);
    wtap_rec_cleanup(&rec);
}

void PacketListRecord::cacheColumnStrings(column_info *cinfo)
{
    // packet_list_store.c:packet_list_change_record(PacketList *packet_list, PacketListRecord *record, int col, column_info *cinfo)
    if (!cinfo) {
        return;
    }

    QStringList *col_text = new QStringList();

    lines_ = 1;
    line_count_changed_ = false;

    for (int column = 0; column < cinfo->num_cols; ++column) {
        int col_lines = 1;

        QString col_str;
        int text_col = cinfo_column_.value(column, -1);
        if (text_col < 0) {
            col_fill_in_frame_data(fdata_, cinfo, column, false);
        }

        col_str = QString(get_column_text(cinfo, column));
        *col_text << col_str;
        col_lines = static_cast<int>(col_str.count('\n'));
        if (col_lines > lines_) {
            lines_ = col_lines;
            line_count_changed_ = true;
        }
    }

    col_text_cache_.insert(fdata_->num, col_text);
}
