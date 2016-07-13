/* packet_list_record.cpp
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

#include "packet_list_record.h"

#include <file.h>

#include <epan/epan_dissect.h>
#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>

#include <epan/color_filters.h>

#include "frame_tvbuff.h"

#include <QStringList>

class ColumnTextList : public QList<const char *> {
public:
    // Allocate our records using wmem.
    static void *operator new(size_t size) {
        return wmem_alloc(wmem_file_scope(), size);
    }

    static void operator delete(void *) {}
};

QMap<int, int> PacketListRecord::cinfo_column_;
unsigned PacketListRecord::col_data_ver_ = 1;

PacketListRecord::PacketListRecord(frame_data *frameData) :
    col_text_(0),
    fdata_(frameData),
    lines_(1),
    line_count_changed_(false),
    data_ver_(0),
    colorized_(false),
    conv_(NULL)
{
}

void *PacketListRecord::operator new(size_t size)
{
    return wmem_alloc(wmem_file_scope(), size);
}

// We might want to return a const char * instead. This would keep us from
// creating excessive QByteArrays, e.g. in PacketListModel::recordLessThan.
const QByteArray PacketListRecord::columnString(capture_file *cap_file, int column, bool colorized)
{
    // packet_list_store.c:packet_list_get_value
    g_assert(fdata_);

    if (!cap_file || column < 0 || column > cap_file->cinfo.num_cols) {
        return QByteArray();
    }

    bool dissect_color = colorized && !colorized_;
    if (!col_text_ || column >= col_text_->size() || !col_text_->at(column) || data_ver_ != col_data_ver_ || dissect_color) {
        dissect(cap_file, dissect_color);
    }

    return col_text_->value(column, QByteArray());
}

void PacketListRecord::resetColumns(column_info *cinfo)
{
    col_data_ver_++;

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

void PacketListRecord::resetColorized()
{
    colorized_ = false;
}

void PacketListRecord::dissect(capture_file *cap_file, bool dissect_color)
{
    // packet_list_store.c:packet_list_dissect_and_cache_record
    epan_dissect_t edt;
    column_info *cinfo = NULL;
    gboolean create_proto_tree;
    struct wtap_pkthdr phdr; /* Packet header */
    Buffer buf; /* Packet data */

    if (!col_text_) col_text_ = new ColumnTextList;
    gboolean dissect_columns = col_text_->isEmpty() || data_ver_ != col_data_ver_;

    if (!cap_file) {
        return;
    }

    memset(&phdr, 0, sizeof(struct wtap_pkthdr));

    if (dissect_columns) {
        cinfo = &cap_file->cinfo;
    }

    ws_buffer_init(&buf, 1500);
    if (!cf_read_record_r(cap_file, fdata_, &phdr, &buf)) {
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
        return;    /* error reading the record */
    }

    create_proto_tree = ((dissect_color && color_filters_used()) ||
                         (dissect_columns && (have_custom_cols(cinfo) ||
                                              have_field_extractors())));

    epan_dissect_init(&edt, cap_file->epan,
                      create_proto_tree,
                      FALSE /* proto_tree_visible */);

    /* Re-color when the coloring rules are changed via the UI. */
    if (dissect_color) {
        color_filters_prime_edt(&edt);
        fdata_->flags.need_colorize = 1;
    }
    if (dissect_columns)
        col_custom_prime_edt(&edt, cinfo);

    /*
     * XXX - need to catch an OutOfMemoryError exception and
     * attempt to recover from it.
     */
    epan_dissect_run(&edt, cap_file->cd_t, &phdr, frame_tvbuff_new_buffer(fdata_, &buf), fdata_, cinfo);

    if (dissect_columns) {
        /* "Stringify" non frame_data vals */
        epan_dissect_fill_in_columns(&edt, FALSE, FALSE /* fill_fd_columns */);
        cacheColumnStrings(cinfo);
    }

    if (dissect_color) {
        colorized_ = true;
    }
    data_ver_ = col_data_ver_;

    packet_info *pi = &edt.pi;
    conv_ = find_conversation(pi->num, &pi->src, &pi->dst, pi->ptype,
                              pi->srcport, pi->destport, 0);

    epan_dissect_cleanup(&edt);
    ws_buffer_free(&buf);
}

// This assumes only one packet list. We might want to move this to
// PacketListModel (or replace this with a wmem allocator).
struct _GStringChunk *PacketListRecord::string_pool_ = g_string_chunk_new(1 * 1024 * 1024);
void PacketListRecord::clearStringPool()
{
    g_string_chunk_clear(string_pool_);
}

//#define MINIMIZE_STRING_COPYING 1
void PacketListRecord::cacheColumnStrings(column_info *cinfo)
{
    // packet_list_store.c:packet_list_change_record(PacketList *packet_list, PacketListRecord *record, gint col, column_info *cinfo)
    if (!cinfo) {
        return;
    }

    if (col_text_) {
        col_text_->clear();
    } else {
        col_text_ = new ColumnTextList;
    }
    lines_ = 1;
    line_count_changed_ = false;

    for (int column = 0; column < cinfo->num_cols; ++column) {
        int col_lines = 1;

#ifdef MINIMIZE_STRING_COPYING
        int text_col = cinfo_column_.value(column, -1);

        /* Column based on frame_data or it already contains a value */
        if (text_col < 0) {
            col_fill_in_frame_data(fdata_, cinfo, column, FALSE);
            col_text_->append(cinfo->columns[column].col_data);
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
            if (cinfo->columns[column].col_data && cinfo->columns[column].col_data != cinfo->columns[column].col_buf) {
                /* This is a constant string, so we don't have to copy it */
                // XXX - ui/gtk/packet_list_store.c uses G_MAXUSHORT. We don't do proper UTF8
                // truncation in either case.
                int col_text_len = MIN(qstrlen(cinfo->col_data[column]) + 1, COL_MAX_INFO_LEN);
                col_text_->append(QByteArray::fromRawData(cinfo->columns[column].col_data, col_text_len));
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
            if (!get_column_resolved(column) && cinfo->col_expr.col_expr_val[column]) {
                /* Use the unresolved value in col_expr_val */
                // XXX Use QContiguousCache?
                col_text_->append(cinfo->col_expr.col_expr_val[column]);
            } else {
                col_text_->append(cinfo->columns[column].col_data);
            }
            break;
        }
#else // MINIMIZE_STRING_COPYING
        const char *col_str;
        if (!get_column_resolved(column) && cinfo->col_expr.col_expr_val[column]) {
            /* Use the unresolved value in col_expr_val */
            col_str = cinfo->col_expr.col_expr_val[column];
        } else {
            int text_col = cinfo_column_.value(column, -1);

            if (text_col < 0) {
                col_fill_in_frame_data(fdata_, cinfo, column, FALSE);
            }
            col_str = cinfo->columns[column].col_data;
        }
        // g_string_chunk_insert_const manages a hash table of pointers to
        // strings:
        // https://git.gnome.org/browse/glib/tree/glib/gstringchunk.c
        // We might be better off adding the equivalent functionality to
        // wmem_tree.
        col_text_->append(g_string_chunk_insert_const(string_pool_, col_str));
        for (int i = 0; col_str[i]; i++) {
            if (col_str[i] == '\n') col_lines++;
        }
        if (col_lines > lines_) {
            lines_ = col_lines;
            line_count_changed_ = true;
        }
#endif // MINIMIZE_STRING_COPYING
    }
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
