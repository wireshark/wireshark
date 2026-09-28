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
#include <epan/color_filters.h>
#include <epan/tag_rules.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/dfilter/dfilter.h>
#include <epan/wmem_scopes.h>
#include <wsutil/wmem/wmem_list.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include <QStringList>

QCache<uint32_t, QStringList> PacketListRecord::col_text_cache_(500);
bool PacketListRecord::dissection_paused_ = false;
QMap<int, int> PacketListRecord::cinfo_column_;
unsigned PacketListRecord::rows_color_ver_ = 1;
bool PacketListRecord::any_tag_column_ = false;

PacketListRecord::PacketListRecord(frame_data *frameData) :
    fdata_(frameData),
    lines_(1),
    line_count_changed_(false),
    color_ver_(0),
    colorized_(false),
    conv_index_(0),
    read_failed_(false),
    row_(0),
    expert_severity_(0),
    color_filters_(NULL),
    color_filter_count_(0)
{
}

PacketListRecord::~PacketListRecord()
{
    g_slist_free(color_filters_);
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

    if (!cap_file || column < 0 || (unsigned)column >= cap_file->cinfo.num_cols) {
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
    any_tag_column_ = false;
    unsigned i, j;
    for (i = 0, j = 0; i < cinfo->num_cols; i++) {
        if (get_column_format(i) == COL_TAG)
            any_tag_column_ = true;
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
    wtap_rec rec; /* Record information */

    if (!cap_file) {
        return;
    }

    // The dissection_paused_ is used by the Lua Debugger when paused in
    // a nested UI loop and re-entry would corrupt pause-thread state.
    // The main UI is frozen and will dissect again when unfrozen.
    if (dissection_paused_) {
        return;
    }

    if (dissect_columns) {
        cinfo = &cap_file->cinfo;
    }

    wtap_rec_init(&rec, DEFAULT_INIT_BUFFER_SIZE_2048);
    if (read_failed_) {
        read_failed_ = !cf_read_record_no_alert(cap_file, fdata_, &rec);
    } else {
        read_failed_ = !cf_read_record(cap_file, fdata_, &rec);
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
    create_proto_tree = ((dissect_color && (color_filters_used() || any_tag_column_)) ||
                         (dissect_columns && (have_custom_cols(cinfo) ||
                                              have_field_extractors())));

    epan_dissect_init(&edt, cap_file->epan,
                      create_proto_tree,
                      false /* proto_tree_visible */);

    /* Re-color when the coloring rules are changed via the UI. */
    if (dissect_color) {
        color_filters_prime_edt(&edt);
        if (any_tag_column_)
            tag_rules_prime_edt(&edt);
        fdata_->need_colorize = 1;
    }
    if (dissect_columns)
        col_custom_prime_edt(&edt, cinfo);

    /*
     * XXX - need to catch an OutOfMemoryError exception and
     * attempt to recover from it.
     */
    epan_dissect_run(&edt, cap_file->cd_t, &rec, fdata_, cinfo);
    expert_severity_ = edt.pi.expert_severity;

    if (dissect_columns) {
        /* "Stringify" non frame_data vals */
        epan_dissect_fill_in_columns(&edt, false, false /* fill_fd_columns */);
        cacheColumnStrings(cinfo);
    }

    if (dissect_color) {
        colorized_ = true;
        color_ver_ = rows_color_ver_;

        // Free previous color list
        g_slist_free(color_filters_);
        color_filters_ = NULL;
        color_filter_count_ = 0;

        // Get all matching colors if any multi-color feature is enabled
        if (prefs.gui_packet_list_multi_color_mode != PACKET_LIST_MULTI_COLOR_MODE_OFF ||
            prefs.gui_packet_list_multi_color_details) {
            wmem_list_t *wm_matches = NULL;
            fdata_->color_filter = color_filters_colorize_packet_all(&edt, wmem_file_scope(), &wm_matches);
            if (wm_matches) {
                for (wmem_list_frame_t *lf = wmem_list_head(wm_matches); lf != NULL; lf = wmem_list_frame_next(lf)) {
                    color_filters_ = g_slist_append(color_filters_, wmem_list_frame_data(lf));
                    color_filter_count_++;
                }
                wmem_destroy_list(wm_matches);
            }
        } else {
            color_filter_count_ = fdata_->color_filter ? 1 : 0;
        }

        // Apply tagging rules: build display strings and store rule names as
        // proto_data (key 1) for frame.tag field population in dissect_frame().
        // The GSList spine and its strings are both wmem_file_scope()-allocated
        // (rather than glib-heap-allocated via g_slist_append) so they are
        // reclaimed automatically when the capture file closes, with no
        // explicit free needed even for a frame's last redissection.
        tag_column_str_.clear();
        tag_column_tip_.clear();
        tag_column_segments_.clear();
        tag_link_list_.clear();
        if (any_tag_column_) {
            const GSList *rule_list = tag_rules_get_list();
            int frame_proto_id = proto_get_id_by_filter_name("frame");
            p_remove_proto_data(wmem_file_scope(), &edt.pi, frame_proto_id, 1);
            GSList *tag_names = NULL;
            GSList *tag_names_tail = NULL;
            QStringList tip_lines;
            tag_prefs_t tag_prefs = tag_rules_get_prefs();
            for (const GSList *r = rule_list; r; r = g_slist_next(r)) {
                tag_rule_t *rule = (tag_rule_t *)r->data;
                if (!rule->disabled && rule->c_tagfilter &&
                    dfilter_apply_edt(rule->c_tagfilter, &edt)) {
                    QString seg_text = (rule->tag_content && rule->tag_content[0])
                        ? QString::fromUtf8(rule->tag_content) : QString();
                    QString seg_url  = (rule->tag_url && rule->tag_url[0])
                        ? QString::fromUtf8(rule->tag_url) : QString();
                    if (!seg_text.isEmpty()) {
                        if (!tag_column_str_.isEmpty() && tag_prefs.separator != '\0')
                            tag_column_str_ += QChar::fromLatin1(tag_prefs.separator);
                        tag_column_str_ += seg_text;
                    }
                    tag_column_segments_.append(qMakePair(seg_text, seg_url));
                    if (!seg_url.isEmpty()) {
                        QString link_name = QString::fromUtf8(rule->rule_name);
                        tag_link_list_.append(qMakePair(link_name, seg_url));
                    }
                    QString tip_line = QString::fromUtf8(rule->rule_name);
                    if (rule->comment && rule->comment[0])
                        tip_line += QStringLiteral(": ") + QString::fromUtf8(rule->comment);
                    tip_lines << tip_line;
                    /* Store rule name in proto_data for frame.tag display */
                    char *tag_str = wmem_strdup(wmem_file_scope(), rule->rule_name);
                    GSList *node = wmem_new(wmem_file_scope(), GSList);
                    node->data = tag_str;
                    node->next = NULL;
                    if (tag_names_tail)
                        tag_names_tail->next = node;
                    else
                        tag_names = node;
                    tag_names_tail = node;
                }
            }
            tag_column_tip_ = tip_lines.join(QStringLiteral("\n"));
            if (tag_names) {
                p_add_proto_data(wmem_file_scope(), &edt.pi, frame_proto_id, 1, tag_names);
            }
        }
    }

    struct conversation * conv = find_conversation_pinfo_ro(&edt.pi, 0);

    conv_index_ = ! conv ? 0 : conv->conv_index;

    epan_dissect_cleanup(&edt);
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

    for (unsigned column = 0; column < cinfo->num_cols; ++column) {
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
