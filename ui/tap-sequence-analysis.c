/* tap-sequence-analysis.c
 * Flow sequence analysis
 *
 * Some code from from gtk/flow_graph.c
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include "file.h"

#include "tap-sequence-analysis.h"

#include "epan/addr_resolv.h"
#include "epan/packet.h"
#include "epan/tap.h"

#include "ui/alert_box.h"

#include <wsutil/file_util.h>

#define NODE_CHARS_WIDTH 20
#define CONV_TIME_HEADER       "Conv.| Time    "
#define TIME_HEADER "|Time     "
#define CONV_TIME_EMPTY_HEADER "     |         "
#define TIME_EMPTY_HEADER      "|         "
#define CONV_TIME_HEADER_LENGTH 16
#define TIME_HEADER_LENGTH 10

void
sequence_analysis_list_get(capture_file *cf, seq_analysis_info_t *sainfo)
{
    register_analysis_t* analysis = NULL;

    if (!cf || !sainfo)
        return;

    analysis = sequence_analysis_find_by_name(sainfo->name);
    if (analysis == NULL)
        return;

    register_tap_listener(sequence_analysis_get_tap_listener_name(analysis), sainfo, NULL, sequence_analysis_get_tap_flags(analysis),
                               NULL, sequence_analysis_get_packet_func(analysis), NULL);

    cf_retap_packets(cf);
    remove_tap_listener(sainfo);

    /* SEQ_ANALYSIS_DEBUG("%d items", g_queue_get_length(sainfo->items)); */
}

/****************************************************************************/
/* Adds trailing characters to complete the requested length.               */
/****************************************************************************/

static void enlarge_string(GString *gstr, guint32 length, char pad) {

    gsize i;

    for (i = gstr->len; i < length; i++) {
        g_string_append_c(gstr, pad);
    }
}

/****************************************************************************/
/* overwrites the characters in a string, between positions p1 and p2, with */
/*   the characters of text_to_insert                                       */
/*   NB: it does not check that p1 and p2 fit into string                   */
/****************************************************************************/

static void overwrite (GString *gstr, char *text_to_insert, guint32 p1, guint32 p2) {

    glong len, ins_len;
    gsize pos;
    gchar *ins_str = NULL;

    if (p1 == p2)
        return;

    if (p1 > p2) {
        pos = p2;
        len = p1 - p2;
    }
    else{
        pos = p1;
        len = p2 - p1;
    }

    ins_len = g_utf8_strlen(text_to_insert, -1);
    if (len > ins_len) {
        len = ins_len;
    } else if (len < ins_len) {
#if GLIB_CHECK_VERSION(2,30,0)
        ins_str = g_utf8_substring(text_to_insert, 0, len);
#else
        gchar *end = g_utf8_offset_to_pointer(text_to_insert, len);
        ins_str = g_strndup(text_to_insert, end - text_to_insert);
#endif
    }

    if (!ins_str) ins_str = g_strdup(text_to_insert);

    if (pos > gstr->len)
        pos = gstr->len;

    g_string_erase(gstr, pos, len);

    g_string_insert(gstr, pos, ins_str);
    g_free(ins_str);
}

/****************************************************************************/
gboolean
sequence_analysis_dump_to_file(const char *pathname, seq_analysis_info_t *sainfo, capture_file *cf, unsigned int first_node)
{
    guint32  i, display_items, display_nodes;
    guint32  start_position, end_position, item_width, header_length;
    seq_analysis_item_t *sai;
    frame_data *fd;
    guint16  first_conv_num = 0;
    gboolean several_convs  = FALSE;
    gboolean first_packet   = TRUE;

    GString    *label_string, *empty_line, *separator_line, *tmp_str, *tmp_str2;
    const char *empty_header;
    char        src_port[8], dst_port[8];
    gchar      *time_str;
    GList      *list;
    char       *addr_str;

    FILE  *of;

    of = ws_fopen(pathname, "w");
    if (of==NULL) {
        open_failure_alert_box(pathname, errno, TRUE);
        return FALSE;
    }

    time_str       = (gchar *)g_malloc(COL_MAX_LEN);
    label_string   = g_string_new("");
    empty_line     = g_string_new("");
    separator_line = g_string_new("");
    tmp_str        = g_string_new("");
    tmp_str2       = g_string_new("");

    display_items = 0;
    list = g_queue_peek_nth_link(sainfo->items, 0);
    while (list)
    {
        sai = (seq_analysis_item_t *)list->data;
        list = g_list_next(list);

        if (!sai->display)
            continue;

        display_items += 1;
        if (first_packet) {
            first_conv_num = sai->conv_num;
            first_packet = FALSE;
        }
        else if (sai->conv_num != first_conv_num) {
            several_convs = TRUE;
        }
    }

    /* if not items to display */
    if (display_items == 0)
        goto exit;

    display_nodes = sainfo->num_nodes;

    /* Write the conv. and time headers */
    if (several_convs) {
        fprintf(of, CONV_TIME_HEADER);
        empty_header = CONV_TIME_EMPTY_HEADER;
        header_length = CONV_TIME_HEADER_LENGTH;
    }
    else{
        fprintf(of, TIME_HEADER);
        empty_header = TIME_EMPTY_HEADER;
        header_length = TIME_HEADER_LENGTH;
    }

    /* Write the node names on top */
    for (i=0; i<display_nodes; i+=2) {
        /* print the node identifiers */
        addr_str = address_to_display(NULL, &(sainfo->nodes[i+first_node]));
        g_string_printf(label_string, "| %s", addr_str);
        wmem_free(NULL, addr_str);
        enlarge_string(label_string, NODE_CHARS_WIDTH*2, ' ');
        fprintf(of, "%s", label_string->str);
        g_string_printf(label_string, "| ");
        enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
        g_string_append(empty_line, label_string->str);
    }

    fprintf(of, "|\n%s", empty_header);
    g_string_printf(label_string, "| ");
    enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
    fprintf(of, "%s", label_string->str);

    /* Write the node names on top */
    for (i=1; i<display_nodes; i+=2) {
        /* print the node identifiers */
        addr_str = address_to_display(NULL, &(sainfo->nodes[i+first_node]));
        g_string_printf(label_string, "| %s", addr_str);
        wmem_free(NULL, addr_str);
        if (label_string->len < NODE_CHARS_WIDTH)
        {
            enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
            g_string_append(label_string, "| ");
        }
        enlarge_string(label_string, NODE_CHARS_WIDTH*2, ' ');
        fprintf(of, "%s", label_string->str);
        g_string_printf(label_string, "| ");
        enlarge_string(label_string, NODE_CHARS_WIDTH, ' ');
        g_string_append(empty_line, label_string->str);
    }

    fprintf(of, "\n");

    g_string_append_c(empty_line, '|');

    enlarge_string(separator_line, (guint32) empty_line->len + header_length, '-');

    /*
     * Draw the items
     */

    list = g_queue_peek_nth_link(sainfo->items, 0);
    while (list)
    {
        sai = (seq_analysis_item_t *)list->data;
        list = g_list_next(list);

        if (!sai->display)
            continue;

        start_position = (sai->src_node-first_node)*NODE_CHARS_WIDTH+NODE_CHARS_WIDTH/2;

        end_position = (sai->dst_node-first_node)*NODE_CHARS_WIDTH+NODE_CHARS_WIDTH/2;

        if (start_position > end_position) {
            item_width = start_position-end_position;
        }
        else if (start_position < end_position) {
            item_width = end_position-start_position;
        }
        else{ /* same origin and destination address */
            end_position = start_position+NODE_CHARS_WIDTH;
            item_width = NODE_CHARS_WIDTH;
        }

        /* separator between conversations */
        if (sai->conv_num != first_conv_num) {
            fprintf(of, "%s\n", separator_line->str);
            first_conv_num = sai->conv_num;
        }

        /* write the conversation number */
        if (several_convs) {
            g_string_printf(label_string, "%i", sai->conv_num);
            enlarge_string(label_string, 5, ' ');
            fprintf(of, "%s", label_string->str);
        }

        fd = frame_data_sequence_find(cf->frames, sai->frame_number);
#if 0
        /* write the time */
        g_string_printf(label_string, "|%.3f", nstime_to_sec(&fd->rel_ts));
#endif
        /* Write the time, using the same format as in the time col */
        set_fd_time(cf->epan, fd, time_str);
        g_string_printf(label_string, "|%s", time_str);
        enlarge_string(label_string, 10, ' ');
        fprintf(of, "%s", label_string->str);

        /* write the frame label */

        g_string_printf(tmp_str, "%s", empty_line->str);
        overwrite(tmp_str, sai->frame_label,
            start_position,
            end_position
            );
        fprintf(of, "%s", tmp_str->str);

        /* write the comments */
        fprintf(of, "%s\n", sai->comment);

        /* write the arrow and frame label*/
        fprintf(of, "%s", empty_header);

        g_string_printf(tmp_str, "%s", empty_line->str);

        g_string_truncate(tmp_str2, 0);

        if (start_position<end_position) {
            enlarge_string(tmp_str2, item_width-2, '-');
            g_string_append_c(tmp_str2, '>');
        }
        else{
            g_string_printf(tmp_str2, "<");
            enlarge_string(tmp_str2, item_width-1, '-');
        }

        overwrite(tmp_str, tmp_str2->str,
            start_position,
            end_position
            );

        g_snprintf(src_port, sizeof(src_port), "(%i)", sai->port_src);
        g_snprintf(dst_port, sizeof(dst_port), "(%i)", sai->port_dst);

        if (start_position<end_position) {
            overwrite(tmp_str, src_port, start_position-9, start_position-1);
            overwrite(tmp_str, dst_port, end_position+1, end_position+9);
        }
        else{
            overwrite(tmp_str, src_port, start_position+1, start_position+9);
            overwrite(tmp_str, dst_port, end_position-9, end_position+1);
        }

        fprintf(of, "%s\n", tmp_str->str);
    }

exit:
    g_string_free(label_string, TRUE);
    g_string_free(empty_line, TRUE);
    g_string_free(separator_line, TRUE);
    g_string_free(tmp_str, TRUE);
    g_string_free(tmp_str2, TRUE);
    g_free(time_str);
    fclose (of);
    return TRUE;

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
