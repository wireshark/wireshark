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
#include "epan/column-utils.h"
#include "epan/packet.h"
#include "epan/tap.h"
#include "epan/dissectors/packet-tcp.h"

#include "ui/alert_box.h"

#include <wsutil/file_util.h>

#define NODE_OVERFLOW MAX_NUM_NODES+1

#define NODE_CHARS_WIDTH 20
#define CONV_TIME_HEADER       "Conv.| Time    "
#define TIME_HEADER "|Time     "
#define CONV_TIME_EMPTY_HEADER "     |         "
#define TIME_EMPTY_HEADER      "|         "
#define CONV_TIME_HEADER_LENGTH 16
#define TIME_HEADER_LENGTH 10

/****************************************************************************/
/* whenever a frame packet is seen by the tap listener */
/* Add a new frame into the graph */
static gboolean
seq_analysis_frame_packet( void *ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *dummy _U_)
{
    seq_analysis_info_t *sainfo = (seq_analysis_info_t *) ptr;

    if ((sainfo->all_packets)||(pinfo->fd->flags.passed_dfilter==1)){
        int i;
        gchar *protocol = NULL;
        gchar *colinfo = NULL;
        seq_analysis_item_t *sai = NULL;

        if (sainfo->any_addr) {
            if (pinfo->net_src.type!=AT_NONE && pinfo->net_dst.type!=AT_NONE) {
                sai = (seq_analysis_item_t *)g_malloc0(sizeof(seq_analysis_item_t));
                COPY_ADDRESS(&(sai->src_addr),&(pinfo->net_src));
                COPY_ADDRESS(&(sai->dst_addr),&(pinfo->net_dst));
            }

        } else {
            if (pinfo->src.type!=AT_NONE && pinfo->dst.type!=AT_NONE) {
                sai = (seq_analysis_item_t *)g_malloc0(sizeof(seq_analysis_item_t));
                COPY_ADDRESS(&(sai->src_addr),&(pinfo->src));
                COPY_ADDRESS(&(sai->dst_addr),&(pinfo->dst));
            }
        }

        if (!sai) return FALSE;

        sai->fd = pinfo->fd;

        sai->port_src=pinfo->srcport;
        sai->port_dst=pinfo->destport;

        if(pinfo->cinfo) {
            if (pinfo->cinfo->col_first[COL_INFO]>=0){

                for (i = pinfo->cinfo->col_first[COL_INFO]; i <= pinfo->cinfo->col_last[COL_INFO]; i++) {
                    if (pinfo->cinfo->fmt_matx[i][COL_INFO]) {
                        colinfo = g_strdup(pinfo->cinfo->col_data[i]);
                        /* break; ? or g_free(colinfo); before g_strdup() */
                    }
                }
            }

            if (pinfo->cinfo->col_first[COL_PROTOCOL]>=0){

                for (i = pinfo->cinfo->col_first[COL_PROTOCOL]; i <= pinfo->cinfo->col_last[COL_PROTOCOL]; i++) {
                    if (pinfo->cinfo->fmt_matx[i][COL_PROTOCOL]) {
                        protocol = g_strdup(pinfo->cinfo->col_data[i]);
                        /* break; ? or g_free(protocol); before g_strdup() */
                    }
                }
            }
        }

        if (colinfo != NULL) {
            if (protocol != NULL) {
                sai->frame_label = g_strdup(colinfo);
                sai->comment = g_strdup_printf("%s: %s", protocol, colinfo);
            } else {
                sai->frame_label = g_strdup(colinfo);
                sai->comment = g_strdup(colinfo);
            }
        } else {
            /* This will probably never happen...*/
            if (protocol != NULL) {
                sai->frame_label = g_strdup(protocol);
                sai->comment = g_strdup(protocol);
            }
        }

        g_free(protocol);
        g_free(colinfo);

        sai->line_style=1;
        sai->conv_num=0;
        sai->display=TRUE;

        sainfo->list = g_list_prepend(sainfo->list, sai);
    }

    return TRUE;
}

/****************************************************************************/
/* whenever a TCP packet is seen by the tap listener */
/* Add a new tcp frame into the graph */
static gboolean
seq_analysis_tcp_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *tcp_info)
{
    seq_analysis_info_t *sainfo = (seq_analysis_info_t *) ptr;
    const struct tcpheader *tcph = (const struct tcpheader *)tcp_info;

    if ((sainfo->all_packets)||(pinfo->fd->flags.passed_dfilter==1)){
        /* copied from packet-tcp */
        static const gchar *fstr[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR" };
        guint i, bpos;
        gboolean flags_found = FALSE;
        gchar flags[64];
        seq_analysis_item_t *sai;

        sai = (seq_analysis_item_t *)g_malloc0(sizeof(seq_analysis_item_t));
        sai->fd = pinfo->fd;
        if (sainfo->any_addr) {
            COPY_ADDRESS(&(sai->src_addr),&(pinfo->net_src));
            COPY_ADDRESS(&(sai->dst_addr),&(pinfo->net_dst));
        } else {
            COPY_ADDRESS(&(sai->src_addr),&(pinfo->src));
            COPY_ADDRESS(&(sai->dst_addr),&(pinfo->dst));
        }
        sai->port_src=pinfo->srcport;
        sai->port_dst=pinfo->destport;

        flags[0] = '\0';
        for (i = 0; i < 8; i++) {
            bpos = 1 << i;
            if (tcph->th_flags & bpos) {
                if (flags_found) {
                    g_strlcat(flags, ", ", sizeof(flags));
                }
                g_strlcat(flags, fstr[i], sizeof(flags));
                flags_found = TRUE;
            }
        }
        if (flags[0] == '\0') {
            g_snprintf (flags, sizeof(flags), "<None>");
        }

        if ((tcph->th_have_seglen)&&(tcph->th_seglen!=0)){
            sai->frame_label = g_strdup_printf("%s - Len: %u",flags, tcph->th_seglen);
        }
        else{
            sai->frame_label = g_strdup(flags);
        }

        if (tcph->th_flags & TH_ACK)
            sai->comment = g_strdup_printf("Seq = %u Ack = %u",tcph->th_seq, tcph->th_ack);
        else
            sai->comment = g_strdup_printf("Seq = %u",tcph->th_seq);

        sai->line_style = 1;
        sai->conv_num = 0;
        sai->display = TRUE;

        sainfo->list = g_list_prepend(sainfo->list, sai);
    }

    return TRUE;
}

void
sequence_analysis_list_get(capture_file *cf, seq_analysis_info_t *sainfo)
{
    GList *list;
    gchar time_str[COL_MAX_LEN];

    if (!cf || !sainfo) return;

    switch (sainfo->type) {
    case SEQ_ANALYSIS_ANY:
        register_tap_listener("frame", sainfo, NULL,
            TL_REQUIRES_COLUMNS,
            NULL,
            seq_analysis_frame_packet,
            NULL
            );
        break;
    case SEQ_ANALYSIS_TCP:
        register_tap_listener("tcp", sainfo, NULL,
            0,
            NULL,
            seq_analysis_tcp_packet,
            NULL
            );
        break;
    case SEQ_ANALYSIS_VOIP:
    default:
        return;
        break;

    }

    cf_retap_packets(cf);
    sainfo->list = g_list_reverse(sainfo->list);
    remove_tap_listener(sainfo);

    /* Fill in the timestamps */
    list = g_list_first(sainfo->list);
    while (list)
    {
        seq_analysis_item_t *seq_item = (seq_analysis_item_t *)list->data;
        set_fd_time(cf->epan, seq_item->fd, time_str);
        seq_item->time_str = g_strdup(time_str);
        list = g_list_next(list);
    }
}

void
sequence_analysis_list_free(seq_analysis_info_t *sainfo)
{
    GList *list;
    int i;

    if (!sainfo) return;

    /* free the graph data items */
    list = g_list_first(sainfo->list);
    while (list)
    {
        seq_analysis_item_t *seq_item = (seq_analysis_item_t *)list->data;
        g_free(seq_item->frame_label);
        g_free(seq_item->time_str);
        g_free(seq_item->comment);
        g_free(list->data);
        list = g_list_next(list);
    }
    g_list_free(sainfo->list);
    sainfo->list = NULL;
    sainfo->nconv = 0;

    for (i=0; i<MAX_NUM_NODES; i++) {
        sainfo->nodes[i].type = AT_NONE;
        sainfo->nodes[i].len = 0;
        g_free((void *)sainfo->nodes[i].data);
        sainfo->nodes[i].data = NULL;
    }
    sainfo->num_nodes = 0;
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

/* Return the index array if the node is in the array. Return -1 if there is room in the array
 * and Return -2 if the array is full
 */
/****************************************************************************/
static gint add_or_get_node(seq_analysis_info_t *sainfo, address *node) {
    guint i;

    if (node->type == AT_NONE) return NODE_OVERFLOW;

    for (i=0; i<MAX_NUM_NODES && i < sainfo->num_nodes ; i++) {
        if ( CMP_ADDRESS(&(sainfo->nodes[i]), node) == 0 ) return i; /* it is in the array */
    }

    if (i == MAX_NUM_NODES) {
        return  NODE_OVERFLOW;
    } else {
        sainfo->num_nodes++;
        COPY_ADDRESS(&(sainfo->nodes[i]), node);
        return i;
    }
}

/* Get the nodes from the list */
/****************************************************************************/
int
sequence_analysis_get_nodes(seq_analysis_info_t *sainfo)
{
    GList *list;
    seq_analysis_item_t *gai;
    int num_items = 0;

    /* fill the node array */
    list = g_list_first(sainfo->list);
    while (list)
    {
        gai = (seq_analysis_item_t *)list->data;
        if (gai->display) {
            num_items++;
#if 0 /* inverse is always false ? */
            if (!user_data->dlg.inverse) {
#endif
                gai->src_node = (guint16)add_or_get_node(sainfo, &(gai->src_addr));
                gai->dst_node = (guint16)add_or_get_node(sainfo, &(gai->dst_addr));
#if 0 /* inverse is always false ? */
            } else {
                gai->dst_node = (guint16)add_or_get_node(sainfo, &(gai->src_addr));
                gai->src_node = (guint16)add_or_get_node(sainfo, &(gai->dst_addr));
            }
#endif
        }
        list = g_list_next(list);
    }
    return num_items;
}

/****************************************************************************/
gboolean
sequence_analysis_dump_to_file(const char *pathname, seq_analysis_info_t *sainfo, capture_file *cf, unsigned int first_node)
{
    guint32  i, display_items, display_nodes;
    guint32  start_position, end_position, item_width, header_length;
    seq_analysis_item_t *sai;
    guint16  first_conv_num = 0;
    gboolean several_convs  = FALSE;
    gboolean first_packet   = TRUE;

    GString    *label_string, *empty_line, *separator_line, *tmp_str, *tmp_str2;
    const char *empty_header;
    char        src_port[8], dst_port[8];
    gchar      *time_str;
    GList      *list;

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
    list = g_list_first(sainfo->list);
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
        g_string_printf(label_string, "| %s",
            ep_address_to_display(&(sainfo->nodes[i+first_node])));
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
        g_string_printf(label_string, "| %s",
            ep_address_to_display(&(sainfo->nodes[i+first_node])));
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

    list = g_list_first(sainfo->list);
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

#if 0
        /* write the time */
        g_string_printf(label_string, "|%.3f", nstime_to_sec(&sai->fd->rel_ts));
#endif
        /* Write the time, using the same format as in the time col */
        set_fd_time(cf->epan, sai->fd, time_str);
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
