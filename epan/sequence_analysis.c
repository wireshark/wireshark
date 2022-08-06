/* sequence-analysis.c
 * Flow sequence analysis
 *
 * Some code from gtk/flow_graph.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "sequence_analysis.h"

#include "addr_resolv.h"
#include "proto.h"
#include "color_filters.h"
#include <epan/column.h>
#include "tap.h"
#include <epan/wmem_scopes.h>

#define NODE_OVERFLOW MAX_NUM_NODES+1

struct register_analysis {
    const char* name;          /* Name (used for lookup) */
    const char* ui_name;       /* Name used for UI */
    int proto_id;              /* protocol id (0-indexed) */
    const char* tap_listen_str;      /* string used in register_tap_listener (NULL to use protocol name) */
    guint tap_flags;
    tap_packet_cb analysis_func;    /* function to be called for new incoming packets for sequence analysis */
};

static wmem_tree_t *registered_seq_analysis = NULL;

void
register_seq_analysis(const char* name, const char* ui_name, const int proto_id, const char* tap_listener, guint tap_flags, tap_packet_cb tap_func)
{
    register_analysis_t* analysis;

    DISSECTOR_ASSERT(tap_func);

    analysis = wmem_new0(wmem_epan_scope(), register_analysis_t);

    analysis->name          = name;
    analysis->ui_name       = ui_name;
    analysis->proto_id      = proto_id;
    if (tap_listener != NULL)
        analysis->tap_listen_str = tap_listener;
    else
        analysis->tap_listen_str = proto_get_protocol_filter_name(proto_id);
    analysis->tap_flags     = tap_flags;
    analysis->analysis_func = tap_func;

    if (registered_seq_analysis == NULL)
        registered_seq_analysis = wmem_tree_new(wmem_epan_scope());

    wmem_tree_insert_string(registered_seq_analysis, name, analysis, 0);
}

const char* sequence_analysis_get_name(register_analysis_t* analysis)
{
    return analysis->name;
}

const char* sequence_analysis_get_ui_name(register_analysis_t* analysis)
{
    return analysis->ui_name;
}

const char* sequence_analysis_get_tap_listener_name(register_analysis_t* analysis)
{
    return analysis->tap_listen_str;
}

tap_packet_cb sequence_analysis_get_packet_func(register_analysis_t* analysis)
{
    return analysis->analysis_func;
}

guint sequence_analysis_get_tap_flags(register_analysis_t* analysis)
{
    return analysis->tap_flags;
}


register_analysis_t* sequence_analysis_find_by_name(const char* name)
{
    return (register_analysis_t*)wmem_tree_lookup_string(registered_seq_analysis, name, 0);
}

void sequence_analysis_table_iterate_tables(wmem_foreach_func func, gpointer user_data)
{
    wmem_tree_foreach(registered_seq_analysis, func, user_data);
}

seq_analysis_item_t* sequence_analysis_create_sai_with_addresses(packet_info *pinfo, seq_analysis_info_t *sainfo)
{
    seq_analysis_item_t *sai = NULL;
    char time_str[COL_MAX_LEN];

    if (sainfo->any_addr) {
        if (pinfo->net_src.type!=AT_NONE && pinfo->net_dst.type!=AT_NONE) {
            sai = g_new0(seq_analysis_item_t, 1);
            copy_address(&(sai->src_addr),&(pinfo->net_src));
            copy_address(&(sai->dst_addr),&(pinfo->net_dst));
        }

    } else {
        if (pinfo->src.type!=AT_NONE && pinfo->dst.type!=AT_NONE) {
            sai = g_new0(seq_analysis_item_t, 1);
            copy_address(&(sai->src_addr),&(pinfo->src));
            copy_address(&(sai->dst_addr),&(pinfo->dst));
        }
    }

    if (sai) {
        /* Fill in the timestamps */
        set_fd_time(pinfo->epan, pinfo->fd, time_str);
        sai->time_str = g_strdup(time_str);
    }

    return sai;
}

void sequence_analysis_use_color_filter(packet_info *pinfo, seq_analysis_item_t *sai)
{
    if (pinfo->fd->color_filter) {
        sai->bg_color = color_t_to_rgb(&pinfo->fd->color_filter->bg_color);
        sai->fg_color = color_t_to_rgb(&pinfo->fd->color_filter->fg_color);
        sai->has_color_filter = TRUE;
    }
}

void sequence_analysis_use_col_info_as_label_comment(packet_info *pinfo, seq_analysis_item_t *sai)
{
    const gchar *protocol = NULL;
    const gchar *colinfo = NULL;

    if (pinfo->cinfo) {
        colinfo = col_get_text(pinfo->cinfo, COL_INFO);
        protocol = col_get_text(pinfo->cinfo, COL_PROTOCOL);
    }

    if (colinfo != NULL) {
        sai->frame_label = g_strdup(colinfo);
        if (protocol != NULL) {
            sai->comment = ws_strdup_printf("%s: %s", protocol, colinfo);
        } else {
            sai->comment = g_strdup(colinfo);
        }
    } else {
        /* This will probably never happen...*/
        if (protocol != NULL) {
            sai->frame_label = g_strdup(protocol);
            sai->comment = g_strdup(protocol);
        }
    }
}

seq_analysis_info_t *
sequence_analysis_info_new(void)
{
    seq_analysis_info_t *sainfo = g_new0(seq_analysis_info_t, 1);

    /* SEQ_ANALYSIS_DEBUG("adding new item"); */
    sainfo->items = g_queue_new();
    sainfo->ht= g_hash_table_new(g_direct_hash, g_direct_equal);
    return sainfo;
}

void sequence_analysis_info_free(seq_analysis_info_t *sainfo)
{
    if (!sainfo) return;

    /* SEQ_ANALYSIS_DEBUG("%d items", g_queue_get_length(sainfo->items)); */
    sequence_analysis_list_free(sainfo);

    g_queue_free(sainfo->items);
    if (sainfo->ht != NULL)
        g_hash_table_destroy(sainfo->ht);

    g_free(sainfo);
}

static void sequence_analysis_item_free(gpointer data)
{
    seq_analysis_item_t *seq_item = (seq_analysis_item_t *)data;
    g_free(seq_item->frame_label);
    g_free(seq_item->time_str);
    g_free(seq_item->comment);
    free_address(&seq_item->src_addr);
    free_address(&seq_item->dst_addr);
    if (seq_item->info_ptr) {
        g_free(seq_item->info_ptr);
    }
    g_free(data);
}


/* compare two list entries by packet no */
static gint
sequence_analysis_sort_compare(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
    const seq_analysis_item_t *entry_a = (const seq_analysis_item_t *)a;
    const seq_analysis_item_t *entry_b = (const seq_analysis_item_t *)b;

    if(entry_a->frame_number < entry_b->frame_number)
        return -1;

    if(entry_a->frame_number > entry_b->frame_number)
        return 1;

    return 0;
}


void
sequence_analysis_list_sort(seq_analysis_info_t *sainfo)
{
    if (!sainfo) return;
    g_queue_sort(sainfo->items, sequence_analysis_sort_compare, NULL);
}

void
sequence_analysis_list_free(seq_analysis_info_t *sainfo)
{
    if (!sainfo) return;
    /* SEQ_ANALYSIS_DEBUG("%d items", g_queue_get_length(sainfo->items)); */

    /* free the graph data items */

       if (sainfo->items != NULL)
            g_queue_free_full(sainfo->items, sequence_analysis_item_free);
       sainfo->items = g_queue_new();

    if (NULL != sainfo->ht) {
        g_hash_table_remove_all(sainfo->ht);
    }
    sainfo->nconv = 0;

    sequence_analysis_free_nodes(sainfo);
}

/* Return the index array if the node is in the array. Return -1 if there is room in the array
 * and Return -2 if the array is full
 */
/****************************************************************************/
static guint add_or_get_node(seq_analysis_info_t *sainfo, address *node) {
    guint i;

    if (node->type == AT_NONE) return NODE_OVERFLOW;

    for (i=0; i<MAX_NUM_NODES && i < sainfo->num_nodes ; i++) {
        if ( cmp_address(&(sainfo->nodes[i]), node) == 0 ) return i; /* it is in the array */
    }

    if (i >= MAX_NUM_NODES) {
        return  NODE_OVERFLOW;
    } else {
        sainfo->num_nodes++;
        copy_address(&(sainfo->nodes[i]), node);
        return i;
    }
}

struct sainfo_counter {
    seq_analysis_info_t *sainfo;
    int num_items;
};

static void sequence_analysis_get_nodes_item_proc(gpointer data, gpointer user_data)
{
    seq_analysis_item_t *gai = (seq_analysis_item_t *)data;
    struct sainfo_counter *sc = (struct sainfo_counter *)user_data;
    if (gai->display) {
        (sc->num_items)++;
        gai->src_node = add_or_get_node(sc->sainfo, &(gai->src_addr));
        gai->dst_node = add_or_get_node(sc->sainfo, &(gai->dst_addr));
    }
}

/* Get the nodes from the list */
/****************************************************************************/
int
sequence_analysis_get_nodes(seq_analysis_info_t *sainfo)
{
    struct sainfo_counter sc = {sainfo, 0};

    /* Fill the node array */
    g_queue_foreach(sainfo->items, sequence_analysis_get_nodes_item_proc, &sc);

    return sc.num_items;
}

/* Free the node address list */
/****************************************************************************/
void
sequence_analysis_free_nodes(seq_analysis_info_t *sainfo)
{
    int i;

    for (i=0; i<MAX_NUM_NODES; i++) {
        free_address(&sainfo->nodes[i]);
    }
    sainfo->num_nodes = 0;
}

/* Writing analysis to file */
/****************************************************************************/

#define NODE_CHARS_WIDTH 20
#define CONV_TIME_HEADER       "Conv.| Time    "
#define TIME_HEADER "|Time     "
#define CONV_TIME_EMPTY_HEADER "     |         "
#define TIME_EMPTY_HEADER      "|         "
#define CONV_TIME_HEADER_LENGTH 16
#define TIME_HEADER_LENGTH 10

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
        ins_str = g_utf8_substring(text_to_insert, 0, len);
    }

    if (!ins_str) ins_str = g_strdup(text_to_insert);

    if (pos > gstr->len)
        pos = gstr->len;

    g_string_erase(gstr, pos, len);

    g_string_insert(gstr, pos, ins_str);
    g_free(ins_str);
}


void
sequence_analysis_dump_to_file(FILE  *of, seq_analysis_info_t *sainfo, unsigned int first_node)
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
    GList      *list = NULL;
    char       *addr_str;

    display_items = 0;
    if (sainfo->items != NULL)
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
    if (display_items == 0) {
        return;
    }

    label_string   = g_string_new("");
    empty_line     = g_string_new("");
    separator_line = g_string_new("");
    tmp_str        = g_string_new("");
    tmp_str2       = g_string_new("");

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

        if (sai->time_str != NULL) {
            g_string_printf(label_string, "|%s", sai->time_str);
            enlarge_string(label_string, 10, ' ');
            fprintf(of, "%s", label_string->str);
        }

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

        snprintf(src_port, sizeof(src_port), "(%i)", sai->port_src);
        snprintf(dst_port, sizeof(dst_port), "(%i)", sai->port_dst);

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

    g_string_free(label_string, TRUE);
    g_string_free(empty_line, TRUE);
    g_string_free(separator_line, TRUE);
    g_string_free(tmp_str, TRUE);
    g_string_free(tmp_str2, TRUE);
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
