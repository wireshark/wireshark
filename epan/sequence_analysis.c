/* sequence-analysis.c
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

#include "sequence_analysis.h"

#include "addr_resolv.h"
#include "proto.h"
#include "color_filters.h"
#include "column-info.h"
#include "tap.h"
#include "wmem/wmem.h"

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
            sai->comment = g_strdup_printf("%s: %s", protocol, colinfo);
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
    sainfo->ht= g_hash_table_new(g_int_hash, g_int_equal);
    return sainfo;
}

void sequence_analysis_info_free(seq_analysis_info_t *sainfo)
{
    if (!sainfo) return;

    /* SEQ_ANALYSIS_DEBUG("%d items", g_queue_get_length(sainfo->items)); */
    sequence_analysis_list_free(sainfo);

    g_queue_free(sainfo->items);
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

#if GLIB_CHECK_VERSION (2, 32, 0)
       g_queue_free_full(sainfo->items, sequence_analysis_item_free);
       sainfo->items = g_queue_new();
#else
    {
        GList *list = g_queue_peek_nth_link(sainfo->items, 0);
        while (list)
        {
            sequence_analysis_item_free(list->data);
            list = g_list_next(list);
        }
        g_queue_clear(sainfo->items);
    }
#endif

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
