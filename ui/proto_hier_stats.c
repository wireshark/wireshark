/* proto_hier_stats.c
 * Routines for calculating statistics based on protocol.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "file.h"
#include "frame_tvbuff.h"
#include "ui/proto_hier_stats.h"
#include "ui/progress_dlg.h"
#include "epan/epan_dissect.h"
#include "epan/proto.h"
#include <wsutil/ws_assert.h>

/* Update the progress bar this many times when scanning the packet list. */
#define N_PROGBAR_UPDATES	100

#define STAT_NODE_STATS(n)   ((ph_stats_node_t*)(n)->data)
#define STAT_NODE_HFINFO(n)  (STAT_NODE_STATS(n)->hfinfo)

static int pc_proto_id = -1;

    static GNode*
find_stat_node(GNode *parent_stat_node, const header_field_info *needle_hfinfo)
{
    GNode		*needle_stat_node, *up_parent_stat_node;
    const header_field_info	*hfinfo;
    ph_stats_node_t	*stats;

    /* Look down the tree */
    needle_stat_node = g_node_first_child(parent_stat_node);

    while (needle_stat_node) {
        hfinfo = STAT_NODE_HFINFO(needle_stat_node);
        if (hfinfo &&  hfinfo->id == needle_hfinfo->id) {
            return needle_stat_node;
        }
        needle_stat_node = g_node_next_sibling(needle_stat_node);
    }

    /* Look up the tree */
    up_parent_stat_node = parent_stat_node;
    while (up_parent_stat_node && up_parent_stat_node->parent)
    {
        needle_stat_node = g_node_first_child(up_parent_stat_node->parent);
        while (needle_stat_node) {
            hfinfo = STAT_NODE_HFINFO(needle_stat_node);
            if (hfinfo &&  hfinfo->id == needle_hfinfo->id) {
                return needle_stat_node;
            }
            needle_stat_node = g_node_next_sibling(needle_stat_node);
        }

        up_parent_stat_node = up_parent_stat_node->parent;
    }

    /* None found. Create one. */
    stats = g_new(ph_stats_node_t, 1);

    /* Initialize counters */
    stats->hfinfo = needle_hfinfo;
    stats->num_pkts_total = 0;
    stats->num_pdus_total = 0;
    stats->num_pkts_last = 0;
    stats->num_bytes_total = 0;
    stats->num_bytes_last = 0;
    stats->last_pkt = 0;

    needle_stat_node = g_node_new(stats);
    g_node_append(parent_stat_node, needle_stat_node);
    return needle_stat_node;
}


    static void
process_node(proto_node *ptree_node, GNode *parent_stat_node, ph_stats_t *ps)
{
    field_info		*finfo;
    ph_stats_node_t	*stats;
    proto_node		*proto_sibling_node;
    GNode		*stat_node;

    finfo = PNODE_FINFO(ptree_node);
    /* We don't fake protocol nodes we expect them to have a field_info.
     * Even with a faked proto tree, we don't fake nodes when PTREE_FINFO(tree)
     * is NULL in order to avoid crashes here and elsewhere. (See epan/proto.c)
     */
    ws_assert(finfo);

    stat_node = find_stat_node(parent_stat_node, finfo->hfinfo);

    stats = STAT_NODE_STATS(stat_node);
    /* Only increment the total packet count once per packet for a given
     * node, since there could be multiple PDUs in a frame.
     * (All the other statistics should be incremented every time,
     * including the count for how often a protocol was the last
     * protocol in a packet.)
     */
    if (stats->last_pkt != ps->tot_packets) {
        stats->num_pkts_total++;
        stats->last_pkt = ps->tot_packets;
    }
    stats->num_pdus_total++;
    stats->num_bytes_total += finfo->length + finfo->appendix_length;

    proto_sibling_node = ptree_node->next;

    /* Skip entries that are not protocols, e.g.
     * toplevel tree item of desegmentation "[Reassembled TCP Segments]")
     * XXX: We should probably skip PINOs with field_type FT_BYTES too.
     *
     * XXX: We look at siblings not children, and thus don't descend into
     * the tree to pick up embedded protocols not added to the toplevel of
     * the tree.
     */
    while (proto_sibling_node && !proto_registrar_is_protocol(PNODE_FINFO(proto_sibling_node)->hfinfo->id)) {
        proto_sibling_node = proto_sibling_node->next;
    }

    if (proto_sibling_node) {
        process_node(proto_sibling_node, stat_node, ps);
    } else {
        stats->num_pkts_last++;
        stats->num_bytes_last += finfo->length + finfo->appendix_length;
    }
}



    static void
process_tree(proto_tree *protocol_tree, ph_stats_t* ps)
{
    proto_node	*ptree_node;

    /*
     * Skip over non-protocols and comments. (Packet comments are a PINO
     * with FT_PROTOCOL field type). This keeps us from having a top-level
     * "Packet comments" item that steals items from "Frame".
     */
    ptree_node = ((proto_node *)protocol_tree)->first_child;
    while (ptree_node && (ptree_node->finfo->hfinfo->id == pc_proto_id || !proto_registrar_is_protocol(ptree_node->finfo->hfinfo->id))) {
        ptree_node = ptree_node->next;
    }

    if (!ptree_node) {
        return;
    }

    process_node(ptree_node, ps->stats_tree, ps);
}

    static bool
process_record(capture_file *cf, frame_data *frame, column_info *cinfo,
               wtap_rec *rec, Buffer *buf, ph_stats_t* ps)
{
    epan_dissect_t	edt;
    double		cur_time;

    /* Load the record from the capture file */
    if (!cf_read_record(cf, frame, rec, buf))
        return false;	/* failure */

    /* Dissect the record   tree  not visible */
    epan_dissect_init(&edt, cf->epan, true, false);
    /* Don't fake protocols. We need them for the protocol hierarchy */
    epan_dissect_fake_protocols(&edt, false);
    epan_dissect_run(&edt, cf->cd_t, rec,
                     frame_tvbuff_new_buffer(&cf->provider, frame, buf),
                     frame, cinfo);

    /* Get stats from this protocol tree */
    process_tree(edt.tree, ps);

    if (frame->has_ts) {
        /* Update times */
        cur_time = nstime_to_sec(&frame->abs_ts);
        if (cur_time < ps->first_time)
            ps->first_time = cur_time;
        if (cur_time > ps->last_time)
            ps->last_time = cur_time;
    }

    /* Free our memory. */
    epan_dissect_cleanup(&edt);

    return true;	/* success */
}

    ph_stats_t*
ph_stats_new(capture_file *cf)
{
    ph_stats_t	*ps;
    uint32_t	framenum;
    frame_data	*frame;
    progdlg_t	*progbar = NULL;
    int		count;
    wtap_rec	rec;
    Buffer	buf;
    float	progbar_val;
    char	status_str[100];
    int		progbar_nextstep;
    int		progbar_quantum;

    if (!cf) return NULL;

    if (cf->read_lock) {
        ws_warning("Failing to compute protocol hierarchy stats on \"%s\" since a read is in progress", cf->filename);
        return NULL;
    }
    cf->read_lock = true;

    cf->stop_flag = false;

    pc_proto_id = proto_registrar_get_id_byname("pkt_comment");

    /* Initialize the data */
    ps = g_new(ph_stats_t, 1);
    ps->tot_packets = 0;
    ps->tot_bytes = 0;
    ps->stats_tree = g_node_new(NULL);
    ps->first_time = 0.0;
    ps->last_time = 0.0;

    /* Update the progress bar when it gets to this value. */
    progbar_nextstep = 0;
    /* When we reach the value that triggers a progress bar update,
       bump that value by this amount. */
    progbar_quantum = cf->count/N_PROGBAR_UPDATES;
    /* Count of packets at which we've looked. */
    count = 0;
    /* Progress so far. */
    progbar_val = 0.0f;

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    for (framenum = 1; framenum <= cf->count; framenum++) {
        frame = frame_data_sequence_find(cf->provider.frames, framenum);

        /* Create the progress bar if necessary.
           We check on every iteration of the loop, so that
           it takes no longer than the standard time to create
           it (otherwise, for a large file, we might take
           considerably longer than that standard time in order
           to get to the next progress bar step). */
        if (progbar == NULL)
            progbar = delayed_create_progress_dlg(
                    cf->window, "Computing",
                    "protocol hierarchy statistics",
                    true, &cf->stop_flag, progbar_val);

        /* Update the progress bar, but do it only N_PROGBAR_UPDATES
           times; when we update it, we have to run the GTK+ main
           loop to get it to repaint what's pending, and doing so
           may involve an "ioctl()" to see if there's any pending
           input from an X server, and doing that for every packet
           can be costly, especially on a big file. */
        if (count >= progbar_nextstep) {
            /* let's not divide by zero. I should never be started
             * with count == 0, so let's assert that
             */
            ws_assert(cf->count > 0);

            progbar_val = (float) count / cf->count;

            if (progbar != NULL) {
                snprintf(status_str, sizeof(status_str),
                        "%4u of %u frames", count, cf->count);
                update_progress_dlg(progbar, progbar_val, status_str);
            }

            progbar_nextstep += progbar_quantum;
        }

        if (cf->stop_flag) {
            /* Well, the user decided to abort the statistics.
               computation process  Just stop. */
            break;
        }

        /* Skip frames that are hidden due to the display filter.
           XXX - should the progress bar count only packets that
           passed the display filter?  If so, it should
           probably do so for other loops (see "file.c") that
           look only at those packets. */
        if (frame->passed_dfilter) {

            if (frame->has_ts) {
                if (ps->tot_packets == 0) {
                    double cur_time = nstime_to_sec(&frame->abs_ts);
                    ps->first_time = cur_time;
                    ps->last_time = cur_time;
                }
            }

            /* We throw away the statistics if we quit in the middle,
             * so increment this first so that the count starts at 1
             * when processing records, since we initialize the stat
             * nodes' last_pkt to 0.
             */
            ps->tot_packets++;

            /* we don't care about colinfo */
            if (!process_record(cf, frame, NULL, &rec, &buf, ps)) {
                /*
                 * Give up, and set "stop_flag" so we
                 * just abort rather than popping up
                 * the statistics window.
                 */
                cf->stop_flag = true;
                break;
            }

            ps->tot_bytes += frame->pkt_len;
        }

        count++;
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    /* We're done calculating the statistics; destroy the progress bar
       if it was created. */
    if (progbar != NULL)
        destroy_progress_dlg(progbar);

    if (cf->stop_flag) {
        /*
         * We quit in the middle; throw away the statistics
         * and return NULL, so our caller doesn't pop up a
         * window with the incomplete statistics.
         */
        ph_stats_free(ps);
        ps = NULL;
    }

    ws_assert(cf->read_lock);
    cf->read_lock = false;

    return ps;
}

    static gboolean
stat_node_free(GNode *node, void *data _U_)
{
    ph_stats_node_t	*stats = (ph_stats_node_t *)node->data;
    g_free(stats);
    return false;
}

    void
ph_stats_free(ph_stats_t *ps)
{
    if (ps->stats_tree) {
        g_node_traverse(ps->stats_tree, G_IN_ORDER,
                G_TRAVERSE_ALL, -1,
                stat_node_free, NULL);
        g_node_destroy(ps->stats_tree);
    }

    g_free(ps);
}
