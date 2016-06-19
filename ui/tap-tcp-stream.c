/* tap-tcp-stream.c
 * TCP stream statistics
 * Originally from tcp_graph.c by Pavel Mores <pvl@uh.cz>
 * Win32 port:  rwh@unifiedtech.com
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

#include "config.h"


#include <stdlib.h>

#include <file.h>
#include <frame_tvbuff.h>

#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/tap.h>

#include <epan/dissectors/packet-tcp.h>

#include "ui/simple_dialog.h"

#include "tap-tcp-stream.h"

typedef struct _tcp_scan_t {
    struct segment         *current;
    int                     direction;
    struct tcp_graph       *tg;
    struct segment         *last;
} tcp_scan_t;


static gboolean
tapall_tcpip_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    tcp_scan_t   *ts = (tcp_scan_t *)pct;
    struct tcp_graph *tg  = ts->tg;
    const struct tcpheader *tcphdr = (const struct tcpheader *)vip;

    if (tg->stream == tcphdr->th_stream
            && (tg->src_address.type == AT_NONE || tg->dst_address.type == AT_NONE)) {
        /*
         * We only know the stream number. Fill in our connection data.
         * We assume that the server response is more interesting.
         */
        copy_address(&tg->src_address, &tcphdr->ip_dst);
        tg->src_port = tcphdr->th_dport;
        copy_address(&tg->dst_address, &tcphdr->ip_src);
        tg->dst_port = tcphdr->th_sport;
    }

    if (compare_headers(&tg->src_address, &tg->dst_address,
                        tg->src_port, tg->dst_port,
                        &tcphdr->ip_src, &tcphdr->ip_dst,
                        tcphdr->th_sport, tcphdr->th_dport,
                        ts->direction)
        && tg->stream == tcphdr->th_stream)
    {
        struct segment *segment = (struct segment *)g_malloc(sizeof(struct segment));
        segment->next      = NULL;
        segment->num       = pinfo->num;
        segment->rel_secs  = (guint32)pinfo->rel_ts.secs;
        segment->rel_usecs = pinfo->rel_ts.nsecs/1000;
        /* Currently unused
        segment->abs_secs  = (guint32)pinfo->abs_ts.secs;
        segment->abs_usecs = pinfo->abs_ts.nsecs/1000;
        */
        segment->th_seq    = tcphdr->th_seq;
        segment->th_ack    = tcphdr->th_ack;
        segment->th_win    = tcphdr->th_win;
        segment->th_flags  = tcphdr->th_flags;
        segment->th_sport  = tcphdr->th_sport;
        segment->th_dport  = tcphdr->th_dport;
        segment->th_seglen = tcphdr->th_seglen;
        copy_address(&segment->ip_src, &tcphdr->ip_src);
        copy_address(&segment->ip_dst, &tcphdr->ip_dst);

        segment->num_sack_ranges = MIN(MAX_TCP_SACK_RANGES, tcphdr->num_sack_ranges);
        if (segment->num_sack_ranges > 0) {
            /* Copy entries in the order they happen */
            memcpy(&segment->sack_left_edge, &tcphdr->sack_left_edge, sizeof(segment->sack_left_edge));
            memcpy(&segment->sack_right_edge, &tcphdr->sack_right_edge, sizeof(segment->sack_right_edge));
        }

        if (ts->tg->segments) {
            ts->last->next = segment;
        } else {
            ts->tg->segments = segment;
        }
        ts->last = segment;
    }

    return FALSE;
}

/* here we collect all the external data we will ever need */
void
graph_segment_list_get(capture_file *cf, struct tcp_graph *tg, gboolean stream_known)
{
    struct segment current;
    GString    *error_string;
    tcp_scan_t  ts;

    g_log(NULL, G_LOG_LEVEL_DEBUG, "graph_segment_list_get()");

    if (!cf || !tg) return;

    if (!stream_known) {
        struct tcpheader *header = select_tcpip_session(cf, &current);
        if (!header) return;
        if (tg->type == GRAPH_THROUGHPUT)
            ts.direction = COMPARE_CURR_DIR;
        else
            ts.direction = COMPARE_ANY_DIR;

        /* Remember stream info in graph */
        copy_address(&tg->src_address, &current.ip_src);
        tg->src_port = current.th_sport;
        copy_address(&tg->dst_address, &current.ip_dst);
        tg->dst_port = current.th_dport;
        tg->stream = header->th_stream;
    }
    else {
            ts.direction = COMPARE_ANY_DIR;
    }

    /* rescan all the packets and pick up all interesting tcp headers.
     * we only filter for TCP here for speed and do the actual compare
     * in the tap listener
     */
    ts.current = &current;
    ts.tg      = tg;
    ts.last    = NULL;
    error_string = register_tap_listener("tcp", &ts, "tcp", 0, NULL, tapall_tcpip_packet, NULL);
    if (error_string) {
        fprintf(stderr, "wireshark: Couldn't register tcp_graph tap: %s\n",
                error_string->str);
        g_string_free(error_string, TRUE);
        exit(1);   /* XXX: fix this */
    }
    cf_retap_packets(cf);
    remove_tap_listener(&ts);
}

void
graph_segment_list_free(struct tcp_graph *tg)
{
    struct segment *segment;

    while (tg->segments) {
        segment = tg->segments->next;
        g_free(tg->segments);
        tg->segments = segment;
    }
    tg->segments = NULL;
}

int
compare_headers(address *saddr1, address *daddr1, guint16 sport1, guint16 dport1, const address *saddr2, const address *daddr2, guint16 sport2, guint16 dport2, int dir)
{
    int dir1, dir2;

    dir1 = ((!(cmp_address(saddr1, saddr2))) &&
            (!(cmp_address(daddr1, daddr2))) &&
            (sport1==sport2)                 &&
            (dport1==dport2));

    if (dir == COMPARE_CURR_DIR) {
        return dir1;
    } else {
        dir2 = ((!(cmp_address(saddr1, daddr2))) &&
                (!(cmp_address(daddr1, saddr2))) &&
                (sport1 == dport2)               &&
                (dport1 == sport2));
        return dir1 || dir2;
    }
}

int
get_num_dsegs(struct tcp_graph *tg)
{
    int count;
    struct segment *tmp;

    for (tmp=tg->segments, count=0; tmp; tmp=tmp->next) {
        if (compare_headers(&tg->src_address, &tg->dst_address,
                            tg->src_port, tg->dst_port,
                            &tmp->ip_src, &tmp->ip_dst,
                            tmp->th_sport, tmp->th_dport,
                            COMPARE_CURR_DIR)) {
            count++;
        }
    }
    return count;
}

int
get_num_acks(struct tcp_graph *tg, int *num_sack_ranges)
{
    int count;
    struct segment *tmp;

    for (tmp = tg->segments, count=0; tmp; tmp = tmp->next) {
        if (!compare_headers(&tg->src_address, &tg->dst_address,
                             tg->src_port, tg->dst_port,
                             &tmp->ip_src, &tmp->ip_dst,
                             tmp->th_sport, tmp->th_dport,
                             COMPARE_CURR_DIR)) {
            count++;
            *num_sack_ranges += tmp->num_sack_ranges;
        }
    }
    return count;
}



typedef struct _th_t {
    int num_hdrs;
    #define MAX_SUPPORTED_TCP_HEADERS 8
    struct tcpheader *tcphdrs[MAX_SUPPORTED_TCP_HEADERS];
} th_t;

static gboolean
tap_tcpip_packet(void *pct, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *vip)
{
    int       n;
    gboolean  is_unique = TRUE;
    th_t     *th        = (th_t *)pct;
    const struct tcpheader *header = (const struct tcpheader *)vip;

    /* Check new header details against any/all stored ones */
    for (n=0; n < th->num_hdrs; n++) {
        struct tcpheader *stored = th->tcphdrs[n];

        if (compare_headers(&stored->ip_src, &stored->ip_dst,
                            stored->th_sport, stored->th_dport,
                            &header->ip_src, &header->ip_dst,
                            header->th_sport, stored->th_dport,
                            COMPARE_CURR_DIR))
        {
            is_unique = FALSE;
            break;
        }
    }

    /* Add address if unique and have space for it */
    if (is_unique && (th->num_hdrs < MAX_SUPPORTED_TCP_HEADERS)) {
        /* Need to take a deep copy of the tap struct, it may not be valid
           to read after this function returns? */
        th->tcphdrs[th->num_hdrs] = (struct tcpheader *)g_malloc(sizeof(struct tcpheader));
        *(th->tcphdrs[th->num_hdrs]) = *header;
        copy_address(&th->tcphdrs[th->num_hdrs]->ip_src, &header->ip_src);
        copy_address(&th->tcphdrs[th->num_hdrs]->ip_dst, &header->ip_dst);

        th->num_hdrs++;
    }

    return FALSE;
}

/* XXX should be enhanced so that if we have multiple TCP layers in the trace
 * then present the user with a dialog where the user can select WHICH tcp
 * session to graph.
 */
struct tcpheader *
select_tcpip_session(capture_file *cf, struct segment *hdrs)
{
    frame_data     *fdata;
    epan_dissect_t  edt;
    dfilter_t      *sfcode;
    gchar          *err_msg;
    GString        *error_string;
    nstime_t        rel_ts;
    th_t th = {0, {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}};

    if (!cf || !hdrs)
        return NULL;

    fdata = cf->current_frame;

    /* no real filter yet */
    if (!dfilter_compile("tcp", &sfcode, &err_msg)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
        return NULL;
    }

    /* dissect the current record */
    if (!cf_read_record(cf, fdata))
        return NULL;    /* error reading the record */


    error_string=register_tap_listener("tcp", &th, NULL, 0, NULL, tap_tcpip_packet, NULL);
    if (error_string) {
        fprintf(stderr, "wireshark: Couldn't register tcp_graph tap: %s\n",
                error_string->str);
        g_string_free(error_string, TRUE);
        exit(1);
    }

    epan_dissect_init(&edt, cf->epan, TRUE, FALSE);
    epan_dissect_prime_dfilter(&edt, sfcode);
    epan_dissect_run_with_taps(&edt, cf->cd_t, &cf->phdr, frame_tvbuff_new_buffer(fdata, &cf->buf), fdata, NULL);
    rel_ts = edt.pi.rel_ts;
    epan_dissect_cleanup(&edt);
    remove_tap_listener(&th);

    if (th.num_hdrs == 0) {
        /* This "shouldn't happen", as our menu items shouldn't
         * even be enabled if the selected packet isn't a TCP
         * segment, as tcp_graph_selected_packet_enabled() is used
         * to determine whether to enable any of our menu items. */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Selected packet isn't a TCP segment or is truncated");
        return NULL;
    }
    /* XXX fix this later, we should show a dialog allowing the user
       to select which session he wants here
    */
    if (th.num_hdrs > 1) {
        /* can only handle a single tcp layer yet */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "The selected packet has more than one TCP unique conversation "
                      "in it.");
        return NULL;
    }

    /* For now, still always choose the first/only one */
    hdrs->num   = fdata->num;
    hdrs->rel_secs  = (guint32) rel_ts.secs;
    hdrs->rel_usecs = rel_ts.nsecs/1000;
    /* Currently unused
    hdrs->abs_secs  = (guint32) fdata->abs_ts.secs;
    hdrs->abs_usecs = fdata->abs_ts.nsecs/1000;
    */
    hdrs->th_seq    = th.tcphdrs[0]->th_seq;
    hdrs->th_ack    = th.tcphdrs[0]->th_ack;
    hdrs->th_win    = th.tcphdrs[0]->th_win;
    hdrs->th_flags  = th.tcphdrs[0]->th_flags;
    hdrs->th_sport  = th.tcphdrs[0]->th_sport;
    hdrs->th_dport  = th.tcphdrs[0]->th_dport;
    hdrs->th_seglen = th.tcphdrs[0]->th_seglen;
    copy_address(&hdrs->ip_src, &th.tcphdrs[0]->ip_src);
    copy_address(&hdrs->ip_dst, &th.tcphdrs[0]->ip_dst);
    return th.tcphdrs[0];
}

int rtt_is_retrans(struct unack *list, unsigned int seqno)
{
    struct unack *u;

    for (u=list; u; u=u->next) {
        if (u->seqno == seqno)
            return TRUE;
    }
    return FALSE;
}

struct unack *rtt_get_new_unack(double time_val, unsigned int seqno)
{
    struct unack *u;

    u = (struct unack * )g_malloc(sizeof(struct unack));
    u->next  = NULL;
    u->time  = time_val;
    u->seqno = seqno;
    return u;
}

void rtt_put_unack_on_list(struct unack **l, struct unack *new_unack)
{
    struct unack *u, *list = *l;

    for (u=list; u; u=u->next) {
        if (!u->next)
            break;
    }
    if (u)
        u->next = new_unack;
    else
        *l = new_unack;
}

void rtt_delete_unack_from_list(struct unack **l, struct unack *dead)
{
    struct unack *u, *list = *l;

    if (!dead || !list)
        return;

    if (dead == list) {
        *l = list->next;
        g_free(list);
    } else {
        for (u=list; u; u=u->next) {
            if (u->next == dead) {
                u->next = u->next->next;
                g_free(dead);
                break;
            }
        }
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

