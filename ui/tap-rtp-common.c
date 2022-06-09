/* tap-rtp-common.c
 * RTP stream handler functions used by tshark and wireshark
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from ui/gtk/rtp_stream.c and ui/gtk/rtp_analysis.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <glib.h>

#include <epan/rtp_pt.h>
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-rtp.h>
#include <wsutil/pint.h>
#include "rtp_stream.h"
#include "tap-rtp-common.h"

/* XXX: are changes needed to properly handle situations where
        info_all_data_present == FALSE ?
        E.G., when captured frames are truncated.
 */

/****************************************************************************/
/* Type for storing and writing rtpdump information */
typedef struct st_rtpdump_info {
    double rec_time;       /**< milliseconds since start of recording */
    guint16 num_samples;   /**< number of bytes in *frame */
    const guint8 *samples; /**< data bytes */
} rtpdump_info_t;

/****************************************************************************/
/* init rtpstream_info_t structure */
void rtpstream_info_init(rtpstream_info_t *info)
{
    memset(info, 0, sizeof(rtpstream_info_t));
}

/****************************************************************************/
/* malloc and init rtpstream_info_t structure */
rtpstream_info_t *rtpstream_info_malloc_and_init(void)
{
    rtpstream_info_t *dest;

    dest = g_new(rtpstream_info_t, 1);
    rtpstream_info_init(dest);

    return dest;
}

/****************************************************************************/
/* deep copy of rtpstream_info_t */
void rtpstream_info_copy_deep(rtpstream_info_t *dest, const rtpstream_info_t *src)
{
    /* Deep clone of contents */
    *dest = *src;  /* memberwise copy of struct */
    copy_address(&(dest->id.src_addr), &(src->id.src_addr));
    copy_address(&(dest->id.dst_addr), &(src->id.dst_addr));
    dest->all_payload_type_names = g_strdup(src->all_payload_type_names);
}

/****************************************************************************/
/* malloc and deep copy rtpstream_info_t structure */
rtpstream_info_t *rtpstream_info_malloc_and_copy_deep(const rtpstream_info_t *src)
{
    rtpstream_info_t *dest;

    dest = g_new(rtpstream_info_t, 1);
    rtpstream_info_copy_deep(dest, src);

    return dest;
}

/****************************************************************************/
/* free rtpstream_info_t referenced values */
void rtpstream_info_free_data(rtpstream_info_t *info)
{
    if (info->all_payload_type_names != NULL) {
        g_free(info->all_payload_type_names);
    }

    rtpstream_id_free(&info->id);
}

/****************************************************************************/
/* free rtpstream_info_t referenced values and whole structure */
void rtpstream_info_free_all(rtpstream_info_t *info)
{
    rtpstream_info_free_data(info);
    g_free(info);
}

/****************************************************************************/
/* GCompareFunc style comparison function for rtpstream_info_t */
gint rtpstream_info_cmp(gconstpointer aa, gconstpointer bb)
{
    const rtpstream_info_t *a = (const rtpstream_info_t *)aa;
    const rtpstream_info_t *b = (const rtpstream_info_t *)bb;

    if (a==b)
        return 0;
    if (a==NULL || b==NULL)
        return 1;
    if (rtpstream_id_equal(&(a->id),&(b->id),RTPSTREAM_ID_EQUAL_SSRC))
        return 0;
    else
        return 1;
}

/****************************************************************************/
/* compare the endpoints of two RTP streams */
gboolean rtpstream_info_is_reverse(const rtpstream_info_t *stream_a, rtpstream_info_t *stream_b)
{
    if (stream_a == NULL || stream_b == NULL)
        return FALSE;

    if ((addresses_equal(&(stream_a->id.src_addr), &(stream_b->id.dst_addr)))
        && (stream_a->id.src_port == stream_b->id.dst_port)
        && (addresses_equal(&(stream_a->id.dst_addr), &(stream_b->id.src_addr)))
        && (stream_a->id.dst_port == stream_b->id.src_port))
        return TRUE;
    else
        return FALSE;
}

/****************************************************************************/
/* when there is a [re]reading of packet's */
void rtpstream_reset(rtpstream_tapinfo_t *tapinfo)
{
    GList* list;
    rtpstream_info_t *stream_info;

    if (tapinfo->mode == TAP_ANALYSE) {
        /* free the data items first */
        if (tapinfo->strinfo_hash) {
            g_hash_table_foreach(tapinfo->strinfo_hash, rtpstream_info_multihash_destroy_value, NULL);
            g_hash_table_destroy(tapinfo->strinfo_hash);
        }
        list = g_list_first(tapinfo->strinfo_list);
        while (list)
        {
            stream_info = (rtpstream_info_t *)(list->data);
            rtpstream_info_free_data(stream_info);
            g_free(list->data);
            list = g_list_next(list);
        }
        g_list_free(tapinfo->strinfo_list);
        tapinfo->strinfo_list = NULL;
        tapinfo->strinfo_hash = NULL;
        tapinfo->nstreams = 0;
        tapinfo->npackets = 0;
    }

    return;
}

void rtpstream_reset_cb(void *arg)
{
    rtpstream_tapinfo_t *ti =(rtpstream_tapinfo_t *)arg;
    if (ti->tap_reset) {
        /* Give listeners a chance to cleanup references. */
        ti->tap_reset(ti);
    }
    rtpstream_reset(ti);
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/

/****************************************************************************/
/* redraw the output */
static void rtpstream_draw_cb(void *ti_ptr)
{
    rtpstream_tapinfo_t *tapinfo = (rtpstream_tapinfo_t *)ti_ptr;
/* XXX: see rtpstream_on_update in rtp_streams_dlg.c for comments
    g_signal_emit_by_name(top_level, "signal_rtpstream_update");
*/
    if (tapinfo && tapinfo->tap_draw) {
        /* RTP_STREAM_DEBUG("streams: %d packets: %d", tapinfo->nstreams, tapinfo->npackets); */
        tapinfo->tap_draw(tapinfo);
    }
    return;
}



/****************************************************************************/
void
remove_tap_listener_rtpstream(rtpstream_tapinfo_t *tapinfo)
{
    if (tapinfo && tapinfo->is_registered) {
        remove_tap_listener(tapinfo);
        tapinfo->is_registered = FALSE;
    }
}

/****************************************************************************/
void
register_tap_listener_rtpstream(rtpstream_tapinfo_t *tapinfo, const char *fstring, rtpstream_tap_error_cb tap_error)
{
    GString *error_string;

    if (!tapinfo) {
        return;
    }

    if (!tapinfo->is_registered) {
        error_string = register_tap_listener("rtp", tapinfo,
            fstring, 0, rtpstream_reset_cb, rtpstream_packet_cb,
            rtpstream_draw_cb, NULL);

        if (error_string != NULL) {
            if (tap_error) {
                tap_error(error_string);
            }
            g_string_free(error_string, TRUE);
            exit(1);
        }

        tapinfo->is_registered = TRUE;
    }
}

/*
* rtpdump file format
*
* The file starts with the tool to be used for playing this file,
* the multicast/unicast receive address and the port.
*
* #!rtpplay1.0 224.2.0.1/3456\n
*
* This is followed by one binary header (RD_hdr_t) and one RD_packet_t
* structure for each received packet.  All fields are in network byte
* order.  We don't need the source IP address since we can do mapping
* based on SSRC.  This saves (a little) space, avoids non-IPv4
* problems and privacy/security concerns. The header is followed by
* the RTP/RTCP header and (optionally) the actual payload.
*/

static const gchar *PAYLOAD_UNKNOWN_STR = "Unknown";

static void update_payload_names(rtpstream_info_t *stream_info, const struct _rtp_info *rtpinfo)
{
    GString *payload_type_names;
    const gchar *new_payload_type_str;

    /* Ensure that we have non empty payload_type_str */
    if (rtpinfo->info_payload_type_str != NULL) {
        new_payload_type_str = rtpinfo->info_payload_type_str;
    }
    else {
        /* String is created from const strings only */
        new_payload_type_str = val_to_str_ext_const(rtpinfo->info_payload_type,
            &rtp_payload_type_short_vals_ext,
            PAYLOAD_UNKNOWN_STR
        );
    }
    stream_info->payload_type_names[rtpinfo->info_payload_type] = new_payload_type_str;

    /* Join all existing payload names to one string */
    payload_type_names = g_string_sized_new(40); /* Preallocate memory */
    for(int i=0; i<256; i++) {
        if (stream_info->payload_type_names[i] != NULL) {
            if (payload_type_names->len > 0) {
                g_string_append(payload_type_names, ", ");
            }
            g_string_append(payload_type_names, stream_info->payload_type_names[i]);
        }
    }
    if (stream_info->all_payload_type_names != NULL) {
        g_free(stream_info->all_payload_type_names);
    }
    stream_info->all_payload_type_names = payload_type_names->str;
    g_string_free(payload_type_names, FALSE);
}

gboolean rtpstream_is_payload_used(const rtpstream_info_t *stream_info, const guint8 payload_type)
{
    return stream_info->payload_type_names[payload_type] != NULL;
}

#define RTPFILE_VERSION "1.0"

/*
* Write a header to the current output file.
* The header consists of an identifying string, followed
* by a binary structure.
*/
void rtp_write_header(rtpstream_info_t *strinfo, FILE *file)
{
    guint32 start_sec;     /* start of recording (GMT) (seconds) */
    guint32 start_usec;    /* start of recording (GMT) (microseconds)*/
    guint32 source;        /* network source (multicast address) */
    size_t sourcelen;
    guint16 port;          /* UDP port */
    guint16 padding;       /* 2 padding bytes */
    char* addr_str = address_to_display(NULL, &(strinfo->id.dst_addr));

    fprintf(file, "#!rtpplay%s %s/%u\n", RTPFILE_VERSION,
            addr_str,
            strinfo->id.dst_port);
    wmem_free(NULL, addr_str);

    start_sec = g_htonl(strinfo->start_fd->abs_ts.secs);
    start_usec = g_htonl(strinfo->start_fd->abs_ts.nsecs / 1000);
    /* rtpdump only accepts guint32 as source, will be fake for IPv6 */
    memset(&source, 0, sizeof source);
    sourcelen = strinfo->id.src_addr.len;
    if (sourcelen > sizeof source)
        sourcelen = sizeof source;
    memcpy(&source, strinfo->id.src_addr.data, sourcelen);
    port = g_htons(strinfo->id.src_port);
    padding = 0;

    if (fwrite(&start_sec, 4, 1, file) == 0)
        return;
    if (fwrite(&start_usec, 4, 1, file) == 0)
        return;
    if (fwrite(&source, 4, 1, file) == 0)
        return;
    if (fwrite(&port, 2, 1, file) == 0)
        return;
    if (fwrite(&padding, 2, 1, file) == 0)
        return;
}

/* utility function for writing a sample to file in rtpdump -F dump format (.rtp)*/
static void rtp_write_sample(rtpdump_info_t* rtpdump_info, FILE* file)
{
    guint16 length;    /* length of packet, including this header (may
                          be smaller than plen if not whole packet recorded) */
    guint16 plen;      /* actual header+payload length for RTP, 0 for RTCP */
    guint32 offset;    /* milliseconds since the start of recording */

    length = g_htons(rtpdump_info->num_samples + 8);
    plen = g_htons(rtpdump_info->num_samples);
    offset = g_htonl(rtpdump_info->rec_time);

    if (fwrite(&length, 2, 1, file) == 0)
        return;
    if (fwrite(&plen, 2, 1, file) == 0)
        return;
    if (fwrite(&offset, 4, 1, file) == 0)
        return;
    if (fwrite(rtpdump_info->samples, rtpdump_info->num_samples, 1, file) == 0)
        return;
}


/****************************************************************************/
/* whenever a RTP packet is seen by the tap listener */
tap_packet_status rtpstream_packet_cb(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *arg2, tap_flags_t flags _U_)
{
    rtpstream_tapinfo_t *tapinfo = (rtpstream_tapinfo_t *)arg;
    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)arg2;
    rtpstream_id_t new_stream_id;
    rtpstream_info_t *stream_info = NULL;
    rtpdump_info_t rtpdump_info;

    /* gather infos on the stream this packet is part of.
     * Addresses and strings are read-only and must be duplicated if copied. */
    rtpstream_id_copy_pinfo(pinfo,&new_stream_id,FALSE);
    new_stream_id.ssrc = rtpinfo->info_sync_src;

    if (tapinfo->mode == TAP_ANALYSE) {
        /* if display filtering activated and packet do not match, ignore it */
        if (tapinfo->apply_display_filter && (pinfo->fd->passed_dfilter == 0)) {
            return TAP_PACKET_DONT_REDRAW;
        }

        /* check whether we already have a stream with these parameters in the list */
        if (tapinfo->strinfo_hash) {
            stream_info = rtpstream_info_multihash_lookup(tapinfo->strinfo_hash, &new_stream_id);
        }

        /* not in the list? then create a new entry */
        if (!stream_info) {
            /* init info and collect id */
            stream_info = rtpstream_info_malloc_and_init();
            rtpstream_id_copy_pinfo(pinfo,&(stream_info->id),FALSE);
            stream_info->id.ssrc = rtpinfo->info_sync_src;

            /* init counters for first packet */
            rtpstream_info_analyse_init(stream_info, pinfo, rtpinfo);

            /* add it to hash */
            tapinfo->strinfo_list = g_list_prepend(tapinfo->strinfo_list, stream_info);
            if (!tapinfo->strinfo_hash) {
                tapinfo->strinfo_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
            }
            rtpstream_info_multihash_insert(tapinfo->strinfo_hash, stream_info);
        }

        /* update analysis counters */
        rtpstream_info_analyse_process(stream_info, pinfo, rtpinfo);

        /* increment the packets counter of all streams */
        ++(tapinfo->npackets);

        return TAP_PACKET_REDRAW;  /* refresh output */
    }
    else if (tapinfo->mode == TAP_SAVE) {
        if (rtpstream_id_equal(&new_stream_id, &(tapinfo->filter_stream_fwd->id), RTPSTREAM_ID_EQUAL_SSRC)) {
            /* XXX - what if rtpinfo->info_all_data_present is
               FALSE, so that we don't *have* all the data? */
            rtpdump_info.rec_time = nstime_to_msec(&pinfo->abs_ts) -
                nstime_to_msec(&tapinfo->filter_stream_fwd->start_fd->abs_ts);
            rtpdump_info.num_samples = rtpinfo->info_data_len;
            rtpdump_info.samples = rtpinfo->info_data;
            rtp_write_sample(&rtpdump_info, tapinfo->save_file);
        }
    }
    else if (tapinfo->mode == TAP_MARK && tapinfo->tap_mark_packet) {
        if (rtpstream_id_equal(&new_stream_id, &(tapinfo->filter_stream_fwd->id), RTPSTREAM_ID_EQUAL_SSRC)
                || rtpstream_id_equal(&new_stream_id, &(tapinfo->filter_stream_rev->id), RTPSTREAM_ID_EQUAL_SSRC))
        {
            tapinfo->tap_mark_packet(tapinfo, pinfo->fd);
        }
    }
    return TAP_PACKET_DONT_REDRAW;
}

/****************************************************************************/
/* evaluate rtpstream_info_t calculations */
/* - code is gathered from existing GTK/Qt/tui sources related to RTP statistics calculation
 * - one place for calculations ensures that all wireshark tools shows same output for same input and avoids code duplication
 */
void rtpstream_info_calculate(const rtpstream_info_t *strinfo, rtpstream_info_calc_t *calc)
{
        double sumt;
        double sumTS;
        double sumt2;
        double sumtTS;
        double clock_drift_x;
        guint32 clock_rate_x;
        double duration_x;

        calc->src_addr_str = address_to_display(NULL, &(strinfo->id.src_addr));
        calc->src_port = strinfo->id.src_port;
        calc->dst_addr_str = address_to_display(NULL, &(strinfo->id.dst_addr));
        calc->dst_port = strinfo->id.dst_port;
        calc->ssrc = strinfo->id.ssrc;

        calc->all_payload_type_names = wmem_strdup(NULL, strinfo->all_payload_type_names);

        calc->packet_count = strinfo->packet_count;
        /* packet count, lost packets */
        calc->packet_expected = (strinfo->rtp_stats.stop_seq_nr + strinfo->rtp_stats.seq_cycles*0x10000)
            - strinfo->rtp_stats.start_seq_nr + 1;
        calc->total_nr = strinfo->rtp_stats.total_nr;
        calc->lost_num = calc->packet_expected - strinfo->rtp_stats.total_nr;
        if (calc->packet_expected) {
                calc->lost_perc = (double)(calc->lost_num*100)/(double)calc->packet_expected;
        } else {
                calc->lost_perc = 0;
        }

        calc->max_delta = strinfo->rtp_stats.max_delta;
        calc->min_delta = strinfo->rtp_stats.min_delta;
        calc->mean_delta = strinfo->rtp_stats.mean_delta;
        calc->min_jitter = strinfo->rtp_stats.min_jitter;
        calc->max_jitter = strinfo->rtp_stats.max_jitter;
        calc->mean_jitter = strinfo->rtp_stats.mean_jitter;
        calc->max_skew = strinfo->rtp_stats.max_skew;
        calc->problem = strinfo->problem;
        sumt = strinfo->rtp_stats.sumt;
        sumTS = strinfo->rtp_stats.sumTS;
        sumt2 = strinfo->rtp_stats.sumt2;
        sumtTS = strinfo->rtp_stats.sumtTS;
        duration_x = strinfo->rtp_stats.time - strinfo->rtp_stats.start_time;

        if ((calc->packet_count >0) && (sumt2 > 0)) {
                clock_drift_x = (calc->packet_count * sumtTS - sumt * sumTS) / (calc->packet_count * sumt2 - sumt * sumt);
                calc->clock_drift_ms = duration_x * (clock_drift_x - 1.0);
                clock_rate_x = (guint32)(strinfo->rtp_stats.clock_rate * clock_drift_x);
                calc->freq_drift_hz = clock_drift_x * clock_rate_x;
                calc->freq_drift_perc = 100.0 * (clock_drift_x - 1.0);
        } else {
                calc->clock_drift_ms = 0.0;
                calc->freq_drift_hz = 0.0;
                calc->freq_drift_perc = 0.0;
        }
        calc->duration_ms = duration_x / 1000.0;
        calc->sequence_err = strinfo->rtp_stats.sequence;
        calc->start_time_ms = strinfo->rtp_stats.start_time / 1000.0;
        calc->first_packet_num = strinfo->rtp_stats.first_packet_num;
        calc->last_packet_num = strinfo->rtp_stats.max_nr;
}

/****************************************************************************/
/* free rtpstream_info_calc_t structure (internal items) */
void rtpstream_info_calc_free(rtpstream_info_calc_t *calc)
{
        wmem_free(NULL, calc->src_addr_str);
        wmem_free(NULL, calc->dst_addr_str);
        wmem_free(NULL, calc->all_payload_type_names);
}

/****************************************************************************/
/* Init analyse counters in rtpstream_info_t from pinfo */
void rtpstream_info_analyse_init(rtpstream_info_t *stream_info, const packet_info *pinfo, const struct _rtp_info *rtpinfo)
{
    struct _rtp_conversation_info *p_conv_data = NULL;

    /* reset stream stats */
    stream_info->first_payload_type = rtpinfo->info_payload_type;
    stream_info->first_payload_type_name = rtpinfo->info_payload_type_str;
    stream_info->start_fd = pinfo->fd;
    stream_info->start_rel_time = pinfo->rel_ts;
    stream_info->start_abs_time = pinfo->abs_ts;

    /* reset RTP stats */
    stream_info->rtp_stats.first_packet = TRUE;
    stream_info->rtp_stats.reg_pt = PT_UNDEFINED;

    /* Get the Setup frame number who set this RTP stream */
    p_conv_data = (struct _rtp_conversation_info *)p_get_proto_data(wmem_file_scope(), (packet_info *)pinfo, proto_get_id_by_filter_name("rtp"), 0);
    if (p_conv_data)
        stream_info->setup_frame_number = p_conv_data->frame_number;
    else
        stream_info->setup_frame_number = 0xFFFFFFFF;
}

/****************************************************************************/
/* Update analyse counters in rtpstream_info_t from pinfo */
void rtpstream_info_analyse_process(rtpstream_info_t *stream_info, const packet_info *pinfo, const struct _rtp_info *rtpinfo)
{
    /* get RTP stats for the packet */
    rtppacket_analyse(&(stream_info->rtp_stats), pinfo, rtpinfo);
    if (stream_info->payload_type_names[rtpinfo->info_payload_type] == NULL ) {
        update_payload_names(stream_info, rtpinfo);
    }

    if (stream_info->rtp_stats.flags & STAT_FLAG_WRONG_TIMESTAMP
            || stream_info->rtp_stats.flags & STAT_FLAG_WRONG_SEQ)
        stream_info->problem = TRUE;

    /* increment the packets counter for this stream */
    ++(stream_info->packet_count);
    stream_info->stop_rel_time = pinfo->rel_ts;
}

/****************************************************************************/
/* Get hash for rtpstream_info_t */
guint rtpstream_to_hash(gconstpointer key)
{
    if (key) {
        return rtpstream_id_to_hash(&((rtpstream_info_t *)key)->id);
    } else {
        return 0;
    }
}

/****************************************************************************/
/* Inserts new_stream_info to multihash if its not there */

void rtpstream_info_multihash_insert(GHashTable *multihash, rtpstream_info_t *new_stream_info)
{
    GList *hlist = (GList *)g_hash_table_lookup(multihash, GINT_TO_POINTER(rtpstream_to_hash(new_stream_info)));
    gboolean found = FALSE;
    if (hlist) {
        // Key exists in hash
        GList *list = g_list_first(hlist);
        while (list)
        {
            if (rtpstream_id_equal(&(new_stream_info->id), &((rtpstream_info_t *)(list->data))->id, RTPSTREAM_ID_EQUAL_SSRC)) {
                found = TRUE;
                break;
            }
            list = g_list_next(list);
        }
        if (!found) {
            // stream_info is not in list yet, add it
            hlist = g_list_prepend(hlist, new_stream_info);
        }
    } else {
        // No key in hash, init new list
        hlist = g_list_prepend(hlist, new_stream_info);
    }
    g_hash_table_insert(multihash, GINT_TO_POINTER(rtpstream_to_hash(new_stream_info)), hlist);
}

/****************************************************************************/
/* Lookup stream_info in multihash */

rtpstream_info_t *rtpstream_info_multihash_lookup(GHashTable *multihash, rtpstream_id_t *stream_id)
{
    GList *hlist = (GList *)g_hash_table_lookup(multihash, GINT_TO_POINTER(rtpstream_to_hash(stream_id)));
    if (hlist) {
        // Key exists in hash
        GList *list = g_list_first(hlist);
        while (list)
        {
            if (rtpstream_id_equal(stream_id, &((rtpstream_info_t *)(list->data))->id, RTPSTREAM_ID_EQUAL_SSRC)) {
                return (rtpstream_info_t *)(list->data);
            }
            list = g_list_next(list);
        }
    }

    // No stream_info in hash or was not found in existing list
    return NULL;
}

/****************************************************************************/
/* Destroys GList used in multihash */

void rtpstream_info_multihash_destroy_value(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    g_list_free((GList *)value);
}
