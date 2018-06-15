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

#include <glib.h>

#include <math.h>

#include <string.h>
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
/* GCompareFunc style comparison function for rtp_stream_info_t */
gint rtpstream_info_cmp(gconstpointer aa, gconstpointer bb)
{
    const rtpstream_info_t* a = (const rtpstream_info_t*)aa;
    const rtpstream_info_t* b = (const rtpstream_info_t*)bb;

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

    if (tapinfo->mode == TAP_ANALYSE) {
        /* free the data items first */
        list = g_list_first(tapinfo->strinfo_list);
        while (list)
        {
            g_free(list->data);
            /* TODO free src_addr, dest_addr and payload_type_name? */
            list = g_list_next(list);
        }
        g_list_free(tapinfo->strinfo_list);
        tapinfo->strinfo_list = NULL;
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
    start_usec = g_htonl(strinfo->start_fd->abs_ts.nsecs / 1000000);
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
int rtpstream_packet_cb(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *arg2)
{
    rtpstream_tapinfo_t *tapinfo = (rtpstream_tapinfo_t *)arg;
    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)arg2;
    rtpstream_info_t new_stream_info;
    rtpstream_info_t *stream_info = NULL;
    GList* list;
    rtpdump_info_t rtpdump_info;

    struct _rtp_conversation_info *p_conv_data = NULL;

    /* gather infos on the stream this packet is part of.
     * Addresses and strings are read-only and must be duplicated if copied. */
    memset(&new_stream_info, 0, sizeof(rtpstream_info_t));
    rtpstream_id_copy_pinfo(pinfo,&(new_stream_info.id),FALSE);
    new_stream_info.id.ssrc = rtpinfo->info_sync_src;
    new_stream_info.payload_type = rtpinfo->info_payload_type;
    new_stream_info.payload_type_name = (char *)rtpinfo->info_payload_type_str;

    if (tapinfo->mode == TAP_ANALYSE) {
        /* check whether we already have a stream with these parameters in the list */
        list = g_list_first(tapinfo->strinfo_list);
        while (list)
        {
            if (rtpstream_info_cmp(&new_stream_info, (rtpstream_info_t*)(list->data))==0)
            {
                stream_info = (rtpstream_info_t*)(list->data);  /*found!*/
                break;
            }
            list = g_list_next(list);
        }

        /* not in the list? then create a new entry */
        if (!stream_info) {
            new_stream_info.start_fd = pinfo->fd;
            new_stream_info.start_rel_time = pinfo->rel_ts;

            /* reset RTP stats */
            new_stream_info.rtp_stats.first_packet = TRUE;
            new_stream_info.rtp_stats.reg_pt = PT_UNDEFINED;

            /* Get the Setup frame number who set this RTP stream */
            p_conv_data = (struct _rtp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_get_id_by_filter_name("rtp"), 0);
            if (p_conv_data)
                new_stream_info.setup_frame_number = p_conv_data->frame_number;
            else
                new_stream_info.setup_frame_number = 0xFFFFFFFF;

            stream_info = g_new(rtpstream_info_t,1);
            /* Deep clone of contents. */
            copy_address(&(new_stream_info.id.src_addr), &(new_stream_info.id.src_addr));
            copy_address(&(new_stream_info.id.dst_addr), &(new_stream_info.id.dst_addr));
            new_stream_info.payload_type_name = g_strdup(new_stream_info.payload_type_name);
            *stream_info = new_stream_info;  /* memberwise copy of struct */
            tapinfo->strinfo_list = g_list_prepend(tapinfo->strinfo_list, stream_info);
        }

        /* get RTP stats for the packet */
        rtppacket_analyse(&(stream_info->rtp_stats), pinfo, rtpinfo);
        if (stream_info->rtp_stats.flags & STAT_FLAG_WRONG_TIMESTAMP
                || stream_info->rtp_stats.flags & STAT_FLAG_WRONG_SEQ)
            stream_info->problem = TRUE;


        /* increment the packets counter for this stream */
        ++(stream_info->packet_count);
        stream_info->stop_rel_time = pinfo->rel_ts;

        /* increment the packets counter of all streams */
        ++(tapinfo->npackets);

        return 1;  /* refresh output */
    }
    else if (tapinfo->mode == TAP_SAVE) {
        if (rtpstream_info_cmp(&new_stream_info, tapinfo->filter_stream_fwd)==0) {
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
        if (rtpstream_info_cmp(&new_stream_info, tapinfo->filter_stream_fwd)==0
                || rtpstream_info_cmp(&new_stream_info, tapinfo->filter_stream_rev)==0)
        {
            tapinfo->tap_mark_packet(tapinfo, pinfo->fd);
        }
    }
    return 0;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
