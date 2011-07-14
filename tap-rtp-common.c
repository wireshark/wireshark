/* tap-rtp-common.c
 * RTP stream handler functions used by tshark and wireshark
 *
 * $Id$
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from gtk/rtp_stream.c and gtk/rtp_analisys.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <math.h>
#include "globals.h"

#include <epan/tap.h>
#include <string.h>
#include <epan/rtp_pt.h>
#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-rtp.h>
#include "gtk/rtp_stream.h"
#include "tap-rtp-common.h"

/* XXX: are changes needed to properly handle situations where
        info_all_data_present == FALSE ?
        E.G., when captured frames are truncated.
 */

/****************************************************************************/
/* GCompareFunc style comparison function for _rtp_stream_info */
gint rtp_stream_info_cmp(gconstpointer aa, gconstpointer bb)
{
	const struct _rtp_stream_info* a = aa;
	const struct _rtp_stream_info* b = bb;

	if (a==b)
		return 0;
	if (a==NULL || b==NULL)
		return 1;
	if (ADDRESSES_EQUAL(&(a->src_addr), &(b->src_addr))
		&& (a->src_port == b->src_port)
		&& ADDRESSES_EQUAL(&(a->dest_addr), &(b->dest_addr))
		&& (a->dest_port == b->dest_port)
		&& (a->ssrc == b->ssrc))
		return 0;
	else
		return 1;
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
			list = g_list_next(list);
		}
		g_list_free(tapinfo->strinfo_list);
		tapinfo->strinfo_list = NULL;
		tapinfo->nstreams = 0;
		tapinfo->npackets = 0;
	}

	++(tapinfo->launch_count);

	return;
}

void rtpstream_reset_cb(void *arg)
{
	rtpstream_reset(arg);
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
void rtp_write_header(rtp_stream_info_t *strinfo, FILE *file)
{
	guint32 start_sec;     /* start of recording (GMT) (seconds) */
	guint32 start_usec;    /* start of recording (GMT) (microseconds)*/
	guint32 source;        /* network source (multicast address) */
	size_t sourcelen;
	guint16 port;          /* UDP port */
	guint16 padding;       /* 2 padding bytes */

	fprintf(file, "#!rtpplay%s %s/%u\n", RTPFILE_VERSION,
		get_addr_name(&(strinfo->dest_addr)),
		strinfo->dest_port);

	start_sec = g_htonl(strinfo->start_sec);
	start_usec = g_htonl(strinfo->start_usec);
	/* rtpdump only accepts guint32 as source, will be fake for IPv6 */
	memset(&source, 0, sizeof source);
	sourcelen = strinfo->src_addr.len;
	if (sourcelen > sizeof source)
		sourcelen = sizeof source;
	memcpy(&source, strinfo->src_addr.data, sourcelen);
	port = g_htons(strinfo->src_port);
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
void rtp_write_sample(rtp_sample_t* sample, FILE* file)
{
	guint16 length;    /* length of packet, including this header (may
	                     be smaller than plen if not whole packet recorded) */
	guint16 plen;      /* actual header+payload length for RTP, 0 for RTCP */
	guint32 offset;    /* milliseconds since the start of recording */

	length = g_htons(sample->header.frame_length + 8);
	plen = g_htons(sample->header.frame_length);
	offset = g_htonl(sample->header.rec_time);

	if (fwrite(&length, 2, 1, file) == 0)
		return;
	if (fwrite(&plen, 2, 1, file) == 0)
		return;
	if (fwrite(&offset, 4, 1, file) == 0)
		return;
	if (fwrite(sample->frame, sample->header.frame_length, 1, file) == 0)
		return;
}


/****************************************************************************/
/* whenever a RTP packet is seen by the tap listener */
int rtpstream_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *arg2)
{
	rtpstream_tapinfo_t *tapinfo = arg;
	const struct _rtp_info *rtpinfo = arg2;
	rtp_stream_info_t tmp_strinfo;
	rtp_stream_info_t *strinfo = NULL;
	GList* list;
	rtp_sample_t sample;

	struct _rtp_conversation_info *p_conv_data = NULL;

	/* gather infos on the stream this packet is part of */
	COPY_ADDRESS(&(tmp_strinfo.src_addr), &(pinfo->src));
	tmp_strinfo.src_port = pinfo->srcport;
	COPY_ADDRESS(&(tmp_strinfo.dest_addr), &(pinfo->dst));
	tmp_strinfo.dest_port = pinfo->destport;
	tmp_strinfo.ssrc = rtpinfo->info_sync_src;
	tmp_strinfo.pt = rtpinfo->info_payload_type;
	tmp_strinfo.info_payload_type_str = rtpinfo->info_payload_type_str;

	if (tapinfo->mode == TAP_ANALYSE) {
		/* check whether we already have a stream with these parameters in the list */
		list = g_list_first(tapinfo->strinfo_list);
		while (list)
		{
			if (rtp_stream_info_cmp(&tmp_strinfo, (rtp_stream_info_t*)(list->data))==0)
			{
				strinfo = (rtp_stream_info_t*)(list->data);  /*found!*/
				break;
			}
			list = g_list_next(list);
		}

		/* not in the list? then create a new entry */
		if (!strinfo) {
			tmp_strinfo.npackets = 0;
			tmp_strinfo.first_frame_num = pinfo->fd->num;
			tmp_strinfo.start_sec = (guint32) pinfo->fd->abs_ts.secs;
			tmp_strinfo.start_usec = pinfo->fd->abs_ts.nsecs/1000;
			tmp_strinfo.start_rel_sec = (guint32) pinfo->fd->rel_ts.secs;
			tmp_strinfo.start_rel_usec = pinfo->fd->rel_ts.nsecs/1000;
			tmp_strinfo.tag_vlan_error = 0;
			tmp_strinfo.tag_diffserv_error = 0;
			tmp_strinfo.vlan_id = 0;
			tmp_strinfo.problem = FALSE;

			/* reset RTP stats */
			tmp_strinfo.rtp_stats.first_packet = TRUE;
			tmp_strinfo.rtp_stats.max_delta = 0;
			tmp_strinfo.rtp_stats.max_jitter = 0;
			tmp_strinfo.rtp_stats.mean_jitter = 0;
			tmp_strinfo.rtp_stats.delta = 0;
			tmp_strinfo.rtp_stats.diff = 0;
			tmp_strinfo.rtp_stats.jitter = 0;
			tmp_strinfo.rtp_stats.bandwidth = 0;
			tmp_strinfo.rtp_stats.total_bytes = 0;
			tmp_strinfo.rtp_stats.bw_start_index = 0;
			tmp_strinfo.rtp_stats.bw_index = 0;
			tmp_strinfo.rtp_stats.timestamp = 0;
			tmp_strinfo.rtp_stats.max_nr = 0;
			tmp_strinfo.rtp_stats.total_nr = 0;
			tmp_strinfo.rtp_stats.sequence = 0;
			tmp_strinfo.rtp_stats.start_seq_nr = 0;
			tmp_strinfo.rtp_stats.stop_seq_nr = 0;
			tmp_strinfo.rtp_stats.cycles = 0;
			tmp_strinfo.rtp_stats.under = FALSE;
			tmp_strinfo.rtp_stats.start_time = 0;
			tmp_strinfo.rtp_stats.time = 0;
			tmp_strinfo.rtp_stats.reg_pt = PT_UNDEFINED;

            /* Get the Setup frame number who set this RTP stream */
            p_conv_data = p_get_proto_data(pinfo->fd, proto_get_id_by_filter_name("rtp"));
            if (p_conv_data)
				tmp_strinfo.setup_frame_number = p_conv_data->frame_number;
            else
                tmp_strinfo.setup_frame_number = 0xFFFFFFFF;

			strinfo = g_malloc(sizeof(rtp_stream_info_t));
			*strinfo = tmp_strinfo;  /* memberwise copy of struct */
			tapinfo->strinfo_list = g_list_append(tapinfo->strinfo_list, strinfo);
		}

		/* get RTP stats for the packet */
		rtp_packet_analyse(&(strinfo->rtp_stats), pinfo, rtpinfo);
		if (strinfo->rtp_stats.flags & STAT_FLAG_WRONG_TIMESTAMP
			|| strinfo->rtp_stats.flags & STAT_FLAG_WRONG_SEQ)
			strinfo->problem = TRUE;


		/* increment the packets counter for this stream */
		++(strinfo->npackets);
		strinfo->stop_rel_sec = (guint32) pinfo->fd->rel_ts.secs;
		strinfo->stop_rel_usec = pinfo->fd->rel_ts.nsecs/1000;

		/* increment the packets counter of all streams */
		++(tapinfo->npackets);

		return 1;  /* refresh output */
	}
	else if (tapinfo->mode == TAP_SAVE) {
		if (rtp_stream_info_cmp(&tmp_strinfo, tapinfo->filter_stream_fwd)==0) {
			/* XXX - what if rtpinfo->info_all_data_present is
			   FALSE, so that we don't *have* all the data? */
			sample.header.rec_time =
				(pinfo->fd->abs_ts.nsecs/1000 + 1000000 - tapinfo->filter_stream_fwd->start_usec)/1000
				+ (guint32) (pinfo->fd->abs_ts.secs - tapinfo->filter_stream_fwd->start_sec - 1)*1000;
			sample.header.frame_length = rtpinfo->info_data_len;
			sample.frame = rtpinfo->info_data;
			rtp_write_sample(&sample, tapinfo->save_file);
		}
	}
#ifdef __GTK_H__
	else if (tapinfo->mode == TAP_MARK) {
		if (rtp_stream_info_cmp(&tmp_strinfo, tapinfo->filter_stream_fwd)==0
			|| rtp_stream_info_cmp(&tmp_strinfo, tapinfo->filter_stream_rev)==0)
		{
			cf_mark_frame(&cfile, pinfo->fd);
		}
	}
#endif
	return 0;
}


typedef struct _key_value {
  guint32  key;
  guint32  value;
} key_value;


/* RTP sampling clock rates for fixed payload types as defined in
 http://www.iana.org/assignments/rtp-parameters */
static const key_value clock_map[] = {
	{PT_PCMU,       8000},
	{PT_1016,       8000},
	{PT_G721,       8000},
	{PT_GSM,        8000},
	{PT_G723,       8000},
	{PT_DVI4_8000,  8000},
	{PT_DVI4_16000, 16000},
	{PT_LPC,        8000},
	{PT_PCMA,       8000},
	{PT_G722,       8000},
	{PT_L16_STEREO, 44100},
	{PT_L16_MONO,   44100},
	{PT_QCELP,      8000},
	{PT_CN,         8000},
	{PT_MPA,        90000},
	{PT_G728,       8000},
	{PT_G728,       8000},
	{PT_DVI4_11025, 11025},
	{PT_DVI4_22050, 22050},
	{PT_G729,       8000},
	{PT_CN_OLD,     8000},
	{PT_CELB,       90000},
	{PT_JPEG,       90000},
	{PT_NV,         90000},
	{PT_H261,       90000},
	{PT_MPV,        90000},
	{PT_MP2T,       90000},
	{PT_H263,       90000},
};

#define NUM_CLOCK_VALUES	(sizeof clock_map / sizeof clock_map[0])

static guint32
get_clock_rate(guint32 key)
{
	size_t i;

	for (i = 0; i < NUM_CLOCK_VALUES; i++) {
		if (clock_map[i].key == key)
			return clock_map[i].value;
	}
	return 0;
}

typedef struct _mimetype_and_clock {
	const gchar   *pt_mime_name_str;
	guint32 value;
} mimetype_and_clock;
/*	RTP sampling clock rates for
	"In addition to the RTP payload formats (encodings) listed in the RTP
	Payload Types table, there are additional payload formats that do not
	have static RTP payload types assigned but instead use dynamic payload
	type number assignment.  Each payload format is named by a registered
	MIME subtype"
	http://www.iana.org/assignments/rtp-parameters.

	NOTE: Please keep the mimetypes in case insensitive alphabetical order.
*/
static const mimetype_and_clock mimetype_and_clock_map[] = {
	{"AMR",		8000},			/* [RFC4867][RFC3267] */
	{"AMR-WB",	16000},			/* [RFC4867][RFC3267] */
	{"BMPEG",	90000},			/* [RFC2343],[RFC3555] */
	{"BT656",	90000},			/* [RFC2431],[RFC3555] */
	{"DV",		90000},			/* [RFC3189] */
	{"EVRC",	8000},			/* [RFC3558] */
	{"EVRC0",	8000},			/* [RFC4788] */
	{"EVRC1",	8000},			/* [RFC4788] */
	{"EVRCB",	8000},			/* [RFC4788] */
	{"EVRCB0",	8000},			/* [RFC4788] */
	{"EVRCB1",	8000},			/* [RFC4788] */
	{"EVRCWB",	16000},			/* [RFC5188] */
	{"EVRCWB0",	16000},			/* [RFC5188] */
	{"EVRCWB1",	16000},			/* [RFC5188] */
	{"G7221",	16000},			/* [RFC3047] */
	{"G726-16",	8000},			/* [RFC3551][RFC4856] */
	{"G726-24",	8000},			/* [RFC3551][RFC4856] */
	{"G726-32",	8000},			/* [RFC3551][RFC4856] */
	{"G726-40",	8000},			/* [RFC3551][RFC4856] */
	{"G729D",	8000},			/* [RFC3551][RFC4856] */
	{"G729E",	8000},			/* [RFC3551][RFC4856] */
	{"GSM-EFR",	8000},			/* [RFC3551] */
	{"H263-1998",	90000},		/* [RFC2429],[RFC3555] */
	{"H263-2000",	90000},		/* [RFC2429],[RFC3555] */
	{"H264",	90000},         /* [RFC3984] */
	{"MP1S",	90000},			/* [RFC2250],[RFC3555] */
	{"MP2P",	90000},			/* [RFC2250],[RFC3555] */
	{"MP4V-ES",	90000},			/* [RFC3016] */
	{"mpa-robust",	90000},		/* [RFC3119] */
	{"pointer",	90000},			/* [RFC2862] */
	{"raw",		90000},			/* [RFC4175] */
	{"red",		1000},			/* [RFC4102] */
	{"SMV",		8000},			/* [RFC3558] */
	{"SMV0",	8000},			/* [RFC3558] */
	{"t140",	1000},			/* [RFC4103] */
	{"telephone-event", 8000},  /* [RFC4733] */
};

#define NUM_DYN_CLOCK_VALUES	(sizeof mimetype_and_clock_map / sizeof mimetype_and_clock_map[0])

static guint32
get_dyn_pt_clock_rate(gchar *payload_type_str)
{
	int i;

	/* Search for matching mimetype in reverse order to avoid false matches
	 * when pt_mime_name_str is the prefix of payload_type_str */
	for (i = NUM_DYN_CLOCK_VALUES - 1; i > -1 ; i--) {
		if (g_ascii_strncasecmp(mimetype_and_clock_map[i].pt_mime_name_str,payload_type_str,(strlen(mimetype_and_clock_map[i].pt_mime_name_str))) == 0)
			return mimetype_and_clock_map[i].value;
	}

	return 0;
}

/****************************************************************************/
int rtp_packet_analyse(tap_rtp_stat_t *statinfo,
                              packet_info *pinfo,
                              const struct _rtp_info *rtpinfo)
{
	double current_time;
	double current_jitter;
	double current_diff = 0;
	double nominaltime;
	double arrivaltime;		/* Time relative to start_time */
	double expected_time;
	double absskew;
	guint32 clock_rate;

	/* Store the current time */
	current_time = nstime_to_msec(&pinfo->fd->rel_ts);

	/*  Is this the first packet we got in this direction? */
	if (statinfo->first_packet) {
		statinfo->start_seq_nr = rtpinfo->info_seq_num;
		statinfo->stop_seq_nr = rtpinfo->info_seq_num;
		statinfo->seq_num = rtpinfo->info_seq_num;
		statinfo->start_time = current_time;
		statinfo->timestamp = rtpinfo->info_timestamp;
		statinfo->first_timestamp = rtpinfo->info_timestamp;
		statinfo->time = current_time;
		statinfo->lastnominaltime = 0;
		statinfo->pt = rtpinfo->info_payload_type;
		statinfo->reg_pt = rtpinfo->info_payload_type;
		statinfo->bw_history[statinfo->bw_index].bytes = rtpinfo->info_data_len + 28;
		statinfo->bw_history[statinfo->bw_index].time = current_time;
		statinfo->bw_index++;
		statinfo->total_bytes += rtpinfo->info_data_len + 28;
		statinfo->bandwidth = (double)(statinfo->total_bytes*8)/1000;
		/* Not needed ? initialised to zero? */
		statinfo->delta = 0;
		statinfo->jitter = 0;
		statinfo->diff = 0;

		statinfo->total_nr++;
		statinfo->flags |= STAT_FLAG_FIRST;
		if (rtpinfo->info_marker_set) {
			statinfo->flags |= STAT_FLAG_MARKER;
		}
		statinfo->first_packet = FALSE;
		return 0;
	}

	/* Reset flags */
	statinfo->flags = 0;

	/* When calculating expected rtp packets the seq number can wrap around
	 * so we have to count the number of cycles
	 * Variable cycles counts the wraps around in forwarding connection and
	 * under is flag that indicates where we are
	 *
	 * XXX How to determine number of cycles with all possible lost, late
	 * and duplicated packets without any doubt? It seems to me, that
	 * because of all possible combination of late, duplicated or lost
	 * packets, this can only be more or less good approximation
	 *
	 * There are some combinations (rare but theoretically possible),
	 * where below code won't work correctly - statistic may be wrong then.
	 */

	/* So if the current sequence number is less than the start one
	 * we assume, that there is another cycle running
	 */
	if ((rtpinfo->info_seq_num < statinfo->start_seq_nr) && (statinfo->under == FALSE)){
		statinfo->cycles++;
		statinfo->under = TRUE;
	}
	/* what if the start seq nr was 0? Then the above condition will never
	 * be true, so we add another condition. XXX The problem would arise
	 * if one of the packets with seq nr 0 or 65535 would be lost or late
	 */
	else if ((rtpinfo->info_seq_num == 0) && (statinfo->stop_seq_nr == 65535) &&
		(statinfo->under == FALSE)){
		statinfo->cycles++;
		statinfo->under = TRUE;
	}
	/* the whole round is over, so reset the flag */
	else if ((rtpinfo->info_seq_num > statinfo->start_seq_nr) && (statinfo->under != FALSE)) {
		statinfo->under = FALSE;
	}

	/* Since it is difficult to count lost, duplicate or late packets separately,
	 * we would like to know at least how many times the sequence number was not ok
	 */

	/* If the current seq number equals the last one or if we are here for
	 * the first time, then it is ok, we just store the current one as the last one
	 */
	if ( (statinfo->seq_num+1 == rtpinfo->info_seq_num) || (statinfo->flags & STAT_FLAG_FIRST) )
		statinfo->seq_num = rtpinfo->info_seq_num;
	/* If the first one is 65535. XXX same problem as above: if seq 65535 or 0 is lost... */
	else if ( (statinfo->seq_num == 65535) && (rtpinfo->info_seq_num == 0) )
		statinfo->seq_num = rtpinfo->info_seq_num;
	/* Lost packets */
	else if (statinfo->seq_num+1 < rtpinfo->info_seq_num) {
		statinfo->seq_num = rtpinfo->info_seq_num;
		statinfo->sequence++;
		statinfo->flags |= STAT_FLAG_WRONG_SEQ;
	}
	/* Late or duplicated */
	else if (statinfo->seq_num+1 > rtpinfo->info_seq_num) {
		statinfo->sequence++;
		statinfo->flags |= STAT_FLAG_WRONG_SEQ;
	}

	/* Check payload type */
	if (rtpinfo->info_payload_type == PT_CN
		|| rtpinfo->info_payload_type == PT_CN_OLD)
		statinfo->flags |= STAT_FLAG_PT_CN;
	if (statinfo->pt == PT_CN
		|| statinfo->pt == PT_CN_OLD)
		statinfo->flags |= STAT_FLAG_FOLLOW_PT_CN;
	if (rtpinfo->info_payload_type != statinfo->pt)
		statinfo->flags |= STAT_FLAG_PT_CHANGE;
	statinfo->pt = rtpinfo->info_payload_type;

	/*
	 * Return 0 for unknown payload types
	 * Ignore jitter calculation for clockrate = 0
	 */
	if (statinfo->pt < 96 ){
		clock_rate = get_clock_rate(statinfo->pt);
	}else{ /* Dynamic PT */
		if ( rtpinfo->info_payload_type_str != NULL ){
			/* Is it a "telephone-event" ?
			 * Timestamp is not increased for telepone-event packets impacting
			 * calculation of Jitter Skew and clock drift.
			 * see 2.2.1 of RFC 4733
			 */
			if (g_ascii_strncasecmp("telephone-event",rtpinfo->info_payload_type_str,(strlen("telephone-event")))==0){
				clock_rate = 0;
				statinfo->flags |= STAT_FLAG_PT_T_EVENT;
			}else{
				if(rtpinfo->info_payload_rate !=0){
					clock_rate = rtpinfo->info_payload_rate;
				}else{
					clock_rate = get_dyn_pt_clock_rate(rtpinfo-> info_payload_type_str);
				}
			}
		}else{
			clock_rate = 0;
		}
	}

		/* Handle wraparound ? */
	arrivaltime = current_time - statinfo->start_time;

	if (statinfo->first_timestamp > rtpinfo->info_timestamp){
		/* Handle wraparound */
		nominaltime = (double)(rtpinfo->info_timestamp + 0xffffffff - statinfo->first_timestamp + 1);
	}else{
		nominaltime = (double)(rtpinfo->info_timestamp - statinfo->first_timestamp);
	}

	/* Can only analyze defined sampling rates */
    if (clock_rate != 0) {
		statinfo->clock_rate = clock_rate;
		/* Convert from sampling clock to ms */
		nominaltime = nominaltime /(clock_rate/1000);

		/* Calculate the current jitter(in ms) */
		if (!statinfo->first_packet) {
			expected_time = statinfo->time + (nominaltime - statinfo->lastnominaltime);
			current_diff = fabs(current_time - expected_time);
			current_jitter = (15 * statinfo->jitter + current_diff) / 16;

			statinfo->delta = current_time-(statinfo->time);
			statinfo->jitter = current_jitter;
			statinfo->diff = current_diff;
		}
		statinfo->lastnominaltime = nominaltime;
		/* Calculate skew, i.e. absolute jitter that also catches clock drift
		 * Skew is positive if TS (nominal) is too fast
		 */
		statinfo->skew    = nominaltime - arrivaltime;
		absskew = fabs(statinfo->skew);
		if(absskew > fabs(statinfo->max_skew)){
			statinfo->max_skew = statinfo->skew;
		}
		/* Gather data for calculation of average, minimum and maximum framerate based on timestamp */
#if 0
		if (numPackets > 0 && (!hardPayloadType || !alternatePayloadType)) {
			/* Skip first packet and possibly alternate payload type packets */
			double dt;
			dt     = nominaltime - statinfo->lastnominaltime;
			sumdt += 1.0 * dt;
			numdt += (dt != 0 ? 1 : 0);
			mindt  = (dt < mindt ? dt : mindt);
			maxdt  = (dt > maxdt ? dt : maxdt);
		}
#endif
		/* Gather data for calculation of skew least square */
		statinfo->sumt   += 1.0 * current_time;
		statinfo->sumTS  += 1.0 * nominaltime;
		statinfo->sumt2  += 1.0 * current_time * current_time;
		statinfo->sumtTS += 1.0 * current_time * nominaltime;
	}

	/* Calculate the BW in Kbps adding the IP+UDP header to the RTP -> 20bytes(IP)+8bytes(UDP) = 28bytes */
	statinfo->bw_history[statinfo->bw_index].bytes = rtpinfo->info_data_len + 28;
	statinfo->bw_history[statinfo->bw_index].time = current_time;

	/* Check if there are more than 1sec in the history buffer to calculate BW in bps. If so, remove those for the calculation */
	while ((statinfo->bw_history[statinfo->bw_start_index].time+1000/* ms */)<current_time){
	 	statinfo->total_bytes -= statinfo->bw_history[statinfo->bw_start_index].bytes;
		statinfo->bw_start_index++;
		if (statinfo->bw_start_index == BUFF_BW) statinfo->bw_start_index=0;
	};
	statinfo->total_bytes += rtpinfo->info_data_len + 28;
	statinfo->bandwidth = (double)(statinfo->total_bytes*8)/1000;
	statinfo->bw_index++;
	if (statinfo->bw_index == BUFF_BW) statinfo->bw_index = 0;


	/* Is it a packet with the mark bit set? */
	if (rtpinfo->info_marker_set) {
		statinfo->delta_timestamp = rtpinfo->info_timestamp - statinfo->timestamp;
		if (rtpinfo->info_timestamp > statinfo->timestamp){
			statinfo->flags |= STAT_FLAG_MARKER;
		}
		else{
			statinfo->flags |= STAT_FLAG_WRONG_TIMESTAMP;
		}
	}
	/* Is it a regular packet? */
	if (!(statinfo->flags & STAT_FLAG_FIRST)
		&& !(statinfo->flags & STAT_FLAG_MARKER)
		&& !(statinfo->flags & STAT_FLAG_PT_CN)
		&& !(statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP)
		&& !(statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)) {
		/* Include it in maximum delta calculation */
		if (statinfo->delta > statinfo->max_delta) {
			statinfo->max_delta = statinfo->delta;
			statinfo->max_nr = pinfo->fd->num;
		}
		if (clock_rate != 0) {
			/* Maximum and mean jitter calculation */
			if (statinfo->jitter > statinfo->max_jitter) {
				statinfo->max_jitter = statinfo->jitter;
			}
			statinfo->mean_jitter = (statinfo->mean_jitter*statinfo->total_nr + current_diff) / (statinfo->total_nr+1);
		}
	}
	/* Regular payload change? (CN ignored) */
	if (!(statinfo->flags & STAT_FLAG_FIRST)
		&& !(statinfo->flags & STAT_FLAG_PT_CN)) {
		if ((statinfo->pt != statinfo->reg_pt)
			&& (statinfo->reg_pt != PT_UNDEFINED)) {
			statinfo->flags |= STAT_FLAG_REG_PT_CHANGE;
		}
	}

	/* Set regular payload*/
	if (!(statinfo->flags & STAT_FLAG_PT_CN)) {
		statinfo->reg_pt = statinfo->pt;
	}

	statinfo->time = current_time;
	statinfo->timestamp = rtpinfo->info_timestamp;
	statinfo->stop_seq_nr = rtpinfo->info_seq_num;
	statinfo->total_nr++;

	return 0;
}


