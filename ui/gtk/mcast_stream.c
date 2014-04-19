/* mcast_stream.c
 *
 * Copyright 2006, Iskratel , Slovenia
 * By Jakob Bratkovic <j.bratkovic@iskratel.si> and
 * Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream.c
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <gtk/gtk.h>

#include <epan/epan.h>
#include <epan/address.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/to_str.h>

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/mcast_stream.h"
#include "ui/gtk/mcast_stream_dlg.h"
#include "ui/gtk/main.h"
#include "ui/gtk/stock_icons.h"

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

gint32  mcast_stream_trigger         =     50; /* limit for triggering the burst alarm (in packets per second) */
gint32  mcast_stream_bufferalarm     =  10000; /* limit for triggernig the buffer alarm (in bytes) */
guint16 mcast_stream_burstint        =    100; /* burst interval in ms */
gint32  mcast_stream_emptyspeed      =   5000; /* outgoing speed for single stream (kbps)*/
gint32  mcast_stream_cumulemptyspeed = 100000; /* outgoiong speed for all streams (kbps)*/

/* sliding window and buffer usage */
static gint32  buffsize = (int)((double)MAX_SPEED * 100 / 1000) * 2;
static guint16 comparetimes(struct timeval *t1, struct timeval *t2, guint16 burstint_lcl);
static void    buffusagecalc(mcast_stream_info_t *strinfo, packet_info *pinfo, double emptyspeed_lcl);
static void    slidingwindow(mcast_stream_info_t *strinfo, packet_info *pinfo);


/****************************************************************************/
/* the one and only global mcaststream_tapinfo_t structure */
static mcaststream_tapinfo_t the_tapinfo_struct =
	{0, NULL, 0, NULL, 0, FALSE};


/****************************************************************************/
/* GCompareFunc style comparison function for _mcast_stream_info */
static gint
mcast_stream_info_cmp(gconstpointer aa, gconstpointer bb)
{
	const struct _mcast_stream_info* a = (const struct _mcast_stream_info *)aa;
	const struct _mcast_stream_info* b = (const struct _mcast_stream_info *)bb;

        if (a==b)
                return 0;
        if (a==NULL || b==NULL)
                return 1;
        if (ADDRESSES_EQUAL(&(a->src_addr), &(b->src_addr))
                && (a->src_port == b->src_port)
                && ADDRESSES_EQUAL(&(a->dest_addr), &(b->dest_addr))
                && (a->dest_port == b->dest_port))
                return 0;
        else
                return 1;

}


/****************************************************************************/
/* when there is a [re]reading of packet's */
void
mcaststream_reset(mcaststream_tapinfo_t *tapinfo)
{
	GList* list;

	/* free the data items first */
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		/* XYZ I don't know how to clean this */
		/*g_free(list->element.buff); */
		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapinfo->strinfo_list);
	tapinfo->strinfo_list = NULL;

	/* XYZ and why does the line below causes a crach? */
	/*g_free(tapinfo->allstreams->element.buff);*/
	g_free(tapinfo->allstreams);
	tapinfo->allstreams = NULL;

	tapinfo->nstreams = 0;
	tapinfo->npackets = 0;

	++(tapinfo->launch_count);

	return;
}

static void
mcaststream_reset_cb(void *arg)
{
	mcaststream_reset((mcaststream_tapinfo_t *)arg);
}

/****************************************************************************/
/* redraw the output */
static void
mcaststream_draw(void *arg _U_)
{
/* XXX: see mcaststream_on_update in mcast_streams_dlg.c for comments
	g_signal_emit_by_name(top_level, "signal_mcaststream_update");
*/
	mcaststream_dlg_update(the_tapinfo_struct.strinfo_list);
	return;
}



/****************************************************************************/
/* whenever a udp packet is seen by the tap listener */
static int
mcaststream_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *arg2 _U_)
{
	mcaststream_tapinfo_t *tapinfo = (mcaststream_tapinfo_t *)arg;
        mcast_stream_info_t tmp_strinfo;
        mcast_stream_info_t *strinfo = NULL;
        GList* list;
	float deltatime;

        /* gather infos on the stream this packet is part of */
        COPY_ADDRESS(&(tmp_strinfo.src_addr), &(pinfo->src));
        tmp_strinfo.src_port = pinfo->srcport;
        COPY_ADDRESS(&(tmp_strinfo.dest_addr), &(pinfo->dst));
        tmp_strinfo.dest_port = pinfo->destport;

	/* first we ignore non multicast packets; we filter out only those ethernet packets
	 * which start with the 01:00:5E multicast address (for IPv4) and 33:33 multicast
	 * address (for IPv6).
	 */
	if ((pinfo->dl_dst.type != AT_ETHER) ||
	    ((g_ascii_strncasecmp("01005E", bytes_to_ep_str((const guint8 *)pinfo->dl_dst.data, pinfo->dl_dst.len), 6) != 0) &&
	     (g_ascii_strncasecmp("3333", bytes_to_ep_str((const guint8 *)pinfo->dl_dst.data, pinfo->dl_dst.len), 4) != 0)) )
		return 0;

	/* check whether we already have a stream with these parameters in the list */
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		if (mcast_stream_info_cmp(&tmp_strinfo, (mcast_stream_info_t*)(list->data))==0)
		{
			strinfo = (mcast_stream_info_t*)(list->data);  /*found!*/
			break;
		}
		list = g_list_next(list);
	}

	/* not in the list? then create a new entry */
	if (!strinfo) {
		/*printf("nov sip %s sp %d dip %s dp %d\n", g_strdup(ep_address_to_display(&(pinfo->src))),
			pinfo->srcport, g_strdup(ep_address_to_display(&(pinfo->dst))), pinfo->destport);*/
		tmp_strinfo.npackets = 0;
		tmp_strinfo.apackets = 0;
		tmp_strinfo.first_frame_num = pinfo->fd->num;
		tmp_strinfo.start_sec = (guint32) pinfo->fd->abs_ts.secs;
		tmp_strinfo.start_usec = pinfo->fd->abs_ts.nsecs/1000;
		tmp_strinfo.start_rel_sec = (guint32) pinfo->rel_ts.secs;
		tmp_strinfo.start_rel_usec = pinfo->rel_ts.nsecs/1000;
		tmp_strinfo.vlan_id = 0;

		/* reset Mcast stats */
		tmp_strinfo.average_bw = 0;
		tmp_strinfo.total_bytes = 0;

		/* reset slidingwindow and buffer parameters */
		tmp_strinfo.element.buff = (struct timeval *)g_malloc(buffsize * sizeof(struct timeval));
		tmp_strinfo.element.first=0;
		tmp_strinfo.element.last=0;
		tmp_strinfo.element.burstsize=1;
		tmp_strinfo.element.topburstsize=1;
		tmp_strinfo.element.numbursts=0;
		tmp_strinfo.element.burststatus=0;
		tmp_strinfo.element.count=1;
		tmp_strinfo.element.buffusage=pinfo->fd->pkt_len;
		tmp_strinfo.element.topbuffusage=pinfo->fd->pkt_len;
		tmp_strinfo.element.numbuffalarms=0;
		tmp_strinfo.element.buffstatus=0;
		tmp_strinfo.element.maxbw=0;

		strinfo = (mcast_stream_info_t *)g_malloc(sizeof(mcast_stream_info_t));
		*strinfo = tmp_strinfo;  /* memberwise copy of struct */
		tapinfo->strinfo_list = g_list_append(tapinfo->strinfo_list, strinfo);
		strinfo->element.buff = (struct timeval *)g_malloc(buffsize * sizeof(struct timeval));

		/* set time with the first packet */
		if (tapinfo->npackets == 0) {
			tapinfo->allstreams = (mcast_stream_info_t *)g_malloc(sizeof(mcast_stream_info_t));
			tapinfo->allstreams->element.buff =
					(struct timeval *)g_malloc(buffsize * sizeof(struct timeval));
			tapinfo->allstreams->start_rel_sec = (guint32) pinfo->rel_ts.secs;
			tapinfo->allstreams->start_rel_usec = pinfo->rel_ts.nsecs/1000;
			tapinfo->allstreams->total_bytes = 0;
			tapinfo->allstreams->element.first=0;
			tapinfo->allstreams->element.last=0;
			tapinfo->allstreams->element.burstsize=1;
			tapinfo->allstreams->element.topburstsize=1;
			tapinfo->allstreams->element.numbursts=0;
			tapinfo->allstreams->element.burststatus=0;
			tapinfo->allstreams->element.count=1;
			tapinfo->allstreams->element.buffusage=pinfo->fd->pkt_len;
			tapinfo->allstreams->element.topbuffusage=pinfo->fd->pkt_len;
			tapinfo->allstreams->element.numbuffalarms=0;
			tapinfo->allstreams->element.buffstatus=0;
			tapinfo->allstreams->element.maxbw=0;
		}
	}

	/* time between first and last packet in the group */
	strinfo->stop_rel_sec = (guint32) pinfo->rel_ts.secs;
	strinfo->stop_rel_usec = pinfo->rel_ts.nsecs/1000;
	deltatime = ((float)((strinfo->stop_rel_sec * 1000000 + strinfo->stop_rel_usec)
					- (strinfo->start_rel_sec*1000000 + strinfo->start_rel_usec)))/1000000;

	/* calculate average bandwidth for this stream */
	strinfo->total_bytes = strinfo->total_bytes + pinfo->fd->pkt_len;
	if (deltatime > 0)
		strinfo->average_bw = (((float)(strinfo->total_bytes*8) / deltatime) / 1000000);

	/* increment the packets counter for this stream and calculate average pps */
	++(strinfo->npackets);
	strinfo->apackets = (guint32) (strinfo->npackets / deltatime);

	/* time between first and last packet in any group */
	tapinfo->allstreams->stop_rel_sec = (guint32) pinfo->rel_ts.secs;
	tapinfo->allstreams->stop_rel_usec = pinfo->rel_ts.nsecs/1000;
	deltatime = ((float)((tapinfo->allstreams->stop_rel_sec * 1000000 + tapinfo->allstreams->stop_rel_usec)
		- (tapinfo->allstreams->start_rel_sec*1000000 + tapinfo->allstreams->start_rel_usec)))/1000000;

	/* increment the packets counter of all streams */
	++(tapinfo->npackets);

	/* calculate average bandwidth for all streams */
	tapinfo->allstreams->total_bytes = tapinfo->allstreams->total_bytes + pinfo->fd->pkt_len;
	if (deltatime > 0)
		tapinfo->allstreams->average_bw = (((float)(tapinfo->allstreams->total_bytes *8) / deltatime) / 1000000);

	/* sliding window and buffercalc for this group*/
	slidingwindow(strinfo, pinfo);
	buffusagecalc(strinfo, pinfo, mcast_stream_emptyspeed*1000);
	/* sliding window and buffercalc for all groups */
	slidingwindow(tapinfo->allstreams, pinfo);
	buffusagecalc(tapinfo->allstreams, pinfo, mcast_stream_cumulemptyspeed*1000);
	/* end of sliding window */

	return 1;  /* refresh output */

}

/****************************************************************************/
/* scan for Mcast streams */
void
mcaststream_scan(void)
{
	gboolean was_registered = the_tapinfo_struct.is_registered;
	if (!the_tapinfo_struct.is_registered)
		register_tap_listener_mcast_stream();

	cf_retap_packets(&cfile);

	if (!was_registered)
		remove_tap_listener_mcast_stream();
}


/****************************************************************************/
const mcaststream_tapinfo_t *
mcaststream_get_info(void)
{
	return &the_tapinfo_struct;
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/

/****************************************************************************/
void
remove_tap_listener_mcast_stream(void)
{
	if (the_tapinfo_struct.is_registered) {
		remove_tap_listener(&the_tapinfo_struct);

		the_tapinfo_struct.is_registered = FALSE;
	}
}


/****************************************************************************/
void
register_tap_listener_mcast_stream(void)
{
	GString *error_string;
	if (!the_tapinfo_struct.is_registered) {
		error_string = register_tap_listener("udp", &the_tapinfo_struct,
			NULL, 0, mcaststream_reset_cb, mcaststream_packet,
			mcaststream_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}

		the_tapinfo_struct.is_registered = TRUE;
	}
}

/*******************************************************************************/
/* sliding window and buffer calculations */

/* compare two times */
static guint16
comparetimes(struct timeval *t1, struct timeval *t2, guint16 burstint_lcl)
{
	if(((t2->tv_sec - t1->tv_sec)*1000 + (t2->tv_usec - t1->tv_usec)/1000) > burstint_lcl){
		return 1;
	} else{
		return 0;
	}
}

/* calculate buffer usage */
static void
buffusagecalc(mcast_stream_info_t *strinfo, packet_info *pinfo, double emptyspeed_lcl)
{
	time_t sec=0;
	gint32 usec=0, cur, prev;
	struct timeval *buffer;
	double timeelapsed;

	buffer = strinfo->element.buff;
	cur = strinfo->element.last;
	if(cur == 0){
		cur = buffsize - 1;
		prev = cur - 1;
	} else if(cur == 1){
		prev = buffsize - 1;
		cur = 0;
	} else{
		cur=cur-1;
		prev=cur-1;
	}

	sec = buffer[cur].tv_sec - buffer[prev].tv_sec;
	usec = (gint32)buffer[cur].tv_usec - (gint32)buffer[prev].tv_usec;
	timeelapsed = (double)usec/1000000 + (double)sec;

	/* bytes added to buffer */
	strinfo->element.buffusage+=pinfo->fd->pkt_len;

	/* bytes cleared from buffer */
	strinfo->element.buffusage-= (guint32) (timeelapsed * emptyspeed_lcl / 8);

	if(strinfo->element.buffusage < 0) strinfo->element.buffusage=0;
	if(strinfo->element.buffusage > strinfo->element.topbuffusage)
		strinfo->element.topbuffusage = strinfo->element.buffusage;
	/* check for buffer losses */
	if((strinfo->element.buffusage >= mcast_stream_bufferalarm) && (strinfo->element.buffstatus == 0)){
		strinfo->element.buffstatus = 1;
		strinfo->element.numbuffalarms++;
	} else if(strinfo->element.buffusage < mcast_stream_bufferalarm){
		strinfo->element.buffstatus = 0;
	}

	return;
}

/* sliding window calculation */
static void
slidingwindow(mcast_stream_info_t *strinfo, packet_info *pinfo)
{
	struct timeval *buffer;
	gint32 diff;

	buffer = strinfo->element.buff;

	diff = strinfo->element.last - strinfo->element.first;
	if(diff < 0) diff+=buffsize;

	/* check if buffer is full */
	if(diff >= (buffsize - 2)){
		fprintf(stderr, "Warning: capture buffer full\n");
		strinfo->element.first++;
		if(strinfo->element.first >= buffsize) strinfo->element.first = strinfo->element.first % buffsize;
	}

	/* burst count */
	buffer[strinfo->element.last].tv_sec = (guint32) pinfo->rel_ts.secs;
	buffer[strinfo->element.last].tv_usec = pinfo->rel_ts.nsecs/1000;
	while(comparetimes((struct timeval *)&(buffer[strinfo->element.first]),
			   (struct timeval *)&(buffer[strinfo->element.last]), mcast_stream_burstint)){
		strinfo->element.first++;
		if(strinfo->element.first >= buffsize) strinfo->element.first = strinfo->element.first % buffsize;
		diff--;
	}
	strinfo->element.burstsize = diff;
	if(strinfo->element.burstsize > strinfo->element.topburstsize) {
		strinfo->element.topburstsize = strinfo->element.burstsize;
		strinfo->element.maxbw = (float)(strinfo->element.topburstsize) * 1000 / mcast_stream_burstint * pinfo->fd->pkt_len * 8 / 1000000;
	}

	strinfo->element.last++;
	if(strinfo->element.last >= buffsize) strinfo->element.last = strinfo->element.last % buffsize;
	/* trigger check */
	if((strinfo->element.burstsize >= mcast_stream_trigger) && (strinfo->element.burststatus == 0)){
		strinfo->element.burststatus = 1;
		strinfo->element.numbursts++;
	} else if(strinfo->element.burstsize < mcast_stream_trigger){
		strinfo->element.burststatus = 0;
	}

	strinfo->element.count++;
}

