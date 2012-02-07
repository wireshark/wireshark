/* voip_calls.c
 * VoIP calls summary addition for Wireshark
 *
 * $Id$
 *
 * Copyright 2004, Ericsson, Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
 *
 * based on h323_calls.c
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * H323, RTP, RTP Event, MGCP, AudioCodes (ISDN PRI and CAS), T38 and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation,	Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <string.h>

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/tap-voip.h>
#include <epan/dissectors/packet-sip.h>
#include <epan/dissectors/packet-mtp3.h>
#include <epan/dissectors/packet-isup.h>
#include <epan/dissectors/packet-h225.h>
#include <epan/dissectors/packet-h245.h>
#include <epan/dissectors/packet-q931.h>
#include <epan/dissectors/packet-sdp.h>
#include <epan/dissectors/packet-mgcp.h>
#include <epan/dissectors/packet-actrace.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/dissectors/packet-rtp-events.h>
#include <epan/dissectors/packet-t38.h>
#include <epan/dissectors/packet-t30.h>
#include <epan/dissectors/packet-h248.h>
#include <epan/dissectors/packet-sccp.h>
#include <plugins/unistim/packet-unistim.h>
#include <epan/dissectors/packet-skinny.h>
#include <epan/dissectors/packet-iax2.h>
#include <epan/rtp_pt.h>

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include "ui/gtk/graph_analysis.h"
#include "ui/gtk/voip_calls.h"
#include "ui/gtk/voip_calls_dlg.h"
#include "ui/gtk/main.h"

#ifdef HAVE_LIBPORTAUDIO
#include "ui/gtk/rtp_player.h"
#endif /* HAVE_LIBPORTAUDIO */


const char *voip_call_state_name[8]={
	"",
	"CALL SETUP",
	"RINGING",
	"IN CALL",
	"CANCELLED",
	"COMPLETED",
	"REJECTED",
	"UNKNOWN"
};

/* defines whether we can consider the call active */
const char *voip_protocol_name[]={
	"SIP",
	"ISUP",
	"H.323",
	"MGCP",
	"AC_ISDN",
	"AC_CAS",
	"T.38",
	"H.248",
	"SCCP",
	"BSSMAP",
	"RANAP",
	"UNISTIM",
	"SKINNY",
	"IAX2",
	"VoIP"
};

typedef struct {
	gchar *frame_label;
	gchar *comment;
} graph_str;

#define H245_MAX 6

typedef struct {
	guint32	frame_num;
	gint8 labels_count;
	graph_str labels[H245_MAX];
} h245_labels_t;

static h245_labels_t h245_labels;

/* defines a RTP stream */
typedef struct _voip_rtp_stream_info {
	address src_addr;
	guint16 src_port;
	address dest_addr;
	guint16 dest_port;
	guint32 ssrc;
	guint32  pt;
	gchar *pt_str;
	gboolean is_srtp;  
	guint32 npackets;
	gboolean end_stream;

	guint32 setup_frame_number; /* frame number of setup message */
	/* The frame_data struct holds the frame number and timing information needed. */
	frame_data *start_fd; 
	frame_data *stop_fd;
	gint32 rtp_event;
} voip_rtp_stream_info_t;

/****************************************************************************/
/* the one and only global voip_calls_tapinfo_t structure */
static voip_calls_tapinfo_t the_tapinfo_struct =
	{0, NULL, {0}, 0, NULL, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* the one and only global voip_rtp_tapinfo_t structure */
static voip_rtp_tapinfo_t the_tapinfo_rtp_struct =
	{0, NULL, 0, 0};

/****************************************************************************/
/* when there is a [re]reading of packet's */
void voip_calls_reset(voip_calls_tapinfo_t *tapinfo)
{
	voip_calls_info_t *callsinfo;
	voip_rtp_tapinfo_t *rtp_tapinfo = &the_tapinfo_rtp_struct;
	voip_rtp_stream_info_t *strinfo;
	graph_analysis_item_t *graph_item;
	GList *list;

#ifdef HAVE_LIBPORTAUDIO
	/* reset the RTP player */
	reset_rtp_player();
#endif

	/* free the data items first */
	list = g_list_first(tapinfo->callsinfo_list);
	while (list)
	{
		callsinfo = list->data;
		g_free(callsinfo->call_id);
		g_free(callsinfo->from_identity);
		g_free(callsinfo->to_identity);
		g_free((void *)(callsinfo->initial_speaker.data));
		g_free(callsinfo->protocol_name);
		g_free(callsinfo->call_comment);

		if (callsinfo->free_prot_info && callsinfo->prot_info)
			callsinfo->free_prot_info(callsinfo->prot_info);

		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapinfo->callsinfo_list);
	/* free the SIP_HASH */
	if(NULL!=tapinfo->callsinfo_hashtable[SIP_HASH])
		g_hash_table_remove_all (tapinfo->callsinfo_hashtable[SIP_HASH]);
	tapinfo->callsinfo_list = NULL;
	tapinfo->ncalls = 0;
	tapinfo->npackets = 0;
	tapinfo->start_packets = 0;
	tapinfo->completed_calls = 0;
	tapinfo->rejected_calls = 0;
	tapinfo->reversed= 0;

	/* free the graph data items first */
	if(NULL!=tapinfo->graph_analysis->ht)
		g_hash_table_remove_all(tapinfo->graph_analysis->ht);
	list = g_list_first(tapinfo->graph_analysis->list);
	while (list)
	{
		graph_item = list->data;
		g_free(graph_item->frame_label);
		g_free(graph_item->comment);
		g_free((void *)graph_item->src_addr.data);
		g_free((void *)graph_item->dst_addr.data);
		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapinfo->graph_analysis->list);
	tapinfo->graph_analysis->nconv = 0;
	tapinfo->graph_analysis->list = NULL;

	++(tapinfo->launch_count);

	/* free the strinfo data items first */
	list = g_list_first(rtp_tapinfo->list);
	while(list)
	{
		strinfo = list->data;
		g_free(strinfo->pt_str);
		list = g_list_next(list);
	}
	g_list_free(rtp_tapinfo->list);
	rtp_tapinfo->list = NULL;

	return;
}

/****************************************************************************/
void graph_analysis_data_init(void){
	the_tapinfo_struct.graph_analysis = g_malloc(sizeof(graph_analysis_info_t));
	the_tapinfo_struct.graph_analysis->nconv = 0;
	the_tapinfo_struct.graph_analysis->list = NULL;
	the_tapinfo_struct.graph_analysis->ht= g_hash_table_new(g_int_hash, g_int_equal);
}

/****************************************************************************/
/* Add a new item into the graph */
static void add_to_graph(voip_calls_tapinfo_t *tapinfo _U_, packet_info *pinfo, const gchar *frame_label, const gchar *comment, guint16 call_num, address *src_addr, address *dst_addr, guint16 line_style)
{
	graph_analysis_item_t *gai;

	gai = g_malloc(sizeof(graph_analysis_item_t));
	gai->fd = pinfo->fd;
	COPY_ADDRESS(&(gai->src_addr),src_addr);
	COPY_ADDRESS(&(gai->dst_addr),dst_addr);

	gai->port_src=pinfo->srcport;
	gai->port_dst=pinfo->destport;
	if (frame_label != NULL)
		gai->frame_label = g_strdup(frame_label);
	else
		gai->frame_label = g_strdup("");

	if (comment != NULL)
		gai->comment = g_strdup(comment);
	else
		gai->comment = g_strdup("");
	gai->conv_num=call_num;
	gai->line_style=line_style;
	gai->display=FALSE;

	tapinfo->graph_analysis->list = g_list_prepend(tapinfo->graph_analysis->list, gai);
	g_hash_table_insert(tapinfo->graph_analysis->ht, &gai->fd->num, gai); 

}

/****************************************************************************/
/* Append str to frame_label and comment in a graph item */
/* return 0 if the frame_num is not in the graph list */
static int append_to_frame_graph(voip_calls_tapinfo_t *tapinfo _U_, guint32 frame_num, const gchar *new_frame_label, const gchar *new_comment)
{
	graph_analysis_item_t *gai=NULL;
	gchar *frame_label = NULL;
	gchar *comment = NULL;

	if(NULL!=tapinfo->graph_analysis->ht)
		gai=g_hash_table_lookup(tapinfo->graph_analysis->ht, &frame_num);
	if(gai){
		frame_label = gai->frame_label;
		comment = gai->comment;

		if (new_frame_label != NULL){
			gai->frame_label = g_strdup_printf("%s %s", frame_label, new_frame_label);
			g_free(frame_label);
		}

		if (new_comment != NULL){
			gai->comment = g_strdup_printf("%s %s", comment, new_comment);
			g_free(comment);
		}
	}

	return gai? 1 : 0;
}

/****************************************************************************/
/* Change the frame_label and comment in a graph item if not NULL*/
/* return 0 if the frame_num is not in the graph list */
static int change_frame_graph(voip_calls_tapinfo_t *tapinfo _U_, guint32 frame_num, const gchar *new_frame_label, const gchar *new_comment)
{
	graph_analysis_item_t *gai=NULL;
	gchar *frame_label = NULL;
	gchar *comment = NULL;

	if(NULL!=tapinfo->graph_analysis->ht)
		gai=g_hash_table_lookup(tapinfo->graph_analysis->ht, &frame_num);
	if(gai){
		frame_label = gai->frame_label;
		comment = gai->comment;

		if (new_frame_label != NULL){
			gai->frame_label = g_strdup(new_frame_label);
			g_free(frame_label);
		}

		if (new_comment != NULL){
			gai->comment = g_strdup(new_comment);
			g_free(comment);
		}
	}

	return gai? 1 : 0;
}

/****************************************************************************/
/* Change all the graph items with call_num to new_call_num */
static guint change_call_num_graph(voip_calls_tapinfo_t *tapinfo _U_, guint16 call_num, guint16 new_call_num)
{
	graph_analysis_item_t *gai;
	GList *list;
	guint items_changed;

	items_changed = 0;
	list = g_list_first(tapinfo->graph_analysis->list);
	while (list)
	{
		gai = list->data;
		if (gai->conv_num == call_num){
			gai->conv_num = new_call_num;
			items_changed++;
		}
		list = g_list_next(list);
	}
	return items_changed;
}

/****************************************************************************/
/* Insert the item in the graph list */
static void insert_to_graph_t38(voip_calls_tapinfo_t *tapinfo _U_, packet_info *pinfo, const gchar *frame_label, const gchar *comment, guint16 call_num, address *src_addr, address *dst_addr, guint16 line_style, guint32 frame_num)
{
	graph_analysis_item_t *gai, *new_gai;
	GList *list;
	guint item_num;
	gboolean inserted;

	new_gai = g_malloc(sizeof(graph_analysis_item_t));
	new_gai->fd = new_packet_list_get_row_data(frame_num);
	COPY_ADDRESS(&(new_gai->src_addr),src_addr);
	COPY_ADDRESS(&(new_gai->dst_addr),dst_addr);

	new_gai->port_src=pinfo->srcport;
	new_gai->port_dst=pinfo->destport;
	if (frame_label != NULL)
		new_gai->frame_label = g_strdup(frame_label);
	else
		new_gai->frame_label = g_strdup("");

	if (comment != NULL)
		new_gai->comment = g_strdup(comment);
	else
		new_gai->comment = g_strdup("");
	new_gai->conv_num=call_num;
	new_gai->line_style=line_style;
	new_gai->display=FALSE;

	item_num = 0;
	inserted = FALSE;
	list = g_list_first(tapinfo->graph_analysis->list);
	while (list)
	{
		gai = list->data;
		if (gai->fd->num > frame_num){
			the_tapinfo_struct.graph_analysis->list = g_list_insert(the_tapinfo_struct.graph_analysis->list, new_gai, item_num);
			inserted = TRUE;
			break;
		}
		list = g_list_next(list);
		item_num++;
	}

	if (!inserted) tapinfo->graph_analysis->list = g_list_prepend(tapinfo->graph_analysis->list, new_gai);
}

/****************************************************************************/
/* ***************************TAP for RTP Events*****************************/
/****************************************************************************/

static guint32 rtp_evt_frame_num = 0;
static guint8 rtp_evt = 0;
static gboolean rtp_evt_end = FALSE;
/*static guint32 rtp_evt_setup_frame_num = 0;*/

/****************************************************************************/
/* whenever a rtp event packet is seen by the tap listener */
static int
rtp_event_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *rtp_event_info)
{
	const struct _rtp_event_info *pi = rtp_event_info;

	/* do not consider RTP events packets without a setup frame */
	if (pi->info_setup_frame_num == 0){
		return 0;
	}

	rtp_evt_frame_num = pinfo->fd->num;
	rtp_evt = pi->info_rtp_evt;
	rtp_evt_end = pi->info_end;

	return 0;
}

/****************************************************************************/
static gboolean have_rtp_event_tap_listener=FALSE;

void
rtp_event_init_tap(void)
{
	GString *error_string;


	if(have_rtp_event_tap_listener==FALSE)
	{
		error_string = register_tap_listener("rtpevent", &(the_tapinfo_rtp_struct.rtp_event_dummy),
			NULL,
			0,
			NULL,
			rtp_event_packet,
			NULL
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_rtp_event_tap_listener=TRUE;
	}
}

/****************************************************************************/

void
remove_tap_listener_rtp_event(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_rtp_struct.rtp_event_dummy));
	unprotect_thread_critical_region();

	have_rtp_event_tap_listener=FALSE;
}

/****************************************************************************/
/* ***************************TAP for RTP **********************************/
/****************************************************************************/

/****************************************************************************/
/* when there is a [re]reading of RTP packet's */
static void voip_rtp_reset(void *ptr _U_)
{
	voip_rtp_tapinfo_t *tapinfo = &the_tapinfo_rtp_struct;
	GList *list;
	/* free the data items first */
	list = g_list_first(tapinfo->list);
	while (list)
	{
		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapinfo->list);
	tapinfo->list = NULL;
	tapinfo->nstreams = 0;
	return;
}

/****************************************************************************/
/* whenever a RTP packet is seen by the tap listener */
static int
RTP_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, void const *RTPinfo)
{
	voip_rtp_tapinfo_t *tapinfo = &the_tapinfo_rtp_struct;
	voip_rtp_stream_info_t *tmp_listinfo;
	voip_rtp_stream_info_t *strinfo = NULL;
	GList *list;
	struct _rtp_conversation_info *p_conv_data = NULL;

	const struct _rtp_info *pi = RTPinfo;

	/* do not consider RTP packets without a setup frame */
	if (pi->info_setup_frame_num == 0){
		return 0;
	}

	/* add this RTP for future listening using the RTP Player*/
#ifdef HAVE_LIBPORTAUDIO
	add_rtp_packet(pi, pinfo);
#endif

	/* check whether we already have a RTP stream with this setup frame and ssrc in the list */
	list = g_list_first(tapinfo->list);
	while (list)
	{
		tmp_listinfo=list->data;
		if ( (tmp_listinfo->setup_frame_number == pi->info_setup_frame_num)
			&& (tmp_listinfo->ssrc == pi->info_sync_src) && (tmp_listinfo->end_stream == FALSE)){
			/* if the payload type has changed, we mark the stream as finished to create a new one
			   this is to show multiple payload changes in the Graph for example for DTMF RFC2833 */
			if ( tmp_listinfo->pt != pi->info_payload_type ) {
				tmp_listinfo->end_stream = TRUE;
			} else {
				strinfo = (voip_rtp_stream_info_t*)(list->data);
				break;
			}
		}
		list = g_list_next(list);
	}

	/* if this is a duplicated RTP Event End, just return */
	if ((rtp_evt_frame_num == pinfo->fd->num) && !strinfo && (rtp_evt_end == TRUE)) {
		return 0;
	}

	/* not in the list? then create a new entry */
	if (strinfo==NULL){
		strinfo = g_malloc(sizeof(voip_rtp_stream_info_t));
		COPY_ADDRESS(&(strinfo->src_addr), &(pinfo->src));
		strinfo->src_port = pinfo->srcport;
		COPY_ADDRESS(&(strinfo->dest_addr), &(pinfo->dst));
		strinfo->dest_port = pinfo->destport;
		strinfo->ssrc = pi->info_sync_src;
		strinfo->end_stream = FALSE;
		strinfo->pt = pi->info_payload_type;
		strinfo->pt_str = NULL;
		strinfo->is_srtp = pi->info_is_srtp;
		/* if it is dynamic payload, let use the conv data to see if it is defined */
		if ( (strinfo->pt >= PT_UNDF_96) && (strinfo->pt <= PT_UNDF_127) ) {
			/* Use existing packet info if available */
			p_conv_data = p_get_proto_data(pinfo->fd, proto_get_id_by_filter_name("rtp"));
			if (p_conv_data && p_conv_data->rtp_dyn_payload) {
				encoding_name_and_rate_t *encoding_name_and_rate_pt = NULL;
				encoding_name_and_rate_pt = g_hash_table_lookup(p_conv_data->rtp_dyn_payload, &strinfo->pt);
				if (encoding_name_and_rate_pt) {
					strinfo->pt_str = g_strdup(encoding_name_and_rate_pt->encoding_name);
				}
			}
		}
		if (!strinfo->pt_str) strinfo->pt_str = g_strdup(val_to_str_ext(strinfo->pt, &rtp_payload_type_short_vals_ext, "%u"));
		strinfo->npackets = 0;
		strinfo->start_fd = pinfo->fd;
		strinfo->setup_frame_number = pi->info_setup_frame_num;
		strinfo->rtp_event = -1;
		tapinfo->list = g_list_prepend(tapinfo->list, strinfo);
	}

	if (strinfo!=NULL){
		/* Add the info to the existing RTP stream */
		strinfo->npackets++;
		strinfo->stop_fd = pinfo->fd;

		/* process RTP Event */
		if (rtp_evt_frame_num == pinfo->fd->num) {
			strinfo->rtp_event = rtp_evt;
			if (rtp_evt_end == TRUE) {
				strinfo->end_stream = TRUE;
			}
		}
	}

	the_tapinfo_struct.redraw = TRUE;

	return 1;
}

/****************************************************************************/
/* whenever a redraw in the RTP tap listener */
static void RTP_packet_draw(void *prs _U_)
{
	voip_rtp_tapinfo_t *rtp_tapinfo = &the_tapinfo_rtp_struct;
	GList *rtp_streams_list;
	voip_rtp_stream_info_t *rtp_listinfo;
	GList *voip_calls_graph_list;
	guint item;
	graph_analysis_item_t *gai;
	graph_analysis_item_t *new_gai;
	guint16 conv_num;
	guint32 duration;

	/* add each rtp stream to the graph */
	rtp_streams_list = g_list_first(rtp_tapinfo->list);
	while (rtp_streams_list)
	{
		rtp_listinfo = rtp_streams_list->data;

		/* using the setup frame number of the RTP stream, we get the call number that it belongs */
		voip_calls_graph_list = g_list_first(the_tapinfo_struct.graph_analysis->list);
		while (voip_calls_graph_list)
		{
			gai = voip_calls_graph_list->data;
			conv_num = gai->conv_num;
			/* if we get the setup frame number, then get the time position to graph the RTP arrow */
			if (rtp_listinfo->setup_frame_number == gai->fd->num){
				/* look again from the begining because there are cases where the Setup frame is after the RTP */
				voip_calls_graph_list = g_list_first(the_tapinfo_struct.graph_analysis->list);
				item = 0;
				while(voip_calls_graph_list){
					gai = voip_calls_graph_list->data;
					/* if RTP was already in the Graph, just update the comment information */
					if (rtp_listinfo->start_fd->num == gai->fd->num){
						duration = (guint32)(nstime_to_msec(&rtp_listinfo->stop_fd->rel_ts) - nstime_to_msec(&rtp_listinfo->start_fd->rel_ts));
						g_free(gai->comment);
						gai->comment = g_strdup_printf("%s Num packets:%u  Duration:%u.%03us SSRC:0x%X",
														(rtp_listinfo->is_srtp)?"SRTP":"RTP", rtp_listinfo->npackets,
														duration/1000,(duration%1000), rtp_listinfo->ssrc);
						break;
					}

					/* we increment the list here to be able to check if it is the last item in this calls, which means the RTP is after so we have to draw it */
					voip_calls_graph_list = g_list_next(voip_calls_graph_list);
					if (!voip_calls_graph_list) item++;

					/* add the RTP item to the graph if was not there*/
					if (rtp_listinfo->start_fd->num<gai->fd->num || !voip_calls_graph_list){
						new_gai = g_malloc(sizeof(graph_analysis_item_t));
						new_gai->fd = rtp_listinfo->start_fd;
						COPY_ADDRESS(&(new_gai->src_addr),&(rtp_listinfo->src_addr));
						COPY_ADDRESS(&(new_gai->dst_addr),&(rtp_listinfo->dest_addr));
						new_gai->port_src = rtp_listinfo->src_port;
						new_gai->port_dst = rtp_listinfo->dest_port;
						duration = (guint32)(nstime_to_msec(&rtp_listinfo->stop_fd->rel_ts) - nstime_to_msec(&rtp_listinfo->start_fd->rel_ts));
						new_gai->frame_label = g_strdup_printf("%s (%s) %s",
										       (rtp_listinfo->is_srtp)?"SRTP":"RTP",
										       rtp_listinfo->pt_str,
										       (rtp_listinfo->rtp_event == -1)?
										         "":val_to_str_const(rtp_listinfo->rtp_event, rtp_event_type_values, "Unknown RTP Event"));
						new_gai->comment = g_strdup_printf("%s Num packets:%u  Duration:%u.%03us SSRC:0x%X",
															(rtp_listinfo->is_srtp)?"SRTP":"RTP", rtp_listinfo->npackets,
															duration/1000,(duration%1000), rtp_listinfo->ssrc);
						new_gai->conv_num = conv_num;
						new_gai->display=FALSE;
						new_gai->line_style = 2;  /* the arrow line will be 2 pixels width */
						the_tapinfo_struct.graph_analysis->list = g_list_insert(the_tapinfo_struct.graph_analysis->list, new_gai, item);
						break;
					}
					if (voip_calls_graph_list) item++;
				}
				break;
			}
			voip_calls_graph_list = g_list_next(voip_calls_graph_list);
		}
		rtp_streams_list = g_list_next(rtp_streams_list);
	}
}

static gboolean have_RTP_tap_listener=FALSE;
/****************************************************************************/
void
rtp_init_tap(void)
{
	GString *error_string;

	if(have_RTP_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("rtp", &(the_tapinfo_rtp_struct.rtp_dummy), NULL,
			0,
			voip_rtp_reset,
			RTP_packet,
			RTP_packet_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_RTP_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_rtp(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_rtp_struct.rtp_dummy));
	unprotect_thread_critical_region();

	have_RTP_tap_listener=FALSE;
}

/****************************************************************************/
/******************************TAP for T38 **********************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a T38 packet is seen by the tap listener */
static int
T38_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *T38info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;

	voip_calls_info_t *callsinfo = NULL;
	voip_calls_info_t *tmp_listinfo;
	GList *voip_calls_graph_list;
	GList *list;
	gchar *frame_label = NULL;
	gchar *comment = NULL;
	graph_analysis_item_t *tmp_gai, *gai = NULL;
	guint16 line_style = 2;
	double duration;
	int conv_num = -1;

	const t38_packet_info *pi = T38info;

	if  (pi->setup_frame_number != 0) {
		/* using the setup frame number of the T38 packet, we get the call number that it belongs */
		voip_calls_graph_list = g_list_first(tapinfo->graph_analysis->list);
		while (voip_calls_graph_list)
		{
			tmp_gai = voip_calls_graph_list->data;
			if (pi->setup_frame_number == tmp_gai->fd->num){
				gai = tmp_gai;
				break;
			}
			voip_calls_graph_list = g_list_next(voip_calls_graph_list);
		}
		if (gai) conv_num = (int) gai->conv_num;
	}

	/* if setup_frame_number in the t38 packet is 0, it means it was not set using an SDP or H245 sesion, which means we don't
	 * have the associated Voip calls. It probably means the the packet was decoded using the default t38 port, or using "Decode as.."
	 * in this case we create a "voip" call that only have t38 media (no signaling)
	 * OR if we have not found the Setup message in the graph.
	 */
	if ( (pi->setup_frame_number == 0) || (gai == NULL) ){
		/* check whether we already have a call with these parameters in the list */
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if (tmp_listinfo->protocol == MEDIA_T38){
				callsinfo = (voip_calls_info_t*)(list->data);
				break;
			}
			list = g_list_next (list);
		}

		/* not in the list? then create a new entry */
		if (callsinfo==NULL){
			callsinfo = g_malloc0(sizeof(voip_calls_info_t));
			callsinfo->call_active_state = VOIP_ACTIVE;
			callsinfo->call_state = VOIP_UNKNOWN;
			callsinfo->from_identity=g_strdup("T38 Media only");
			callsinfo->to_identity=g_strdup("T38 Media only");
			COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
			callsinfo->selected=FALSE;
			callsinfo->start_fd = pinfo->fd;
			callsinfo->protocol=MEDIA_T38;
			callsinfo->prot_info=NULL;
			callsinfo->free_prot_info = NULL;
			callsinfo->npackets = 0;
			callsinfo->call_num = tapinfo->ncalls++;
			tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
		}
		++(callsinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);

		conv_num = (int) callsinfo->call_num;
	}

	/* at this point we should have found the call num for this t38 packets belong */
	if (conv_num == -1) {
		return 0;
	}

	/* add the item to the graph list */
	if (pi->type_msg == 0) { /* 0=t30-indicator */
		frame_label = g_strdup(val_to_str(pi->t30ind_value, t38_T30_indicator_vals, "Ukn (0x%02X)") );
		comment = g_strdup_printf("t38:t30 Ind:%s",val_to_str(pi->t30ind_value, t38_T30_indicator_vals, "Ukn (0x%02X)") );
		line_style = 1;
	} else if (pi->type_msg == 1) {	/* 1=data */
		switch(pi->Data_Field_field_type_value){
			case 0: /* hdlc-data */
				break;
			case 2: /* hdlc-fcs-OK */
			case 4: /* hdlc-fcs-OK-sig-end */
				frame_label = g_strdup_printf("%s %s", val_to_str(pi->t30_Facsimile_Control & 0x7F, t30_facsimile_control_field_vals_short, "Ukn (0x%02X)"), pi->desc);
				comment = g_strdup_printf("t38:%s:HDLC:%s",val_to_str(pi->data_value, t38_T30_data_vals, "Ukn (0x%02X)"), val_to_str(pi->t30_Facsimile_Control & 0x7F, t30_facsimile_control_field_vals, "Ukn (0x%02X)"));
				break;
			case 3: /* hdlc-fcs-BAD */
			case 5: /* hdlc-fcs-BAD-sig-end */
				frame_label = g_strdup(pi->Data_Field_field_type_value == 3 ? "fcs-BAD" : "fcs-BAD-sig-end");
				comment = g_strdup_printf("WARNING: received t38:%s:HDLC:%s", val_to_str(pi->data_value, t38_T30_data_vals, "Ukn (0x%02X)"), pi->Data_Field_field_type_value == 3 ? "fcs-BAD" : "fcs-BAD-sig-end");
				break;
			case 7: /* t4-non-ecm-sig-end */
				duration = nstime_to_sec(&pinfo->fd->rel_ts) - pi->time_first_t4_data;
				frame_label = g_strdup_printf("t4-non-ecm-data:%s",val_to_str(pi->data_value, t38_T30_data_vals, "Ukn (0x%02X)") );
				comment = g_strdup_printf("t38:t4-non-ecm-data:%s Duration: %.2fs %s",val_to_str(pi->data_value, t38_T30_data_vals, "Ukn (0x%02X)"), duration, pi->desc_comment );
				insert_to_graph_t38(tapinfo, pinfo, frame_label, comment, (guint16)conv_num, &(pinfo->src), &(pinfo->dst), line_style, pi->frame_num_first_t4_data);
				break;
		}
	}

	if (frame_label && !(pi->Data_Field_field_type_value == 7 && pi->type_msg == 1)) {
		add_to_graph(tapinfo, pinfo, frame_label, comment, (guint16)conv_num, &(pinfo->src), &(pinfo->dst), line_style);
	}

	g_free(comment);
	g_free(frame_label);

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}

static gboolean have_T38_tap_listener=FALSE;
/****************************************************************************/
void
t38_init_tap(void)
{
	GString *error_string;

	if(have_T38_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("t38", &(the_tapinfo_struct.t38_dummy), NULL,
			0,
			voip_calls_dlg_reset,
			T38_packet,
			voip_calls_dlg_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_T38_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_t38(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.t38_dummy));
	unprotect_thread_critical_region();

	have_T38_tap_listener=FALSE;
}


/****************************************************************************/
static gchar *sdp_summary = NULL;
static guint32 sdp_frame_num = 0;

/****************************************************************************/
/* ***************************TAP for SIP **********************************/
/****************************************************************************/


static void free_sip_info(gpointer p) {
	sip_calls_info_t *si = p;

	g_free(si->call_identifier);
	g_free(si);
}

/****************************************************************************/
/* whenever a SIP packet is seen by the tap listener */
static int
SIPcalls_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *SIPinfo)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	/* we just take note of the ISUP data here; when we receive the MTP3 part everything will
	   be compared with existing calls */

	voip_calls_info_t *callsinfo = NULL;
	sip_calls_info_t *tmp_sipinfo = NULL;
	address tmp_src, tmp_dst;
	gchar *frame_label = NULL;
	gchar *comment = NULL;
	gchar *key=NULL;

	const sip_info_value_t *pi = SIPinfo;

	/* do not consider packets without call_id */
	if (pi->tap_call_id ==NULL){
		return 0;
	}
	key=pi->tap_call_id;
	/* init the hash table */
	if(NULL==tapinfo->callsinfo_hashtable[SIP_HASH]) {
		/* TODO: check how efficient g_str_hash is for sip call ids */
		tapinfo->callsinfo_hashtable[SIP_HASH]=g_hash_table_new_full(g_str_hash,
															g_str_equal,
															NULL, /* key_destroy_func */
                                                         	NULL);/* value_destroy_func */
	}
	/* search the call information in the SIP_HASH */
	callsinfo = g_hash_table_lookup(tapinfo->callsinfo_hashtable[SIP_HASH], key);
		
	/* not in the hash? then create a new entry if the message is INVITE -i.e. if this session is a call*/
	if ((callsinfo==NULL) &&(pi->request_method!=NULL)){
		if (strcmp(pi->request_method,"INVITE")==0){
			callsinfo = g_malloc0(sizeof(voip_calls_info_t));
			callsinfo->call_active_state = VOIP_ACTIVE;
			callsinfo->call_state = VOIP_CALL_SETUP;
			callsinfo->from_identity=g_strdup(pi->tap_from_addr);
			callsinfo->to_identity=g_strdup(pi->tap_to_addr);
			COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
			callsinfo->selected=FALSE;
			callsinfo->start_fd=pinfo->fd;
			callsinfo->protocol=VOIP_SIP;
			callsinfo->prot_info=g_malloc(sizeof(sip_calls_info_t));
			callsinfo->free_prot_info = free_sip_info;
			tmp_sipinfo = callsinfo->prot_info;
			tmp_sipinfo->call_identifier = g_strdup(pi->tap_call_id);
			tmp_sipinfo->sip_state = SIP_INVITE_SENT;
			tmp_sipinfo->invite_cseq = pi->tap_cseq_number;
			callsinfo->npackets = 0;
			callsinfo->call_num = tapinfo->ncalls++;
			tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
			/* insert the call information in the SIP_HASH */
			g_hash_table_insert(tapinfo->callsinfo_hashtable[SIP_HASH], 
				tmp_sipinfo->call_identifier, callsinfo);
		}
	}

	if (callsinfo!=NULL){
		tmp_sipinfo = callsinfo->prot_info;

		/* let's analyze the call state */

		COPY_ADDRESS(&(tmp_src), &(pinfo->src));
		COPY_ADDRESS(&(tmp_dst), &(pinfo->dst));

		if (pi->request_method == NULL){
			frame_label = g_strdup_printf("%u %s", pi->response_code, pi->reason_phrase );
			comment = g_strdup("SIP Status");

			if ((tmp_sipinfo && pi->tap_cseq_number == tmp_sipinfo->invite_cseq)&&(ADDRESSES_EQUAL(&tmp_dst,&(callsinfo->initial_speaker)))){
				if ((pi->response_code > 199) && (pi->response_code<300) && (tmp_sipinfo->sip_state == SIP_INVITE_SENT)){
					tmp_sipinfo->sip_state = SIP_200_REC;
				}
				else if ((pi->response_code>299)&&(tmp_sipinfo->sip_state == SIP_INVITE_SENT)){
					callsinfo->call_state = VOIP_REJECTED;
					tapinfo->rejected_calls++;
				}
			}

		}
		else{
			frame_label = g_strdup(pi->request_method);

			if ((strcmp(pi->request_method,"INVITE")==0)&&(ADDRESSES_EQUAL(&tmp_src,&(callsinfo->initial_speaker)))){
				tmp_sipinfo->invite_cseq = pi->tap_cseq_number;
				callsinfo->call_state = VOIP_CALL_SETUP;
				comment = g_strdup_printf("SIP From: %s To:%s", callsinfo->from_identity, callsinfo->to_identity);
			}
			else if ((strcmp(pi->request_method,"ACK")==0)&&(pi->tap_cseq_number == tmp_sipinfo->invite_cseq)
				&&(ADDRESSES_EQUAL(&tmp_src,&(callsinfo->initial_speaker)))&&(tmp_sipinfo->sip_state==SIP_200_REC)
				&&(callsinfo->call_state == VOIP_CALL_SETUP)){
				callsinfo->call_state = VOIP_IN_CALL;
				comment = g_strdup("SIP Request");
			}
			else if (strcmp(pi->request_method,"BYE")==0){
				callsinfo->call_state = VOIP_COMPLETED;
				tapinfo->completed_calls++;
				comment = g_strdup("SIP Request");
			}
			else if ((strcmp(pi->request_method,"CANCEL")==0)&&(pi->tap_cseq_number == tmp_sipinfo->invite_cseq)
				&&(ADDRESSES_EQUAL(&tmp_src,&(callsinfo->initial_speaker)))&&(callsinfo->call_state==VOIP_CALL_SETUP)){
				callsinfo->call_state = VOIP_CANCELLED;
				tmp_sipinfo->sip_state = SIP_CANCEL_SENT;
				comment = g_strdup("SIP Request");
			} else {
				comment = g_strdup("SIP Request");
			}
		}

		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);

		/* add to the graph */
		add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
		g_free(comment);
		g_free(frame_label);
		g_free((void *)tmp_src.data);
		g_free((void *)tmp_dst.data);

		/* add SDP info if apply */
		if ( (sdp_summary != NULL) && (sdp_frame_num == pinfo->fd->num) ){
				append_to_frame_graph(tapinfo, pinfo->fd->num, sdp_summary, NULL);
				g_free(sdp_summary);
				sdp_summary = NULL;
		}
	}

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}


/****************************************************************************/
voip_calls_tapinfo_t* voip_calls_get_info(void)
{
	return &the_tapinfo_struct;
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_SIP_tap_listener=FALSE;
/****************************************************************************/
void
sip_calls_init_tap(void)
{
	GString *error_string;

	if(have_SIP_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("sip", &(the_tapinfo_struct.sip_dummy), NULL,
			0,
			voip_calls_dlg_reset,
			SIPcalls_packet,
			voip_calls_dlg_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_SIP_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_sip_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.sip_dummy));
	unprotect_thread_critical_region();

	have_SIP_tap_listener=FALSE;
}

/****************************************************************************/
/* ***************************TAP for ISUP **********************************/
/****************************************************************************/

static	guint32		mtp3_opc, mtp3_dpc;
static	guint8		mtp3_ni;
static 	guint32		mtp3_frame_num;


/****************************************************************************/
/* whenever a isup_ packet is seen by the tap listener */
static int
isup_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *isup_info _U_)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *callsinfo = NULL;
	isup_calls_info_t *tmp_isupinfo;
	gboolean found = FALSE;
	gboolean forward = FALSE;
	gboolean right_pair;
	GList *list;
	gchar *frame_label = NULL;
	gchar *comment = NULL;

	/*voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct; unused */
	const isup_tap_rec_t *pi = isup_info;

	/* check if the lower layer is MTP matching the frame number */
	if (mtp3_frame_num != pinfo->fd->num) return 0;

	/* check whether we already have a call with these parameters in the list */
	list = g_list_first(tapinfo->callsinfo_list);
	while (list)
	{
		right_pair = TRUE;
		tmp_listinfo=list->data;
		if ((tmp_listinfo->protocol == VOIP_ISUP)&&(tmp_listinfo->call_active_state==VOIP_ACTIVE)){
			tmp_isupinfo = tmp_listinfo->prot_info;
			if ((tmp_isupinfo->cic == pinfo->circuit_id)&&(tmp_isupinfo->ni == mtp3_ni)) {
				if ((tmp_isupinfo->opc == mtp3_opc)&&(tmp_isupinfo->dpc == mtp3_dpc)){
					 forward = TRUE;
				} else if ((tmp_isupinfo->dpc == mtp3_opc)&&(tmp_isupinfo->opc == mtp3_dpc)){
					 forward = FALSE;
				} else{
					right_pair = FALSE;
				}

				 if (right_pair){
					/* if there is an IAM for a call that is not in setup state, that means the previous call in the same
					   cic is no longer active */
					if (tmp_listinfo->call_state == VOIP_CALL_SETUP){
						found = TRUE;
					} else if (pi->message_type != 1){
						found = TRUE;
					} else{
						tmp_listinfo->call_active_state=VOIP_INACTIVE;
					}
				}

				if (found){
					callsinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
		}
		list = g_list_next (list);
	}

	/* not in the list? then create a new entry if the message is IAM
	   -i.e. if this session is a call*/


	if ((callsinfo==NULL) &&(pi->message_type==1)){
		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_active_state = VOIP_ACTIVE;
		callsinfo->call_state = VOIP_UNKNOWN;
		COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
		callsinfo->selected=FALSE;
		callsinfo->start_fd=pinfo->fd;
		callsinfo->protocol=VOIP_ISUP;
		if (pi->calling_number!=NULL){
			callsinfo->from_identity=g_strdup(pi->calling_number);
		}
		if (pi->called_number!=NULL){
			callsinfo->to_identity=g_strdup(pi->called_number);
		}
		callsinfo->prot_info=g_malloc(sizeof(isup_calls_info_t));
		callsinfo->free_prot_info = g_free;
		tmp_isupinfo=callsinfo->prot_info;
		tmp_isupinfo->opc = mtp3_opc;
		tmp_isupinfo->dpc = mtp3_dpc;
		tmp_isupinfo->ni = mtp3_ni;
		tmp_isupinfo->cic = pinfo->circuit_id;
		callsinfo->npackets = 0;
		callsinfo->call_num = tapinfo->ncalls++;
		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
	}


	if (callsinfo!=NULL){
		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);

		/* Let's analyze the call state */

		frame_label = g_strdup(val_to_str_ext_const(pi->message_type, &isup_message_type_value_acro_ext, "Unknown"));

		if (callsinfo->npackets == 1){ /* this is the first packet, that must be an IAM */

			if ((pi->calling_number!=NULL)&&(pi->called_number !=NULL)){
				comment = g_strdup_printf("Call from %s to %s",
				 pi->calling_number, pi->called_number);
			 }
		} else if (callsinfo->npackets == 2){ /* in the second packet we show the SPs */
			if (forward){
				comment = g_strdup_printf("%i-%i -> %i-%i. Cic:%i",
				 mtp3_ni, mtp3_opc,
				 mtp3_ni, mtp3_dpc, pinfo->circuit_id);
			} else {
				comment = g_strdup_printf("%i-%i -> %i-%i. Cic:%i",
				 mtp3_ni, mtp3_dpc,
				 mtp3_ni, mtp3_opc, pinfo->circuit_id);
			}
		}


		switch(pi->message_type){
			case 1: /* IAM */
				callsinfo->call_state=VOIP_CALL_SETUP;
				break;
			case 7: /* CONNECT */
			case 9: /* ANSWER */
				callsinfo->call_state=VOIP_IN_CALL;
				break;
			case 12: /* RELEASE */
				if (callsinfo->call_state==VOIP_CALL_SETUP){
					if (forward){
						callsinfo->call_state=VOIP_CANCELLED;
					}
					else{
						callsinfo->call_state=VOIP_REJECTED;
						tapinfo->rejected_calls++;
					}
				}
				else if (callsinfo->call_state == VOIP_IN_CALL){
					callsinfo->call_state = VOIP_COMPLETED;
					tapinfo->completed_calls++;
				}
				comment = g_strdup_printf("Cause %i - %s",
							  pi->cause_value,
							  val_to_str_ext_const(pi->cause_value, &q931_cause_code_vals_ext, "(Unknown)"));
				break;
		}

		/* increment the packets counter of all calls */
		++(tapinfo->npackets);

		/* add to the graph */
		add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
		g_free(comment);
		g_free(frame_label);
	}

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}

/****************************************************************************/

static gboolean have_isup_tap_listener=FALSE;

void
isup_calls_init_tap(void)
{
	GString *error_string;


	if(have_isup_tap_listener==FALSE)
	{
		error_string = register_tap_listener("isup", &(the_tapinfo_struct.isup_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			isup_calls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_isup_tap_listener=TRUE;
	}
}

/****************************************************************************/

void
remove_tap_listener_isup_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.isup_dummy));
	unprotect_thread_critical_region();

	have_isup_tap_listener=FALSE;
}


/****************************************************************************/
/* ***************************TAP for MTP3 **********************************/
/****************************************************************************/


/****************************************************************************/
/* whenever a mtp3_ packet is seen by the tap listener */
static int
mtp3_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *mtp3_info _U_)
{
	const mtp3_tap_rec_t *pi = mtp3_info;

	/* keep the data in memory to use when the ISUP information arrives */

	mtp3_opc = pi->addr_opc.pc;
	mtp3_dpc = pi->addr_dpc.pc;
	mtp3_ni = pi->addr_opc.ni;
	mtp3_frame_num = pinfo->fd->num;

	return 0;
}

/****************************************************************************/

static gboolean have_mtp3_tap_listener=FALSE;
static gboolean have_m3ua_tap_listener=FALSE;

void
mtp3_calls_init_tap(void)
{
	GString *error_string;


	if(have_mtp3_tap_listener==FALSE)
	{
		error_string = register_tap_listener("mtp3", &(the_tapinfo_struct.mtp3_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			mtp3_calls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_mtp3_tap_listener=TRUE;
	}

	if(have_m3ua_tap_listener==FALSE)
	{
		error_string = register_tap_listener("m3ua", &(the_tapinfo_struct.mtp3_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			mtp3_calls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_m3ua_tap_listener=TRUE;
	}

}

/****************************************************************************/

void
remove_tap_listener_mtp3_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.mtp3_dummy));
	remove_tap_listener(&(the_tapinfo_struct.m3ua_dummy));
	unprotect_thread_critical_region();

	have_mtp3_tap_listener=FALSE;
	have_m3ua_tap_listener=FALSE;
}

/****************************************************************************/
/* ***************************TAP for Q931 **********************************/
/****************************************************************************/
void h245_add_to_graph(guint32 new_frame_num);
static const e_guid_t guid_allzero = {0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
/* defines specific H323 data */

static gchar *q931_calling_number;
static gchar *q931_called_number;
static guint8 q931_cause_value;
static gint32 q931_crv;
static guint32 q931_frame_num;

static guint32 h225_frame_num = 0;
static guint16 h225_call_num = 0;
static h225_cs_type h225_cstype = H225_OTHER;
static gboolean h225_is_faststart;

static guint32 actrace_frame_num = 0;
static gint32 actrace_trunk = 0;
static gint32 actrace_direction = 0;


/****************************************************************************/
/* whenever a q931_ packet is seen by the tap listener */
static int
q931_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *q931_info)
{
	GList *list,*list2;
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	h323_calls_info_t *tmp_h323info,*tmp2_h323info;
	actrace_isdn_calls_info_t *tmp_actrace_isdn_info;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *callsinfo = NULL;
	h245_address_t *h245_add = NULL;
	gchar *comment;

	const q931_packet_info *pi = q931_info;

	/* free previously allocated q931_calling/ed_number */
	g_free(q931_calling_number);
	g_free(q931_called_number);

	if (pi->calling_number!=NULL)
		q931_calling_number = g_strdup(pi->calling_number);
	else
		q931_calling_number = g_strdup("");

	if (pi->called_number!=NULL)
		q931_called_number = g_strdup(pi->called_number);
	else
		q931_called_number = g_strdup("");
	q931_cause_value = pi->cause_value;
	q931_frame_num = pinfo->fd->num;
	q931_crv = pi->crv;


	/* add staff to H323 calls */
	if (h225_frame_num == q931_frame_num) {
		tmp_h323info = NULL;
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if ( (tmp_listinfo->protocol == VOIP_H323) && (tmp_listinfo->call_num == h225_call_num) ){
				tmp_h323info = tmp_listinfo->prot_info;
				callsinfo = (voip_calls_info_t*)(list->data);

				/* Add the CRV to the h323 call */
				if (tmp_h323info->q931_crv == -1) {
					tmp_h323info->q931_crv = q931_crv;
				} else if (tmp_h323info->q931_crv != q931_crv) {
					tmp_h323info->q931_crv2 = q931_crv;
				}
				break;
			}
			list = g_list_next (list);
		}

		if (callsinfo != NULL) {
			comment = NULL;
			if (h225_cstype == H225_SETUP) {
				/* set te calling and called number from the Q931 packet */
				if (q931_calling_number != NULL){
					g_free(callsinfo->from_identity);
					callsinfo->from_identity=g_strdup(q931_calling_number);
				}
				if (q931_called_number != NULL){
					g_free(callsinfo->to_identity);
					callsinfo->to_identity=g_strdup(q931_called_number);
				}

				/* check if there is an LRQ/LCF that match this Setup */
				/* TODO: we are just checking the DialedNumer in LRQ/LCF agains the Setup
					we should also check if the h225 signaling IP and port match the destination
					Setup ip and port */
				list = g_list_first(tapinfo->callsinfo_list);
				while (list)
				{
					tmp_listinfo=list->data;
					if (tmp_listinfo->protocol == VOIP_H323){
						tmp2_h323info = tmp_listinfo->prot_info;

						/* check if the called number match a LRQ/LCF */
						if ( (strcmp(callsinfo->to_identity, tmp_listinfo->to_identity)==0)
							 && (memcmp(&tmp2_h323info->guid, &guid_allzero, GUID_LEN) == 0) ){
							/* change the call graph to the LRQ/LCF to belong to this call */
							callsinfo->npackets += change_call_num_graph(tapinfo, tmp_listinfo->call_num, callsinfo->call_num);

							/* remove this LRQ/LCF call entry because we have found the Setup that match them */
							g_free(tmp_listinfo->from_identity);
							g_free(tmp_listinfo->to_identity);
							g_free(tmp2_h323info->guid);

							list2 = g_list_first(tmp2_h323info->h245_list);
							while (list2)
							{
								h245_add=list2->data;
								g_free((void *)h245_add->h245_address.data);
								g_free(list2->data);
								list2 = g_list_next(list2);
							}
							g_list_free(tmp_h323info->h245_list);
							tmp_h323info->h245_list = NULL;
							g_free(tmp_listinfo->prot_info);
							tapinfo->callsinfo_list = g_list_remove(tapinfo->callsinfo_list, tmp_listinfo);
							break;
						}
					}
			        list = g_list_next (list);
				}

				comment = g_strdup_printf("H225 From: %s To:%s  TunnH245:%s FS:%s", callsinfo->from_identity, callsinfo->to_identity, (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
							  (h225_is_faststart==TRUE?"on":"off"));
			} else if (h225_cstype == H225_RELEASE_COMPLET) {
				/* get the Q931 Release cause code */
				if (q931_cause_value != 0xFF){
					comment = g_strdup_printf("H225 Q931 Rel Cause (%i):%s", q931_cause_value,
                                                                  val_to_str_ext_const(q931_cause_value, &q931_cause_code_vals_ext, "<unknown>"));
				} else { /* Cause not set */
					comment = g_strdup("H225 No Q931 Rel Cause");
				}
			}
			/* change the graph comment for this new one */
			if (comment != NULL) {
				change_frame_graph(tapinfo, h225_frame_num, NULL, comment);
				g_free(comment);
			}
		}
		/* we reset the h225_frame_num to 0 because there could be empty h225 in the same frame
		   as non empty h225 (e.g connect), so we don't have to be here twice */
		h225_frame_num = 0;

	/* add staff to H245 */
	} else if (h245_labels.frame_num == q931_frame_num) {
	/* there are empty H225 frames that don't have guid (guaid=0) but they have h245 info,
	   so the only way to match those frames is with the Q931 CRV number */
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if (tmp_listinfo->protocol == VOIP_H323){
				tmp_h323info = tmp_listinfo->prot_info;
				if ( ((tmp_h323info->q931_crv == q931_crv) || (tmp_h323info->q931_crv2 == q931_crv)) && (q931_crv!=-1)){
					/* if the frame number exists in graph, append to it*/
					if (!append_to_frame_graph(tapinfo, q931_frame_num, NULL, NULL)) {
						/* if not exist, add to the graph */
						add_to_graph(tapinfo, pinfo, NULL, NULL, tmp_listinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
						++(tmp_listinfo->npackets);
						/* increment the packets counter of all calls */
						++(tapinfo->npackets);
					}

					/* Add the H245 info if exists to the Graph */
					h245_add_to_graph(pinfo->fd->num);
					break;
				}
			}
			list = g_list_next (list);
		}

	/* add staff to ACTRACE */
	} else if (actrace_frame_num == q931_frame_num) {
		address pstn_add;

		comment = NULL;
		callsinfo = NULL;
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if ( tmp_listinfo->protocol == VOIP_AC_ISDN ){
				tmp_actrace_isdn_info = tmp_listinfo->prot_info;
				/* TODO: Also check the IP of the Blade, and if the call is complete (no active) */
				if ( (tmp_actrace_isdn_info->crv == q931_crv) && (tmp_actrace_isdn_info->trunk == actrace_trunk) ) {
					callsinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
			list = g_list_next (list);
		}

		SET_ADDRESS(&pstn_add, AT_STRINGZ, 5, g_strdup("PSTN"));

		/* if it is a new call, add it to the list */
		if (!callsinfo) {
			callsinfo = g_malloc0(sizeof(voip_calls_info_t));
			callsinfo->call_active_state = VOIP_ACTIVE;
			callsinfo->call_state = VOIP_CALL_SETUP;
			callsinfo->from_identity=g_strdup(q931_calling_number);
			callsinfo->to_identity=g_strdup(q931_called_number);
			COPY_ADDRESS(&(callsinfo->initial_speaker),actrace_direction?&pstn_add:&(pinfo->src));
			callsinfo->selected=FALSE;
			callsinfo->start_fd=pinfo->fd;
			callsinfo->protocol=VOIP_AC_ISDN;
			callsinfo->prot_info=g_malloc(sizeof(actrace_isdn_calls_info_t));
			callsinfo->free_prot_info = g_free;
			tmp_actrace_isdn_info=callsinfo->prot_info;
			tmp_actrace_isdn_info->crv=q931_crv;
			tmp_actrace_isdn_info->trunk=actrace_trunk;
			callsinfo->npackets = 0;
			callsinfo->call_num = tapinfo->ncalls++;
			tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
		}

		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);

		switch(pi->message_type){
		case Q931_SETUP:
			comment = g_strdup_printf("AC_ISDN trunk:%u Calling: %s  Called:%s", actrace_trunk, q931_calling_number, q931_called_number);
			callsinfo->call_state=VOIP_CALL_SETUP;
			break;
		case Q931_CONNECT:
			callsinfo->call_state=VOIP_IN_CALL;
			break;
		case Q931_RELEASE_COMPLETE:
		case Q931_RELEASE:
		case Q931_DISCONNECT:
			if (callsinfo->call_state==VOIP_CALL_SETUP){
				if (ADDRESSES_EQUAL(&(callsinfo->initial_speaker), actrace_direction?&pstn_add:&(pinfo->src) )){  /* forward direction */
					callsinfo->call_state=VOIP_CANCELLED;
				}
				else{												/* reverse */
					callsinfo->call_state=VOIP_REJECTED;
					tapinfo->rejected_calls++;
				}
			} else if ( (callsinfo->call_state!=VOIP_CANCELLED) && (callsinfo->call_state!=VOIP_REJECTED) ){
					callsinfo->call_state=VOIP_COMPLETED;
					tapinfo->completed_calls++;
			}
			if (q931_cause_value != 0xFF){
				comment = g_strdup_printf("AC_ISDN trunk:%u Q931 Rel Cause (%i):%s", actrace_trunk, q931_cause_value,
                                                          val_to_str_ext_const(q931_cause_value, &q931_cause_code_vals_ext, "<unknown>"));
			} else { /* Cause not set */
				comment = g_strdup("AC_ISDN No Q931 Rel Cause");
			}
			break;
		}

		if (!comment)
			comment = g_strdup_printf("AC_ISDN  trunk:%u", actrace_trunk );

		add_to_graph(tapinfo, pinfo, val_to_str(pi->message_type, q931_message_type_vals, "<unknown>") , comment, callsinfo->call_num,
				actrace_direction?&pstn_add:&(pinfo->src),
				actrace_direction?&(pinfo->src):&pstn_add,
				1 );

		g_free(comment);
		g_free((char *)pstn_add.data);
	}

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}

/****************************************************************************/
static gboolean have_q931_tap_listener=FALSE;

void
q931_calls_init_tap(void)
{
	GString *error_string;


	if(have_q931_tap_listener==FALSE)
	{
		error_string = register_tap_listener("q931", &(the_tapinfo_struct.q931_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			q931_calls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_q931_tap_listener=TRUE;
	}
}

/****************************************************************************/

void
remove_tap_listener_q931_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.q931_dummy));
	unprotect_thread_critical_region();

	have_q931_tap_listener=FALSE;
}

/****************************************************************************/
/****************************TAP for H323 ***********************************/
/****************************************************************************/

static void add_h245_Address(h323_calls_info_t *h323info,  h245_address_t *h245_address)
{
	h323info->h245_list = g_list_prepend(h323info->h245_list, h245_address);
}


static void free_h225_info(gpointer p) {
	h323_calls_info_t *tmp_h323info = p;

	g_free(tmp_h323info->guid);

	if (tmp_h323info->h245_list) {
		GList *list2 = g_list_first(tmp_h323info->h245_list);
		while (list2)
		{
			h245_address_t *h245_add=list2->data;
			g_free((void *)h245_add->h245_address.data);
			g_free(list2->data);
			list2 = g_list_next(list2);
		}

		g_list_free(tmp_h323info->h245_list);

	}

	g_free(p);
}
/****************************************************************************/
/* whenever a H225 packet is seen by the tap listener */
static int
H225calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *H225info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *callsinfo = NULL;
	h323_calls_info_t *tmp_h323info = NULL;
	gchar *frame_label;
	gchar *comment;
	GList *list;
	h245_address_t *h245_add = NULL;

	const h225_packet_info *pi = H225info;

	/* if not guid and RAS and not LRQ, LCF or LRJ return because did not belong to a call */
	/* OR, if not guid and is H225 return because doesn't belong to a call */
	if ((memcmp(&pi->guid, &guid_allzero, GUID_LEN) == 0))
		if ( ((pi->msg_type == H225_RAS) && ((pi->msg_tag < 18) || (pi->msg_tag > 20))) || (pi->msg_type != H225_RAS) )
			return 0;

	/* if it is RAS LCF or LRJ*/
	if ( (pi->msg_type == H225_RAS) && ((pi->msg_tag == 19) || (pi->msg_tag == 20))) {
		/* if the LCF/LRJ doesn't match to a LRQ, just return */
		if (!pi->request_available) return 0;

		/* check whether we already have a call with this request SeqNum */
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			g_assert(tmp_listinfo != NULL);
			if (tmp_listinfo->protocol == VOIP_H323){
				tmp_h323info = tmp_listinfo->prot_info;
				if (tmp_h323info->requestSeqNum == pi->requestSeqNum) {
					callsinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
			list = g_list_next (list);
		}
	} else {
		/* check whether we already have a call with this guid in the list */
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if (tmp_listinfo->protocol == VOIP_H323){
				tmp_h323info = tmp_listinfo->prot_info;
				g_assert(tmp_h323info != NULL);
				if ( (memcmp(tmp_h323info->guid, &guid_allzero, GUID_LEN) != 0) && (memcmp(tmp_h323info->guid, &pi->guid,GUID_LEN)==0) ){
					callsinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
			list = g_list_next (list);
		}
	}

	h225_cstype = pi->cs_type;
	h225_is_faststart = pi->is_faststart;

	/* not in the list? then create a new entry */
	if (callsinfo==NULL){
		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_active_state = VOIP_ACTIVE;
		callsinfo->call_state = VOIP_UNKNOWN;
		callsinfo->from_identity=g_strdup("");
		callsinfo->to_identity=g_strdup("");
		COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
		callsinfo->selected=FALSE;
		callsinfo->start_fd=pinfo->fd;
		callsinfo->protocol=VOIP_H323;
		callsinfo->prot_info=g_malloc(sizeof(h323_calls_info_t));
		callsinfo->free_prot_info = free_h225_info;

		tmp_h323info = callsinfo->prot_info;
		g_assert(tmp_h323info != NULL);
		tmp_h323info->guid = g_memdup(&pi->guid, sizeof pi->guid);
		tmp_h323info->h225SetupAddr.type = AT_NONE;
		tmp_h323info->h225SetupAddr.len = 0;
		tmp_h323info->h245_list = NULL;
		tmp_h323info->is_faststart_Setup = FALSE;
		tmp_h323info->is_faststart_Proc = FALSE;
		tmp_h323info->is_h245Tunneling = FALSE;
		tmp_h323info->is_h245 = FALSE;
		tmp_h323info->q931_crv = -1;
		tmp_h323info->q931_crv2 = -1;
		tmp_h323info->requestSeqNum = 0;
		callsinfo->call_num = tapinfo->ncalls++;
		callsinfo->npackets = 0;

		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
	}

	if (callsinfo!=NULL){

		h225_frame_num = pinfo->fd->num;
		h225_call_num = callsinfo->call_num;

		/* let's analyze the call state */

		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);


		/* XXX: it is supposed to be initialized isn't it? */
		g_assert(tmp_h323info != NULL);

		/* change the status */
		if (pi->msg_type == H225_CS){

			/* this is still IPv4 only, because the dissector is */
			if (pi->is_h245 == TRUE){
				h245_add = g_malloc(sizeof (h245_address_t));
				h245_add->h245_address.type=AT_IPv4;
				h245_add->h245_address.len=4;
				h245_add->h245_address.data = g_malloc(sizeof(pi->h245_address));
				memcpy((void *)(h245_add->h245_address.data), &(pi->h245_address), 4);
				h245_add->h245_port = pi->h245_port;
				add_h245_Address(tmp_h323info, h245_add);
			}

			if (pi->cs_type != H225_RELEASE_COMPLET) tmp_h323info->is_h245Tunneling = pi->is_h245Tunneling;

			frame_label = g_strdup(pi->frame_label);

			switch(pi->cs_type){
			case H225_SETUP:
				tmp_h323info->is_faststart_Setup = pi->is_faststart;

				/* Set the Setup address if it was not set */
				if (tmp_h323info->h225SetupAddr.type == AT_NONE)
					COPY_ADDRESS(&(tmp_h323info->h225SetupAddr), &(pinfo->src));
				callsinfo->call_state=VOIP_CALL_SETUP;
				comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
										  (pi->is_faststart==TRUE?"on":"off"));
				break;
			case H225_CONNECT:
				callsinfo->call_state=VOIP_IN_CALL;
				if (pi->is_faststart == TRUE) tmp_h323info->is_faststart_Proc = TRUE;
					comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
											  (pi->is_faststart==TRUE?"on":"off"));
				break;
			case H225_RELEASE_COMPLET:
				if (callsinfo->call_state==VOIP_CALL_SETUP){
					if (ADDRESSES_EQUAL(&(tmp_h323info->h225SetupAddr),&(pinfo->src))){  /* forward direction */
						callsinfo->call_state=VOIP_CANCELLED;
					}
					else{												/* reverse */
						callsinfo->call_state=VOIP_REJECTED;
						tapinfo->rejected_calls++;
					}
				} else {
						callsinfo->call_state=VOIP_COMPLETED;
						tapinfo->completed_calls++;
				}
				comment = g_strdup("H225 No Q931 Rel Cause");
				break;
			case H225_PROGRESS:
			case H225_ALERTING:
			case H225_CALL_PROCEDING:
				if (pi->is_faststart == TRUE) tmp_h323info->is_faststart_Proc = TRUE;
				comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
										  (pi->is_faststart==TRUE?"on":"off"));
				break;
			default:
				comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
										  (pi->is_faststart==TRUE?"on":"off"));

			}
		}
		else if (pi->msg_type == H225_RAS){
			switch(pi->msg_tag){
			case 18:  /* LRQ */
				if (!pi->is_duplicate){
					g_free(callsinfo->to_identity);
					callsinfo->to_identity=g_strdup(pi->dialedDigits);
					tmp_h323info->requestSeqNum = pi->requestSeqNum;
				}
			case 19: /* LCF */
				if (strlen(pi->dialedDigits))
					comment = g_strdup_printf("H225 RAS dialedDigits: %s", pi->dialedDigits);
				else
					comment = g_strdup("H225 RAS");
				break;
			default:
				comment = g_strdup("H225 RAS");
			}
			frame_label = g_strdup(val_to_str_const(pi->msg_tag, h225_RasMessage_vals, "<unknown>"));
		} else {
			frame_label = g_strdup("H225: Unknown");
			comment = NULL;
		}

		/* add to graph analysis */

		/* if the frame number exists in graph, append to it*/
		if (!append_to_frame_graph(tapinfo, pinfo->fd->num, pi->frame_label, comment)) {
			/* if not exist, add to the graph */
			add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
		}

		/* Add the H245 info if exists to the Graph */
		h245_add_to_graph(pinfo->fd->num);

		g_free(frame_label);
		g_free(comment);
	}

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_H225_tap_listener=FALSE;
/****************************************************************************/
void
h225_calls_init_tap(void)
{
	GString *error_string;

	if(have_H225_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("h225", &(the_tapinfo_struct.h225_dummy), NULL,
			0,
			voip_calls_dlg_reset,
			H225calls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_H225_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_h225_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.h225_dummy));
	unprotect_thread_critical_region();

	have_H225_tap_listener=FALSE;
}

/* Add the h245 label info to the graph */
void h245_add_to_graph(guint32 new_frame_num)
{
	gint8 n;

	if (new_frame_num != h245_labels.frame_num) return;

	for (n=0; n<h245_labels.labels_count; n++) {
		append_to_frame_graph(&the_tapinfo_struct, new_frame_num, h245_labels.labels[n].frame_label, h245_labels.labels[n].comment);
		g_free(h245_labels.labels[n].frame_label);
		h245_labels.labels[n].frame_label = NULL;
		g_free(h245_labels.labels[n].comment);
		h245_labels.labels[n].comment = NULL;
	}
	h245_labels.frame_num = 0;
	h245_labels.labels_count = 0;
}

/* free the h245_labels if the frame number is different */
static void h245_free_labels(guint32 new_frame_num)
{
	gint8 n;

	if (new_frame_num == h245_labels.frame_num) return;

	for (n=0; n<h245_labels.labels_count; n++) {
		g_free(h245_labels.labels[n].frame_label);
		h245_labels.labels[n].frame_label = NULL;
		g_free(h245_labels.labels[n].comment);
		h245_labels.labels[n].comment = NULL;
	}
	h245_labels.frame_num = 0;
	h245_labels.labels_count = 0;
}

/* add the frame_label and comment to h245_labels and free the actual one if it is different frame num */
static void h245_add_label(guint32 new_frame_num, const gchar *frame_label, const gchar *comment)
{
	h245_free_labels(new_frame_num);

	h245_labels.frame_num = new_frame_num;
	h245_labels.labels[h245_labels.labels_count].frame_label = g_strdup(frame_label);
	h245_labels.labels[h245_labels.labels_count].comment = g_strdup(comment);

	if (h245_labels.labels_count < (H245_MAX-1))
		h245_labels.labels_count++;

}

/****************************************************************************/
/* whenever a H245dg packet is seen by the tap listener (when H245 tunneling is ON) */
static int
H245dgcalls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *H245info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *callsinfo = NULL;
	h323_calls_info_t *tmp_h323info;
	GList *list;
	GList *list2;
	h245_address_t *h245_add = NULL;

	const h245_packet_info *pi = H245info;

	/* check if Tunneling is OFF and we have a call with this H245 add */
	list = g_list_first(tapinfo->callsinfo_list);
	while (list)
	{
		tmp_listinfo=list->data;
		if (tmp_listinfo->protocol == VOIP_H323){
			tmp_h323info = tmp_listinfo->prot_info;

			list2 = g_list_first(tmp_h323info->h245_list);
			while (list2)
			{
				h245_add=list2->data;
				if ( (ADDRESSES_EQUAL(&(h245_add->h245_address),&(pinfo->src)) && (h245_add->h245_port == pinfo->srcport))
					|| (ADDRESSES_EQUAL(&(h245_add->h245_address),&(pinfo->dst)) && (h245_add->h245_port == pinfo->destport)) ){
					callsinfo = (voip_calls_info_t*)(list->data);

					++(callsinfo->npackets);
					/* increment the packets counter of all calls */
					++(tapinfo->npackets);

					break;
				}
				list2 = g_list_next(list2);
			}
			if (callsinfo!=NULL) break;
		}
		list = g_list_next(list);
	}

	/* Tunnel is OFF, and we matched the h245 add so we add it to graph */
	if (callsinfo!=NULL){
		++(callsinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);
		/* if the frame number exists in graph, append to it*/
		if (!append_to_frame_graph(tapinfo, pinfo->fd->num, pi->frame_label, pi->comment)) {
			/* if not exist, add to the graph */
			add_to_graph(tapinfo, pinfo, pi->frame_label, pi->comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
		}
	} else {
	/* Tunnel is ON, so we save the label info to use it into h225 or q931 tap. OR may be
		 tunnel OFF but we did not matched the h245 add, in this case nobady will set this label
		 since the frame_num will not match */

		h245_add_label(pinfo->fd->num, (gchar *) pi->frame_label, (gchar *) pi->comment);
	}

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_H245dg_tap_listener=FALSE;
/****************************************************************************/
void
h245dg_calls_init_tap(void)
{
	GString *error_string;

	if(have_H245dg_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("h245dg", &(the_tapinfo_struct.h245dg_dummy), NULL,
			0,
			voip_calls_dlg_reset,
			H245dgcalls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_H245dg_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_h245dg_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.h245dg_dummy));
	unprotect_thread_critical_region();

	have_H245dg_tap_listener=FALSE;
}

/****************************************************************************/
/****************************TAP for SDP PROTOCOL ***************************/
/****************************************************************************/
/* whenever a SDP packet is seen by the tap listener */
static int
SDPcalls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *SDPinfo)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	const sdp_packet_info *pi = SDPinfo;

	/* There are protocols like MGCP/SIP where the SDP is called before the tap for the
	   MGCP/SIP packet, in those cases we assign the SPD summary to global lastSDPsummary
	   to use it later
	*/
	g_free(sdp_summary);
	sdp_frame_num = pinfo->fd->num;
	/* Append to graph the SDP summary if the packet exists */
	sdp_summary = g_strdup_printf("SDP (%s)", pi->summary_str);
	append_to_frame_graph(tapinfo, pinfo->fd->num, sdp_summary, NULL);

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_sdp_tap_listener=FALSE;
/****************************************************************************/
void
sdp_calls_init_tap(void)
{
	GString *error_string;

	if(have_sdp_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("sdp", &(the_tapinfo_struct.sdp_dummy), NULL,
			0,
			voip_calls_dlg_reset,
			SDPcalls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_sdp_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_sdp_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.sdp_dummy));
	unprotect_thread_critical_region();

	have_sdp_tap_listener=FALSE;
}



/****************************************************************************/
/* ***************************TAP for MGCP **********************************/
/****************************************************************************/

/*
   This function will look for a signal/event in the SignalReq/ObsEvent string
   and return true if it is found
*/
static gboolean isSignal(const gchar *signal_str_p, const gchar *signalStr)
{
	gint i;
	gchar **resultArray;

	/* if there is no signalStr, just return false */
	if (signalStr == NULL) return FALSE;

	/* if are both "blank" return true */
	if ( (*signal_str_p == '\0') &&  (*signalStr == '\0') ) return TRUE;

	/* look for signal in signalStr */
	resultArray = g_strsplit(signalStr, ",", 10);

	for (i = 0; resultArray[i]; i++) {
		g_strstrip(resultArray[i]);
		if (strcmp(resultArray[i], signal_str_p) == 0) return TRUE;
	}

	g_strfreev(resultArray);

	return FALSE;
}

/*
   This function will get the Caller ID info and replace the current string
   This is how it looks the caller Id: rg, ci(02/16/08/29, "3035550002","Ale Sipura 2")
*/
static void mgcpCallerID(gchar *signalStr, gchar **callerId)
{
	gchar **arrayStr;

	/* if there is no signalStr, just return false */
	if (signalStr == NULL) return;

	arrayStr = g_strsplit(signalStr, "\"", 10);

	if (arrayStr[0] == NULL) return;

	/* look for the ci signal */
	if (strstr(arrayStr[0], "ci(") && (arrayStr[1] != NULL) ) {
		/* free the previous "From" field of the call, and assign the new */
		g_free(*callerId);
		*callerId = g_strdup(arrayStr[1]);
	}
	g_strfreev(arrayStr);

	return;
}


/*
   This function will get the Dialed Digits and replace the current string
   This is how it looks the dialed digits 5,5,5,0,0,0,2,#,*
*/
static void mgcpDialedDigits(gchar *signalStr, gchar **dialedDigits)
{
	gchar *tmpStr;
	gchar resultStr[50];
	gint i,j;

	/* if there is no signalStr, just return false */
	if (signalStr == NULL) return;

	tmpStr = g_strdup(signalStr);

	for ( i = 0 ; tmpStr[i] ; i++) {
		switch (tmpStr[i]) {
			case '0' : case '1' : case '2' : case '3' : case '4' :
			case '5' : case '6' : case '7' : case '8' : case '9' :
			case '#' : case '*' :
				break;
			default:
				tmpStr[i] = '?';
				break;
		}
	}

	for (i = 0, j = 0; tmpStr[i] && i<50; i++) {
		if (tmpStr[i] != '?')
			resultStr[j++] = tmpStr[i];
	}
	resultStr[j] = '\0';

	if (*resultStr == '\0') return;

	g_free(*dialedDigits);
	*dialedDigits = g_strdup(resultStr);
	g_free(tmpStr);

	return;
}



/****************************************************************************/
/* whenever a MGCP packet is seen by the tap listener */
static int
MGCPcalls_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *MGCPinfo)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;

	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *callsinfo = NULL;
	mgcp_calls_info_t *tmp_mgcpinfo = NULL;
	GList *list;
	GList *listGraph;
	gchar *frame_label = NULL;
	gchar *comment = NULL;
	graph_analysis_item_t *gai;
	gboolean new = FALSE;
	gboolean fromEndpoint = FALSE; /* true for calls originated in Endpoints, false for calls from MGC */
	gdouble diff_time;

	const mgcp_info_t *pi = MGCPinfo;


	if ((pi->mgcp_type == MGCP_REQUEST) && !pi->is_duplicate ){
		/* check whether we already have a call with this Endpoint and it is active*/
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if ((tmp_listinfo->protocol == VOIP_MGCP) && (tmp_listinfo->call_active_state == VOIP_ACTIVE)){
				tmp_mgcpinfo = tmp_listinfo->prot_info;
				if (pi->endpointId != NULL){
					if (g_ascii_strcasecmp(tmp_mgcpinfo->endpointId,pi->endpointId) == 0){
						/*
						   check first if it is an ended call. We can still match packets to this Endpoint 2 seconds
						   after the call has been released
						*/
						diff_time = nstime_to_sec(&pinfo->fd->rel_ts) - nstime_to_sec(&tmp_listinfo->stop_fd->rel_ts);
						if ( ((tmp_listinfo->call_state == VOIP_CANCELLED) ||
						     (tmp_listinfo->call_state == VOIP_COMPLETED)  ||
						     (tmp_listinfo->call_state == VOIP_REJECTED)) &&
						       (diff_time > 2) )
						{
							tmp_listinfo->call_active_state = VOIP_INACTIVE;
						} else {
							callsinfo = (voip_calls_info_t*)(list->data);
							break;
						}
					}
				}
			}
			list = g_list_next (list);
		}

		/* there is no call with this Endpoint, lets see if this a new call or not */
		if (callsinfo == NULL){
			if ( (strcmp(pi->code, "NTFY") == 0) && isSignal("hd", pi->observedEvents) ){ /* off hook transition */
				/* this is a new call from the Endpoint */
				fromEndpoint = TRUE;
				new = TRUE;
			} else if (strcmp(pi->code, "CRCX") == 0){
				/* this is a new call from the MGC */
				fromEndpoint = FALSE;
				new = TRUE;
			}
			if (!new) return 0;
		}
	} else if ( ((pi->mgcp_type == MGCP_RESPONSE) && pi->request_available) ||
			((pi->mgcp_type == MGCP_REQUEST) && pi->is_duplicate) ) {
		/* if it is a response OR if it is a duplicated Request, lets look in the Graph to see
		   if there is a request that matches */
		listGraph = g_list_first(tapinfo->graph_analysis->list);
		while (listGraph)
		{
			gai = listGraph->data;
			if (gai->fd->num == pi->req_num){
				/* there is a request that match, so look the associated call with this call_num */
				list = g_list_first(tapinfo->callsinfo_list);
				while (list)
				{
					tmp_listinfo=list->data;
					if (tmp_listinfo->protocol == VOIP_MGCP){
						if (tmp_listinfo->call_num == gai->conv_num){
							tmp_mgcpinfo = tmp_listinfo->prot_info;
							callsinfo = (voip_calls_info_t*)(list->data);
							break;
						}
					}
					list = g_list_next (list);
				}
				if (callsinfo != NULL) break;
			}
			listGraph = g_list_next(listGraph);
		}
		/* if there is not a matching request, just return */
		if (callsinfo == NULL) return 0;
	} else return 0;

	/* not in the list? then create a new entry */
	if (callsinfo==NULL){
		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_active_state = VOIP_ACTIVE;
		callsinfo->call_state = VOIP_CALL_SETUP;
		if (fromEndpoint) {
			callsinfo->from_identity=g_strdup(pi->endpointId);
			callsinfo->to_identity=g_strdup("");
		} else {
			callsinfo->from_identity=g_strdup("");
			callsinfo->to_identity=g_strdup(pi->endpointId);
		}
		COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
		callsinfo->selected=FALSE;
		callsinfo->start_fd=pinfo->fd;
		callsinfo->protocol=VOIP_MGCP;
		callsinfo->prot_info=g_malloc(sizeof(mgcp_calls_info_t));
		callsinfo->free_prot_info = g_free;
		tmp_mgcpinfo=callsinfo->prot_info;
		tmp_mgcpinfo->endpointId = g_strdup(pi->endpointId);
		tmp_mgcpinfo->fromEndpoint = fromEndpoint;
		callsinfo->npackets = 0;
		callsinfo->call_num = tapinfo->ncalls++;
		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
	}

	g_assert(tmp_mgcpinfo != NULL);

	/* change call state and add to graph */
	switch (pi->mgcp_type)
	{
	case MGCP_REQUEST:
		if ( (strcmp(pi->code, "NTFY") == 0) && (pi->observedEvents != NULL) ){
			frame_label = g_strdup_printf("%s ObsEvt:%s",pi->code, pi->observedEvents);

			if (tmp_mgcpinfo->fromEndpoint){
				/* use the Dialed digits to fill the "To" for the call, but use the first NTFY */
				if (callsinfo->to_identity[0] == '\0') mgcpDialedDigits(pi->observedEvents, &(callsinfo->to_identity));

			/* from MGC and the user picked up, the call is connected */
			} else if (isSignal("hd", pi->observedEvents))
				callsinfo->call_state=VOIP_IN_CALL;

			/* hung up signal */
			if (isSignal("hu", pi->observedEvents)) {
				if ((callsinfo->call_state == VOIP_CALL_SETUP) || (callsinfo->call_state == VOIP_RINGING)){
					callsinfo->call_state = VOIP_CANCELLED;
				} else {
					callsinfo->call_state = VOIP_COMPLETED;
				}
			}

		} else if (strcmp(pi->code, "RQNT") == 0) {
			/* for calls from Endpoint: if there is a "no signal" RQNT and the call was RINGING, we assume this is the CONNECT */
			if ( tmp_mgcpinfo->fromEndpoint && isSignal("", pi->signalReq) && (callsinfo->call_state == VOIP_RINGING) ) {
					callsinfo->call_state = VOIP_IN_CALL;
			}

			/* if there is ringback or ring tone, change state to ringing */
			if ( isSignal("rg", pi->signalReq) || isSignal("rt", pi->signalReq) ) {
					callsinfo->call_state = VOIP_RINGING;
			}

			/* if there is a Busy or ReorderTone, and the call was Ringing or Setup the call is Rejected */
			if ( (isSignal("ro", pi->signalReq) || isSignal("bz", pi->signalReq)) && ((callsinfo->call_state == VOIP_CALL_SETUP) || (callsinfo->call_state == VOIP_RINGING)) ) {
					callsinfo->call_state = VOIP_REJECTED;
			}

			if (pi->signalReq != NULL)
				frame_label = g_strdup_printf("%s%sSigReq:%s",pi->code, (pi->hasDigitMap == TRUE)?" DigitMap ":"", pi->signalReq);
			else
				frame_label = g_strdup_printf("%s%s",pi->code, (pi->hasDigitMap == TRUE)?" DigitMap ":"");

			/* use the CallerID info to fill the "From" for the call */
			if (!tmp_mgcpinfo->fromEndpoint) mgcpCallerID(pi->signalReq, &(callsinfo->from_identity));

		} else if (strcmp(pi->code, "DLCX") == 0) {
			/*
			  if there is a DLCX in a call To an Endpoint and the call was not connected, we use
			  the DLCX as the end of the call
			*/
			if (!tmp_mgcpinfo->fromEndpoint){
				if ((callsinfo->call_state == VOIP_CALL_SETUP) || (callsinfo->call_state == VOIP_RINGING)){
					callsinfo->call_state = VOIP_CANCELLED;
				}
			}
		}

		if (frame_label == NULL) frame_label = g_strdup(pi->code);
		break;
	case MGCP_RESPONSE:
		frame_label = g_strdup_printf("%u (%s)",pi->rspcode, pi->code);
		break;
	case MGCP_OTHERS:
		/* XXX what to do? */
		break;
	}


	comment = g_strdup_printf("MGCP %s %s%s", tmp_mgcpinfo->endpointId, (pi->mgcp_type == MGCP_REQUEST)?"Request":"Response", pi->is_duplicate?" Duplicate":"");

	callsinfo->stop_fd = pinfo->fd;
	++(callsinfo->npackets);
	/* increment the packets counter of all calls */
	++(tapinfo->npackets);

	/* add to the graph */
	add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
	g_free(comment);
	g_free(frame_label);

	/* add SDP info if apply */
	if ( (sdp_summary != NULL) && (sdp_frame_num == pinfo->fd->num) ){
			append_to_frame_graph(tapinfo, pinfo->fd->num, sdp_summary, NULL);
			g_free(sdp_summary);
			sdp_summary = NULL;
	}

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_MGCP_tap_listener=FALSE;
/****************************************************************************/
void
mgcp_calls_init_tap(void)
{
	GString *error_string;

	if(have_MGCP_tap_listener==FALSE)
	{
		/*
		 * Don't register the tap listener if we have it already.
		 * We set TL_REQUIRES_PROTO_TREE to force a non-null "tree"
		 * in the MGCP dissector; otherwise, the dissector
		 * doesn't fill in the info passed to the tap's packet
		 * routine.
		 */
		error_string = register_tap_listener("mgcp",
			&(the_tapinfo_struct.mgcp_dummy),
			NULL,
			TL_REQUIRES_PROTO_TREE,
			voip_calls_dlg_reset,
			MGCPcalls_packet,
			voip_calls_dlg_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_MGCP_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_mgcp_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.mgcp_dummy));
	unprotect_thread_critical_region();

	have_MGCP_tap_listener=FALSE;
}


/****************************************************************************/
/****************************TAP for ACTRACE (AudioCodes trace)**************/
/****************************************************************************/

/* whenever a ACTRACE packet is seen by the tap listener */
static int
ACTRACEcalls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *ACTRACEinfo)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	const actrace_info_t *pi = ACTRACEinfo;
	GList *list;
	actrace_cas_calls_info_t *tmp_actrace_cas_info;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *callsinfo = NULL;


	actrace_frame_num = pinfo->fd->num;
	actrace_trunk = pi->trunk;
	actrace_direction = pi->direction;

	if (pi->type == 1){ /* is CAS protocol */
		address pstn_add;
		gchar *comment = NULL;

		callsinfo = NULL;
		list = g_list_first(tapinfo->callsinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if ( tmp_listinfo->protocol == VOIP_AC_CAS ){
				tmp_actrace_cas_info = tmp_listinfo->prot_info;
				/* TODO: Also check the IP of the Blade, and if the call is complete (no active) */
				if ( (tmp_actrace_cas_info->bchannel == pi->cas_bchannel) && (tmp_actrace_cas_info->trunk == actrace_trunk) ) {
					callsinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
			list = g_list_next (list);
		}

		SET_ADDRESS(&pstn_add, AT_STRINGZ, 5, "PSTN");

		/* if it is a new call, add it to the list */
		if (!callsinfo) {
			callsinfo = g_malloc0(sizeof(voip_calls_info_t));
			callsinfo->call_active_state = VOIP_ACTIVE;
			callsinfo->call_state = VOIP_CALL_SETUP;
			callsinfo->from_identity=g_strdup("N/A");
			callsinfo->to_identity=g_strdup("N/A");
			COPY_ADDRESS(&(callsinfo->initial_speaker),actrace_direction?&pstn_add:&(pinfo->src));
			callsinfo->selected=FALSE;
			callsinfo->start_fd=pinfo->fd;
			callsinfo->protocol=VOIP_AC_CAS;
			callsinfo->prot_info=g_malloc(sizeof(actrace_cas_calls_info_t));
			callsinfo->free_prot_info = g_free;

			tmp_actrace_cas_info=callsinfo->prot_info;
			tmp_actrace_cas_info->bchannel=pi->cas_bchannel;
			tmp_actrace_cas_info->trunk=actrace_trunk;
			callsinfo->npackets = 0;
			callsinfo->call_num = tapinfo->ncalls++;
			tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
		}

		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);

		comment = g_strdup_printf("AC_CAS  trunk:%u", actrace_trunk);

		add_to_graph(tapinfo, pinfo, pi->cas_frame_label, comment, callsinfo->call_num,
				actrace_direction?&pstn_add:&(pinfo->src),
				actrace_direction?&(pinfo->src):&pstn_add,
				1 );

		g_free(comment);
	}

	tapinfo->redraw = TRUE;

	return 1;  /* refresh output */
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_actrace_tap_listener=FALSE;
/****************************************************************************/
void
actrace_calls_init_tap(void)
{
	GString *error_string;

	if(have_actrace_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("actrace", &(the_tapinfo_struct.actrace_dummy), NULL,
			0,
			voip_calls_dlg_reset,
			ACTRACEcalls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_actrace_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_actrace_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.actrace_dummy));
	unprotect_thread_critical_region();

	have_actrace_tap_listener=FALSE;
}


/****************************************************************************/
/**************************** TAP for H248/MEGACO **********************************/
/****************************************************************************/
static gboolean have_h248_tap_listener = FALSE;
static gboolean have_megaco_tap_listener = FALSE;

#define gcp_is_req(type) ( type == GCP_CMD_ADD_REQ || type == GCP_CMD_MOVE_REQ || type == GCP_CMD_MOD_REQ || \
							type == GCP_CMD_SUB_REQ || type == GCP_CMD_AUDITCAP_REQ || type == GCP_CMD_AUDITVAL_REQ || \
							type == GCP_CMD_NOTIFY_REQ || type == GCP_CMD_SVCCHG_REQ || type == GCP_CMD_TOPOLOGY_REQ || \
							type == GCP_CMD_CTX_ATTR_AUDIT_REQ )

static int h248_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prot_info) {
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	const gcp_cmd_t *cmd = prot_info;
	GList *list;
	voip_calls_info_t *callsinfo = NULL;
	address *mgw;
	address *mgc;
	gchar mgw_addr[128];

	if (cmd->ctx->id == NULL_CONTEXT || cmd->ctx->id == ALL_CONTEXTS ) {
		return 0;
	}

	if ( gcp_is_req(cmd->type) ) {
		mgw = &(pinfo->dst);
		mgc = &(pinfo->src);
	} else {
		mgc = &(pinfo->dst);
		mgw = &(pinfo->src);
	}

	address_to_str_buf(mgw, mgw_addr, 128);

	/* check whether we already have this context in the list */
	list = g_list_first(tapinfo->callsinfo_list);
	while (list)
	{
		voip_calls_info_t* tmp_listinfo = list->data;

		if (tmp_listinfo->protocol == TEL_H248){
			if (tmp_listinfo->prot_info == cmd->ctx){
				callsinfo = (voip_calls_info_t*)(list->data);
				break;
			}
		}
		list = g_list_next (list);
	}

	if (callsinfo==NULL){

		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_state = VOIP_NO_STATE;
		callsinfo->call_active_state = VOIP_ACTIVE;
		callsinfo->from_identity = g_strdup_printf("%s : %.8x", mgw_addr, cmd->ctx->id);
		callsinfo->to_identity = g_strdup("");
		callsinfo->prot_info = cmd->ctx;
		callsinfo->free_prot_info = NULL;

		callsinfo->npackets = 1;

		COPY_ADDRESS(&(callsinfo->initial_speaker), mgc);

		callsinfo->protocol = TEL_H248;
		callsinfo->call_num = tapinfo->ncalls++;
		callsinfo->start_fd = pinfo->fd;
		callsinfo->stop_fd = pinfo->fd;

		callsinfo->selected = FALSE;

		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);

	} else {
		GString *s = g_string_new("");
		gcp_terms_t *ctx_term;

		g_free(callsinfo->from_identity);
		callsinfo->from_identity = g_strdup_printf("%s : %.8x", mgw_addr, ((gcp_ctx_t*)callsinfo->prot_info)->id);

		g_free(callsinfo->to_identity);

		for (ctx_term = ((gcp_ctx_t*)callsinfo->prot_info)->terms.next;
			 ctx_term;
			 ctx_term = ctx_term->next ) {
			if ( ctx_term->term && ctx_term->term->str) {
				g_string_append_printf(s," %s",ctx_term->term->str);
			}
		}

		callsinfo->to_identity = s->str;
		g_string_free(s,FALSE);

		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
	}

	add_to_graph(tapinfo, pinfo, cmd->str ? cmd->str : "unknown Msg",
				 ep_strdup_printf("TrxId = %u, CtxId = %.8x",cmd->trx->id,cmd->ctx->id),
				 callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

	++(tapinfo->npackets);

	tapinfo->redraw = TRUE;

	return 1;
}

void h248_calls_init_tap(void)
{
	GString *error_string;


	if(have_megaco_tap_listener==FALSE)
	{
		error_string = register_tap_listener("megaco", &(the_tapinfo_struct.megaco_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			h248_calls_packet,
			voip_calls_dlg_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}

		have_megaco_tap_listener=TRUE;
	}

	if(have_h248_tap_listener==FALSE)
	{
		error_string = register_tap_listener("h248", &(the_tapinfo_struct.h248_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			h248_calls_packet,
			voip_calls_dlg_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}

		have_h248_tap_listener=TRUE;
	}
}

void
remove_tap_listener_h248_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.h248_dummy));
	remove_tap_listener(&(the_tapinfo_struct.megaco_dummy));
	unprotect_thread_critical_region();

	have_megaco_tap_listener=FALSE;
	have_h248_tap_listener=FALSE;
}

/****************************************************************************/
/**************************** TAP for SCCP and SUA **********************************/
/**************************** ( RANAP and BSSAP ) **********************************/
/****************************************************************************/

static gboolean have_sccp_tap_listener = FALSE;
static gboolean have_sua_tap_listener = FALSE;

static const voip_protocol sccp_proto_map[] = {
	TEL_SCCP,
	TEL_BSSMAP,
	TEL_RANAP
};
#define SP2VP(ap) ((ap) < SCCP_PLOAD_NUM_PLOADS ? sccp_proto_map[(ap)] : TEL_SCCP)
const value_string* sccp_payload_values;

static int sccp_calls(packet_info *pinfo, const void *prot_info) {
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	const sccp_msg_info_t* msg = prot_info;
	sccp_assoc_info_t* assoc = msg->data.co.assoc;
	GList *list;
	voip_calls_info_t *callsinfo = NULL;
	const gchar *label = NULL;
	const gchar *comment = NULL;
	/* check whether we already have this assoc in the list */

	for(list = g_list_first(tapinfo->callsinfo_list) ; list ; list = g_list_next (list) ) {
		if ( ((voip_calls_info_t*)(list->data))->prot_info == assoc ){
				callsinfo = (voip_calls_info_t*)(list->data);
				break;
		}
	}

	if (callsinfo==NULL){
		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_state = VOIP_CALL_SETUP;
		callsinfo->call_active_state = VOIP_ACTIVE;
		if ( assoc->calling_party ) {
			callsinfo->from_identity =  g_strdup(assoc->calling_party);
		} else {
			callsinfo->from_identity =  g_strdup("Unknown");
		}

		if ( assoc->called_party ) {
			callsinfo->to_identity =  g_strdup(assoc->called_party);
		} else {
			callsinfo->to_identity =  g_strdup("Unknown");
		}

		callsinfo->prot_info = (void*)assoc;
		callsinfo->free_prot_info = NULL;

		callsinfo->npackets = 1;

		COPY_ADDRESS(&(callsinfo->initial_speaker), &(pinfo->src));

		callsinfo->protocol =   SP2VP(assoc->payload);
		/* Store frame data which holds time and frame number */
		callsinfo->start_fd = pinfo->fd;
		callsinfo->stop_fd = pinfo->fd;

		callsinfo->selected = FALSE;
		callsinfo->call_num = tapinfo->ncalls++;

		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
	} else {

		if ( assoc->calling_party ) {
			g_free(callsinfo->from_identity);
			callsinfo->from_identity =  g_strdup(assoc->calling_party);
		}

		if ( assoc->called_party ) {
			g_free(callsinfo->to_identity);
			callsinfo->to_identity =  g_strdup(assoc->called_party);
		}

		callsinfo->protocol =  SP2VP(assoc->payload);
		/* Store frame data which holds stop time and frame number */
		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);

		switch (msg->type) {
			case SCCP_MSG_TYPE_CC:
				callsinfo->call_state = VOIP_IN_CALL;
				break;
			case SCCP_MSG_TYPE_RLC:
				callsinfo->call_state = VOIP_COMPLETED;
				callsinfo->call_active_state = VOIP_INACTIVE;
				break;
			default:
				break;
		}
	}

	if (msg->data.co.label) {
		label = msg->data.co.label;
	} else {
		label = val_to_str(msg->type, sccp_payload_values, "Unknown(%d)");
	}

	if (msg->data.co.comment) {
		comment = msg->data.co.comment;
	} else {
		comment = NULL;
	}

	add_to_graph(tapinfo, pinfo, label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

	++(tapinfo->npackets);

	tapinfo->redraw = TRUE;

	return 1;
}

static int sccp_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prot_info) {
	sccp_payload_values = sccp_message_type_acro_values;
	return sccp_calls(pinfo, prot_info);
}


static int sua_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prot_info) {
	sccp_payload_values = sua_co_class_type_acro_values;
	return sccp_calls(pinfo, prot_info);
}


void sccp_calls_init_tap(void)
{
	GString *error_string;

	if(have_sccp_tap_listener==FALSE)
	{
		error_string = register_tap_listener("sccp", &(the_tapinfo_struct.sccp_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			sccp_calls_packet,
			voip_calls_dlg_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}

		have_sccp_tap_listener=TRUE;
	}

	if(have_sua_tap_listener==FALSE)
	{
		error_string = register_tap_listener("sua", &(the_tapinfo_struct.sua_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			sua_calls_packet,
			voip_calls_dlg_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}

		have_sua_tap_listener=TRUE;
	}

}

void
remove_tap_listener_sccp_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.sccp_dummy));
	unprotect_thread_critical_region();

	have_sccp_tap_listener=FALSE;
	have_sua_tap_listener=FALSE;
}


/****************************************************************************/
/****************************TAP for UNISTIM ********************************/
/****************************************************************************/

static int
unistim_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *unistim_info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *callsinfo = NULL;
	unistim_info_t *tmp_unistim_info = NULL;
	GList *list = NULL;
	GString *g_tmp = NULL;
	gchar *frame_label = NULL;
	gchar *comment = NULL;

	/* Fetch specific packet infos */
	const unistim_info_t *pi = unistim_info;

	/* Init gstring */
	g_tmp = g_string_new(NULL);

	/* Check to see if this is a dup */
	list = g_list_first(tapinfo->callsinfo_list);

	while(list)
	{
		tmp_listinfo = list->data;

		if(tmp_listinfo->protocol == VOIP_UNISTIM){

			tmp_unistim_info = tmp_listinfo->prot_info;

			/* Search by termid if possible, otherwise use ni/it ip + port.. */
			if(pi->termid != 0){
				if(tmp_unistim_info->termid == pi->termid){
					/* If the call has ended, then we can reuse it.. */
					if(tmp_listinfo->call_state == VOIP_COMPLETED || tmp_listinfo->call_state == VOIP_UNKNOWN){
						/* Do nothing */
					} else {
						callsinfo = (voip_calls_info_t*)(list->data);
						break;
					}
				}
			} else {
				/* If no term id use ips / port to find entry */
				if(ADDRESSES_EQUAL(&tmp_unistim_info->it_ip, &pinfo->dst) && ADDRESSES_EQUAL(&tmp_unistim_info->ni_ip,&pinfo->src) && (tmp_unistim_info->it_port == pinfo->destport)){
					if(tmp_listinfo->call_state == VOIP_COMPLETED || tmp_listinfo->call_state == VOIP_UNKNOWN){
						/* Do nothing previous call */
					} else {
						callsinfo = (voip_calls_info_t*)(list->data);
						break;
					}
				}
				else if(ADDRESSES_EQUAL(&tmp_unistim_info->it_ip, &pinfo->src) && ADDRESSES_EQUAL(&tmp_unistim_info->ni_ip,&pinfo->dst) && (tmp_unistim_info->it_port == pinfo->srcport)) {
					if(tmp_listinfo->call_state == VOIP_COMPLETED || tmp_listinfo->call_state == VOIP_UNKNOWN){
						/* Do nothing, it ain't our call.. */
					} else {
						callsinfo = (voip_calls_info_t*)(list->data);
						break;
					}
				}
			}
		}

		/* Otherwise, go to the next one.. */
		list = g_list_next(list);
	}

	if(pi->payload_type == 2 || pi->payload_type == 1){

		if(pi->key_state == 1 || pi->hook_state == 1){

			/* If the user hits a button,
			   Session will be SETUP */

			/* If new add to list */
			if (callsinfo==NULL){

				callsinfo = g_malloc0(sizeof(voip_calls_info_t));
				callsinfo->call_active_state = VOIP_ACTIVE;
				callsinfo->call_state = VOIP_CALL_SETUP;
				callsinfo->from_identity=g_strdup_printf("%x",pi->termid);
				callsinfo->to_identity=g_strdup("UNKNOWN");
				COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
				callsinfo->selected=FALSE;

				/* Set this on init of struct so in case the call doesn't complete, we'll have a ref. */
				/* Otherwise if the call is completed we'll have the open/close streams to ref actual call duration */
				/* Store frame data which holds time and frame number */
				callsinfo->start_fd=pinfo->fd;

				callsinfo->protocol=VOIP_UNISTIM;
				callsinfo->prot_info=g_malloc(sizeof(unistim_info_t));

				tmp_unistim_info = callsinfo->prot_info;

				/* Clear tap struct */
				tmp_unistim_info->rudp_type = 0;
				tmp_unistim_info->payload_type = 0;
				tmp_unistim_info->sequence = pi->sequence;
				tmp_unistim_info->termid = pi->termid;
				tmp_unistim_info->key_val = -1;
				tmp_unistim_info->key_state = -1;
				tmp_unistim_info->hook_state = -1;
				tmp_unistim_info->stream_connect = -1;
				tmp_unistim_info->trans_connect = -1;
				tmp_unistim_info->set_termid = -1;
				tmp_unistim_info->string_data = NULL;
				tmp_unistim_info->key_buffer = NULL;

				COPY_ADDRESS(&(tmp_unistim_info->it_ip),&(pi->it_ip));
				COPY_ADDRESS(&(tmp_unistim_info->ni_ip),&(pi->ni_ip));
				tmp_unistim_info->it_port = pi->it_port;

				callsinfo->free_prot_info = g_free;
				callsinfo->npackets = 0;
				callsinfo->call_num = tapinfo->ncalls++;
				tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);

			} else {

				/* Set up call wide info struct */
				tmp_unistim_info = callsinfo->prot_info;
				tmp_unistim_info->sequence = pi->sequence;
			}

			/* Each packet COULD BE OUR LAST!!!! */
			/* Store frame data which holds time and frame number */
			callsinfo->stop_fd = pinfo->fd;

			/* This is a valid packet so increment counter */
			++(callsinfo->npackets);

			/* increment the packets counter of all calls */
			++(tapinfo->npackets);

			/* Key was depressed.. update key buffer.. */
			if(pi->key_val >= 0 && pi->key_val <= 11){

				if(tmp_unistim_info->key_buffer != NULL){

					/* assign to temp variable */
					g_string_assign(g_tmp,tmp_unistim_info->key_buffer);

					/* Manipulate the data */
					if(pi->key_val == 10) {
						tmp_unistim_info->key_buffer = g_strdup_printf("%s*",g_tmp->str);
					} else if(pi->key_val == 11) {
						tmp_unistim_info->key_buffer = g_strdup_printf("%s#",g_tmp->str);
					} else {
						tmp_unistim_info->key_buffer = g_strdup_printf("%s%d",g_tmp->str,pi->key_val);
					}

				} else {

					/* Create new string */
					if(pi->key_val == 10) {
						tmp_unistim_info->key_buffer = g_strdup("*");
					} else if(pi->key_val == 11) {
						tmp_unistim_info->key_buffer = g_strdup("#");
					} else {
						tmp_unistim_info->key_buffer = g_strdup_printf("%d",pi->key_val);
					}

				}

				/* Select for non-digit characters */
				if(pi->key_val == 10) {
					comment = g_strdup_printf("Key Input Sent: * (%d)", pi->sequence);
				} else if(pi->key_val == 11) {
					comment = g_strdup_printf("Key Input Sent: # (%d)", pi->sequence);
				} else {
					comment = g_strdup_printf("Key Input Sent: %d (%d)",pi->key_val, pi->sequence);
				}
			} else if(pi->key_val == 12) {
				/* Set label and comment for graph */
				comment = g_strdup_printf("Key Input Sent: UP (%d)", pi->sequence);
			} else if(pi->key_val == 13) {
				/* Set label and comment for graph */
				comment = g_strdup_printf("Key Input Sent: DOWN (%d)", pi->sequence);
			} else if(pi->key_val == 14) {
				/* Set label and comment for graph */
				comment = g_strdup_printf("Key Input Sent: RIGHT (%d)", pi->sequence);
			} else if(pi->key_val == 15) {
				if(pi->key_buffer != NULL){
					/* Get data */
					g_string_assign(g_tmp,pi->key_buffer);

					/* Manipulate the data */
					g_string_truncate(g_tmp,g_tmp->len-1);

					/* Insert new data */
					tmp_unistim_info->key_buffer = g_strdup(g_tmp->str);
				}

				/* Set label and comment for graph */
				comment = g_strdup_printf("Key Input Sent: LEFT (%d)", pi->sequence);
			} else if(pi->key_val == 20) {
				/* User pressed the soft key 0 probably dial */
				comment = g_strdup_printf("Key Input Sent: S0 (%d)", pi->sequence);
			} else if(pi->key_val == 21) {
				/* User pressed the soft key 1 */
				comment = g_strdup_printf("Key Input Sent: S1 (%d)", pi->sequence);
			} else if(pi->key_val == 22) {
				/* User pressed the soft key 2 */
				/* On cs2k phones, soft key 2 is backspace. */
				if(pi->key_buffer != NULL) {

					/* Get data */
					g_string_assign(g_tmp,pi->key_buffer);

					/* Manipulate the data */
					g_string_truncate(g_tmp,g_tmp->len-1);

					/* Insert new data */
					tmp_unistim_info->key_buffer = g_strdup(g_tmp->str);
				}

				/* add label and comment */
				comment = g_strdup_printf("Key Input Sent: S2 (%d)", pi->sequence);
			} else if(pi->key_val == 28) {
				/* User pressed something */
				comment = g_strdup_printf("Key Input Sent: Release (%d)", pi->sequence);
			} else if(pi->key_val == 23) {
				/* User pressed the soft key 3 */
				/* Cancel on cs2k so clear buffer */
				/* On mcs its config which will clear the buffer too */
				tmp_unistim_info->key_buffer = g_strdup("\n");

				/* User pressed something, set labels*/
				comment = g_strdup_printf("Key Input Sent: S3 (%d)", pi->sequence);
			} else if(pi->key_val == 27) {
				/* User pressed something */
				comment = g_strdup_printf("Key Input Sent: Hold (%d)", pi->sequence);
			} else if(pi->key_val == 29) {
				/* User pressed something */
				comment = g_strdup_printf("Key Input Sent: Mute (%d)", pi->sequence);
			} else if(pi->key_val == 30) {
				/* User pressed something */
				comment = g_strdup_printf("Key Input Sent: Headset (%d)", pi->sequence);
			} else if(pi->key_val == 31) {
				/* Handsfree button */
				comment = g_strdup_printf("Key Input Sent: Handsfree (%d)", pi->sequence);
			} else if(pi->key_val >= 32 && pi->key_val <= 56) {
				/* Prog. Key X */
				comment = g_strdup_printf("Key Input Sent: Prog%d (%d)", (pi->key_val & 31), pi->sequence);
			}

			if(pi->key_val != -1) {

				frame_label = "KEY INPUT";

				if (comment == NULL)
					/* Ouch! What do you do!? */
					/* User pressed something */
					comment = g_strdup_printf("Key Input Sent: UNKNOWN - %d (%d)", pi->key_val, pi->sequence);

				/* add to the graph */
				add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

				g_free(comment);
			}

			if(pi->hook_state == 1) {

				/* Phone is off hook */
				frame_label = "OFF HOOK";
				comment = g_strdup_printf("Off Hook (%d)", pi->sequence);

				/* add to the graph */
				add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

				g_free(comment);
			} else if(pi->hook_state == 0) {

				/* Phone is on hook */
				frame_label = "ON HOOK";
				comment = g_strdup_printf("On Hook (%d)", pi->sequence);

				/* add to the graph */
				add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

				g_free(comment);
			}
		}

		/* Open stream was sent from server */
		if(pi->stream_connect == 1 && callsinfo != NULL) {

			/* Open stream */
			/* Signifies the start of the call so set start_sec & start_usec */
			/* Frame data holds the time info */
			callsinfo->start_fd=pinfo->fd;

			/* Local packets too */
			++(callsinfo->npackets);

			/* increment the packets counter of all calls */
			++(tapinfo->npackets);

			/* ?? means we're not quite sure if this is accurate. Since Unistim isn't a true
			   Call control protocol, we can only guess at the destination by messing with
			   key buffers. */
			if(tmp_unistim_info->key_buffer != NULL){
				callsinfo->to_identity = g_strdup_printf("?? %s",tmp_unistim_info->key_buffer);
			}

			/* change sequence number for ACK detection */
			tmp_unistim_info->sequence = pi->sequence;

			/* State changes too */
			callsinfo->call_active_state = VOIP_ACTIVE;
			callsinfo->call_state = VOIP_IN_CALL;

			/* Add graph data */
			frame_label = "STREAM OPENED";
			comment = g_strdup_printf("Stream Opened (%d)",pi->sequence);

			/* add to the graph */
			add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

		} else if(pi->stream_connect == 1 && callsinfo == NULL) {

			/* Research indicates some nortel products initiate stream first
			 * without keypresses. therefore creating this solely on a keypress is
			 * ineffective.
			 * Sometimes calls start immediately with open stream.
			 */
			callsinfo = g_malloc0(sizeof(voip_calls_info_t));
			callsinfo->call_active_state = VOIP_ACTIVE;
			callsinfo->call_state = VOIP_CALL_SETUP;
			callsinfo->from_identity=g_strdup("UNKNOWN");
			callsinfo->to_identity=g_strdup("UNKNOWN");
			COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
			callsinfo->selected=FALSE;

			/* Set this on init of struct so in case the call doesn't complete, we'll have a ref. */
			/* Otherwise if the call is completed we'll have the open/close streams to ref actual call duration */
			callsinfo->start_fd=pinfo->fd;

			callsinfo->protocol=VOIP_UNISTIM;
			callsinfo->prot_info=g_malloc(sizeof(unistim_info_t));

			tmp_unistim_info = callsinfo->prot_info;

			/* Clear tap struct */
			tmp_unistim_info->rudp_type = 0;
			tmp_unistim_info->payload_type = 0;
			tmp_unistim_info->sequence = pi->sequence;
			tmp_unistim_info->termid = 0;
			tmp_unistim_info->key_val = -1;
			tmp_unistim_info->key_state = -1;
			tmp_unistim_info->hook_state = -1;
			tmp_unistim_info->stream_connect = -1;
			tmp_unistim_info->trans_connect = -1;
			tmp_unistim_info->set_termid = -1;
			tmp_unistim_info->string_data = NULL;
			tmp_unistim_info->key_buffer = NULL;

			COPY_ADDRESS(&(tmp_unistim_info->it_ip),&(pi->it_ip));
			COPY_ADDRESS(&(tmp_unistim_info->ni_ip),&(pi->ni_ip));
			tmp_unistim_info->it_port = pi->it_port;

			callsinfo->free_prot_info = g_free;
			callsinfo->npackets = 0;
			callsinfo->call_num = tapinfo->ncalls++;
			tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);

				/* Open stream */
			/* Signifies the start of the call so set start_sec & start_usec */
			/* frame_data holds the time info */
			callsinfo->start_fd=pinfo->fd;

			/* Local packets too */
			++(callsinfo->npackets);

			/* increment the packets counter of all calls */
			++(tapinfo->npackets);

			/* ?? means we're not quite sure if this is accurate. Since Unistim isn't a true
			   Call control protocol, we can only guess at the destination by messing with
			   key buffers. */
			if(tmp_unistim_info->key_buffer != NULL){
				callsinfo->to_identity = g_strdup_printf("?? %s",tmp_unistim_info->key_buffer);
			}

			/* change sequence number for ACK detection */
			tmp_unistim_info->sequence = pi->sequence;

			/* State changes too */
			callsinfo->call_active_state = VOIP_ACTIVE;
			callsinfo->call_state = VOIP_IN_CALL;

			/* Add graph data */
			frame_label = "STREAM OPENED";
			comment = g_strdup_printf("Stream Opened (%d)",pi->sequence);

			/* add to the graph */
			add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

		} else if(pi->stream_connect == 0 && callsinfo != NULL) {
			/* Close Stream */

			/* Set stop seconds + usec */
			/* frame_data holds the time info */
			callsinfo->stop_fd = pinfo->fd;

			tmp_unistim_info->sequence = pi->sequence;

			if(callsinfo->call_state == VOIP_IN_CALL){
				callsinfo->call_active_state = VOIP_INACTIVE;
				callsinfo->call_state = VOIP_COMPLETED;
			} else {
				callsinfo->call_state = VOIP_UNKNOWN;
				callsinfo->call_active_state = VOIP_INACTIVE;
			}

			frame_label = "STREAM CLOSED";
			comment = g_strdup_printf("Stream Closed (%d)",pi->sequence);

			/* add to the graph */
			add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

		} else
			comment = NULL;

	} else if(pi->rudp_type == 1 && callsinfo != NULL) {
		/* ACK */
		/* Only show acks for processed seq #s */
		if(tmp_unistim_info->sequence == pi->sequence) {

			frame_label = "ACK";
			comment = g_strdup_printf("ACK for sequence %d",pi->sequence);

			/* add to the graph */
			add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

		}

	} else if(pi->rudp_type == 0 && callsinfo != NULL) {

		/* NAK */
		frame_label = "NAK";
		comment = g_strdup_printf("NAK for sequence %d",pi->sequence);

		/* add to the graph */
		add_to_graph(tapinfo, pinfo, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

	}

	/* free data */
	g_free(comment);

	tapinfo->redraw = TRUE;

	return 1;
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_unistim_tap_listener=FALSE;
/****************************************************************************/
void
unistim_calls_init_tap(void){

	GString *error_string;

	if(have_unistim_tap_listener==FALSE) {

		error_string = register_tap_listener("unistim", &(the_tapinfo_struct.unistim_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			unistim_calls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}

		have_unistim_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_unistim_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.unistim_dummy));
	unprotect_thread_critical_region();

	have_unistim_tap_listener=FALSE;
}

/****************************************************************************/
/* ***************************TAP for SKINNY **********************************/
/****************************************************************************/

/* Telecaster to tap-voip call state mapping */
static const voip_call_state skinny_tap_voip_state[] = {
        VOIP_NO_STATE,
        VOIP_CALL_SETUP,
        VOIP_COMPLETED,
        VOIP_RINGING,
        VOIP_RINGING,
        VOIP_IN_CALL,
        VOIP_REJECTED,
        VOIP_REJECTED,
        VOIP_IN_CALL,
        VOIP_IN_CALL,
        VOIP_COMPLETED,
        VOIP_COMPLETED,
        VOIP_CALL_SETUP,
        VOIP_UNKNOWN,
        VOIP_REJECTED
};

static int
skinny_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *skinny_info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	GList* list;
	voip_calls_info_t *callsinfo = NULL;
	address* phone;
	const skinny_info_t *si = skinny_info;
	skinny_calls_info_t *tmp_skinnyinfo;
	gchar *comment;

	if (si == NULL || (si->callId == 0 && si->passThruId == 0))
		return 0;
	/* check whether we already have this context in the list */
	list = g_list_first(tapinfo->callsinfo_list);
	while (list)
	{
		voip_calls_info_t* tmp_listinfo = list->data;
		if (tmp_listinfo->protocol == VOIP_SKINNY){
			tmp_skinnyinfo = tmp_listinfo->prot_info;
			if (tmp_skinnyinfo->callId == si->callId ||
			    tmp_skinnyinfo->callId == si->passThruId){
				callsinfo = (voip_calls_info_t*)(list->data);
				break;
			}
		}
		list = g_list_next (list);
	}

	if (si->messId >= 256)
		phone = &(pinfo->dst);
	else
		phone = &(pinfo->src);

	if (callsinfo==NULL){
		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_state = VOIP_NO_STATE;
		callsinfo->call_active_state = VOIP_ACTIVE;
		/* callsinfo->from_identity = g_strdup_printf("%s : %.8x", "Skinny", 1); */
		callsinfo->from_identity = g_strdup("");
		callsinfo->to_identity = g_strdup("");
		callsinfo->prot_info = g_malloc(sizeof(skinny_calls_info_t));
		callsinfo->free_prot_info = g_free;
		tmp_skinnyinfo = callsinfo->prot_info;
		tmp_skinnyinfo->callId = si->callId ? si->callId : si->passThruId;
		callsinfo->npackets = 1;

		COPY_ADDRESS(&(callsinfo->initial_speaker), phone);

		callsinfo->protocol = VOIP_SKINNY;
		callsinfo->call_num = tapinfo->ncalls++;
		callsinfo->start_fd = pinfo->fd;
		callsinfo->stop_fd = pinfo->fd;

		callsinfo->selected = FALSE;
		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
	} else {
		if (si->callingParty) {
			g_free(callsinfo->from_identity);
			callsinfo->from_identity = g_strdup(si->callingParty);
		}
		if (si->calledParty) {
			g_free(callsinfo->to_identity);
			callsinfo->to_identity =  g_strdup(si->calledParty);
		}
		if ((si->callState > 0) && (si->callState < (sizeof(skinny_tap_voip_state)/sizeof(skinny_tap_voip_state[0]))))
			callsinfo->call_state = skinny_tap_voip_state[si->callState];

		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
	}

	if (si->callId) {
		if (si->passThruId)
			comment = g_strdup_printf("CallId = %u, PTId = %u", si->callId, si->passThruId);
		else
			comment = g_strdup_printf("CallId = %u, LineId = %u", si->callId, si->lineId);
	} else {
		if (si->passThruId)
			comment = g_strdup_printf("PTId = %u", si->passThruId);
		else
			comment = NULL;
	}

	add_to_graph(tapinfo, pinfo, si->messageName, comment,
				 callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
	g_free(comment);

	return 1;
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_skinny_tap_listener=FALSE;
/****************************************************************************/
void
skinny_calls_init_tap(void)
{
	GString *error_string;

	if(have_skinny_tap_listener==FALSE)
	{
		/*
		 * Don't register the tap listener if we have it already.
		 * We set TL_REQUIRES_PROTO_TREE to force a non-null "tree"
		 * in the SKINNY dissector; otherwise, the dissector
		 * doesn't fill in the info passed to the tap's packet
		 * routine.
		 */
		error_string = register_tap_listener("skinny", 
			&(the_tapinfo_struct.skinny_dummy), 
			NULL,
			TL_REQUIRES_PROTO_TREE,
			voip_calls_dlg_reset,
			skinny_calls_packet,
			voip_calls_dlg_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_skinny_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_skinny_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.skinny_dummy));
	unprotect_thread_critical_region();

	have_skinny_tap_listener=FALSE;
}

/****************************************************************************/
/* ***************************TAP for IAX2 **********************************/
/****************************************************************************/

/* IAX2 to tap-voip call state mapping */
static const voip_call_state tap_iax_voip_state[] = {
	VOIP_NO_STATE,
        VOIP_CALL_SETUP, /*NEW*/
	VOIP_NO_STATE,
	VOIP_NO_STATE,
        VOIP_COMPLETED,  /*HANGUP*/
        VOIP_REJECTED, 	 /*REJECT*/
        VOIP_RINGING,	/*ACCEPT*/
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_CALL_SETUP, /*DIAL*/
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE,
	VOIP_NO_STATE
};

static void free_iax2_info(gpointer p) {
	iax2_info_t *ii = p;

	g_free(ii);
}


/****************************************************************************/
/* whenever a IAX2 packet is seen by the tap listener */
static int
iax2_calls_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *iax2_info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	GList* list;
	voip_calls_info_t *callsinfo = NULL;
	address* phone;
	const iax2_info_t *ii = iax2_info;
	iax2_info_t *tmp_iax2info;
	gchar * comment;

	if (ii == NULL || ii->ptype != IAX2_FULL_PACKET || (ii->scallno == 0 && ii->dcallno == 0))
		return 0;
	/* check whether we already have this context in the list */
	list = g_list_first(tapinfo->callsinfo_list);
	while (list)
	{
		voip_calls_info_t* tmp_listinfo = list->data;
		if (tmp_listinfo->protocol == VOIP_IAX2){
			tmp_iax2info = tmp_listinfo->prot_info;
			if (tmp_iax2info->scallno == ii->scallno ||
			    tmp_iax2info->scallno == ii->dcallno){
				callsinfo = (voip_calls_info_t*)(list->data);
				break;
			}
		}
		list = g_list_next (list);
	}
	phone = &(pinfo->src);


	if (callsinfo==NULL){
		/* We only care about real calls, i.e., no registration stuff */
		if (ii->ftype != AST_FRAME_IAX ||  ii->csub != IAX_COMMAND_NEW)
			return 0;
		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_state = VOIP_NO_STATE;
		callsinfo->call_active_state = VOIP_ACTIVE;
		callsinfo->prot_info=g_malloc(sizeof(iax2_info_t));
		callsinfo->free_prot_info = free_iax2_info;
		tmp_iax2info = callsinfo->prot_info;

		tmp_iax2info->scallno = ii->scallno;
		if (tmp_iax2info->scallno == 0) tmp_iax2info->scallno = ii->dcallno;
		tmp_iax2info->callState = tap_iax_voip_state[ii->callState];

		callsinfo->npackets = 1;

		COPY_ADDRESS(&(callsinfo->initial_speaker), phone);
		callsinfo->from_identity = g_strdup(ii->callingParty);
		callsinfo->to_identity =  g_strdup(ii->calledParty);

		callsinfo->protocol = VOIP_IAX2;
		callsinfo->call_num = tapinfo->ncalls++;
		callsinfo->start_fd=pinfo->fd;
		callsinfo->stop_fd = pinfo->fd;

		callsinfo->selected = FALSE;
		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);

	} else {
		if ((ii->callState > 0) && (ii->callState < (sizeof(tap_iax_voip_state)/sizeof(tap_iax_voip_state[0]))))
			callsinfo->call_state = tap_iax_voip_state[ii->callState];

		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
	}

	comment = "";

	add_to_graph(tapinfo, pinfo, ii->messageName, comment,
				 callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

	return 1;

}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_iax2_tap_listener=FALSE;
/****************************************************************************/
void
iax2_calls_init_tap(void)
{
	GString *error_string;

	if(have_iax2_tap_listener==FALSE)
	{
		/*
		 * Don't register the tap listener if we have it already.
		 * We set TL_REQUIRES_PROTO_TREE to force a non-null "tree"
		 * in the IAX2 dissector; otherwise, the dissector
		 * doesn't fill in the info passed to the tap's packet
		 * routine.
		 * XXX - that appears to be true of the MGCP and SKINNY
		 * dissectors, but, unless I've missed something, it doesn't
		 * appear to be true of the IAX2 dissector.
		 */
		error_string = register_tap_listener("IAX2", 
			&(the_tapinfo_struct.iax2_dummy), 
			NULL,
			TL_REQUIRES_PROTO_TREE,
			voip_calls_dlg_reset,
			iax2_calls_packet,
			voip_calls_dlg_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s",
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_iax2_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_iax2_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.iax2_dummy));
	unprotect_thread_critical_region();

	have_iax2_tap_listener=FALSE;
}

/****************************************************************************/
/* ***************************TAP for OTHER PROTOCOL **********************************/
/****************************************************************************/

static int
VoIPcalls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *VoIPinfo)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *callsinfo = NULL;
	voip_calls_info_t *tmp_listinfo;
	GList *list = NULL;
	const voip_packet_info_t *pi = VoIPinfo;

	if (pi->call_id)
		list = g_list_first(tapinfo->callsinfo_list);
	while (list) {
		tmp_listinfo = list->data;
		if ( tmp_listinfo->protocol == VOIP_COMMON ) {
			if (!strcmp(pi->call_id, tmp_listinfo->call_id)) {
				callsinfo = (voip_calls_info_t*)(list->data);
				break;
			}
		}
		list = g_list_next(list);
	}

	if (callsinfo == NULL) {
		callsinfo = g_malloc0(sizeof(voip_calls_info_t));
		callsinfo->call_active_state = pi->call_active_state;
		callsinfo->call_state = pi->call_state;
		callsinfo->call_id=g_strdup((pi->call_id)?pi->call_id:"");
		callsinfo->from_identity = g_strdup((pi->from_identity)?pi->from_identity:"");
		callsinfo->to_identity = g_strdup((pi->to_identity)?pi->to_identity:"");
		COPY_ADDRESS(&(callsinfo->initial_speaker),&(pinfo->src));
		callsinfo->selected=FALSE;
		callsinfo->start_fd=pinfo->fd;
		callsinfo->protocol=VOIP_COMMON;
		callsinfo->protocol_name=g_strdup((pi->protocol_name)?pi->protocol_name:"");
		callsinfo->call_comment=g_strdup((pi->call_comment)?pi->call_comment:"");
		callsinfo->prot_info=NULL;
		callsinfo->free_prot_info = NULL;

		callsinfo->call_num = tapinfo->ncalls++;
		callsinfo->npackets = 0;

		tapinfo->callsinfo_list = g_list_prepend(tapinfo->callsinfo_list, callsinfo);
	}

	if (callsinfo != NULL) {
		callsinfo->call_active_state = pi->call_active_state;
		if ((callsinfo->call_state != VOIP_COMPLETED) && (pi->call_state == VOIP_COMPLETED))
			tapinfo->completed_calls++;
        if (pi->call_state != VOIP_NO_STATE)
			callsinfo->call_state = pi->call_state;
		if (pi->call_comment) {
			g_free(callsinfo->call_comment);
			callsinfo->call_comment=g_strdup(pi->call_comment);
		}
		callsinfo->stop_fd = pinfo->fd;
		++(callsinfo->npackets);
		++(tapinfo->npackets);
	}

	/* add to the graph */
	add_to_graph(tapinfo, pinfo, (pi->frame_label)?pi->frame_label:"VoIP msg", pi->frame_comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

	tapinfo->redraw = TRUE;

	return 1;
}
/****************************************************************************/
static gboolean have_voip_tap_listener=FALSE;

void
VoIPcalls_init_tap(void)
{
	GString *error_string;

	if(have_voip_tap_listener==FALSE)
	{
		error_string = register_tap_listener("voip", &(the_tapinfo_struct.voip_dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			VoIPcalls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_voip_tap_listener=TRUE;
	}
}
/****************************************************************************/
void
remove_tap_listener_voip_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.voip_dummy));
	unprotect_thread_critical_region();

	have_voip_tap_listener=FALSE;
}


/****************************************************************************/
/* ***************************TAP for OTHER PROTOCOL **********************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a prot_ packet is seen by the tap listener */
/*
static int
prot_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prot_info _U_)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	if (callsinfo!=NULL){
		callsinfo->stop_abs = pinfo->fd->abs_ts;
		callsinfo->stop_rel = pinfo->fd->rel_ts;
		callsinfo->last_frame_num=pinfo->fd->num;
		++(callsinfo->npackets);
		++(tapinfo->npackets);
	}

	tapinfo->redraw = TRUE;

	return 1;
}
*/
/****************************************************************************/
/*
static gboolean have_prot__tap_listener=FALSE;

void
prot_calls_init_tap(void)
{
	GString *error_string;

	if(have_prot__tap_listener==FALSE)
	{
		error_string = register_tap_listener("prot_", &(the_tapinfo_struct.prot__dummy),
			NULL,
			0,
			voip_calls_dlg_reset,
			prot__calls_packet,
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_prot__tap_listener=TRUE;
	}
}
*/
/****************************************************************************/
/*
void
remove_tap_listener_prot__calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.prot__dummy));
	unprotect_thread_critical_region();

	have_prot__tap_listener=FALSE;
}
*/
