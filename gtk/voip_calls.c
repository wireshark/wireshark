/* voip_calls.c
 * VoIP calls summary addition for ethereal
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
 * H323, RTP, RTP Event, MGCP and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "graph_analysis.h"
#include "voip_calls.h"
#include "voip_calls_dlg.h"

#include "globals.h"

#include <epan/tap.h>
#include <epan/dissectors/packet-sip.h>
#include <epan/dissectors/packet-mtp3.h>
#include <epan/dissectors/packet-isup.h>
#include <epan/dissectors/packet-h225.h>
#include <epan/dissectors/packet-h245.h>
#include <epan/dissectors/packet-q931.h>
#include <epan/dissectors/packet-sdp.h>
#include <plugins/mgcp/packet-mgcp.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/dissectors/packet-rtp-events.h>
#include "rtp_pt.h"

#include "alert_box.h"
#include "simple_dialog.h"

char *voip_call_state_name[7]={
	"CALL SETUP",
	"RINGING",
	"IN CALL",
	"CANCELLED",
	"COMPLETED",
	"REJECTED",
	"UNKNOWN"
	};

/* defines whether we can consider the call active */
char *voip_protocol_name[4]={
	"SIP",
	"ISUP",
	"H323",
	"MGCP"
	};



/****************************************************************************/
/* the one and only global voip_calls_tapinfo_t structure */
static voip_calls_tapinfo_t the_tapinfo_struct =
	{0, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0};

/* the one and only global voip_rtp_tapinfo_t structure */
static voip_rtp_tapinfo_t the_tapinfo_rtp_struct =
	{0, NULL, 0, 0};

/****************************************************************************/
/* when there is a [re]reading of packet's */
void voip_calls_reset(voip_calls_tapinfo_t *tapinfo)
{
	voip_calls_info_t *strinfo;
	sip_calls_info_t *tmp_sipinfo;
	h323_calls_info_t *tmp_h323info;
	h245_address_t *h245_add;

	graph_analysis_item_t *graph_item;

	GList* list;
	GList* list2;

	/* free the data items first */
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		strinfo = list->data;
		g_free(strinfo->from_identity);
		g_free(strinfo->to_identity);
		g_free((void *)(strinfo->initial_speaker.data));
		if (strinfo->protocol == VOIP_SIP){
			tmp_sipinfo = strinfo->prot_info;
			g_free(tmp_sipinfo->call_identifier);
		}
		if (strinfo->protocol == VOIP_H323){
			tmp_h323info = strinfo->prot_info;
			g_free(tmp_h323info->guid);
			/* free the H245 list address */
			list2 = g_list_first(tmp_h323info->h245_list);
			while (list2)
			{
				h245_add=list2->data;
				g_free((void *)h245_add->h245_address.data);
				g_free(list2->data);
				list2 = g_list_next(list2);
			}
			g_list_free(tmp_h323info->h245_list);
			tmp_h323info->h245_list = NULL;
		}
		g_free(strinfo->prot_info);

		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapinfo->strinfo_list);
	tapinfo->strinfo_list = NULL;
	tapinfo->ncalls = 0;
	tapinfo->npackets = 0;
	tapinfo->start_packets = 0;
    tapinfo->completed_calls = 0;
    tapinfo->rejected_calls = 0;

	/* free the graph data items first */
	list = g_list_first(tapinfo->graph_analysis->list);
	while (list)
	{
		graph_item = list->data;
		g_free(graph_item->frame_label);
		g_free(graph_item->comment);
		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapinfo->graph_analysis->list);
	tapinfo->graph_analysis->nconv = 0;
	tapinfo->graph_analysis->list = NULL;

	++(tapinfo->launch_count);

	return;
}

/****************************************************************************/
void graph_analysis_data_init(void){
	the_tapinfo_struct.graph_analysis = g_malloc(sizeof(graph_analysis_info_t));
	the_tapinfo_struct.graph_analysis->nconv = 0;
	the_tapinfo_struct.graph_analysis->list = NULL;

}

/****************************************************************************/
/* Add a new item into the graph */
int add_to_graph(voip_calls_tapinfo_t *tapinfo _U_, packet_info *pinfo, gchar *frame_label, gchar *comment, guint16 call_num)
{
	graph_analysis_item_t *gai;

	gai = g_malloc(sizeof(graph_analysis_item_t));
	gai->frame_num = pinfo->fd->num;
	gai->time= (double)pinfo->fd->rel_secs + (double) pinfo->fd->rel_usecs/1000000;
	COPY_ADDRESS(&(gai->src_addr),&(pinfo->src));
	COPY_ADDRESS(&(gai->dst_addr),&(pinfo->dst));
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
	gai->line_style=1;
	gai->display=FALSE;

	tapinfo->graph_analysis->list = g_list_append(tapinfo->graph_analysis->list, gai);

	return 1;

}

/****************************************************************************/
/* Append str to frame_label and comment in a graph item */
/* return 0 if the frame_num is not in the graph list */
int append_to_frame_graph(voip_calls_tapinfo_t *tapinfo _U_, guint32 frame_num, const gchar *new_frame_label, const gchar *new_comment)
{
	graph_analysis_item_t *gai;
	GList* list;
	gchar *tmp_str = NULL;
	gchar *tmp_str2 = NULL;

	list = g_list_first(tapinfo->graph_analysis->list);
	while (list)
	{
		gai = list->data;
		if (gai->frame_num == frame_num){
			tmp_str = gai->frame_label;
			tmp_str2 = gai->comment;

			if (new_frame_label != NULL){
				gai->frame_label = g_strdup_printf("%s %s", gai->frame_label, new_frame_label);
				g_free(tmp_str);
			}


			if (new_comment != NULL){
				gai->comment = g_strdup_printf("%s %s", gai->comment, new_comment);
				g_free(tmp_str2);
			}
			break;
		}
		list = g_list_next (list);
	}
	if (tmp_str == NULL) return 0;		/* it is not in the list */
	return 1;

}

/****************************************************************************/
/* Change all the graph items with call_num to new_call_num */
guint change_call_num_graph(voip_calls_tapinfo_t *tapinfo _U_, guint16 call_num, guint16 new_call_num)
{
	graph_analysis_item_t *gai;
	GList* list;
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
		list = g_list_next (list);
	}
	return items_changed;
}

/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

/****************************************************************************/
/* ***************************TAP for RTP Events*****************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a rtp event packet is seen by the tap listener */
static int 
rtp_event_packet(void *ptr _U_, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *rtp_event_info)
{
	const struct _rtp_event_info *pi = rtp_event_info;
	voip_rtp_tapinfo_t *tapinfo = &the_tapinfo_rtp_struct;
	voip_rtp_stream_info_t *tmp_listinfo;
	voip_rtp_stream_info_t *strinfo = NULL;
	GList* list;

	/* do not consider RTP events packets without a setup frame */
	if (pi->info_setup_frame_num == 0){
		return 0;
	}

	/* check wether we already have a RTP stream with this setup frame in the list */
	list = g_list_first(tapinfo->list);
	while (list)
	{
		tmp_listinfo=list->data;
		if ( (tmp_listinfo->setup_frame_number == pi->info_setup_frame_num) 
			&& (tmp_listinfo->end_stream == FALSE) && (tmp_listinfo->rtp_event == -1)){
				strinfo = (voip_rtp_stream_info_t*)(list->data);
				strinfo->rtp_event = pi->info_rtp_evt;
				break;
		}
		list = g_list_next (list);
	}


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
			NULL,
			rtp_event_packet,
			NULL
			);
			
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
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
void voip_rtp_reset(void *ptr _U_)
{
	voip_rtp_tapinfo_t *tapinfo = &the_tapinfo_rtp_struct;
	GList* list;
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
RTP_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *RTPinfo)
{
	voip_rtp_tapinfo_t *tapinfo = &the_tapinfo_rtp_struct;
	voip_rtp_stream_info_t *tmp_listinfo;
	voip_rtp_stream_info_t *strinfo = NULL;
	GList* list;

	const struct _rtp_info *pi = RTPinfo;

	/* do not consider RTP packets without a setup frame */
	if (pi->info_setup_frame_num == 0){
		return 0;
	}

	/* check wether we already have a RTP stream with this setup frame and ssrc in the list */
	list = g_list_first(tapinfo->list);
	while (list)
	{
		tmp_listinfo=list->data;
		if ( (tmp_listinfo->setup_frame_number == pi->info_setup_frame_num) 
			&& (tmp_listinfo->ssrc == pi->info_sync_src) && (tmp_listinfo->end_stream == FALSE)){
			/* if the payload type has changed, we mark the stream as finished to create a new one
			   this is to show multiple payload changes in the Graph for example for DTMF RFC2833 */	   
			if ( tmp_listinfo->pt != pi->info_payload_type ) 
				tmp_listinfo->end_stream = TRUE;
			else {
				strinfo = (voip_rtp_stream_info_t*)(list->data);
				break;
			}
		}
		list = g_list_next (list);
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
		strinfo->npackets = 0;
		strinfo->first_frame_num = pinfo->fd->num;
		strinfo->start_rel_sec = pinfo->fd->rel_secs;
		strinfo->start_rel_usec = pinfo->fd->rel_usecs;
		strinfo->setup_frame_number = pi->info_setup_frame_num;
		strinfo->rtp_event = -1;
		tapinfo->list = g_list_append(tapinfo->list, strinfo);
	}

	if (strinfo!=NULL){
		/* Add the info to the existing RTP stream */
		strinfo->npackets++;
		strinfo->stop_rel_sec = pinfo->fd->rel_secs;
		strinfo->stop_rel_usec = pinfo->fd->rel_usecs;
	}
	return 1;
}

/****************************************************************************/
/* whenever a redraw in the RTP tap listener */
void RTP_packet_draw(void *prs _U_)
{
	voip_rtp_tapinfo_t *rtp_tapinfo = &the_tapinfo_rtp_struct;
	GList* rtp_streams_list;
	voip_rtp_stream_info_t *rtp_listinfo;
	GList* voip_calls_graph_list;
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
		item = 0;
		while (voip_calls_graph_list)
		{			
			gai = voip_calls_graph_list->data;
			conv_num = gai->conv_num;
			/* if we get the setup frame number, then get the time position to graph the RTP arrow */
			if (rtp_listinfo->setup_frame_number == gai->frame_num){
				while(voip_calls_graph_list){
					gai = voip_calls_graph_list->data;
					/* if RTP was already in the Graph, just update the comment information */
					if (rtp_listinfo->first_frame_num == gai->frame_num){
						duration = (rtp_listinfo->stop_rel_sec*1000000 + rtp_listinfo->stop_rel_usec) - (rtp_listinfo->start_rel_sec*1000000 + rtp_listinfo->start_rel_usec);
						g_free(gai->comment);
						gai->comment = g_strdup_printf("RTP Num packets:%d  Duration:%d.%03ds ssrc:%d", rtp_listinfo->npackets, duration/1000000,(duration%1000000)/1000, rtp_listinfo->ssrc);
						break;
					/* add the RTP item to the graph if was not there*/
					} else if (rtp_listinfo->first_frame_num<gai->frame_num){
						new_gai = g_malloc(sizeof(graph_analysis_item_t));
						new_gai->frame_num = rtp_listinfo->first_frame_num;
						new_gai->time = (double)rtp_listinfo->start_rel_sec + (double)rtp_listinfo->start_rel_usec/1000000;
						COPY_ADDRESS(&(new_gai->src_addr),&(rtp_listinfo->src_addr));
						COPY_ADDRESS(&(new_gai->dst_addr),&(rtp_listinfo->dest_addr));
						new_gai->port_src = rtp_listinfo->src_port;
						new_gai->port_dst = rtp_listinfo->dest_port;
						duration = (rtp_listinfo->stop_rel_sec*1000000 + rtp_listinfo->stop_rel_usec) - (rtp_listinfo->start_rel_sec*1000000 + rtp_listinfo->start_rel_usec);
						new_gai->frame_label = g_strdup_printf("RTP (%s) %s", val_to_str(rtp_listinfo->pt, rtp_payload_type_short_vals, "%u"), (rtp_listinfo->rtp_event == -1)?"":val_to_str(rtp_listinfo->rtp_event, rtp_event_type_values, "Uknown RTP Event"));
						new_gai->comment = g_strdup_printf("RTP Num packets:%d  Duration:%d.%03ds ssrc:%d", rtp_listinfo->npackets, duration/1000000,(duration%1000000)/1000, rtp_listinfo->ssrc);
						new_gai->conv_num = conv_num;
						new_gai->display=FALSE;
						new_gai->line_style = 2;  /* the arrow line will be 2 pixels width */
						the_tapinfo_struct.graph_analysis->list = g_list_insert(the_tapinfo_struct.graph_analysis->list, new_gai, item);
						break;
					}
					
					voip_calls_graph_list = g_list_next(voip_calls_graph_list);
					item++;
				}
				break;
			}
			voip_calls_graph_list = g_list_next(voip_calls_graph_list);
			item++;
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
			voip_rtp_reset, 
			RTP_packet, 
			RTP_packet_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
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
/* ***************************TAP for SIP **********************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a SIP packet is seen by the tap listener */
static int 
SIPcalls_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *SIPinfo)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	/* we just take note of the ISUP data here; when we receive the MTP3 part everything will
	   be compared with existing calls */

	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *strinfo = NULL;
	sip_calls_info_t *tmp_sipinfo = NULL;
	GList* list;
	address tmp_src, tmp_dst;
	gchar *frame_label = NULL;
	gchar *comment = NULL;

	const sip_info_value_t *pi = SIPinfo;

	/* do not consider packets without call_id */
	if (pi->tap_call_id ==NULL){
		return 0;
	}

	/* check wether we already have a call with these parameters in the list */
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		tmp_listinfo=list->data;
		if (tmp_listinfo->protocol == VOIP_SIP){
			tmp_sipinfo = tmp_listinfo->prot_info;
			if (strcmp(tmp_sipinfo->call_identifier,pi->tap_call_id)==0){
				strinfo = (voip_calls_info_t*)(list->data);
				break;
			}
		}
		list = g_list_next (list);
	}

	/* not in the list? then create a new entry if the message is INVITE -i.e. if this session is a call*/
	if ((strinfo==NULL) &&(pi->request_method!=NULL)){
		if (strcmp(pi->request_method,"INVITE")==0){
			strinfo = g_malloc(sizeof(voip_calls_info_t));
			strinfo->call_active_state = VOIP_ACTIVE;
			strinfo->call_state = VOIP_CALL_SETUP;
			strinfo->from_identity=g_strdup(pi->tap_from_addr);
			strinfo->to_identity=g_strdup(pi->tap_to_addr);
			COPY_ADDRESS(&(strinfo->initial_speaker),&(pinfo->src));
			strinfo->first_frame_num=pinfo->fd->num;
			strinfo->selected=FALSE;
			strinfo->start_sec=pinfo->fd->rel_secs;
			strinfo->start_usec=pinfo->fd->rel_usecs;
			strinfo->protocol=VOIP_SIP;
			strinfo->prot_info=g_malloc(sizeof(sip_calls_info_t));
			tmp_sipinfo=strinfo->prot_info;
			tmp_sipinfo->call_identifier=strdup(pi->tap_call_id);
			tmp_sipinfo->sip_state=SIP_INVITE_SENT;
			tmp_sipinfo->invite_cseq=pi->tap_cseq_number;
			strinfo->npackets = 0;
			strinfo->call_num = tapinfo->ncalls++;
			tapinfo->strinfo_list = g_list_append(tapinfo->strinfo_list, strinfo);
		}
	}

	g_free(pi->tap_from_addr);
	g_free(pi->tap_to_addr);
	g_free(pi->tap_call_id);

	if (strinfo!=NULL){

		/* let's analyze the call state */

		COPY_ADDRESS(&(tmp_src), &(pinfo->src));
		COPY_ADDRESS(&(tmp_dst), &(pinfo->dst));
		
		if (pi->request_method == NULL){
			frame_label = g_strdup_printf("%d %s", pi->response_code, pi->reason_phrase );
			comment = g_strdup_printf("SIP Status");

			if ((tmp_sipinfo && pi->tap_cseq_number == tmp_sipinfo->invite_cseq)&&(ADDRESSES_EQUAL(&tmp_dst,&(strinfo->initial_speaker)))){
				if ((pi->response_code > 199) && (pi->response_code<300) && (tmp_sipinfo->sip_state == SIP_INVITE_SENT)){
					tmp_sipinfo->sip_state = SIP_200_REC;
				}
				else if ((pi->response_code>299)&&(tmp_sipinfo->sip_state == SIP_INVITE_SENT)){
					strinfo->call_state = VOIP_REJECTED;
					tapinfo->rejected_calls++;
				}
			}

		}
		else{
			frame_label = g_strdup(pi->request_method);

			if ((strcmp(pi->request_method,"INVITE")==0)&&(ADDRESSES_EQUAL(&tmp_src,&(strinfo->initial_speaker)))){
				tmp_sipinfo->invite_cseq = pi->tap_cseq_number;
				strinfo->call_state = VOIP_CALL_SETUP;
				comment = g_strdup_printf("SIP From: %s To:%s", strinfo->from_identity, strinfo->to_identity);
			}
			else if ((strcmp(pi->request_method,"ACK")==0)&&(pi->tap_cseq_number == tmp_sipinfo->invite_cseq)
				&&(ADDRESSES_EQUAL(&tmp_src,&(strinfo->initial_speaker)))&&(tmp_sipinfo->sip_state==SIP_200_REC)
				&&(strinfo->call_state == VOIP_CALL_SETUP)){
				strinfo->call_state = VOIP_IN_CALL;
				comment = g_strdup_printf("SIP Request");
			}
			else if (strcmp(pi->request_method,"BYE")==0){
				strinfo->call_state = VOIP_COMPLETED;
				tapinfo->completed_calls++;
				comment = g_strdup_printf("SIP Request");
			}
			else if ((strcmp(pi->request_method,"CANCEL")==0)&&(pi->tap_cseq_number == tmp_sipinfo->invite_cseq)
				&&(ADDRESSES_EQUAL(&tmp_src,&(strinfo->initial_speaker)))&&(strinfo->call_state==VOIP_CALL_SETUP)){
				strinfo->call_state = VOIP_CANCELLED;
				tmp_sipinfo->sip_state = SIP_CANCEL_SENT;
				comment = g_strdup_printf("SIP Request");
			} else {
				comment = g_strdup_printf("SIP Request");
			}
		}

		strinfo->stop_sec=pinfo->fd->rel_secs;
		strinfo->stop_usec=pinfo->fd->rel_usecs;
		strinfo->last_frame_num=pinfo->fd->num;
		++(strinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);

		/* add to the graph */
		add_to_graph(tapinfo, pinfo, frame_label, comment, strinfo->call_num);  
		g_free(comment);
		g_free(frame_label);
		g_free((void *)tmp_src.data);
		g_free((void *)tmp_dst.data);
	}
	return 1;  /* refresh output */
}


/****************************************************************************/
const voip_calls_tapinfo_t* voip_calls_get_info(void)
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
			voip_calls_dlg_reset, 
			SIPcalls_packet, 
			voip_calls_dlg_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_SIP_tap_listener=TRUE;
	}
}



/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

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

static gchar		isup_called_number[255], isup_calling_number[255];
static guint16		isup_cic;
static guint8		isup_message_type;
static guint8		isup_cause_value;
static guint32		isup_frame_num;

/****************************************************************************/
/* whenever a isup_ packet is seen by the tap listener */
static int 
isup_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *isup_info _U_)
{
	/*voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct; unused */
	const isup_tap_rec_t *pi = isup_info;

	if (pi->calling_number!=NULL){
		strcpy(isup_calling_number, pi->calling_number);
	}
	if (pi->called_number!=NULL){
		strcpy(isup_called_number, pi->called_number);
	}
	isup_message_type = pi->message_type;
	isup_cause_value = pi->cause_value;
	isup_cic = pinfo->circuit_id;
	isup_frame_num = pinfo->fd->num;
	isup_frame_num = pinfo->fd->num;
	
	return 0;
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
			voip_calls_dlg_reset, 
			isup_calls_packet, 
			voip_calls_dlg_draw
			);
	
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
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
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *strinfo = NULL;
	isup_calls_info_t *tmp_isupinfo;
	gboolean found = FALSE;
	gboolean forward = FALSE;
	gboolean right_pair = TRUE;
	GList* list;
	gchar *frame_label = NULL;
	gchar *comment = NULL;
	int i;

	const mtp3_tap_rec_t *pi = mtp3_info;

	/* check if the upper layer is ISUP matching the frame number */
	if (isup_frame_num != pinfo->fd->num) return 0;
	
	/* check wether we already have a call with these parameters in the list */
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		tmp_listinfo=list->data;
		if ((tmp_listinfo->protocol == VOIP_ISUP)&&(tmp_listinfo->call_active_state==VOIP_ACTIVE)){
			tmp_isupinfo = tmp_listinfo->prot_info;
			if ((tmp_isupinfo->cic == isup_cic)&&(tmp_isupinfo->ni == pi->addr_opc.ni)) {
				if ((tmp_isupinfo->opc == pi->addr_opc.pc)&&(tmp_isupinfo->dpc == pi->addr_dpc.pc)){
					 forward = TRUE;
				 }
				 else if ((tmp_isupinfo->dpc == pi->addr_opc.pc)&&(tmp_isupinfo->opc == pi->addr_dpc.pc)){
					 forward = FALSE;
				 }
				 else{
					 /* XXX: what about forward is it FALSE as declared or should it be true */
					 right_pair = FALSE;
				 }
				 if (right_pair){
					/* if there is an IAM for a call that is not in setup state, that means the previous call in the same
					   cic is no longer active */
					if (tmp_listinfo->call_state == VOIP_CALL_SETUP){
						found = TRUE;
					}
					else if (isup_message_type != 1){
						found = TRUE;
					}
					else{
						tmp_listinfo->call_active_state=VOIP_INACTIVE;
					}
				}
				if (found){
					strinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
		}
		list = g_list_next (list);
	}

	/* not in the list? then create a new entry if the message is IAM
	   -i.e. if this session is a call*/


	if ((strinfo==NULL) &&(isup_message_type==1)){

		strinfo = g_malloc(sizeof(voip_calls_info_t));
		strinfo->call_active_state = VOIP_ACTIVE;
		strinfo->call_state = VOIP_UNKNOWN;
		COPY_ADDRESS(&(strinfo->initial_speaker),&(pinfo->src));
		strinfo->selected=FALSE;
		strinfo->first_frame_num=pinfo->fd->num;
		strinfo->start_sec=pinfo->fd->rel_secs;
		strinfo->start_usec=pinfo->fd->rel_usecs;
		strinfo->protocol=VOIP_ISUP;
		strinfo->from_identity=g_strdup(isup_calling_number);
		strinfo->to_identity=g_strdup(isup_called_number);
		strinfo->prot_info=g_malloc(sizeof(isup_calls_info_t));
		tmp_isupinfo=strinfo->prot_info;
		tmp_isupinfo->opc = pi->addr_opc.pc;
		tmp_isupinfo->dpc = pi->addr_dpc.pc;
		tmp_isupinfo->ni = pi->addr_opc.ni;
		tmp_isupinfo->cic = pinfo->circuit_id;
		strinfo->npackets = 0;
		strinfo->call_num = tapinfo->ncalls++;
		tapinfo->strinfo_list = g_list_append(tapinfo->strinfo_list, strinfo);
	}

	if (strinfo!=NULL){
		strinfo->stop_sec=pinfo->fd->rel_secs;
		strinfo->stop_usec=pinfo->fd->rel_usecs;
		strinfo->last_frame_num=pinfo->fd->num;
		++(strinfo->npackets);

		/* Let's analyze the call state */


		for (i=0;(isup_message_type_value[i].strptr!=NULL)&& (isup_message_type_value[i].value!=isup_message_type);i++);

		if (isup_message_type_value[i].value==isup_message_type){
			frame_label = g_strdup(isup_message_type_value_acro[i].strptr);
		}
		else{
			frame_label = g_strdup_printf("Unknown");
		}

		if (strinfo->npackets == 1){ /* this is the first packet, that must be an IAM */
			comment = g_strdup_printf("Call from %s to %s",
			 isup_calling_number, isup_called_number);
		}
		else if (strinfo->npackets == 2){ /* in the second packet we show the SPs */
			if (forward){
				comment = g_strdup_printf("%i-%i -> %i-%i. Cic:%i",
				 pi->addr_opc.ni, pi->addr_opc.pc,
				 pi->addr_opc.ni, pi->addr_dpc.pc, pinfo->circuit_id);

			}
			else{
				comment = g_strdup_printf("%i-%i -> %i-%i. Cic:%i",
				 pi->addr_opc.ni, pi->addr_dpc.pc,
				 pi->addr_opc.ni, pi->addr_opc.pc, pinfo->circuit_id);

			}
		}

		switch(isup_message_type){
			case 1: /* IAM */
				strinfo->call_state=VOIP_CALL_SETUP;
				break;
			case 7: /* CONNECT */
			case 9: /* ANSWER */
				strinfo->call_state=VOIP_IN_CALL;
				break;
			case 12: /* RELEASE */
				if (strinfo->call_state==VOIP_CALL_SETUP){
					if (forward){
						strinfo->call_state=VOIP_CANCELLED;
					}
					else{
						strinfo->call_state=VOIP_REJECTED;
						tapinfo->rejected_calls++;
					}
				}
				else if (strinfo->call_state == VOIP_IN_CALL){
					strinfo->call_state = VOIP_COMPLETED;
					tapinfo->completed_calls++;
				}
				for (i=0;(q931_cause_code_vals[i].strptr!=NULL)&& (q931_cause_code_vals[i].value!=isup_cause_value);i++);
				if (q931_cause_code_vals[i].value==isup_cause_value){
					comment = g_strdup_printf("Cause %i - %s",isup_cause_value, q931_cause_code_vals[i].strptr);
				}
				else{
					comment = g_strdup_printf("Cause %i",isup_cause_value);
				}
				break;
		}

		/* increment the packets counter of all calls */
		++(tapinfo->npackets);

		/* add to the graph */
		add_to_graph(tapinfo, pinfo, frame_label, comment, strinfo->call_num);  
		g_free(comment);
		g_free(frame_label);
	}


	return 1;
}

/****************************************************************************/

static gboolean have_mtp3_tap_listener=FALSE;

void
mtp3_calls_init_tap(void)
{
	GString *error_string;


	if(have_mtp3_tap_listener==FALSE)
	{
		error_string = register_tap_listener("mtp3", &(the_tapinfo_struct.mtp3_dummy),
			NULL,
			voip_calls_dlg_reset, 
			mtp3_calls_packet, 
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_mtp3_tap_listener=TRUE;
	}
}

/****************************************************************************/

void
remove_tap_listener_mtp3_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.mtp3_dummy));
	unprotect_thread_critical_region();

	have_mtp3_tap_listener=FALSE;
}

/****************************************************************************/
/* ***************************TAP for Q931 **********************************/
/****************************************************************************/

static gchar *q931_calling_number;
static gchar *q931_called_number;
static guint8 q931_cause_value;
static gint32 q931_crv;
static guint32 q931_frame_num;

/****************************************************************************/
/* whenever a q931_ packet is seen by the tap listener */
static int 
q931_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *q931_info _U_)
{
	/*voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct; */
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

	return 0;
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
			voip_calls_dlg_reset,
			q931_calls_packet,
			voip_calls_dlg_draw
			);
			
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
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

#define GUID_LEN	16
static const guint8 guid_allzero[GUID_LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
/* defines specific H323 data */


void add_h245_Address(h323_calls_info_t *h323info,  h245_address_t *h245_address)
{
	h323info->h245_list = g_list_append(h323info->h245_list, h245_address);				
}

/****************************************************************************/
/* whenever a H225 packet is seen by the tap listener */
static int 
H225calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *H225info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *strinfo = NULL;
	h323_calls_info_t *tmp_h323info = NULL;
	h323_calls_info_t *tmp2_h323info;
	gchar *frame_label;
	gchar *comment;
	GList *list, *list2;
	address tmp_src, tmp_dst;
	h245_address_t *h245_add = NULL;
	guint foo;
	
	const h225_packet_info *pi = H225info;
	
	/* if not guid and RAS and not LRQ, LCF or LRJ return because did not belong to a call */
	if ((memcmp(pi->guid, guid_allzero, GUID_LEN) == 0) && (pi->msg_type == H225_RAS) && ((pi->msg_tag < 18) || (pi->msg_tag > 20)))
		return 0;
	
	
	if ( (memcmp(pi->guid, guid_allzero, GUID_LEN) == 0) && (q931_frame_num == pinfo->fd->num) ){
		/* check wether we already have a call with this Q931 CRV */
		list = g_list_first(tapinfo->strinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if (tmp_listinfo->protocol == VOIP_H323){
				tmp_h323info = tmp_listinfo->prot_info;
				if ( ((tmp_h323info->q931_crv == q931_crv) || (tmp_h323info->q931_crv2 == q931_crv)) && (q931_crv!=-1)){
					strinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
			list = g_list_next (list);
		}
		if (strinfo==NULL) 	return 0;		
	} else if ( (pi->msg_type == H225_RAS) && ((pi->msg_tag == 19) || (pi->msg_tag == 20))) { /* RAS LCF or LRJ*/
		/* if the LCF/LRJ doesn't match to a LRQ, just return */
		if (!pi->request_available) return 0;
		
		/* check wether we already have a call with this request SeqNum */
		list = g_list_first(tapinfo->strinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if (tmp_listinfo->protocol == VOIP_H323){
				tmp_h323info = tmp_listinfo->prot_info;
				if (tmp_h323info->requestSeqNum == pi->requestSeqNum) {
					strinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
			list = g_list_next (list);
		}
	} else {
		/* check wether we already have a call with this guid in the list */
		list = g_list_first(tapinfo->strinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if (tmp_listinfo->protocol == VOIP_H323){
				tmp_h323info = tmp_listinfo->prot_info;
				if ( (memcmp(tmp_h323info->guid, guid_allzero, GUID_LEN) != 0) && (memcmp(tmp_h323info->guid, pi->guid,GUID_LEN)==0) ){ 
					strinfo = (voip_calls_info_t*)(list->data);
					break;
				}
			}
			list = g_list_next (list);
		}
	}
	
	/* not in the list? then create a new entry */
	if ((strinfo==NULL)){
		strinfo = g_malloc(sizeof(voip_calls_info_t));
		strinfo->call_active_state = VOIP_ACTIVE;
		strinfo->call_state = VOIP_UNKNOWN;
		strinfo->from_identity=g_strdup("");
		strinfo->to_identity=g_strdup("");
		COPY_ADDRESS(&(strinfo->initial_speaker),&(pinfo->src));
		strinfo->selected=FALSE;
		strinfo->first_frame_num=pinfo->fd->num;
		strinfo->start_sec=pinfo->fd->rel_secs;
		strinfo->start_usec=pinfo->fd->rel_usecs;
		strinfo->protocol=VOIP_H323;
		strinfo->prot_info=g_malloc(sizeof(h323_calls_info_t));
		tmp_h323info = strinfo->prot_info;
		tmp_h323info->guid = (guint8 *) g_memdup(pi->guid,GUID_LEN);
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
		strinfo->call_num = tapinfo->ncalls++;
		strinfo->npackets = 0;
		
		tapinfo->strinfo_list = g_list_append(tapinfo->strinfo_list, strinfo);				
	}

	if (strinfo!=NULL){

		/* let's analyze the call state */

		COPY_ADDRESS(&(tmp_src),&(pinfo->src));
		COPY_ADDRESS(&(tmp_dst),&(pinfo->dst));

		strinfo->stop_sec=pinfo->fd->rel_secs;
		strinfo->stop_usec=pinfo->fd->rel_usecs;
		strinfo->last_frame_num=pinfo->fd->num;
		++(strinfo->npackets);
		/* increment the packets counter of all calls */
		++(tapinfo->npackets);


		/* XXX: it is supposed to be initialized isn't it? */
		g_assert(tmp_h323info != NULL);

		/* change the status */
		if (pi->msg_type == H225_CS){
			if (tmp_h323info->q931_crv == -1) {
				tmp_h323info->q931_crv = q931_crv;
			} else if (tmp_h323info->q931_crv != q931_crv) {
				tmp_h323info->q931_crv2 = q931_crv;
			}

			/* this is still IPv4 only, because the dissector is */
			if (pi->is_h245 == TRUE){
				h245_add = g_malloc(sizeof (h245_address_t));
				h245_add->h245_address.type=AT_IPv4;
				h245_add->h245_address.len=4;
				h245_add->h245_address.data = g_malloc(sizeof(pi->h245_address));
				g_memmove((void *)(h245_add->h245_address.data), &(pi->h245_address), 4);
				h245_add->h245_port = pi->h245_port;
				add_h245_Address(tmp_h323info, h245_add);
			}

			if (pi->cs_type != H225_RELEASE_COMPLET) tmp_h323info->is_h245Tunneling = pi->is_h245Tunneling;

			frame_label = g_strdup(pi->frame_label);

			switch(pi->cs_type){
			case H225_SETUP:
				tmp_h323info->is_faststart_Setup = pi->is_faststart;
				/* set te calling and called number from the Q931 packet */
				if (q931_frame_num == pinfo->fd->num){
					if (q931_calling_number != NULL){
						g_free(strinfo->from_identity);
						strinfo->from_identity=g_strdup(q931_calling_number);
					}
					if (q931_called_number != NULL){
						g_free(strinfo->to_identity);
						strinfo->to_identity=g_strdup(q931_called_number);
					}
				}
					/* check if there is an LRQ/LCF that match this Setup */
					/* TODO: we are just checking the DialedNumer in LRQ/LCF agains the Setup 
					we should also check if the h225 signaling IP and port match the destination 
					Setup ip and port */
					list = g_list_first(tapinfo->strinfo_list);
				foo=	g_list_length(list);
				while (list)
				{
					tmp_listinfo=list->data;
					if (tmp_listinfo->protocol == VOIP_H323){
						tmp2_h323info = tmp_listinfo->prot_info;
						
						/* check if there called number match a LRQ/LCF */
						if ( (strcmp(strinfo->to_identity, tmp_listinfo->to_identity)==0)  
							 && (memcmp(tmp2_h323info->guid, guid_allzero, GUID_LEN) == 0) ){ 
							/* change the call graph to the LRQ/LCF to belong to this call */
							strinfo->npackets += change_call_num_graph(tapinfo, tmp_listinfo->call_num, strinfo->call_num);
							
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
							tapinfo->strinfo_list = g_list_remove(tapinfo->strinfo_list, tmp_listinfo);
							break;
						}
					}
			        list = g_list_next (list);
				}
					foo = g_list_length(list);
				/* Set the Setup address if it was not set */
				if (tmp_h323info->h225SetupAddr.type == AT_NONE) 
				  COPY_ADDRESS(&(tmp_h323info->h225SetupAddr), &(pinfo->src));
					strinfo->call_state=VOIP_CALL_SETUP;
				comment = g_strdup_printf("H225 From: %s To:%s  TunnH245:%s FS:%s", strinfo->from_identity, strinfo->to_identity, (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"), 
										  (pi->is_faststart==TRUE?"on":"off"));
				break;
			case H225_CONNECT:
				strinfo->call_state=VOIP_IN_CALL;
				if (pi->is_faststart == TRUE) tmp_h323info->is_faststart_Proc = TRUE;
					comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"), 
											  (pi->is_faststart==TRUE?"on":"off"));
				break;
			case H225_RELEASE_COMPLET:
			    COPY_ADDRESS(&tmp_src,&(pinfo->src));
				if (strinfo->call_state==VOIP_CALL_SETUP){
					if (ADDRESSES_EQUAL(&(tmp_h323info->h225SetupAddr),&tmp_src)){  /* forward direction */
						strinfo->call_state=VOIP_CANCELLED;
					}
					else{												/* reverse */
						strinfo->call_state=VOIP_REJECTED;
						tapinfo->rejected_calls++;
					}
				} else {
						strinfo->call_state=VOIP_COMPLETED;
						tapinfo->completed_calls++;
				}
				/* get the Q931 Release cause code */
				if (q931_frame_num == pinfo->fd->num &&
					q931_cause_value != 0xFF){		
					comment = g_strdup_printf("H225 Q931 Rel Cause (%i):%s", q931_cause_value, val_to_str(q931_cause_value, q931_cause_code_vals, "<unknown>"));
				} else {			/* Cause not set */
					comment = g_strdup("H225 No Q931 Rel Cause");
				}
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
				
			} /* switch pi->cs_type*/
		} /* if pi->msg_type == H225_CS */
		else if (pi->msg_type == H225_RAS){
		switch(pi->msg_tag){
			case 18:  /* LRQ */
				if (!pi->is_duplicate){
					g_free(strinfo->to_identity);
					strinfo->to_identity=g_strdup(pi->dialedDigits);
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
		frame_label = g_strdup_printf("%s", val_to_str(pi->msg_tag, RasMessage_vals, "<unknown>"));
	} else {
		frame_label = g_strdup("H225: Unknown");
		comment = g_strdup("");
	}

	/* add to graph analysis */

	/* if the frame number exists in graph, append to it*/
	if (!append_to_frame_graph(tapinfo, pinfo->fd->num, pi->frame_label, comment)) {
		/* if not exist, add to the graph */
		add_to_graph(tapinfo, pinfo, frame_label, comment, strinfo->call_num);
		g_free((void *)tmp_src.data);
		g_free((void *)tmp_dst.data);
	}

	g_free(frame_label);
	g_free(comment);
	
	} /* if strinfo!=NULL */
	
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
			voip_calls_dlg_reset, 
			H225calls_packet, 
			voip_calls_dlg_draw
			);
			
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_H225_tap_listener=TRUE;
	}
}



/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

/****************************************************************************/
void
remove_tap_listener_h225_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.h225_dummy));
	unprotect_thread_critical_region();

	have_H225_tap_listener=FALSE;
}


/****************************************************************************/
/* whenever a H245dg packet is seen by the tap listener (when H245 tunneling is ON) */
static int 
H245dgcalls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *H245info)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	voip_calls_info_t *tmp_listinfo;
	voip_calls_info_t *strinfo = NULL;
	h323_calls_info_t *tmp_h323info;
	gchar *frame_label;
	gchar *comment;
	GList* list;
	GList* list2;
	address tmp_src, tmp_dst;
	h245_address_t *h245_add = NULL;

	const h245_packet_info *pi = H245info;

	/* if H245 tunneling is on, append to graph */
	if (append_to_frame_graph(tapinfo, pinfo->fd->num, pi->frame_label, pi->comment)) return 1;


	/* it is not Tunneling or it is not in the list. So check if there is no tunneling
	   and there is a call with this H245 address */
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		tmp_listinfo=list->data;
		if (tmp_listinfo->protocol == VOIP_H323){
			tmp_h323info = tmp_listinfo->prot_info;

			COPY_ADDRESS(&(tmp_src), &(pinfo->src));
			COPY_ADDRESS(&(tmp_dst), &(pinfo->dst));
			list2 = g_list_first(tmp_h323info->h245_list);
			while (list2)
			{
				h245_add=list2->data;
				if ( (ADDRESSES_EQUAL(&(h245_add->h245_address),&tmp_src) && (h245_add->h245_port == pinfo->srcport))
					|| (ADDRESSES_EQUAL(&(h245_add->h245_address),&tmp_dst) && (h245_add->h245_port == pinfo->destport)) ){
					strinfo = (voip_calls_info_t*)(list->data);

					++(strinfo->npackets);
					/* increment the packets counter of all calls */
					++(tapinfo->npackets);

					break;
				}			
			list2 = g_list_next(list2);
			}
			if (strinfo!=NULL) break;
			g_free((void *)tmp_src.data);
			g_free((void *)tmp_dst.data);
		}
		list = g_list_next(list);
	}

	if (strinfo!=NULL){
		frame_label = g_strdup(pi->frame_label);
		comment = g_strdup(pi->comment);
		add_to_graph(tapinfo, pinfo, frame_label, comment, strinfo->call_num);
		g_free(frame_label);
		g_free(comment);
	}

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
			voip_calls_dlg_reset,
			H245dgcalls_packet, 
			voip_calls_dlg_draw
			);
		
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_H245dg_tap_listener=TRUE;
	}
}


/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

/****************************************************************************/
void
remove_tap_listener_h245dg_calls(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(the_tapinfo_struct.h245dg_dummy));
	unprotect_thread_critical_region();

	have_H245dg_tap_listener=FALSE;
}

static gchar *sdp_summary = NULL;
static guint32 sdp_frame_num = 0;

/****************************************************************************/
/****************************TAP for SDP PROTOCOL ***************************/
/****************************************************************************/
/* whenever a SDP packet is seen by the tap listener */
static int 
SDPcalls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *SDPinfo)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	const sdp_packet_info *pi = SDPinfo;

	/* There are protocols like MGCP where the SDP is called before the tap for the
	   MGCP packet, in those cases we assign the SPD summary to global lastSDPsummary
	   to use it later 
	*/
	g_free(sdp_summary);
	sdp_frame_num = pinfo->fd->num;
	/* Append to graph the SDP summary if the packet exists */
	sdp_summary = g_strdup_printf("SDP (%s)", pi->summary_str);
	append_to_frame_graph(tapinfo, pinfo->fd->num, sdp_summary, NULL);

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
			voip_calls_dlg_reset, 
			SDPcalls_packet, 
			voip_calls_dlg_draw
			);
			
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_sdp_tap_listener=TRUE;
	}
}


/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

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
gboolean isSignal(gchar *signal, gchar *signalStr)
{
	gint i; 
	gchar **resultArray;
	
	/* if there is no signalStr, just return false */
	if (signalStr == NULL) return FALSE;

	/* if are both "blank" return true */
	if ( (*signal == '\0') &&  (*signalStr == '\0') ) return TRUE;

	/* look for signal in signalSre */
	resultArray = g_strsplit(signalStr, ",", 10);

	for (i = 0; resultArray[i]; i++) {
		g_strstrip(resultArray[i]);
		if (strcmp(resultArray[i], signal) == 0) return TRUE;
	}

	g_strfreev(resultArray);
	
	return FALSE;
}

/*
   This function will get the Caller ID info and replace the current string
   This is how it looks the caller Id: rg, ci(02/16/08/29, "3035550002","Ale Sipura 2")
*/
void mgcpCallerID(gchar *signalStr, gchar **callerId)
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
void mgcpDialedDigits(gchar *signalStr, gchar **dialedDigits)
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
	voip_calls_info_t *strinfo = NULL;
	mgcp_calls_info_t *tmp_mgcpinfo = NULL;
	GList* list;
	GList* listGraph;
	gchar *frame_label = NULL;
	gchar *comment = NULL;
	graph_analysis_item_t *gai;
	gboolean new = FALSE;
	gboolean fromEndpoint = FALSE; /* true for calls originated in Endpoints, false for calls from MGC */
	gdouble diff_time;

	const mgcp_info_t *pi = MGCPinfo;


	if ((pi->mgcp_type == MGCP_REQUEST) && !pi->is_duplicate ){
		/* check wether we already have a call with this Endpoint and it is active*/
		list = g_list_first(tapinfo->strinfo_list);
		while (list)
		{
			tmp_listinfo=list->data;
			if ((tmp_listinfo->protocol == VOIP_MGCP) && (tmp_listinfo->call_active_state == VOIP_ACTIVE)){
				tmp_mgcpinfo = tmp_listinfo->prot_info;
				if (pi->endpointId != NULL){
					if (g_strcasecmp(tmp_mgcpinfo->endpointId,pi->endpointId) == 0){
						/*
						   check first if it is an ended call. We consider an ended call after 1sec we don't 
						   get a packet in this Endpoint and the call has been released
						*/
						diff_time = (pinfo->fd->rel_secs + (double)pinfo->fd->rel_secs/1000000) - (tmp_listinfo->stop_sec + (double)tmp_listinfo->stop_usec/1000000);
						if ( ((tmp_listinfo->call_state == VOIP_CANCELLED) || (tmp_listinfo->call_state == VOIP_COMPLETED)  || (tmp_listinfo->call_state == VOIP_REJECTED)) && (diff_time > 1) ){
							tmp_listinfo->call_active_state = VOIP_INACTIVE;
						} else {
							strinfo = (voip_calls_info_t*)(list->data);
							break;
						}
					}
				}
			}
			list = g_list_next (list);
		}
		
		/* there is no call with this Endpoint, lets see if this a new call or not */
		if (strinfo == NULL){
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
		/* if it is a response OR if it is a duplicated Request, lets look in the Graph if thre is a request that match */
		listGraph = g_list_first(tapinfo->graph_analysis->list);
		while (listGraph)
		{
			gai = listGraph->data;
			if (gai->frame_num == pi->req_num){
				/* there is a request that match, so look the associated call with this call_num */
				list = g_list_first(tapinfo->strinfo_list);
				while (list)
				{
					tmp_listinfo=list->data;
					if (tmp_listinfo->protocol == VOIP_MGCP){
						if (tmp_listinfo->call_num == gai->conv_num){
							tmp_mgcpinfo = tmp_listinfo->prot_info;
							strinfo = (voip_calls_info_t*)(list->data);
							break;
						}
					}
					list = g_list_next (list);
				}
				if (strinfo != NULL) break;
			}
			listGraph = g_list_next(listGraph);
		}
		/* if there is not a matching request, just return */
		if (strinfo == NULL) return 0;
	} else return 0;

	/* not in the list? then create a new entry */
	if (strinfo==NULL){
		strinfo = g_malloc(sizeof(voip_calls_info_t));
		strinfo->call_active_state = VOIP_ACTIVE;
		strinfo->call_state = VOIP_CALL_SETUP;
		if (fromEndpoint) {
			strinfo->from_identity=g_strdup(pi->endpointId);
			strinfo->to_identity=g_strdup("");
		} else {
			strinfo->from_identity=g_strdup("");
			strinfo->to_identity=g_strdup(pi->endpointId);
		}
		COPY_ADDRESS(&(strinfo->initial_speaker),&(pinfo->src));
		strinfo->first_frame_num=pinfo->fd->num;
		strinfo->selected=FALSE;
		strinfo->start_sec=pinfo->fd->rel_secs;
		strinfo->start_usec=pinfo->fd->rel_usecs;
		strinfo->protocol=VOIP_MGCP;
		strinfo->prot_info=g_malloc(sizeof(mgcp_calls_info_t));
		tmp_mgcpinfo=strinfo->prot_info;
		tmp_mgcpinfo->endpointId = g_strdup(pi->endpointId);
		tmp_mgcpinfo->fromEndpoint = fromEndpoint;
		strinfo->npackets = 0;
		strinfo->call_num = tapinfo->ncalls++;
		tapinfo->strinfo_list = g_list_append(tapinfo->strinfo_list, strinfo);
	}

	g_assert(tmp_mgcpinfo != NULL);

	/* change call state and add to graph */
	switch (pi->mgcp_type)
	{
	case MGCP_REQUEST:
		if ( (strcmp(pi->code, "NTFY") == 0) && (pi->observedEvents != NULL) ){
			frame_label = g_strdup_printf("%s ObsEvt:%s",pi->code, pi->observedEvents);

			if (tmp_mgcpinfo->fromEndpoint){
				/* use the Dialed digits to fill the "To" for the call */
				mgcpDialedDigits(pi->observedEvents, &(strinfo->to_identity));

			/* from MGC and the user picked up, the call is connected */
			} else if (isSignal("hd", pi->observedEvents))  
				strinfo->call_state=VOIP_IN_CALL;

			/* hung up signal */
			if (isSignal("hu", pi->observedEvents)) {
				if ((strinfo->call_state == VOIP_CALL_SETUP) || (strinfo->call_state == VOIP_RINGING)){
					strinfo->call_state = VOIP_CANCELLED;
				} else {
					strinfo->call_state = VOIP_COMPLETED;
				}
			}	
			
		} else if (strcmp(pi->code, "RQNT") == 0) {
			/* for calls from Endpoint: if there is a "no signal" RQNT and the call was RINGING, we assume this is the CONNECT */
			if ( tmp_mgcpinfo->fromEndpoint && isSignal("", pi->signalReq) && (strinfo->call_state == VOIP_RINGING) ) { 
					strinfo->call_state = VOIP_IN_CALL;
			}

			/* if there is ringback or ring tone, change state to ringing */
			if ( isSignal("rg", pi->signalReq) || isSignal("rt", pi->signalReq) ) { 
					strinfo->call_state = VOIP_RINGING;
			}

			/* if there is a Busy or ReorderTone, and the call was Ringing or Setup the call is Rejected */
			if ( (isSignal("ro", pi->signalReq) || isSignal("bz", pi->signalReq)) && ((strinfo->call_state == VOIP_CALL_SETUP) || (strinfo->call_state = VOIP_RINGING)) ) { 
					strinfo->call_state = VOIP_REJECTED;
			}

			if (pi->signalReq != NULL)
				frame_label = g_strdup_printf("%s%sSigReq:%s",pi->code, (pi->hasDigitMap == TRUE)?" DigitMap ":"", pi->signalReq);
			else
				frame_label = g_strdup_printf("%s%s",pi->code, (pi->hasDigitMap == TRUE)?" DigitMap ":"");
			
			/* use the CallerID info to fill the "From" for the call */
			if (!tmp_mgcpinfo->fromEndpoint) mgcpCallerID(pi->signalReq, &(strinfo->from_identity));

		} else if (strcmp(pi->code, "DLCX") == 0) {
			/*
			  if there is a DLCX in a call To an Endpoint and the call was not connected, we use
			  the DLCX as the end of the call
			*/
			if (!tmp_mgcpinfo->fromEndpoint){
				if ((strinfo->call_state == VOIP_CALL_SETUP) || (strinfo->call_state == VOIP_RINGING)){
					strinfo->call_state = VOIP_CANCELLED;
				} 
			} 
		}

		if (frame_label == NULL) frame_label = g_strdup_printf("%s",pi->code);
		break;
	case MGCP_RESPONSE:
		frame_label = g_strdup_printf("%d (%s)",pi->rspcode, pi->code);
		break;
	case MGCP_OTHERS:
		/* XXX what to do? */
		break;
	}


	comment = g_strdup_printf("MGCP %s %s%s", tmp_mgcpinfo->endpointId, (pi->mgcp_type == MGCP_REQUEST)?"Request":"Response", pi->is_duplicate?" Duplicate":"");

	strinfo->stop_sec=pinfo->fd->rel_secs;
	strinfo->stop_usec=pinfo->fd->rel_usecs;
	strinfo->last_frame_num=pinfo->fd->num;
	++(strinfo->npackets);
	/* increment the packets counter of all calls */
	++(tapinfo->npackets);

	/* add to the graph */
	add_to_graph(tapinfo, pinfo, frame_label, comment, strinfo->call_num);  
	g_free(comment);
	g_free(frame_label);

	/* add SDP info if apply */
	if ( (sdp_summary != NULL) && (sdp_frame_num == pinfo->fd->num) ){
			append_to_frame_graph(tapinfo, pinfo->fd->num, sdp_summary, NULL);
			g_free(sdp_summary);
			sdp_summary = NULL;
	}

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
		/* don't register tap listener, if we have it already */
		/* we send an empty filter, to force a non null "tree" in the mgcp dissector */
		error_string = register_tap_listener("mgcp", &(the_tapinfo_struct.mgcp_dummy), strdup(""),
			voip_calls_dlg_reset, 
			MGCPcalls_packet, 
			voip_calls_dlg_draw
			);
		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_MGCP_tap_listener=TRUE;
	}
}



/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

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
/* ***************************TAP for OTHER PROTOCOL **********************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a prot_ packet is seen by the tap listener */
/*
static int 
prot_calls_packet(void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prot_info _U_)
{
	voip_calls_tapinfo_t *tapinfo = &the_tapinfo_struct;
	if (strinfo!=NULL){
		strinfo->stop_sec=pinfo->fd->rel_secs;
		strinfo->stop_usec=pinfo->fd->rel_usecs;
		strinfo->last_frame_num=pinfo->fd->num;
		++(strinfo->npackets);
		++(tapinfo->npackets);
	}

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
			voip_calls_dlg_reset,
			prot__calls_packet, 
			voip_calls_dlg_draw
			);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
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

