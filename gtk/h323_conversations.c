/* h323_conversations.c
 * H323 conversations summary addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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

#include "h323_conversations.h"
#include "h323_conversations_dlg.h"

#include "globals.h"

#include <epan/tap.h>
#include <epan/dissectors/packet-h225.h>
#include <epan/dissectors/packet-h245.h>

#include "alert_box.h"
#include "simple_dialog.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

char *transport_prot_name[256] ={
	"","","","","","","tcp","","","",  /* 0 to 10 */
    "","","","","","","","udp","","",  /* 10 to 20 */
    "","","","","","","","","","",     /* 20 to 30 */
    "","","","","","","","","","",     /* 30 to 40 */
    "","","","","","","","","","",     /* 40 to 50 */
    "","","","","","","","","","",     /* 50 to 60 */
    "","","","","","","","","","",     /* 60 to 70 */
    "","","","","","","","","","",     /* 70 to 80 */
    "","","","","","","","","","",     /* 80 to 90 */
    "","","","","","","","","","",     /* 90 to 100 */
    "","","","","","","","","","",     /* 100 to 110 */
    "","","","","","","","","","",     /* 110 to 120 */
    "","","","","","","","","","",     /* 120 to 130 */
    "","","sctp","","","","","","","", /* 130 to 140 */
    "","","","","","","","","","",     /* 140 to 150 */
    "","","","","","","","","","",     /* 150 to 160 */
    "","","","","","","","","","",     /* 160 to 170 */
    "","","","","","","","","","",     /* 170 to 180 */
    "","","","","","","","","","",     /* 180 to 190 */
    "","","","","","","","","","",     /* 190 to 200 */
    "","","","","","","","","","",     /* 200 to 210 */
    "","","","","","","","","","",     /* 210 to 220 */
    "","","","","","","","","","",     /* 220 to 230 */
    "","","","","","","","","","",     /* 230 to 240 */
    "","","","","","","","","","",     /* 240 to 250 */
    "","","","","",""                  /* 250 to 255 */
    };

/****************************************************************************/
/* the one and only global h323conversations_tapinfo_t structure */
static h323conversations_tapinfo_t the_tapinfo_struct =
	{0, NULL, 0, NULL, 0, 0, 0, 0};

/****************************************************************************/
/* GCompareFunc style comparison function for _h323_conversations_info */
gint h323_conversations_info_cmp(gconstpointer aa, gconstpointer bb)
{
	const struct _h323_conversations_info* a = aa;
	const struct _h323_conversations_info* b = bb;

	if (a==b)
		return 0;
	if (a==NULL || b==NULL)
		return 1;
	if ((a->src_addr == b->src_addr)
		&& (a->src_port == b->src_port)
		&& (a->dest_addr == b->dest_addr)
		&& (a->dest_port == b->dest_port)
		&& (a->transport == b->transport)
		)
		return 0;
	else if ((a->src_addr == b->dest_addr)
		&& (a->src_port == b->dest_port)
		&& (a->dest_addr == b->src_addr)
		&& (a->dest_port == b->src_port)
		&& (a->transport == b->transport)
		)
		return 0;
	else
		return 1;
}


/****************************************************************************/
/* when there is a [re]reading of packet's */
void h225conversations_reset(h323conversations_tapinfo_t *tapinfo)
{
	GList* list;

	/* free the data items first */
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapinfo->strinfo_list);
	tapinfo->strinfo_list = NULL;
	tapinfo->nconversationss = 0;
	tapinfo->npackets = 0;
	tapinfo->setup_packets = 0;
        tapinfo->completed_calls = 0;
        tapinfo->rejected_calls = 0;

	++(tapinfo->launch_count);

	return;
}

/****************************************************************************/
/* redraw the output */
void h225conversations_draw(h323conversations_tapinfo_t *tapinfo _U_)
{
/* XXX: see h323conversations_on_update in h323_conversationss_dlg.c for comments
	gtk_signal_emit_by_name(top_level, "signal_h225conversations_update");
*/
	h323conversations_dlg_update(the_tapinfo_struct.strinfo_list);
	return;
}



/****************************************************************************/
/* whenever a H225 packet is seen by the tap listener */
int h225conversations_packet(h323conversations_tapinfo_t *tapinfo _U_, packet_info *pinfo, epan_dissect_t *edt _U_, void *h225info)
{
	h323_conversations_info_t tmp_strinfo;
	h323_conversations_info_t *strinfo = NULL;
	GList* list;

	h225_packet_info *pi = h225info;
	
	/* TODO: evaluate RAS Messages. Just ignore them for now*/
	if(pi->msg_type==H225_RAS)
		return 0;

	/* gather infos on the conversations this packet is part of */
	g_memmove(&(tmp_strinfo.src_addr), pinfo->src.data, 4);
	tmp_strinfo.src_port = pinfo->srcport;
	g_memmove(&(tmp_strinfo.dest_addr), pinfo->dst.data, 4);
	tmp_strinfo.dest_port = pinfo->destport;
	tmp_strinfo.transport = pinfo->ipproto;


		/* check wether we already have a conversations with these parameters in the list */
		list = g_list_first(tapinfo->strinfo_list);
		while (list)
		{
			if (h323_conversations_info_cmp(&tmp_strinfo, (h323_conversations_info_t*)(list->data))==0)
			{
				strinfo = (h323_conversations_info_t*)(list->data);  /*found!*/
				break;
			}
			list = g_list_next(list);
		}

		/* not in the list? then create a new entry */
		if (!strinfo) {
			tmp_strinfo.call_state = UNKNOWN;
			tmp_strinfo.npackets = 0;
			tmp_strinfo.h245packets = 0;
			tmp_strinfo.first_frame_num = pinfo->fd->num;
			tmp_strinfo.faststart = pi->is_faststart; 
			tmp_strinfo.is_h245 = pi->is_h245; 
			tmp_strinfo.h245address = pi->h245_address; 
			tmp_strinfo.h245port = pi->h245_port; 
			strinfo = g_malloc(sizeof(h323_conversations_info_t));
			*strinfo = tmp_strinfo;  /* memberwise copy of struct */
			tapinfo->strinfo_list = g_list_append(tapinfo->strinfo_list, strinfo);

		}
		/* ok, there is an entry, but is it also an entry for h.245 address.
		 * h.245 address can be provided in connect message, but entry for this conversation
		 * already exists at this point */
		else if (pi->is_h245) {
			strinfo->is_h245 = pi->is_h245; 
			strinfo->h245address = pi->h245_address; 
			strinfo->h245port = pi->h245_port; 
		}

		/* we check the faststart again in the connect message, if there is no
		 * faststart field in connect message, we asume, there is no faststart */
		if ((pi->cs_type == H225_CONNECT) && (pi->is_faststart == 0))
			strinfo->faststart = 0;

		/* in the list or not in the list, we want the status */
		/* we have four states: CALL SETUP, IN_CALL, COMPLETED, REJECTED 
		 * CALL_SETUP: if the setup, call proceding, alerting, 
		 * IN_CALL: connect 
		 * COMPLETED: release complete after connect
		 * REJECTED: release complete without connect
		 */
		switch (pi->cs_type) {

	                case H225_SETUP:
        			strinfo->call_state = CALL_SETUP;
				++(tapinfo->setup_packets);
        	                break;
        	        case H225_CALL_PROCEDING:
        			strinfo->call_state = CALL_SETUP;
        	                break;
			case H225_ALERTING:
        			strinfo->call_state = CALL_SETUP;
        	                break;
                	case H225_CONNECT:
        			strinfo->call_state = IN_CALL;
        	                break;
	                case H225_RELEASE_COMPLET:
				if (strinfo->call_state == IN_CALL) {
					strinfo->call_state = COMPLETED;
        				++(tapinfo->completed_calls);
				}
				else if (strinfo->call_state == CALL_SETUP) {
					strinfo->call_state = REJECTED;
        				++(tapinfo->rejected_calls);
				}
				else if (strinfo->call_state == COMPLETED)
					strinfo->call_state = COMPLETED;
				else if (strinfo->call_state == REJECTED)
					strinfo->call_state = REJECTED;
				else 
					strinfo->call_state = UNKNOWN;
	                case H225_OTHER:
				;
                }

		/* increment the packets counter for this conversations */
		++(strinfo->npackets);

		/* increment the packets counter of all conversationss */
		++(tapinfo->npackets);
		
		return 1;  /* refresh output */
}


/****************************************************************************/
const h323conversations_tapinfo_t* h323conversations_get_info(void)
{
	return &the_tapinfo_struct;
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
static gboolean have_h225_tap_listener=FALSE;
/****************************************************************************/
void
h225conversations_init_tap(void)
{
	GString *error_string;
	
	h225conversations_reset(&the_tapinfo_struct);

	if(have_h225_tap_listener==FALSE)
	{
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("h225", &the_tapinfo_struct, NULL,
			(void*)h225conversations_reset, (void*)h225conversations_packet, (void*)h225conversations_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_h225_tap_listener=TRUE;
	}
}


/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

/****************************************************************************/
void
remove_tap_listener_h225_conversations(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&the_tapinfo_struct);
	unprotect_thread_critical_region();
	
	have_h225_tap_listener=FALSE;
}


/****************************************************************************/
/* ***************************TAP for h245 **********************************/
/****************************************************************************/

/****************************************************************************/
/* redraw the output */
void h245conversations_draw(h323conversations_tapinfo_t *tapinfo _U_)
{
	h323conversations_dlg_update(the_tapinfo_struct.strinfo_list);
	return;
}

/****************************************************************************/
/* whenever a H245 packet is seen by the tap listener */
int h245conversations_packet(h323conversations_tapinfo_t *tapinfo _U_, packet_info *pinfo, epan_dissect_t *edt _U_, void *h245info _U_)
{
	GList* list;
	struct _h323_conversations_info* a;
	guint32 src, dst;
	guint16 srcp, dstp;
	guint16 p_transport;

	/* check wether this packet is a part of any H323 conversation in the list*/
	list = g_list_first(tapinfo->strinfo_list);
	while (list)
	{
		a = (h323_conversations_info_t*)(list->data);
		g_memmove(&src, pinfo->src.data, 4);
		g_memmove(&dst, pinfo->dst.data, 4);
		//src = *(pinfo->src.data);
		//dst = *(pinfo->dst.data);
		srcp = pinfo->srcport;
		dstp = pinfo->destport;
		p_transport = pinfo->ipproto;
		if ( ((a->h245address == src) && (a->h245port == srcp) && (a->transport == p_transport)) ||
				( (a->h245address == dst) && (a->h245port == dstp) && (a->transport == p_transport)) ) {
				/* in the list? increment packet number */
				++(a->h245packets);
			break;
		}
		list = g_list_next(list);
	}

	return 1;  /* refresh output */
}

/****************************************************************************/
static gboolean have_h245_tap_listener=FALSE;

void
h245conversations_init_tap(void)
{
	GString *error_string;
	
	if(have_h245_tap_listener==FALSE)
	{ 
		/* don't register tap listener, if we have it already */
		error_string = register_tap_listener("h245", &the_tapinfo_struct,
			NULL,
			(void*)h245conversations_reset, (void*)h245conversations_packet, (void*)h245conversations_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}
		have_h245_tap_listener=TRUE;
	}
}

/****************************************************************************/
void
remove_tap_listener_h245_conversations(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&the_tapinfo_struct);
	unprotect_thread_critical_region();
	
	have_h245_tap_listener=FALSE;
}


/****************************************************************************/

void h245conversations_reset(h323conversations_tapinfo_t *tapinfo _U_)
{
	return;
}

