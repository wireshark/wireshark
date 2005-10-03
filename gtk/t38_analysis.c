/* t38_analysis.c
 * t38 fax analysis for ethereal
 *
 * $Id$
 *
 * Copyright 2005 Verso Technologies Inc.
 * By Alejandro Vaquero <alejandro.vaquero@verso.com>
 *
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

#include "globals.h"

#include <epan/tap.h>
#include <epan/epan_dissect.h>
#include <epan/dissectors/packet-t38.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/conversation.h>
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"

#include "main.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "graph_analysis.h"

#define MAX_HDLC_FRAME 1024

typedef enum {
	UNKNOWN,
    CORRECT, 
    EARLY,	/* seq_num > than expected, we assume all previous as lost */
    LATE    /* seq_num < than expected, late packet we drop it */
} SEQ_STATUS;

typedef struct _tap_t38_stat_t {
	gboolean first_packet;
	gint32 seq_num;	/* UDPTLPacket sequence number */
	gint32 wrong_seq_num;	/* count UDPTLPacket wron sequence number */
	guint8 hdlc_data[MAX_HDLC_FRAME];  /* V21 HDLC data */
	guint16 hdlc_data_index;			/* V21 HDLC index */
	gboolean valid_hdlc_data;
	guint32 other_data_num_bytes;		/* num of bytes of other data (non hdlc) */
	guint32 other_data_lost;		/* num of packet lost (wrong seq num) of other data (non hdlc) */
	guint32 other_data_max_burst_lost;	/* max burst num of packet lost (wrong seq num) of other data (non hdlc) */
	guint32 other_data_burst_lost;	/* burst num of packet lost (wrong seq num) of other data (non hdlc) */
	gint32 start_frame_other_data; /* start frame of other_data */
	double start_time_other_data; /* start time of other_data */
	SEQ_STATUS prev_seq_status;   /*previous seq num status used to calclate the busrt error */

} tap_t38_stat_t;

/* structure that holds general information about the connection 
* and structures for both directions */
typedef struct _user_data_t {
	/* tap associated data*/
	address ip_src_fwd;
	guint16 port_src_fwd;
	address ip_dst_fwd;
	guint16 port_dst_fwd;
	address ip_src_rev;
	guint16 port_src_rev;
	address ip_dst_rev;
	guint16 port_dst_rev;

	tap_t38_stat_t forward;
	tap_t38_stat_t reverse;

	graph_analysis_data_t *graph_analysis_data;
} user_data_t;





/****************************************************************************/
/* Add a new item into the graph */
int add_to_graph_t38(user_data_t *user_data, packet_info *pinfo, const gchar *frame_label, gchar *comment, gint line_style)
{
	graph_analysis_item_t *gai;

	gai = g_malloc(sizeof(graph_analysis_item_t));
	gai->frame_num = pinfo->fd->num;
	gai->time= nstime_to_sec(&pinfo->fd->rel_ts);
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
	gai->conv_num=1;
	gai->line_style=line_style; /* 1=single line   2=dual line */
	gai->display=TRUE;

	user_data->graph_analysis_data->graph_info->list = g_list_append(user_data->graph_analysis_data->graph_info->list, gai);

	return 1;
}

/****************************************************************************/
/* Change the frame_label and comment in a graph item if not NULL*/
/* return 0 if the frame_num is not in the graph list */
int change_frame_graph_t38(user_data_t *user_data, gint32 frame_num, const gchar *new_frame_label, const gchar *new_comment)
{
	graph_analysis_item_t *gai;
	GList* list;
	gchar *tmp_str = NULL;
	gchar *tmp_str2 = NULL;

	if (frame_num == -1) return 0;

	list = g_list_first(user_data->graph_analysis_data->graph_info->list);
	while (list)
	{
		gai = list->data;
		if (gai->frame_num == (guint32) frame_num){
			tmp_str = gai->frame_label;
			tmp_str2 = gai->comment;

			if (new_frame_label != NULL){
				gai->frame_label = g_strdup(new_frame_label);
				g_free(tmp_str);
			}

			if (new_comment != NULL){
				gai->comment = g_strdup(new_comment);
				g_free(tmp_str2);
			}
			break;
		}
		list = g_list_next (list);
	}
	if (tmp_str == NULL) return 0;		/* it is not in the list */
	return 1;
}

/* TODO: Dissect the complete t30 HDLC packets */
#if 0
#define MAX_DESC 1024 
void dissect_t30_DIS_DTC(guint8 *data, guint len)
{
	guint8 octet;
	int offset;
	gchar  buf[MAX_DESC];

	offset = 3;

	if (len == 0)
		return;
	octet = data[offset];

	g_snprintf(buf, MAX_DESC, "%sStore and forward Internet fax- Simple mode (ITU-T T.37)", octet&0x80?"":"No ");

	g_snprintf(buf, MAX_DESC, "%sReal-time Internet fax (ITU T T.38)", octet&0x20?"":"No ");

	g_snprintf(buf, MAX_DESC, "%s3rd Generation Mobile Network ", octet&0x10?"":"No ")
}
#endif

/****************************************************************************/
static const value_string t30_facsimile_control_field_vals_short[] = {
	{ 0x01, "DIS" },
	{ 0x02, "CSI" },
	{ 0x04, "NSF" },
	{ 0x81, "DTC" },
	{ 0x82, "CIG" },
	{ 0x84, "NSC" },
	{ 0x83, "PWD" },
	{ 0x85, "SEP" },
	{ 0x86, "PSA" },
	{ 0x87, "CIA" },
	{ 0x88, "ISP" },
	{ 0x41, "DCS" },
	{ 0x42, "TSI" },
	{ 0x44, "NSS" },
	{ 0x43, "SUB" },
	{ 0x45, "SID" },
	{ 0x46, "TSA" },
	{ 0x47, "IRA" },
	{ 0x21, "CFR" },
	{ 0x22, "FTT" },
	{ 0x24, "CSA" },
	{ 0x71, "EOM" },
	{ 0x72, "MPS" },
	{ 0x74, "EOP" },
	{ 0x79, "PRI-EOM" },
	{ 0x7A, "PRI-MPS" },
	{ 0x7C, "PRI-EOP" },
	{ 0x78, "PRI-EOP" },
	{ 0x31, "MCF" },
	{ 0x33, "RTP" },
	{ 0x32, "RTN" },
	{ 0x35, "PIP" },
	{ 0x34, "PIN" },
	{ 0x3F, "FDM" },
	{ 0x5F, "DCN" },
	{ 0x58, "CRP" },
	{ 0x53, "FNV" },
	{ 0x57, "TNR" },
	{ 0x56, "TR" }
};

static const value_string t30_facsimile_control_field_vals[] = {
	{ 0x01, "Digital Identification Signal" },
	{ 0x02, "Called Subscriber Identification" },
	{ 0x04, "Non-Standard Facilities" },
	{ 0x81, "Digital Transmit Command" },
	{ 0x82, "Calling Subscriber Identification" },
	{ 0x84, "Non-Standard facilities Command" },
	{ 0x83, "Password" },
	{ 0x85, "Selective Polling" },
	{ 0x86, "Polled Subaddress" },
	{ 0x87, "Calling subscriber Internet Address" },
	{ 0x88, "Internet Selective Polling Address" },
	{ 0x41, "Digital Command Signal" },
	{ 0x42, "Transmitting Subscriber Identification" },
	{ 0x44, "Non-Standard facilities Set-up" },
	{ 0x43, "Subaddress" },
	{ 0x45, "Sender Identification" },
	{ 0x46, "Transmitting Subscriber Internet address" },
	{ 0x47, "Internet Routing Address" },
	{ 0x21, "Confirmation To Receive" },
	{ 0x22, "Failure To Train" },
	{ 0x24, "Called Subscriber Internet Address" },
	{ 0x71, "End Of Message" },
	{ 0x72, "MultiPage Signal" },
	{ 0x74, "End Of Procedure" },
	{ 0x79, "Procedure Interrupt-End Of Message" },
	{ 0x7A, "Procedure Interrupt-MultiPage Signal" },
	{ 0x7C, "Procedure Interrupt-End Of Procedure" },
	{ 0x78, "Procedure Interrupt-End Of Procedure" },
	{ 0x31, "Message Confirmation" },
	{ 0x33, "Retrain Positive" },
	{ 0x32, "Retrain Negative" },
	{ 0x35, "Procedure Interrupt Positive" },
	{ 0x34, "Procedure Interrupt Negative" },
	{ 0x3F, "File Diagnostics Message" },
	{ 0x5F, "Disconnect" },
	{ 0x58, "Command Repeat" },
	{ 0x53, "Field Not Valid" },
	{ 0x57, "Transmit not ready" },
	{ 0x56, "Transmit ready" }

};

static const value_string data_vals[] = {
	{ 0, "v21" },
	{ 1, "v27-2400" },
	{ 2, "v27-4800" },
	{ 3, "v29-7200" },
	{ 4, "v29-9600" },
	{ 5, "v17-7200" },
	{ 6, "v17-9600" },
	{ 7, "v17-12000" },
	{ 8, "v17-14400" },
	{ 9, "v8" },
	{ 10, "v34-pri-rate" },
	{ 11, "v34-CC-1200" },
	{ 12, "v34-pri-ch" },
	{ 13, "v33-12000" },
	{ 14, "v33-14400" },
	{ 0, NULL },
};

void dissect_t30(tap_t38_stat_t *statinfo,
 							  user_data_t *user_data _U_,
                              packet_info *pinfo,
							  guint32 data_value
)
{
	gchar *frame_label = NULL;
	gchar *comment = NULL;
	guint8 octet;

	octet = statinfo->hdlc_data[2];

/* TODO: Dissect the complete t30 HDLC packets */
#if 0
	/* Facsimile Control Field (FCF) */
	if ( ((octet&0xF0) == 0x00) || ((octet&0xF0) == 0x80) ) { /* Initial identification  or Command to send */
		frame_label = g_strdup_printf("%s:hdlc:%s", val_to_str(data_value, data_vals, "Ukn (0x%02X)"), val_to_str(octet, t30_facsimile_control_field_vals_short, "Ukn (0x%02X)"));
		comment = g_strdup_printf("%s:HDLC:%s",val_to_str(data_value, data_vals, "Ukn (0x%02X)"), val_to_str(octet, t30_facsimile_control_field_vals, "Ukn (0x%02X)"));
		if ( (octet == 0x01) || (octet == 0x81) ) {
			dissect_t30_DIS_DTC(statinfo->hdlc_data, statinfo->hdlc_data_index);
		}
	} else { /* all other values */
		frame_label = g_strdup_printf("%s:hdlc:%s", val_to_str(data_value, data_vals, "Ukn (0x%02X)"), val_to_str(octet&0x7F, t30_facsimile_control_field_vals_short, "Ukn (0x%02X)"));
		comment = g_strdup_printf("%s:HDLC:%s",val_to_str(data_value, data_vals, "Ukn (0x%02X)"), val_to_str(octet&0x7F, t30_facsimile_control_field_vals, "Ukn (0x%02X)"));
	}
#else
	frame_label = g_strdup_printf("%s:hdlc:%s", val_to_str(data_value, data_vals, "Ukn (0x%02X)"), val_to_str(octet&0x7F, t30_facsimile_control_field_vals_short, "Ukn (0x%02X)"));
	comment = g_strdup_printf("%s:HDLC:%s",val_to_str(data_value, data_vals, "Ukn (0x%02X)"), val_to_str(octet&0x7F, t30_facsimile_control_field_vals, "Ukn (0x%02X)"));
#endif
	add_to_graph_t38(user_data, pinfo, frame_label, comment, 2);
}

/****************************************************************************/
int t38_packet_analyse(tap_t38_stat_t *statinfo,
							  user_data_t *user_data _U_,
                              packet_info *pinfo,
                              const t38_packet_info *t38_info)
{
	gchar *frame_label = NULL;
	gchar *comment = NULL;
	SEQ_STATUS seq_status = UNKNOWN;
	
	/* if it is duplicated, just return */
	if (statinfo->seq_num == t38_info->seq_num) return 0;

	/* if it is the correct seq or first packet */
	if ( (statinfo->seq_num+1 == t38_info->seq_num) || (statinfo->seq_num == -1) ) seq_status = CORRECT;

	/* EARLY: seq_num > than expexted */
	else if (t38_info->seq_num > statinfo->seq_num+1 ) seq_status = EARLY;

	/* LATE: seq_num < than expexted */
	else if (t38_info->seq_num < statinfo->seq_num+1 ) seq_status = LATE;

		
	if (t38_info->type_msg == 0) {	/*  t30-indicator */
		frame_label = g_strdup_printf("t30 Ind:%s",val_to_str(t38_info->t30ind_value, t30_indicator_vals, "Ukn (0x%02X)") );
		comment = g_strdup_printf("t30 Ind:%s",val_to_str(t38_info->t30ind_value, t30_indicator_vals, "Ukn (0x%02X)") );
		add_to_graph_t38(user_data, pinfo, frame_label, comment, 1);

		/* reset other_data stats in case we never got the previos t4-non-ecm-sig-end */
		statinfo->other_data_num_bytes = 0;
		statinfo->other_data_lost = 0;
		statinfo->start_frame_other_data = -1;
		statinfo->prev_seq_status = CORRECT;
		statinfo->other_data_max_burst_lost = 0;
		statinfo->other_data_burst_lost = 0;
		statinfo->start_time_other_data = 0;
	} else if (t38_info->type_msg == 1) {	/*  data */
		int i;
		for (i=0; i<t38_info->t38_info_data_item_index; i++) {
			switch(t38_info->data_type[i]){
			case 0: /* hdlc-data */
				/* if it is hdlc-data add it to the array */
				/* check we'll not excede the array */
				if (statinfo->hdlc_data_index+t38_info->data_len[i] < MAX_HDLC_FRAME) {
					g_memmove(&statinfo->hdlc_data[statinfo->hdlc_data_index], t38_info->data[i],t38_info->data_len[i]);
					statinfo->hdlc_data_index += t38_info->data_len[i];
				}
				if (seq_status != CORRECT) statinfo->valid_hdlc_data = FALSE;
				break;
			case 2: /* hdlc-fcs-OK */
			case 4: /* hdlc-fcs-OK-sig-end */
				if (statinfo->valid_hdlc_data)
					dissect_t30(statinfo, user_data, pinfo, t38_info->data_value);
				else {
					frame_label = g_strdup_printf("%s:hdlc:not decoded",val_to_str(t38_info->data_value, data_vals, "Ukn (0x%02X)"));
					comment = g_strdup_printf("%s:HDLC:ERROR: wrong seq number in HDLC packet(s)",val_to_str(t38_info->data_value, data_vals, "Ukn (0x%02X)"));
					add_to_graph_t38(user_data, pinfo, frame_label, comment, 2);
				}
				statinfo->hdlc_data_index = 0;
				statinfo->valid_hdlc_data = TRUE;
				break;
			case 1: /* hdlc-sig-end */
				if (statinfo->hdlc_data_index != 0) { /* if there was no fcs-OK, this is an error */
					frame_label = g_strdup_printf("%s:hdlc:hdlc-sig-end",val_to_str(t38_info->data_value, data_vals, "Ukn (0x%02X)"));
					comment = g_strdup_printf("%s:HDLC:ERROR: received hdlc-sig-end without received fcs-OK or fcs-BAD",val_to_str(t38_info->data_value, data_vals, "Ukn (0x%02X)"));
					add_to_graph_t38(user_data, pinfo, frame_label, comment, 2);
					statinfo->hdlc_data_index = 0;
				}
				break;
			case 3: /* hdlc-fcs-BAD */
			case 5: /* hdlc-fcs-BAD-sig-end */
				frame_label = g_strdup_printf("%s:hdlc:%s",val_to_str(t38_info->data_value, data_vals, "Ukn (0x%02X)"),t38_info->data_type[i] == 3 ? "fcs-BAD" : "fcs-BAD-sig-end" );
				comment = g_strdup_printf("WARNING: received %s:hdlc:%s", val_to_str(t38_info->data_value, data_vals, "Ukn (0x%02X)"), t38_info->data_type[i] == 3 ? "fcs-BAD" : "fcs-BAD-sig-end");
				add_to_graph_t38(user_data, pinfo, frame_label, comment, 2);
				statinfo->hdlc_data_index = 0;
				break;
			} 
			if ( (t38_info->data_type[i] == 6) || (t38_info->data_type[i] == 7) ) { /* t4-non-ecm-data or t4-non-ecm-sig-end */
				statinfo->other_data_num_bytes += t38_info->data_len[i];
				if (seq_status != CORRECT) { 
					statinfo->other_data_lost++;
					statinfo->other_data_burst_lost++;
				} else {
					if (statinfo->other_data_burst_lost > statinfo->other_data_max_burst_lost) 
						statinfo->other_data_max_burst_lost = statinfo->other_data_burst_lost;
						statinfo->other_data_burst_lost = 0;
				}
				if (statinfo->start_frame_other_data == -1) {
					statinfo->start_frame_other_data = pinfo->fd->num;
					statinfo->start_time_other_data = nstime_to_sec(&pinfo->fd->rel_ts);
				}

				frame_label = g_strdup_printf("data:%s",val_to_str(t38_info->data_value, data_vals, "Ukn (0x%02X)")  );
				comment = g_strdup_printf("Num of bytes: %d  Duration: %.2fs Wrong seq num: %d  Burst pack lost: %d", 
					statinfo->other_data_num_bytes, 
					nstime_to_sec(&pinfo->fd->rel_ts) - statinfo->start_time_other_data,
					statinfo->other_data_lost, 
					statinfo->other_data_max_burst_lost);
				if ( !change_frame_graph_t38(user_data, statinfo->start_frame_other_data, frame_label, comment) )
					add_to_graph_t38(user_data, pinfo, frame_label, comment, 2);

				if (t38_info->data_type[i] == 7) { /* t4-non-ecm-sig-end reset values */
					statinfo->other_data_num_bytes = 0;
					statinfo->other_data_lost = 0;
					statinfo->start_frame_other_data = -1;
					statinfo->prev_seq_status = CORRECT;
					statinfo->other_data_max_burst_lost = 0;
					statinfo->other_data_burst_lost = 0;
				}
			}
		}
	}
	if (seq_status != LATE) statinfo->seq_num = t38_info->seq_num;
	g_free(frame_label);
	g_free(comment);
	return 0;
}

/****************************************************************************/
/* whenever a T38 packet is seen by the tap listener */
static int t38_packet(void *user_data_arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *t38_info_arg)
{
	user_data_t *user_data = user_data_arg;
	const t38_packet_info *t38_info = t38_info_arg;
	/* we ignore packets that are not displayed */
	if (pinfo->fd->flags.passed_dfilter == 0)
		return 0;
	/* is it the forward direction?  */
	else if (CMP_ADDRESS(&(user_data->ip_src_fwd), &(pinfo->net_src)) == 0
		&& user_data->port_src_fwd == pinfo->srcport
		&& CMP_ADDRESS(&(user_data->ip_dst_fwd), &(pinfo->net_dst)) == 0
		&& user_data->port_dst_fwd == pinfo->destport)  {
		t38_packet_analyse(&(user_data->forward),user_data, pinfo, t38_info);
	}
	/* is it the reversed direction? */
	else if (CMP_ADDRESS(&(user_data->ip_src_rev), &(pinfo->net_src)) == 0
		&& user_data->port_src_rev == pinfo->srcport
		&& CMP_ADDRESS(&(user_data->ip_dst_rev), &(pinfo->net_dst)) == 0
		&& user_data->port_dst_rev == pinfo->destport)  {
		t38_packet_analyse(&(user_data->reverse),user_data, pinfo, t38_info);
	}

	return 1;
}

/****************************************************************************/
/* reset user_data valueas and clean graph info */
static void
t38_clean(user_data_t *user_data)
{
	graph_analysis_item_t *gai;
	GList* list;

	user_data->forward.hdlc_data_index = 0;
	user_data->reverse.hdlc_data_index = 0;

	user_data->forward.wrong_seq_num = 0;
	user_data->reverse.wrong_seq_num = 0;

	user_data->forward.seq_num = -1;
	user_data->reverse.seq_num = -1;

	user_data->forward.valid_hdlc_data = TRUE;
	user_data->reverse.valid_hdlc_data = TRUE;

	user_data->forward.other_data_num_bytes = 0;
	user_data->reverse.other_data_num_bytes = 0;

	user_data->forward.other_data_lost = 0;
	user_data->reverse.other_data_lost = 0;

	user_data->forward.other_data_max_burst_lost = 0;
	user_data->reverse.other_data_max_burst_lost = 0;

	user_data->forward.other_data_burst_lost = 0;
	user_data->reverse.other_data_burst_lost = 0;

	user_data->forward.start_frame_other_data = -1;
	user_data->reverse.start_frame_other_data = -1;

	user_data->forward.start_time_other_data = 0;
	user_data->reverse.start_time_other_data = 0;

	user_data->forward.prev_seq_status = CORRECT;
	user_data->reverse.prev_seq_status = CORRECT;
	
	/* free the graph list */
	list = g_list_first(user_data->graph_analysis_data->graph_info->list);
	while (list)
	{
		gai = list->data;
		g_free(gai->frame_label);
		g_free(gai->comment);
		g_free((void *)gai->src_addr.data);
		g_free((void *)gai->dst_addr.data);
		g_free(list->data);
		list = g_list_next (list);
	}
	g_list_free(user_data->graph_analysis_data->graph_info->list);
	user_data->graph_analysis_data->graph_info->nconv = 0;
	user_data->graph_analysis_data->graph_info->list = NULL;

	return;
}


/****************************************************************************/
/* when there is a [re]reading of packet's */
static void
t38_reset(void *user_data_arg)
{
	user_data_t *user_data = user_data_arg;

	t38_clean(user_data);
	
	/* create or refresh the graph windows */
	if (user_data->graph_analysis_data->dlg.window == NULL)	/* create the window */
		graph_analysis_create(user_data->graph_analysis_data);
	else
		graph_analysis_update(user_data->graph_analysis_data);		/* refresh it */

	return;
}

/****************************************************************************/
static void
t38_draw(void *user_data_arg)
{
	user_data_t *user_data = user_data_arg;

	graph_analysis_redraw(user_data->graph_analysis_data);

	return;
}

/****************************************************************************/
/* called when the graph windows is destroyed */
static void
t38_on_destroy(void *user_data_arg)
{
	user_data_t *user_data = user_data_arg;

	/* remove tap listener */
	protect_thread_critical_region();
	remove_tap_listener(user_data);
	unprotect_thread_critical_region();

	/* free the address */
	g_free((void *)user_data->ip_src_fwd.data);
	g_free((void *)user_data->ip_dst_fwd.data);
	g_free((void *)user_data->ip_src_rev.data);
	g_free((void *)user_data->ip_dst_rev.data);

	/* clean graph info */
	t38_clean(user_data);

	g_free(user_data->graph_analysis_data->graph_info);

}

/****************************************************************************/
void t38_analysis(
		address *ip_src_fwd,
		guint16 port_src_fwd,
		address *ip_dst_fwd,
		guint16 port_dst_fwd,
		address *ip_src_rev,
		guint16 port_src_rev,
		address *ip_dst_rev,
		guint16 port_dst_rev
		)
{
	user_data_t *user_data;
	GString *error_string;

	/* init */
	user_data = g_malloc(sizeof(user_data_t));

	user_data->graph_analysis_data = graph_analysis_init();
	user_data->graph_analysis_data->graph_info = g_malloc(sizeof(graph_analysis_info_t));
	user_data->graph_analysis_data->graph_info->nconv = 0;
	user_data->graph_analysis_data->graph_info->list = NULL;

	user_data->graph_analysis_data->dlg.title = g_strdup("Fax T38 analysis");

	user_data->graph_analysis_data->dlg.inverse = TRUE;  /* to display "calling ----> called" fax call */

	user_data->graph_analysis_data->on_destroy_user_data = t38_on_destroy;
	user_data->graph_analysis_data->data = user_data;

	COPY_ADDRESS(&(user_data->ip_src_fwd), ip_src_fwd);
	user_data->port_src_fwd = port_src_fwd;
	COPY_ADDRESS(&(user_data->ip_dst_fwd), ip_dst_fwd);
	user_data->port_dst_fwd = port_dst_fwd;
	COPY_ADDRESS(&(user_data->ip_src_rev), ip_src_rev);
	user_data->port_src_rev = port_src_rev;
	COPY_ADDRESS(&(user_data->ip_dst_rev), ip_dst_rev);
	user_data->port_dst_rev = port_dst_rev;
	
	/* register tap listener */
	error_string = register_tap_listener("t38", user_data, NULL,
		t38_reset, t38_packet, t38_draw);
	if (error_string != NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
			g_string_free(error_string, TRUE);
		return;
	}

	/* retap all packets */
	cf_retap_packets(&cfile, FALSE);	
}

/****************************************************************************/
/* entry point from main menu */
void t38_analysis_cb(GtkWidget *w _U_, gpointer data _U_) 
{
	address ip_src_fwd;
	guint16 port_src_fwd;
	address ip_dst_fwd;
	guint16 port_dst_fwd;
	address ip_src_rev;
	guint16 port_src_rev;
	address ip_dst_rev;
	guint16 port_dst_rev;

	gchar filter_text[256];
	dfilter_t *sfcode;
	capture_file *cf;
	epan_dissect_t *edt;
	gint err;
	gchar *err_info;
	gboolean frame_matched;
	frame_data *fdata;

	/* Try to compile the filter. */
	strcpy(filter_text,"t38 && (ip || ipv6)");
	if (!dfilter_compile(filter_text, &sfcode)) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, dfilter_error_msg);
		return;
	}
	/* we load the current file into cf variable */
	cf = &cfile;
	fdata = cf->current_frame;
	
	/* we are on the selected frame now */
	if (fdata == NULL)
		return; /* if we exit here it's an error */

	/* dissect the current frame */
	if (!wtap_seek_read(cf->wth, fdata->file_off, &cf->pseudo_header,
	    cf->pd, fdata->cap_len, &err, &err_info)) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			cf_read_error_message(err, err_info), cf->filename);
		return;
	}
	edt = epan_dissect_new(TRUE, FALSE);
	epan_dissect_prime_dfilter(edt, sfcode);
	epan_dissect_run(edt, &cf->pseudo_header, cf->pd, fdata, NULL);
	frame_matched = dfilter_apply_edt(sfcode, edt);
	
	/* check if it is a t38 frame */
	frame_matched = dfilter_apply_edt(sfcode, edt);
	if (frame_matched != 1) {
		epan_dissect_free(edt);
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "You didn't choose a T38 packet!");
		return;
	}

	/* ok, it is a T38 frame, so let's get the ip and port values */
	COPY_ADDRESS(&(ip_src_fwd), &(edt->pi.src))
	COPY_ADDRESS(&(ip_dst_fwd), &(edt->pi.dst))
	port_src_fwd = edt->pi.srcport;
	port_dst_fwd = edt->pi.destport;

	/* assume the inverse ip/port combination for the reverse direction */
	COPY_ADDRESS(&(ip_src_rev), &(edt->pi.dst))
	COPY_ADDRESS(&(ip_dst_rev), &(edt->pi.src))
	port_src_rev = edt->pi.destport;
	port_dst_rev = edt->pi.srcport;
	
	t38_analysis(
		&ip_src_fwd,
		port_src_fwd,
		&ip_dst_fwd,
		port_dst_fwd,
		&ip_src_rev,
		port_src_rev,
		&ip_dst_rev,
		port_dst_rev
	);
	
}

/****************************************************************************/
static void
t38_analysis_init(char *dummy _U_)
{
	t38_analysis_cb(NULL, NULL);
}

/****************************************************************************/
void
register_tap_listener_t38_analysis(void)
{
	register_stat_cmd_arg("t38", t38_analysis_init);


	register_stat_menu_item("Fax T38 Analysis...", REGISTER_STAT_GROUP_TELEPHONY,
	    t38_analysis_cb, NULL, NULL, NULL);
}
