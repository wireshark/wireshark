/*
 * tap_rtp.c
 *
 * $Id: tap_rtp.c,v 1.10 2003/04/23 08:20:06 guy Exp $
 *
 * RTP analysing addition for ethereal
 *
 * Copyright 2003, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
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
 *
 * This tap works as follows:
 * When the user clicks on the RTP analisys button, we first check if it is a RTP packet.
 * If yes we store the SSRC, ip, and port values. Then the tap is registered and the 
 * redissect_packets() routine is called. So we go through all the RTP packets and search 
 * for SSRC of reversed connection (it has inversed socket parameters). If more than one 
 * is found a window is displayed where the user can select the appropriate from the list.
 * Rigth now we have the information about the converstion we are looking for (both SSRC). 
 * The redissect_packets() routine is called again. This time whenever a RTP packet with
 * matching SSRC values arrives, we store all the information we need (number, sequence
 * number, arrival time, ...) and compute the delay, jitter and wrong sequence number.
 * We add this values to CList. If the RTP packet carries voice in g711 alaw or ulaw, we
 * also store this voice information in a temp file. Window is displayed.
 * Then three buttons are available: Close, Refresh and Save voice.
 * The Refresh button calls the redissect_packets() routine again. It goes through the packets
 * again and does all the calculation again (if capturing in real time this means that some
 * more packets could come and can be computed in statistic). It also writes the sound
 * data again.
 * The Save voice button opens the dialog where we can choose the file name, format (not yet)
 * and direction we want to save. Currently it works only with g711 alaw and ulaw, and if the
 * length of captured packets is equal the length of packets on wire and if there are no padding
 * bits.    
 *
 * To do:
 * - Support for saving voice in more different formats and with more different codecs:
 *   Since this should be portable to all OS, there is only possibility to save the 
 *   voice in a file and not play it directly through the sound card. There are enough 
 *   players on all platforms, that are doing right this. What about the format? 
 *   Currently there is only support for saving as an .au file (ulaw, 8000 Hz, 8bit)
 *   There are many players for this format on all platforms (for example Windows Media Player
 *   under Windows, command play under Linux). Support will be added for wav format and 
 *   possibility to save with two channels (separate channel for each direction)
 *
 * - Support for more codecs. Now you can save voice only if the codec is g.711 alaw or ulaw.
 *
 * - right now, the reversed connection must have the same (only inversed) ip and port numbers.
 *   I think that there is no reason that in special cases the reversed connection would not use 
 *   some different port or even the IP combination (please correct me if I am wrong). 
 *   So this will be added soon.
 *
 * - some more statistics (delay and jitter distribution)
 *
 * - GTK2 implementation
 *
 * - grammar correction
 * 
 * - some more testing (other OS)
 *
 * XXX Problems: 
 *
 * - instead of tmpnam() use of mkstemp(). 
 *   I tried to do it with mkstemp() but didn't now how to solve following  problem: 
 *   I call mkstemp() and then write in this temp file and it works fine . But if the user 
 *   then hits the refresh button, this temp file should be deleted and opened again. I tried
 *   to call close() and unlink(), but when I call mkstemp() for the second time I always get
 *   an error ( -1) as return value. What is the correct order? Is it possible to call 
 *   mkstemp() twice with the same template?    
 *
 * - problem with statistics for lost (late, duplicated) packets. How to make the statistic 
 *   more resistant to special (bizarre) arrival of sequence numbers
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include "globals.h"
#include <string.h>
#include "epan/packet_info.h"
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include "../tap.h"
#include "../register.h"
#include "../packet-rtp.h"
#include "file_dlg.h"
#include "dlg_utils.h"
#include "ui_util.h"
#include "simple_dialog.h"
#include "menu.h"
#include "main.h"
#include <math.h>
#include "progress_dlg.h"
#include "compat_macros.h"
#include "../g711.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>

#ifdef HAVE_IO_H
#include <io.h>	/* open/close on win32 */
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

static GtkWidget *rtp_w = NULL;
static GtkWidget *save_voice_as_w = NULL;
static GtkWidget *main_vb;
static GtkWidget *clist;
static GtkWidget *clist_r;
static GtkWidget *max;
static GtkWidget *max_r;

static gboolean copy_file(gchar *, /*gint,*/ gint, void *);

static char f_tempname[100], r_tempname[100];

/* type of error when saving voice in a file didn't succeed */
typedef enum {
	TAP_RTP_WRONG_CODEC,
	TAP_RTP_WRONG_LENGTH,
	TAP_RTP_PADDING_SET,
	TAP_RTP_FILE_OPEN_ERROR,
	TAP_RTP_NO_DATA
} error_type_t; 

/* structure that holds the information about the forwarding and reversed connection */
/* f_* always aplies to the forward direction and r_* to the reversed */
typedef struct _info_stat {
	gchar source[16];
	gchar destination[16];
	guint16 srcport;
	guint16 dstport;
	guint32 ssrc_forward;
	guint32 ssrc_reversed;
	guint32 *ssrc_tmp;
	gboolean search_ssrc;
	guint reversed_ip;
	guint reversed_ip_and_port;
	gboolean f_first_packet;
	gboolean r_first_packet;
	guint16 f_seq_num;
	guint16 r_seq_num;
	guint32 f_timestamp;
	guint32 r_timestamp;
	guint32 f_delta_timestamp;
	guint32 r_delta_timestamp;
	double f_delay;
	double r_delay;
	double f_jitter;
	double r_jitter;
	double f_time;
	double r_time;
	double f_start_time;
	double r_start_time;
	double f_max_delay;
	double r_max_delay;
	guint32 f_max_nr;
	guint32 r_max_nr;
	guint16 f_start_seq_nr;
	guint16 r_start_seq_nr;
	guint16 f_stop_seq_nr;
	guint16 r_stop_seq_nr;
	guint32 f_total_nr;
	guint32 r_total_nr;
	guint32 f_sequence;
	guint32 r_sequence;
	gint f_cycles;
	gint r_cycles;
	gboolean f_under;
	gboolean r_under;
	FILE *f_fp;
	FILE *r_fp;
	gboolean f_saved;
	gboolean r_saved;
	error_type_t f_error_type;
	error_type_t r_error_type;
	guint32 f_count;
	guint32 r_count;
} info_stat;


/* when there is a [re]reading of packet's */
static void
rtp_reset(void *prs)
{
  info_stat *rs=prs;

  rs->f_first_packet = TRUE;
  rs->r_first_packet = TRUE;
  rs->f_max_delay = 0;
  rs->r_max_delay = 0;
  rs->f_max_nr = 0;
  rs->r_max_nr = 0;
  rs->f_total_nr = 0;
  rs->r_total_nr = 0;
  rs->f_sequence = 0;
  rs->r_sequence = 0;
  rs->f_start_seq_nr = 0;
  rs->r_start_seq_nr = 1; /* 1 is ok (for statistics in reversed direction) */
  rs->f_stop_seq_nr = 0;
  rs->r_stop_seq_nr = 0;
  rs->f_cycles = 0;
  rs->r_cycles = 0;
  rs->f_under = FALSE;
  rs->r_under = FALSE;
  rs->f_saved = FALSE;
  rs->r_saved = FALSE;
  rs->f_start_time = 0;
  rs->r_start_time = 0;
  rs->f_count = 0;
  rs->r_count = 0;
  /* XXX check for error at fclose? */
  if (rs->f_fp != NULL)
	fclose(rs->f_fp); 
  if (rs->r_fp != NULL)
	fclose(rs->r_fp); 
  rs->f_fp = fopen(f_tempname, "wb"); 
  if (rs->f_fp == NULL)
	rs->f_error_type = TAP_RTP_FILE_OPEN_ERROR;
  rs->r_fp = fopen(r_tempname, "wb");
  if (rs->r_fp == NULL)
	rs->r_error_type = TAP_RTP_FILE_OPEN_ERROR;
  return;
}

/* here we can redraw the output */
/* not used yet */
static void rtp_draw(void *prs _U_)
{
	return;
}

/* when we are finished with redisection, we add the label for the statistic */
static void draw_stat(void *prs)
{
	info_stat *rs=prs;
	gchar label_max[200];
	guint32 f_expected = (rs->f_stop_seq_nr + rs->f_cycles*65536) - rs->f_start_seq_nr + 1;
	guint32 r_expected = (rs->r_stop_seq_nr + rs->r_cycles*65536) - rs->r_start_seq_nr + 1;
	gint32 f_lost = f_expected - rs->f_total_nr;
	gint32 r_lost = r_expected - rs->r_total_nr;

	g_snprintf(label_max, 199, "Max delay = %f sec at packet nr. %u \n\n"
		"Total RTP packets = %u   (expected %u)   Lost RTP packets = %d"  
		"   Sequence error = %u",
			rs->f_max_delay, rs->f_max_nr, rs->f_total_nr, f_expected, 
							f_lost, rs->f_sequence);

	gtk_label_set_text(GTK_LABEL(max), label_max);

	g_snprintf(label_max, 199, "Max delay = %f sec at packet nr. %u \n\n"
		"Total RTP packets = %u   (expected %u)   Lost RTP packets = %d"
		"   Sequence error = %u",
			 rs->r_max_delay, rs->r_max_nr, rs->r_total_nr, r_expected,
							r_lost, rs->r_sequence);

	gtk_label_set_text(GTK_LABEL(max_r), label_max);

	/* could be done somewhere else, but can be here as well */
	/* if this is true, then we don't have any reversed connection, so the error type
	 * will be no data. This applies only the reversed connection */
	if (rs->reversed_ip_and_port == 0)
		rs->r_error_type = TAP_RTP_NO_DATA;

	return ;
}

/* append a line to clist */
/* XXX is there a nicer way to make these assignements? */
static void add_to_clist(gboolean forward, guint32 number, guint16 seq_num, 
				double delay, double jitter, gboolean status, gboolean marker)
{
	gchar *data[6];
	gchar field[6][30];

	data[0]=&field[0][0];
	data[1]=&field[1][0];
	data[2]=&field[2][0];
	data[3]=&field[3][0];
	data[4]=&field[4][0];
	data[5]=&field[5][0];

	g_snprintf(field[0], 20, "%u", number);
	g_snprintf(field[1], 20, "%u", seq_num);
	g_snprintf(field[2], 20, "%f", delay);
	g_snprintf(field[3], 20, "%f", jitter);
	g_snprintf(field[4], 20, "%s", marker? "SET" : "");
	g_snprintf(field[5], 29, "%s", status? "OK" : "NOK - Wrong sequence nr.");

	gtk_clist_append(GTK_CLIST(forward? clist : clist_r), data);

}

/* whenever a RTP packet is seen by the tap listener */
/* this function works as follows:
 * 1) packets that are not displayed are ignored
 *	return
 * 2) are we searching what could be the reversed connection (looking for reversed SSRC)
 *	if yes, do the parameters match (inversed IP and port combination from the forward one)?
 *		if yes, do we already have this SSRC stored
 *			if not store it
 * 3) if not, is current packet matching the forward direction
 *	is it the first time we see a packet in this direction
 *		if yes, store some values, add a line to list and save the voice info
 *		in a temporary file if the codec is supported and the RTP data is ok
 *	if not, is it a packet with mark bit set (there was silence surpression)
 *		same as above, only we have to add some silence in front of the voice data
 *	if not, then this must be a normal packet
 *		store the values and voice data
 * 4) if not, is current packet matching the reversed connection
 *	(same as for number 3)
 */
static int rtp_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, void *vpri)
{
	info_stat *rs=prs;
	struct _rtp_info *pri=vpri;
	guint i;
	double n_time;
	double n_jitter;
	guint8 *data;
	gint16 tmp;

	/* we ignore packets that are not displayed */
	if (pinfo->fd->flags.passed_dfilter == 0)
		return 0;

	/* are we looking for the SSRC of the reversed connection? */
	if (rs->search_ssrc != FALSE) {
		/* XXX what should be the rules for reversed connection? 
		 * 1. It should should have same inversed IP and port numbers
		 * 2. If none are found, only inversed IP's - is this possible?
		 * 3. If none are found, there isn't any reversed connection 
		 * XXX is it possible that the conversation is not P2P? 
		 * Curretly it works only if it matches the number 1. */

		/* have we found inverse parameters? */
		if ( strcmp(ip_to_str(pinfo->src.data), rs->destination) == 0  && 
				strcmp( ip_to_str(pinfo->dst.data), rs->source) == 0 ) {

			/* do the ports also match? */
			if ((rs->srcport == pinfo->destport) && (rs->dstport == pinfo->srcport)) {
				/* ok, the ip and port combination does match 
				 * do we already have this ssrc stored */
				for(i=0; i< rs->reversed_ip_and_port; i++) {
					if (pri->info_sync_src == *(rs->ssrc_tmp+i) ) 
						return 0;
				}
				
				/* no, we found new ssrc, let's store it */
				rs->ssrc_tmp = (guint32*)g_realloc(rs->ssrc_tmp, 
								(i+1)*sizeof(guint32));
				*(rs->ssrc_tmp+i) = pri->info_sync_src;
				rs->reversed_ip_and_port++;
				return 0;
			}
			/* no, only ip addresses match */
			/* XXX not implemented yet */
			else {
				rs->reversed_ip++;
				return 0;
			}

		}
	}
	
	/* ok, we are not looking for SSRC of the reversed connection */
	/* is it the forward direction? 
	 * if yes, there 3 possibilities:
	 * a) is this the first packet we got in this direction?
	 * b) or is it a packet with the mark bit set?
	 * c) if neither then it is a "normal" packet */
	else if (rs->ssrc_forward == pri->info_sync_src) {
		/* first packet? */
		if (rs->f_first_packet != FALSE) {
			/* we store all the values */
			rs->f_seq_num = pri->info_seq_num;
			rs->f_delay = 0;
			rs->f_jitter = 0;
			rs->f_first_packet = FALSE;
			rs->f_timestamp = pri->info_timestamp;
			rs->f_start_seq_nr = pri->info_seq_num;
			rs->f_stop_seq_nr = pri->info_seq_num;
			rs->f_total_nr++;
			rs->f_time = (double)pinfo->fd->rel_secs + 
						(double) pinfo->fd->rel_usecs/1000000;
			rs->f_start_time = rs->f_time;
			/* and add a row to clist; delay and jitter are 0 for the first packet */
			add_to_clist(TRUE, pinfo->fd->num, pri->info_seq_num, 0, 0, TRUE, FALSE);

			/* and now save the voice info */

			/* if we couldn't open the tmp file for writing, then we set the flag */
			if (rs->f_fp == NULL) {
				rs->f_saved = FALSE;
				rs->f_error_type = TAP_RTP_FILE_OPEN_ERROR;
				return 0;
			}
			/* if the captured length and packet length aren't equal, we quit 
			 * because there is some information missing */
			if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
				rs->f_saved = FALSE;
				rs->f_error_type = TAP_RTP_WRONG_LENGTH;
				return 0;
			}
			/* if padding bit is set, we don't do it yet */
			if (pri->info_padding_set != FALSE) {
				rs->f_saved = FALSE;
				rs->f_error_type = TAP_RTP_PADDING_SET;
				return 0;
			}
			/* is it the ulaw? */
			if (pri->info_payload_type == 0) {
				/* we put the pointer at the beggining of the RTP data, that is
				 * at the end of the current frame minus the length of the 
				 * RTP field plus 12 for the RTP header */
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len-12 ); i++, data++) {
					tmp = (gint16 )ulaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->f_fp);
					rs->f_count++;
				}
				rs->f_saved = TRUE;
				return 0;
			}
			/* alaw? */
			else if (pri->info_payload_type == 8) {
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len -12 ); i++, data++) {
					tmp = (gint16 )alaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->f_fp);
					rs->f_count++;
				}
				rs->f_saved = TRUE;
				return 0;
			}
			/* unsupported codec or other error */
			else {
				rs->f_saved = FALSE;
				rs->f_error_type = TAP_RTP_WRONG_CODEC;
				return 0;
			}
		}
		
		/* packet with mark bit set? */
		if (pri->info_marker_set != FALSE) {
			n_time = (double)pinfo->fd->rel_secs +
					(double) pinfo->fd->rel_usecs/1000000;
			/* jitter is calculated as for RCTP - RFC 1889 
			 * J = J + ( | D(i-1, i) | - J) / 16
			 * XXX the output there should be in timestamp (probably miliseconds)
			 * units expressed as an unsigned integer, so should we do it the same? 
			 * (currently we use seconds) 
			 *
			 * XXX Packet loss in RTCP is calculated as the difference between the
			 * number of packets expected and actually received, where for actually 
			 * received the number is simply the count of packets as they arrive, 
			 * including any late or duplicate packets (this means that the number
			 * can be negative). For example, if the seq numbers of the arrived
			 * packets are: 1,2,3,4,5,5,7,7,9,10 the expected number is 10 and the
			 * the number of actually captured frames is also 10. So in upper 
			 * calculation there would be no losses. But there are 2 losses and 
			 * 2 duplicate packets. Because this kind of statistic is rather 
			 * useless (or confusing) we add the information, that there was 
			 * an error with sequence number each time the sequence number was 
			 * not one bigger than the previous one
			*/
                       
			/* jitter calculation */
			n_jitter = rs->f_jitter + ( fabs(n_time-(rs->f_time) - 
					((double)(pri->info_timestamp)-
					(double)(rs->f_timestamp))/8000) - rs->f_jitter)/16;

			/* we add the information into the clist */
			add_to_clist(TRUE, pinfo->fd->num, pri->info_seq_num, n_time-(rs->f_time),
				 n_jitter, rs->f_seq_num+1 == pri->info_seq_num?TRUE:FALSE, TRUE);

			/* when calculating expected rtp packets the seq number can wrap around
			 * so we have to count the number of cycles 
			 * f_cycles counts the wraps around in forwarding connection and
			 * f_under is flag that indicates where we are 
			 *
			 * XXX how to determine number of cycles with all possible lost, late
			 * and duplicated packets without any doubt? It seems to me, that 
			 * because of all possible combination of late, duplicated or lost
			 * packets, this can only be more or less good approximation
			 *
			 * There are some combinations (rare but theoretically possible), 
			 * where below code won't work correctly - statistic may be wrong then.
			 */

			/* so if the current sequence number is less than the start one
			 * we assume, that there is another cycle running */
			if ((pri->info_seq_num < rs->f_start_seq_nr) && (rs->f_under == FALSE)){
				rs->f_cycles++;
				rs->f_under = TRUE;
			}
			/* what if the start seq nr was 0. Then the above condition will never 
			 * be true, so we add another condition. XXX The problem would arise if
			 * if one of the packets with seq nr 0 or 65535 would be lost or late */
			else if ((pri->info_seq_num == 0) && (rs->f_stop_seq_nr == 65535) && 
									(rs->f_under == FALSE)){
				rs->f_cycles++;
				rs->f_under = TRUE;
			}
			/* the whole round is over, so reset the flag */
			else if ((pri->info_seq_num>rs->f_start_seq_nr)&&(rs->f_under!=FALSE)){
				rs->f_under = FALSE;
			}

			/* number of times where sequence number was not ok */
			if ( rs->f_seq_num+1 == pri->info_seq_num)
				rs->f_seq_num = pri->info_seq_num;
			/* XXX same problem as above */
			else if ( (rs->f_seq_num == 65535) && (pri->info_seq_num == 0) )
				rs->f_seq_num = pri->info_seq_num;
			/* lost packets */
			else if (rs->f_seq_num+1 < pri->info_seq_num) {
				rs->f_seq_num = pri->info_seq_num;
				rs->f_sequence++;
			}
			/* late or duplicated */
			else if (rs->f_seq_num+1 > pri->info_seq_num)
				rs->f_sequence++;

			rs->f_stop_seq_nr = pri->info_seq_num;
			rs->f_time = n_time;
			rs->f_jitter = n_jitter;
			rs->f_delta_timestamp = pri->info_timestamp - rs->f_timestamp;
			rs->f_timestamp = pri->info_timestamp;
			rs->f_total_nr++;

			/* save the voice information */
			/* if there was already an error, we quit */
			if (rs->f_saved == FALSE)
				return 0;
			/* if the captured length and packet length aren't equal, we quit */
			if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
				rs->f_saved = FALSE;
				rs->f_error_type = TAP_RTP_WRONG_LENGTH;
				return 0;
			}
			/* if padding bit is set, we don't do it yet */
			if (pri->info_padding_set != FALSE) {
				rs->f_saved = FALSE;
				rs->f_error_type = TAP_RTP_PADDING_SET;
				return 0;
			}
			/* because the mark bit is set, we have to add some silence in front */
			/* is it the ulaw? */
			if (pri->info_payload_type == 0) {
				/* we insert some silence */
				/* XXX the amount of silence should be the difference between
				 * the last timestamp and the current one minus x in the
				 * I am not sure if x is equal the amount of information 
				 * current packet? */
				for(i=0; i<(rs->f_delta_timestamp-pri->info_data_len+12); i++) {
					tmp = (gint16 )ulaw2linear((unsigned char)(0x55));
					fwrite(&tmp, 2, 1, rs->f_fp);
					rs->f_count++;
				}
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len-12 ); i++, data++) {
					tmp = (gint16 )ulaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->f_fp);
					rs->f_count++;
				}
				return 0;
			}
			/* alaw? */
			else if (pri->info_payload_type == 8) {
				for(i=0; i < (rs->f_delta_timestamp-pri->info_data_len+12); i++) {
					tmp = (gint16 )ulaw2linear((unsigned char)(0x55));
					fwrite(&tmp, 2, 1, rs->f_fp);
					rs->f_count++;
				}
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len -12 ); i++, data++) {
					tmp = (gint16 )alaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->f_fp);
					rs->f_count++;
				}
				return 0;
			}
			/* unsupported codec or other error */
			else {
				rs->f_saved = FALSE;
				rs->f_error_type = TAP_RTP_WRONG_CODEC;
				return 0;
			}
			return 0;
		}
		
		/* normal packet in forward connection */
		n_time = (double)pinfo->fd->rel_secs +
					(double) pinfo->fd->rel_usecs/1000000;
		n_jitter = rs->f_jitter + ( fabs (n_time-(rs->f_time) - 
				((double)(pri->info_timestamp)-
				(double)(rs->f_timestamp))/8000) - rs->f_jitter)/16;
		rs->f_delay =  n_time-(rs->f_time);
		/* the delay is bigger than previous max delay, so store the delay and nr */
		if (rs->f_delay > rs->f_max_delay) {
			rs->f_max_delay = rs->f_delay;
			rs->f_max_nr = pinfo->fd->num;
		}
		add_to_clist(TRUE, pinfo->fd->num, pri->info_seq_num, n_time-(rs->f_time),
				 n_jitter, rs->f_seq_num+1 == pri->info_seq_num?TRUE:FALSE, FALSE);

		/* count the cycles */
		if ((pri->info_seq_num < rs->f_start_seq_nr) && (rs->f_under == FALSE)){
			rs->f_cycles++;
			rs->f_under = TRUE;
		}
		else if ((pri->info_seq_num == 0) && (rs->f_stop_seq_nr == 65535) && 
								(rs->f_under == FALSE)){
			rs->f_cycles++;
			rs->f_under = TRUE;
		}
		/* the whole round is over, so reset the flag */
		else if ((pri->info_seq_num>rs->f_start_seq_nr+1)&&(rs->f_under!=FALSE)){
			rs->f_under = FALSE;
		}

		/* number of times where sequence number was not ok */
		if ( rs->f_seq_num+1 == pri->info_seq_num)
			rs->f_seq_num = pri->info_seq_num;
		else if ( (rs->f_seq_num == 65535) && (pri->info_seq_num == 0) )
			rs->f_seq_num = pri->info_seq_num;
		/* lost packets */
		else if (rs->f_seq_num+1 < pri->info_seq_num) {
			rs->f_seq_num = pri->info_seq_num;
			rs->f_sequence++;
		}
		/* late or duplicated */
		else if (rs->f_seq_num+1 > pri->info_seq_num)
			rs->f_sequence++;

		rs->f_stop_seq_nr = pri->info_seq_num;
		rs->f_time = n_time;
		rs->f_jitter = n_jitter;
		rs->f_timestamp = pri->info_timestamp;
		rs->f_total_nr++;

		/* save the voice information */
		/* we do it only in following cases:
		 * - the codecs we support are g.711 alaw in ulaw
		 * - the captured length must equal the packet length
		 * - XXX we don't support it if there are padding bits 
		 */
		/* if there was already an error, we quit */
		if (rs->f_saved == FALSE)
			return 0;
		/* if the captured length and packet length aren't equal, we quit */
		if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
			rs->f_saved = FALSE;
			rs->f_error_type = TAP_RTP_WRONG_LENGTH;
			return 0;
		}
		/* if padding bit is set, we don't do it yet */
		if (pri->info_padding_set != FALSE) {
			rs->f_saved = FALSE;
			rs->f_error_type = TAP_RTP_PADDING_SET;
			return 0;
		}
		/* is it the ulaw? */
		if (pri->info_payload_type == 0) {
			/* cfile.pd points at the beggining of the actual packet. We have
			 * to move this pointer at the RTP data. This is the packet length,
			 * minus whole RTP data length (including the RTP header, that is
			 * why we add 12) */
			data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
			for(i=0; i < (pri->info_data_len - 12); i++, data++) {
				tmp = (gint16 )ulaw2linear((unsigned char)*data);
				fwrite(&tmp, 2, 1, rs->f_fp);
				rs->f_count++;
			}
			return 0;				
		}
		/* alaw? */
		else if (pri->info_payload_type == 8) {
			data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
			for(i=0; i < (pri->info_data_len-12 ); i++, data++) {
				tmp = (gint16 )alaw2linear((unsigned char)*data);
				fwrite(&tmp, 2, 1, rs->f_fp);
				rs->f_count++;
			}
			return 0;
		}
		/* unsupported codec or other error */
		else {
			rs->f_saved = FALSE;
			rs->f_error_type = TAP_RTP_WRONG_CODEC;
			return 0;
		}
	}				

	/* is it the reversed direction? */
	else if (rs->ssrc_reversed == pri->info_sync_src) {
		/* first packet? */
		if (rs->r_first_packet !=FALSE) {
			rs->r_seq_num = pri->info_seq_num;
			rs->r_delay = 0;
			rs->r_jitter = 0;
			rs->r_first_packet = FALSE;
			rs->r_timestamp = pri->info_timestamp;
			rs->r_start_seq_nr = pri->info_seq_num;
			rs->r_stop_seq_nr = pri->info_seq_num;
			rs->r_total_nr++;
			rs->r_time = (double)pinfo->fd->rel_secs + 
						(double) pinfo->fd->rel_usecs/1000000;
			rs->r_start_time = rs->r_time;
			add_to_clist(FALSE, pinfo->fd->num, pri->info_seq_num, 0, 0, TRUE, FALSE);

			/* save it */
			/* if we couldn't open the tmp file for writing, then we set the flag */
			if (rs->r_fp == NULL) {
				rs->r_saved = FALSE;
				return 0;
			}
			/* if the captured length and packet length aren't equal, we quit */
			if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
				rs->r_saved = FALSE;
				rs->r_error_type = TAP_RTP_WRONG_LENGTH;
				return 0;
			}
			/* if padding bit is set, we don't do it yet */
			if (pri->info_padding_set != FALSE) {
				rs->r_saved = FALSE;
				rs->r_error_type = TAP_RTP_PADDING_SET;
				return 0;
			}
			/* is it the ulaw? */
			if (pri->info_payload_type == 0) {
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len-12 ); i++, data++) {
					tmp = (gint16 )ulaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->r_fp);
					rs->r_count++;
				}
				rs->r_saved = TRUE;
				return 0;
			}
			/* alaw? */
			else if (pri->info_payload_type == 8) {
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len -12 ); i++, data++) {
					tmp = (gint16 )alaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->r_fp);
					rs->r_count++;
				}
				rs->r_saved = TRUE;
				return 0;
			}
			/* unsupported codec or other error */
			else {
				rs->r_saved = FALSE;
				rs->r_error_type = TAP_RTP_WRONG_CODEC;
				return 0;
			}
		}
		
		/* packet with mark bit set? */
		if (pri->info_marker_set != FALSE) {
			n_time = (double)pinfo->fd->rel_secs +
					(double) pinfo->fd->rel_usecs/1000000;
			n_jitter = rs->r_jitter + ( fabs (n_time-(rs->r_time) - 
					((double)(pri->info_timestamp)-
					(double)(rs->r_timestamp))/8000) - rs->r_jitter)/16;
			add_to_clist(FALSE, pinfo->fd->num, pri->info_seq_num, n_time-(rs->r_time),
				 n_jitter, rs->r_seq_num+1 == pri->info_seq_num?TRUE:FALSE, TRUE);

			/* count the cycles */
			if ((pri->info_seq_num < rs->r_start_seq_nr) && (rs->r_under == FALSE)){
				rs->r_cycles++;
				rs->r_under = TRUE;
			}
			else if ((pri->info_seq_num == 0) && (rs->r_stop_seq_nr == 65535) && 
									(rs->r_under == FALSE)){
				rs->r_cycles++;
				rs->r_under = TRUE;
			}
			/* the whole round is over, so reset the flag */
			else if ((pri->info_seq_num>rs->r_start_seq_nr+1)&&(rs->r_under!=FALSE)){
				rs->r_under = FALSE;
			}

			/* number of times where sequence number was not ok */
			if ( rs->r_seq_num+1 == pri->info_seq_num)
				rs->r_seq_num = pri->info_seq_num;
			else if ( (rs->r_seq_num == 65535) && (pri->info_seq_num == 0) )
				rs->r_seq_num = pri->info_seq_num;
			/* lost packets */
			else if (rs->r_seq_num+1 < pri->info_seq_num) {
				rs->r_seq_num = pri->info_seq_num;
				rs->r_sequence++;
			}
			/* late or duplicated */
			else if (rs->r_seq_num+1 > pri->info_seq_num)
				rs->r_sequence++;

			rs->r_stop_seq_nr = pri->info_seq_num;
			rs->r_time = n_time;
			rs->r_jitter = n_jitter;
			rs->r_delta_timestamp = pri->info_timestamp - rs->r_timestamp;
			rs->r_timestamp = pri->info_timestamp;
			rs->r_total_nr++;

			/* save the voice information */
			/* if there was already an error, we quit */
			if (rs->r_saved == FALSE)
				return 0;
			/* if the captured length and packet length aren't equal, we quit */
			if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
				rs->r_saved = FALSE;
				rs->r_error_type = TAP_RTP_WRONG_LENGTH;
				return 0;
			}
			/* if padding bit is set, we don't do it yet */
			if (pri->info_padding_set != FALSE) {
				rs->r_saved = FALSE;
				rs->r_error_type = TAP_RTP_PADDING_SET;
				return 0;
			}
			/* because the mark bit is set, we have to add some silence in front */
			/* is it the ulaw? */
			if (pri->info_payload_type == 0) {
				/* we insert some silence */
				for(i=0; i<(rs->r_delta_timestamp-pri->info_data_len+12); i++) {
					tmp = (gint16 )ulaw2linear((unsigned char)(0x55));
					fwrite(&tmp, 2, 1, rs->r_fp);
					rs->r_count++;
				}
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len-12 ); i++, data++) {
					tmp = (gint16 )ulaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->r_fp);
					rs->r_count++;
				}
				return 0;
			}
			/* alaw? */
			else if (pri->info_payload_type == 8) {
				for(i=0; i < (rs->r_delta_timestamp-pri->info_data_len+12); i++) {
					tmp = (gint16 )ulaw2linear((unsigned char)(0x55));
					fwrite(&tmp, 2, 1, rs->r_fp);
					rs->r_count++;
				}
				data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
				for(i=0; i < (pri->info_data_len -12 ); i++, data++) {
					tmp = (gint16 )alaw2linear((unsigned char)*data);
					fwrite(&tmp, 2, 1, rs->r_fp);
					rs->r_count++;
				}
				return 0;
			}
			/* unsupported codec or other error */
			else {
				rs->r_saved = FALSE;
				rs->r_error_type = TAP_RTP_WRONG_CODEC;
				return 0;
			}
			return 0;
		}
		
		/* normal packet in reversed connection */
		n_time = (double)pinfo->fd->rel_secs +
				(double) pinfo->fd->rel_usecs/1000000;
		n_jitter = rs->r_jitter + ( fabs (n_time-(rs->r_time) - 
				((double)(pri->info_timestamp)-
				(double)(rs->r_timestamp))/8000) - rs->r_jitter)/16;
		rs->r_delay =  n_time-(rs->r_time);
		if (rs->r_delay > rs->r_max_delay) {
			rs->r_max_delay = rs->r_delay;
			rs->r_max_nr = pinfo->fd->num;
		}
		add_to_clist(FALSE, pinfo->fd->num, pri->info_seq_num, n_time-(rs->r_time),
				 n_jitter, rs->r_seq_num+1 == pri->info_seq_num?TRUE:FALSE, FALSE);
		/* count the cycles */
		if ((pri->info_seq_num < rs->r_start_seq_nr) && (rs->r_under == FALSE)){
			rs->r_cycles++;
			rs->r_under = TRUE;
		}
		else if ((pri->info_seq_num == 0) && (rs->r_stop_seq_nr == 65535) && 
								(rs->r_under == FALSE)){
			rs->r_cycles++;
			rs->r_under = TRUE;
		}
		/* the whole round is over, so reset the flag */
		else if ((pri->info_seq_num>rs->r_start_seq_nr+1)&&(rs->r_under!=FALSE)){
			rs->r_under = FALSE;
		}

		/* number of times where sequence number was not ok */
		if ( rs->r_seq_num+1 == pri->info_seq_num)
			rs->r_seq_num = pri->info_seq_num;
		else if ( (rs->r_seq_num == 65535) && (pri->info_seq_num == 0) )
			rs->r_seq_num = pri->info_seq_num;
		/* lost packets */
		else if (rs->r_seq_num+1 < pri->info_seq_num) {
			rs->r_seq_num = pri->info_seq_num;
			rs->r_sequence++;
		}
		/* late or duplicated */
		else if (rs->r_seq_num+1 > pri->info_seq_num)
			rs->r_sequence++;

		rs->r_stop_seq_nr = pri->info_seq_num;
		rs->r_time = n_time;
		rs->r_jitter = n_jitter;
		rs->r_timestamp = pri->info_timestamp;
		rs->r_total_nr++;

		/* save the voice information */
		/* if there was already an error, we quit */
		if (rs->r_saved == FALSE)
			return 0;
		/* if the captured length and packet length aren't equal, we quit */
		if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
			rs->r_saved = FALSE;
			rs->r_error_type = TAP_RTP_WRONG_LENGTH;
			return 0;
		}
		/* if padding bit is set, we don't do it yet */
		if (pri->info_padding_set != FALSE) {
			rs->r_saved = FALSE;
			rs->r_error_type = TAP_RTP_PADDING_SET;
			return 0;
		}
		/* is it the ulaw? */
		if (pri->info_payload_type == 0) {
			data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
			for(i=0; i < (pri->info_data_len-12 ); i++, data++) {
				tmp = (gint16 )ulaw2linear((unsigned char)*data);
				fwrite(&tmp, 2, 1, rs->r_fp);
				rs->r_count++;
			}
			return 0;
		}
		/* alaw? */
		else if (pri->info_payload_type == 8) {
			data = cfile.pd + (pinfo->fd->pkt_len - pri->info_data_len + 12);
			for(i=0; i < (pri->info_data_len -12 ); i++, data++) {
				tmp = (gint16 )alaw2linear((unsigned char)*data);
				fwrite(&tmp, 2, 1, rs->r_fp);
				rs->r_count++;
			}
			return 0;
		}
		/* unsupported codec or other error */
		else {
			rs->r_saved = FALSE;
			rs->r_error_type = TAP_RTP_WRONG_CODEC;
			return 0;
		}
	}				

	return 0;
}

/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);


/* here we close the rtp analysis dialog window and remove the tap listener */
static void rtp_destroy_cb(GtkWidget *win _U_, gpointer data _U_)
{
  info_stat *rs=(info_stat *)data;

  protect_thread_critical_region();
  remove_tap_listener(rs);
  unprotect_thread_critical_region();

  /* xxx is this enough? */
  g_free(rs->ssrc_tmp);
  g_free(rs);
 
  if (rs->f_fp != NULL)
	fclose(rs->f_fp);
  if (rs->r_fp != NULL)
	fclose(rs->r_fp);
  remove(f_tempname);
  remove(r_tempname);

  /* Is there a save voice window open? */
  if (save_voice_as_w != NULL)
	gtk_widget_destroy(save_voice_as_w);

  /* Note that we no longer have a "RTP Analyse" dialog box. */
  rtp_w = NULL;
}

/* when the close button in rtp window was clicked */
/* it seems to me that rtp_destroy_cb is automatically called, so we don't
 * need to do the g_free... and rtp_w = NULL ... */
static void rtp_destroy (GtkWidget *close_bt _U_, gpointer parent_w)
{
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}

/* we search the rtp.ssrc node here (thanks to Guy Harris - code here is magic for me */
static guint32 process_node(proto_item *ptree_node, header_field_info *hfinformation) 
{
  field_info            *finfo;
  proto_item            *proto_sibling_node;
  header_field_info     *hfssrc;
  guint32 ssrc;

  finfo = PITEM_FINFO(ptree_node);

  if (hfinformation==(finfo->hfinfo)) {
	hfssrc = proto_registrar_get_byname("rtp.ssrc");
	if (hfssrc == NULL)
		return 0;
	for(ptree_node=g_node_first_child(ptree_node); ptree_node!=NULL; 
				ptree_node=g_node_next_sibling(ptree_node)) {
		finfo=PITEM_FINFO(ptree_node);
		if (hfssrc==finfo->hfinfo) {
			ssrc = fvalue_get_integer(finfo->value);
			return ssrc;
		}
		}
  }

  proto_sibling_node = g_node_next_sibling(ptree_node);

  if (proto_sibling_node) {
	ssrc = process_node(proto_sibling_node, hfinformation);
	return ssrc;
  }
  else
	return 0;
}

/* here we search the rtp protocol */
static guint32 process_tree(proto_tree *protocol_tree)
{
  proto_item      *ptree_node;
  header_field_info     *hfinformation;

  hfinformation = proto_registrar_get_byname("rtp");
  if (hfinformation == NULL)
	return 0;

  ptree_node = g_node_first_child(protocol_tree);
  if (!ptree_node)
	return 0;

  return process_node(ptree_node, hfinformation);
}

/* when we want to update the information */
static void refresh_cb(GtkWidget *w _U_, void *pri)
{
  info_stat *rs=pri;

  gtk_clist_clear(GTK_CLIST(clist));
  gtk_clist_clear(GTK_CLIST(clist_r));
  redissect_packets(&cfile);
  draw_stat(rs);
}

static void save_voice_as_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a Save voice info dialog box. */
  save_voice_as_w = NULL;
}

/* the user wants to save in a file */
/* XXX support for different formats is currently commented out */
static void save_voice_as_ok_cb(GtkWidget *ok_bt, gpointer fs)
{
  gchar *g_dest;
  /*GtkWidget *wav, *au, *sw;*/
  GtkWidget *rev, *forw, *both;
  info_stat *rs;
  gint channels /*, format*/;

  g_dest = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(g_dest) == EISDIR) {
	/* It's a directory - set the file selection box to display it. */
	set_last_open_dir(g_dest);
	g_free(g_dest);
	gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);
	return;
  }

  /*wav = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "wav_rb");
  au = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "au_rb");
  sw = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "sw_rb");*/
  rev = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "reversed_rb");
  forw = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "forward_rb");
  both = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "both_rb");
  rs = (info_stat *)OBJECT_GET_DATA(ok_bt, "info_stat");

  /* XXX user clicks the ok button, but we know we can't save the voice info because f.e.
   * we don't support that codec. So we pop up a warning. Maybe it would be better to
   * disable the ok button or disable the buttons for direction if only one is not ok. The
   * problem is if we open the save voice dialog and then click the refresh button and maybe 
   * the state changes, so we can't save anymore. In this case we should be able to update
   * the buttons. For now it is easier if we put the warning when the ok button is pressed.
   */

  /* we can not save in both dirctions */
  if ((rs->f_saved == FALSE) && (rs->r_saved == FALSE) && (GTK_TOGGLE_BUTTON (both)->active)) {
	/* there are many combinations here, we just exit when first matches */
	if ((rs->f_error_type == TAP_RTP_WRONG_CODEC) || (rs->r_error_type == TAP_RTP_WRONG_CODEC))
		simple_dialog(ESD_TYPE_CRIT, NULL, 
		"Can't save in a file: Unsupported codec!");
	else if ((rs->f_error_type == TAP_RTP_WRONG_LENGTH) || (rs->r_error_type == TAP_RTP_WRONG_LENGTH))
		simple_dialog(ESD_TYPE_CRIT, NULL, 
		"Can't save in a file: Wrong length of captured packets!");
	else if ((rs->f_error_type == TAP_RTP_PADDING_SET) || (rs->r_error_type == TAP_RTP_PADDING_SET))
		simple_dialog(ESD_TYPE_CRIT, NULL, 
		"Can't save in a file: RTP data with padding!");
	else  
		simple_dialog(ESD_TYPE_CRIT, NULL, 
		"Can't save in a file: File I/O problem!");
	return;
  }
  /* we can not save forward direction */
  else if ((rs->f_saved == FALSE) && ((GTK_TOGGLE_BUTTON (forw)->active) ||
						(GTK_TOGGLE_BUTTON (both)->active))) {  
	if (rs->f_error_type == TAP_RTP_WRONG_CODEC)
                simple_dialog(ESD_TYPE_CRIT, NULL, 
		"Can't save forward direction in a file: Unsupported codec!");
        else if (rs->f_error_type == TAP_RTP_WRONG_LENGTH)
                simple_dialog(ESD_TYPE_CRIT, NULL,
                "Can't save forward direction in a file: Wrong length of captured packets!");
        else if (rs->f_error_type == TAP_RTP_PADDING_SET)
                simple_dialog(ESD_TYPE_CRIT, NULL, 
		"Can't save forward direction in a file: RTP data with padding!");
        else
                simple_dialog(ESD_TYPE_CRIT, NULL, 
		"Can't save forward direction in a file: File I/O problem!");
	return;
  }
  /* we can not save reversed direction */
  else if ((rs->r_saved == FALSE) && ((GTK_TOGGLE_BUTTON (rev)->active) ||
						(GTK_TOGGLE_BUTTON (both)->active))) {  
	if (rs->r_error_type == TAP_RTP_WRONG_CODEC)
                simple_dialog(ESD_TYPE_CRIT, NULL,
                "Can't save reversed direction in a file: Unsupported codec!");
        else if (rs->r_error_type == TAP_RTP_WRONG_LENGTH)
                simple_dialog(ESD_TYPE_CRIT, NULL,
                "Can't save reversed direction in a file: Wrong length of captured packets!");
        else if (rs->r_error_type == TAP_RTP_PADDING_SET)
                simple_dialog(ESD_TYPE_CRIT, NULL,
                "Can't save reversed direction in a file: RTP data with padding!");
        else if (rs->r_error_type == TAP_RTP_NO_DATA)
                simple_dialog(ESD_TYPE_CRIT, NULL,
                "Can't save reversed direction in a file: No RTP data!");
	else
                simple_dialog(ESD_TYPE_CRIT, NULL,
                "Can't save reversed direction in a file: File I/O problem!");
        return;
  }

  /*if (GTK_TOGGLE_BUTTON (wav)->active)
	format = 1;
  else if (GTK_TOGGLE_BUTTON (au)->active)
	format = 2;
  else if (GTK_TOGGLE_BUTTON (sw)->active)
	format = 3;*/

  if (GTK_TOGGLE_BUTTON (rev)->active)
	channels = 2;
  else if (GTK_TOGGLE_BUTTON (both)->active)
	channels = 3;
  else 
	channels = 1;

  if(!copy_file(g_dest, channels/*, format*/, rs)) {
	simple_dialog(ESD_TYPE_CRIT, NULL, "An error occured while saving voice in a file!");
	return;
  }

  /* XXX I get GTK warning (sometimes?)!!! */
  gtk_widget_destroy(GTK_WIDGET(save_voice_as_w));
}

/* when the user wants to save the voice information in a file */
/* XXX support for different formats is currently commented out */
static void save_voice_as_cb(GtkWidget *w _U_, gpointer data)
{
  info_stat *rs=(info_stat *)data;

  GtkWidget *vertb;
  GtkWidget *table1;
  GtkWidget *label_format;
  GtkWidget *channels_label;
  /*GSList *format_group = NULL;*/
  GSList *channels_group = NULL;
  GtkWidget *forward_rb;
  GtkWidget *reversed_rb;
  GtkWidget *both_rb;
  /*GtkWidget *wav_rb; GtkWidget *au_rb; GtkWidget *sw_rb;*/
  GtkWidget *ok_bt;

  /* if we can't save in a file: wrong codec, cut packets or other errors */
  /* shold the error arise here or later when you click ok button ? 
   * if we do it here, then we must disable the refresh button, so we don't do it here */

  if (save_voice_as_w != NULL) {
	/* There's already a Save voice info dialog box; reactivate it. */
	reactivate_window(save_voice_as_w);
	return;
  }
  
  save_voice_as_w = gtk_file_selection_new("Ethereal: Save Voice Data As");
  gtk_signal_connect(GTK_OBJECT(save_voice_as_w), "destroy",
       GTK_SIGNAL_FUNC(save_voice_as_destroy_cb), NULL);

  /* Container for each row of widgets */
  vertb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(vertb), 5);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(save_voice_as_w)->action_area),
    vertb, FALSE, FALSE, 0);
  gtk_widget_show (vertb);

  table1 = gtk_table_new (2, 4, FALSE);
  gtk_widget_show (table1);
  gtk_box_pack_start (GTK_BOX (vertb), table1, FALSE, FALSE, 0);
  gtk_container_set_border_width (GTK_CONTAINER (table1), 10);
  gtk_table_set_row_spacings (GTK_TABLE (table1), 20);

  label_format = gtk_label_new ("Format: .au (ulaw, 8 bit, 8000 Hz, mono) ");
  gtk_widget_show (label_format);
  gtk_table_attach (GTK_TABLE (table1), label_format, 0, 3, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  /* we support .au - ulaw*/ 
/*  wav_rb = gtk_radio_button_new_with_label (format_group, ".wav");
  format_group = gtk_radio_button_group (GTK_RADIO_BUTTON (wav_rb));
  gtk_widget_show (wav_rb);
  gtk_table_attach (GTK_TABLE (table1), wav_rb, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  sw_rb = gtk_radio_button_new_with_label (format_group, "8 kHz, 16 bit  ");
  format_group = gtk_radio_button_group (GTK_RADIO_BUTTON (sw_rb));
  gtk_widget_show (sw_rb);
  gtk_table_attach (GTK_TABLE (table1), sw_rb, 2, 3, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  au_rb = gtk_radio_button_new_with_label (format_group, ".au");
  format_group = gtk_radio_button_group (GTK_RADIO_BUTTON (au_rb));
  gtk_widget_show (au_rb);
  gtk_table_attach (GTK_TABLE (table1), au_rb, 3, 4, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
 */ 

  channels_label = gtk_label_new ("Channels:");
  gtk_widget_show (channels_label);
  gtk_table_attach (GTK_TABLE (table1), channels_label, 0, 1, 1, 2,
				(GtkAttachOptions) (GTK_FILL),
				(GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (channels_label), 0, 0.5);

  forward_rb = gtk_radio_button_new_with_label (channels_group, "forward  ");
  channels_group = gtk_radio_button_group (GTK_RADIO_BUTTON (forward_rb));
  gtk_widget_show (forward_rb);
  gtk_table_attach (GTK_TABLE (table1), forward_rb, 1, 2, 1, 2,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);

  reversed_rb = gtk_radio_button_new_with_label (channels_group, "reversed");
  channels_group = gtk_radio_button_group (GTK_RADIO_BUTTON (reversed_rb));
  gtk_widget_show (reversed_rb);
  gtk_table_attach (GTK_TABLE (table1), reversed_rb, 2, 3, 1, 2,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);

  both_rb = gtk_radio_button_new_with_label (channels_group, "both");
  channels_group = gtk_radio_button_group (GTK_RADIO_BUTTON (both_rb));
  gtk_widget_show (both_rb);
  gtk_table_attach (GTK_TABLE (table1), both_rb, 3, 4, 1, 2,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);

  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(both_rb), TRUE);

  /* if one direction is nok we don't allow saving 
  XXX this is not ok since the user can click the refresh button and cause changes
  but we can not update this window. So we move all the decision on the time the ok
  button is clicked
  if (rs->f_saved == FALSE) {
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(reversed_rb), TRUE);
	gtk_widget_set_sensitive(forward_rb, FALSE);
	gtk_widget_set_sensitive(both_rb, FALSE);
  }
  else if (rs->r_saved == FALSE) {
	gtk_widget_set_sensitive(reversed_rb, FALSE);
	gtk_widget_set_sensitive(both_rb, FALSE);
  }
  */

  ok_bt = GTK_FILE_SELECTION(save_voice_as_w)->ok_button;
  /*OBJECT_SET_DATA(ok_bt, "wav_rb", wav_rb);
  OBJECT_SET_DATA(ok_bt, "au_rb", au_rb);
  OBJECT_SET_DATA(ok_bt, "sw_rb", sw_rb);*/
  OBJECT_SET_DATA(ok_bt, "forward_rb", forward_rb);
  OBJECT_SET_DATA(ok_bt, "reversed_rb", reversed_rb);
  OBJECT_SET_DATA(ok_bt, "both_rb", both_rb);
  OBJECT_SET_DATA(ok_bt, "info_stat", rs);

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT_OBJECT(GTK_FILE_SELECTION(save_voice_as_w)->cancel_button,
                        "clicked", (GtkSignalFunc)gtk_widget_destroy,
                        save_voice_as_w);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(save_voice_as_w, GTK_FILE_SELECTION(save_voice_as_w)->cancel_button);
  
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		GTK_SIGNAL_FUNC(save_voice_as_ok_cb), save_voice_as_w);
  
  gtk_widget_show(save_voice_as_w);
}

/* all the graphics on the window is done here */
static void add_rtp_notebook(void *pri) 
{
  info_stat *rs=pri;

  GtkWidget *notebook, *page, *page_r, *label, *label1, *label2, *label3;
  GtkWidget *scrolled_window, *scrolled_window_r/*, *frame, *text, *label4, *page_help*/;
  GtkWidget *box4, *voice_bt, *refresh_bt, *close_bn;
  
  gchar *titles[6] =  {"Packet nr.", "Sequence",  "Delay (s)", "Jitter (s)", "Marker", "Status"};
  gchar label_forward[150];
  gchar label_reverse[150];

  g_snprintf(label_forward, 149, 
		"Analysing connection from  %s port %u  to  %s port %u   SSRC = %u\n", 
		rs->source, rs->srcport, rs->destination, rs->dstport, rs->ssrc_forward);
  g_snprintf(label_reverse, 149,
		"Analysing connection from  %s port %u  to  %s port %u   SSRC = %u\n", 
		rs->destination, rs->dstport, rs->source, rs->srcport, rs->ssrc_reversed);

  gtk_widget_destroy(main_vb);
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(rtp_w), main_vb);
  gtk_widget_show(main_vb);

  /* Start a nootbook for flipping between sets of changes */
  notebook = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), notebook);
  gtk_object_set_data(GTK_OBJECT(rtp_w), "notebook", notebook);

  /* page for forward connection */
  page = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(page), 20);

  /* scrolled window */
  scrolled_window = gtk_scrolled_window_new(NULL, NULL);
  gtk_widget_set_usize(scrolled_window, 600, 200);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), 
					GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

  /* direction label */
  label1 = gtk_label_new(label_forward);
  gtk_box_pack_start(GTK_BOX(page), label1, FALSE, FALSE, 0);

  /* place for some statistics */
  max = gtk_label_new("\n\n");
  gtk_box_pack_end(GTK_BOX(page), max, FALSE, FALSE, 5);

  /* clist for the information */
  clist = gtk_clist_new_with_titles(6, titles);
  gtk_widget_show(clist);
  gtk_container_add(GTK_CONTAINER(scrolled_window), clist);
  gtk_box_pack_start(GTK_BOX(page), scrolled_window, TRUE, TRUE, 0);

  /* and the label */
  label = gtk_label_new("     Forward Direction     ");
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page, label);

  /* column width and justification */
  gtk_clist_set_column_width(GTK_CLIST(clist), 0, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist), 1, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist), 2, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist), 3, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist), 4, 40);
  gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_CENTER);

  /* same page for reversed connection */
  page_r = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(page_r), 20);
  scrolled_window_r = gtk_scrolled_window_new(NULL, NULL);
  gtk_widget_set_usize(scrolled_window_r, 600, 200);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window_r), 
				GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
  label3 = gtk_label_new(label_reverse);
  gtk_box_pack_start(GTK_BOX(page_r), label3, FALSE, FALSE, 0);
  max_r = gtk_label_new("\n\n");
  gtk_box_pack_end(GTK_BOX(page_r), max_r, FALSE, FALSE, 5);
  clist_r = gtk_clist_new_with_titles(6, titles);
  gtk_widget_show(clist_r);
  gtk_container_add(GTK_CONTAINER(scrolled_window_r), clist_r);
  gtk_box_pack_start(GTK_BOX(page_r), scrolled_window_r, TRUE, TRUE, 0);
  label2 = gtk_label_new("     Reversed Direction     ");
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_r, label2);

  gtk_clist_set_column_width(GTK_CLIST(clist_r), 0, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist_r), 1, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist_r), 2, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist_r), 3, 80);
  gtk_clist_set_column_width(GTK_CLIST(clist_r), 4, 40);
  gtk_clist_set_column_justification(GTK_CLIST(clist_r), 0, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist_r), 1, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist_r), 2, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist_r), 3, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist_r), 4, GTK_JUSTIFY_CENTER);
  gtk_clist_set_column_justification(GTK_CLIST(clist_r), 5, GTK_JUSTIFY_CENTER);

  /* page for help&about or future 
  page_help = gtk_hbox_new(FALSE, 5);
  label4 = gtk_label_new("     Future    ");
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_help, label4);
  frame = gtk_frame_new("");
  text = gtk_label_new("\n\nMaybe some more statistics: delay and jitter distribution,...");
  gtk_label_set_justify(GTK_LABEL(text), GTK_JUSTIFY_LEFT);
  gtk_container_add(GTK_CONTAINER(frame), text);
  gtk_container_set_border_width(GTK_CONTAINER(frame), 20);
  gtk_box_pack_start(GTK_BOX(page_help), frame, TRUE, TRUE, 0);
*/
  /* show all notebooks */
  gtk_widget_show_all(notebook);

  /* and the buttons */
  box4 = gtk_hbutton_box_new();
  gtk_box_pack_start(GTK_BOX(main_vb), box4, FALSE, TRUE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(box4), 10);
  gtk_button_box_set_layout(GTK_BUTTON_BOX(box4), GTK_BUTTONBOX_SPREAD);
  gtk_widget_show(box4);

  voice_bt = gtk_button_new_with_label("Save voice data as...");
  gtk_container_add(GTK_CONTAINER(box4), voice_bt);
  gtk_widget_show(voice_bt);
  gtk_signal_connect(GTK_OBJECT(voice_bt), "clicked",
		GTK_SIGNAL_FUNC(save_voice_as_cb), rs);

  refresh_bt = gtk_button_new_with_label("Refresh");
  gtk_container_add(GTK_CONTAINER(box4), refresh_bt);
  gtk_widget_show(refresh_bt);
  gtk_signal_connect(GTK_OBJECT(refresh_bt), "clicked",
		GTK_SIGNAL_FUNC(refresh_cb), rs);

  close_bn = gtk_button_new_with_label("Close");
  gtk_container_add(GTK_CONTAINER(box4), close_bn);
  gtk_widget_show(close_bn);
  gtk_signal_connect(GTK_OBJECT(close_bn), "clicked",
		GTK_SIGNAL_FUNC(rtp_destroy), GTK_OBJECT(rtp_w));

  redissect_packets(&cfile);

  draw_stat(rs);
}


/* when we click on the selected row it copies that ssrc value into ssrc_reversed */
static void get_selected_ssrc(GtkWidget *clist_r, gint row, gint column, 
						GdkEventButton *event _U_, gpointer data)
{
  info_stat *rs=(info_stat *)data;
  gchar *text;

  gtk_clist_get_text(GTK_CLIST(clist_r), row, column, &text);
  /* XXX is this strtoul portable for guint32? */
  rs->ssrc_reversed = strtoul(text, (char **)NULL, 10);
  return;
}

/* when we click apply button in ssrc reversed dialog */
static void apply_selected_ssrc(GtkWidget *w _U_, gpointer data)
{
  info_stat *rs=(info_stat *)data;
  add_rtp_notebook(rs);
}

/* this function goes through all the packets that have the same ip and port combination 
 * (only inversed) as the forward direction (XXX what if the reversed direction doesn't use 
 * the same ports???) and looks for different SSRC values. This can happen if you capture
 * two RTP conversations one after another from the same pair of phones (PC's). 
 * Both have same IP's and can also have same port numbers, so they (should) differ only 
 * in SSRC values. In such case we get a list of ssrc values and we have to choose the right 
 * one from the list. If there is only one or none, we do it automatically */ 
static void get_reversed_ssrc(void *prs)
{
	info_stat *ri = prs;
	GtkWidget *scroll_r, *clist_r, *ok_bt, *label, *label2, *label1, *main_hbnbox;
	gchar temp[150];
	guint i;

	switch(ri->reversed_ip_and_port)
	{
		/* in case we haven't found any reversed ssrc */
		/* XXX in this case we could look for the inversed IP only */
		case 0: {
			ri->ssrc_reversed = 0;
			ri->search_ssrc = FALSE;
			add_rtp_notebook(ri);
			return;
		}
		/* in case we found exactly one matching ssrc for reversed connection */ 
		case 1: { 
			ri->ssrc_reversed = ri->ssrc_tmp[0];
			ri->search_ssrc = FALSE;
			add_rtp_notebook(ri);
			return;
		}
		/* there is more then one matching ssrc, so we have to choose between them */
		default: {
			ri->search_ssrc = FALSE;
			/* let's draw the window */
			label = gtk_label_new("Found more SSRC values for the reversed\n"
						 "connection with following parameters:\n");
			g_snprintf(temp, 149, "Source %s port %u Destination %s port %u", 
					ri->destination, ri->dstport, ri->source, ri->srcport);
			label2 = gtk_label_new(temp);
			gtk_box_pack_start(GTK_BOX(main_vb), label, FALSE, FALSE, 0);
			gtk_box_pack_start(GTK_BOX(main_vb), label2, FALSE, FALSE, 0);
			scroll_r = gtk_scrolled_window_new(NULL, NULL);
			gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_r), 
						GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
			clist_r = gtk_clist_new(1);
			gtk_clist_set_column_width(GTK_CLIST(clist_r), 0, 80);
			gtk_container_add(GTK_CONTAINER(scroll_r), clist_r);
			gtk_box_pack_start(GTK_BOX(main_vb), scroll_r, TRUE, TRUE, 0);
			label1 = gtk_label_new("Select one value and click apply");
			gtk_box_pack_start(GTK_BOX(main_vb), label1, FALSE, FALSE, 0);

			main_hbnbox = gtk_hbutton_box_new();
			gtk_box_pack_start(GTK_BOX(main_vb), main_hbnbox, FALSE, TRUE, 0);
			gtk_container_set_border_width(GTK_CONTAINER(main_hbnbox), 10);
			gtk_button_box_set_layout(GTK_BUTTON_BOX(main_hbnbox), 
								GTK_BUTTONBOX_SPREAD);
			gtk_widget_show(main_hbnbox);

			ok_bt = gtk_button_new_with_label("Apply");
			gtk_container_add(GTK_CONTAINER(main_hbnbox), ok_bt);
			gtk_signal_connect(GTK_OBJECT(clist_r), "select_row", 
					GTK_SIGNAL_FUNC(get_selected_ssrc), ri);
			gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked", 
					GTK_SIGNAL_FUNC(apply_selected_ssrc), ri);

			/* add all the ssrc values in the clist */
			/* XXX I'm sure the tmp variable could be avoided here
			 * i tried to assign guint32 from ri->ssrc_tmp somehow to gchar **text
			 * but gave up. So if you can do this, just go ahead */
			for (i=0; i < ri->reversed_ip_and_port; i++) {
				gchar *text[1];
				gchar tmp[20];
				g_snprintf(tmp, 20, "%u", ri->ssrc_tmp[i]);
				text[0] = (gchar *)&tmp;
				gtk_clist_append(GTK_CLIST(clist_r), text);
			}
			
			gtk_clist_select_row(GTK_CLIST(clist_r), 0, 0);

			gtk_widget_show(label);
			gtk_widget_show(label1);
			gtk_widget_show(label2);
			gtk_widget_show(ok_bt);
			gtk_widget_show(clist_r);
			gtk_widget_show(scroll_r);
		}
	}
}

/* XXX only handles RTP over IPv4, should add IPv6 support */
/* when the user clicks the RTP dialog button */
static void rtp_analyse_cb(GtkWidget *w _U_, gpointer data _U_) 
{ 
  info_stat *rs;
  gchar filter_text[256];
  dfilter_t *sfcode;
  capture_file *cf;
  epan_dissect_t *edt;
  gint err;
  gboolean frame_matched;
  frame_data *fdata;
  GString *error_string;

  /* There's already a "Display Options" dialog box; reactivate it. */
  if (rtp_w != NULL) {
	reactivate_window(rtp_w);
	return;
  }

  /* Try to compile the filter. */
  strcpy(filter_text,"rtp && ip");
  if (!dfilter_compile(filter_text, &sfcode)) {
	simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
	return;
  }
  /* we load the current file into cf variable */
  cf = &cfile;
  fdata = cf->current_frame;

  /* we are on the selected frame now */
  if (fdata == NULL)
	return; /* if we exit here it's an error */

  /* XXX instead of looking for RTP protocol like this, we could do the process_node() staff */
  /* dissect the current frame */
  wtap_seek_read(cf->wth, fdata->file_off, &cf->pseudo_header, cf->pd, fdata->cap_len, &err);
  edt = epan_dissect_new(TRUE, FALSE);
  epan_dissect_prime_dfilter(edt, sfcode);
  epan_dissect_run(edt, &cf->pseudo_header, cf->pd, fdata, &cf->cinfo);
  frame_matched = dfilter_apply_edt(sfcode, edt);

  /* if it is not an rtp frame, exit */
  frame_matched = dfilter_apply_edt(sfcode, edt);
  if (frame_matched != 1) {
	epan_dissect_free(edt);
	simple_dialog(ESD_TYPE_CRIT, NULL, "You didn't choose a RTP packet!");
	return;
	}

  /* in rs we put all the info */
  rs=g_malloc(sizeof(info_stat));	

  /* ok, it is a RTP frame, so let's get the ip and port values */
  rs->srcport = edt->pi.srcport;
  rs->dstport = edt->pi.destport;
  strncpy(rs->source, ip_to_str(edt->pi.src.data), 16);  
  strncpy(rs->destination, ip_to_str(edt->pi.dst.data), 16);  

  /* now we need the SSRC value of the current frame */
  rs->ssrc_forward = process_tree(edt->tree);
  if (rs->ssrc_forward == 0) {
	simple_dialog(ESD_TYPE_CRIT, NULL, "SSRC value couldn't be found!");
	return;
  }

  /* now we have all the information about the forwarding connection
   * we need to go through all the packets and search for reversed connection
   */
  rs->search_ssrc = TRUE;
  rs->ssrc_reversed = 0;	
  rs->reversed_ip = 0;
  rs->reversed_ip_and_port = 0;
  rs->ssrc_tmp = NULL;

  sprintf(filter_text,"rtp && ip && !icmp && (( ip.src==%s && udp.srcport==%d && ip.dst==%s && udp.dstport==%d ) || ( ip.src==%s && udp.srcport==%d && ip.dst==%s && udp.dstport==%d ))",
	  ip_to_str(edt->pi.src.data),
	  edt->pi.srcport,
	  ip_to_str(edt->pi.dst.data),
	  edt->pi.destport,
	  ip_to_str(edt->pi.dst.data),
	  edt->pi.destport,
	  ip_to_str(edt->pi.src.data),
	  edt->pi.srcport
	  );
/* XXX compiler warning:passing arg 5 of `register_tap_listener' from incompatible pointer type */
  error_string = register_tap_listener("rtp", rs, filter_text, rtp_reset, rtp_packet, rtp_draw);
  if (error_string != NULL) {
	simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
	/* XXX is this enough or do I have to free anything else? */
	g_string_free(error_string, TRUE);
	g_free(rs);
	exit(1);
  }

  /* let's draw the window */
  rtp_w = dlg_window_new("Ethereal: RTP Analyse");
  gtk_window_set_position (GTK_WINDOW (rtp_w), GTK_WIN_POS_CENTER);
  gtk_signal_connect(GTK_OBJECT(rtp_w), "destroy",
	GTK_SIGNAL_FUNC(rtp_destroy_cb), rs);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(rtp_w), main_vb);
  gtk_widget_show(main_vb);

  /* file names for storing sound data */
  tmpnam(f_tempname);
  tmpnam(r_tempname);
  rs->f_fp = NULL;
  rs->r_fp = NULL;

  redissect_packets(cf);

  /* so how many reversed connection we have ? */
  get_reversed_ssrc(rs);

  /* and finally display this window */
  gtk_widget_show(rtp_w);
}

static void
rtp_analyse_init(char *dummy _U_)
{
	rtp_analyse_cb(NULL, NULL);
}

void
register_tap_listener_gtkrtp(void)
{
	register_ethereal_tap("rtp", rtp_analyse_init);
}

void
register_tap_menu_gtkrtp(void)
{
	register_tap_menu_item("RTP Analysis...", rtp_analyse_cb);
}


/* here we save it into a file that user specified */
/* XXX what about endians here? could go something wrong? */
static gboolean copy_file(gchar *dest, gint channels, /*gint format,*/ void *data)
{
	info_stat *rs=(info_stat *)data;
	int to_fd, forw_fd, rev_fd, fread = 0, rread = 0, fwritten, rwritten;
	gint16 f_pd;
	gint16 r_pd;
	gchar pd[1];
	guint32 f_write_silence = 0;
	guint32 r_write_silence = 0;
	progdlg_t *progbar;
	guint32 progbar_count, progbar_quantum, progbar_nextstep = 0, count = 0;
	gboolean stop_flag = FALSE;

	forw_fd = open(f_tempname, O_RDONLY | O_BINARY);
	if (forw_fd < 0) 
		return FALSE;
	rev_fd = open(r_tempname, O_RDONLY | O_BINARY);
	if (rev_fd < 0) {
		close(forw_fd); 
		return FALSE;
	}

	/* open file for saving */
	to_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (to_fd < 0) {
		close(forw_fd);
		close(rev_fd);
		return FALSE;
	}

	progbar = create_progress_dlg("Saving voice in a file", dest, "Stop", &stop_flag);

	/* First we write the .au header. XXX Hope this is endian independant */
	/* the magic word 0x2e736e64 == .snd */
	*pd = (unsigned char)0x2e; write(to_fd, pd, 1);
	*pd = (unsigned char)0x73; write(to_fd, pd, 1);
	*pd = (unsigned char)0x6e; write(to_fd, pd, 1);
	*pd = (unsigned char)0x64; write(to_fd, pd, 1);
	/* header offset == 24 bytes */
	*pd = (unsigned char)0x00; write(to_fd, pd, 1);
	write(to_fd, pd, 1);
	write(to_fd, pd, 1);
	*pd = (unsigned char)0x18; write(to_fd, pd, 1);
	/* total length, it is permited to set this to 0xffffffff */
	*pd = (unsigned char)0xff; write(to_fd, pd, 1); 
	write(to_fd, pd, 1); 
	write(to_fd, pd, 1); 
	write(to_fd, pd, 1);
	/* encoding format == 8 bit ulaw */
	*pd = (unsigned char)0x00; write(to_fd, pd, 1);
	write(to_fd, pd, 1);
	write(to_fd, pd, 1);
	*pd = (unsigned char)0x01; write(to_fd, pd, 1);
	/* sample rate == 8000 Hz */
	*pd = (unsigned char)0x00; write(to_fd, pd, 1);
	write(to_fd, pd, 1);
	*pd = (unsigned char)0x1f; write(to_fd, pd, 1);
	*pd = (unsigned char)0x40; write(to_fd, pd, 1);
	/* channels == 1 */
	*pd = (unsigned char)0x00; write(to_fd, pd, 1);
	write(to_fd, pd, 1);
	write(to_fd, pd, 1);
	*pd = (unsigned char)0x01; write(to_fd, pd, 1);
	
	switch (channels) {
		/* only forward direction */
		case 1: {
			progbar_count = rs->f_count;
			progbar_quantum = rs->f_count/100;
			while ((fread = read(forw_fd, &f_pd, 2)) > 0) {
				if(stop_flag) 
					break;
				if((count > progbar_nextstep) && (count <= progbar_count)) {
					update_progress_dlg(progbar, 
						(gfloat) count/progbar_count, "Saving");
					progbar_nextstep = progbar_nextstep + progbar_quantum;
				}
				count++;
				*pd = (unsigned char)linear2ulaw(f_pd);
				fwritten = write(to_fd, pd, 1);
				if ((fwritten*2 < fread) || (fwritten < 0) || (fread < 0)) {
					close(forw_fd);
					close(rev_fd);
					close(to_fd);
					destroy_progress_dlg(progbar);
					return FALSE;
				}
			}
			break;
		}
		/* only reversed direction */
		case 2: {
			progbar_count = rs->r_count;
			progbar_quantum = rs->r_count/100;
			while ((rread = read(rev_fd, &r_pd, 2)) > 0) {
				if(stop_flag) 
					break;
				if((count > progbar_nextstep) && (count <= progbar_count)) {
					update_progress_dlg(progbar, 
						(gfloat) count/progbar_count, "Saving");
					progbar_nextstep = progbar_nextstep + progbar_quantum;
				}
				count++;
				*pd = (unsigned char)linear2ulaw(r_pd);
				rwritten = write(to_fd, pd, 1);
				if ((rwritten*2 < rread) || (rwritten < 0) || (rread < 0)) {
					close(forw_fd);
					close(rev_fd);
					close(to_fd);
					destroy_progress_dlg(progbar);
					return FALSE;
				}
			}
			break;
		}
		/* both directions */
		default: {
			(rs->f_count > rs->r_count) ? (progbar_count = rs->f_count) : 
								(progbar_count = rs->r_count);
			progbar_quantum = progbar_count/100;
			/* since conversation in one way can start later than in the other one, 
			 * we have to write some silence information for one channel */
			if (rs->f_start_time > rs->r_start_time) {
				f_write_silence = (rs->f_start_time-rs->r_start_time)*8000;
			}
			else if (rs->f_start_time < rs->r_start_time) {
				r_write_silence = (rs->r_start_time-rs->f_start_time)*8000;
			}
			for(;;) {
				if(stop_flag) 
					break;
				if((count > progbar_nextstep) && (count <= progbar_count)) {
					update_progress_dlg(progbar, 
						(gfloat) count/progbar_count, "Saving");
					progbar_nextstep = progbar_nextstep + progbar_quantum;
				}
				count++;
				if(f_write_silence > 0) {
					rread = read(rev_fd, &r_pd, 2);
					f_pd = 0;
					fread = 1;
					f_write_silence--;
				}
				else if(r_write_silence > 0) {
					fread = read(forw_fd, &f_pd, 2);
					r_pd = 0;
					rread = 1;
					r_write_silence--;
				}
				else {
					fread = read(forw_fd, &f_pd, 2); 
					rread = read(rev_fd, &r_pd, 2);
				}
				if ((rread == 0) && (fread == 0)) 
					break;
				*pd = (unsigned char)linear2ulaw( (f_pd + r_pd)/2 );
				rwritten = write(to_fd, pd, 1);
				if ((rwritten < 0) || (rread < 0) || (fread < 0)) {
					close(forw_fd);
					close(rev_fd);
					close(to_fd);
					destroy_progress_dlg(progbar);
					return FALSE;
				}
			}
		}
	}
	destroy_progress_dlg(progbar);
	close(forw_fd);
	close(rev_fd);
	close(to_fd);
	return TRUE;

}
