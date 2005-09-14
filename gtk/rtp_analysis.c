/* rtp_analysis.c
 * RTP analysis addition for ethereal
 *
 * $Id$
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * based on tap_rtp.c
 * Copyright 2003, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * Graph. Copyright 2004, Verso Technology
 * By Alejandro Vaquero <alejandro.vaquero@verso.com>
 * Based on io_stat.c by Ronnie Sahlberg 
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
#include "config.h"
#endif

/*do not define this symbol. will be added soon*/
/*#define USE_CONVERSATION_GRAPH 1*/

#include "rtp_analysis.h"
#include "rtp_stream.h"
#include "rtp_stream_dlg.h"

#ifdef USE_CONVERSATION_GRAPH
#include "../graph/graph.h"
#endif

#include <epan/epan_dissect.h>
#include <epan/filesystem.h>

#include "util.h"
#include <epan/tap.h>
#include "register.h"
#include <epan/dissectors/packet-rtp.h>
#include "g711.h"
#include "rtp_pt.h"
#include <epan/addr_resolv.h>

/* in /gtk ... */
#include <gtk/gtk.h>
#include "gtkglobals.h"

#include <epan/stat_cmd_args.h>
#include "dlg_utils.h"
#include "gui_utils.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "main.h"
#include "progress_dlg.h"
#include "compat_macros.h"
#include "../color.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#include <math.h>
#include <fcntl.h>
#include <string.h>
#include <locale.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_IO_H
#include <io.h> /* open/close on win32 */
#endif

/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY 0
#endif

/****************************************************************************/

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;

#define NUM_COLS 9
#define NUM_GRAPH_ITEMS 100000
#define MAX_YSCALE 16
#define AUTO_MAX_YSCALE 0
#define MAX_GRAPHS 4
#define GRAPH_FWD_JITTER 0
#define GRAPH_FWD_DIFF 1
#define GRAPH_REV_JITTER 2
#define GRAPH_REV_DIFF 3
static guint32 yscale_max[MAX_YSCALE] = {AUTO_MAX_YSCALE, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 2000000, 5000000, 10000000, 20000000, 50000000};

#define MAX_PIXELS_PER_TICK 4
#define DEFAULT_PIXELS_PER_TICK 1
static guint32 pixels_per_tick[MAX_PIXELS_PER_TICK] = {1, 2, 5, 10};
static const char *graph_descr[4] = {"Fwd Jitter", "Fwd Difference", "Rvr Jitter", "Rvr Difference"};
/* unit is in ms */
#define MAX_TICK_VALUES 5
#define DEFAULT_TICK_VALUE 1
static guint tick_interval_values[MAX_TICK_VALUES] = { 1, 10, 100, 1000, 10000 };
typedef struct _dialog_graph_graph_item_t {
	guint32 value;
	guint32 flags;
} dialog_graph_graph_item_t;

typedef struct _dialog_graph_graph_t {
	struct _user_data_t *ud;	
        dialog_graph_graph_item_t items[NUM_GRAPH_ITEMS];
        int plot_style;
        gboolean display;
        GtkWidget *display_button;
        int hf_index;
        GdkColor color;
        GdkGC *gc;
	gchar title[100];
} dialog_graph_graph_t;


typedef struct _dialog_graph_t {
	gboolean needs_redraw;
        gint32 interval;    /* measurement interval in ms */
        guint32 last_interval;
        guint32 max_interval; /* XXX max_interval and num_items are redundant */
        guint32 num_items;
	struct _dialog_graph_graph_t graph[MAX_GRAPHS];
        GtkWidget *window;
        GtkWidget *draw_area;
        GdkPixmap *pixmap;
        GtkAdjustment *scrollbar_adjustment;
        GtkWidget *scrollbar;
        int pixmap_width;
        int pixmap_height;
        int pixels_per_tick;
        int max_y_units;
	double start_time;
} dialog_graph_t;	

typedef struct _dialog_data_t {
	GtkWidget *window;
	GtkCList *clist_fwd;
	GtkCList *clist_rev;
	GtkWidget *label_stats_fwd;
	GtkWidget *label_stats_rev;
	column_arrows *col_arrows_fwd;
	column_arrows *col_arrows_rev;
	GtkWidget *notebook;
	GtkCList *selected_clist;
	GtkWidget *save_voice_as_w;
	GtkWidget *save_csv_as_w;
	gint notebook_signal_id;
	gint selected_row;
        dialog_graph_t dialog_graph;
#ifdef USE_CONVERSATION_GRAPH
	GtkWidget *graph_window;
#endif
} dialog_data_t;

#define OK_TEXT "[ Ok ]"

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
	return 1;
}


/* type of error when saving voice in a file didn't succeed */
typedef enum {
	TAP_RTP_WRONG_CODEC,
	TAP_RTP_WRONG_LENGTH,
	TAP_RTP_PADDING_ERROR,
	TAP_RTP_SHORT_FRAME,
	TAP_RTP_FILE_OPEN_ERROR,
	TAP_RTP_NO_DATA
} error_type_t; 

#if GTK_MAJOR_VERSION < 2
GtkRcStyle *rc_style;
GdkColormap *colormap;
#endif

typedef struct _tap_rtp_save_info_t {
	FILE *fp;
	guint32 count;
	error_type_t error_type;
	gboolean saved;
} tap_rtp_save_info_t;


/* structure that holds the information about the forward and reversed direction */
struct _info_direction {
	tap_rtp_stat_t statinfo;
	tap_rtp_save_info_t saveinfo;
};

#define TMPNAMSIZE 100

/* structure that holds general information about the connection 
* and structures for both directions */
typedef struct _user_data_t {
	/* tap associated data*/
	address ip_src_fwd;
	guint16 port_src_fwd;
	address ip_dst_fwd;
	guint16 port_dst_fwd;
	guint32 ssrc_fwd;
	address ip_src_rev;
	guint16 port_src_rev;
	address ip_dst_rev;
	guint16 port_dst_rev;
	guint32 ssrc_rev;

	struct _info_direction forward;
	struct _info_direction reversed;

	char f_tempname[TMPNAMSIZE];
	char r_tempname[TMPNAMSIZE];

	/* dialog associated data */
	dialog_data_t dlg;

#ifdef USE_CONVERSATION_GRAPH
	time_series_t series_fwd;
	time_series_t series_rev;
#endif
} user_data_t;


/* Column titles. */
static const gchar *titles[9] =  {
	"Packet",
	"Sequence",
	"Delta (ms)",
	"Jitter (ms)",
	"IP BW (kbps)",
	"Marker",
	"Status",
	"Date",
	"Length"
};

#define SAVE_FORWARD_DIRECTION_MASK 0x01
#define SAVE_REVERSE_DIRECTION_MASK 0x02	
#define SAVE_BOTH_DIRECTION_MASK	(SAVE_FORWARD_DIRECTION_MASK|SAVE_REVERSE_DIRECTION_MASK) 

#define SAVE_AU_FORMAT	2
#define SAVE_RAW_FORMAT	4


static void on_refresh_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_);
/****************************************************************************/
static void enable_graph(dialog_graph_graph_t *dgg)
{
        
        dgg->display=TRUE;

}

static void dialog_graph_reset(user_data_t* user_data);



/****************************************************************************/
/* TAP FUNCTIONS */

/****************************************************************************/
/* when there is a [re]reading of packet's */
static void
rtp_reset(void *user_data_arg)
{
	user_data_t *user_data = user_data_arg;
	user_data->forward.statinfo.first_packet = TRUE;
	user_data->reversed.statinfo.first_packet = TRUE;
	user_data->forward.statinfo.max_delta = 0;
	user_data->reversed.statinfo.max_delta = 0;
	user_data->forward.statinfo.max_jitter = 0;
	user_data->reversed.statinfo.max_jitter = 0;
	user_data->forward.statinfo.mean_jitter = 0;
	user_data->reversed.statinfo.mean_jitter = 0;
	user_data->forward.statinfo.delta = 0;
	user_data->reversed.statinfo.delta = 0;
	user_data->forward.statinfo.diff = 0;
	user_data->reversed.statinfo.diff = 0;
	user_data->forward.statinfo.jitter = 0;
	user_data->reversed.statinfo.jitter = 0;
	user_data->forward.statinfo.bandwidth = 0;
	user_data->reversed.statinfo.bandwidth = 0;
	user_data->forward.statinfo.total_bytes = 0;
	user_data->reversed.statinfo.total_bytes = 0;
	user_data->forward.statinfo.bw_start_index = 0;
	user_data->reversed.statinfo.bw_start_index = 0;
	user_data->forward.statinfo.bw_index = 0;
	user_data->reversed.statinfo.bw_index = 0;
	user_data->forward.statinfo.timestamp = 0;
	user_data->reversed.statinfo.timestamp = 0;
	user_data->forward.statinfo.max_nr = 0;
	user_data->reversed.statinfo.max_nr = 0;
	user_data->forward.statinfo.total_nr = 0;
	user_data->reversed.statinfo.total_nr = 0;
	user_data->forward.statinfo.sequence = 0;
	user_data->reversed.statinfo.sequence = 0;
	user_data->forward.statinfo.start_seq_nr = 0;
	user_data->reversed.statinfo.start_seq_nr = 1; /* 1 is ok (for statistics in reversed direction) */
	user_data->forward.statinfo.stop_seq_nr = 0;
	user_data->reversed.statinfo.stop_seq_nr = 0;
	user_data->forward.statinfo.cycles = 0;
	user_data->reversed.statinfo.cycles = 0;
	user_data->forward.statinfo.under = FALSE;
	user_data->reversed.statinfo.under = FALSE;
	user_data->forward.statinfo.start_time = 0;
	user_data->reversed.statinfo.start_time = 0;
	user_data->forward.statinfo.time = 0;
	user_data->reversed.statinfo.time = 0;
	user_data->forward.statinfo.reg_pt = PT_UNDEFINED;
	user_data->reversed.statinfo.reg_pt = PT_UNDEFINED;

	user_data->forward.saveinfo.count = 0;
	user_data->reversed.saveinfo.count = 0;
	user_data->forward.saveinfo.saved = FALSE;
	user_data->reversed.saveinfo.saved = FALSE;

	/* clear the dialog box clists */
	gtk_clist_clear(GTK_CLIST(user_data->dlg.clist_fwd));
	gtk_clist_clear(GTK_CLIST(user_data->dlg.clist_rev));

	/* reset graph info */
	dialog_graph_reset(user_data);

#ifdef USE_CONVERSATION_GRAPH
	if (user_data->dlg.graph_window != NULL)
		window_destroy(user_data->dlg.graph_window);
	
	g_array_free(user_data->series_fwd.value_pairs, TRUE);
	user_data->series_fwd.value_pairs = g_array_new(FALSE, FALSE, sizeof(value_pair_t));

	g_array_free(user_data->series_rev.value_pairs, TRUE);
	user_data->series_rev.value_pairs = g_array_new(FALSE, FALSE, sizeof(value_pair_t));
#endif

	/* XXX check for error at fclose? */
	if (user_data->forward.saveinfo.fp != NULL)
		fclose(user_data->forward.saveinfo.fp); 
	if (user_data->reversed.saveinfo.fp != NULL)
		fclose(user_data->reversed.saveinfo.fp); 
	user_data->forward.saveinfo.fp = fopen(user_data->f_tempname, "wb"); 
	if (user_data->forward.saveinfo.fp == NULL)
		user_data->forward.saveinfo.error_type = TAP_RTP_FILE_OPEN_ERROR;
	user_data->reversed.saveinfo.fp = fopen(user_data->r_tempname, "wb");
	if (user_data->reversed.saveinfo.fp == NULL)
		user_data->reversed.saveinfo.error_type = TAP_RTP_FILE_OPEN_ERROR;
	return;
}

/****************************************************************************/
static int rtp_packet_add_graph(dialog_graph_graph_t *dgg, tap_rtp_stat_t *statinfo, packet_info *pinfo, guint32 value)
{
	dialog_graph_graph_item_t *it;
	int idx;
	double rtp_time;

	/* we sometimes get called when dgg is disabled.
	this is a bug since the tap listener should be removed first */
	if(!dgg->display){
		return 0;
	}

	dgg->ud->dlg.dialog_graph.needs_redraw=TRUE;

	/*
	* Find which interval this is supposed to to in and store the
	* interval index as idx
	*/
	if (dgg->ud->dlg.dialog_graph.start_time == -1){ /* it is the first */
		dgg->ud->dlg.dialog_graph.start_time = statinfo->start_time;
	}
	rtp_time = nstime_to_sec(&pinfo->fd->rel_ts) - dgg->ud->dlg.dialog_graph.start_time;
	if(rtp_time<0){
		return FALSE;
	}
	idx = (guint32)(rtp_time*1000)/dgg->ud->dlg.dialog_graph.interval;

	/* some sanity checks */
	if((idx<0)||(idx>=NUM_GRAPH_ITEMS)){
		return FALSE;
	}

	/* update num_items */
	if((guint32)idx > dgg->ud->dlg.dialog_graph.num_items){
		dgg->ud->dlg.dialog_graph.num_items=idx;
		dgg->ud->dlg.dialog_graph.max_interval=idx*dgg->ud->dlg.dialog_graph.interval;
	}

	/*
	* Find the appropriate dialog_graph_graph_item_t structure
	*/
	it=&dgg->items[idx];

	/*
	* Use the max value to highlight RTP problems
	*/
	if (value > it->value) {
		it->value=value;
	}
	it->flags = it->flags | statinfo->flags;

	return TRUE;
}

/****************************************************************************/
/* here we can redraw the output */
/* not used yet */
static void rtp_draw(void *prs _U_)
{
	return;
}

/* forward declarations */
static void add_to_clist(GtkCList *clist, guint32 number, guint16 seq_num,
                         double delta, double jitter, double bandwidth, gchar *status, gboolean marker,
                         gchar *timeStr, guint32 pkt_len, GdkColor *color);

static int rtp_packet_add_info(GtkCList *clist,
	tap_rtp_stat_t *statinfo, packet_info *pinfo,
	const struct _rtp_info *rtpinfo);

static int rtp_packet_save_payload(tap_rtp_save_info_t *saveinfo, 
                                   tap_rtp_stat_t *statinfo,
                                   packet_info *pinfo,
                                   const struct _rtp_info *rtpinfo);


/****************************************************************************/
/* whenever a RTP packet is seen by the tap listener */
static int rtp_packet(void *user_data_arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *rtpinfo_arg)
{
	user_data_t *user_data = user_data_arg;
	const struct _rtp_info *rtpinfo = rtpinfo_arg;
#ifdef USE_CONVERSATION_GRAPH
	value_pair_t vp;
#endif
	/* we ignore packets that are not displayed */
	if (pinfo->fd->flags.passed_dfilter == 0)
		return 0;
	/* also ignore RTP Version != 2 */
	else if (rtpinfo->info_version !=2)
		return 0;
	/* is it the forward direction?  */
	else if (user_data->ssrc_fwd == rtpinfo->info_sync_src
		&& CMP_ADDRESS(&(user_data->ip_src_fwd), &(pinfo->net_src)) == 0
		&& user_data->port_src_fwd == pinfo->srcport
		&& CMP_ADDRESS(&(user_data->ip_dst_fwd), &(pinfo->net_dst)) == 0
		&& user_data->port_dst_fwd == pinfo->destport)  {
#ifdef USE_CONVERSATION_GRAPH
		vp.time = ((double)pinfo->fd->rel_secs + (double)pinfo->fd->rel_usecs/1000000);
		vp.fnumber = pinfo->fd->num;
		g_array_append_val(user_data->series_fwd.value_pairs, vp);
#endif
		rtp_packet_analyse(&(user_data->forward.statinfo), pinfo, rtpinfo);
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_FWD_JITTER]), &(user_data->forward.statinfo), pinfo, (guint32)(user_data->forward.statinfo.jitter*1000000));
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_FWD_DIFF]), &(user_data->forward.statinfo), pinfo, (guint32)(user_data->forward.statinfo.diff*1000000));
		rtp_packet_add_info(user_data->dlg.clist_fwd,
			&(user_data->forward.statinfo), pinfo, rtpinfo);
		rtp_packet_save_payload(&(user_data->forward.saveinfo),
			&(user_data->forward.statinfo), pinfo, rtpinfo);
	}
	/* is it the reversed direction? */
	else if (user_data->ssrc_rev == rtpinfo->info_sync_src
		&& CMP_ADDRESS(&(user_data->ip_src_rev), &(pinfo->net_src)) == 0
		&& user_data->port_src_rev == pinfo->srcport
		&& CMP_ADDRESS(&(user_data->ip_dst_rev), &(pinfo->net_dst)) == 0
		&& user_data->port_dst_rev == pinfo->destport)  {
#ifdef USE_CONVERSATION_GRAPH
		vp.time = ((double)pinfo->fd->rel_secs + (double)pinfo->fd->rel_usecs/1000000);
		vp.fnumber = pinfo->fd->num;
		g_array_append_val(user_data->series_rev.value_pairs, vp);
#endif
		rtp_packet_analyse(&(user_data->reversed.statinfo), pinfo, rtpinfo);
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_REV_JITTER]), &(user_data->reversed.statinfo), pinfo, (guint32)(user_data->reversed.statinfo.jitter*1000000));
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_REV_DIFF]), &(user_data->reversed.statinfo), pinfo, (guint32)(user_data->reversed.statinfo.diff*1000000));
		rtp_packet_add_info(user_data->dlg.clist_rev,
			&(user_data->reversed.statinfo), pinfo, rtpinfo);
		rtp_packet_save_payload(&(user_data->reversed.saveinfo),
			&(user_data->reversed.statinfo), pinfo, rtpinfo);
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
	double current_diff;
	guint32 clock_rate;

	statinfo->flags = 0;
	/* check payload type */
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
	 * XXX - should "get_clock_rate()" return 0 for unknown
	 * payload types, presumably meaning that we should
	 * just ignore this packet?
	 */
	clock_rate = get_clock_rate(statinfo->pt);

	/* store the current time and calculate the current jitter */
	current_time = nstime_to_sec(&pinfo->fd->rel_ts);
	current_diff = fabs (current_time - (statinfo->time) - ((double)(rtpinfo->info_timestamp)-(double)(statinfo->timestamp))/clock_rate);
	current_jitter = statinfo->jitter + ( current_diff - statinfo->jitter)/16;
	statinfo->delta = current_time-(statinfo->time);
	statinfo->jitter = current_jitter;
	statinfo->diff = current_diff;

	/* calculate the BW in Kbps adding the IP+UDP header to the RTP -> 20bytes(IP)+8bytes(UDP) = 28bytes */
	statinfo->bw_history[statinfo->bw_index].bytes = rtpinfo->info_data_len + 28;
	statinfo->bw_history[statinfo->bw_index].time = current_time;
	/* check if there are more than 1sec in the history buffer to calculate BW in bps. If so, remove those for the calculation */
	while ((statinfo->bw_history[statinfo->bw_start_index].time+1)<current_time){
	 	statinfo->total_bytes -= statinfo->bw_history[statinfo->bw_start_index].bytes;	
		statinfo->bw_start_index++;
		if (statinfo->bw_start_index == BUFF_BW) statinfo->bw_start_index=0;
	};
	statinfo->total_bytes += rtpinfo->info_data_len + 28;
	statinfo->bandwidth = (double)(statinfo->total_bytes*8)/1000;
	statinfo->bw_index++;
	if (statinfo->bw_index == BUFF_BW) statinfo->bw_index = 0;	


	/*  is this the first packet we got in this direction? */
	if (statinfo->first_packet) {
		statinfo->start_seq_nr = rtpinfo->info_seq_num;
		statinfo->start_time = current_time;
		statinfo->delta = 0;
		statinfo->jitter = 0;
		statinfo->diff = 0;
		statinfo->flags |= STAT_FLAG_FIRST;
		statinfo->first_packet = FALSE;
	}
	/* is it a packet with the mark bit set? */
	if (rtpinfo->info_marker_set) {
		if (rtpinfo->info_timestamp > statinfo->timestamp){
			statinfo->delta_timestamp = rtpinfo->info_timestamp - statinfo->timestamp;
			statinfo->flags |= STAT_FLAG_MARKER;
		}
		else{
			statinfo->flags |= STAT_FLAG_WRONG_TIMESTAMP;
		}
	}
	/* is it a regular packet? */
	if (!(statinfo->flags & STAT_FLAG_FIRST)
		&& !(statinfo->flags & STAT_FLAG_MARKER)
		&& !(statinfo->flags & STAT_FLAG_PT_CN)
		&& !(statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP)
		&& !(statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)) {
		/* include it in maximum delta calculation */
		if (statinfo->delta > statinfo->max_delta) {
			statinfo->max_delta = statinfo->delta;
			statinfo->max_nr = pinfo->fd->num;
		}
		/* maximum and mean jitter calculation */
		if (statinfo->jitter > statinfo->max_jitter) {
			statinfo->max_jitter = statinfo->jitter;
		}
		statinfo->mean_jitter = (statinfo->mean_jitter*statinfo->total_nr + current_diff) / (statinfo->total_nr+1);
	}
	/* regular payload change? (CN ignored) */
	if (!(statinfo->flags & STAT_FLAG_FIRST)
		&& !(statinfo->flags & STAT_FLAG_PT_CN)) {
		if ((statinfo->pt != statinfo->reg_pt)
			&& (statinfo->reg_pt != PT_UNDEFINED)) {
			statinfo->flags |= STAT_FLAG_REG_PT_CHANGE;
		}
	}

	/* set regular payload*/
	if (!(statinfo->flags & STAT_FLAG_PT_CN)) {
		statinfo->reg_pt = statinfo->pt;
	}


	/* When calculating expected rtp packets the seq number can wrap around
	* so we have to count the number of cycles
	* Variable cycles counts the wraps around in forwarding connection and
	* under is flag that indicates where we are
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
	if ((rtpinfo->info_seq_num < statinfo->start_seq_nr) && (statinfo->under == FALSE)){
		statinfo->cycles++;
		statinfo->under = TRUE;
	}
	/* what if the start seq nr was 0? Then the above condition will never
	* be true, so we add another condition. XXX The problem would arise
	* if one of the packets with seq nr 0 or 65535 would be lost or late */
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
	* we would like to know at least how many times the sequence number was not ok */

	/* if the current seq number equals the last one or if we are here for
	* the first time, then it is ok, we just store the current one as the last one */
	if ( (statinfo->seq_num+1 == rtpinfo->info_seq_num) || (statinfo->flags & STAT_FLAG_FIRST) )
		statinfo->seq_num = rtpinfo->info_seq_num;
	/* if the first one is 65535. XXX same problem as above: if seq 65535 or 0 is lost... */
	else if ( (statinfo->seq_num == 65535) && (rtpinfo->info_seq_num == 0) )
		statinfo->seq_num = rtpinfo->info_seq_num;
	/* lost packets */
	else if (statinfo->seq_num+1 < rtpinfo->info_seq_num) {
		statinfo->seq_num = rtpinfo->info_seq_num;
		statinfo->sequence++;
		statinfo->flags |= STAT_FLAG_WRONG_SEQ;
	}
	/* late or duplicated */
	else if (statinfo->seq_num+1 > rtpinfo->info_seq_num) {
		statinfo->sequence++;
		statinfo->flags |= STAT_FLAG_WRONG_SEQ;
	}
	statinfo->time = current_time;
	statinfo->timestamp = rtpinfo->info_timestamp;
	statinfo->stop_seq_nr = rtpinfo->info_seq_num;
	statinfo->total_nr++;

	return 0;
}


static const GdkColor COLOR_DEFAULT = {0, 0xffff, 0xffff, 0xffff};
static const GdkColor COLOR_ERROR = {0, 0xffff, 0xbfff, 0xbfff};
static const GdkColor COLOR_WARNING = {0, 0xffff, 0xdfff, 0xbfff};
static const GdkColor COLOR_CN = {0, 0xbfff, 0xbfff, 0xffff};

/****************************************************************************/
/* adds statistics information from the packet to the clist */
static int rtp_packet_add_info(GtkCList *clist,
	tap_rtp_stat_t *statinfo, packet_info *pinfo,
	const struct _rtp_info *rtpinfo)
{
	guint16 msecs;
	gchar timeStr[32];
	struct tm *tm_tmp;
	time_t then;
	gchar status[40];
	GdkColor color = COLOR_DEFAULT;
	then = pinfo->fd->abs_ts.secs;
	msecs = (guint16)(pinfo->fd->abs_ts.nsecs/1000000);
	tm_tmp = localtime(&then);
	g_snprintf(timeStr,sizeof(timeStr),"%02d/%02d/%04d %02d:%02d:%02d.%03d",
		tm_tmp->tm_mon + 1,
		tm_tmp->tm_mday,
		tm_tmp->tm_year + 1900,
		tm_tmp->tm_hour,
		tm_tmp->tm_min,
		tm_tmp->tm_sec,
		msecs);

	if (statinfo->pt == PT_CN) {
		g_snprintf(status,sizeof(status),"Comfort noise (PT=13, RFC 3389)");
		color = COLOR_CN;
	}
	else if (statinfo->pt == PT_CN_OLD) {
		g_snprintf(status,sizeof(status),"Comfort noise (PT=19, reserved)");
		color = COLOR_CN;
	}
	else if (statinfo->flags & STAT_FLAG_WRONG_SEQ) {
		g_snprintf(status,sizeof(status),"Wrong sequence nr.");
		color = COLOR_ERROR;
	}
	else if (statinfo->flags & STAT_FLAG_REG_PT_CHANGE) {
		g_snprintf(status,sizeof(status),"Payload changed to PT=%u", statinfo->pt);
		color = COLOR_WARNING;
	}
	else if (statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP) {
		g_snprintf(status,sizeof(status),"Incorrect timestamp");
		color = COLOR_WARNING;
	}
	else if ((statinfo->flags & STAT_FLAG_PT_CHANGE)
		&&  !(statinfo->flags & STAT_FLAG_FIRST)
		&&  !(statinfo->flags & STAT_FLAG_PT_CN)
		&&  (statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)
		&&  !(statinfo->flags & STAT_FLAG_MARKER)) {
		g_snprintf(status,sizeof(status),"Marker missing?");
		color = COLOR_WARNING;
	}
	else {
		if (statinfo->flags & STAT_FLAG_MARKER) {
			color = COLOR_WARNING;
		}
		g_snprintf(status,sizeof(status),OK_TEXT);
	}
	/*  is this the first packet we got in this direction? */
	if (statinfo->flags & STAT_FLAG_FIRST) {
		add_to_clist(clist,
			pinfo->fd->num, rtpinfo->info_seq_num,
			0,
			0,
			statinfo->bandwidth,
			status,
			rtpinfo->info_marker_set,
			timeStr, pinfo->fd->pkt_len,
			&color);
	}
	else {
		add_to_clist(clist,
			pinfo->fd->num, rtpinfo->info_seq_num,
			statinfo->delta*1000,
			statinfo->jitter*1000,
			statinfo->bandwidth,
			status,
			rtpinfo->info_marker_set,
			timeStr, pinfo->fd->pkt_len,
			&color);
	}
	return 0;
}


/****************************************************************************/
static int rtp_packet_save_payload(tap_rtp_save_info_t *saveinfo, 
                                   tap_rtp_stat_t *statinfo,
                                   packet_info *pinfo,
                                   const struct _rtp_info *rtpinfo)
{
	guint i;
	const guint8 *data;
	gint16 tmp;

	/*  is this the first packet we got in this direction? */
	if (statinfo->flags & STAT_FLAG_FIRST) {
		if (saveinfo->fp == NULL) {
			saveinfo->saved = FALSE;
			saveinfo->error_type = TAP_RTP_FILE_OPEN_ERROR;
		}
		else
			saveinfo->saved = TRUE;
	}

	/* save the voice information */
	/* if there was already an error, we quit */
	if (saveinfo->saved == FALSE)
		return 0;

	/* if the captured length and packet length aren't equal, we quit
	* because there is some information missing */
	if (pinfo->fd->pkt_len != pinfo->fd->cap_len) {
		saveinfo->saved = FALSE;
		saveinfo->error_type = TAP_RTP_WRONG_LENGTH;
		return 0;
	}

	/* if padding bit is set, but the padding count is bigger
	* then the whole RTP data - error with padding count */
	if ( (rtpinfo->info_padding_set != FALSE) &&
		(rtpinfo->info_padding_count > rtpinfo->info_payload_len) ) {
		saveinfo->saved = FALSE;
		saveinfo->error_type = TAP_RTP_PADDING_ERROR;
		return 0;
	}

	/* do we need to insert some silence? */
	if ((rtpinfo->info_marker_set) &&
		!(statinfo->flags & STAT_FLAG_FIRST) &&
		(statinfo->delta_timestamp > (rtpinfo->info_payload_len - rtpinfo->info_padding_count)) )  {
		/* the amount of silence should be the difference between
		* the last timestamp and the current one minus x
		* x should equal the amount of information in the last frame
		* XXX not done yet */
		for(i=0; i < (statinfo->delta_timestamp - rtpinfo->info_payload_len -
			rtpinfo->info_padding_count); i++) {
			tmp = (gint16 )ulaw2linear((unsigned char)(0x55));
			fwrite(&tmp, 2, 1, saveinfo->fp);
			saveinfo->count++;
		}
		fflush(saveinfo->fp);
	}

	
	if (rtpinfo->info_payload_type == PT_CN
		|| rtpinfo->info_payload_type == PT_CN_OLD) {
	}
	/*all other payloads*/
	else {
		if (!rtpinfo->info_all_data_present) {
			/* Not all the data was captured. */
			saveinfo->saved = FALSE;
			saveinfo->error_type = TAP_RTP_SHORT_FRAME;
			return 0;
		}

		/* we put the pointer at the beginning of the RTP
		* payload, that is, at the beginning of the RTP data
		* plus the offset of the payload from the beginning
		* of the RTP data */
		data = rtpinfo->info_data + rtpinfo->info_payload_offset;
		fwrite(data, sizeof(unsigned char), (rtpinfo->info_payload_len - rtpinfo->info_padding_count), saveinfo->fp);
		saveinfo->count+=(rtpinfo->info_payload_len - rtpinfo->info_padding_count);

		fflush(saveinfo->fp);
		saveinfo->saved = TRUE;
		return 0;
	}

	return 0;
}


/****************************************************************************/
/* CALLBACKS */

/****************************************************************************/
/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);


/****************************************************************************/
/* close the dialog window and remove the tap listener */
static void on_destroy(GtkWidget *win _U_, user_data_t *user_data _U_)
{
	/* remove tap listener */
	protect_thread_critical_region();
	remove_tap_listener(user_data);
	unprotect_thread_critical_region();

	/* close and remove temporary files */
	if (user_data->forward.saveinfo.fp != NULL)
		fclose(user_data->forward.saveinfo.fp);
	if (user_data->reversed.saveinfo.fp != NULL)
		fclose(user_data->reversed.saveinfo.fp);
	/*XXX: test for error **/
	remove(user_data->f_tempname);
	remove(user_data->r_tempname);

	/* destroy save_voice_as window if open */
	if (user_data->dlg.save_voice_as_w != NULL)
		window_destroy(user_data->dlg.save_voice_as_w);

	/* destroy graph window if open */
	if (user_data->dlg.dialog_graph.window != NULL)
		window_destroy(user_data->dlg.dialog_graph.window);

#ifdef USE_CONVERSATION_GRAPH
	/* destroy graph window if open */
	if (user_data->dlg.graph_window != NULL)
		window_destroy(user_data->dlg.graph_window);
#endif

	/* disable the "switch_page" signal in the dlg, otherwise will be called when the windows is destroy and cause an exeption using GTK1*/
	gtk_signal_disconnect(GTK_OBJECT(user_data->dlg.notebook), user_data->dlg.notebook_signal_id);

	g_free(user_data->dlg.col_arrows_fwd);
	g_free(user_data->dlg.col_arrows_rev);
	g_free(user_data);
}


/****************************************************************************/
static void on_notebook_switch_page(GtkNotebook *notebook _U_,
                                    GtkNotebookPage *page _U_,
                                    gint page_num _U_,
                                    user_data_t *user_data _U_)
{
	user_data->dlg.selected_clist =
		(page_num==0) ? user_data->dlg.clist_fwd : user_data->dlg.clist_rev ;
	user_data->dlg.selected_row = 0;
}

/****************************************************************************/
static void on_clist_select_row(GtkCList        *clist _U_,
                                gint             row _U_,
                                gint             column _U_,
                                GdkEvent        *event _U_,
                                user_data_t     *user_data _U_)
{
	user_data->dlg.selected_clist = clist;
	user_data->dlg.selected_row = row;
}


#ifdef USE_CONVERSATION_GRAPH
/****************************************************************************/
/* when the graph window gets destroyed */
static void on_destroy_graph(GtkWidget *win _U_, user_data_t *user_data _U_)
{
	/* note that graph window has been destroyed */
	user_data->dlg.graph_window = NULL;
}

/****************************************************************************/
static void graph_selection_callback(value_pair_t vp, user_data_t *user_data)
{
	guint row;
	GtkCList *clist = NULL;
	if (vp.fnumber != 0) {
		clist = GTK_CLIST(user_data->dlg.clist_fwd);
		row = gtk_clist_find_row_from_data(clist,
				GUINT_TO_POINTER(vp.fnumber));
		if (row==-1) {
			clist = GTK_CLIST(user_data->dlg.clist_rev);
			row = gtk_clist_find_row_from_data(clist,
					GUINT_TO_POINTER(vp.fnumber));
		}
		if (row!=-1) {
			gtk_notebook_set_page(GTK_NOTEBOOK(user_data->dlg.notebook),
				(clist == GTK_CLIST(user_data->dlg.clist_fwd)) ? 0 : 1);
			gtk_clist_select_row(clist, row, 0);
			gtk_clist_moveto(clist, row, 0, 0.5, 0);
		}
	}
}


/****************************************************************************/
static void on_graph_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	gchar title1[80];
	gchar title2[80];
	GList *list = NULL;
	
	if (user_data->dlg.graph_window != NULL) {
		/* There's already a graph window; reactivate it. */
		reactivate_window(user_data->dlg.graph_window);
		return;
	}
	list = g_list_append(list, &(user_data->series_fwd));
	list = g_list_append(list, &(user_data->series_rev));

	user_data->series_fwd.color.pixel = 0;
	user_data->series_fwd.color.red = 0x80ff;
	user_data->series_fwd.color.green = 0xe0ff;
	user_data->series_fwd.color.blue = 0xffff;
	user_data->series_fwd.yvalue = 0.5;

	user_data->series_rev.color.pixel = 0;
	user_data->series_rev.color.red = 0x60ff;
	user_data->series_rev.color.green = 0xc0ff;
	user_data->series_rev.color.blue = 0xffff;
	user_data->series_rev.yvalue = -0.5;

	g_snprintf(title1, 80, "Forward: %s:%u to %s:%u (SSRC=%u)",
		get_addr_name(&(user_data->ip_src_fwd)), 
		user_data->port_src_fwd,
		get_addr_name(&(user_data->ip_dst_fwd)),
		user_data->port_dst_fwd,
		user_data->ssrc_fwd);

	g_snprintf(title2, 80, "Reverse: %s:%u to %s:%u (SSRC=%u)",
		get_addr_name(&(user_data->ip_src_rev)),
		user_data->port_src_rev,
		get_addr_name(&(user_data->ip_dst_rev)),
		user_data->port_dst_rev,
		user_data->ssrc_rev);

	user_data->dlg.graph_window = show_conversation_graph(list, title1, title2,
		&graph_selection_callback, user_data);
	SIGNAL_CONNECT(user_data->dlg.graph_window, "destroy",
			on_destroy_graph, user_data);
}
#endif /*USE_CONVERSATION_GRAPH*/

/****************************************************************************/
static void dialog_graph_set_title(user_data_t* user_data)
{
	char            *title;
	if (!user_data->dlg.dialog_graph.window){
		return;
	}
	title = g_strdup_printf("RTP Graph Analysis Forward: %s:%u to %s:%u   Reverse: %s:%u to %s:%u",
			get_addr_name(&(user_data->ip_src_fwd)),
			user_data->port_src_fwd,
			get_addr_name(&(user_data->ip_dst_fwd)),
			user_data->port_dst_fwd,
			get_addr_name(&(user_data->ip_src_rev)),
			user_data->port_src_rev,
			get_addr_name(&(user_data->ip_dst_rev)),
			user_data->port_dst_rev);

	gtk_window_set_title(GTK_WINDOW(user_data->dlg.dialog_graph.window), title);
	g_free(title);	

}


/****************************************************************************/
static void dialog_graph_reset(user_data_t* user_data)
{
	int i, j;

	user_data->dlg.dialog_graph.needs_redraw=TRUE;
	for(i=0;i<MAX_GRAPHS;i++){
                for(j=0;j<NUM_GRAPH_ITEMS;j++){
                        dialog_graph_graph_item_t *dggi;
                        dggi=&user_data->dlg.dialog_graph.graph[i].items[j];
			dggi->value=0;
			dggi->flags=0;
                }
        }
	user_data->dlg.dialog_graph.last_interval=0xffffffff;
	user_data->dlg.dialog_graph.max_interval=0;
	user_data->dlg.dialog_graph.num_items=0;

	/* create the color titles near the filter buttons */
	for(i=0;i<MAX_GRAPHS;i++){
		/* it is forward */ 
		if (i<2){
       			g_snprintf(user_data->dlg.dialog_graph.graph[i].title, 100, "%s: %s:%u to %s:%u (SSRC=%u)",
			graph_descr[i],
                	get_addr_name(&(user_data->ip_src_fwd)),
                	user_data->port_src_fwd,
                	get_addr_name(&(user_data->ip_dst_fwd)),
                	user_data->port_dst_fwd,
                	user_data->ssrc_fwd);
		/* it is reverse */
		} else {
			g_snprintf(user_data->dlg.dialog_graph.graph[i].title, 100, "%s: %s:%u to %s:%u (SSRC=%u)",
			graph_descr[i],
                	get_addr_name(&(user_data->ip_src_rev)),
                	user_data->port_src_rev,
                	get_addr_name(&(user_data->ip_dst_rev)),
                	user_data->port_dst_rev,
                	user_data->ssrc_rev);
		}
	}

	dialog_graph_set_title(user_data);	
}

/****************************************************************************/
static guint32 get_it_value(dialog_graph_graph_t *dgg, int idx)
{
        dialog_graph_graph_item_t *it;

        it=&dgg->items[idx];

	return it->value;
}

/****************************************************************************/
static void print_time_scale_string(char *buf, int buf_len, guint32 t)
{
        if(t>=10000000){
                g_snprintf(buf, buf_len, "%ds",t/1000000);
        } else if(t>=1000000){
                g_snprintf(buf, buf_len, "%d.%03ds",t/1000000,(t%1000000)/1000);
        } else if(t>=10000){
                g_snprintf(buf, buf_len, "%dms",t/1000);
        } else if(t>=1000){
                g_snprintf(buf, buf_len, "%d.%03dms",t/1000,t%1000);
        } else {
                g_snprintf(buf, buf_len, "%dus",t);
        }
}

/****************************************************************************/
static void dialog_graph_draw(user_data_t* user_data)
{
        int i, lwidth;
        guint32 last_interval, first_interval, interval_delta, delta_multiplier;
        gint32 current_interval;
        guint32 left_x_border;
        guint32 right_x_border;
        guint32 top_y_border;
        guint32 bottom_y_border;
#if GTK_MAJOR_VERSION < 2
        GdkFont *font;
#else
        PangoLayout  *layout;
#endif
        guint32 label_width, label_height;
        guint32 draw_width, draw_height;
        char label_string[15];

        /* new variables */
        guint32 num_time_intervals;
        guint32 max_value;              /* max value of seen data */
        guint32 max_y;                  /* max value of the Y scale */

#if GTK_MAJOR_VERSION <2
        font = user_data->dlg.dialog_graph.draw_area->style->font;
#endif
        if(!user_data->dlg.dialog_graph.needs_redraw){
                return;
        }
        user_data->dlg.dialog_graph.needs_redraw=FALSE;

        /*
         * Find the length of the intervals we have data for
         * so we know how large arrays we need to malloc()
         */
        num_time_intervals=user_data->dlg.dialog_graph.num_items;
        /* if there isnt anything to do, just return */
        if(num_time_intervals==0){
                return;
        }
        num_time_intervals+=1;
        /* XXX move this check to _packet() */
        if(num_time_intervals>NUM_GRAPH_ITEMS){
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "RTP Graph error. There are too many entries, bailing out");
                return;
        }

        /*
         * find the max value so we can autoscale the y axis
         */
        max_value=0;
        for(i=0;i<MAX_GRAPHS;i++){
                int idx;

                if(!user_data->dlg.dialog_graph.graph[i].display){
                        continue;
                }
                for(idx=0;(guint32) (idx) < num_time_intervals;idx++){
                        guint32 val;

                        val=get_it_value(&user_data->dlg.dialog_graph.graph[i], idx);

                        /* keep track of the max value we have encountered */
                        if(val>max_value){
                                max_value=val;
                        }
                }
        }
	
        /*
         * Clear out old plot
         */
        gdk_draw_rectangle(user_data->dlg.dialog_graph.pixmap,
                           user_data->dlg.dialog_graph.draw_area->style->white_gc,
                           TRUE,
                           0, 0,
                           user_data->dlg.dialog_graph.draw_area->allocation.width,
                           user_data->dlg.dialog_graph.draw_area->allocation.height);


        /*
         * Calculate the y scale we should use
         */
        if(user_data->dlg.dialog_graph.max_y_units==AUTO_MAX_YSCALE){
                max_y=yscale_max[MAX_YSCALE-1];
                for(i=MAX_YSCALE-1;i>0;i--){
                        if(max_value<yscale_max[i]){
                                max_y=yscale_max[i];
                        }
                }
        } else {
                /* the user had specified an explicit y scale to use */
                max_y=user_data->dlg.dialog_graph.max_y_units;
        }

        /*
         * Calculate size of borders surrounding the plot
         * The border on the right side needs to be adjusted depending
         * on the width of the text labels. For simplicity we assume that the
         * top y scale label will be the widest one
         */
         print_time_scale_string(label_string, 15, max_y);
#if GTK_MAJOR_VERSION < 2
        label_width=gdk_string_width(font, label_string);
        label_height=gdk_string_height(font, label_string);
#else
        layout = gtk_widget_create_pango_layout(user_data->dlg.dialog_graph.draw_area, label_string);
        pango_layout_get_pixel_size(layout, &label_width, &label_height);
#endif
        left_x_border=10;
        right_x_border=label_width+20;
        top_y_border=10;
        bottom_y_border=label_height+20;


        /*
         * Calculate the size of the drawing area for the actual plot
         */
        draw_width=user_data->dlg.dialog_graph.pixmap_width-right_x_border-left_x_border;
        draw_height=user_data->dlg.dialog_graph.pixmap_height-top_y_border-bottom_y_border;


        /*
         * Draw the y axis and labels
         * (we always draw the y scale with 11 ticks along the axis)
         */
        gdk_draw_line(user_data->dlg.dialog_graph.pixmap, user_data->dlg.dialog_graph.draw_area->style->black_gc,
                user_data->dlg.dialog_graph.pixmap_width-right_x_border+1,
                top_y_border,
                user_data->dlg.dialog_graph.pixmap_width-right_x_border+1,
                user_data->dlg.dialog_graph.pixmap_height-bottom_y_border);
        for(i=0;i<=10;i++){
                int xwidth, lwidth;

                xwidth=5;
                if(!(i%5)){
                        /* first, middle and last tick are slightly longer */
                        xwidth=10;
                }
                /* draw the tick */
                gdk_draw_line(user_data->dlg.dialog_graph.pixmap, user_data->dlg.dialog_graph.draw_area->style->black_gc,
                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+1,
                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10,
                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+1+xwidth,
                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10);
                /* draw the labels */
                if(i==0){
                        print_time_scale_string(label_string, 15, (max_y*i/10));
#if GTK_MAJOR_VERSION < 2
                        lwidth=gdk_string_width(font, label_string);
                        gdk_draw_string(user_data->dlg.dialog_graph.pixmap,
                                        font,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+15+label_width-lwidth,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10+label_height/2,
                                        label_string);
#else
                        pango_layout_set_text(layout, label_string, -1);
                        pango_layout_get_pixel_size(layout, &lwidth, NULL);
                        gdk_draw_layout(user_data->dlg.dialog_graph.pixmap,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+15+label_width-lwidth,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10-label_height/2,
                                        layout);
#endif
                }
                if(i==5){
                        print_time_scale_string(label_string, 15, (max_y*i/10));
#if GTK_MAJOR_VERSION < 2
                        lwidth=gdk_string_width(font, label_string);
                        gdk_draw_string(user_data->dlg.dialog_graph.pixmap,
                                        font,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+15+label_width-lwidth,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10+label_height/2,
                                        label_string);
#else
                        pango_layout_set_text(layout, label_string, -1);
                        pango_layout_get_pixel_size(layout, &lwidth, NULL);
                        gdk_draw_layout(user_data->dlg.dialog_graph.pixmap,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+15+label_width-lwidth,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10-label_height/2,
                                        layout);
#endif
                }
                if(i==10){
                        print_time_scale_string(label_string, 15, (max_y*i/10));
#if GTK_MAJOR_VERSION < 2
                        lwidth=gdk_string_width(font, label_string);
                        gdk_draw_string(user_data->dlg.dialog_graph.pixmap,
                                        font,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+15+label_width-lwidth,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10+label_height/2,
                                        label_string);
#else
                        pango_layout_set_text(layout, label_string, -1);
                        pango_layout_get_pixel_size(layout, &lwidth, NULL);
                        gdk_draw_layout(user_data->dlg.dialog_graph.pixmap,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        user_data->dlg.dialog_graph.pixmap_width-right_x_border+15+label_width-lwidth,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border-draw_height*i/10-label_height/2,
                                        layout);
#endif
                }
        }



        /*
         * if we have not specified the last_interval via the gui,
         * then just pick the current end of the capture so that is scrolls
         * nicely when doing live captures
         */
        if(user_data->dlg.dialog_graph.last_interval==0xffffffff){
                last_interval=user_data->dlg.dialog_graph.max_interval;
        } else {
                last_interval=user_data->dlg.dialog_graph.last_interval;
        }




/*XXX*/
        /* plot the x-scale */
        gdk_draw_line(user_data->dlg.dialog_graph.pixmap, user_data->dlg.dialog_graph.draw_area->style->black_gc, left_x_border, user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+1, user_data->dlg.dialog_graph.pixmap_width-right_x_border+1, user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+1);

        if((last_interval/user_data->dlg.dialog_graph.interval)>draw_width/user_data->dlg.dialog_graph.pixels_per_tick+1){
                first_interval=(last_interval/user_data->dlg.dialog_graph.interval)-draw_width/user_data->dlg.dialog_graph.pixels_per_tick+1;
                first_interval*=user_data->dlg.dialog_graph.interval;
        } else {
                first_interval=0;
        }

        interval_delta=1;
        delta_multiplier=5;
        while(interval_delta<((last_interval-first_interval)/10)){
                interval_delta*=delta_multiplier;
                if(delta_multiplier==5){
                        delta_multiplier=2;
                } else {
                        delta_multiplier=5;
                }
        }

        for(current_interval=last_interval;current_interval>(gint32)first_interval;current_interval=current_interval-user_data->dlg.dialog_graph.interval){
                int x, xlen;

                /* if pixels_per_tick is <5, only draw every 10 ticks */
                if((user_data->dlg.dialog_graph.pixels_per_tick<10) && (current_interval%(10*user_data->dlg.dialog_graph.interval))){
                        continue;
                }

                if(current_interval%interval_delta){
                        xlen=5;
                } else {
                        xlen=17;
                }

                x=draw_width+left_x_border-((last_interval-current_interval)/user_data->dlg.dialog_graph.interval)*user_data->dlg.dialog_graph.pixels_per_tick;
                gdk_draw_line(user_data->dlg.dialog_graph.pixmap, user_data->dlg.dialog_graph.draw_area->style->black_gc,
                        x-1-user_data->dlg.dialog_graph.pixels_per_tick/2,
                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+1,
                        x-1-user_data->dlg.dialog_graph.pixels_per_tick/2,
                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+xlen+1);

                if(xlen==17){
                        int lwidth;
                        if(user_data->dlg.dialog_graph.interval>=1000){
                                g_snprintf(label_string, 15, "%ds", current_interval/1000);
                        } else if(user_data->dlg.dialog_graph.interval>=100){
                                g_snprintf(label_string, 15, "%d.%1ds", current_interval/1000,(current_interval/100)%10)
;
                        } else if(user_data->dlg.dialog_graph.interval>=10){
                                g_snprintf(label_string, 15, "%d.%2ds", current_interval/1000,(current_interval/10)%100)
;
                        } else {
                                g_snprintf(label_string, 15, "%d.%3ds", current_interval/1000,current_interval%1000);
                        }
#if GTK_MAJOR_VERSION < 2
                        lwidth=gdk_string_width(font, label_string);
                        gdk_draw_string(user_data->dlg.dialog_graph.pixmap,
                                        font,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        x-1-user_data->dlg.dialog_graph.pixels_per_tick/2-lwidth/2,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+20+label_height,
                                        label_string);
#else
                        pango_layout_set_text(layout, label_string, -1);
                        pango_layout_get_pixel_size(layout, &lwidth, NULL);
                        gdk_draw_layout(user_data->dlg.dialog_graph.pixmap,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        x-1-user_data->dlg.dialog_graph.pixels_per_tick/2-lwidth/2,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+20,
                                        layout);
#endif
                }

        }






        /*
         * Draw "x" for Sequence Errors and "m" for Marks
         */
	/* Draw the labels Fwd and Rev */
	strcpy(label_string,"<-Fwd");
#if GTK_MAJOR_VERSION < 2
	lwidth=gdk_string_width(font, label_string);
	gdk_draw_string(user_data->dlg.dialog_graph.pixmap,
		font,
		user_data->dlg.dialog_graph.draw_area->style->black_gc,
		user_data->dlg.dialog_graph.pixmap_width-right_x_border+33-lwidth,
		user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+3+label_height,
		label_string);
#else
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &lwidth, NULL);
	gdk_draw_layout(user_data->dlg.dialog_graph.pixmap,
		user_data->dlg.dialog_graph.draw_area->style->black_gc,
		user_data->dlg.dialog_graph.pixmap_width-right_x_border+33-lwidth,
		user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+3,
		layout);
#endif
        strcpy(label_string,"<-Rev");
#if GTK_MAJOR_VERSION < 2
        lwidth=gdk_string_width(font, label_string);
        gdk_draw_string(user_data->dlg.dialog_graph.pixmap,
                font,
                user_data->dlg.dialog_graph.draw_area->style->black_gc,
                user_data->dlg.dialog_graph.pixmap_width-right_x_border+33-lwidth,
                user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+3+9+label_height,
                label_string);
#else
        pango_layout_set_text(layout, label_string, -1);
        pango_layout_get_pixel_size(layout, &lwidth, NULL);
        gdk_draw_layout(user_data->dlg.dialog_graph.pixmap,
                user_data->dlg.dialog_graph.draw_area->style->black_gc,
                user_data->dlg.dialog_graph.pixmap_width-right_x_border+33-lwidth,
                user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+3+9,
                layout);
#endif

	/* Draw the marks */	
	for(i=MAX_GRAPHS-1;i>=0;i--){
		guint32 interval;
		guint32 x_pos, prev_x_pos;

		/* XXX for fwd or rev, the flag info for jitter and diff is the same, and here I loop twice */
		if (!user_data->dlg.dialog_graph.graph[i].display){
			continue;
		}
		/* initialize prev x/y to the low left corner of the graph */
		prev_x_pos=draw_width-1-user_data->dlg.dialog_graph.pixels_per_tick*((last_interval-first_interval)/user_data->dlg.dialog_graph.interval+1)+left_x_border;

		for(interval=first_interval+user_data->dlg.dialog_graph.interval;interval<=last_interval;interval+=user_data->dlg.dialog_graph.interval){
			x_pos=draw_width-1-user_data->dlg.dialog_graph.pixels_per_tick*((last_interval-interval)/user_data->dlg.dialog_graph.interval+1)+left_x_border;

			if(user_data->dlg.dialog_graph.graph[i].items[interval/user_data->dlg.dialog_graph.interval].flags & (STAT_FLAG_WRONG_SEQ|STAT_FLAG_MARKER)){
				int lwidth;
				if (user_data->dlg.dialog_graph.graph[i].items[interval/user_data->dlg.dialog_graph.interval].flags & STAT_FLAG_WRONG_SEQ){
					strcpy(label_string,"x");
				} else {
				        strcpy(label_string,"m");
				}
					
#if GTK_MAJOR_VERSION < 2
                                lwidth=gdk_string_width(font, label_string);
                                gdk_draw_string(user_data->dlg.dialog_graph.pixmap,
                                        font,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        x_pos-1-lwidth/2,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+3+7*(i/2)+label_height,
                                        label_string);
#else				
                           	pango_layout_set_text(layout, label_string, -1);
                                pango_layout_get_pixel_size(layout, &lwidth, NULL);
                                gdk_draw_layout(user_data->dlg.dialog_graph.pixmap,
                                        user_data->dlg.dialog_graph.draw_area->style->black_gc,
                                        x_pos-1-lwidth/2,
                                        user_data->dlg.dialog_graph.pixmap_height-bottom_y_border+3+7*(i/2),
                                        layout);
#endif
                        }

                        prev_x_pos=x_pos;
                }
        }

#if GTK_MAJOR_VERSION >= 2
        g_object_unref(G_OBJECT(layout));
#endif


        /*
         * Loop over all graphs and draw them
         */
	for(i=MAX_GRAPHS-1;i>=0;i--){
		guint32 interval;
		guint32 x_pos, y_pos, prev_x_pos, prev_y_pos;
	        if (!user_data->dlg.dialog_graph.graph[i].display){
                        continue;
                }	
		/* initialize prev x/y to the low left corner of the graph */
		prev_x_pos=draw_width-1-user_data->dlg.dialog_graph.pixels_per_tick*((last_interval-first_interval)/user_data->dlg.dialog_graph.interval+1)+left_x_border;
		prev_y_pos=draw_height-1+top_y_border;
		
		for(interval=first_interval+user_data->dlg.dialog_graph.interval;interval<=last_interval;interval+=user_data->dlg.dialog_graph.interval){
			guint32 val;
			x_pos=draw_width-1-user_data->dlg.dialog_graph.pixels_per_tick*((last_interval-interval)/user_data->dlg.dialog_graph.interval+1)+left_x_border;
			val=get_it_value(&user_data->dlg.dialog_graph.graph[i], interval/user_data->dlg.dialog_graph.interval);
			if(val>max_y){
                                y_pos=0;
                        } else {
                                y_pos=draw_height-1-(val*draw_height)/max_y+top_y_border;
                        }

                        /* dont need to draw anything if the segment
                         * is entirely above the top of the graph
                         */
                        if( (prev_y_pos==0) && (y_pos==0) ){
                                prev_y_pos=y_pos;
                                prev_x_pos=x_pos;
                                continue;
                        }
		
                        if(val){
	                        gdk_draw_line(user_data->dlg.dialog_graph.pixmap, user_data->dlg.dialog_graph.graph[i].gc,
                                x_pos, draw_height-1+top_y_border,
                                x_pos, y_pos);
        		}

                        prev_y_pos=y_pos;
                        prev_x_pos=x_pos;
                }
        }


        gdk_draw_pixmap(user_data->dlg.dialog_graph.draw_area->window,
                        user_data->dlg.dialog_graph.draw_area->style->fg_gc[GTK_WIDGET_STATE(user_data->dlg.dialog_graph.draw_area)],
                        user_data->dlg.dialog_graph.pixmap,
                        0, 0,
                        0, 0,
                        user_data->dlg.dialog_graph.pixmap_width, user_data->dlg.dialog_graph.pixmap_height);


        /* update the scrollbar */
        user_data->dlg.dialog_graph.scrollbar_adjustment->upper=(gfloat) user_data->dlg.dialog_graph.max_interval;
        user_data->dlg.dialog_graph.scrollbar_adjustment->step_increment=(gfloat) ((last_interval-first_interval)/10);
        user_data->dlg.dialog_graph.scrollbar_adjustment->page_increment=(gfloat) (last_interval-first_interval);
        if((last_interval-first_interval)*100 < user_data->dlg.dialog_graph.max_interval){
                user_data->dlg.dialog_graph.scrollbar_adjustment->page_size=(gfloat) (user_data->dlg.dialog_graph.max_interval/100);
        } else {
                user_data->dlg.dialog_graph.scrollbar_adjustment->page_size=(gfloat) (last_interval-first_interval);
        }
        user_data->dlg.dialog_graph.scrollbar_adjustment->value=last_interval-user_data->dlg.dialog_graph.scrollbar_adjustment->page_size;
        gtk_adjustment_changed(user_data->dlg.dialog_graph.scrollbar_adjustment);
        gtk_adjustment_value_changed(user_data->dlg.dialog_graph.scrollbar_adjustment);

}

/****************************************************************************/
static void dialog_graph_redraw(user_data_t* user_data)
{
        user_data->dlg.dialog_graph.needs_redraw=TRUE;
        dialog_graph_draw(user_data); 
}

/****************************************************************************/
static gint quit(GtkWidget *widget, GdkEventExpose *event _U_)
{
        user_data_t *user_data;

        user_data=(user_data_t *)OBJECT_GET_DATA(widget, "user_data_t");

	user_data->dlg.dialog_graph.window = NULL;
        return TRUE;
}

/****************************************************************************/
static gint expose_event(GtkWidget *widget, GdkEventExpose *event)
{
	user_data_t *user_data;

	user_data=(user_data_t *)OBJECT_GET_DATA(widget, "user_data_t");
        if(!user_data){
                exit(10);
        }


        gdk_draw_pixmap(widget->window,
                        widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
                        user_data->dlg.dialog_graph.pixmap,
                        event->area.x, event->area.y,
                        event->area.x, event->area.y,
                        event->area.width, event->area.height);

        return FALSE;
}

/****************************************************************************/
static gint configure_event(GtkWidget *widget, GdkEventConfigure *event _U_)
{
        user_data_t *user_data;
	int i;

        user_data=(user_data_t *)OBJECT_GET_DATA(widget, "user_data_t");

        if(!user_data){
                exit(10);
        }

        if(user_data->dlg.dialog_graph.pixmap){
                gdk_pixmap_unref(user_data->dlg.dialog_graph.pixmap);
                user_data->dlg.dialog_graph.pixmap=NULL;
        }

        user_data->dlg.dialog_graph.pixmap=gdk_pixmap_new(widget->window,
                        widget->allocation.width,
                        widget->allocation.height,
                        -1);
        user_data->dlg.dialog_graph.pixmap_width=widget->allocation.width;
        user_data->dlg.dialog_graph.pixmap_height=widget->allocation.height;

        gdk_draw_rectangle(user_data->dlg.dialog_graph.pixmap,
                        widget->style->white_gc,
                        TRUE,
                        0, 0,
                        widget->allocation.width,
                        widget->allocation.height);

        /* set up the colors and the GC structs for this pixmap */
	for(i=0;i<MAX_GRAPHS;i++){
		user_data->dlg.dialog_graph.graph[i].gc=gdk_gc_new(user_data->dlg.dialog_graph.pixmap);
#if GTK_MAJOR_VERSION < 2
                colormap = gtk_widget_get_colormap (widget);
                if (!gdk_color_alloc (colormap, &user_data->dlg.dialog_graph.graph[i].color)){
                        g_warning ("Couldn't allocate color");
                }

                gdk_gc_set_foreground(user_data->dlg.dialog_graph.graph[i].gc, &user_data->dlg.dialog_graph.graph[i].color);
#else
                gdk_gc_set_rgb_fg_color(user_data->dlg.dialog_graph.graph[i].gc, &user_data->dlg.dialog_graph.graph[i].color);
#endif
	}

	dialog_graph_redraw(user_data);
        return TRUE;
}

/****************************************************************************/
static gint scrollbar_changed(GtkWidget *widget _U_, gpointer data)
{
        user_data_t *user_data=(user_data_t *)data;
        guint32 mi;

        mi=(guint32) (user_data->dlg.dialog_graph.scrollbar_adjustment->value+user_data->dlg.dialog_graph.scrollbar_adjustment->page_size);
        if(user_data->dlg.dialog_graph.last_interval==mi){
                return TRUE;
        }
        if( (user_data->dlg.dialog_graph.last_interval==0xffffffff)
        &&  (mi==user_data->dlg.dialog_graph.max_interval) ){
                return TRUE;
        }

        user_data->dlg.dialog_graph.last_interval=(mi/user_data->dlg.dialog_graph.interval)*user_data->dlg.dialog_graph.interval;

	dialog_graph_redraw(user_data);
        return TRUE;
}

/****************************************************************************/
static void create_draw_area(user_data_t* user_data, GtkWidget *box)
{
        user_data->dlg.dialog_graph.draw_area=gtk_drawing_area_new();
        SIGNAL_CONNECT(user_data->dlg.dialog_graph.draw_area, "destroy", quit, user_data);
        OBJECT_SET_DATA(user_data->dlg.dialog_graph.draw_area, "user_data_t", user_data);

        WIDGET_SET_SIZE(user_data->dlg.dialog_graph.draw_area, user_data->dlg.dialog_graph.pixmap_width, user_data->dlg.dialog_graph.pixmap_height);

        /* signals needed to handle backing pixmap */
        SIGNAL_CONNECT(user_data->dlg.dialog_graph.draw_area, "expose_event", expose_event, NULL);
        SIGNAL_CONNECT(user_data->dlg.dialog_graph.draw_area, "configure_event", configure_event, user_data);

        gtk_widget_show(user_data->dlg.dialog_graph.draw_area);
        gtk_box_pack_start(GTK_BOX(box), user_data->dlg.dialog_graph.draw_area, TRUE, TRUE, 0);

        /* create the associated scrollbar */
        user_data->dlg.dialog_graph.scrollbar_adjustment=(GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
        user_data->dlg.dialog_graph.scrollbar=gtk_hscrollbar_new(user_data->dlg.dialog_graph.scrollbar_adjustment);
        gtk_widget_show(user_data->dlg.dialog_graph.scrollbar);
        gtk_box_pack_start(GTK_BOX(box), user_data->dlg.dialog_graph.scrollbar, FALSE, FALSE, 0);
        SIGNAL_CONNECT(user_data->dlg.dialog_graph.scrollbar_adjustment, "value_changed", scrollbar_changed, user_data);
}

/****************************************************************************/
static void disable_graph(dialog_graph_graph_t *dgg)
{
        if (dgg->display) {
                dgg->display=FALSE;
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(dgg->display_button),
                    FALSE);
        }
}

/****************************************************************************/
static gint filter_callback(GtkWidget *widget _U_, dialog_graph_graph_t *dgg)
{
        /* this graph is not active, just update display and redraw */
        if(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(dgg->display_button))){
                disable_graph(dgg); 
                dialog_graph_redraw(dgg->ud);
		return 0;
        }

	enable_graph(dgg);
        cf_retap_packets(&cfile, FALSE);
        dialog_graph_redraw(dgg->ud);

        return 0;
}

/****************************************************************************/
static void create_filter_box(dialog_graph_graph_t *dgg, GtkWidget *box, int num)
{
        GtkWidget *hbox;
        GtkWidget *label;
        char str[256];

        hbox=gtk_hbox_new(FALSE, 3);
        gtk_container_add(GTK_CONTAINER(box), hbox);
        gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
        gtk_widget_show(hbox);

	g_snprintf(str, 256, "Graph %d", num);
	dgg->display_button=gtk_toggle_button_new_with_label(str);
        gtk_box_pack_start(GTK_BOX(hbox), dgg->display_button, FALSE, FALSE, 0);
        gtk_widget_show(dgg->display_button);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(dgg->display_button), dgg->display);
        SIGNAL_CONNECT(dgg->display_button, "toggled", filter_callback, dgg);

	label=gtk_label_new(dgg->title);
        gtk_widget_show(label);
        gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

#if GTK_MAJOR_VERSION < 2
    /* setting the color of the display button doesn't work */
        rc_style = gtk_rc_style_new ();
        rc_style->fg[GTK_STATE_NORMAL] = dgg->color;
        rc_style->color_flags[GTK_STATE_NORMAL] |= GTK_RC_FG;
        rc_style->fg[GTK_STATE_ACTIVE] = dgg->color;
        rc_style->color_flags[GTK_STATE_ACTIVE] |= GTK_RC_FG;
        rc_style->fg[GTK_STATE_PRELIGHT] = dgg->color;
        rc_style->color_flags[GTK_STATE_PRELIGHT] |= GTK_RC_FG;
        rc_style->fg[GTK_STATE_SELECTED] = dgg->color;
        rc_style->color_flags[GTK_STATE_SELECTED] |= GTK_RC_FG;
        rc_style->fg[GTK_STATE_INSENSITIVE] = dgg->color;
        rc_style->color_flags[GTK_STATE_INSENSITIVE] |= GTK_RC_FG;
        gtk_widget_modify_style (label, rc_style);
        gtk_rc_style_unref (rc_style);
#else
        gtk_widget_modify_fg(label, GTK_STATE_NORMAL, &dgg->color);
        gtk_widget_modify_fg(label, GTK_STATE_ACTIVE, &dgg->color);
        gtk_widget_modify_fg(label, GTK_STATE_PRELIGHT, &dgg->color);
        gtk_widget_modify_fg(label, GTK_STATE_SELECTED, &dgg->color);
        gtk_widget_modify_fg(label, GTK_STATE_INSENSITIVE, &dgg->color);
#endif

        return;
}

/****************************************************************************/
static void create_filter_area(user_data_t* user_data, GtkWidget *box)
{
        GtkWidget *frame;
        GtkWidget *vbox;
	int i;
	GtkWidget *label;

    	frame=gtk_frame_new("Graphs");
        gtk_container_add(GTK_CONTAINER(box), frame);
        gtk_widget_show(frame);

        vbox=gtk_vbox_new(FALSE, 1);
        gtk_container_add(GTK_CONTAINER(frame), vbox);
    	gtk_container_border_width(GTK_CONTAINER(vbox), 3);
        gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_START);
        gtk_widget_show(vbox);

	for(i=0;i<MAX_GRAPHS;i++){
		create_filter_box(&user_data->dlg.dialog_graph.graph[i], vbox, i+1);
	}

	label=gtk_label_new("Label:    x = Wrong Seq. number      m = Mark set");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

        return;
}

/****************************************************************************/
static void yscale_select(GtkWidget *item, gpointer key)
{
        int val;
	user_data_t *user_data;
        
        user_data=(user_data_t *)key;
        val=(int)OBJECT_GET_DATA(item, "yscale_max");

        user_data->dlg.dialog_graph.max_y_units=val;
        dialog_graph_redraw(user_data);
}

/****************************************************************************/
static void pixels_per_tick_select(GtkWidget *item, gpointer key)
{
        int val;
        user_data_t *user_data;

        user_data=(user_data_t *)key;
        val=(int)OBJECT_GET_DATA(item, "pixels_per_tick");
        user_data->dlg.dialog_graph.pixels_per_tick=val;
        dialog_graph_redraw(user_data);
}

/****************************************************************************/
static void tick_interval_select(GtkWidget *item, gpointer key)
{
        int val;
        user_data_t *user_data;

        user_data=(user_data_t *)key;
        val=(int)OBJECT_GET_DATA(item, "tick_interval");

        user_data->dlg.dialog_graph.interval=val;
        cf_retap_packets(&cfile, FALSE);
        dialog_graph_redraw(user_data);
}

/****************************************************************************/
static void create_yscale_max_menu_items(user_data_t* user_data, GtkWidget *menu)
{
        char str[15];
        GtkWidget *menu_item;
        int i;

        for(i=0;i<MAX_YSCALE;i++){
                if(yscale_max[i]==AUTO_MAX_YSCALE){
                        strcpy(str,"Auto");
                } else {
                        g_snprintf(str, 15, "%u ms", yscale_max[i]/1000);
                }
                menu_item=gtk_menu_item_new_with_label(str);
                OBJECT_SET_DATA(menu_item, "yscale_max",
                                GUINT_TO_POINTER(yscale_max[i]));
                SIGNAL_CONNECT(menu_item, "activate", yscale_select, user_data);
                gtk_widget_show(menu_item);
                gtk_menu_append(GTK_MENU(menu), menu_item);
        }
        return;
}

/****************************************************************************/
static void create_pixels_per_tick_menu_items(user_data_t* user_data, GtkWidget *menu)
{
        char str[5];
        GtkWidget *menu_item;
        int i;

        for(i=0;i<MAX_PIXELS_PER_TICK;i++){
                g_snprintf(str, 5, "%u", pixels_per_tick[i]);
                menu_item=gtk_menu_item_new_with_label(str);

                OBJECT_SET_DATA(menu_item, "pixels_per_tick",
                                GUINT_TO_POINTER(pixels_per_tick[i]));
                SIGNAL_CONNECT(menu_item, "activate", pixels_per_tick_select, user_data);
                gtk_widget_show(menu_item);
                gtk_menu_append(GTK_MENU(menu), menu_item);
        }
        gtk_menu_set_active(GTK_MENU(menu), DEFAULT_PIXELS_PER_TICK);
        return;
}


/****************************************************************************/
static void create_tick_interval_menu_items(user_data_t* user_data, GtkWidget *menu)
{
        char str[15];
        GtkWidget *menu_item;
        int i;

        for(i=0;i<MAX_TICK_VALUES;i++){
                if(tick_interval_values[i]>=1000){
                        g_snprintf(str, 15, "%u sec", tick_interval_values[i]/1000);
                } else if(tick_interval_values[i]>=100){
                        g_snprintf(str, 15, "0.%1u sec", (tick_interval_values[i]/100)%10);
                } else if(tick_interval_values[i]>=10){
                        g_snprintf(str, 15, "0.%02u sec", (tick_interval_values[i]/10)%10);
                } else {
                        g_snprintf(str, 15, "0.%03u sec", (tick_interval_values[i])%10);
                }

                menu_item=gtk_menu_item_new_with_label(str);
                OBJECT_SET_DATA(menu_item, "tick_interval",
                                GUINT_TO_POINTER(tick_interval_values[i]));
                SIGNAL_CONNECT(menu_item, "activate", tick_interval_select, (gpointer)user_data);
                gtk_widget_show(menu_item);
                gtk_menu_append(GTK_MENU(menu), menu_item);
        }
        gtk_menu_set_active(GTK_MENU(menu), DEFAULT_TICK_VALUE);
        return;
}

/****************************************************************************/
static void create_ctrl_menu(user_data_t* user_data, GtkWidget *box, const char *name, void (*func)(user_data_t* user_data, GtkWidget *menu))
{
        GtkWidget *hbox;
        GtkWidget *label;
        GtkWidget *option_menu;
        GtkWidget *menu;

        hbox=gtk_hbox_new(FALSE, 0);
        gtk_container_add(GTK_CONTAINER(box), hbox);
        gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
        gtk_widget_show(hbox);

        label=gtk_label_new(name);
        gtk_widget_show(label);
        gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

        option_menu=gtk_option_menu_new();
        menu=gtk_menu_new();
        (*func)(user_data, menu);
        gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);
        gtk_box_pack_end(GTK_BOX(hbox), option_menu, FALSE, FALSE, 0);
        gtk_widget_show(option_menu);
}

/****************************************************************************/
static void create_ctrl_area(user_data_t* user_data, GtkWidget *box)
{
	GtkWidget *frame_vbox;
    	GtkWidget *frame;
        GtkWidget *vbox;

        frame_vbox=gtk_vbox_new(FALSE, 0);
        gtk_container_add(GTK_CONTAINER(box), frame_vbox);
        gtk_widget_show(frame_vbox);

	frame = gtk_frame_new("X Axis");
        gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
        gtk_widget_show(frame);

        vbox=gtk_vbox_new(FALSE, 0);
        gtk_container_add(GTK_CONTAINER(frame), vbox);
	gtk_container_border_width(GTK_CONTAINER(vbox), 3);
        gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_END);
        gtk_widget_show(vbox);

        create_ctrl_menu(user_data, vbox, "Tick interval:", create_tick_interval_menu_items);
        create_ctrl_menu(user_data, vbox, "Pixels per tick:", create_pixels_per_tick_menu_items);

    	frame = gtk_frame_new("Y Axis");
        gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
        gtk_widget_show(frame);

        vbox=gtk_vbox_new(FALSE, 0);
        gtk_container_add(GTK_CONTAINER(frame), vbox);
    	gtk_container_border_width(GTK_CONTAINER(vbox), 3);
        gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_END);
        gtk_widget_show(vbox);

        create_ctrl_menu(user_data, vbox, "Scale:", create_yscale_max_menu_items);

        return;
}

/****************************************************************************/
static void dialog_graph_init_window(user_data_t* user_data)
{
        GtkWidget *vbox;
        GtkWidget *hbox;
    	GtkWidget *bt_close;

        /* create the main window */
        user_data->dlg.dialog_graph.window=window_new(GTK_WINDOW_TOPLEVEL, "I/O Graphs");

        vbox=gtk_vbox_new(FALSE, 0);
        gtk_container_add(GTK_CONTAINER(user_data->dlg.dialog_graph.window), vbox);
        gtk_widget_show(vbox);

        create_draw_area(user_data, vbox);

        hbox=gtk_hbox_new(FALSE, 3);
        gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
    	gtk_container_border_width(GTK_CONTAINER(hbox), 3);
        gtk_box_set_child_packing(GTK_BOX(vbox), hbox, FALSE, FALSE, 0, GTK_PACK_START);
        gtk_widget_show(hbox);

        create_filter_area(user_data, hbox);
        create_ctrl_area(user_data, hbox);

        dialog_graph_set_title(user_data);

    hbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
        gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
    gtk_widget_show(hbox);

    bt_close = OBJECT_GET_DATA(hbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(user_data->dlg.dialog_graph.window, bt_close, window_cancel_button_cb);

    SIGNAL_CONNECT(user_data->dlg.dialog_graph.window, "delete_event", window_delete_event_cb, NULL);

    gtk_widget_show(user_data->dlg.dialog_graph.window);
    window_present(user_data->dlg.dialog_graph.window);

}


/****************************************************************************/
static void on_graph_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
        if (user_data->dlg.dialog_graph.window != NULL) {
                /* There's already a graph window; reactivate it. */
                reactivate_window(user_data->dlg.dialog_graph.window);
                return;
        }

	dialog_graph_init_window(user_data);	

}

/****************************************************************************/
static void on_goto_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	guint fnumber;

	if (user_data->dlg.selected_clist!=NULL) {
		fnumber = GPOINTER_TO_UINT(gtk_clist_get_row_data(
			GTK_CLIST(user_data->dlg.selected_clist), user_data->dlg.selected_row) );
		cf_goto_frame(&cfile, fnumber);
	}
}


static void draw_stat(user_data_t *user_data);

/****************************************************************************/
/* re-dissects all packets */
static void on_refresh_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	GString *error_string;
	
	/* remove tap listener */
	protect_thread_critical_region();
	remove_tap_listener(user_data);
	unprotect_thread_critical_region();

	/* register tap listener */
	error_string = register_tap_listener("rtp", user_data, NULL,
		rtp_reset, rtp_packet, rtp_draw);
	if (error_string != NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
			g_string_free(error_string, TRUE);
		return;
	}

	/* retap all packets */
	cf_retap_packets(&cfile, FALSE);

	/* draw statistics info */
	draw_stat(user_data);

	gtk_clist_sort(user_data->dlg.clist_fwd);
	gtk_clist_sort(user_data->dlg.clist_rev);
}

/****************************************************************************/
static void on_next_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	GtkCList *clist;
	gchar *text;
	gint row;
	if (user_data->dlg.selected_clist==NULL)
		return;

	clist = user_data->dlg.selected_clist;
	row = user_data->dlg.selected_row + 1;

	while (gtk_clist_get_text(clist,row,6,&text)) {
		if (strcmp(text, OK_TEXT) != 0) {
			gtk_clist_select_row(clist, row, 0);
			gtk_clist_moveto(clist, row, 0, 0.5, 0);
			return;
		}
		++row;
	}

	/* wrap around */
	row = 0;
	while (gtk_clist_get_text(clist,row,6,&text) && row<user_data->dlg.selected_row) {
		if (strcmp(text, OK_TEXT) != 0) {
			gtk_clist_select_row(clist, row, 0);
			gtk_clist_moveto(clist, row, 0, 0.5, 0);
			return;
		}
		++row;
	}
}

/****************************************************************************/
/* when we want to save the information */
static void save_csv_as_ok_cb(GtkWidget *bt _U_, gpointer fs /*user_data_t *user_data*/ _U_)
{
	gchar *g_dest;
	GtkWidget *rev, *forw, *both;
	user_data_t *user_data;
	
	FILE *fp;
	char *columnText;
	int i,j;
	
	g_dest = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
	
	/* Perhaps the user specified a directory instead of a file.
	Check whether they did. */
	if (test_for_directory(g_dest) == EISDIR) {
		/* It's a directory - set the file selection box to display it. */
		set_last_open_dir(g_dest);
		g_free(g_dest);
		file_selection_set_current_folder(fs, get_last_open_dir());
		return;
	}
	
	rev = (GtkWidget*)OBJECT_GET_DATA(bt, "reversed_rb");
	forw = (GtkWidget*)OBJECT_GET_DATA(bt, "forward_rb");
	both = (GtkWidget*)OBJECT_GET_DATA(bt, "both_rb");
	user_data = (user_data_t*)OBJECT_GET_DATA(bt, "user_data");
	
	if (GTK_TOGGLE_BUTTON(forw)->active || GTK_TOGGLE_BUTTON(both)->active) {
		fp = fopen(g_dest, "w");
		if (fp == NULL) {
			open_failure_alert_box(g_dest, errno, TRUE);
			return;
		}
		
		if (GTK_TOGGLE_BUTTON(both)->active) {
			fprintf(fp, "Forward\n");
			if (ferror(fp)) {
				write_failure_alert_box(g_dest, errno);
				fclose(fp);
				return;
			}
		}
		
		for(j = 0; j < NUM_COLS; j++) {
			if (j == 0) {
				fprintf(fp,"%s",titles[j]);
			} else {
				fprintf(fp,",%s",titles[j]);
			}
		}
		fprintf(fp,"\n");
		if (ferror(fp)) {
			write_failure_alert_box(g_dest, errno);
			fclose(fp);
			return;
		}
		for (i = 0; i < GTK_CLIST(user_data->dlg.clist_fwd)->rows; i++) {
			for(j = 0; j < GTK_CLIST(user_data->dlg.clist_fwd)->columns; j++) {
				gtk_clist_get_text(GTK_CLIST(user_data->dlg.clist_fwd),i,j,&columnText);
				if (j == 0) {
					fprintf(fp,"%s",columnText);
				} else {
					fprintf(fp,",%s",columnText);
				}
			}
			fprintf(fp,"\n");
			if (ferror(fp)) {
				write_failure_alert_box(g_dest, errno);
				fclose(fp);
				return;
			}
		}
		
		if (fclose(fp) == EOF) {
			write_failure_alert_box(g_dest, errno);
			return;
		}
	}
	
	if (GTK_TOGGLE_BUTTON(rev)->active || GTK_TOGGLE_BUTTON(both)->active) {
		
		if (GTK_TOGGLE_BUTTON(both)->active) {
			fp = fopen(g_dest, "a");
			if (fp == NULL) {
				open_failure_alert_box(g_dest, errno, TRUE);
				return;
			}
			fprintf(fp, "\nReverse\n");
			if (ferror(fp)) {
				write_failure_alert_box(g_dest, errno);
				fclose(fp);
				return;
			}
		} else {
			fp = fopen(g_dest, "w");
			if (fp == NULL) {
				open_failure_alert_box(g_dest, errno, TRUE);
				return;
			}
		}
		for(j = 0; j < NUM_COLS; j++) {
			if (j == 0) {
				fprintf(fp,"%s",titles[j]);
			} else {
				fprintf(fp,",%s",titles[j]);
			}
		}
		fprintf(fp,"\n");
		if (ferror(fp)) {
			write_failure_alert_box(g_dest, errno);
			fclose(fp);
			return;
		}
		for (i = 0; i < GTK_CLIST(user_data->dlg.clist_rev)->rows; i++) {
			for(j = 0; j < GTK_CLIST(user_data->dlg.clist_rev)->columns; j++) {
				gtk_clist_get_text(GTK_CLIST(user_data->dlg.clist_rev),i,j,&columnText);
				if (j == 0) {
					fprintf(fp,"%s",columnText);
				} else {
					fprintf(fp,",%s",columnText);
				}
			}
			fprintf(fp,"\n");
			if (ferror(fp)) {
				write_failure_alert_box(g_dest, errno);
				fclose(fp);
				return;
			}
		}
		if (fclose(fp) == EOF) {
			write_failure_alert_box(g_dest, errno);
			return;
		}
	}

	window_destroy(GTK_WIDGET(user_data->dlg.save_csv_as_w));
}

static void save_csv_as_destroy_cb(GtkWidget *win _U_, user_data_t *user_data _U_)
{
	user_data->dlg.save_csv_as_w = NULL;
}

/* when the user wants to save the csv information in a file */
static void save_csv_as_cb(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	GtkWidget *vertb;
	GtkWidget *table1;
	GtkWidget *label_format;
	GtkWidget *channels_label;
	GSList *channels_group = NULL;
	GtkWidget *forward_rb;
	GtkWidget *reversed_rb;
	GtkWidget *both_rb;
	GtkWidget *ok_bt;
	
	if (user_data->dlg.save_csv_as_w != NULL) {
		/* There's already a Save CSV info dialog box; reactivate it. */
		reactivate_window(user_data->dlg.save_csv_as_w);
		return;
	}
	
	user_data->dlg.save_csv_as_w = gtk_file_selection_new("Ethereal: Save Data As CSV");
	
	/* Container for each row of widgets */
	vertb = gtk_vbox_new(FALSE, 0);
	gtk_container_border_width(GTK_CONTAINER(vertb), 5);
	gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(user_data->dlg.save_csv_as_w)->action_area),
		vertb, FALSE, FALSE, 0);
	gtk_widget_show (vertb);
	
	table1 = gtk_table_new (2, 4, FALSE);
	gtk_widget_show (table1);
	gtk_box_pack_start (GTK_BOX (vertb), table1, FALSE, FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (table1), 10);
	gtk_table_set_row_spacings (GTK_TABLE (table1), 20);
	
	label_format = gtk_label_new ("Format: Comma Separated Values");
	gtk_widget_show (label_format);
	gtk_table_attach (GTK_TABLE (table1), label_format, 0, 3, 0, 1,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);
	
	
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
	
	ok_bt = GTK_FILE_SELECTION(user_data->dlg.save_csv_as_w)->ok_button;
	OBJECT_SET_DATA(ok_bt, "forward_rb", forward_rb);
	OBJECT_SET_DATA(ok_bt, "reversed_rb", reversed_rb);
	OBJECT_SET_DATA(ok_bt, "both_rb", both_rb);
	OBJECT_SET_DATA(ok_bt, "user_data", user_data);
	SIGNAL_CONNECT(ok_bt, "clicked", save_csv_as_ok_cb,
		user_data->dlg.save_csv_as_w);
	
	window_set_cancel_button(user_data->dlg.save_csv_as_w, 
		GTK_FILE_SELECTION(user_data->dlg.save_csv_as_w)->cancel_button, NULL);
	
	SIGNAL_CONNECT(user_data->dlg.save_csv_as_w, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(user_data->dlg.save_csv_as_w, "destroy",
		save_csv_as_destroy_cb, user_data);
	
	gtk_widget_show(user_data->dlg.save_csv_as_w);
	window_present(user_data->dlg.save_csv_as_w);
}


/****************************************************************************/
static void save_voice_as_destroy_cb(GtkWidget *win _U_, user_data_t *user_data _U_)
{
	/* Note that we no longer have a Save voice info dialog box. */
	user_data->dlg.save_voice_as_w = NULL;
}

/****************************************************************************/
/* here we save it into a file that user specified */
/* XXX what about endians here? could go something wrong? */
static gboolean copy_file(gchar *dest, gint channels, gint format, user_data_t *user_data)
{
	int to_fd, forw_fd, rev_fd, fread = 0, rread = 0, fwritten, rwritten;
	gchar f_pd[1];
	gchar r_pd[1];
	gint16 tmp;
	gchar pd[1];
	guint32 f_write_silence = 0;
	guint32 r_write_silence = 0;
	progdlg_t *progbar;
	guint32 progbar_count, progbar_quantum, progbar_nextstep = 0, count = 0;
	gboolean stop_flag = FALSE;

	forw_fd = open(user_data->f_tempname, O_RDONLY | O_BINARY);
	if (forw_fd < 0) 
		return FALSE;
	rev_fd = open(user_data->r_tempname, O_RDONLY | O_BINARY);
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

	progbar = create_progress_dlg("Saving voice in a file", dest, &stop_flag);

	if	(format == SAVE_AU_FORMAT) /* au format */
	{
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
				progbar_count = user_data->forward.saveinfo.count;
				progbar_quantum = user_data->forward.saveinfo.count/100;
				while ((fread = read(forw_fd, f_pd, 1)) > 0) {
					if(stop_flag) 
						break;
					if((count > progbar_nextstep) && (count <= progbar_count)) {
						update_progress_dlg(progbar, 
							(gfloat) count/progbar_count, "Saving");
						progbar_nextstep = progbar_nextstep + progbar_quantum;
					}
					count++;

					if (user_data->forward.statinfo.pt == PT_PCMU){
						tmp = (gint16 )ulaw2linear(*f_pd);
						*pd = (unsigned char)linear2ulaw(tmp);
					}
					else if(user_data->forward.statinfo.pt == PT_PCMA){
						tmp = (gint16 )alaw2linear(*f_pd);
						*pd = (unsigned char)linear2ulaw(tmp);
					}
					else{
						close(forw_fd);
						close(rev_fd);
						close(to_fd);
						destroy_progress_dlg(progbar);
						return FALSE;
					}
					
					fwritten = write(to_fd, pd, 1);
					if ((fwritten < fread) || (fwritten < 0) || (fread < 0)) {
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
				progbar_count = user_data->reversed.saveinfo.count;
				progbar_quantum = user_data->reversed.saveinfo.count/100;
				while ((rread = read(rev_fd, r_pd, 1)) > 0) {
					if(stop_flag) 
						break;
					if((count > progbar_nextstep) && (count <= progbar_count)) {
						update_progress_dlg(progbar, 
							(gfloat) count/progbar_count, "Saving");
						progbar_nextstep = progbar_nextstep + progbar_quantum;
					}
					count++;

					if (user_data->forward.statinfo.pt == PT_PCMU){
						tmp = (gint16 )ulaw2linear(*r_pd);
						*pd = (unsigned char)linear2ulaw(tmp);
					}
					else if(user_data->forward.statinfo.pt == PT_PCMA){
						tmp = (gint16 )alaw2linear(*r_pd);
						*pd = (unsigned char)linear2ulaw(tmp);
					}
					else{
						close(forw_fd);
						close(rev_fd);
						close(to_fd);
						destroy_progress_dlg(progbar);
						return FALSE;
					}
					
					rwritten = write(to_fd, pd, 1);
					if ((rwritten < rread) || (rwritten < 0) || (rread < 0)) {
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
				(user_data->forward.saveinfo.count > user_data->reversed.saveinfo.count) ? 
						(progbar_count = user_data->forward.saveinfo.count) : 
							(progbar_count = user_data->reversed.saveinfo.count);
				progbar_quantum = progbar_count/100;
				/* since conversation in one way can start later than in the other one, 
				 * we have to write some silence information for one channel */
				if (user_data->forward.statinfo.start_time > user_data->reversed.statinfo.start_time) {
					f_write_silence = (guint32)
						((user_data->forward.statinfo.start_time-user_data->reversed.statinfo.start_time)*8000);
				}
				else if (user_data->forward.statinfo.start_time < user_data->reversed.statinfo.start_time) {
					r_write_silence = (guint32)
						((user_data->reversed.statinfo.start_time-user_data->forward.statinfo.start_time)*8000);
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
						rread = read(rev_fd, r_pd, 1);
						*f_pd = 0;
						fread = 1;
						f_write_silence--;
					}
					else if(r_write_silence > 0) {
						fread = read(forw_fd, f_pd, 1);
						*r_pd = 0;
						rread = 1;
						r_write_silence--;
					}
					else {
						fread = read(forw_fd, f_pd, 1); 
						rread = read(rev_fd, r_pd, 1);
					}
					if ((rread == 0) && (fread == 0)) 
						break;
					if ((user_data->forward.statinfo.pt == PT_PCMU) && (user_data->reversed.statinfo.pt == PT_PCMU)){
						tmp = ulaw2linear(*r_pd);
						tmp += ulaw2linear(*f_pd);
						*pd = (unsigned char)linear2ulaw(tmp/2);
					}
					else if((user_data->forward.statinfo.pt == PT_PCMA) && (user_data->reversed.statinfo.pt == PT_PCMA)){
						tmp = alaw2linear(*r_pd);
						tmp += alaw2linear(*f_pd);
						*pd = (unsigned char)linear2ulaw(tmp/2);
					}
					else
					{
						close(forw_fd);
						close(rev_fd);
						close(to_fd);
						destroy_progress_dlg(progbar);
						return FALSE;
					}
					
					
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
	}
	else if (format == SAVE_RAW_FORMAT)	/* raw format */
	{
		int fd;
		switch (channels) {
			/* only forward direction */
			case 1: {
				progbar_count = user_data->forward.saveinfo.count;
				progbar_quantum = user_data->forward.saveinfo.count/100;
				fd = forw_fd;
				break;
			}
			/* only reversed direction */
			case 2: {
				progbar_count = user_data->reversed.saveinfo.count;
				progbar_quantum = user_data->reversed.saveinfo.count/100;
				fd = rev_fd;
				break;
			}
			default: {
				close(forw_fd);
				close(rev_fd);
				close(to_fd);
				destroy_progress_dlg(progbar);
				return FALSE;
			}
		}

		

		/* XXX how do you just copy the file? */
		while ((rread = read(fd, pd, 1)) > 0) {
			if(stop_flag) 
				break;
			if((count > progbar_nextstep) && (count <= progbar_count)) {
				update_progress_dlg(progbar, 
					(gfloat) count/progbar_count, "Saving");
				progbar_nextstep = progbar_nextstep + progbar_quantum;
			}
			count++;

			rwritten = write(to_fd, pd, 1);

			if ((rwritten < rread) || (rwritten < 0) || (rread < 0)) {
				close(forw_fd);
				close(rev_fd);
				close(to_fd);
				destroy_progress_dlg(progbar);
				return FALSE;
			}
		}
	}

	destroy_progress_dlg(progbar);
	close(forw_fd);
	close(rev_fd);
	close(to_fd);
	return TRUE;
}


/****************************************************************************/
/* the user wants to save in a file */
/* XXX support for different formats is currently commented out */
static void save_voice_as_ok_cb(GtkWidget *ok_bt _U_, gpointer fs _U_)
{
	gchar *g_dest;
	/*GtkWidget *wav, *au, *sw;*/
	GtkWidget *au, *raw;
	GtkWidget *rev, *forw, *both;
	user_data_t *user_data;
	gint channels , format;
	
	g_dest = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
	
	/* Perhaps the user specified a directory instead of a file.
	Check whether they did. */
	if (test_for_directory(g_dest) == EISDIR) {
		/* It's a directory - set the file selection box to display it. */
		set_last_open_dir(g_dest);
		g_free(g_dest);
		file_selection_set_current_folder(fs, get_last_open_dir());
		return;
	}
	
	/*wav = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "wav_rb");
	sw = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "sw_rb");*/
	au = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "au_rb");
	raw = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "raw_rb");
	rev = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "reversed_rb");
	forw = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "forward_rb");
	both = (GtkWidget *)OBJECT_GET_DATA(ok_bt, "both_rb");
	user_data = (user_data_t *)OBJECT_GET_DATA(ok_bt, "user_data");
	
	/* XXX user clicks the ok button, but we know we can't save the voice info because f.e.
	* we don't support that codec. So we pop up a warning. Maybe it would be better to
	* disable the ok button or disable the buttons for direction if only one is not ok. The
	* problem is if we open the save voice dialog and then click the refresh button and maybe 
	* the state changes, so we can't save anymore. In this case we should be able to update
	* the buttons. For now it is easier if we put the warning when the ok button is pressed.
	*/
	
	/* we can not save in both directions */
	if ((user_data->forward.saveinfo.saved == FALSE) && (user_data->reversed.saveinfo.saved == FALSE) && (GTK_TOGGLE_BUTTON (both)->active)) {
		/* there are many combinations here, we just exit when first matches */
		if ((user_data->forward.saveinfo.error_type == TAP_RTP_WRONG_CODEC) || 
			(user_data->reversed.saveinfo.error_type == TAP_RTP_WRONG_CODEC))
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save in a file: Unsupported codec!");
		else if ((user_data->forward.saveinfo.error_type == TAP_RTP_WRONG_LENGTH) || 
			(user_data->reversed.saveinfo.error_type == TAP_RTP_WRONG_LENGTH))
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save in a file: Wrong length of captured packets!");
		else if ((user_data->forward.saveinfo.error_type == TAP_RTP_PADDING_ERROR) || 
			(user_data->reversed.saveinfo.error_type == TAP_RTP_PADDING_ERROR))
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save in a file: RTP data with padding!");
		else if ((user_data->forward.saveinfo.error_type == TAP_RTP_SHORT_FRAME) || 
			(user_data->reversed.saveinfo.error_type == TAP_RTP_SHORT_FRAME))
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save in a file: Not all data in all packets was captured!");
		else
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save in a file: File I/O problem!");
		return;
	}
	/* we can not save forward direction */
	else if ((user_data->forward.saveinfo.saved == FALSE) && ((GTK_TOGGLE_BUTTON (forw)->active) ||
		(GTK_TOGGLE_BUTTON (both)->active))) {	
		if (user_data->forward.saveinfo.error_type == TAP_RTP_WRONG_CODEC)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save forward direction in a file: Unsupported codec!");
		else if (user_data->forward.saveinfo.error_type == TAP_RTP_WRONG_LENGTH)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save forward direction in a file: Wrong length of captured packets!");
		else if (user_data->forward.saveinfo.error_type == TAP_RTP_PADDING_ERROR)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save forward direction in a file: RTP data with padding!");
		else if (user_data->forward.saveinfo.error_type == TAP_RTP_SHORT_FRAME)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save forward direction in a file: Not all data in all packets was captured!");
		else
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save forward direction in a file: File I/O problem!");
		return;
	}
	/* we can not save reversed direction */
	else if ((user_data->reversed.saveinfo.saved == FALSE) && ((GTK_TOGGLE_BUTTON (rev)->active) ||
		(GTK_TOGGLE_BUTTON (both)->active))) {	
		if (user_data->reversed.saveinfo.error_type == TAP_RTP_WRONG_CODEC)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: Unsupported codec!");
		else if (user_data->reversed.saveinfo.error_type == TAP_RTP_WRONG_LENGTH)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: Wrong length of captured packets!");
		else if (user_data->reversed.saveinfo.error_type == TAP_RTP_PADDING_ERROR)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: RTP data with padding!");
		else if (user_data->forward.saveinfo.error_type == TAP_RTP_SHORT_FRAME)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: Not all data in all packets was captured!");
		else if (user_data->reversed.saveinfo.error_type == TAP_RTP_NO_DATA)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: No RTP data!");
		else
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: File I/O problem!");
		return;
	}
	
	/*if (GTK_TOGGLE_BUTTON (wav)->active)
	format = 1;
	else */if (GTK_TOGGLE_BUTTON (au)->active)
	format = SAVE_AU_FORMAT;/*
	else if (GTK_TOGGLE_BUTTON (sw)->active)
	format = 3;*/
	else if (GTK_TOGGLE_BUTTON (raw)->active)
		format =SAVE_RAW_FORMAT;
	
	
	if (GTK_TOGGLE_BUTTON (rev)->active)
		channels = SAVE_REVERSE_DIRECTION_MASK;
	else if (GTK_TOGGLE_BUTTON (both)->active)
		channels = SAVE_BOTH_DIRECTION_MASK;
	else 
		channels = SAVE_FORWARD_DIRECTION_MASK;

	/* direction/format validity*/
	if (format == SAVE_AU_FORMAT)
	{
		/* make sure streams are alaw/ulaw */
		if ((channels & SAVE_FORWARD_DIRECTION_MASK) && (user_data->forward.statinfo.pt != PT_PCMA) && (user_data->forward.statinfo.pt != PT_PCMU)){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Can't save in a file: saving in au format supported only for alaw/ulaw streams");
			return;
		}
		if ((channels & SAVE_REVERSE_DIRECTION_MASK) && (user_data->reversed.statinfo.pt != PT_PCMA) && (user_data->reversed.statinfo.pt != PT_PCMU)){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Can't save in a file: saving in au format supported only for alaw/ulaw streams");
			return;
		}
		/* make sure pt's don't differ */
		if ((channels == SAVE_REVERSE_DIRECTION_MASK) && (user_data->forward.statinfo.pt != user_data->forward.statinfo.pt)){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Can't save in a file: Forward and reverse direction differ in type");
			return;
		}
	}
	else if (format == SAVE_RAW_FORMAT)
	{
		/* can't save raw in both directions */
		if (channels == SAVE_REVERSE_DIRECTION_MASK){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Can't save in a file: Unable to save raw data in both directions");
			return;
		}
	}
	else
	{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save in a file: Invalid save format");
		return;
	}
	
	if(!copy_file(g_dest, channels, format, user_data)) {
		/* XXX - report the error type! */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"An error occured while saving voice in a file!");
		return;
	}
	
	window_destroy(GTK_WIDGET(user_data->dlg.save_voice_as_w));
}

/****************************************************************************/
/* when the user wants to save the voice information in a file */
/* XXX support for different formats is currently commented out */
static void on_save_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	GtkWidget *vertb;
	GtkWidget *table1;
	GtkWidget *label_format;
	GtkWidget *channels_label;
	GSList *format_group = NULL;
	GSList *channels_group = NULL;
	GtkWidget *forward_rb;
	GtkWidget *reversed_rb;
	GtkWidget *both_rb;
	/*GtkWidget *wav_rb;  GtkWidget *sw_rb;*/
	GtkWidget *au_rb;
	GtkWidget *raw_rb;
	GtkWidget *ok_bt;
	
	/* if we can't save in a file: wrong codec, cut packets or other errors */
	/* shold the error arise here or later when you click ok button ? 
	* if we do it here, then we must disable the refresh button, so we don't do it here */
	
	if (user_data->dlg.save_voice_as_w != NULL) {
		/* There's already a Save voice info dialog box; reactivate it. */
		reactivate_window(user_data->dlg.save_voice_as_w);
		return;
	}
	
    /* XXX - use file_selection from dlg_utils instead! */
	user_data->dlg.save_voice_as_w = gtk_file_selection_new("Ethereal: Save Payload As ...");
	
	/* Container for each row of widgets */
	vertb = gtk_vbox_new(FALSE, 0);
	gtk_container_border_width(GTK_CONTAINER(vertb), 5);
	gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(user_data->dlg.save_voice_as_w)->action_area),
		vertb, FALSE, FALSE, 0);
	gtk_widget_show (vertb);
	
	table1 = gtk_table_new (2, 4, FALSE);
	gtk_widget_show (table1);
	gtk_box_pack_start (GTK_BOX (vertb), table1, FALSE, FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (table1), 10);
	gtk_table_set_row_spacings (GTK_TABLE (table1), 20);
	
	/*label_format = gtk_label_new ("Format: .au (ulaw, 8 bit, 8000 Hz, mono) ");
	gtk_widget_show (label_format);
	gtk_table_attach (GTK_TABLE (table1), label_format, 0, 3, 0, 1,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);*/

	label_format = gtk_label_new ("Format: ");
	gtk_widget_show (label_format);
	gtk_table_attach (GTK_TABLE (table1), label_format, 0, 3, 0, 1,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);

	gtk_misc_set_alignment (GTK_MISC (label_format), 0, 0.5);

	raw_rb = gtk_radio_button_new_with_label (format_group, ".raw");
	format_group = gtk_radio_button_group (GTK_RADIO_BUTTON (raw_rb));
	gtk_widget_show (raw_rb);
	gtk_table_attach (GTK_TABLE (table1), raw_rb, 1, 2, 0, 1,
	(GtkAttachOptions) (GTK_FILL),
	(GtkAttachOptions) (0), 0, 0);
	
	  
	au_rb = gtk_radio_button_new_with_label (format_group, ".au");
	format_group = gtk_radio_button_group (GTK_RADIO_BUTTON (au_rb));
	gtk_widget_show (au_rb);
	gtk_table_attach (GTK_TABLE (table1), au_rb, 3, 4, 0, 1,
	(GtkAttachOptions) (GTK_FILL),
	(GtkAttachOptions) (0), 0, 0);
	
	/* we support .au - ulaw*/ 
	/*	wav_rb = gtk_radio_button_new_with_label (format_group, ".wav");
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
	if (user_data->forward.saved == FALSE) {
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(reversed_rb), TRUE);
	gtk_widget_set_sensitive(forward_rb, FALSE);
	gtk_widget_set_sensitive(both_rb, FALSE);
	}
	else if (user_data->reversed.saved == FALSE) {
	gtk_widget_set_sensitive(reversed_rb, FALSE);
	gtk_widget_set_sensitive(both_rb, FALSE);
	}
	*/
	
	ok_bt = GTK_FILE_SELECTION(user_data->dlg.save_voice_as_w)->ok_button;
	/*OBJECT_SET_DATA(ok_bt, "wav_rb", wav_rb);*/
	OBJECT_SET_DATA(ok_bt, "au_rb", au_rb);
	/*OBJECT_SET_DATA(ok_bt, "sw_rb", sw_rb);*/
	OBJECT_SET_DATA(ok_bt, "raw_rb", raw_rb);
	OBJECT_SET_DATA(ok_bt, "forward_rb", forward_rb);
	OBJECT_SET_DATA(ok_bt, "reversed_rb", reversed_rb);
	OBJECT_SET_DATA(ok_bt, "both_rb", both_rb);
	OBJECT_SET_DATA(ok_bt, "user_data", user_data);
	SIGNAL_CONNECT(ok_bt, "clicked", save_voice_as_ok_cb,
                       user_data->dlg.save_voice_as_w);

    window_set_cancel_button(user_data->dlg.save_voice_as_w, 
      GTK_FILE_SELECTION(user_data->dlg.save_voice_as_w)->cancel_button, window_cancel_button_cb);

    SIGNAL_CONNECT(user_data->dlg.save_voice_as_w, "delete_event", 
                        window_delete_event_cb, NULL);
	SIGNAL_CONNECT(user_data->dlg.save_voice_as_w, "destroy",
                        save_voice_as_destroy_cb, user_data);

	gtk_widget_show(user_data->dlg.save_voice_as_w);
    window_present(user_data->dlg.save_voice_as_w);
}


/****************************************************************************/
/* when we are finished with redisection, we add the label for the statistic */
static void draw_stat(user_data_t *user_data)
{
	gchar label_max[200];
	guint32 f_expected = (user_data->forward.statinfo.stop_seq_nr + user_data->forward.statinfo.cycles*65536)
		- user_data->forward.statinfo.start_seq_nr + 1;
	guint32 r_expected = (user_data->reversed.statinfo.stop_seq_nr + user_data->reversed.statinfo.cycles*65536)
		- user_data->reversed.statinfo.start_seq_nr + 1;
	gint32 f_lost = f_expected - user_data->forward.statinfo.total_nr;
	gint32 r_lost = r_expected - user_data->reversed.statinfo.total_nr;
	double f_perc, r_perc;
	if (f_expected){
		f_perc = (double)(f_lost*100)/(double)f_expected;
	} else {
		f_perc = 0;
	}
        if (r_expected){
                r_perc = (double)(r_lost*100)/(double)r_expected;
        } else {
                r_perc = 0;
        } 
		
	g_snprintf(label_max, 199, "Max delta = %f sec at packet no. %u \n"
		"Total RTP packets = %u   (expected %u)   Lost RTP packets = %d (%.2f%%)"
		"   Sequence errors = %u",
		user_data->forward.statinfo.max_delta, user_data->forward.statinfo.max_nr,
		user_data->forward.statinfo.total_nr,
		f_expected, f_lost, f_perc, user_data->forward.statinfo.sequence);

	gtk_label_set_text(GTK_LABEL(user_data->dlg.label_stats_fwd), label_max);

	g_snprintf(label_max, 199, "Max delta = %f sec at packet no. %u \n"
		"Total RTP packets = %u   (expected %u)   Lost RTP packets = %d (%.2f%%)"
		"   Sequence errors = %u",
		user_data->reversed.statinfo.max_delta, user_data->reversed.statinfo.max_nr,
		user_data->reversed.statinfo.total_nr,
		r_expected, r_lost, r_perc, user_data->reversed.statinfo.sequence);

	gtk_label_set_text(GTK_LABEL(user_data->dlg.label_stats_rev), label_max);

	return ;
}



/****************************************************************************/
/* append a line to clist */
static void add_to_clist(GtkCList *clist, guint32 number, guint16 seq_num,
                         double delta, double jitter, double bandwidth, gchar *status, gboolean marker,
                         gchar *timeStr, guint32 pkt_len, GdkColor *color)
{
	guint added_row;
	gchar *data[9];
	gchar field[9][32];
	char *savelocale;

	data[0]=&field[0][0];
	data[1]=&field[1][0];
	data[2]=&field[2][0];
	data[3]=&field[3][0];
	data[4]=&field[4][0];
	data[5]=&field[5][0];
	data[6]=&field[6][0];
	data[7]=&field[7][0];
	data[8]=&field[8][0];

	/* save the current locale */
	savelocale = setlocale(LC_NUMERIC, NULL);
	/* switch to "C" locale to avoid problems with localized decimal separators
		in g_snprintf("%f") functions */
	setlocale(LC_NUMERIC, "C");
	g_snprintf(field[0], 20, "%u", number);
	g_snprintf(field[1], 20, "%u", seq_num);
	g_snprintf(field[2], 20, "%.2f", delta);
	g_snprintf(field[3], 20, "%.2f", jitter);
	g_snprintf(field[4], 20, "%.2f", bandwidth);
	g_snprintf(field[5], 20, "%s", marker? "SET" : "");
	g_snprintf(field[6], 40, "%s", status);
	g_snprintf(field[7], 32, "%s", timeStr);
	g_snprintf(field[8], 20, "%u", pkt_len);
	/* restore previous locale setting */
	setlocale(LC_NUMERIC, savelocale);

	added_row = gtk_clist_append(GTK_CLIST(clist), data);
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, GUINT_TO_POINTER(number));
	gtk_clist_set_background(GTK_CLIST(clist), added_row, color);
}


/****************************************************************************/
/* callback for sorting columns of clist */
static gint rtp_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	int i1, i2;
	double f1, f2;

	const GtkCListRow *row1 = ptr1;
	const GtkCListRow *row2 = ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	/* columns representing strings */
	case 5:
	case 6:
	case 7:
		return strcmp (text1, text2);
	/* columns representing ints */
	case 0:
	case 1:
	case 8:
		i1=atoi(text1);
		i2=atoi(text2);
		return i1-i2;
	/* columns representing floats */
	case 2:
	case 3:
	case 4:
		f1=atof(text1);
		f2=atof(text2);
		if (fabs(f1-f2)<0.0000005)
			return 0;
		if (f1<f2)
			return -1;
		return 1;
	}
	g_assert_not_reached();
	return 0;
}


/****************************************************************************/
static void
click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	gtk_clist_freeze(clist);

	for (i = 0; i < NUM_COLS; i++) {
		gtk_widget_hide(col_arrows[i].ascend_pm);
		gtk_widget_hide(col_arrows[i].descend_pm);
	}

	if (column == clist->sort_column) {
		if (clist->sort_type == GTK_SORT_ASCENDING) {
			clist->sort_type = GTK_SORT_DESCENDING;
			gtk_widget_show(col_arrows[column].descend_pm);
		} else {
			clist->sort_type = GTK_SORT_ASCENDING;
			gtk_widget_show(col_arrows[column].ascend_pm);
		}
	} else {
		clist->sort_type = GTK_SORT_ASCENDING;
		gtk_widget_show(col_arrows[column].ascend_pm);
		gtk_clist_set_sort_column(clist, column);
	}
	gtk_clist_thaw(clist);

	gtk_clist_sort(clist);
}


/****************************************************************************/
/* Add the packet list */
static
GtkWidget* create_clist(user_data_t* user_data)
{
	GtkWidget* clist_fwd;

	/* clist for the information */
	clist_fwd = gtk_clist_new(NUM_COLS);
	gtk_widget_show(clist_fwd);
	SIGNAL_CONNECT(clist_fwd, "select_row", on_clist_select_row, user_data);

	gtk_clist_column_titles_show(GTK_CLIST(clist_fwd));
	gtk_clist_set_compare_func(GTK_CLIST(clist_fwd), rtp_sort_column);
	gtk_clist_set_sort_column(GTK_CLIST(clist_fwd), 0);
	gtk_clist_set_sort_type(GTK_CLIST(clist_fwd), GTK_SORT_ASCENDING);

	/* hide date and length column */
	gtk_clist_set_column_visibility(GTK_CLIST(clist_fwd), 7, FALSE);
	gtk_clist_set_column_visibility(GTK_CLIST(clist_fwd), 8, FALSE);

	/* column widths and justification */
	gtk_clist_set_column_width(GTK_CLIST(clist_fwd), 0, 60);
	gtk_clist_set_column_width(GTK_CLIST(clist_fwd), 1, 75);
	gtk_clist_set_column_width(GTK_CLIST(clist_fwd), 2, 75);
	gtk_clist_set_column_width(GTK_CLIST(clist_fwd), 3, 75);
	gtk_clist_set_column_width(GTK_CLIST(clist_fwd), 4, 50);
	gtk_clist_set_column_width(GTK_CLIST(clist_fwd), 5, 75);
	gtk_clist_set_column_justification(GTK_CLIST(clist_fwd), 0, GTK_JUSTIFY_RIGHT);
	gtk_clist_set_column_justification(GTK_CLIST(clist_fwd), 1, GTK_JUSTIFY_RIGHT);
	gtk_clist_set_column_justification(GTK_CLIST(clist_fwd), 2, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist_fwd), 3, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist_fwd), 4, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist_fwd), 5, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist_fwd), 6, GTK_JUSTIFY_CENTER);
	return clist_fwd;
}


/****************************************************************************/
/* Add the sort by column feature for a packet clist */
static
column_arrows* add_sort_by_column(GtkWidget* window, GtkWidget* clist,
								  user_data_t* user_data _U_)
{
	column_arrows *col_arrows;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	GtkStyle *win_style;
	GtkWidget *column_lb;
	int i;

	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);
	win_style = gtk_widget_get_style(window);
	ascend_pm = gdk_pixmap_create_from_xpm_d(window->window,
			&ascend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_ascend_xpm);
	descend_pm = gdk_pixmap_create_from_xpm_d(window->window,
			&descend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_descend_xpm);

	for (i=0; i<NUM_COLS; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		col_arrows[i].ascend_pm = gtk_pixmap_new(ascend_pm, ascend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = gtk_pixmap_new(descend_pm, descend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
		/* make packet-nr be the default sort order */
		if (i == 0) {
			gtk_widget_show(col_arrows[i].ascend_pm);
		}
		gtk_clist_set_column_widget(GTK_CLIST(clist), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}

	SIGNAL_CONNECT(clist, "click-column", click_column_cb, col_arrows);

	return col_arrows;
}

/****************************************************************************/
/* Create the dialog box with all widgets */
static void create_rtp_dialog(user_data_t* user_data)
{
	GtkWidget *window = NULL;
	GtkWidget *clist_fwd;
	GtkWidget *clist_rev;
	GtkWidget *label_stats_fwd;
	GtkWidget *label_stats_rev;
	GtkWidget *notebook;

	GtkWidget *main_vb, *page, *page_r;
	GtkWidget *label;
	GtkWidget *scrolled_window, *scrolled_window_r/*, *frame, *text, *label4, *page_help*/;
	GtkWidget *box4, *voice_bt, *refresh_bt, *goto_bt, *close_bt, *csv_bt, *next_bt;
#ifdef USE_CONVERSATION_GRAPH
	GtkWidget *graph_bt;
#endif
	GtkWidget *graph_bt;
	gchar label_forward[150];
	gchar label_reverse[150];

	gchar str_ip_src[16];
	gchar str_ip_dst[16];
	column_arrows *col_arrows_fwd;
	column_arrows *col_arrows_rev;
	
	window = window_new(GTK_WINDOW_TOPLEVEL, "Ethereal: RTP Stream Analysis");
	gtk_window_set_default_size(GTK_WINDOW(window), 700, 400);

	/* Container for each row of widgets */
	main_vb = gtk_vbox_new(FALSE, 2);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 2);
	gtk_container_add(GTK_CONTAINER(window), main_vb);
	gtk_widget_show(main_vb);

	/* Notebooks... */
	strcpy(str_ip_src, get_addr_name(&(user_data->ip_src_fwd)));
	strcpy(str_ip_dst, get_addr_name(&(user_data->ip_dst_fwd)));

	g_snprintf(label_forward, 149, 
		"Analysing stream from  %s port %u  to  %s port %u   SSRC = %u", 
		str_ip_src, user_data->port_src_fwd, str_ip_dst, user_data->port_dst_fwd, user_data->ssrc_fwd);


	strcpy(str_ip_src, get_addr_name(&(user_data->ip_src_rev)));
	strcpy(str_ip_dst, get_addr_name(&(user_data->ip_dst_rev)));

	g_snprintf(label_reverse, 149,
		"Analysing stream from  %s port %u  to  %s port %u   SSRC = %u", 
		str_ip_src, user_data->port_src_rev, str_ip_dst, user_data->port_dst_rev, user_data->ssrc_rev);

	/* Start a notebook for flipping between sets of changes */
	notebook = gtk_notebook_new();
	gtk_container_add(GTK_CONTAINER(main_vb), notebook);
	OBJECT_SET_DATA(window, "notebook", notebook);

	user_data->dlg.notebook_signal_id = SIGNAL_CONNECT(notebook, "switch_page", on_notebook_switch_page,
                       user_data);

	/* page for forward connection */
	page = gtk_vbox_new(FALSE, 8);
	gtk_container_set_border_width(GTK_CONTAINER(page), 8);

	/* direction label */
	label = gtk_label_new(label_forward);
	gtk_box_pack_start(GTK_BOX(page), label, FALSE, FALSE, 0);

	/* place for some statistics */
	label_stats_fwd = gtk_label_new("\n");
	gtk_box_pack_end(GTK_BOX(page), label_stats_fwd, FALSE, FALSE, 0);

	/* scrolled window */
	scrolled_window = scrolled_window_new(NULL, NULL);

	/* packet clist */
	clist_fwd = create_clist(user_data);
	gtk_widget_show(clist_fwd);
	gtk_container_add(GTK_CONTAINER(scrolled_window), clist_fwd);
	gtk_box_pack_start(GTK_BOX(page), scrolled_window, TRUE, TRUE, 0);
	gtk_widget_show(scrolled_window);

	/* tab */
	label = gtk_label_new("  Forward Direction  ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page, label);

	/* same page for reversed connection */
	page_r = gtk_vbox_new(FALSE, 8);
	gtk_container_set_border_width(GTK_CONTAINER(page_r), 8);
	label = gtk_label_new(label_reverse);
	gtk_box_pack_start(GTK_BOX(page_r), label, FALSE, FALSE, 0);
	label_stats_rev = gtk_label_new("\n");
	gtk_box_pack_end(GTK_BOX(page_r), label_stats_rev, FALSE, FALSE, 0);

	scrolled_window_r = scrolled_window_new(NULL, NULL);

	clist_rev = create_clist(user_data);
	gtk_widget_show(clist_rev);
	gtk_container_add(GTK_CONTAINER(scrolled_window_r), clist_rev);
	gtk_box_pack_start(GTK_BOX(page_r), scrolled_window_r, TRUE, TRUE, 0);
	gtk_widget_show(scrolled_window_r);

	label = gtk_label_new("  Reversed Direction  ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_r, label);

	/* page for help&about or future
	page_help = gtk_hbox_new(FALSE, 5);
	label = gtk_label_new("     Future    ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_help, label);
	frame = gtk_frame_new("");
	text = gtk_label_new("\n\nMaybe some more statistics: delta and jitter distribution,...");
	gtk_label_set_justify(GTK_LABEL(text), GTK_JUSTIFY_LEFT);
	gtk_container_add(GTK_CONTAINER(frame), text);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 20);
	gtk_box_pack_start(GTK_BOX(page_help), frame, TRUE, TRUE, 0);
	*/

	/* show all notebooks */
	gtk_widget_show_all(notebook);

	/* buttons */
	box4 = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(main_vb), box4, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(box4), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (box4), GTK_BUTTONBOX_EDGE);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (box4), 0);
	gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (box4), 4, 0);
	gtk_widget_show(box4);

	voice_bt = gtk_button_new_with_label("Save payload...");
	gtk_container_add(GTK_CONTAINER(box4), voice_bt);
	gtk_widget_show(voice_bt);
	SIGNAL_CONNECT(voice_bt, "clicked", on_save_bt_clicked, user_data);

	csv_bt = gtk_button_new_with_label("Save as CSV...");
	gtk_container_add(GTK_CONTAINER(box4), csv_bt);
	gtk_widget_show(csv_bt);
	SIGNAL_CONNECT(csv_bt, "clicked", save_csv_as_cb, user_data);

	refresh_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_REFRESH);
	gtk_container_add(GTK_CONTAINER(box4), refresh_bt);
	gtk_widget_show(refresh_bt);
	SIGNAL_CONNECT(refresh_bt, "clicked", on_refresh_bt_clicked, user_data);

	goto_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_JUMP_TO);
	gtk_container_add(GTK_CONTAINER(box4), goto_bt);
	gtk_widget_show(goto_bt);
	SIGNAL_CONNECT(goto_bt, "clicked", on_goto_bt_clicked, user_data);

        graph_bt = gtk_button_new_with_label("Graph");
	gtk_container_add(GTK_CONTAINER(box4), graph_bt);
	gtk_widget_show(graph_bt);
	SIGNAL_CONNECT(graph_bt, "clicked", on_graph_bt_clicked, user_data);	


#ifdef USE_CONVERSATION_GRAPH
	graph_bt = gtk_button_new_with_label("Graph");
	gtk_container_add(GTK_CONTAINER(box4), graph_bt);
	gtk_widget_show(graph_bt);
	SIGNAL_CONNECT(graph_bt, "clicked", on_graph_bt_clicked, user_data);
#endif

	next_bt = gtk_button_new_with_label("Next non-Ok");
	gtk_container_add(GTK_CONTAINER(box4), next_bt);
	gtk_widget_show(next_bt);
	SIGNAL_CONNECT(next_bt, "clicked", on_next_bt_clicked, user_data);

	close_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_container_add(GTK_CONTAINER(box4), close_bt);
    GTK_WIDGET_SET_FLAGS(close_bt, GTK_CAN_DEFAULT);
	gtk_widget_show(close_bt);
    window_set_cancel_button(window, close_bt, window_cancel_button_cb);

    SIGNAL_CONNECT(window, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(window, "destroy", on_destroy, user_data);

    gtk_widget_show(window);
    window_present(window);

	/* sort by column feature */
	col_arrows_fwd = add_sort_by_column(window, clist_fwd, user_data);
	col_arrows_rev = add_sort_by_column(window, clist_rev, user_data);

	/* some widget references need to be saved for outside use */
	user_data->dlg.window = window;
	user_data->dlg.clist_fwd = GTK_CLIST(clist_fwd);
	user_data->dlg.clist_rev = GTK_CLIST(clist_rev);
	user_data->dlg.label_stats_fwd = label_stats_fwd;
	user_data->dlg.label_stats_rev = label_stats_rev;
	user_data->dlg.notebook = notebook;
	user_data->dlg.selected_clist = GTK_CLIST(clist_fwd);
	user_data->dlg.selected_row = 0;
	user_data->dlg.col_arrows_fwd = col_arrows_fwd;
	user_data->dlg.col_arrows_rev = col_arrows_rev;
}


/****************************************************************************/
static gboolean process_node(proto_node *ptree_node, header_field_info *hfinformation,
							const gchar* proto_field, guint32* p_result)
{
	field_info            *finfo;
	proto_node            *proto_sibling_node;
	header_field_info     *hfssrc;
	ipv4_addr             *ipv4;

	finfo = PITEM_FINFO(ptree_node);

	if (hfinformation==(finfo->hfinfo)) {
		hfssrc = proto_registrar_get_byname(proto_field);
		if (hfssrc == NULL)
			return FALSE;
		for(ptree_node=ptree_node->first_child; ptree_node!=NULL; 
					ptree_node=ptree_node->next) {
			finfo=PITEM_FINFO(ptree_node);
			if (hfssrc==finfo->hfinfo) {
				if (hfinformation->type==FT_IPv4) {
					ipv4 = fvalue_get(&finfo->value);
					*p_result = ipv4_get_net_order_addr(ipv4);
				}
				else {
					*p_result = fvalue_get_integer(&finfo->value);
				}
				return TRUE;
			}
		}
	}

	proto_sibling_node = ptree_node->next;

	if (proto_sibling_node) {
		return process_node(proto_sibling_node, hfinformation, proto_field, p_result);
	}
	else
	return FALSE;
}

/****************************************************************************/
static gboolean get_int_value_from_proto_tree(proto_tree *protocol_tree,
						 const gchar* proto_name,
						 const gchar* proto_field,
						 guint32* p_result)
{
	proto_node      *ptree_node;
	header_field_info     *hfinformation;

	hfinformation = proto_registrar_get_byname(proto_name);
	if (hfinformation == NULL)
		return FALSE;

	ptree_node = ((proto_node *)protocol_tree)->first_child;
	if (!ptree_node)
		return FALSE;

	return process_node(ptree_node, hfinformation, proto_field, p_result);
}


/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

/****************************************************************************/
void rtp_analysis(
		address *ip_src_fwd,
		guint16 port_src_fwd,
		address *ip_dst_fwd,
		guint16 port_dst_fwd,
		guint32 ssrc_fwd,
		address *ip_src_rev,
		guint16 port_src_rev,
		address *ip_dst_rev,
		guint16 port_dst_rev,
		guint32 ssrc_rev
		)
{
	user_data_t *user_data;
	int fd;
	int i;
	static color_t col[MAX_GRAPHS] = {
       		{0,     0x0000, 0x0000, 0x0000},
        	{0,     0xffff, 0x0000, 0x0000},
        	{0,     0x0000, 0xffff, 0x0000},
        	{0,     0x0000, 0x0000, 0xffff}
	};

	/* init */
	user_data = g_malloc(sizeof(user_data_t));

	COPY_ADDRESS(&(user_data->ip_src_fwd), ip_src_fwd);
	user_data->port_src_fwd = port_src_fwd;
	COPY_ADDRESS(&(user_data->ip_dst_fwd), ip_dst_fwd);
	user_data->port_dst_fwd = port_dst_fwd;
	user_data->ssrc_fwd = ssrc_fwd;
	COPY_ADDRESS(&(user_data->ip_src_rev), ip_src_rev);
	user_data->port_src_rev = port_src_rev;
	COPY_ADDRESS(&(user_data->ip_dst_rev), ip_dst_rev);
	user_data->port_dst_rev = port_dst_rev;
	user_data->ssrc_rev = ssrc_rev;


	/* file names for storing sound data */
	/*XXX: check for errors*/
	fd = create_tempfile(user_data->f_tempname, sizeof(user_data->f_tempname),
		"ether_rtp_f");
	close(fd);
	fd = create_tempfile(user_data->r_tempname, sizeof(user_data->r_tempname),
		"ether_rtp_r");
	close(fd);
	user_data->forward.saveinfo.fp = NULL;
	user_data->reversed.saveinfo.fp = NULL;
	user_data->dlg.save_voice_as_w = NULL;
	user_data->dlg.save_csv_as_w = NULL;
        user_data->dlg.dialog_graph.window = NULL;

#ifdef USE_CONVERSATION_GRAPH
	user_data->dlg.graph_window = NULL;
	user_data->series_fwd.value_pairs = NULL;
	user_data->series_rev.value_pairs = NULL;
#endif

        /* init dialog_graph */
        user_data->dlg.dialog_graph.needs_redraw=TRUE;
        user_data->dlg.dialog_graph.interval=tick_interval_values[DEFAULT_TICK_VALUE];
        user_data->dlg.dialog_graph.draw_area=NULL;
        user_data->dlg.dialog_graph.pixmap=NULL;
        user_data->dlg.dialog_graph.scrollbar=NULL;
        user_data->dlg.dialog_graph.scrollbar_adjustment=NULL;
        user_data->dlg.dialog_graph.pixmap_width=500;
        user_data->dlg.dialog_graph.pixmap_height=200;
        user_data->dlg.dialog_graph.pixels_per_tick=pixels_per_tick[DEFAULT_PIXELS_PER_TICK];
        user_data->dlg.dialog_graph.max_y_units=AUTO_MAX_YSCALE;
        user_data->dlg.dialog_graph.last_interval=0xffffffff;
        user_data->dlg.dialog_graph.max_interval=0;
        user_data->dlg.dialog_graph.num_items=0;
	user_data->dlg.dialog_graph.start_time = -1;

	for(i=0;i<MAX_GRAPHS;i++){
        	user_data->dlg.dialog_graph.graph[i].gc=NULL;
        	user_data->dlg.dialog_graph.graph[i].color.pixel=0;
        	user_data->dlg.dialog_graph.graph[i].color.red=col[i].red;
        	user_data->dlg.dialog_graph.graph[i].color.green=col[i].green;
        	user_data->dlg.dialog_graph.graph[i].color.blue=col[i].blue;
        	user_data->dlg.dialog_graph.graph[i].display=TRUE;
        	user_data->dlg.dialog_graph.graph[i].display_button=NULL;
        	user_data->dlg.dialog_graph.graph[i].ud=user_data;
	}

	/* create the dialog box */
	create_rtp_dialog(user_data);

	/* proceed as if the Refresh button would have been pressed */
	on_refresh_bt_clicked(NULL, user_data);
}

/****************************************************************************/
/* entry point from main menu */
static void rtp_analysis_cb(GtkWidget *w _U_, gpointer data _U_) 
{
	address ip_src_fwd;
	guint16 port_src_fwd;
	address ip_dst_fwd;
	guint16 port_dst_fwd;
	guint32 ssrc_fwd = 0;
	address ip_src_rev;
	guint16 port_src_rev;
	address ip_dst_rev;
	guint16 port_dst_rev;
	guint32 ssrc_rev = 0;
	unsigned int version_fwd;

	gchar filter_text[256];
	dfilter_t *sfcode;
	capture_file *cf;
	epan_dissect_t *edt;
	gint err;
	gchar *err_info;
	gboolean frame_matched;
	frame_data *fdata;
	GList *strinfo_list;
	GList *filtered_list = NULL;
	rtp_stream_info_t *strinfo;
	guint nfound;

	/* Try to compile the filter. */
	strcpy(filter_text,"rtp && rtp.version && rtp.ssrc && (ip || ipv6)");
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
	
	/* if it is not an rtp frame, show the rtpstream dialog */
	frame_matched = dfilter_apply_edt(sfcode, edt);
	if (frame_matched != 1) {
		epan_dissect_free(edt);
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "You didn't choose a RTP packet!");
		return;
	}

	/* ok, it is a RTP frame, so let's get the ip and port values */
	COPY_ADDRESS(&(ip_src_fwd), &(edt->pi.src))
	COPY_ADDRESS(&(ip_dst_fwd), &(edt->pi.dst))
	port_src_fwd = edt->pi.srcport;
	port_dst_fwd = edt->pi.destport;

	/* assume the inverse ip/port combination for the reverse direction */
	COPY_ADDRESS(&(ip_src_rev), &(edt->pi.dst))
	COPY_ADDRESS(&(ip_dst_rev), &(edt->pi.src))
	port_src_rev = edt->pi.destport;
	port_dst_rev = edt->pi.srcport;

        /* check if it is RTP Version 2 */
        if (!get_int_value_from_proto_tree(edt->tree, "rtp", "rtp.version", &version_fwd) || version_fwd != 2) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "RTP Version != 2 isn't supported!");
                return;
        }
	
	/* now we need the SSRC value of the current frame */
	if (!get_int_value_from_proto_tree(edt->tree, "rtp", "rtp.ssrc", &ssrc_fwd)) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "SSRC value couldn't be found!");
		return;
	}

	/* Scan for rtpstream */
	rtpstream_scan();
	/* search for reversed direction in the global rtp streams list */
	nfound = 0;
	strinfo_list = g_list_first(rtpstream_get_info()->strinfo_list);
	while (strinfo_list)
	{
		strinfo = (rtp_stream_info_t*)(strinfo_list->data);
		if (ADDRESSES_EQUAL(&(strinfo->src_addr),&(ip_src_fwd))
			&& strinfo->src_port==port_src_fwd
			&& ADDRESSES_EQUAL(&(strinfo->dest_addr),&(ip_dst_fwd))
			&& strinfo->dest_port==port_dst_fwd)
		{
			filtered_list = g_list_prepend(filtered_list, strinfo);
		}

		if (ADDRESSES_EQUAL(&(strinfo->src_addr),&(ip_src_rev))
			&& strinfo->src_port==port_src_rev
			&& ADDRESSES_EQUAL(&(strinfo->dest_addr),&(ip_dst_rev))
			&& strinfo->dest_port==port_dst_rev)
		{
			++nfound;
			filtered_list = g_list_append(filtered_list, strinfo);
			if (ssrc_rev==0)
				ssrc_rev = strinfo->ssrc;
		}

		strinfo_list = g_list_next(strinfo_list);
	}

	/* if more than one reverse streams found, we let the user choose the right one */
	if (nfound>1) {
		rtpstream_dlg_show(filtered_list);
		return;
	}
	else {
		rtp_analysis(
			&ip_src_fwd,
			port_src_fwd,
			&ip_dst_fwd,
			port_dst_fwd,
			ssrc_fwd,
			&ip_src_rev,
			port_src_rev,
			&ip_dst_rev,
			port_dst_rev,
			ssrc_rev
			);
	}
}

/****************************************************************************/
static void
rtp_analysis_init(const char *dummy _U_)
{
	rtp_analysis_cb(NULL, NULL);
}

/****************************************************************************/
void
register_tap_listener_rtp_analysis(void)
{
	register_stat_cmd_arg("rtp", rtp_analysis_init);

	register_stat_menu_item("RTP/Stream Analysis...", REGISTER_STAT_GROUP_TELEPHONY,
	    rtp_analysis_cb, NULL, NULL, NULL);
}
