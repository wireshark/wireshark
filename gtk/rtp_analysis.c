/* rtp_analysis.c
 * RTP analysis addition for Wireshark
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
#include "config.h"
#endif

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <locale.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <gtk/gtk.h>

#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include <epan/pint.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/rtp_pt.h>
#include <epan/addr_resolv.h>
#include <epan/stat_cmd_args.h>
#include <epan/strutil.h>

#include "../util.h"
#include "../g711.h"
#include "../alert_box.h"
#include "../simple_dialog.h"
#include "../stat_menu.h"
#include "../progress_dlg.h"
#include "../tempfile.h"
#include <wsutil/file_util.h>

#include "gtk/gtkglobals.h"
#include "gtk/dlg_utils.h"
#include "gtk/file_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/pixmap_save.h"
#include "gtk/main.h"
#include "gtk/rtp_analysis.h"
#include "gtk/rtp_stream.h"
#include "gtk/rtp_stream_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/utf8_entities.h"

#ifdef HAVE_LIBPORTAUDIO
#include "gtk/graph_analysis.h"
#include "gtk/voip_calls.h"
#include "gtk/rtp_player.h"
#endif /* HAVE_LIBPORTAUDIO */

#include "gtk/old-gtk-compat.h"

enum
{
	PACKET_COLUMN,
	SEQUENCE_COLUMN,
	TIMESTAMP_COLUMN,
	DELTA_COLUMN,
	JITTER_COLUMN,
	SKEW_COLUMN,
	IPBW_COLUMN,
	MARKER_COLUMN,
	STATUS_COLUMN,
	DATE_COLUMN,
	LENGTH_COLUMN,
	FOREGROUND_COLOR_COL,
	BACKGROUND_COLOR_COL,
	N_COLUMN /* The number of columns */
};
/****************************************************************************/

#define NUM_COLS 9
#define NUM_GRAPH_ITEMS 100000
#define MAX_YSCALE 16
#define AUTO_MAX_YSCALE_INDEX 0
#define AUTO_MAX_YSCALE 0
#define MAX_GRAPHS 6
#define GRAPH_FWD_JITTER 0
#define GRAPH_FWD_DIFF 1
#define GRAPH_FWD_DELTA 2
#define GRAPH_REV_JITTER 3
#define GRAPH_REV_DIFF 4
#define GRAPH_REV_DELTA 5
static guint32 yscale_max[MAX_YSCALE] = {AUTO_MAX_YSCALE, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 2000000, 5000000, 10000000, 20000000, 50000000};

#define MAX_PIXELS_PER_TICK 4
#define DEFAULT_PIXELS_PER_TICK_INDEX 2
static guint32 pixels_per_tick[MAX_PIXELS_PER_TICK] = {1, 2, 5, 10};
static const char *graph_descr[MAX_GRAPHS] = {"Fwd Jitter", "Fwd Difference", "Fwd Delta", "Rvr Jitter", "Rvr Difference", "Rvr Delta"};
/* unit is in ms */
#define MAX_TICK_VALUES 5
#define DEFAULT_TICK_INTERVAL_VALUES_INDEX 1
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
	gchar title[100];
} dialog_graph_graph_t;


typedef struct _dialog_graph_t {
	gboolean needs_redraw;
	gint32 interval_index;  /* index into tick_interval_values_array */
	gint32 interval;        /* measurement interval in ms */
	guint32 last_interval;
	guint32 max_interval;  /* XXX max_interval and num_items are redundant */
	guint32 num_items;
	struct _dialog_graph_graph_t graph[MAX_GRAPHS];
	GtkWidget *window;
	GtkWidget *draw_area;
#if GTK_CHECK_VERSION(2,22,0)
	cairo_surface_t *surface;
#else
	GdkPixmap *pixmap;
#endif
	GtkAdjustment *scrollbar_adjustment;
	GtkWidget *scrollbar;
	int surface_width;
	int surface_height;
	int pixels_per_tick_index; /* index into pixels_per_tick array */
	int pixels_per_tick;
	int max_y_units_index;     /* index into yscale_max array      */
	int max_y_units;
	double start_time;
} dialog_graph_t;

typedef struct _dialog_data_t {
	GtkWidget *window;
	GtkWidget *list_fwd;
	GtkTreeIter  iter;
	GtkWidget *list_rev;
	GtkWidget *label_stats_fwd;
	GtkWidget *label_stats_rev;
	GtkWidget *selected_list;
	guint	number_of_nok;
	GtkTreeSelection *selected_list_sel;
	gint selected_list_row;
	GtkWidget *notebook;
	GtkWidget *save_voice_as_w;
	GtkWidget *save_csv_as_w;
	gint notebook_signal_id;
	dialog_graph_t dialog_graph;
} dialog_data_t;

#define OK_TEXT "[ Ok ]"

/* type of error when saving voice in a file didn't succeed */
typedef enum {
	TAP_RTP_WRONG_CODEC,
	TAP_RTP_WRONG_LENGTH,
	TAP_RTP_PADDING_ERROR,
	TAP_RTP_SHORT_FRAME,
	TAP_RTP_FILE_OPEN_ERROR,
	TAP_RTP_FILE_WRITE_ERROR,
	TAP_RTP_NO_DATA
} error_type_t;

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

#define SILENCE_PCMU	(guint8)0xFF
#define SILENCE_PCMA	(guint8)0x55

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

	char *f_tempname;
	char *r_tempname;

	/* dialog associated data */
	dialog_data_t dlg;

} user_data_t;


/* Column titles. */
static const gchar *titles[11] =  {
	"Packet",
	"Sequence",
	"Time stamp",
	"Delta (ms)",
	"Jitter (ms)",
	"Skew(ms)",
	"IP BW (kbps)",
	"Marker",
	"Status",
	"Date",
	"Length"
};

#define SAVE_FORWARD_DIRECTION_MASK 0x01
#define SAVE_REVERSE_DIRECTION_MASK 0x02
#define SAVE_BOTH_DIRECTION_MASK	(SAVE_FORWARD_DIRECTION_MASK|SAVE_REVERSE_DIRECTION_MASK)

#define SAVE_NONE_FORMAT 0
#define SAVE_WAV_FORMAT	1
#define SAVE_AU_FORMAT	2
#define SAVE_SW_FORMAT	3
#define SAVE_RAW_FORMAT	4


static void on_refresh_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data);
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
	user_data->forward.statinfo.max_skew = 0;
	user_data->reversed.statinfo.max_skew = 0;
	user_data->forward.statinfo.mean_jitter = 0;
	user_data->reversed.statinfo.mean_jitter = 0;
	user_data->forward.statinfo.delta = 0;
	user_data->reversed.statinfo.delta = 0;
	user_data->forward.statinfo.diff = 0;
	user_data->reversed.statinfo.diff = 0;
	user_data->forward.statinfo.jitter = 0;
	user_data->reversed.statinfo.jitter = 0;
	user_data->forward.statinfo.skew = 0;
	user_data->reversed.statinfo.skew = 0;
	user_data->forward.statinfo.sumt = 0;
	user_data->reversed.statinfo.sumt = 0;
	user_data->forward.statinfo.sumTS = 0;
	user_data->reversed.statinfo.sumTS = 0;
	user_data->forward.statinfo.sumt2 = 0;
	user_data->reversed.statinfo.sumt2 = 0;
	user_data->forward.statinfo.sumtTS = 0;
	user_data->reversed.statinfo.sumtTS = 0;
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

	/* clear the dialog box lists */
	gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(user_data->dlg.list_fwd))));
	gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(user_data->dlg.list_rev))));

	/* reset graph info */
	dialog_graph_reset(user_data);

#ifdef HAVE_LIBPORTAUDIO
	/* reset the RTP player */
	reset_rtp_player();
#endif
	/* XXX check for error at fclose? */
	if (user_data->forward.saveinfo.fp != NULL)
		fclose(user_data->forward.saveinfo.fp);
	if (user_data->reversed.saveinfo.fp != NULL)
		fclose(user_data->reversed.saveinfo.fp);
	user_data->forward.saveinfo.fp = ws_fopen(user_data->f_tempname, "wb");
	if (user_data->forward.saveinfo.fp == NULL)
		user_data->forward.saveinfo.error_type = TAP_RTP_FILE_OPEN_ERROR;
	user_data->reversed.saveinfo.fp = ws_fopen(user_data->r_tempname, "wb");
	if (user_data->reversed.saveinfo.fp == NULL)
		user_data->reversed.saveinfo.error_type = TAP_RTP_FILE_OPEN_ERROR;
	return;
}

/****************************************************************************/
static gboolean rtp_packet_add_graph(dialog_graph_graph_t *dgg, tap_rtp_stat_t *statinfo, packet_info *pinfo, guint32 value)
{
	dialog_graph_graph_item_t *it;
	guint32 idx;
	double rtp_time;

	/*
	* We sometimes get called when dgg is disabled.
	* This is a bug since the tap listener should be removed first
	*/
	if(!dgg->display){
		return FALSE;
	}

	dgg->ud->dlg.dialog_graph.needs_redraw=TRUE;

	/*
	* Find which interval this is supposed to go in and store the
	* interval index as idx
	*/
	if (dgg->ud->dlg.dialog_graph.start_time == -1){ /* it is the first */
		dgg->ud->dlg.dialog_graph.start_time = statinfo->start_time;
	}
	rtp_time = nstime_to_msec(&pinfo->fd->rel_ts) - dgg->ud->dlg.dialog_graph.start_time;
	if(rtp_time<0){
		return FALSE;
	}
	idx = (guint32)(rtp_time)/dgg->ud->dlg.dialog_graph.interval;

	/* some sanity checks */
	if(idx>=NUM_GRAPH_ITEMS){
		return FALSE;
	}

	/* update num_items */
	if(idx > dgg->ud->dlg.dialog_graph.num_items){
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
static void add_to_list(GtkWidget *list, user_data_t * user_data, guint32 number, guint16 seq_num, guint32 timestamp,
			double delta, double jitter, double skew ,double bandwidth, gchar *status, gboolean marker,
			gchar *timeStr, guint32 pkt_len,gchar *color_str, guint32 flags);

static int rtp_packet_add_info(GtkWidget *list, user_data_t * user_data,
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
	gboolean rtp_selected = FALSE;

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
		rtp_packet_analyse(&(user_data->forward.statinfo), pinfo, rtpinfo);
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_FWD_JITTER]),
			&(user_data->forward.statinfo), pinfo,
			(guint32)(user_data->forward.statinfo.jitter*1000));
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_FWD_DIFF]),
			&(user_data->forward.statinfo), pinfo,
			(guint32)(user_data->forward.statinfo.diff*1000));
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_FWD_DELTA]),
			&(user_data->forward.statinfo), pinfo,
			(guint32)(user_data->forward.statinfo.delta*1000));
		rtp_packet_add_info(user_data->dlg.list_fwd, user_data,
			&(user_data->forward.statinfo), pinfo, rtpinfo);
		rtp_packet_save_payload(&(user_data->forward.saveinfo),
			&(user_data->forward.statinfo), pinfo, rtpinfo);
		rtp_selected = TRUE;
	}
	/* is it the reversed direction? */
	else if (user_data->ssrc_rev == rtpinfo->info_sync_src
		&& CMP_ADDRESS(&(user_data->ip_src_rev), &(pinfo->net_src)) == 0
		&& user_data->port_src_rev == pinfo->srcport
		&& CMP_ADDRESS(&(user_data->ip_dst_rev), &(pinfo->net_dst)) == 0
		&& user_data->port_dst_rev == pinfo->destport)  {
		rtp_packet_analyse(&(user_data->reversed.statinfo), pinfo, rtpinfo);
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_REV_JITTER]),
			&(user_data->reversed.statinfo), pinfo,
			(guint32)(user_data->reversed.statinfo.jitter*1000));
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_REV_DIFF]),
			&(user_data->reversed.statinfo), pinfo,
			(guint32)(user_data->reversed.statinfo.diff*1000));
		rtp_packet_add_graph(&(user_data->dlg.dialog_graph.graph[GRAPH_REV_DELTA]),
			&(user_data->reversed.statinfo), pinfo,
			(guint32)(user_data->reversed.statinfo.delta*1000));
		rtp_packet_add_info(user_data->dlg.list_rev, user_data,
			&(user_data->reversed.statinfo), pinfo, rtpinfo);
		rtp_packet_save_payload(&(user_data->reversed.saveinfo),
			&(user_data->reversed.statinfo), pinfo, rtpinfo);
		rtp_selected = TRUE;
	}
	/* add this RTP for future listening using the RTP Player*/
#ifdef HAVE_LIBPORTAUDIO
	if (rtp_selected)
		add_rtp_packet(rtpinfo, pinfo);
#endif

	return 0;
}

/*
Replaced by using the strings instead.
static const GdkColor COLOR_DEFAULT = {0, 0xffff, 0xffff, 0xffff};
static const GdkColor COLOR_ERROR = {0, 0xffff, 0xbfff, 0xbfff};
static const GdkColor COLOR_WARNING = {0, 0xffff, 0xdfff, 0xbfff};
static const GdkColor COLOR_CN = {0, 0xbfff, 0xbfff, 0xffff};
COLOR_T_EVENT g_snprintf(color_str,sizeof(color_str),"#ef8c bfff ffff");
static const GdkColor COLOR_FOREGROUND = {0, 0x0000, 0x0000, 0x0000};
*/
/****************************************************************************/
/* adds statistics information from the packet to the list */
static int rtp_packet_add_info(GtkWidget *list, user_data_t * user_data,
	tap_rtp_stat_t *statinfo, packet_info *pinfo,
	const struct _rtp_info *rtpinfo)
{
	guint16 msecs;
	gchar timeStr[32];
	struct tm *tm_tmp;
	time_t then;
	gchar status[40];
	gchar color_str[14];
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

	/* Default to using black on white text if nothing below overrides it */
	g_snprintf(color_str,sizeof(color_str),"#ffffffffffff");

	if (statinfo->pt == PT_CN) {
		g_snprintf(status,sizeof(status),"Comfort noise (PT=13, RFC 3389)");
		/* color = COLOR_CN; */
		g_snprintf(color_str,sizeof(color_str),"#bfffbfffffff");
	}
	else if (statinfo->pt == PT_CN_OLD) {
		g_snprintf(status,sizeof(status),"Comfort noise (PT=19, reserved)");
		/* color = COLOR_CN; */
		g_snprintf(color_str,sizeof(color_str),"#bfffbfffffff");
	}
	else if (statinfo->flags & STAT_FLAG_WRONG_SEQ) {
		g_snprintf(status,sizeof(status),"Wrong sequence nr.");
		/* color = COLOR_ERROR; */
		g_snprintf(color_str,sizeof(color_str),"#ffffbfffbfff");
	}
	else if (statinfo->flags & STAT_FLAG_REG_PT_CHANGE) {
		if (statinfo->flags & STAT_FLAG_PT_T_EVENT){
			g_snprintf(status,sizeof(status),"Payload changed to PT=%u telephone/event", statinfo->pt);
		}else{
			g_snprintf(status,sizeof(status),"Payload changed to PT=%u", statinfo->pt);
		}
		/* color = COLOR_WARNING; */
		g_snprintf(color_str,sizeof(color_str),"#ffffdfffbfff");
	}
	else if (statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP) {
		g_snprintf(status,sizeof(status),"Incorrect timestamp");
		/* color = COLOR_WARNING; */
		g_snprintf(color_str,sizeof(color_str),"#ffffdfffbfff");
	}
	else if ((statinfo->flags & STAT_FLAG_PT_CHANGE)
		&&  !(statinfo->flags & STAT_FLAG_FIRST)
		&&  !(statinfo->flags & STAT_FLAG_PT_CN)
		&&  (statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)
		&&  !(statinfo->flags & STAT_FLAG_MARKER)) {
		g_snprintf(status,sizeof(status),"Marker missing?");
		/* color = COLOR_WARNING; */
		g_snprintf(color_str,sizeof(color_str),"#ffffdfffbfff");
	}else if (statinfo->flags & STAT_FLAG_PT_T_EVENT){
		g_snprintf(status,sizeof(status),"PT=%u telephone/event", statinfo->pt);
		/* XXX add color? */
		/* color = COLOR_T_EVENT; */
		g_snprintf(color_str,sizeof(color_str),"#ef8cbfffffff");
	}else {
		if (statinfo->flags & STAT_FLAG_MARKER) {
			/* color = COLOR_WARNING; */
			g_snprintf(color_str,sizeof(color_str),"#ffffdfffbfff");
		}
		g_snprintf(status,sizeof(status),OK_TEXT);
	}
	/*  is this the first packet we got in this direction? */
	if (statinfo->flags & STAT_FLAG_FIRST) {
		add_to_list(list, user_data,
			pinfo->fd->num, rtpinfo->info_seq_num,
			statinfo->timestamp,
			0,
			0,
			0,
			statinfo->bandwidth,
			status,
			rtpinfo->info_marker_set,
			timeStr, pinfo->fd->pkt_len,
			color_str,
			statinfo->flags);
	}
	else {
		add_to_list(list, user_data,
			pinfo->fd->num, rtpinfo->info_seq_num,
			statinfo->timestamp,
			statinfo->delta,
			statinfo->jitter,
			statinfo->skew,
			statinfo->bandwidth,
			status,
			rtpinfo->info_marker_set,
			timeStr, pinfo->fd->pkt_len,
			color_str,
			statinfo->flags);
	}
	return 0;
}

#define MAX_SILENCE_TICKS 1000000
/****************************************************************************/
static int rtp_packet_save_payload(tap_rtp_save_info_t *saveinfo,
				   tap_rtp_stat_t *statinfo,
				   packet_info *pinfo,
				   const struct _rtp_info *rtpinfo)
{
	guint i;
	const guint8 *data;
	guint8 tmp;
	size_t nchars;

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
	* if also the RTP dissector thinks there is some information missing */
	if ((pinfo->fd->pkt_len != pinfo->fd->cap_len) &&
	    (!rtpinfo->info_all_data_present)) {
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
		!(statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP) &&
		(statinfo->delta_timestamp > (rtpinfo->info_payload_len - rtpinfo->info_padding_count)) )  {
		/* the amount of silence should be the difference between
		* the last timestamp and the current one minus x
		* x should equal the amount of information in the last frame
		* XXX not done yet */
		for(i=0; i < (statinfo->delta_timestamp - rtpinfo->info_payload_len -
			rtpinfo->info_padding_count) && i < MAX_SILENCE_TICKS; i++) {
			switch (statinfo->reg_pt) {
			case PT_PCMU:
				tmp = SILENCE_PCMU;
				break;
			case PT_PCMA:
				tmp = SILENCE_PCMA;
				break;
			default:
				tmp = 0;
				break;
			}
			nchars = fwrite(&tmp, 1, 1, saveinfo->fp);
			if (nchars != 1) {
				/* Write error or short write */
				saveinfo->saved = FALSE;
				saveinfo->error_type = TAP_RTP_FILE_WRITE_ERROR;
				return 0;
			}
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
		nchars = fwrite(data, sizeof(unsigned char), (rtpinfo->info_payload_len - rtpinfo->info_padding_count), saveinfo->fp);
		if (nchars != (rtpinfo->info_payload_len - rtpinfo->info_padding_count)) {
			/* Write error or short write */
			saveinfo->saved = FALSE;
			saveinfo->error_type = TAP_RTP_FILE_WRITE_ERROR;
			return 0;
		}
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

/****************************************************************************/
/* close the dialog window and remove the tap listener */
static void on_destroy(GtkWidget *win _U_, user_data_t *user_data)
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
	ws_remove(user_data->f_tempname);
	ws_remove(user_data->r_tempname);

#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
	/* destroy save_voice_as window if open */
	if (user_data->dlg.save_voice_as_w != NULL)
		window_destroy(user_data->dlg.save_voice_as_w);
#endif
	/* destroy graph window if open */
	if (user_data->dlg.dialog_graph.window != NULL)
		window_destroy(user_data->dlg.dialog_graph.window);

	/* disable the "switch_page" signal in the dlg, otherwise will be called when the windows is destroy and cause an exception using GTK1*/
	g_signal_handler_disconnect(user_data->dlg.notebook, user_data->dlg.notebook_signal_id);

	g_free(user_data->f_tempname);
	g_free(user_data->r_tempname);
	g_free(user_data);
}


/****************************************************************************/
static void on_notebook_switch_page(GtkNotebook *notebook _U_,
				    gpointer *page _U_,
				    gint page_num _U_,
				    user_data_t *user_data _U_)
{
	user_data->dlg.selected_list =
		(page_num==0) ? user_data->dlg.list_fwd : user_data->dlg.list_rev ;

	user_data->dlg.selected_list_row = 0;
}

/****************************************************************************/

static void on_list_select_row(GtkTreeSelection *selection,
							   user_data_t *user_data/*gpointer data */)
{
	user_data->dlg.selected_list_sel = selection;
}


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
		if (i<(MAX_GRAPHS/2)){
			g_snprintf(user_data->dlg.dialog_graph.graph[i].title,
				   sizeof(user_data->dlg.dialog_graph.graph[0].title),
				   "%s: %s:%u to %s:%u (SSRC=0x%X)",
				   graph_descr[i],
				   get_addr_name(&(user_data->ip_src_fwd)),
				   user_data->port_src_fwd,
				   get_addr_name(&(user_data->ip_dst_fwd)),
				   user_data->port_dst_fwd,
				   user_data->ssrc_fwd);
		/* it is reverse */
		} else {
			g_snprintf(user_data->dlg.dialog_graph.graph[i].title,
				   sizeof(user_data->dlg.dialog_graph.graph[0].title),
				   "%s: %s:%u to %s:%u (SSRC=0x%X)",
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
	PangoLayout  *layout;
	int label_width, label_height;
	int label_width_mid, label_height_mid;
	guint32 draw_width, draw_height;
	char label_string[15];
	GtkAllocation widget_alloc;
	cairo_t *cr;

	/* new variables */
	guint32 num_time_intervals;
	guint32 max_value;              /* max value of seen data */
	guint32 max_y;                  /* max value of the Y scale */

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
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
	cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
	cairo_set_source_rgb (cr, 1, 1, 1);
	gtk_widget_get_allocation(user_data->dlg.dialog_graph.draw_area, &widget_alloc);
	cairo_rectangle (cr,
		0,
		0,
		widget_alloc.width,
		widget_alloc.height);
	cairo_fill (cr);
	cairo_destroy (cr);

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
	 * on the width of the text labels.
	 */
	print_time_scale_string(label_string, sizeof(label_string), max_y);
	layout = gtk_widget_create_pango_layout(user_data->dlg.dialog_graph.draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);
	print_time_scale_string(label_string, sizeof(label_string), max_y*5/10);
	layout = gtk_widget_create_pango_layout(user_data->dlg.dialog_graph.draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width_mid, &label_height_mid);
	if (label_width_mid > label_width) {
		label_width = label_width_mid;
		label_height = label_height_mid;
	}

	left_x_border=10;
	right_x_border=label_width+20;
	top_y_border=10;
	bottom_y_border=label_height+20;


	/*
	 * Calculate the size of the drawing area for the actual plot
	 */
	draw_width=user_data->dlg.dialog_graph.surface_width-right_x_border-left_x_border;
	draw_height=user_data->dlg.dialog_graph.surface_height-top_y_border-bottom_y_border;


	/*
	 * Draw the y axis and labels
	 * (we always draw the y scale with 11 ticks along the axis)
	 */
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
	cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
	cairo_set_line_width (cr, 1.0);
	cairo_move_to(cr, user_data->dlg.dialog_graph.surface_width-right_x_border+1.5, top_y_border+0.5);
	cairo_line_to(cr, user_data->dlg.dialog_graph.surface_width-right_x_border+1.5, user_data->dlg.dialog_graph.surface_height-bottom_y_border+0.5);
	cairo_stroke(cr);
	cairo_destroy(cr);

	for(i=0;i<=10;i++){
		int xwidth;

		xwidth=5;
		if(!(i%5)){
			/* first, middle and last tick are slightly longer */
			xwidth=10;
		}
		/* draw the tick */
#if GTK_CHECK_VERSION(2,22,0)
		cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
		cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
		cairo_set_line_width (cr, 1.0);
		cairo_move_to(cr, 
			user_data->dlg.dialog_graph.surface_width-right_x_border+1.5, 
			user_data->dlg.dialog_graph.surface_height-bottom_y_border-draw_height*i/10+0.5);
		
		cairo_line_to(cr, 
			user_data->dlg.dialog_graph.surface_width-right_x_border+1.5+xwidth,
			user_data->dlg.dialog_graph.surface_height-bottom_y_border-draw_height*i/10+0.5);
		cairo_stroke(cr);
		cairo_destroy(cr);
		/* draw the labels */
		if(i==0){
			print_time_scale_string(label_string, sizeof(label_string), (max_y*i/10));
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
			cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
			cairo_move_to (cr, 
				user_data->dlg.dialog_graph.surface_width-right_x_border+15+label_width-lwidth, 
				user_data->dlg.dialog_graph.surface_height-bottom_y_border-draw_height*i/10-label_height/2);
			pango_cairo_show_layout (cr, layout);
			cairo_destroy (cr);
			cr = NULL;
		}
		if(i==5){
			print_time_scale_string(label_string, sizeof(label_string), (max_y*i/10));
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
			cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
			cairo_move_to (cr, 
				user_data->dlg.dialog_graph.surface_width-right_x_border+15+label_width-lwidth, 
				user_data->dlg.dialog_graph.surface_height-bottom_y_border-draw_height*i/10-label_height/2);
			pango_cairo_show_layout (cr, layout);
			cairo_destroy (cr);
			cr = NULL;
		}
		if(i==10){
			print_time_scale_string(label_string, sizeof(label_string), (max_y*i/10));
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
			cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
			cairo_move_to (cr, 
				user_data->dlg.dialog_graph.surface_width-right_x_border+15+label_width-lwidth, 
				user_data->dlg.dialog_graph.surface_height-bottom_y_border-draw_height*i/10-label_height/2);
			pango_cairo_show_layout (cr, layout);
			cairo_destroy (cr);
			cr = NULL;
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
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
	cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
	cairo_set_line_width (cr, 1.0);
	cairo_move_to(cr, left_x_border+0.5, user_data->dlg.dialog_graph.surface_height-bottom_y_border+1.5);
	cairo_line_to(cr, user_data->dlg.dialog_graph.surface_width-right_x_border+1.5,user_data->dlg.dialog_graph.surface_height-bottom_y_border+1.5);
	cairo_stroke(cr);
	cairo_destroy(cr);

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
#if GTK_CHECK_VERSION(2,22,0)
		cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
		cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
		cairo_set_line_width (cr, 1.0);
		cairo_move_to(cr, x-1-user_data->dlg.dialog_graph.pixels_per_tick/2+0.5, user_data->dlg.dialog_graph.surface_height-bottom_y_border+1.5);
		cairo_line_to(cr, x-1-user_data->dlg.dialog_graph.pixels_per_tick/2+0.5, user_data->dlg.dialog_graph.surface_height-bottom_y_border+xlen+1.5);
		cairo_stroke(cr);
		cairo_destroy(cr);

		if(xlen==17){
			if(user_data->dlg.dialog_graph.interval>=1000){
				g_snprintf(label_string, sizeof(label_string), "%ds", current_interval/1000);
			} else if(user_data->dlg.dialog_graph.interval>=100){
				g_snprintf(label_string, sizeof(label_string), "%d.%1ds", current_interval/1000,(current_interval/100)%10);
			} else if(user_data->dlg.dialog_graph.interval>=10){
				g_snprintf(label_string, sizeof(label_string), "%d.%2ds", current_interval/1000,(current_interval/10)%100);
			} else {
				g_snprintf(label_string, sizeof(label_string), "%d.%3ds", current_interval/1000,current_interval%1000);
			}
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
			cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
			cairo_move_to (cr, 
				x-1-user_data->dlg.dialog_graph.pixels_per_tick/2-lwidth/2, 
				user_data->dlg.dialog_graph.surface_height-bottom_y_border+20);
			pango_cairo_show_layout (cr, layout);
			cairo_destroy (cr);
			cr = NULL;
		}

	}






	/*
	 * Draw "x" for Sequence Errors and "m" for Marks
	 */
	/* Draw the labels Fwd and Rev */
	g_strlcpy(label_string, UTF8_LEFTWARDS_ARROW "Fwd",sizeof(label_string));
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
	cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
	cairo_move_to (cr, 
		user_data->dlg.dialog_graph.surface_width-right_x_border+33-lwidth, 
		user_data->dlg.dialog_graph.surface_height-bottom_y_border+3);
	pango_cairo_show_layout (cr, layout);
	cairo_destroy (cr);
	cr = NULL;

	g_strlcpy(label_string, UTF8_LEFTWARDS_ARROW "Rev",sizeof(label_string));
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
	cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
	cairo_move_to (cr, 
		user_data->dlg.dialog_graph.surface_width-right_x_border+33-lwidth, 
		user_data->dlg.dialog_graph.surface_height-bottom_y_border+3+9);
	pango_cairo_show_layout (cr, layout);
	cairo_destroy (cr);
	cr = NULL;

	/* Draw the marks */
	for(i=MAX_GRAPHS-1;i>=0;i--){
		guint32 interval;
		guint32 x_pos/*, prev_x_pos*/;

		/* XXX for fwd or rev, the flag info for jitter and diff is the same, and here I loop twice */
		if (!user_data->dlg.dialog_graph.graph[i].display){
			continue;
		}
		/* initialize prev x/y to the low left corner of the graph */
		/*prev_x_pos=draw_width-1-user_data->dlg.dialog_graph.pixels_per_tick*((last_interval-first_interval)/user_data->dlg.dialog_graph.interval+1)+left_x_border;*/

		for(interval=first_interval+user_data->dlg.dialog_graph.interval;interval<=last_interval;interval+=user_data->dlg.dialog_graph.interval){
			x_pos=draw_width-1-user_data->dlg.dialog_graph.pixels_per_tick*((last_interval-interval)/user_data->dlg.dialog_graph.interval+1)+left_x_border;

			if(user_data->dlg.dialog_graph.graph[i].items[interval/user_data->dlg.dialog_graph.interval].flags & (STAT_FLAG_WRONG_SEQ|STAT_FLAG_MARKER)){
				if (user_data->dlg.dialog_graph.graph[i].items[interval/user_data->dlg.dialog_graph.interval].flags & STAT_FLAG_WRONG_SEQ){
					g_strlcpy(label_string,"x",sizeof(label_string));
				} else {
					g_strlcpy(label_string,"m",sizeof(label_string));
				}

				pango_layout_set_text(layout, label_string, -1);
				pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
				cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
				cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
				cairo_move_to (cr, 
					x_pos-1-lwidth/2, 
					user_data->dlg.dialog_graph.surface_height-bottom_y_border+3+7*(i/2));
				pango_cairo_show_layout (cr, layout);
				cairo_destroy (cr);
				cr = NULL;

			}

			/*prev_x_pos=x_pos;*/
		}
	}

	g_object_unref(G_OBJECT(layout));

	/*
	 * Loop over all graphs and draw them
	 */
	for(i=MAX_GRAPHS-1;i>=0;i--){
		guint32 interval;
		guint32 x_pos, y_pos, /*prev_x_pos,*/ prev_y_pos;
	        if (!user_data->dlg.dialog_graph.graph[i].display){
			continue;
		}
		/* initialize prev x/y to the low left corner of the graph */
		/*prev_x_pos=draw_width-1-user_data->dlg.dialog_graph.pixels_per_tick*((last_interval-first_interval)/user_data->dlg.dialog_graph.interval+1)+left_x_border;*/
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
				/*prev_x_pos=x_pos;*/
				continue;
			}

			if(val){
#if GTK_CHECK_VERSION(2,22,0)
				cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
				cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
				gdk_cairo_set_source_color (cr, &user_data->dlg.dialog_graph.graph[i].color);
				cairo_set_line_width (cr, 1.0);
				cairo_move_to(cr, x_pos+0.5, draw_height-1+top_y_border+0.5);
				cairo_line_to(cr, x_pos+0.5, y_pos+0.5);
				cairo_stroke(cr);
				cairo_destroy(cr);
			}

			prev_y_pos=y_pos;
			/*prev_x_pos=x_pos;*/
		}
	}

	cr = gdk_cairo_create (gtk_widget_get_window(user_data->dlg.dialog_graph.draw_area));

#if GTK_CHECK_VERSION(2,22,0)
	cairo_set_source_surface (cr, user_data->dlg.dialog_graph.surface, 0, 0); 
#else
	gdk_cairo_set_source_pixmap (cr, user_data->dlg.dialog_graph.pixmap, 0, 0);
#endif
	cairo_rectangle (cr, 0, 0, user_data->dlg.dialog_graph.surface_width, user_data->dlg.dialog_graph.surface_height);
	cairo_fill (cr);

	cairo_destroy (cr);

	/* update the scrollbar */
	gtk_adjustment_set_upper(user_data->dlg.dialog_graph.scrollbar_adjustment, (gfloat) user_data->dlg.dialog_graph.max_interval);
	gtk_adjustment_set_step_increment(user_data->dlg.dialog_graph.scrollbar_adjustment, (gfloat) ((last_interval-first_interval)/10));
	gtk_adjustment_set_page_increment(user_data->dlg.dialog_graph.scrollbar_adjustment, (gfloat) (last_interval-first_interval));
	if((last_interval-first_interval)*100 < user_data->dlg.dialog_graph.max_interval){
		gtk_adjustment_set_page_size(user_data->dlg.dialog_graph.scrollbar_adjustment, (gfloat) (user_data->dlg.dialog_graph.max_interval/100));
	} else {
		gtk_adjustment_set_page_size(user_data->dlg.dialog_graph.scrollbar_adjustment, (gfloat) (last_interval-first_interval));
	}
	gtk_adjustment_set_value(user_data->dlg.dialog_graph.scrollbar_adjustment, last_interval - gtk_adjustment_get_page_size(user_data->dlg.dialog_graph.scrollbar_adjustment));
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
static void quit(GtkWidget *widget _U_, user_data_t *user_data)
{
	GtkWidget *bt_save = g_object_get_data(G_OBJECT(user_data->dlg.dialog_graph.window), "bt_save");
	surface_info_t *surface_info = g_object_get_data(G_OBJECT(bt_save), "surface-info");

	g_free(surface_info);
	user_data->dlg.dialog_graph.window = NULL;
}

/****************************************************************************/
static gint expose_event(GtkWidget *widget, GdkEventExpose *event)
{
	user_data_t *user_data;
	cairo_t *cr = gdk_cairo_create (gtk_widget_get_window(widget));

	user_data=(user_data_t *)g_object_get_data(G_OBJECT(widget), "user_data_t");
	if(!user_data){
		exit(10);
	}

#if GTK_CHECK_VERSION(2,22,0)
	cairo_set_source_surface (cr, user_data->dlg.dialog_graph.surface, 0, 0); 
#else
	gdk_cairo_set_source_pixmap (cr, user_data->dlg.dialog_graph.pixmap, 0, 0);
#endif
	cairo_rectangle (cr, event->area.x, event->area.y, event->area.width, event->area.height);
	cairo_fill (cr);

	cairo_destroy (cr);

	return FALSE;
}

/****************************************************************************/
static gint configure_event(GtkWidget *widget, GdkEventConfigure *event _U_)
{
	user_data_t *user_data;
	GtkWidget *bt_save;
	GtkAllocation widget_alloc;
	cairo_t *cr;
#if GTK_CHECK_VERSION(2,22,0)
	surface_info_t *surface_info = g_new(surface_info_t, 1);
#endif

	user_data=(user_data_t *)g_object_get_data(G_OBJECT(widget), "user_data_t");

	if(!user_data){
		exit(10);
	}

#if GTK_CHECK_VERSION(2,22,0)
	if(user_data->dlg.dialog_graph.surface){
		g_object_unref(user_data->dlg.dialog_graph.surface);
		user_data->dlg.dialog_graph.surface=NULL;
	}
	gtk_widget_get_allocation(widget, &widget_alloc);
	user_data->dlg.dialog_graph.surface = gdk_window_create_similar_surface (gtk_widget_get_window(widget),
			CAIRO_CONTENT_COLOR,
			widget_alloc.width,
			widget_alloc.height);
#else
	if(user_data->dlg.dialog_graph.pixmap){
		g_object_unref(user_data->dlg.dialog_graph.pixmap);
		user_data->dlg.dialog_graph.pixmap=NULL;
	}

	gtk_widget_get_allocation(widget, &widget_alloc);
	user_data->dlg.dialog_graph.pixmap=gdk_pixmap_new(gtk_widget_get_window(widget),
							  widget_alloc.width,
							  widget_alloc.height,
							  -1);
#endif
	user_data->dlg.dialog_graph.surface_width=widget_alloc.width;
	user_data->dlg.dialog_graph.surface_height=widget_alloc.height;

	bt_save = g_object_get_data(G_OBJECT(user_data->dlg.dialog_graph.window), "bt_save");
#if GTK_CHECK_VERSION(2,22,0)
	surface_info->surface = user_data->dlg.dialog_graph.surface;
	surface_info->width = widget_alloc.width;
	surface_info->height = widget_alloc.height;
	g_object_set_data(G_OBJECT(bt_save), "surface-info", surface_info);
	gtk_widget_set_sensitive(bt_save, TRUE);

	cr = cairo_create (user_data->dlg.dialog_graph.surface);
#else
	g_object_set_data(G_OBJECT(bt_save), "pixmap", user_data->dlg.dialog_graph.pixmap);
	gtk_widget_set_sensitive(bt_save, TRUE);

	cr = gdk_cairo_create (user_data->dlg.dialog_graph.pixmap);
#endif
	cairo_rectangle (cr, 0, 0, widget_alloc.width, widget_alloc.height);
	cairo_set_source_rgb (cr, 1, 1, 1);
	cairo_fill (cr);
	cairo_destroy (cr);

	dialog_graph_redraw(user_data);
	return TRUE;
}

/****************************************************************************/
static gint scrollbar_changed(GtkWidget *widget _U_, gpointer data)
{
	user_data_t *user_data=(user_data_t *)data;
	guint32 mi;

	mi=(guint32) (gtk_adjustment_get_value(user_data->dlg.dialog_graph.scrollbar_adjustment) + gtk_adjustment_get_page_size(user_data->dlg.dialog_graph.scrollbar_adjustment));
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
	g_signal_connect(user_data->dlg.dialog_graph.draw_area, "destroy", G_CALLBACK(quit), user_data);
	g_object_set_data(G_OBJECT(user_data->dlg.dialog_graph.draw_area), "user_data_t", user_data);

	gtk_widget_set_size_request(user_data->dlg.dialog_graph.draw_area, user_data->dlg.dialog_graph.surface_width, user_data->dlg.dialog_graph.surface_height);

	/* signals needed to handle backing pixmap */
	g_signal_connect(user_data->dlg.dialog_graph.draw_area, "expose_event", G_CALLBACK(expose_event), NULL);
	g_signal_connect(user_data->dlg.dialog_graph.draw_area, "configure_event", G_CALLBACK(configure_event), user_data);

	gtk_widget_show(user_data->dlg.dialog_graph.draw_area);
	gtk_box_pack_start(GTK_BOX(box), user_data->dlg.dialog_graph.draw_area, TRUE, TRUE, 0);

	/* create the associated scrollbar */
	user_data->dlg.dialog_graph.scrollbar_adjustment=(GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
	user_data->dlg.dialog_graph.scrollbar=gtk_hscrollbar_new(user_data->dlg.dialog_graph.scrollbar_adjustment);
	gtk_widget_show(user_data->dlg.dialog_graph.scrollbar);
	gtk_box_pack_start(GTK_BOX(box), user_data->dlg.dialog_graph.scrollbar, FALSE, FALSE, 0);
	g_signal_connect(user_data->dlg.dialog_graph.scrollbar_adjustment, "value_changed", G_CALLBACK(scrollbar_changed), user_data);
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
	cf_retap_packets(&cfile);
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

	g_snprintf(str, sizeof(str), "Graph %d", num);
	dgg->display_button=gtk_toggle_button_new_with_label(str);
	gtk_box_pack_start(GTK_BOX(hbox), dgg->display_button, FALSE, FALSE, 0);
	gtk_widget_show(dgg->display_button);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(dgg->display_button), dgg->display);
	g_signal_connect(dgg->display_button, "toggled", G_CALLBACK(filter_callback), dgg);

	label=gtk_label_new(dgg->title);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	gtk_widget_modify_fg(label, GTK_STATE_NORMAL, &dgg->color);
	gtk_widget_modify_fg(label, GTK_STATE_ACTIVE, &dgg->color);
	gtk_widget_modify_fg(label, GTK_STATE_PRELIGHT, &dgg->color);
	gtk_widget_modify_fg(label, GTK_STATE_SELECTED, &dgg->color);
	gtk_widget_modify_fg(label, GTK_STATE_INSENSITIVE, &dgg->color);

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
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
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
	int i;
	user_data_t *user_data;

	user_data=(user_data_t *)key;
	i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	user_data->dlg.dialog_graph.max_y_units_index=i;
	user_data->dlg.dialog_graph.max_y_units=yscale_max[i];
	dialog_graph_redraw(user_data);
}

/****************************************************************************/
static void pixels_per_tick_select(GtkWidget *item, gpointer key)
{
	int i;
	user_data_t *user_data;

	user_data=(user_data_t *)key;
	i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	user_data->dlg.dialog_graph.pixels_per_tick_index=i;
	user_data->dlg.dialog_graph.pixels_per_tick=pixels_per_tick[i];
	dialog_graph_redraw(user_data);
}

/****************************************************************************/
static void tick_interval_select(GtkWidget *item, gpointer key)
{
	int i;
	user_data_t *user_data;

	user_data=(user_data_t *)key;
	i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	user_data->dlg.dialog_graph.interval_index=i;
	user_data->dlg.dialog_graph.interval=tick_interval_values[i];
	cf_retap_packets(&cfile);
	dialog_graph_redraw(user_data);
}

/****************************************************************************/
static GtkWidget *
create_yscale_max_menu_items(user_data_t* user_data)
{
	char str[15];
	GtkWidget *combo_box;
	int i;

	combo_box = gtk_combo_box_text_new();

	for(i=0;i<MAX_YSCALE;i++){
		if(yscale_max[i]==AUTO_MAX_YSCALE){
			g_strlcpy(str,"Auto",sizeof(str));
		} else if (yscale_max[i] < 1000000) {
			g_snprintf(str, sizeof(str), "%u ms", yscale_max[i]/1000);
		} else {
			g_snprintf(str, sizeof(str), "%u s", yscale_max[i]/1000000);
		}
		 gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), user_data->dlg.dialog_graph.max_y_units_index);
	g_signal_connect(combo_box, "changed", G_CALLBACK(yscale_select), (gpointer)user_data);

	return combo_box;
}

/****************************************************************************/
static GtkWidget *
create_pixels_per_tick_menu_items(user_data_t *user_data)
{
	char str[5];
	GtkWidget *combo_box;
	int i;

	combo_box = gtk_combo_box_text_new();

	for(i=0;i<MAX_PIXELS_PER_TICK;i++){
		g_snprintf(str, sizeof(str), "%u", pixels_per_tick[i]);
		 gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), user_data->dlg.dialog_graph.pixels_per_tick_index);

	g_signal_connect(combo_box, "changed", G_CALLBACK(pixels_per_tick_select), (gpointer)user_data);

	return combo_box;
}

/****************************************************************************/
static GtkWidget *
create_tick_interval_menu_items(user_data_t *user_data)
{
	GtkWidget *combo_box;
	char str[15];
	int i;

	combo_box = gtk_combo_box_text_new();

	for(i=0;i<MAX_TICK_VALUES;i++){
		if(tick_interval_values[i]>=1000){
			g_snprintf(str, sizeof(str), "%u sec", tick_interval_values[i]/1000);
		} else if(tick_interval_values[i]>=100){
			g_snprintf(str, sizeof(str), "0.%1u sec", (tick_interval_values[i]/100)%10);
		} else if(tick_interval_values[i]>=10){
			g_snprintf(str, sizeof(str), "0.%02u sec", (tick_interval_values[i]/10)%10);
		} else {
			g_snprintf(str, sizeof(str), "0.%03u sec", (tick_interval_values[i])%10);
		}
		 gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), user_data->dlg.dialog_graph.interval_index);
	g_signal_connect(combo_box, "changed", G_CALLBACK(tick_interval_select), (gpointer)user_data);

	return combo_box;
}

/****************************************************************************/
static void create_ctrl_menu(user_data_t* user_data, GtkWidget *box, const char *name, GtkWidget *(*func)(user_data_t* user_data))
{
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *combo_box;

	hbox=gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	label=gtk_label_new(name);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	combo_box = (*func)(user_data);
	gtk_box_pack_end(GTK_BOX(hbox), combo_box, FALSE, FALSE, 0);
	gtk_widget_show(combo_box);
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
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
	gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_END);
	gtk_widget_show(vbox);

	create_ctrl_menu(user_data, vbox, "Tick interval:", create_tick_interval_menu_items);
	create_ctrl_menu(user_data, vbox, "Pixels per tick:", create_pixels_per_tick_menu_items);

 	frame = gtk_frame_new("Y Axis");
	gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
	gtk_widget_show(frame);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
 	gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
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
	GtkWidget *bt_save;

	/* create the main window */
	user_data->dlg.dialog_graph.window=dlg_window_new("I/O Graphs");   /* transient_for top_level */

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(user_data->dlg.dialog_graph.window), vbox);
	gtk_widget_show(vbox);

	create_draw_area(user_data, vbox);

	hbox=gtk_hbox_new(FALSE, 3);
	gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_box_set_child_packing(GTK_BOX(vbox), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	create_filter_area(user_data, hbox);
	create_ctrl_area(user_data, hbox);

	dialog_graph_set_title(user_data);

	hbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_SAVE, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	bt_close = g_object_get_data(G_OBJECT(hbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(user_data->dlg.dialog_graph.window, bt_close, window_cancel_button_cb);

	bt_save = g_object_get_data(G_OBJECT(hbox), GTK_STOCK_SAVE);
	gtk_widget_set_sensitive(bt_save, FALSE);
	gtk_widget_set_tooltip_text(bt_save, "Save the displayed graph to a file");
	g_signal_connect(bt_save, "clicked", G_CALLBACK(pixmap_save_cb), NULL);
	g_object_set_data(G_OBJECT(user_data->dlg.dialog_graph.window), "bt_save", bt_save);

	g_signal_connect(user_data->dlg.dialog_graph.window, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

	gtk_widget_show(user_data->dlg.dialog_graph.window);
	window_present(user_data->dlg.dialog_graph.window);

}


/****************************************************************************/
static void on_graph_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data)
{
	if (user_data->dlg.dialog_graph.window != NULL) {
		/* There's already a graph window; reactivate it. */
		reactivate_window(user_data->dlg.dialog_graph.window);
		return;
	}

	dialog_graph_init_window(user_data);

}

/****************************************************************************/

static void on_goto_bt_clicked_lst(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	guint fnumber;

	selection = user_data->dlg.selected_list_sel;

	if (selection==NULL)
		return;

	if (gtk_tree_selection_get_selected (selection, &model, &iter)){
		gtk_tree_model_get (model, &iter, PACKET_COLUMN, &fnumber, -1);
		cf_goto_frame(&cfile, fnumber);
	}

}

static void draw_stat(user_data_t *user_data);

/****************************************************************************/
/* re-dissects all packets */
static void on_refresh_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data)
{
	GString *error_string;

	/* remove tap listener */
	protect_thread_critical_region();
	remove_tap_listener(user_data);
	unprotect_thread_critical_region();

	/* register tap listener */
	error_string = register_tap_listener("rtp", user_data, NULL, 0,
		rtp_reset, rtp_packet, rtp_draw);
	if (error_string != NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
			g_string_free(error_string, TRUE);
		return;
	}

	/* retap all packets */
	cf_retap_packets(&cfile);

	/* draw statistics info */
	draw_stat(user_data);

}

#ifdef HAVE_LIBPORTAUDIO
/****************************************************************************/
static void
on_player_bt_clicked(GtkButton *button _U_, gpointer user_data _U_)
{
	/*rtp_player_init(voip_calls_get_info());*/
	rtp_player_init(NULL);
}
#endif /* HAVE_LIBPORTAUDIO */

static void on_next_bt_clicked_list(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *text;
	GtkTreeSelection *selection;
	GtkTreePath *path;

	selection = user_data->dlg.selected_list_sel;

	if (selection==NULL)
		return;

try_again:
	if (gtk_tree_selection_get_selected (selection, &model, &iter)){
		while (gtk_tree_model_iter_next (model,&iter)) {
			gtk_tree_model_get (model, &iter, STATUS_COLUMN, &text, -1);
			if (strcmp(text, OK_TEXT) != 0) {
				gtk_tree_selection_select_iter (selection, &iter);
				path = gtk_tree_model_get_path(model, &iter);
				gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW( user_data->dlg.selected_list),
						path,
						NULL, FALSE, 0, 0);
				gtk_tree_path_free(path);
				g_free (text);
				return;
			}
			g_free (text);
		}
		/* wrap around */
		if (user_data->dlg.number_of_nok>1){
			/* Get the first iter and select it before starting over */
			gtk_tree_model_get_iter_first(model, &iter);
			gtk_tree_selection_select_iter (selection, &iter);
			goto try_again;
		}
	}
}


/****************************************************************************/
/* when we want to save the information */
static gboolean save_csv_as_ok_cb(GtkWidget *w _U_, gpointer fc /*user_data_t *user_data*/)
{
	gchar *g_dest;
	GtkWidget *rev, *forw, *both;
	user_data_t *user_data;

	GtkListStore *store;
	GtkTreeIter iter;
	GtkTreeModel *model;
	gboolean more_items = TRUE;

	/* To Hold data from the list row */
	guint32			packet;		/* Packet			*/
	guint16			sequence;	/* Sequence			*/
	guint32			timestamp;	/* timestamp			*/
	gfloat			delta;		/* Delta(ms)			*/
	gfloat			jitter;		/* Jitter(ms)			*/
	gfloat			skew;		/* Skew(ms)			*/
	gfloat			ipbw;		/* IP BW(kbps)			*/
	gboolean		marker;		/* Marker			*/
	char *			status_str;	/* Status			*/
	char *			date_str;	/* Date				*/
	guint			length;		/* Length			*/


	FILE *fp;
	int j;

	g_dest = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fc));

	/* Perhaps the user specified a directory instead of a file.
	 * Check whether they did.
	 */
	if (test_for_directory(g_dest) == EISDIR) {
		/* It's a directory - set the file selection box to display it. */
		set_last_open_dir(g_dest);
		g_free(g_dest);
		file_selection_set_current_folder(fc, get_last_open_dir());
		gtk_file_chooser_set_current_name(fc, "");
		return FALSE; /* run the dialog again */
	}

	rev  = (GtkWidget*)g_object_get_data(G_OBJECT(fc), "reversed_rb");
	forw = (GtkWidget*)g_object_get_data(G_OBJECT(fc), "forward_rb");
	both = (GtkWidget*)g_object_get_data(G_OBJECT(fc), "both_rb");
	user_data = (user_data_t*)g_object_get_data(G_OBJECT(fc), "user_data");

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(forw)) || gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(both))) {
		fp = ws_fopen(g_dest, "w");
		if (fp == NULL) {
			open_failure_alert_box(g_dest, errno, TRUE);
			g_free(g_dest);
			return TRUE; /* we're done */
		}

		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(both))) {
			fprintf(fp, "Forward\n");
			if (ferror(fp)) {
				write_failure_alert_box(g_dest, errno);
				fclose(fp);
				g_free(g_dest);
				return TRUE; /* we're done */
			}
		}

		for(j = 0; j < NUM_COLS; j++) {
			if (j == 0) {
				fprintf(fp,"\"%s\"",titles[j]);
			} else {
				fprintf(fp,",\"%s\"",titles[j]);
			}
		}
		fprintf(fp,"\n");
		if (ferror(fp)) {
			write_failure_alert_box(g_dest, errno);
			fclose(fp);
			g_free(g_dest);
			return TRUE;
		}
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(user_data->dlg.list_fwd));
		store = GTK_LIST_STORE(model);
		if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {

			 while (more_items){
				 gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
						    PACKET_COLUMN,    &packet,
						    SEQUENCE_COLUMN,  &sequence,
						    TIMESTAMP_COLUMN, &timestamp,
						    DELTA_COLUMN,     &delta,
						    JITTER_COLUMN,    &jitter,
						    SKEW_COLUMN,      &skew,
						    IPBW_COLUMN,      &ipbw,
						    MARKER_COLUMN,    &marker,
						    STATUS_COLUMN,    &status_str,
						    DATE_COLUMN,      &date_str,
						    LENGTH_COLUMN,    &length,
					 -1);
				 fprintf(fp, "\"%u\"",    packet);
				 fprintf(fp, ",\"%u\"",   sequence);
				 fprintf(fp, ",\"%u\"",   timestamp);
				 fprintf(fp, ",\"%.2f\"", delta);
				 fprintf(fp, ",\"%.2f\"", jitter);
				 fprintf(fp, ",\"%.2f\"", skew);
				 fprintf(fp, ",\"%.2f\"", ipbw);
				 fprintf(fp, ",\"%s\"",   marker? "SET" : "");
				 fprintf(fp, ",\"%s\"",   status_str);
				 fprintf(fp, ",\"%s\"",   date_str);
				 fprintf(fp, ",\"%u\"",   length);
				 fprintf(fp,"\n");
				 g_free(status_str);
				 g_free(date_str);
				 if (ferror(fp)) {
					 write_failure_alert_box(g_dest, errno);
					 fclose(fp);
					 g_free(g_dest);
					 return TRUE; /* we're done */
				 }

	 			 more_items = gtk_tree_model_iter_next (model,&iter);
			 }
		 }

		if (fclose(fp) == EOF) {
			write_failure_alert_box(g_dest, errno);
			g_free(g_dest);
			return TRUE; /* we're done */
		}
	}

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rev)) || gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(both))) {

		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(both))) {
			fp = ws_fopen(g_dest, "a");
			if (fp == NULL) {
				open_failure_alert_box(g_dest, errno, TRUE);
				g_free(g_dest);
				return TRUE; /* we're done */
			}
			fprintf(fp, "\nReverse\n");
			if (ferror(fp)) {
				write_failure_alert_box(g_dest, errno);
				fclose(fp);
				g_free(g_dest);
				return TRUE; /* we're done */
			}
		} else {
			fp = ws_fopen(g_dest, "w");
			if (fp == NULL) {
				open_failure_alert_box(g_dest, errno, TRUE);
				g_free(g_dest);
				return TRUE; /* we're done */
			}
		}
		for(j = 0; j < NUM_COLS; j++) {
			if (j == 0) {
				fprintf(fp,"\"%s\"",titles[j]);
			} else {
				fprintf(fp,",\"%s\"",titles[j]);
			}
		}
		fprintf(fp,"\n");
		if (ferror(fp)) {
			write_failure_alert_box(g_dest, errno);
			fclose(fp);
			g_free(g_dest);
			return TRUE; /* we're done */
		}
		model = gtk_tree_view_get_model(GTK_TREE_VIEW(user_data->dlg.list_rev));
		store = GTK_LIST_STORE(model);
		if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {

			more_items = TRUE;

			 while (more_items){
				 gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					 PACKET_COLUMN,    &packet,
					 SEQUENCE_COLUMN,  &sequence,
					 TIMESTAMP_COLUMN, &timestamp,
					 DELTA_COLUMN,     &delta,
					 JITTER_COLUMN,    &jitter,
					 SKEW_COLUMN,      &skew,
					 IPBW_COLUMN,      &ipbw,
					 MARKER_COLUMN,    &marker,
					 STATUS_COLUMN,    &status_str,
					 DATE_COLUMN,      &date_str,
					 LENGTH_COLUMN,    &length,
					 -1);
				 fprintf(fp, "\"%u\"",    packet);
				 fprintf(fp, ",\"%u\"",   sequence);
				 fprintf(fp, ",\"%u\"",   timestamp);
				 fprintf(fp, ",\"%.2f\"", delta);
				 fprintf(fp, ",\"%.2f\"", jitter);
				 fprintf(fp, ",\"%.2f\"", skew);
				 fprintf(fp, ",\"%.2f\"", ipbw);
				 fprintf(fp, ",\"%s\"",   marker? "SET" : "");
				 fprintf(fp, ",\"%s\"",   status_str);
				 fprintf(fp, ",\"%s\"",   date_str);
				 fprintf(fp, ",\"%u\"",   length);
				 fprintf(fp,"\n");
				 g_free(status_str);
				 g_free(date_str);
				 if (ferror(fp)) {
					 write_failure_alert_box(g_dest, errno);
					 fclose(fp);
					 g_free(g_dest);
					 return TRUE; /* we're done */
				 }

				 more_items = gtk_tree_model_iter_next (model,&iter);
			 }
		 }
		if (fclose(fp) == EOF) {
			write_failure_alert_box(g_dest, errno);
			g_free(g_dest);
			return TRUE; /* we're done */
		}
	}

	g_free(g_dest);
	return TRUE; /* we're done */
}

static void save_csv_as_destroy_cb(GtkWidget *win _U_, user_data_t *user_data)
{
	user_data->dlg.save_csv_as_w = NULL;
}

/* when the user wants to save the csv information in a file */
static void save_csv_as_cb(GtkWidget *bt _U_, user_data_t *user_data)
{
	GtkWidget *vertb;
	GtkWidget *table1;
	GtkWidget *label_format;
	GtkWidget *channels_label;
	GtkWidget *forward_rb;
	GtkWidget *reversed_rb;
	GtkWidget *both_rb;

#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
	if (user_data->dlg.save_csv_as_w != NULL) {
		/* There's already a Save CSV info dialog box; reactivate it. */
		reactivate_window(user_data->dlg.save_csv_as_w);
		return;
	}
#endif
	user_data->dlg.save_csv_as_w = gtk_file_chooser_dialog_new("Wireshark: Save Data As CSV",
								   GTK_WINDOW(user_data->dlg.notebook),
								   GTK_FILE_CHOOSER_ACTION_SAVE,
								   GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
								   GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
								   NULL);
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(user_data->dlg.save_csv_as_w), TRUE);
	gtk_window_set_transient_for(GTK_WINDOW(user_data->dlg.save_csv_as_w),GTK_WINDOW(user_data->dlg.window));

	/* Container for each row of widgets */
	vertb = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vertb), 5);
	gtk_file_chooser_set_extra_widget(GTK_FILE_CHOOSER(user_data->dlg.save_csv_as_w), vertb);
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

	gtk_misc_set_alignment (GTK_MISC (label_format), 0, 0.5f);


	channels_label = gtk_label_new ("Channels:    ");
	gtk_widget_show (channels_label);
	gtk_table_attach (GTK_TABLE (table1), channels_label, 0, 1, 1, 2,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (channels_label), 0, 0.5f);

	forward_rb = gtk_radio_button_new_with_label (NULL, "forward  ");
	gtk_widget_show (forward_rb);
	gtk_table_attach (GTK_TABLE (table1), forward_rb, 1, 2, 1, 2,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);

	reversed_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(forward_rb), "reversed    ");
	gtk_widget_show (reversed_rb);
	gtk_table_attach (GTK_TABLE (table1), reversed_rb, 2, 3, 1, 2,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);

	both_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(forward_rb), "both");
	gtk_widget_show (both_rb);
	gtk_table_attach (GTK_TABLE (table1), both_rb, 3, 4, 1, 2,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(both_rb), TRUE);

	g_object_set_data(G_OBJECT(user_data->dlg.save_csv_as_w), "forward_rb", forward_rb);
	g_object_set_data(G_OBJECT(user_data->dlg.save_csv_as_w), "reversed_rb", reversed_rb);
	g_object_set_data(G_OBJECT(user_data->dlg.save_csv_as_w), "both_rb", both_rb);
	g_object_set_data(G_OBJECT(user_data->dlg.save_csv_as_w), "user_data", user_data);

	g_signal_connect(user_data->dlg.save_csv_as_w, "delete_event",
		G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(user_data->dlg.save_csv_as_w, "destroy",
		G_CALLBACK(save_csv_as_destroy_cb), user_data);

	gtk_widget_show(user_data->dlg.save_csv_as_w);
	window_present(user_data->dlg.save_csv_as_w);

	/* "Run" the GtkFileChooserDialog.                                              */
	/* Upon exit: If "Accept" run the OK callback.                                  */
	/*            If the OK callback returns with a FALSE status, re-run the dialog.*/
	/*            Destroy the window.                                               */
	/* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
	/*      return with a TRUE status so that the dialog window will be destroyed.  */
	/*      Trying to re-run the dialog after popping up an alert box will not work */
	/*       since the user will not be able to dismiss the alert box.              */
	/*      The (somewhat unfriendly) effect: the user must re-invoke the           */
	/*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
	/*                                                                              */
	/*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
	/*            GtkFileChooserDialog.                                             */
	while (gtk_dialog_run(GTK_DIALOG(user_data->dlg.save_csv_as_w)) == GTK_RESPONSE_ACCEPT) {
		if (save_csv_as_ok_cb(NULL, user_data->dlg.save_csv_as_w)) {
			break; /* we're done */
		}
	}
	window_destroy(user_data->dlg.save_csv_as_w);
}


/****************************************************************************/
static void save_voice_as_destroy_cb(GtkWidget *win _U_, user_data_t *user_data)
{
	/* Note that we no longer have a Save voice info dialog box. */
	user_data->dlg.save_voice_as_w = NULL;
}

/****************************************************************************/
/* here we save it into a file that user specified */
/* XXX what about endians here? could go something wrong? */

static gboolean copy_file(gchar *dest, gint channels, gint format, user_data_t *user_data)
{
	FILE *to_stream, *forw_stream, *rev_stream;
	size_t fwritten, rwritten;
	int f_rawvalue, r_rawvalue, rawvalue;
	gint16 sample;
	gchar pd[4];
	guint32 f_write_silence = 0;
	guint32 r_write_silence = 0;
	progdlg_t *progbar;
	guint32 progbar_count, progbar_quantum, progbar_nextstep = 0, count = 0;
	gboolean stop_flag = FALSE;
	size_t nchars;
	gboolean ret_val;

	forw_stream = ws_fopen(user_data->f_tempname, "rb");
	if (forw_stream == NULL)
		return FALSE;
	rev_stream = ws_fopen(user_data->r_tempname, "rb");
	if (rev_stream == NULL) {
		fclose(forw_stream);
		return FALSE;
	}

	/* open file for saving */
	to_stream = ws_fopen(dest, "wb");
	if (to_stream == NULL) {
		fclose(forw_stream);
		fclose(rev_stream);
		return FALSE;
	}

	progbar = create_progress_dlg("Saving voice in a file", dest, TRUE, &stop_flag);

	if	(format == SAVE_AU_FORMAT) /* au format */
	{
		/* First we write the .au header. XXX Hope this is endian independent */
		/* the magic word 0x2e736e64 == .snd */
		phtonl(pd, 0x2e736e64);
		nchars = fwrite(pd, 1, 4, to_stream);
		if (nchars != 4)
			goto copy_file_err;
		/* header offset == 24 bytes */
		phtonl(pd, 24);
		nchars = fwrite(pd, 1, 4, to_stream);
		if (nchars != 4)
			goto copy_file_err;
		/* total length; it is permitted to set this to 0xffffffff */
		phtonl(pd, -1);
		nchars = fwrite(pd, 1, 4, to_stream);
		if (nchars != 4)
			goto copy_file_err;
		/* encoding format == 16-bit linear PCM */
		phtonl(pd, 3);
		nchars = fwrite(pd, 1, 4, to_stream);
		if (nchars != 4)
			goto copy_file_err;
		/* sample rate == 8000 Hz */
		phtonl(pd, 8000);
		nchars = fwrite(pd, 1, 4, to_stream);
		if (nchars != 4)
			goto copy_file_err;
		/* channels == 1 */
		phtonl(pd, 1);
		nchars = fwrite(pd, 1, 4, to_stream);
		if (nchars != 4)
			goto copy_file_err;


		switch (channels) {
			/* only forward direction */
			case SAVE_FORWARD_DIRECTION_MASK: {
				progbar_count = user_data->forward.saveinfo.count;
				progbar_quantum = user_data->forward.saveinfo.count/100;
				while ((f_rawvalue = getc(forw_stream)) != EOF) {
					if(stop_flag)
						break;
					if((count > progbar_nextstep) && (count <= progbar_count)) {
						update_progress_dlg(progbar,
							(gfloat) count/progbar_count, "Saving");
						progbar_nextstep = progbar_nextstep + progbar_quantum;
					}
					count++;

					if (user_data->forward.statinfo.pt == PT_PCMU){
						sample = ulaw2linear((unsigned char)f_rawvalue);
						phtons(pd, sample);
					}
					else if(user_data->forward.statinfo.pt == PT_PCMA){
						sample = alaw2linear((unsigned char)f_rawvalue);
						phtons(pd, sample);
					}
					else{
						goto copy_file_err;
					}

					fwritten = fwrite(pd, 1, 2, to_stream);
					if (fwritten < 2) {
						goto copy_file_err;
					}
				}
				break;
			}
			/* only reversed direction */
			case SAVE_REVERSE_DIRECTION_MASK: {
				progbar_count = user_data->reversed.saveinfo.count;
				progbar_quantum = user_data->reversed.saveinfo.count/100;
				while ((r_rawvalue = getc(rev_stream)) != EOF) {
					if(stop_flag)
						break;
					if((count > progbar_nextstep) && (count <= progbar_count)) {
						update_progress_dlg(progbar,
							(gfloat) count/progbar_count, "Saving");
						progbar_nextstep = progbar_nextstep + progbar_quantum;
					}
					count++;

					if (user_data->reversed.statinfo.pt == PT_PCMU){
						sample = ulaw2linear((unsigned char)r_rawvalue);
						phtons(pd, sample);
					}
					else if(user_data->reversed.statinfo.pt == PT_PCMA){
						sample = alaw2linear((unsigned char)r_rawvalue);
						phtons(pd, sample);
					}
					else{
						goto copy_file_err;
					}

					rwritten = fwrite(pd, 1, 2, to_stream);
					if (rwritten < 2) {
						goto copy_file_err;
					}
				}
				break;
			}
			/* both directions */
			case SAVE_BOTH_DIRECTION_MASK: {
				(user_data->forward.saveinfo.count > user_data->reversed.saveinfo.count) ?
						(progbar_count = user_data->forward.saveinfo.count) :
							(progbar_count = user_data->reversed.saveinfo.count);
				progbar_quantum = progbar_count/100;
				/* since conversation in one way can start later than in the other one,
				 * we have to write some silence information for one channel */
				if (user_data->forward.statinfo.start_time > user_data->reversed.statinfo.start_time) {
					f_write_silence = (guint32)
						((user_data->forward.statinfo.start_time-user_data->reversed.statinfo.start_time)*(8000/1000));
				}
				else if (user_data->forward.statinfo.start_time < user_data->reversed.statinfo.start_time) {
					r_write_silence = (guint32)
						((user_data->reversed.statinfo.start_time-user_data->forward.statinfo.start_time)*(8000/1000));
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
						r_rawvalue = getc(rev_stream);
						switch (user_data->forward.statinfo.reg_pt) {
						case PT_PCMU:
							f_rawvalue = SILENCE_PCMU;
							break;
						case PT_PCMA:
							f_rawvalue = SILENCE_PCMA;
							break;
						default:
							f_rawvalue = 0;
							break;
						}
						f_write_silence--;
					}
					else if(r_write_silence > 0) {
						f_rawvalue = getc(forw_stream);
						switch (user_data->reversed.statinfo.reg_pt) {
						case PT_PCMU:
							r_rawvalue = SILENCE_PCMU;
							break;
						case PT_PCMA:
							r_rawvalue = SILENCE_PCMA;
							break;
						default:
							r_rawvalue = 0;
							break;
						}
						r_write_silence--;
					}
					else {
						f_rawvalue = getc(forw_stream);
						r_rawvalue = getc(rev_stream);
					}
					if ((r_rawvalue == EOF) && (f_rawvalue == EOF))
						break;
					if ((user_data->forward.statinfo.pt == PT_PCMU) && (user_data->reversed.statinfo.pt == PT_PCMU)){
						sample = (ulaw2linear((unsigned char)r_rawvalue) + ulaw2linear((unsigned char)f_rawvalue)) / 2;
						phtons(pd, sample);
					}
					else if((user_data->forward.statinfo.pt == PT_PCMA) && (user_data->reversed.statinfo.pt == PT_PCMA)){
						sample = (alaw2linear((unsigned char)r_rawvalue) + alaw2linear((unsigned char)f_rawvalue)) / 2;
						phtons(pd, sample);
					}
					else
					{
						goto copy_file_err;
					}


					rwritten = fwrite(pd, 1, 2, to_stream);
					if (rwritten < 2) {
						goto copy_file_err;
					}
				}
			}
		}
	}
	else if (format == SAVE_RAW_FORMAT)	/* raw format */
	{
		FILE *stream;
		switch (channels) {
			/* only forward direction */
			case SAVE_FORWARD_DIRECTION_MASK: {
				progbar_count = user_data->forward.saveinfo.count;
				progbar_quantum = user_data->forward.saveinfo.count/100;
				stream = forw_stream;
				break;
			}
			/* only reversed direction */
			case SAVE_REVERSE_DIRECTION_MASK: {
				progbar_count = user_data->reversed.saveinfo.count;
				progbar_quantum = user_data->reversed.saveinfo.count/100;
				stream = rev_stream;
				break;
			}
			default: {
				goto copy_file_err;
			}
		}



		/* XXX how do you just copy the file? */
		while ((rawvalue = getc(stream)) != EOF) {
			if(stop_flag)
				break;
			if((count > progbar_nextstep) && (count <= progbar_count)) {
				update_progress_dlg(progbar,
					(gfloat) count/progbar_count, "Saving");
				progbar_nextstep = progbar_nextstep + progbar_quantum;
			}
			count++;

			if (putc(rawvalue, to_stream) == EOF) {
				goto copy_file_err;
			}
		}
	}

	ret_val = TRUE;
	goto copy_file_xit;

copy_file_err:
	ret_val = FALSE;
	goto copy_file_xit;

copy_file_xit:
	destroy_progress_dlg(progbar);
	fclose(forw_stream);
	fclose(rev_stream);
	fclose(to_stream);
	return ret_val;
}


/****************************************************************************/
/* the user wants to save in a file */
/* XXX support for different formats is currently commented out */
static gboolean save_voice_as_ok_cb(GtkWidget *w _U_, gpointer fc)
{
	gchar *g_dest;
	/*GtkWidget *wav, *sw;*/
	GtkWidget *au, *raw;
	GtkWidget *rev, *forw, *both;
	user_data_t *user_data;
	gint channels, format;

	g_dest = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fc));

	/* Perhaps the user specified a directory instead of a file.
	 * Check whether they did.
	 */
	if (test_for_directory(g_dest) == EISDIR) {
		/* It's a directory - set the file selection box to display it. */
		set_last_open_dir(g_dest);
		g_free(g_dest);
		file_selection_set_current_folder(fc, get_last_open_dir());
		gtk_file_chooser_set_current_name(fc, "");
		return FALSE; /* run the dialog again */
	}

#if 0
	wav  = (GtkWidget *)g_object_get_data(G_OBJECT(fc), "wav_rb");
	sw   = (GtkWidget *)g_object_get_data(G_OBJECT(fc), "sw_rb");
#endif
	au   = (GtkWidget *)g_object_get_data(G_OBJECT(fc), "au_rb");
	raw  = (GtkWidget *)g_object_get_data(G_OBJECT(fc), "raw_rb");
	rev  = (GtkWidget *)g_object_get_data(G_OBJECT(fc), "reversed_rb");
	forw = (GtkWidget *)g_object_get_data(G_OBJECT(fc), "forward_rb");
	both = (GtkWidget *)g_object_get_data(G_OBJECT(fc), "both_rb");
	user_data = (user_data_t *)g_object_get_data(G_OBJECT(fc), "user_data");

	/* XXX user clicks the ok button, but we know we can't save the voice info because f.e.
	* we don't support that codec. So we pop up a warning. Maybe it would be better to
	* disable the ok button or disable the buttons for direction if only one is not ok. The
	* problem is if we open the save voice dialog and then click the refresh button and maybe
	* the state changes, so we can't save anymore. In this case we should be able to update
	* the buttons. For now it is easier if we put the warning when the ok button is pressed.
	*/

	/* we can not save in both directions */
	if ((user_data->forward.saveinfo.saved == FALSE) && (user_data->reversed.saveinfo.saved == FALSE) && (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (both)))) {
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
		g_free(g_dest);
		return TRUE; /* we're done */
	}
	/* we can not save forward direction */
	else if ((user_data->forward.saveinfo.saved == FALSE) && ((gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (forw))) ||
		(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (both))))) {
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
		g_free(g_dest);
		return TRUE; /* we're done */
	}
	/* we can not save reversed direction */
	else if ((user_data->reversed.saveinfo.saved == FALSE) && ((gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (rev))) ||
		(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (both))))) {
		if (user_data->reversed.saveinfo.error_type == TAP_RTP_WRONG_CODEC)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: Unsupported codec!");
		else if (user_data->reversed.saveinfo.error_type == TAP_RTP_WRONG_LENGTH)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: Wrong length of captured packets!");
		else if (user_data->reversed.saveinfo.error_type == TAP_RTP_PADDING_ERROR)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: RTP data with padding!");
		else if (user_data->reversed.saveinfo.error_type == TAP_RTP_SHORT_FRAME)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: Not all data in all packets was captured!");
		else if (user_data->reversed.saveinfo.error_type == TAP_RTP_NO_DATA)
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: No RTP data!");
		else
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save reversed direction in a file: File I/O problem!");
		g_free(g_dest);
		return TRUE; /* we're done */
	}

#if 0
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (wav)))
		format = SAVE_WAV_FORMAT;
	else
#endif
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (au)))
		format = SAVE_AU_FORMAT;
#if 0
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (sw)))
		format = SAVE_SW_FORMAT;
#endif
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (raw)))
		format = SAVE_RAW_FORMAT;
	else
		format = SAVE_NONE_FORMAT;

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (rev)))
		channels = SAVE_REVERSE_DIRECTION_MASK;
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (both)))
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
			g_free(g_dest);
			return TRUE; /* we're done */
		}
		if ((channels & SAVE_REVERSE_DIRECTION_MASK) && (user_data->reversed.statinfo.pt != PT_PCMA) && (user_data->reversed.statinfo.pt != PT_PCMU)){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Can't save in a file: saving in au format supported only for alaw/ulaw streams");
			g_free(g_dest);
			return TRUE; /* we're done */
		}
		/* make sure pt's don't differ */
		if ((channels == SAVE_BOTH_DIRECTION_MASK) && (user_data->forward.statinfo.pt != user_data->reversed.statinfo.pt)){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Can't save in a file: Forward and reverse direction differ in type");
			g_free(g_dest);
			return TRUE; /* we're done */
		}
	}
	else if (format == SAVE_RAW_FORMAT)
	{
		/* can't save raw in both directions */
		if (channels == SAVE_BOTH_DIRECTION_MASK){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Can't save in a file: Unable to save raw data in both directions");
			g_free(g_dest);
			return TRUE; /* we're done */
		}
	}
	else
	{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't save in a file: Invalid save format");
		g_free(g_dest);
		return TRUE; /* we're done */
	}

	if(!copy_file(g_dest, channels, format, user_data)) {
		/* XXX - report the error type! */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"An error occurred while saving voice in a file!");
		g_free(g_dest);
		return TRUE; /* we're done */
	}

	g_free(g_dest);
	return TRUE; /* we're done */
}

/****************************************************************************/
/* when the user wants to save the voice information in a file */
/* XXX support for different formats is currently commented out */
static void on_save_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data)
{
	GtkWidget *vertb;
	GtkWidget *table1;
	GtkWidget *label_format;
	GtkWidget *channels_label;
	GtkWidget *forward_rb;
	GtkWidget *reversed_rb;
	GtkWidget *both_rb;
	/*GtkWidget *wav_rb;  GtkWidget *sw_rb;*/
	GtkWidget *au_rb;
	GtkWidget *raw_rb;

	/* if we can't save in a file: wrong codec, cut packets or other errors */
	/* Should the error arise here or later when you click ok button ?
	 * if we do it here, then we must disable the refresh button, so we don't do it here
	 */

#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
	if (user_data->dlg.save_voice_as_w != NULL) {
		/* There's already a Save voice info dialog box; reactivate it. */
		reactivate_window(user_data->dlg.save_voice_as_w);
		return;
	}
#endif
	/* XXX - use file_selection from dlg_utils instead! */
	user_data->dlg.save_voice_as_w = gtk_file_chooser_dialog_new("Wireshark: Save Payload As ...",
								     GTK_WINDOW(user_data->dlg.notebook),
								     GTK_FILE_CHOOSER_ACTION_SAVE,
								     GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
								     GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
								     NULL);
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(user_data->dlg.save_voice_as_w), TRUE);
	gtk_window_set_transient_for(GTK_WINDOW(user_data->dlg.save_voice_as_w),GTK_WINDOW(user_data->dlg.window));

	/* Container for each row of widgets */
	vertb = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vertb), 5);
	gtk_file_chooser_set_extra_widget(GTK_FILE_CHOOSER(user_data->dlg.save_voice_as_w), vertb);
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

	gtk_misc_set_alignment (GTK_MISC (label_format), 0, 0.5f);

	raw_rb = gtk_radio_button_new_with_label (NULL, ".raw");
	gtk_widget_show (raw_rb);
	gtk_table_attach (GTK_TABLE (table1), raw_rb, 1, 2, 0, 1,
	(GtkAttachOptions) (GTK_FILL),
	(GtkAttachOptions) (0), 0, 0);


	au_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(raw_rb), ".au");
	gtk_widget_show (au_rb);
	gtk_table_attach (GTK_TABLE (table1), au_rb, 3, 4, 0, 1,
	(GtkAttachOptions) (GTK_FILL),
	(GtkAttachOptions) (0), 0, 0);

#if 0
	/* we support .au - ulaw*/
	wav_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(raw_rb), ".wav");
	gtk_widget_show (wav_rb);
	gtk_table_attach (GTK_TABLE (table1), wav_rb, 1, 2, 0, 1,
	(GtkAttachOptions) (GTK_FILL),
	(GtkAttachOptions) (0), 0, 0);

	sw_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(raw_rb), "8 kHz, 16 bit  ");
	gtk_widget_show (sw_rb);
	gtk_table_attach (GTK_TABLE (table1), sw_rb, 2, 3, 0, 1,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
	au_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(raw_rb), ".au");
	gtk_widget_show (au_rb);
	gtk_table_attach (GTK_TABLE (table1), au_rb, 3, 4, 0, 1,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
#endif

	channels_label = gtk_label_new ("Channels:    ");
	gtk_widget_show (channels_label);
	gtk_table_attach (GTK_TABLE (table1), channels_label, 0, 1, 1, 2,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (channels_label), 0, 0.5f);

	forward_rb = gtk_radio_button_new_with_label (NULL, "forward    ");
	gtk_widget_show (forward_rb);
	gtk_table_attach (GTK_TABLE (table1), forward_rb, 1, 2, 1, 2,
		(GtkAttachOptions) (GTK_FILL),
		(GtkAttachOptions) (0), 0, 0);

	reversed_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(forward_rb), "reversed    ");
	gtk_widget_show (reversed_rb);
	gtk_table_attach (GTK_TABLE (table1), reversed_rb, 2, 3, 1, 2,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);

	both_rb = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON(forward_rb), "both");
	gtk_widget_show (both_rb);
	gtk_table_attach (GTK_TABLE (table1), both_rb, 3, 4, 1, 2,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);


	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(forward_rb), TRUE);

#if 0
	/* if one direction is nok we don't allow saving
	XXX this is not ok since the user can click the refresh button and cause changes
	but we can not update this window. So we move all the decision on the time the ok
	button is clicked
	*/
	if (user_data->forward.saved == FALSE) {
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(reversed_rb), TRUE);
	gtk_widget_set_sensitive(forward_rb, FALSE);
	gtk_widget_set_sensitive(both_rb, FALSE);
	}
	else if (user_data->reversed.saved == FALSE) {
	gtk_widget_set_sensitive(reversed_rb, FALSE);
	gtk_widget_set_sensitive(both_rb, FALSE);
	}
 #endif

	/*g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "wav_rb", wav_rb);*/
	g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "au_rb", au_rb);
	/*g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "sw_rb", sw_rb);*/
	g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "raw_rb", raw_rb);
	g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "forward_rb", forward_rb);
	g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "reversed_rb", reversed_rb);
	g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "both_rb", both_rb);
	g_object_set_data(G_OBJECT(user_data->dlg.save_voice_as_w), "user_data", user_data);

	g_signal_connect(user_data->dlg.save_voice_as_w, "delete_event",
			 G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(user_data->dlg.save_voice_as_w, "destroy",
			 G_CALLBACK(save_voice_as_destroy_cb), user_data);

	gtk_widget_show(user_data->dlg.save_voice_as_w);
	window_present(user_data->dlg.save_voice_as_w);

	/* "Run" the GtkFileChooserDialog.                                              */
	/* Upon exit: If "Accept" run the OK callback.                                  */
	/*            If the OK callback returns with a FALSE status, re-run the dialog.*/
	/*            Destroy the window.                                               */
	/* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
	/*      return with a TRUE status so that the dialog window will be destroyed.  */
	/*      Trying to re-run the dialog after popping up an alert box will not work */
	/*       since the user will not be able to dismiss the alert box.              */
	/*      The (somewhat unfriendly) effect: the user must re-invoke the           */
	/*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
	/*                                                                              */
	/*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
	/*            GtkFileChooserDialog.                                             */
	while (gtk_dialog_run(GTK_DIALOG(user_data->dlg.save_voice_as_w)) == GTK_RESPONSE_ACCEPT) {
		if (save_voice_as_ok_cb(NULL, user_data->dlg.save_voice_as_w)) {
			break;  /* we're done */
		}
	}
	window_destroy(user_data->dlg.save_voice_as_w);

}


/****************************************************************************/
/* when we are finished with redisection, we add the label for the statistic */
static void draw_stat(user_data_t *user_data)
{
	gchar label_max[300];
	guint32 f_expected = (user_data->forward.statinfo.stop_seq_nr + user_data->forward.statinfo.cycles*65536)
		- user_data->forward.statinfo.start_seq_nr + 1;
	guint32 r_expected = (user_data->reversed.statinfo.stop_seq_nr + user_data->reversed.statinfo.cycles*65536)
		- user_data->reversed.statinfo.start_seq_nr + 1;
	guint32 f_total_nr = user_data->forward.statinfo.total_nr;
	guint32 r_total_nr = user_data->reversed.statinfo.total_nr;
	gint32 f_lost = f_expected - f_total_nr;
	gint32 r_lost = r_expected - r_total_nr;
	double f_sumt = user_data->forward.statinfo.sumt;
	double f_sumTS = user_data->forward.statinfo.sumTS;
	double f_sumt2 = user_data->forward.statinfo.sumt2;
	double f_sumtTS = user_data->forward.statinfo.sumtTS;

	double r_sumt = user_data->reversed.statinfo.sumt;
	double r_sumTS = user_data->reversed.statinfo.sumTS;
	double r_sumt2 = user_data->reversed.statinfo.sumt2;
	double r_sumtTS = user_data->reversed.statinfo.sumtTS;
	double f_perc, r_perc;
	double f_clock_drift = 1.0;
	double r_clock_drift = 1.0;
	double f_duration = user_data->forward.statinfo.time - user_data->forward.statinfo.start_time;
	double r_duration = user_data->reversed.statinfo.time - user_data->reversed.statinfo.start_time;
	guint32 f_clock_rate = user_data->forward.statinfo.clock_rate;
	guint32 r_clock_rate = user_data->reversed.statinfo.clock_rate;

	if (f_clock_rate == 0){
		f_clock_rate = 1;
	}

	if (r_clock_rate == 0){
		r_clock_rate = 1;
	}

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

	if ((f_total_nr >0)&&(f_sumt2 > 0)){
		f_clock_drift = (f_total_nr * f_sumtTS - f_sumt * f_sumTS) / (f_total_nr * f_sumt2 - f_sumt * f_sumt);
	}
	if ((r_total_nr >0)&&(r_sumt2 > 0)){
		r_clock_drift = (r_total_nr * r_sumtTS - r_sumt * r_sumTS) / (r_total_nr * r_sumt2 - r_sumt * r_sumt);
	}
	g_snprintf(label_max, sizeof(label_max), "Max delta = %.2f ms at packet no. %u \n"
		"Max jitter = %.2f ms. Mean jitter = %.2f ms.\n"
		"Max skew = %.2f ms.\n"
		"Total RTP packets = %u   (expected %u)   Lost RTP packets = %d (%.2f%%)"
		"   Sequence errors = %u \n"
		"Duration %.2f s (%.0f ms clock drift, corresponding to %.0f Hz (%+.2f%%)",
		user_data->forward.statinfo.max_delta, user_data->forward.statinfo.max_nr,
		user_data->forward.statinfo.max_jitter,user_data->forward.statinfo.mean_jitter,
		user_data->forward.statinfo.max_skew,
		f_expected, f_expected, f_lost, f_perc,
		user_data->forward.statinfo.sequence,
		f_duration/1000,f_duration*(f_clock_drift-1.0),f_clock_drift*f_clock_rate,100.0*(f_clock_drift-1.0));

	gtk_label_set_text(GTK_LABEL(user_data->dlg.label_stats_fwd), label_max);
	gtk_label_set_selectable (GTK_LABEL(user_data->dlg.label_stats_fwd),TRUE);

	g_snprintf(label_max, sizeof(label_max), "Max delta = %.2f ms at packet no. %u \n"
		"Max jitter = %.2f ms. Mean jitter = %.2f ms.\n"
		"Max skew = %.2f ms.\n"
		"Total RTP packets = %u   (expected %u)   Lost RTP packets = %d (%.2f%%)"
		"   Sequence errors = %u \n"
		"Duration %.2f s (%.0f ms clock drift, corresponding to %.0f Hz (%+.2f%%)",
		user_data->reversed.statinfo.max_delta, user_data->reversed.statinfo.max_nr,
		user_data->reversed.statinfo.max_jitter,user_data->reversed.statinfo.mean_jitter,
		user_data->reversed.statinfo.max_skew,
		r_expected, r_expected, r_lost, r_perc,
		user_data->reversed.statinfo.sequence,
		r_duration/1000,r_duration*(r_clock_drift-1.0),r_clock_drift*r_clock_rate,100.0*(r_clock_drift-1.0));

	gtk_label_set_text(GTK_LABEL(user_data->dlg.label_stats_rev), label_max);
	gtk_label_set_selectable (GTK_LABEL(user_data->dlg.label_stats_rev),TRUE);

	return ;
}



/****************************************************************************/
/* append a line to list */
static void add_to_list(GtkWidget *list, user_data_t * user_data, guint32 number, guint16 seq_num, guint32 timestamp,
			double delta, double jitter,double skew, double bandwidth, gchar *status, gboolean marker,
			gchar *timeStr, guint32 pkt_len, gchar *color_str, guint32 flags)
{
	GtkListStore *list_store;

	if (strcmp(status, OK_TEXT) != 0) {
		user_data->dlg.number_of_nok++;
	}

	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (list))); /* Get store */

	/* Creates a new row at position. iter will be changed to point to this new row.
	 * If position is larger than the number of rows on the list, then the new row will be appended to the list.
	 * The row will be filled with the values given to this function.
	 * :
	 * should generally be preferred when inserting rows in a sorted list store.
	 */
	gtk_list_store_insert_with_values( list_store , &user_data->dlg.iter, G_MAXINT,
			     PACKET_COLUMN,        number,
			     SEQUENCE_COLUMN,      seq_num,
			     TIMESTAMP_COLUMN,     timestamp,
			     DELTA_COLUMN,         delta,
			     JITTER_COLUMN,        jitter,
			     SKEW_COLUMN,          skew,
			     IPBW_COLUMN,          bandwidth,
			     MARKER_COLUMN,        marker,
			     STATUS_COLUMN,        (char *)status,
			     DATE_COLUMN,          (char *)timeStr,
			     LENGTH_COLUMN,        pkt_len,
			     FOREGROUND_COLOR_COL, NULL,
			     BACKGROUND_COLOR_COL, (char *)color_str,
			     -1);

	if(flags & STAT_FLAG_FIRST){
		/* Set first row as active */
		gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)), &user_data->dlg.iter);
	}
}

/****************************************************************************
* Functions needed to present values from the list
*/


/* Present boolean value */
static void
rtp_boolean_data_func (GtkTreeViewColumn *column _U_,
		       GtkCellRenderer   *renderer,
		       GtkTreeModel      *model,
		       GtkTreeIter       *iter,
		       gpointer           user_data)
{
	gboolean  bool_val;
	gchar   buf[20];
	/* the col to get data from is in userdata */
	gint bool_col = GPOINTER_TO_INT(user_data);

	gtk_tree_model_get(model, iter, bool_col, &bool_val, -1);

	switch(bool_col){
	case MARKER_COLUMN:
		g_strlcpy(buf, bool_val ? "SET" : "", sizeof(buf));
		break;
	default:
		g_assert_not_reached();
		break;
	}
	g_object_set(renderer, "text", buf, NULL);
}

/* Create list */
static
GtkWidget* create_list(user_data_t* user_data)
{

	GtkListStore *list_store;
	GtkWidget *list;
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	GtkTreeSortable *sortable;
	GtkTreeView     *list_view;
	GtkTreeSelection  *selection;

	/* Create the store */
	list_store = gtk_list_store_new(N_COLUMN,	/* Total number of columns XXX	*/
					G_TYPE_UINT,	/* Packet			*/
					G_TYPE_UINT,	/* Sequence			*/
					G_TYPE_UINT,	/* Time stamp			*/
					G_TYPE_FLOAT,	/* Delta(ms)			*/
					G_TYPE_FLOAT,	/* Filtered Jitter(ms)  	*/
					G_TYPE_FLOAT,	/* Skew(ms)			*/
					G_TYPE_FLOAT,	/* IP BW(kbps)			*/
					G_TYPE_BOOLEAN, /* Marker			*/
					G_TYPE_STRING,  /* Status			*/
					G_TYPE_STRING,	/* Date				*/
					G_TYPE_UINT,	/* Length			*/
					G_TYPE_STRING,  /* Foreground color		*/
					G_TYPE_STRING); /* Background color		*/

	/* Create a view */
	list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

	list_view = GTK_TREE_VIEW(list);
	sortable = GTK_TREE_SORTABLE(list_store);

	/* Speed up the list display */
	gtk_tree_view_set_fixed_height_mode(list_view, TRUE);

	/* Setup the sortable columns */
	gtk_tree_sortable_set_sort_column_id(sortable, PACKET_COLUMN, GTK_SORT_ASCENDING);
	gtk_tree_view_set_headers_clickable(list_view, FALSE);

	/* The view now holds a reference.  We can get rid of our own reference */
	g_object_unref (G_OBJECT (list_store));

	/*
	 * Create the first column packet, associating the "text" attribute of the
	 * cell_renderer to the first column of the model
	 */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Packet", renderer,
							   "text",	PACKET_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);
	gtk_tree_view_column_set_sort_column_id(column, PACKET_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 55);

	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

	/* Sequence. */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Sequence", renderer,
							   "text", SEQUENCE_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);
	gtk_tree_view_column_set_sort_column_id(column, SEQUENCE_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 75);
	gtk_tree_view_append_column (list_view, column);

#if 0
	Currently not visible
		/* Time stamp. */
		renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Time stamp", renderer,
							   "text", TIMESTAMP_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);
	gtk_tree_view_column_set_sort_column_id(column, TIMESTAMP_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 75);
	gtk_tree_view_append_column (list_view, column);
#endif
	/* Delta(ms). */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Delta(ms)", renderer,
							   "text", DELTA_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);

	gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
						GINT_TO_POINTER(DELTA_COLUMN), NULL);

	gtk_tree_view_column_set_sort_column_id(column, DELTA_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 75);
	gtk_tree_view_append_column (list_view, column);

	/* Jitter(ms). */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Filtered Jitter(ms)", renderer,
							   "text", JITTER_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);

	gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
						GINT_TO_POINTER(JITTER_COLUMN), NULL);

	gtk_tree_view_column_set_sort_column_id(column, JITTER_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 110);
	gtk_tree_view_append_column (list_view, column);

	/* Skew(ms). */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Skew(ms)", renderer,
							   "text", SKEW_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);

	gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
						GINT_TO_POINTER(SKEW_COLUMN), NULL);

	gtk_tree_view_column_set_sort_column_id(column, SKEW_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 110);
	gtk_tree_view_append_column (list_view, column);

	/* IP BW(kbps). */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("IP BW(kbps)", renderer,
							   "text", IPBW_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);

	gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
						GINT_TO_POINTER(IPBW_COLUMN), NULL);

	gtk_tree_view_column_set_sort_column_id(column, IPBW_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_append_column (list_view, column);

	/* Marker. */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Marker", renderer,
							   "text", MARKER_COLUMN,
							   "foreground", FOREGROUND_COLOR_COL,
							   "background", BACKGROUND_COLOR_COL,
							   NULL);

	gtk_tree_view_column_set_cell_data_func(column, renderer, rtp_boolean_data_func,
						GINT_TO_POINTER(MARKER_COLUMN), NULL);

	gtk_tree_view_column_set_sort_column_id(column, MARKER_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_append_column (list_view, column);

	/* Status. */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ( "Status", renderer,
							    "text", STATUS_COLUMN,
							    "foreground", FOREGROUND_COLOR_COL,
							    "background", BACKGROUND_COLOR_COL,
							    NULL);
	gtk_tree_view_column_set_sort_column_id(column, STATUS_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 100);
	gtk_tree_view_append_column (list_view, column);

	/* Now enable the sorting of each column */
	gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(list_view), TRUE);
	gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(list_view), TRUE);

	/* Setup the selection handler */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

	g_signal_connect (G_OBJECT (selection), "changed", /* select_row */
			  G_CALLBACK (on_list_select_row),
			  user_data);
	return list;
}

/****************************************************************************/
/* Create the dialog box with all widgets */
static void create_rtp_dialog(user_data_t* user_data)
{
	GtkWidget *window = NULL;
	GtkWidget *list_fwd;
	GtkWidget *list_rev;
	GtkWidget *label_stats_fwd;
	GtkWidget *label_stats_rev;
	GtkWidget *notebook;

	GtkWidget *main_vb, *page, *page_r;
	GtkWidget *label;
	GtkWidget *scrolled_window, *scrolled_window_r/*, *frame, *text, *label4, *page_help*/;
	GtkWidget *box4, *voice_bt, *refresh_bt, *goto_bt, *close_bt, *csv_bt, *next_bt;
#ifdef HAVE_LIBPORTAUDIO
	GtkWidget *player_bt = NULL;
#endif /* HAVE_LIBPORTAUDIO */
	GtkWidget *graph_bt;
	gchar label_forward[150];
	gchar label_forward_tree[150];
	gchar label_reverse[150];

	gchar str_ip_src[16];
	gchar str_ip_dst[16];

	window = dlg_window_new("Wireshark: RTP Stream Analysis");  /* transient_for top_level */
	gtk_window_set_default_size(GTK_WINDOW(window), 700, 400);

	/* Container for each row of widgets */
	main_vb = gtk_vbox_new(FALSE, 2);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 2);
	gtk_container_add(GTK_CONTAINER(window), main_vb);
	gtk_widget_show(main_vb);

	/* Notebooks... */
	g_strlcpy(str_ip_src, get_addr_name(&(user_data->ip_src_fwd)), sizeof(str_ip_src));
	g_strlcpy(str_ip_dst, get_addr_name(&(user_data->ip_dst_fwd)), sizeof(str_ip_dst));

	g_snprintf(label_forward, sizeof(label_forward),
		"Analysing stream from  %s port %u  to  %s port %u   SSRC = 0x%X",
		str_ip_src, user_data->port_src_fwd, str_ip_dst, user_data->port_dst_fwd, user_data->ssrc_fwd);

	g_snprintf(label_forward_tree, sizeof(label_forward_tree),
		"Analysing stream from  %s port %u  to  %s port %u   SSRC = 0x%X",
		str_ip_src, user_data->port_src_fwd, str_ip_dst, user_data->port_dst_fwd, user_data->ssrc_fwd);


	g_strlcpy(str_ip_src, get_addr_name(&(user_data->ip_src_rev)), sizeof(str_ip_src));
	g_strlcpy(str_ip_dst, get_addr_name(&(user_data->ip_dst_rev)), sizeof(str_ip_dst));

	g_snprintf(label_reverse, sizeof(label_reverse),
		"Analysing stream from  %s port %u  to  %s port %u   SSRC = 0x%X",
		str_ip_src, user_data->port_src_rev, str_ip_dst, user_data->port_dst_rev, user_data->ssrc_rev);

	/* Start a notebook for flipping between sets of changes */
	notebook = gtk_notebook_new();
	gtk_container_add(GTK_CONTAINER(main_vb), notebook);
	g_object_set_data(G_OBJECT(window), "notebook", notebook);

	user_data->dlg.notebook_signal_id =
		g_signal_connect(notebook, "switch_page", G_CALLBACK(on_notebook_switch_page), user_data);

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

	/* packet list */
	list_fwd = create_list(user_data);
	gtk_widget_show(list_fwd);
	gtk_container_add(GTK_CONTAINER(scrolled_window), list_fwd);
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

	list_rev = create_list(user_data);
	gtk_widget_show(list_rev);
	gtk_container_add(GTK_CONTAINER(scrolled_window_r), list_rev);
	gtk_box_pack_start(GTK_BOX(page_r), scrolled_window_r, TRUE, TRUE, 0);
	gtk_widget_show(scrolled_window_r);

	label = gtk_label_new("  Reversed Direction  ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_r, label);

	/* page for help&about or future */
#if 0
	page_help = gtk_hbox_new(FALSE, 5);
	label = gtk_label_new("     Future    ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_help, label);
	frame = gtk_frame_new("");
	text = gtk_label_new("\n\nMaybe some more statistics: delta and jitter distribution,...");
	gtk_label_set_justify(GTK_LABEL(text), GTK_JUSTIFY_LEFT);
	gtk_container_add(GTK_CONTAINER(frame), text);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 20);
	gtk_box_pack_start(GTK_BOX(page_help), frame, TRUE, TRUE, 0);
#endif

	/* show all notebooks */
	gtk_widget_show_all(notebook);

	/* buttons */
	box4 = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(main_vb), box4, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(box4), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (box4), GTK_BUTTONBOX_EDGE);
	gtk_box_set_spacing(GTK_BOX (box4), 0);
	gtk_widget_show(box4);

	voice_bt = gtk_button_new_with_label("Save payload...");
	gtk_container_add(GTK_CONTAINER(box4), voice_bt);
	gtk_widget_show(voice_bt);
	g_signal_connect(voice_bt, "clicked", G_CALLBACK(on_save_bt_clicked), user_data);

	csv_bt = gtk_button_new_with_label("Save as CSV...");
	gtk_container_add(GTK_CONTAINER(box4), csv_bt);
	gtk_widget_show(csv_bt);
	g_signal_connect(csv_bt, "clicked", G_CALLBACK(save_csv_as_cb), user_data);

	refresh_bt = gtk_button_new_from_stock(GTK_STOCK_REFRESH);
	gtk_container_add(GTK_CONTAINER(box4), refresh_bt);
	gtk_widget_show(refresh_bt);
	g_signal_connect(refresh_bt, "clicked", G_CALLBACK(on_refresh_bt_clicked), user_data);

	goto_bt = gtk_button_new_from_stock(GTK_STOCK_JUMP_TO);
	gtk_container_add(GTK_CONTAINER(box4), goto_bt);
	gtk_widget_show(goto_bt);
	g_signal_connect(goto_bt, "clicked", G_CALLBACK(on_goto_bt_clicked_lst), user_data);

	graph_bt = gtk_button_new_with_label("Graph");
	gtk_container_add(GTK_CONTAINER(box4), graph_bt);
	gtk_widget_show(graph_bt);
	g_signal_connect(graph_bt, "clicked", G_CALLBACK(on_graph_bt_clicked), user_data);

#ifdef HAVE_LIBPORTAUDIO
	player_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_AUDIO_PLAYER);
	gtk_container_add(GTK_CONTAINER(box4), player_bt);
	gtk_widget_show(player_bt);
	g_signal_connect(player_bt, "clicked", G_CALLBACK(on_player_bt_clicked), NULL);
	/*gtk_widget_set_tooltip_text (player_bt, "Launch the RTP player to listen the audio stream");*/
#endif /* HAVE_LIBPORTAUDIO */

	next_bt = gtk_button_new_with_label("Next non-Ok");
	gtk_container_add(GTK_CONTAINER(box4), next_bt);
	gtk_widget_show(next_bt);
	g_signal_connect(next_bt, "clicked", G_CALLBACK(on_next_bt_clicked_list), user_data);

	close_bt = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
	gtk_container_add(GTK_CONTAINER(box4), close_bt);
#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_set_can_default(close_bt, TRUE);
#else
	GTK_WIDGET_SET_FLAGS(close_bt, GTK_CAN_DEFAULT);
#endif
	gtk_widget_show(close_bt);
	window_set_cancel_button(window, close_bt, window_cancel_button_cb);

	g_signal_connect(window, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(window, "destroy", G_CALLBACK(on_destroy), user_data);

	gtk_widget_show(window);
	window_present(window);


	/* some widget references need to be saved for outside use */
	user_data->dlg.window = window;
	user_data->dlg.list_fwd = list_fwd;
	user_data->dlg.list_rev = list_rev;
	user_data->dlg.label_stats_fwd = label_stats_fwd;
	user_data->dlg.label_stats_rev = label_stats_rev;
	user_data->dlg.notebook = notebook;
	user_data->dlg.selected_list = list_fwd;
	user_data->dlg.number_of_nok = 0;

	/*
	 * select the initial row
	 */
	gtk_widget_grab_focus(list_fwd);

}


/****************************************************************************/
static gboolean process_node(proto_node *ptree_node, header_field_info *hfinformation,
							const gchar* proto_field, guint32* p_result)
{
	field_info            *finfo;
	proto_node            *proto_sibling_node;
	header_field_info     *hfssrc;
	ipv4_addr             *ipv4;

	finfo = PNODE_FINFO(ptree_node);

	g_assert(finfo && "Caller passed top of the protocol tree. Expected child node");

	if (hfinformation==(finfo->hfinfo)) {
		hfssrc = proto_registrar_get_byname(proto_field);
		if (hfssrc == NULL)
			return FALSE;
		for(ptree_node=ptree_node->first_child; ptree_node!=NULL;
					ptree_node=ptree_node->next) {
			finfo=PNODE_FINFO(ptree_node);
			if (hfssrc==finfo->hfinfo) {
				if (hfinformation->type==FT_IPv4) {
					ipv4 = fvalue_get(&finfo->value);
					*p_result = ipv4_get_net_order_addr(ipv4);
				}
				else {
					*p_result = fvalue_get_uinteger(&finfo->value);
				}
				return TRUE;
			}
		}
		if(!ptree_node)
			return FALSE;
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
	static GdkColor col[MAX_GRAPHS] = {
		{0,     0x0000, 0x0000, 0x0000},
		{0,     0xffff, 0x0000, 0x0000},
		{0,     0x0000, 0xffff, 0x0000},
		{0,		0xdddd, 0xcccc, 0x6666},
		{0,		0x6666, 0xcccc, 0xdddd},
		{0,     0x0000, 0x0000, 0xffff}
	};
	char *tempname;

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
	fd = create_tempfile(&tempname, "wireshark_rtp_f");
	user_data->f_tempname = g_strdup(tempname);
	ws_close(fd);
	fd = create_tempfile(&tempname, "wireshark_rtp_r");
	user_data->r_tempname = g_strdup(tempname);
	ws_close(fd);
	user_data->forward.saveinfo.fp = NULL;
	user_data->reversed.saveinfo.fp = NULL;
	user_data->dlg.save_voice_as_w = NULL;
	user_data->dlg.save_csv_as_w = NULL;
	user_data->dlg.dialog_graph.window = NULL;

	/* init dialog_graph */
	user_data->dlg.dialog_graph.needs_redraw=TRUE;
	user_data->dlg.dialog_graph.interval_index=DEFAULT_TICK_INTERVAL_VALUES_INDEX;
	user_data->dlg.dialog_graph.interval=tick_interval_values[DEFAULT_TICK_INTERVAL_VALUES_INDEX];
	user_data->dlg.dialog_graph.draw_area=NULL;
#if GTK_CHECK_VERSION(2,22,0)
	user_data->dlg.dialog_graph.surface=NULL;
#else
	user_data->dlg.dialog_graph.pixmap=NULL;
#endif
	user_data->dlg.dialog_graph.scrollbar=NULL;
	user_data->dlg.dialog_graph.scrollbar_adjustment=NULL;
	user_data->dlg.dialog_graph.surface_width=500;
	user_data->dlg.dialog_graph.surface_height=200;
	user_data->dlg.dialog_graph.pixels_per_tick_index=DEFAULT_PIXELS_PER_TICK_INDEX;
	user_data->dlg.dialog_graph.pixels_per_tick=pixels_per_tick[DEFAULT_PIXELS_PER_TICK_INDEX];
	user_data->dlg.dialog_graph.max_y_units_index=AUTO_MAX_YSCALE_INDEX;
	user_data->dlg.dialog_graph.max_y_units=AUTO_MAX_YSCALE;
	user_data->dlg.dialog_graph.last_interval=0xffffffff;
	user_data->dlg.dialog_graph.max_interval=0;
	user_data->dlg.dialog_graph.num_items=0;
	user_data->dlg.dialog_graph.start_time = -1;

	for(i=0;i<MAX_GRAPHS;i++){
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
	epan_dissect_t edt;
	gboolean frame_matched;
	frame_data *fdata;
	GList *strinfo_list;
	GList *filtered_list = NULL;
	rtp_stream_info_t *strinfo;
	guint nfound;

	/* Try to compile the filter. */
	g_strlcpy(filter_text,"rtp && rtp.version && rtp.ssrc && (ip || ipv6)",sizeof(filter_text));
	if (!dfilter_compile(filter_text, &sfcode)) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", dfilter_error_msg);
		return;
	}
	/* we load the current file into cf variable */
	cf = &cfile;
	fdata = cf->current_frame;

	/* we are on the selected frame now */
	if (fdata == NULL)
		return; /* if we exit here it's an error */

	/* dissect the current frame */
	if (!cf_read_frame(cf, fdata))
		return;	/* error reading the frame */
	epan_dissect_init(&edt, TRUE, FALSE);
	epan_dissect_prime_dfilter(&edt, sfcode);
	epan_dissect_run(&edt, &cf->pseudo_header, cf->pd, fdata, NULL);

	/* if it is not an rtp frame, show the rtpstream dialog */
	frame_matched = dfilter_apply_edt(sfcode, &edt);
	if (frame_matched != TRUE) {
		epan_dissect_cleanup(&edt);
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "You didn't choose a RTP packet!");
		return;
	}

	/* ok, it is a RTP frame, so let's get the ip and port values */
	COPY_ADDRESS(&(ip_src_fwd), &(edt.pi.src))
	COPY_ADDRESS(&(ip_dst_fwd), &(edt.pi.dst))
	port_src_fwd = edt.pi.srcport;
	port_dst_fwd = edt.pi.destport;

	/* assume the inverse ip/port combination for the reverse direction */
	COPY_ADDRESS(&(ip_src_rev), &(edt.pi.dst))
	COPY_ADDRESS(&(ip_dst_rev), &(edt.pi.src))
	port_src_rev = edt.pi.destport;
	port_dst_rev = edt.pi.srcport;

	/* check if it is RTP Version 2 */
	if (!get_int_value_from_proto_tree(edt.tree, "rtp", "rtp.version", &version_fwd) || version_fwd != 2) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "RTP Version != 2 isn't supported!");
		return;
	}

	/* now we need the SSRC value of the current frame */
	if (!get_int_value_from_proto_tree(edt.tree, "rtp", "rtp.ssrc", &ssrc_fwd)) {
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
rtp_analysis_init(const char *dummy _U_,void* userdata _U_)
{
	rtp_analysis_cb(NULL, NULL);
}

/****************************************************************************/
void
register_tap_listener_rtp_analysis(void)
{
	register_stat_cmd_arg("rtp", rtp_analysis_init, NULL);

	register_stat_menu_item("_RTP/Stream Analysis...", REGISTER_STAT_GROUP_TELEPHONY,
	    rtp_analysis_cb, NULL, NULL, NULL);
}
