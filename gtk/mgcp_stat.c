/* mgcp_stat.c
 * mgcp-statistics for ethereal
 * Copyright 2003 Lars Roland
 *
 * $Id: mgcp_stat.c,v 1.25 2004/02/06 19:19:10 ulfl Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <string.h>
#include "../epan/packet_info.h"
#include "../epan/epan.h"
#include "menu.h"
#include "../tap.h"
#include "../epan/value_string.h"
#include "../register.h"
#include "../plugins/mgcp/packet-mgcp.h"
#include "../timestats.h"
#include "gtk_stat_util.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "../tap_dfilter_dlg.h"
#include "tap_dfilter_dlg.h"
#include "ui_util.h"


extern GtkWidget *main_display_filter_widget;

#define NUM_TIMESTATS 10

/* used to keep track of the statistics for an entire program interface */
typedef struct _mgcpstat_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
	GtkWidget *scrolled_window;
	GtkCList *table;
        timestat_t rtd[NUM_TIMESTATS];
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
} mgcpstat_t;

static const value_string mgcp_mesage_type[] = {
  {  0,	"EPCF"},
  {  1,	"CRCX"},
  {  2,	"MDCX"},
  {  3,	"DLCX"},
  {  4,	"RQNT"},
  {  5,	"NTFY"},
  {  6,	"AUEP"},
  {  7, "AUCX"},
  {  8, "RSIP"},
  {  0, NULL}
};

static void
mgcpstat_reset(void *pms)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	int i;

	for(i=0;i<NUM_TIMESTATS;i++) {
		ms->rtd[i].num=0;
		ms->rtd[i].min_num=0;
		ms->rtd[i].max_num=0;
		ms->rtd[i].min.secs=0;
        	ms->rtd[i].min.nsecs=0;
        	ms->rtd[i].max.secs=0;
        	ms->rtd[i].max.nsecs=0;
        	ms->rtd[i].tot.secs=0;
        	ms->rtd[i].tot.nsecs=0;
	}

	ms->open_req_num=0;
	ms->disc_rsp_num=0;
	ms->req_dup_num=0;
	ms->rsp_dup_num=0;
}


static int
mgcpstat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, void *pmi)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	mgcp_info_t *mi=pmi;
	nstime_t delta;

	switch (mi->mgcp_type) {

	case MGCP_REQUEST:
		if(mi->is_duplicate){
			/* Duplicate is ignored */
			ms->req_dup_num++;
			return 0;
		}
		else {
			ms->open_req_num++;
			return 0;
		}
	break;

	case MGCP_RESPONSE:
		if(mi->is_duplicate){
			/* Duplicate is ignored */
			ms->rsp_dup_num++;
			return 0;
		}
		else if (!mi->request_available) {
			/* no request was seen */
			ms->disc_rsp_num++;
			return 0;
		}
		else {
			ms->open_req_num--;
			/* calculate time delta between request and response */
			delta.secs=pinfo->fd->abs_secs-mi->req_time.secs;
			delta.nsecs=pinfo->fd->abs_usecs*1000-mi->req_time.nsecs;
			if(delta.nsecs<0){
				delta.nsecs+=1000000000;
				delta.secs--;
			}

			if (strncasecmp(mi->code, "EPCF", 4) == 0 ) {
				time_stat_update(&(ms->rtd[0]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "CRCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[1]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "MDCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[2]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "DLCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[3]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RQNT", 4) == 0 ) {
				time_stat_update(&(ms->rtd[4]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "NTFY", 4) == 0 ) {
				time_stat_update(&(ms->rtd[5]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUEP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[6]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[7]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RSIP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[8]),&delta, pinfo);
			}
			else {
				time_stat_update(&(ms->rtd[9]),&delta, pinfo);
			}

			return 1;
		}
	break;

	default:
		return 0;
	break;
	}
}

static void
mgcpstat_draw(void *pms)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	int i;
	/* gtk1 using a scrollable clist*/
	char *str[7];

	for(i=0;i<7;i++) {
		str[i]=g_malloc(sizeof(char[256]));
	}

	/* clear list before printing */
	gtk_clist_clear(ms->table);

	for(i=0;i<NUM_TIMESTATS;i++) {
		/* nothing seen, nothing to do */
		if(ms->rtd[i].num==0){
			continue;
		}

		sprintf(str[0], "%s", val_to_str(i,mgcp_mesage_type,"Other"));
		sprintf(str[1], "%d", ms->rtd[i].num);
		sprintf(str[2], "%8.2f msec", nstime_to_msec(&(ms->rtd[i].min)));
		sprintf(str[3], "%8.2f msec", nstime_to_msec(&(ms->rtd[i].max)));
		sprintf(str[4], "%8.2f msec", get_average(&(ms->rtd[i].tot), ms->rtd[i].num));
		sprintf(str[5], "%6u", ms->rtd[i].min_num);
		sprintf(str[6], "%6u", ms->rtd[i].max_num);
		gtk_clist_append(ms->table, str);
	}

	gtk_widget_show(GTK_WIDGET(ms->table));
	for(i=0;i<7;i++) {
		g_free(str[i]);
	}
}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	mgcpstat_t *ms=(mgcpstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ms);
	unprotect_thread_critical_region();

	if(ms->filter){
		g_free(ms->filter);
		ms->filter=NULL;
	}
	g_free(ms);
}

static gchar *titles[]={"Type",
			"Messages",
			"Min SRT",
			"Max SRT",
			"Avg SRT",
			"Min in Frame",
			"Max in Frame" };

void
gtk_mgcpstat_init(char *optarg)
{
	mgcpstat_t *ms;
	char *filter=NULL;
	GString *error_string;

	if(strncmp(optarg,"mgcp,srt,",9) == 0){
		filter=optarg+9;
	} else {
		filter=g_malloc(1);
		*filter='\0';
	}

	ms=g_malloc(sizeof(mgcpstat_t));
	ms->filter=g_malloc(strlen(filter)+1);
	strcpy(ms->filter, filter);

	mgcpstat_reset(ms);

	ms->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	SIGNAL_CONNECT(ms->win, "destroy", win_destroy_cb, ms);

	ms->vbox=gtk_vbox_new(FALSE, 0);

	init_main_stat_window(ms->win, ms->vbox, "MGCP Service Response Time (SRT) Statistics", filter);

	/* GTK1 using a scrollable clist*/
        /* init a scrolled window*/
	ms->scrolled_window = scrolled_window_new(NULL, NULL);
	WIDGET_SET_SIZE(ms->scrolled_window, 550, 150);

	ms->table = create_stat_table(ms->scrolled_window, ms->vbox, 7, titles);

	error_string=register_tap_listener("mgcp", ms, filter, mgcpstat_reset, mgcpstat_packet, mgcpstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ms->filter);
		g_free(ms);
		return;
	}

	gtk_widget_show_all(ms->win);
	retap_packets(&cfile);
}

tap_dfilter_dlg mgcp_srt_dlg = {"MGCP Service Response Time (SRT) Statistics", "mgcp,srt", gtk_mgcpstat_init, -1};

void
register_tap_listener_gtkmgcpstat(void)
{
	register_ethereal_tap("mgcp,srt", gtk_mgcpstat_init);
}

void
register_tap_menu_gtkmgcpstat(void)
{
	if (find_tap_id("mgcp"))
		register_tap_menu_item("_Statistics/Service Response Time/MGCP...",
		    gtk_tap_dfilter_dlg_cb, NULL, NULL, &(mgcp_srt_dlg));
}

