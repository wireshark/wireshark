/* h225_ras_srt.c
 * h225 RAS Service Response Time statistics for ethereal
 * Copyright 2003 Lars Roland
 *
 * $Id: h225_ras_srt.c,v 1.6 2004/01/03 18:05:56 sharpe Exp $
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
#include "../packet-h225.h"
#include "../timestats.h"
#include "gtk_stat_util.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "../tap_dfilter_dlg.h"
#include "tap_dfilter_dlg.h"

extern GtkWidget *main_display_filter_widget;

void gtk_h225rassrt_init(char *optarg);

tap_dfilter_dlg h225_rassrt_dlg = {"H.225 RAS Service Response Time", "h225,srt", gtk_h225rassrt_init, -1};

/* following values represent the size of their valuestring arrays */
#define NUM_RAS_STATS 7

static const value_string ras_message_category[] = {
  {  0,	"Gatekeeper    "},
  {  1,	"Registration  "},
  {  2,	"UnRegistration"},
  {  3,	"Admission     "},
  {  4,	"Bandwidth     "},
  {  5,	"Disengage     "},
  {  6,	"Location      "},
  {  0, NULL }
};

typedef enum _ras_type {
	RAS_REQUEST,
	RAS_CONFIRM,
	RAS_REJECT,
	RAS_OTHER
}ras_type;

typedef enum _ras_category {
	RAS_GATEKEEPER,
	RAS_REGISTRATION,
	RAS_UNREGISTRATION,
	RAS_ADMISSION,
	RAS_BANDWIDTH,
	RAS_DISENGAGE,
	RAS_LOCATION,
	RAS_OTHERS
}ras_category;

/* Summary of response-time calculations*/
typedef struct _h225_rtd_t {
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
	timestat_t stats;
} h225_rtd_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _h225rassrt_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
	GtkWidget *scrolled_window;
	GtkCList *table;
	h225_rtd_t ras_rtd[NUM_RAS_STATS];
} h225rassrt_t;


static void
h225rassrt_reset(void *phs)
{
	h225rassrt_t *hs=(h225rassrt_t *)phs;
	int i;

	for(i=0;i<NUM_RAS_STATS;i++) {
		hs->ras_rtd[i].stats.num = 0;
		hs->ras_rtd[i].stats.min_num = 0;
		hs->ras_rtd[i].stats.max_num = 0;
		hs->ras_rtd[i].stats.min.secs = 0;
        	hs->ras_rtd[i].stats.min.nsecs = 0;
        	hs->ras_rtd[i].stats.max.secs = 0;
        	hs->ras_rtd[i].stats.max.nsecs = 0;
        	hs->ras_rtd[i].stats.tot.secs = 0;
        	hs->ras_rtd[i].stats.tot.nsecs = 0;
		hs->ras_rtd[i].open_req_num = 0;
		hs->ras_rtd[i].disc_rsp_num = 0;
		hs->ras_rtd[i].req_dup_num = 0;
		hs->ras_rtd[i].rsp_dup_num = 0;
	}

}


static int
h225rassrt_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, void *phi)
{
	h225rassrt_t *hs=(h225rassrt_t *)phs;
	h225_packet_info *pi=phi;

	ras_type rasmsg_type = RAS_OTHER;
	ras_category rascategory = RAS_OTHERS;

	if (pi->msg_type != H225_RAS || pi->msg_tag == -1) {
		/* No RAS Message or uninitialized msg_tag -> return */
		return 0;
	}

	if (pi->msg_tag < 21) {
		/* */
		rascategory = pi->msg_tag / 3;
		rasmsg_type = pi->msg_tag % 3;
	}
	else {
		/* No SRT yet (ToDo) */
		return 0;
	}

	switch(rasmsg_type) {

	case RAS_REQUEST:
		if(pi->is_duplicate){
			hs->ras_rtd[rascategory].req_dup_num++;
		}
		else {
			hs->ras_rtd[rascategory].open_req_num++;
		}
		break;

	case RAS_CONFIRM:
		/* no break - delay stats are identical for Confirm and Reject  */
	case RAS_REJECT:
		if(pi->is_duplicate){
			/* Duplicate is ignored */
			hs->ras_rtd[rascategory].rsp_dup_num++;
		}
		else if (!pi->request_available) {
			/* no request was seen, ignore response  */
			hs->ras_rtd[rascategory].disc_rsp_num++;
		}
		else {
			hs->ras_rtd[rascategory].open_req_num--;
			time_stat_update(&(hs->ras_rtd[rascategory].stats),&(pi->delta_time), pinfo);
		}
		break;

	default:
		return 0;
		break;
	}
	return 1;
}

static void
h225rassrt_draw(void *phs)
{
	h225rassrt_t *hs=(h225rassrt_t *)phs;
	int i;
	char *str[11];

	for(i=0;i<11;i++) {
		str[i]=g_malloc(sizeof(char[256]));
	}
	/* Now print Message and Reason Counter Table */
	/* clear list before printing */
	gtk_clist_clear(hs->table);

	for(i=0;i<NUM_RAS_STATS;i++) {
		/* nothing seen, nothing to do */
		if(hs->ras_rtd[i].stats.num==0){
			continue;
		}

		sprintf(str[0], "%s", val_to_str(i,ras_message_category,"Other"));
		sprintf(str[1], "%7d", hs->ras_rtd[i].stats.num);
		sprintf(str[2], "%8.2f msec", nstime_to_msec(&(hs->ras_rtd[i].stats.min)));
		sprintf(str[3], "%8.2f msec", nstime_to_msec(&(hs->ras_rtd[i].stats.max)));;
		sprintf(str[4], "%8.2f msec", get_average(&(hs->ras_rtd[i].stats.tot), hs->ras_rtd[i].stats.num));
		sprintf(str[5], "%6u", hs->ras_rtd[i].stats.min_num);
		sprintf(str[6], "%6u", hs->ras_rtd[i].stats.max_num);
		sprintf(str[7], "%4u", hs->ras_rtd[i].open_req_num);
		sprintf(str[8], "%4u", hs->ras_rtd[i].disc_rsp_num);
		sprintf(str[9], "%4u", hs->ras_rtd[i].req_dup_num);
		sprintf(str[10], "%4u", hs->ras_rtd[i].rsp_dup_num);
		gtk_clist_append(GTK_CLIST(hs->table), str);
	}

	gtk_widget_show(GTK_WIDGET(hs->table));

}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	h225rassrt_t *hs=(h225rassrt_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(hs);
	unprotect_thread_critical_region();

	if(hs->filter){
		g_free(hs->filter);
		hs->filter=NULL;
	}
	g_free(hs);
}


static gchar *titles[]={"RAS-Type",
			"Measurements",
			"Min RTT",
			"Max RTT",
			"Avg RTT",
			"Min in Frame",
			"Max in Frame",
			"Open Requests",
			"Discarded Responses",
			"Repeated Requests",
			"Repeated Responses" };

void
gtk_h225rassrt_init(char *optarg)
{
	h225rassrt_t *hs;
	char *filter=NULL;
	GString *error_string;

	if(strncmp(optarg,"h225,srt,",9) == 0){
		filter=optarg+9;
	} else {
		filter=g_malloc(1);
		*filter='\0';
	}

	hs=g_malloc(sizeof(h225rassrt_t));
	hs->filter=g_malloc(strlen(filter)+1);
	strcpy(hs->filter, filter);

	h225rassrt_reset(hs);

	hs->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	SIGNAL_CONNECT(hs->win, "destroy", win_destroy_cb, hs);

	hs->vbox=gtk_vbox_new(FALSE, 0);

	init_main_stat_window(hs->win, hs->vbox, "ITU-T H.225 RAS Service Response Time", filter);

        /* init a scrolled window*/
	hs->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	WIDGET_SET_SIZE(hs->scrolled_window, 600, 160);

	hs->table = create_stat_table(hs->scrolled_window, hs->vbox, 11, titles);

	error_string=register_tap_listener("h225", hs, filter, h225rassrt_reset, h225rassrt_packet, h225rassrt_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(hs->filter);
		g_free(hs);
		return;
	}

	gtk_widget_show_all(hs->win);
	redissect_packets(&cfile);
}

void
register_tap_listener_gtk_h225rassrt(void)
{
	register_ethereal_tap("h225,srt", gtk_h225rassrt_init);
}

void
register_tap_menu_gtk_h225rassrt(void)
{
	register_tap_menu_item("_Statistics/Service Response Time/ITU-T H.225 RAS ...",
	    gtk_tap_dfilter_dlg_cb, NULL, NULL, &(h225_rassrt_dlg));
}
