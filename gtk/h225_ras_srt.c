/* h225_ras_srt.c
 * H.225 RAS Service Response Time statistics for Wireshar
 * Copyright 2003 Lars Roland
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/value_string.h>

#include <epan/tap.h>
#include "../register.h"
#include <epan/dissectors/packet-h225.h>
#include "../timestats.h"
#include "gui_stat_util.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "../stat_menu.h"
#include "../tap_dfilter_dlg.h"
#include "gui_utils.h"


static void gtk_h225rassrt_init(const char *optarg, void *userdata);

static tap_dfilter_dlg h225_rassrt_dlg = {
	"H.225 RAS Service Response Time",
	"h225,srt",
	gtk_h225rassrt_init,
	-1
};

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
h225rassrt_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *phi)
{
	h225rassrt_t *hs=(h225rassrt_t *)phs;
	const h225_packet_info *pi=phi;

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

		g_snprintf(str[0], sizeof(char[256]), 
            "%s", val_to_str(i,ras_message_category,"Other"));
		g_snprintf(str[1], sizeof(char[256]), 
            "%7d", hs->ras_rtd[i].stats.num);
		g_snprintf(str[2], sizeof(char[256]), 
            "%8.2f msec", nstime_to_msec(&(hs->ras_rtd[i].stats.min)));
		g_snprintf(str[3], sizeof(char[256]), 
            "%8.2f msec", nstime_to_msec(&(hs->ras_rtd[i].stats.max)));;
		g_snprintf(str[4], sizeof(char[256]), 
            "%8.2f msec", get_average(&(hs->ras_rtd[i].stats.tot), hs->ras_rtd[i].stats.num));
		g_snprintf(str[5], sizeof(char[256]), 
            "%6u", hs->ras_rtd[i].stats.min_num);
		g_snprintf(str[6], sizeof(char[256]), 
            "%6u", hs->ras_rtd[i].stats.max_num);
		g_snprintf(str[7], sizeof(char[256]), 
            "%4u", hs->ras_rtd[i].open_req_num);
		g_snprintf(str[8], sizeof(char[256]), 
            "%4u", hs->ras_rtd[i].disc_rsp_num);
		g_snprintf(str[9], sizeof(char[256]), 
            "%4u", hs->ras_rtd[i].req_dup_num);
		g_snprintf(str[10], sizeof(char[256]), 
            "%4u", hs->ras_rtd[i].rsp_dup_num);
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


static const gchar *titles[]={
			"RAS-Type",
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

static void
gtk_h225rassrt_init(const char *optarg, void *userdata _U_)
{
	h225rassrt_t *hs;
	const char *filter=NULL;
	GString *error_string;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	if(strncmp(optarg,"h225,srt,",9) == 0){
		filter=optarg+9;
	} else {
		filter="";
	}

	hs=g_malloc(sizeof(h225rassrt_t));
	hs->filter=g_strdup(filter);

	h225rassrt_reset(hs);

	hs->win=window_new(GTK_WINDOW_TOPLEVEL, "h225-ras-srt");
	gtk_window_set_default_size(GTK_WINDOW(hs->win), 600, 300);

	hs->vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_set_border_width(GTK_CONTAINER(hs->vbox), 12);

	init_main_stat_window(hs->win, hs->vbox, "H.225 RAS Service Response Time", filter);

        /* init a scrolled window*/
	hs->scrolled_window = scrolled_window_new(NULL, NULL);

	hs->table = create_stat_table(hs->scrolled_window, hs->vbox, 11, titles);

	error_string=register_tap_listener("h225", hs, filter, h225rassrt_reset, h225rassrt_packet, h225rassrt_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(hs->filter);
		g_free(hs);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(hs->vbox), bbox, FALSE, FALSE, 0);

	close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(hs->win, close_bt, window_cancel_button_cb);

	SIGNAL_CONNECT(hs->win, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(hs->win, "destroy", win_destroy_cb, hs);

	gtk_widget_show_all(hs->win);
	window_present(hs->win);

	cf_retap_packets(&cfile, FALSE);
}

void
register_tap_listener_gtk_h225rassrt(void)
{
	register_dfilter_stat(&h225_rassrt_dlg, "H.225 RAS",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}
