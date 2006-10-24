/* radius_stat.c
 * radius-statistics for Wireshark
 * Copyright 2006 Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * 
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
#include <epan/dissectors/packet-radius.h>
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


#define NUM_TIMESTATS 8
#define NUM_COLUMNS 11

/* Summary of response-time calculations*/
typedef struct _radius_rtd_t {
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
	timestat_t stats;
} radius_rtd_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _radiusstat_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
	GtkWidget *scrolled_window;
	GtkCList *table;
	radius_rtd_t radius_rtd[NUM_TIMESTATS];
} radiusstat_t;

static const value_string radius_message_code[] = {
  {  0,	"Overall"},
  {  1,	"Access"},
  {  2,	"Accounting"},
  {  3,	"Access Password"},
  {  4, "Ascend Access Event"},
  {  5, "Diconnect"},
  {  6, "Change Filter"},
  {  7, "Other"},
};

typedef enum _radius_category {
	OVERALL,
	ACCESS,
	ACCOUNTING,
	ACCESS_PASSWORD,
	ASCEND_ACCESS_EVENT,
	DISCONNECT,
	CHANGE_FILTER,
	OTHERS
}radius_category;

static void
radiusstat_reset(void *prs)
{
	radiusstat_t *rs=(radiusstat_t *)prs;
	int i;


	for(i=0;i<NUM_TIMESTATS;i++) {
		rs->radius_rtd[i].stats.num=0;
		rs->radius_rtd[i].stats.min_num=0;
		rs->radius_rtd[i].stats.max_num=0;
		rs->radius_rtd[i].stats.min.secs=0;
        rs->radius_rtd[i].stats.min.nsecs=0;
        rs->radius_rtd[i].stats.max.secs=0;
        rs->radius_rtd[i].stats.max.nsecs=0;
        rs->radius_rtd[i].stats.tot.secs=0;
        rs->radius_rtd[i].stats.tot.nsecs=0;
		rs->radius_rtd[i].open_req_num = 0;
		rs->radius_rtd[i].disc_rsp_num = 0;
		rs->radius_rtd[i].req_dup_num = 0;
		rs->radius_rtd[i].rsp_dup_num = 0;
	}

}


static int
radiusstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	radiusstat_t *rs=(radiusstat_t *)prs;
	const radius_info_t *ri=pri;
	nstime_t delta;
	radius_category radius_cat = OTHERS;

	switch (ri->code) { 
		case RADIUS_ACCESS_REQUEST:
		case RADIUS_ACCESS_ACCEPT:
		case RADIUS_ACCESS_REJECT:
			radius_cat = ACCESS;
			break;
		case RADIUS_ACCOUNTING_REQUEST:
		case RADIUS_ACCOUNTING_RESPONSE:
			radius_cat = ACCOUNTING;
			break;
		case RADIUS_ACCESS_PASSWORD_REQUEST:
		case RADIUS_ACCESS_PASSWORD_ACK:
		case RADIUS_ACCESS_PASSWORD_REJECT:
			radius_cat = ACCESS_PASSWORD;
			break;
		case RADIUS_ASCEND_ACCESS_EVENT_REQUEST:
		case RADIUS_ASCEND_ACCESS_EVENT_RESPONSE:
			radius_cat = ASCEND_ACCESS_EVENT;
			break;
		case RADIUS_DISCONNECT_REQUEST:
		case RADIUS_DISCONNECT_REQUEST_ACK:
		case RADIUS_DISCONNECT_REQUEST_NAK:
			radius_cat = DISCONNECT;
			break;
		case RADIUS_CHANGE_FILTER_REQUEST:
		case RADIUS_CHANGE_FILTER_REQUEST_ACK:
		case RADIUS_CHANGE_FILTER_REQUEST_NAK:
			radius_cat = CHANGE_FILTER;
			break;
	}

	switch (ri->code) {

	case RADIUS_ACCESS_REQUEST:
	case RADIUS_ACCOUNTING_REQUEST:
	case RADIUS_ACCESS_PASSWORD_REQUEST:
	case RADIUS_ASCEND_ACCESS_EVENT_REQUEST:
	case RADIUS_DISCONNECT_REQUEST:
	case RADIUS_CHANGE_FILTER_REQUEST:
		if(ri->is_duplicate){
			/* Duplicate is ignored */
			rs->radius_rtd[OVERALL].req_dup_num++;
			rs->radius_rtd[radius_cat].req_dup_num++;
			return 0;
		}
		else {
			rs->radius_rtd[OVERALL].open_req_num++;
			rs->radius_rtd[radius_cat].open_req_num++;
			return 0;
		}
	break;

	case RADIUS_ACCESS_ACCEPT:
	case RADIUS_ACCESS_REJECT:
	case RADIUS_ACCOUNTING_RESPONSE:
	case RADIUS_ACCESS_PASSWORD_ACK:
	case RADIUS_ACCESS_PASSWORD_REJECT:
	case RADIUS_ASCEND_ACCESS_EVENT_RESPONSE:
	case RADIUS_DISCONNECT_REQUEST_ACK:
	case RADIUS_DISCONNECT_REQUEST_NAK:
	case RADIUS_CHANGE_FILTER_REQUEST_ACK:
	case RADIUS_CHANGE_FILTER_REQUEST_NAK:
		if(ri->is_duplicate){
			/* Duplicate is ignored */
			rs->radius_rtd[OVERALL].rsp_dup_num++;
			rs->radius_rtd[radius_cat].rsp_dup_num++;
			return 0;
		}
		else if (!ri->request_available) {
			/* no request was seen */
			rs->radius_rtd[OVERALL].disc_rsp_num++;
			rs->radius_rtd[radius_cat].disc_rsp_num++;
			return 0;
		}
		else {
			rs->radius_rtd[OVERALL].open_req_num--;
			rs->radius_rtd[radius_cat].open_req_num--;
			/* calculate time delta between request and response */
			nstime_delta(&delta, &pinfo->fd->abs_ts, &ri->req_time);

			time_stat_update(&(rs->radius_rtd[OVERALL].stats),&delta, pinfo);
			time_stat_update(&(rs->radius_rtd[radius_cat].stats),&delta, pinfo);

			return 1;
		}
	break;

	default:
		return 0;
	break;
	}
}

static void
radiusstat_draw(void *prs)
{
	radiusstat_t *rs=(radiusstat_t *)prs;
	int i;
	/* gtk1 using a scrollable clist*/
	char *str[NUM_COLUMNS];

	for(i=0;i<NUM_COLUMNS;i++) {
		str[i]=g_malloc(sizeof(char[256]));
	}

	/* clear list before printing */
	gtk_clist_clear(rs->table);

	for(i=0;i<NUM_TIMESTATS;i++) {
		/* nothing seen, nothing to do */
		if(rs->radius_rtd[i].stats.num==0){
			continue;
		}

		g_snprintf(str[0], sizeof(char[256]), "%s", val_to_str(i,radius_message_code,"Other"));
		g_snprintf(str[1], sizeof(char[256]), "%d", rs->radius_rtd[i].stats.num);
		g_snprintf(str[2], sizeof(char[256]), "%8.2f msec", nstime_to_msec(&(rs->radius_rtd[i].stats.min)));
		g_snprintf(str[3], sizeof(char[256]), "%8.2f msec", nstime_to_msec(&(rs->radius_rtd[i].stats.max)));
		g_snprintf(str[4], sizeof(char[256]), "%8.2f msec", get_average(&(rs->radius_rtd[i].stats.tot), rs->radius_rtd[i].stats.num));
		g_snprintf(str[5], sizeof(char[256]), "%6u", rs->radius_rtd[i].stats.min_num);
		g_snprintf(str[6], sizeof(char[256]), "%6u", rs->radius_rtd[i].stats.max_num);
		g_snprintf(str[7], sizeof(char[256]), "%4u", rs->radius_rtd[i].open_req_num);
		g_snprintf(str[8], sizeof(char[256]), "%4u", rs->radius_rtd[i].disc_rsp_num);
		g_snprintf(str[9], sizeof(char[256]), "%4u (%4.2f%%)", rs->radius_rtd[i].req_dup_num, 
			rs->radius_rtd[i].stats.num?((double)rs->radius_rtd[i].req_dup_num*100)/(double)rs->radius_rtd[i].stats.num:0);
		g_snprintf(str[10], sizeof(char[256]), "%4u (%4.2f%%)", rs->radius_rtd[i].rsp_dup_num, 
			rs->radius_rtd[i].stats.num?((double)rs->radius_rtd[i].rsp_dup_num*100)/(double)rs->radius_rtd[i].stats.num:0);

		gtk_clist_append(rs->table, str);
	}

	gtk_widget_show(GTK_WIDGET(rs->table));
	for(i=0;i<NUM_COLUMNS;i++) {
		g_free(str[i]);
	}
}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	radiusstat_t *rs=(radiusstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(rs);
	unprotect_thread_critical_region();

	if(rs->filter){
		g_free(rs->filter);
		rs->filter=NULL;
	}
	g_free(rs);
}

static const gchar *titles[]={
			"Type",
			"Messages",
			"Min SRT",
			"Max SRT",
			"Avg SRT",
			"Min in Frame",
			"Max in Frame",
			"Open Requests",
			"Discarded Responses",
			"Repeated Requests",
			"Repeated Responses" };

static void
gtk_radiusstat_init(const char *optarg, void *userdata _U_)
{
	radiusstat_t *rs;
	const char *filter=NULL;
	GString *error_string;
	GtkWidget *bt_close;
	GtkWidget *bbox;

	if(strncmp(optarg,"radius,srt,",11) == 0){
		filter=optarg+11;
	} else {
		filter="";
	}

	rs=g_malloc(sizeof(radiusstat_t));
	rs->filter=g_strdup(filter);

	radiusstat_reset(rs);

	rs->win=window_new(GTK_WINDOW_TOPLEVEL, "RADIUS SRT");
	gtk_window_set_default_size(GTK_WINDOW(rs->win), 600, 150);

	rs->vbox=gtk_vbox_new(FALSE, 3);

	init_main_stat_window(rs->win, rs->vbox, "RADIUS Service Response Time (SRT) Statistics", filter);

	/* GTK1 using a scrollable clist*/
        /* init a scrolled window*/
	rs->scrolled_window = scrolled_window_new(NULL, NULL);

	rs->table = create_stat_table(rs->scrolled_window, rs->vbox, NUM_COLUMNS, titles);

	error_string=register_tap_listener("radius", rs, filter, radiusstat_reset, radiusstat_packet, radiusstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(rs->filter);
		g_free(rs);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(rs->vbox), bbox, FALSE, FALSE, 0);

	bt_close = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(rs->win, bt_close, window_cancel_button_cb);

	SIGNAL_CONNECT(rs->win, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(rs->win, "destroy", win_destroy_cb, rs);

	gtk_widget_show_all(rs->win);
	window_present(rs->win);
	
	cf_retap_packets(&cfile, FALSE);
}

static tap_dfilter_dlg radius_srt_dlg = {
	"RADIUS Service Response Time (SRT) Statistics",
	"radius,srt",
	gtk_radiusstat_init,
	-1
};

void
register_tap_listener_gtkradiusstat(void)
{
	register_dfilter_stat(&radius_srt_dlg, "RADIUS",
		    REGISTER_STAT_GROUP_RESPONSE_TIME);
}
