/* h225_ras_srt.c
 * h225 RAS Service Response Time statistics for ethereal
 * Copyright 2003 Lars Roland
 *
 * $Id: h225_ras_srt.c,v 1.1 2003/11/16 23:11:20 sahlberg Exp $
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

extern GtkWidget *main_display_filter_widget;

static GtkWidget *dlg=NULL;
static GtkWidget *filter_entry;

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



static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}

static void
dlg_cancel_cb(GtkWidget *cancel_bt _U_, gpointer parent_w)
{
	gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
h225rassrt_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	char *filter;
	char str[256];

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]==0){
		gtk_h225rassrt_init("h225,srt");
	} else {
		sprintf(str,"h225,srt,%s", filter);
		gtk_h225rassrt_init(str);
	}
}


static void
gtk_h225rassrt_cb(GtkWidget *w _U_, gpointer d _U_)
{
	char *filter;
	char *title;
	GtkWidget *dlg_box;
	GtkWidget *filter_box, *filter_label;
	GtkWidget *bbox, *start_button, *cancel_button;

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	title = g_strdup_printf("Ethereal: H.225 RAS Service Response Time: %s", cf_get_display_name(&cfile));

	dlg=dlg_window_new(title);
	g_free(title);
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter label */
	filter_label=gtk_label_new("Filter:");
	gtk_box_pack_start(GTK_BOX(filter_box), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);

	/* Filter entry */
	filter_entry=gtk_entry_new();
	gtk_widget_set_usize(filter_entry, 300, -2);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, TRUE, TRUE, 0);
	filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	if(filter){
		gtk_entry_set_text(GTK_ENTRY(filter_entry), filter);
	}
	gtk_widget_show(filter_entry);

	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);

	/* button box */
	bbox = gtk_hbutton_box_new();
	gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_DEFAULT_STYLE);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	/* the start button */
	start_button=gtk_button_new_with_label("Create Stat");
        SIGNAL_CONNECT_OBJECT(start_button, "clicked",
                              h225rassrt_start_button_clicked, NULL);
	gtk_box_pack_start(GTK_BOX(bbox), start_button, TRUE, TRUE, 0);
	GTK_WIDGET_SET_FLAGS(start_button, GTK_CAN_DEFAULT);
	gtk_widget_grab_default(start_button);
	gtk_widget_show(start_button);

#if GTK_MAJOR_VERSION < 2
	cancel_button=gtk_button_new_with_label("Cancel");
#else
	cancel_button=gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
	SIGNAL_CONNECT(cancel_button, "clicked", dlg_cancel_cb, dlg);
	GTK_WIDGET_SET_FLAGS(cancel_button, GTK_CAN_DEFAULT);
	gtk_box_pack_start(GTK_BOX(bbox), cancel_button, TRUE, TRUE, 0);
	gtk_widget_show(cancel_button);

	/* Catch the "activate" signal on the filter text entry, so that
	   if the user types Return there, we act as if the "Create Stat"
	   button had been selected, as happens if Return is typed if
	   some widget that *doesn't* handle the Return key has the input
	   focus. */
	dlg_set_activate(filter_entry, start_button);

	/* Catch the "key_press_event" signal in the window, so that we can
	   catch the ESC key being pressed and act as if the "Cancel" button
	   had been selected. */
	dlg_set_cancel(dlg, cancel_button);

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(filter_entry);

	gtk_widget_show_all(dlg);
}

void
register_tap_listener_gtk_h225rassrt(void)
{
	register_ethereal_tap("h225,srt", gtk_h225rassrt_init);
}

void
register_tap_menu_gtk_h225rassrt(void)
{
	register_tap_menu_item("Statistics/Service Response Time/ITU-T H.225 RAS ...",
	    gtk_h225rassrt_cb, NULL, NULL);
}
