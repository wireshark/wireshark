/* mgcp_stat.c
 * mgcp-statistics for ethereal
 * Copyright 2003 Lars Roland
 *
 * $Id: mgcp_stat.c,v 1.19 2003/12/16 18:43:34 oabad Exp $
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

static GtkWidget *dlg=NULL;
static GtkWidget *filter_entry;


static void
mgcpstat_reset(void *pms)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	int i;
	char *title;

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

	if (! dlg)
		dlg=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	title = g_strdup_printf("MGCP SRT statistics: %s", cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(dlg), title);
	g_free(title);
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
	ms->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	WIDGET_SET_SIZE(ms->scrolled_window, 550, 150);

	ms->table = create_stat_table(ms->scrolled_window, ms->vbox, 7, titles);

	error_string=register_tap_listener("mgcp", ms, filter, mgcpstat_reset, mgcpstat_packet, mgcpstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ms->filter);
		g_free(ms);
		return;
	}

	gtk_widget_show_all(ms->win);
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
mgcpstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	char *filter;
	char str[256];

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]==0){
		gtk_mgcpstat_init("mgcp,srt");
	} else {
		sprintf(str,"mgcp,srt,%s", filter);
		gtk_mgcpstat_init(str);
	}
}



static void
gtk_mgcpstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	const char *filter;
	char *title;
	GtkWidget *dlg_box;
	GtkWidget *filter_box, *filter_label;
	GtkWidget *bbox, *start_button, *cancel_button;

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	title = g_strdup_printf("Ethereal: Compute MGCP SRT statistics: %s", cf_get_display_name(&cfile));

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
	WIDGET_SET_SIZE(filter_entry, 300, -2);
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
                              mgcpstat_start_button_clicked, NULL);
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
register_tap_listener_gtkmgcpstat(void)
{
	register_ethereal_tap("mgcp,srt", gtk_mgcpstat_init);
}

void
register_tap_menu_gtkmgcpstat(void)
{
	if (find_tap_id("mgcp"))
		register_tap_menu_item("Statistics/Service Response Time/MGCP...",
		    gtk_mgcpstat_cb, NULL, NULL);
}

