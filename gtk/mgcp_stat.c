/* mgcp_stat.c
 * mgcp-statistics for ethereal
 * Copyright 2003 Lars Roland
 *
 * $Id: mgcp_stat.c,v 1.6 2003/04/27 21:50:59 guy Exp $
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
#include "menu.h"
#include "../epan/packet_info.h"
#include "../tap.h"
#include "../epan/value_string.h"
#include "../register.h"
#include "../plugins/mgcp/packet-mgcp.h"
#include "../timestats.h"
#include "gtk_stat_util.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../globals.h"



#define NUM_TIMESTATS 11

/* used to keep track of the statistics for an entire program interface */
typedef struct _mgcpstat_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
#if GTK_MAJOR_VERSION >= 2
	gtk_table *table;
#else /* gtk1 using a scrollable clist*/
	GtkWidget *scrolled_window;
	GtkCList *table;
#endif
        timestat_t rtd[NUM_TIMESTATS];
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
} mgcpstat_t;

static const value_string mgcp_mesage_type[] = {
  {  0,	"Overall"},
  {  1,	"EPCF"},
  {  2,	"CRCX"},
  {  3,	"MDCX"},
  {  4,	"DLCX"},
  {  5,	"RQNT"},
  {  6,	"NTFY"},
  {  7,	"AUEP"},
  {  8, "AUCX"},
  {  9, "RSIP"},
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

			time_stat_update(&(ms->rtd[0]),&delta, pinfo);

			if (strncasecmp(mi->code, "EPCF", 4) == 0 ) {
				time_stat_update(&(ms->rtd[1]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "CRCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[2]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "MDCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[3]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "DLCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[4]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RQNT", 4) == 0 ) {
				time_stat_update(&(ms->rtd[5]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "NTFY", 4) == 0 ) {
				time_stat_update(&(ms->rtd[6]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUEP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[7]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[8]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RSIP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[9]),&delta, pinfo);
			}
			else {
				time_stat_update(&(ms->rtd[10]),&delta, pinfo);
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
#if GTK_MAJOR_VERSION >= 2
	int pos;
	char str[256];

	gtk_widget_destroy(ms->table->widget);
	ms->table->height=5;
	ms->table->width=7;
	ms->table->widget=gtk_table_new(ms->table->height, ms->table->width, TRUE);
	gtk_container_add(GTK_CONTAINER(ms->vbox), ms->table->widget);

	pos=0;

	add_table_entry(ms->table, "Type", 0, pos);
	add_table_entry(ms->table, "Messages", 1, pos);
	add_table_entry(ms->table, "Min RTD", 2, pos);
	add_table_entry(ms->table, "Max RTD", 3, pos);
	add_table_entry(ms->table, "Avg RTD", 4, pos);
	add_table_entry(ms->table, "Min in Frame", 5, pos);
	add_table_entry(ms->table, "Max in Frame", 6, pos);
	pos++;

	for(i=0;i<NUM_TIMESTATS;i++) {
		/* nothing seen, nothing to do */
		if(ms->rtd[i].num==0){
			continue;
		}

		sprintf(str, "%s", val_to_str(i,mgcp_mesage_type,"Other"));
		add_table_entry(ms->table, str, 0, pos);
		sprintf(str, "%d", ms->rtd[i].num);
		add_table_entry(ms->table, str, 1, pos);
		sprintf(str, "%8.2f msec", nstime_to_msec(&(ms->rtd[i].min)));
		add_table_entry(ms->table, str, 2, pos);
		sprintf(str, "%8.2f msec", nstime_to_msec(&(ms->rtd[i].max)));
		add_table_entry(ms->table, str, 3, pos);
		sprintf(str, "%8.2f msec", get_average(&(ms->rtd[i].tot), ms->rtd[i].num));
		add_table_entry(ms->table, str, 4, pos);
		sprintf(str, "%6u", ms->rtd[i].min_num);
		add_table_entry(ms->table, str, 5, pos);
		sprintf(str, "%6u", ms->rtd[i].max_num);
		add_table_entry(ms->table, str, 6, pos);
		pos++;
	}

	gtk_widget_show(ms->table->widget);
#else /* gtk1 using a scrollable clist*/
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
		sprintf(str[3], "%8.2f msec", nstime_to_msec(&(ms->rtd[i].max)));;
		sprintf(str[4], "%8.2f msec", get_average(&(ms->rtd[i].tot), ms->rtd[i].num));
		sprintf(str[5], "%6u", ms->rtd[i].min_num);
		sprintf(str[6], "%6u", ms->rtd[i].max_num);
		gtk_clist_append(ms->table, str);
	}

	gtk_widget_show(GTK_WIDGET(ms->table));
	for(i=0;i<7;i++) {
		g_free(str[i]);
	}
#endif
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
#if GTK_MAJOR_VERSION >= 2
	g_free(ms->table);
	ms->table=NULL;
#endif
	g_free(ms);
}

static gchar *titles[]={"Type",
			"Messages",
			"Min RTD",
			"Max RTD",
			"Avg RTD",
			"Min in Frame",
			"Max in Frame" };

void
gtk_mgcpstat_init(char *optarg)
{
	mgcpstat_t *ms;
	char *filter=NULL;
	GString *error_string;
#if GTK_MAJOR_VERSION >= 2
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	char filter_string[256];
#endif

	if(strncmp(optarg,"mgcp,rtd,",9) == 0){
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

	init_main_stat_window(ms->win, ms->vbox, "MGCP Response Time Delay (RTD) Statistics", filter);

#if GTK_MAJOR_VERSION >= 2

	ms->table =(gtk_table *)g_malloc(sizeof(gtk_table));
	ms->table->height=5;
	ms->table->width=7;
	ms->table->widget=gtk_table_new(ms->table->height, ms->table->width, TRUE);
	gtk_container_add(GTK_CONTAINER(ms->vbox), ms->table->widget);

	add_table_entry(ms->table, "Type", 0, 0);
	add_table_entry(ms->table, "Messages", 1, 0);
	add_table_entry(ms->table, "Min RTD", 2, 0);
	add_table_entry(ms->table, "Max RTD", 3, 0);
	add_table_entry(ms->table, "Avg RTD", 4, 0);
	add_table_entry(ms->table, "Min in Frame", 5, 0);
	add_table_entry(ms->table, "Max in Frame", 6, 0);

	gtk_widget_show(ms->table->widget);

#else /* GTK1 using a scrollable clist*/
        /* init a scrolled window*/
	ms->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	WIDGET_SET_SIZE(ms->scrolled_window, 550, 100);

	ms->table = create_stat_table(ms->scrolled_window, ms->vbox, 7, titles);
#endif

	error_string=register_tap_listener("mgcp", ms, filter, mgcpstat_reset, mgcpstat_packet, mgcpstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
#if GTK_MAJOR_VERSION >= 2
		g_free(ms->table);
#endif
		g_free(ms->filter);
		g_free(ms);
		return;
	}

	gtk_widget_show_all(ms->win);
	redissect_packets(&cfile);
}


static GtkWidget *dlg=NULL, *dlg_box;
static GtkWidget *filter_box;
static GtkWidget *filter_label, *filter_entry;
static GtkWidget *start_button;

static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}

static void
mgcpstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	char *filter;
	char str[256];

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]==0){
		gtk_mgcpstat_init("mgcp,rtd");
	} else {
		sprintf(str,"mgcp,rtd,%s", filter);
		gtk_mgcpstat_init(str);
	}
}



static void
gtk_mgcpstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(dlg), "MGCP RTD Statistics");
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);
	dlg_box=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);


	/* filter box */
	filter_box=gtk_hbox_new(FALSE, 10);
	/* Filter label */
	gtk_container_set_border_width(GTK_CONTAINER(filter_box), 10);
	filter_label=gtk_label_new("Filter:");
	gtk_box_pack_start(GTK_BOX(filter_box), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);

	filter_entry=gtk_entry_new_with_max_length(250);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, FALSE, FALSE, 0);
	gtk_widget_show(filter_entry);

	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);


	/* the start button */
	start_button=gtk_button_new_with_label("Create Stat");
        SIGNAL_CONNECT_OBJECT(start_button, "clicked",
                              mgcpstat_start_button_clicked, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), start_button, TRUE, TRUE, 0);
	gtk_widget_show(start_button);

	gtk_widget_show_all(dlg);
}

void
register_tap_listener_gtkmgcpstat(void)
{
	register_ethereal_tap("mgcp,rtd", gtk_mgcpstat_init);
}

void
register_tap_menu_gtkmgcpstat(void)
{
	if (find_tap_id("mgcp"))
		register_tap_menu_item("MGCP/RTD", gtk_mgcpstat_cb);
}

