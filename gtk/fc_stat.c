/* fc_stat.c
 * fc_stat   2003 Ronnie Sahlberg
 *
 * $Id: fc_stat.c,v 1.12 2003/09/26 02:09:44 guy Exp $
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
#include "../packet-fc.h"
#include "../register.h"
#include "../timestats.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "service_response_time_table.h"

extern GtkWidget   *main_display_filter_widget;

/* used to keep track of the statistics for an entire program interface */
typedef struct _fcstat_t {
	GtkWidget *win;
	srt_stat_table fc_srt_table;
} fcstat_t;

static void
fcstat_set_title(fcstat_t *fc)
{
	char		*title;

	title = g_strdup_printf("Fibre Channel Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(fc->win), title);
	g_free(title);
}

static void
fcstat_reset(void *pfc)
{
	fcstat_t *fc=(fcstat_t *)pfc;

	reset_srt_table_data(&fc->fc_srt_table);
	fcstat_set_title(fc);
}

static int
fcstat_packet(void *pfc, packet_info *pinfo, epan_dissect_t *edt _U_, void *psi)
{
	fc_hdr *fc=(fc_hdr *)psi;
	fcstat_t *fs=(fcstat_t *)pfc;

	/* we are only interested in reply packets */
	if(!(fc->fctl&FC_FCTL_EXCHANGE_RESPONDER)){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if( (!fc->fced) || (fc->fced->first_exchange_frame==0) ){
		return 0;
	}

	add_srt_table_data(&fs->fc_srt_table, fc->type, &fc->fced->fc_time, pinfo);

	return 1;
}



static void
fcstat_draw(void *pfc)
{
	fcstat_t *fc=(fcstat_t *)pfc;

	draw_srt_table_data(&fc->fc_srt_table);
}


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	fcstat_t *fc=(fcstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(fc);
	unprotect_thread_critical_region();

	free_srt_table_data(&fc->fc_srt_table);
	g_free(fc);
}


static void
gtk_fcstat_init(char *optarg)
{
	fcstat_t *fc;
	char *filter=NULL;
	GtkWidget *label;
	char filter_string[256];
	GString *error_string;
	int i;
	GtkWidget *vbox;

	if(!strncmp(optarg,"fc,srt,",7)){
		filter=optarg+7;
	} else {
		filter=NULL;
	}

	fc=g_malloc(sizeof(fcstat_t));

	fc->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(fc->win), 550, 400);
	fcstat_set_title(fc);
	SIGNAL_CONNECT(fc->win, "destroy", win_destroy_cb, fc);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(fc->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("Fibre Channel Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);


	label=gtk_label_new("Fibre Channel Types");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show(fc->win);

	init_srt_table(&fc->fc_srt_table, 256, vbox, NULL);
	for(i=0;i<256;i++){
		init_srt_table_row(&fc->fc_srt_table, i, val_to_str(i, fc_fc4_val, "Unknown(0x%02x)"));
	}


	error_string=register_tap_listener("fc", fc, filter, fcstat_reset, fcstat_packet, fcstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(fc);
		return;
	}

	gtk_widget_show_all(fc->win);
	redissect_packets(&cfile);
}



static GtkWidget *dlg=NULL;
static GtkWidget *filter_entry;

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
fcstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	char *filter;

	str = g_string_new("fc,srt");
	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]!=0){
		g_string_sprintfa(str,",%s", filter);
	}
	gtk_fcstat_init(str->str);
	g_string_free(str, TRUE);
}

static void
gtk_fcstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	GtkWidget *dlg_box;
	GtkWidget *filter_box, *filter_label;
	GtkWidget *bbox, *start_button, *cancel_button;
	char *filter;

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=dlg_window_new("Ethereal: Compute Fibre Channel Service Response Time statistics");
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
	bbox=gtk_hbutton_box_new();
	gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_DEFAULT_STYLE);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	/* the start button */
	start_button=gtk_button_new_with_label("Create Stat");
        SIGNAL_CONNECT_OBJECT(start_button, "clicked",
                              fcstat_start_button_clicked, NULL);
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
	   button had been selected, as happens if Return is typed if some
	   widget that *doesn't* handle the Return key has the input
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
register_tap_listener_gtkfcstat(void)
{
	register_ethereal_tap("fc,srt", gtk_fcstat_init);
}

void
register_tap_menu_gtkfcstat(void)
{
	register_tap_menu_item("Statistics/Service Response Time/Fibre Channel...",
	    gtk_fcstat_cb, NULL, NULL);
}
