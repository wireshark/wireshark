/* smb_stat.c
 * smb_stat   2003 Ronnie Sahlberg
 *
 * $Id: smb_stat.c,v 1.30 2004/01/13 22:49:15 guy Exp $
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
#include "../smb.h"
#include "../register.h"
#include "../timestats.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "filter_prefs.h"
#include "service_response_time_table.h"

extern GtkWidget   *main_display_filter_widget;

/* used to keep track of the statistics for an entire program interface */
typedef struct _smbstat_t {
	GtkWidget *win;
	srt_stat_table smb_srt_table;
	srt_stat_table trans2_srt_table;
	srt_stat_table nt_trans_srt_table;
} smbstat_t;

static void
smbstat_set_title(smbstat_t *ss)
{
	char *title;

	title = g_strdup_printf("SMB Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(ss->win), title);
	g_free(title);
}

static void
smbstat_reset(void *pss)
{
	smbstat_t *ss=(smbstat_t *)pss;

	reset_srt_table_data(&ss->smb_srt_table);
	reset_srt_table_data(&ss->trans2_srt_table);
	reset_srt_table_data(&ss->nt_trans_srt_table);
	smbstat_set_title(ss);
}

static int
smbstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, void *psi)
{
	smbstat_t *ss=(smbstat_t *)pss;
	smb_info_t *si=psi;

	/* we are only interested in reply packets */
	if(si->request){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!si->sip){
		return 0;
	}

	add_srt_table_data(&ss->smb_srt_table, si->cmd, &si->sip->req_time, pinfo);

	if(si->cmd==0xA0){
		smb_nt_transact_info_t *sti=(smb_nt_transact_info_t *)si->sip->extra_info;

		if(sti){
			add_srt_table_data(&ss->nt_trans_srt_table, sti->subcmd, &si->sip->req_time, pinfo);
		}
	} else if(si->cmd==0x32){
		smb_transact2_info_t *st2i=(smb_transact2_info_t *)si->sip->extra_info;

		if(st2i){
			add_srt_table_data(&ss->trans2_srt_table, st2i->subcmd, &si->sip->req_time, pinfo);
		}
	}

	return 1;
}



static void
smbstat_draw(void *pss)
{
	smbstat_t *ss=(smbstat_t *)pss;

	draw_srt_table_data(&ss->smb_srt_table);
	draw_srt_table_data(&ss->trans2_srt_table);
	draw_srt_table_data(&ss->nt_trans_srt_table);
}


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	smbstat_t *ss=(smbstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ss);
	unprotect_thread_critical_region();

	free_srt_table_data(&ss->smb_srt_table);
	free_srt_table_data(&ss->trans2_srt_table);
	free_srt_table_data(&ss->nt_trans_srt_table);
	g_free(ss);
}


static void
gtk_smbstat_init(char *optarg)
{
	smbstat_t *ss;
	char *filter=NULL;
	GtkWidget *label;
	char filter_string[256];
	GString *error_string;
	int i;
	GtkWidget *vbox;

	if(!strncmp(optarg,"smb,srt,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	ss=g_malloc(sizeof(smbstat_t));

	ss->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(ss->win), 550, 600);
	smbstat_set_title(ss);
	SIGNAL_CONNECT(ss->win, "destroy", win_destroy_cb, ss);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ss->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("SMB Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);


	label=gtk_label_new("SMB Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show(ss->win);

	init_srt_table(&ss->smb_srt_table, 256, vbox, "smb.cmd");
	for(i=0;i<256;i++){
		init_srt_table_row(&ss->smb_srt_table, i, val_to_str(i, smb_cmd_vals, "Unknown(0x%02x)"));
	}


	label=gtk_label_new("Transaction2 Sub-Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);
	init_srt_table(&ss->trans2_srt_table, 256, vbox, "smb.trans2.cmd");
	for(i=0;i<256;i++){
		init_srt_table_row(&ss->trans2_srt_table, i, val_to_str(i, trans2_cmd_vals, "Unknown(0x%02x)"));
	}


	label=gtk_label_new("NT Transaction Sub-Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);
	init_srt_table(&ss->nt_trans_srt_table, 256, vbox, "smb.nt.function");
	for(i=0;i<256;i++){
		init_srt_table_row(&ss->nt_trans_srt_table, i, val_to_str(i, nt_cmd_vals, "Unknown(0x%02x)"));
	}


	error_string=register_tap_listener("smb", ss, filter, smbstat_reset, smbstat_packet, smbstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ss);
		return;
	}

	gtk_widget_show_all(ss->win);
	retap_packets(&cfile);
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
smbstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	char *filter;

	str = g_string_new("smb,srt");
	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]!=0){
		g_string_sprintfa(str,",%s", filter);
	}
	gtk_smbstat_init(str->str);
	g_string_free(str, TRUE);
}

static void
gtk_smbstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	GtkWidget *dlg_box;
	GtkWidget *filter_box, *filter_bt;
	GtkWidget *bbox, *start_button, *cancel_button;
	const char *filter;
	static construct_args_t args = {
	  "Service Response Time Statistics Filter",
	  TRUE,
	  FALSE
	};

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=dlg_window_new("Ethereal: Compute SMB SRT statistics");
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter button */
	filter_bt = gtk_button_new_with_label("Filter:");
	SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_bt, FALSE, TRUE, 0);
	gtk_widget_show(filter_bt);

	/* Filter entry */
	filter_entry=gtk_entry_new();
	WIDGET_SET_SIZE(filter_entry, 300, -2);

	/* filter prefs dialog */
	OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_entry);
	/* filter prefs dialog */

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
                              smbstat_start_button_clicked, NULL);
	gtk_box_pack_start(GTK_BOX(bbox), start_button, TRUE, TRUE, 0);
	GTK_WIDGET_SET_FLAGS(start_button, GTK_CAN_DEFAULT);
	gtk_widget_grab_default(start_button);
	gtk_widget_show(start_button);

	cancel_button=BUTTON_NEW_FROM_STOCK(GTK_STOCK_CANCEL);
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
register_tap_listener_gtksmbstat(void)
{
	register_ethereal_tap("smb,srt", gtk_smbstat_init);
}

void
register_tap_menu_gtksmbstat(void)
{
	register_tap_menu_item("_Statistics/Service Response Time/SMB...",
	    gtk_smbstat_cb, NULL, NULL, NULL);
}
