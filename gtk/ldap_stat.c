/* ldap_stat.c
 * ldap_stat   2003 Ronnie Sahlberg
 *
 * $Id: ldap_stat.c,v 1.7 2004/01/13 22:49:14 guy Exp $
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
#include "../packet-ldap.h"
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
typedef struct _ldapstat_t {
	GtkWidget *win;
	srt_stat_table ldap_srt_table;
} ldapstat_t;

static void
ldapstat_set_title(ldapstat_t *ldap)
{
	char		*title;

	title = g_strdup_printf("LDAP Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(ldap->win), title);
	g_free(title);
}

static void
ldapstat_reset(void *pldap)
{
	ldapstat_t *ldap=(ldapstat_t *)pldap;

	reset_srt_table_data(&ldap->ldap_srt_table);
	ldapstat_set_title(ldap);
}

static int
ldapstat_packet(void *pldap, packet_info *pinfo, epan_dissect_t *edt _U_, void *psi)
{
	ldap_call_response_t *ldap=(ldap_call_response_t *)psi;
	ldapstat_t *fs=(ldapstat_t *)pldap;

	/* we are only interested in reply packets */
	if(ldap->is_request){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!ldap->req_frame){ 
		return 0;
	}

	/* only use the commands we know how to handle */
	switch(ldap->protocolOpTag){
	case LDAP_REQ_BIND:
	case LDAP_REQ_SEARCH:
	case LDAP_REQ_MODIFY:
	case LDAP_REQ_ADD:
	case LDAP_REQ_DELETE:
	case LDAP_REQ_MODRDN:
	case LDAP_REQ_COMPARE:
	case LDAP_REQ_EXTENDED:
		break;
	default:
		return 0;
	}

	add_srt_table_data(&fs->ldap_srt_table, ldap->protocolOpTag, &ldap->req_time, pinfo);

	return 1;
}



static void
ldapstat_draw(void *pldap)
{
	ldapstat_t *ldap=(ldapstat_t *)pldap;

	draw_srt_table_data(&ldap->ldap_srt_table);
}


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	ldapstat_t *ldap=(ldapstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ldap);
	unprotect_thread_critical_region();

	free_srt_table_data(&ldap->ldap_srt_table);
	g_free(ldap);
}


static void
gtk_ldapstat_init(char *optarg)
{
	ldapstat_t *ldap;
	char *filter=NULL;
	GtkWidget *label;
	char filter_string[256];
	GString *error_string;
	GtkWidget *vbox;

	if(!strncmp(optarg,"ldap,srt,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	ldap=g_malloc(sizeof(ldapstat_t));

	ldap->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(ldap->win), 550, 400);
	ldapstat_set_title(ldap);
	SIGNAL_CONNECT(ldap->win, "destroy", win_destroy_cb, ldap);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ldap->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("LDAP Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);


	label=gtk_label_new("LDAP Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show(ldap->win);

	init_srt_table(&ldap->ldap_srt_table, 24, vbox, NULL);
	init_srt_table_row(&ldap->ldap_srt_table, 0, "Bind");
	init_srt_table_row(&ldap->ldap_srt_table, 1, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 2, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 3, "Search");
	init_srt_table_row(&ldap->ldap_srt_table, 4, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 5, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 6, "Modify");
	init_srt_table_row(&ldap->ldap_srt_table, 7, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 8, "Add");
	init_srt_table_row(&ldap->ldap_srt_table, 9, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 10, "Delete");
	init_srt_table_row(&ldap->ldap_srt_table, 11, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 12, "Modrdn");
	init_srt_table_row(&ldap->ldap_srt_table, 13, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 14, "Compare");
	init_srt_table_row(&ldap->ldap_srt_table, 15, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 16, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 17, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 18, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 19, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 20, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 21, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 22, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 23, "Extended");


	error_string=register_tap_listener("ldap", ldap, filter, ldapstat_reset, ldapstat_packet, ldapstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ldap);
		return;
	}

	gtk_widget_show_all(ldap->win);
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
ldapstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	char *filter;

	str = g_string_new("ldap,srt");
	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]!=0){
		g_string_sprintfa(str,",%s", filter);
	}
	gtk_ldapstat_init(str->str);
	g_string_free(str, TRUE);
}

static void
gtk_ldapstat_cb(GtkWidget *w _U_, gpointer d _U_)
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

	dlg=dlg_window_new("Ethereal: Compute LDAP Service Response Time statistics");
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter button */
	filter_bt=gtk_button_new_with_label("Filter:");
	SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_bt, FALSE, FALSE, 0);
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
                              ldapstat_start_button_clicked, NULL);
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
register_tap_listener_gtkldapstat(void)
{
	register_ethereal_tap("ldap,srt", gtk_ldapstat_init);
}

void
register_tap_menu_gtkldapstat(void)
{
	register_tap_menu_item("_Statistics/Service Response Time/LDAP...",
	    gtk_ldapstat_cb, NULL, NULL, NULL);
}
