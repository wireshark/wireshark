/* tap_dfilter_dlg.c
 * Routines for display filter dialog used by gui taps
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <string.h>

#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "filter_dlg.h"
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "../tap_dfilter_dlg.h"
#include "gui_utils.h"
#include "gtkglobals.h"


typedef struct _tap_dfilter_dlg_list_item {
	GtkWidget *dlg;
	GtkWidget *filter_entry;
	tap_dfilter_dlg cont;
	construct_args_t args;
	struct _tap_dfilter_dlg_list_item *next;
} tap_dfilter_dlg_list_item;

static tap_dfilter_dlg_list_item *start_dlg_list=NULL;
static tap_dfilter_dlg_list_item *end_dlg_list=NULL;
static tap_dfilter_dlg_list_item *current_dlg = NULL;

static void
tap_dfilter_dlg_cb(GtkWidget *w, gpointer data);

/*
 * Register a stat that has a display filter dialog.
 * We register it both as a command-line stat and a menu item stat.
 */
void
register_dfilter_stat(tap_dfilter_dlg *info, const char *name,
    REGISTER_STAT_GROUP_E group)
{
	char *full_name;

	register_stat_cmd_arg(info->init_string, info->tap_init_cb, NULL);

	/*
	 * This menu item will pop up a dialog box, so append "..."
	 * to it.
	 */
	full_name = g_strdup_printf("%s...", name);
	register_stat_menu_item(full_name, group, tap_dfilter_dlg_cb, NULL,
	    NULL, info);
	g_free(full_name);
}              

void tap_dfilter_dlg_update (void)
{
	tap_dfilter_dlg_list_item *dialog = start_dlg_list;
	char *title;
	
	while(dialog != NULL) {
		if(dialog->dlg) {
			title = g_strdup_printf("Ethereal: %s: %s", dialog->cont.win_title , cf_get_display_name(&cfile));
			gtk_window_set_title(GTK_WINDOW(dialog->dlg), title);
			g_free(title);
		}
		dialog = dialog->next;		
	}
}

static void
dlg_destroy_cb(GtkWidget *item _U_, gpointer dialog_data)
{	
	tap_dfilter_dlg_list_item *dlg_data = (tap_dfilter_dlg_list_item *) dialog_data;
	dlg_data->dlg = NULL;
}

static void
tap_dfilter_dlg_start_button_clicked(GtkWidget *item _U_, gpointer dialog_data)
{
	const char *filter;
	char str[256];
	
	tap_dfilter_dlg_list_item *dlg_data = (tap_dfilter_dlg_list_item *) dialog_data;

	filter=gtk_entry_get_text(GTK_ENTRY(dlg_data->filter_entry));
	if(filter[0]==0){
		g_snprintf(str, sizeof(str), "%s", dlg_data->cont.init_string);
	} else {
		g_snprintf(str, sizeof(str), "%s,%s", dlg_data->cont.init_string, filter);
	}
	(dlg_data->cont.tap_init_cb)(str,NULL);
}


static void
tap_dfilter_dlg_cb(GtkWidget *w _U_, gpointer data)
{
	const char *filter;
	char *title;
	GtkWidget *dlg_box;
	GtkWidget *filter_box, *filter_bt;
	GtkWidget *bbox, *start_button, *cancel_button;
	
	tap_dfilter_dlg *dlg_data = (tap_dfilter_dlg *) data;	

	if(dlg_data==NULL)
		return;
		
	if(dlg_data->index==-1) {
		/* Dialog is not registered */
		if(start_dlg_list==NULL) {
			start_dlg_list = (tap_dfilter_dlg_list_item *) g_malloc(sizeof (tap_dfilter_dlg_list_item));
			end_dlg_list = start_dlg_list;
			end_dlg_list->cont.index = 0; /* first entry in list -> index = 0 */
		} else {
			end_dlg_list->next = (tap_dfilter_dlg_list_item *) g_malloc(sizeof (tap_dfilter_dlg_list_item));
			end_dlg_list->next->cont.index = end_dlg_list->cont.index + 1;
			end_dlg_list = end_dlg_list->next;
		}
		end_dlg_list->dlg = NULL;
		end_dlg_list->filter_entry = NULL;
		end_dlg_list->cont.win_title = dlg_data->win_title;
		end_dlg_list->cont.init_string = dlg_data->init_string;
		end_dlg_list->cont.tap_init_cb = dlg_data->tap_init_cb;
		end_dlg_list->args.title = g_strdup_printf("%s Filter", dlg_data->win_title);
		end_dlg_list->args.wants_apply_button = TRUE;
		end_dlg_list->args.activate_on_ok = FALSE;
        end_dlg_list->args.modal_and_transient = FALSE;
		end_dlg_list->next = NULL;
		dlg_data->index = end_dlg_list->cont.index;
		current_dlg = end_dlg_list;
	} else {
		/* Dialog is registered, find it */
		current_dlg = start_dlg_list;
		while(dlg_data->index != current_dlg->cont.index)
		{
			if(current_dlg->next == NULL) {
				/* could not find any dialog */
				return;
			}
			current_dlg = current_dlg->next;
		}
	}

	/* if the window is already open, bring it to front */
	if(current_dlg->dlg){
		gdk_window_raise(current_dlg->dlg->window);
		return;
	}

	title = g_strdup_printf("Ethereal: %s: %s", current_dlg->cont.win_title , cf_get_display_name(&cfile));

	current_dlg->dlg=dlg_window_new(title);
	gtk_window_set_default_size(GTK_WINDOW(current_dlg->dlg), 300, -1);
	g_free(title);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(current_dlg->dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter button */
	filter_bt=BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY);
	SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &(current_dlg->args));
	gtk_box_pack_start(GTK_BOX(filter_box), filter_bt, FALSE, TRUE, 0);
	gtk_widget_show(filter_bt);

	/* Filter entry */
	current_dlg->filter_entry=gtk_entry_new();
    SIGNAL_CONNECT(current_dlg->filter_entry, "changed", filter_te_syntax_check_cb, NULL);
	
	/* filter prefs dialog */
	OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, current_dlg->filter_entry);
	/* filter prefs dialog */
	
	gtk_box_pack_start(GTK_BOX(filter_box), current_dlg->filter_entry, TRUE, TRUE, 0);
	filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	if(filter){
		gtk_entry_set_text(GTK_ENTRY(current_dlg->filter_entry), filter);
	}
	gtk_widget_show(current_dlg->filter_entry);

	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);

	/* button box */
    bbox = dlg_button_row_new(ETHEREAL_STOCK_CREATE_STAT, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    start_button = OBJECT_GET_DATA(bbox, ETHEREAL_STOCK_CREATE_STAT);
    SIGNAL_CONNECT(start_button, "clicked",
                              tap_dfilter_dlg_start_button_clicked, current_dlg);

    cancel_button = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    window_set_cancel_button(current_dlg->dlg, cancel_button, window_cancel_button_cb);

	/* Catch the "activate" signal on the filter text entry, so that
	   if the user types Return there, we act as if the "Create Stat"
	   button had been selected, as happens if Return is typed if
	   some widget that *doesn't* handle the Return key has the input
	   focus. */
	dlg_set_activate(current_dlg->filter_entry, start_button);

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(current_dlg->filter_entry);

    gtk_widget_grab_default(start_button );

    SIGNAL_CONNECT(current_dlg->dlg, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(current_dlg->dlg, "destroy", dlg_destroy_cb, current_dlg);

    gtk_widget_show_all(current_dlg->dlg);
    window_present(current_dlg->dlg);
}
