/* tap_dfilter_dlg.c
 * Routines for display filter dialog used by gui taps
 * Copyright 2003 Lars Roland
 *
 * $Id: tap_dfilter_dlg.c,v 1.1 2003/12/17 22:13:08 guy Exp $
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

#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"

#include "tap_dfilter_dlg.h"

extern GtkWidget *main_display_filter_widget;

typedef struct _tap_dfilter_dlg_list_item {
	GtkWidget *dlg;
	GtkWidget *filter_entry;
	tap_dfilter_dlg cont;
	struct _tap_dfilter_dlg_list_item *next;
} tap_dfilter_dlg_list_item;

tap_dfilter_dlg_list_item *start_dlg_list=NULL;
tap_dfilter_dlg_list_item *end_dlg_list=NULL;
tap_dfilter_dlg_list_item *current_dlg = NULL;

static void
dlg_destroy_cb(GtkWidget *item _U_, gpointer dialog_data)
{	
	tap_dfilter_dlg_list_item *dlg_data = (tap_dfilter_dlg_list_item *) dialog_data;
	dlg_data->dlg = NULL;
}

static void
dlg_cancel_cb(GtkWidget *cancel_bt _U_, gpointer parent_w)
{
	gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
tap_dfilter_dlg_start_button_clicked(GtkWidget *item _U_, gpointer dialog_data)
{
	char *filter;
	char str[256];
	
	tap_dfilter_dlg_list_item *dlg_data = (tap_dfilter_dlg_list_item *) dialog_data;

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(dlg_data->filter_entry));
	if(filter[0]==0){
		sprintf(str,"%s", dlg_data->cont.init_string);
	} else {
		sprintf(str,"%s,%s", dlg_data->cont.init_string, filter);		
	}
	(dlg_data->cont.tap_init_cb)(str);
}


void
gtk_tap_dfilter_dlg_cb(GtkWidget *w _U_, gpointer data)
{
	const char *filter;
	char *title;
	GtkWidget *dlg_box;
	GtkWidget *filter_box, *filter_label;
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
	g_free(title);
	SIGNAL_CONNECT(current_dlg->dlg, "destroy", dlg_destroy_cb, current_dlg);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(current_dlg->dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter label */
	filter_label=gtk_label_new("Filter:");
	gtk_box_pack_start(GTK_BOX(filter_box), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);

	/* Filter entry */
	current_dlg->filter_entry=gtk_entry_new();
	WIDGET_SET_SIZE(current_dlg->filter_entry, 300, -2);
	gtk_box_pack_start(GTK_BOX(filter_box), current_dlg->filter_entry, TRUE, TRUE, 0);
	filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	if(filter){
		gtk_entry_set_text(GTK_ENTRY(current_dlg->filter_entry), filter);
	}
	gtk_widget_show(current_dlg->filter_entry);

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
        SIGNAL_CONNECT(start_button, "clicked",
                              tap_dfilter_dlg_start_button_clicked, current_dlg);
	gtk_box_pack_start(GTK_BOX(bbox), start_button, TRUE, TRUE, 0);
	GTK_WIDGET_SET_FLAGS(start_button, GTK_CAN_DEFAULT);
	gtk_widget_grab_default(start_button);
	gtk_widget_show(start_button);

#if GTK_MAJOR_VERSION < 2
	cancel_button=gtk_button_new_with_label("Cancel");
#else
	cancel_button=gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
	SIGNAL_CONNECT(cancel_button, "clicked", dlg_cancel_cb, current_dlg->dlg);
	GTK_WIDGET_SET_FLAGS(cancel_button, GTK_CAN_DEFAULT);
	gtk_box_pack_start(GTK_BOX(bbox), cancel_button, TRUE, TRUE, 0);
	gtk_widget_show(cancel_button);

	/* Catch the "activate" signal on the filter text entry, so that
	   if the user types Return there, we act as if the "Create Stat"
	   button had been selected, as happens if Return is typed if
	   some widget that *doesn't* handle the Return key has the input
	   focus. */
	dlg_set_activate(current_dlg->filter_entry, start_button);

	/* Catch the "key_press_event" signal in the window, so that we can
	   catch the ESC key being pressed and act as if the "Cancel" button
	   had been selected. */
	dlg_set_cancel(current_dlg->dlg, cancel_button);

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(current_dlg->filter_entry);

	gtk_widget_show_all(current_dlg->dlg);
}
