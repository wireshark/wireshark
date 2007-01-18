/* macros_dlg.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <gtk/gtk.h>
#include <epan/dfilter/dfilter-macro.h>
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"

static void append_macro(dfilter_macro_t* m, void* lp) {
	GtkWidget *list = lp;
	simple_list_append(list, 0, m->name, 1, m->text, -1);
}

void macros_dialog_cb(GtkWidget *w _U_, gpointer data _U_) {
	GtkWidget   *macros_w, *vbox;
    GtkWidget *scrolledwindow;
    GtkWidget *list;
    const gchar *titles[] = {"Name", "Text"};
	
	macros_w = window_new(GTK_WINDOW_TOPLEVEL, "Display Filter Macros");
	gtk_window_set_default_size(GTK_WINDOW(macros_w), 650, 600);

#if GTK_MAJOR_VERSION >= 2
	gtk_window_set_position(GTK_WINDOW(macros_w), GTK_WIN_POS_CENTER_ON_PARENT);
#else
	gtk_window_set_position(GTK_WINDOW(macros_w), GTK_WIN_POS_CENTER);
#endif
	
	gtk_container_border_width(GTK_CONTAINER(macros_w), 6);

	vbox = gtk_vbox_new(FALSE, 12);
	gtk_container_border_width(GTK_CONTAINER(vbox), 6);
	gtk_container_add(GTK_CONTAINER(macros_w), vbox);

	scrolledwindow = scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(vbox), scrolledwindow);
		
#if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), 
										GTK_SHADOW_IN);
#endif
	
    list = simple_list_new(2 , titles);
	dfilter_macro_foreach(append_macro, list);
    gtk_container_add(GTK_CONTAINER(scrolledwindow), list);
	
	gtk_widget_show_all(macros_w);

    return;
}

