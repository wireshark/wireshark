/* gui_prefs.c
 * Dialog box for GUI preferences
 *
 * $Id: gui_prefs.c,v 1.1 1999/12/16 06:20:15 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include "config.h"
#endif

#include <errno.h>

#ifndef __GLOBALS_H__
#include "globals.h"
#endif

#include "gui_prefs.h"
#include "gtkglobals.h"

#ifndef __PREFS_DLG_H__
#include "prefs_dlg.h"
#endif

static void scrollbar_menu_item_cb(GtkWidget *w, gpointer data);

static gboolean temp_gui_scrollbar_on_right;

GtkWidget*
gui_prefs_show(void)
{
	GtkWidget	*main_vb, *hbox, *label;
	GtkWidget	*menu_item_left, *menu_item_right,
			*scrollbar_menu, *scrollbar_option_menu;

	temp_gui_scrollbar_on_right = prefs.gui_scrollbar_on_right;

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

	/* Scrollbar placment hbox */
	hbox = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start( GTK_BOX(main_vb), hbox, FALSE, FALSE, 5);

	label = gtk_label_new("Vertical Scrollbar Placement:");
	gtk_container_add( GTK_CONTAINER(hbox), label );

	/* Create a simple menu containing the LEFT/RIGHT choices for
	 * the scrollbar placement option */
	scrollbar_menu = gtk_menu_new();
	menu_item_left  = gtk_menu_item_new_with_label("Left");
	menu_item_right = gtk_menu_item_new_with_label("Right");
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_left );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_right );

	gtk_signal_connect( GTK_OBJECT(menu_item_left), "activate",
			scrollbar_menu_item_cb, GINT_TO_POINTER(FALSE) );
	gtk_signal_connect( GTK_OBJECT(menu_item_right), "activate",
			scrollbar_menu_item_cb, GINT_TO_POINTER(TRUE) );

	/* Create the option menu from the option */
	scrollbar_option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu( GTK_OPTION_MENU(scrollbar_option_menu),
			scrollbar_menu );
	gtk_option_menu_set_history( GTK_OPTION_MENU(scrollbar_option_menu),
			temp_gui_scrollbar_on_right);
	gtk_container_add( GTK_CONTAINER(hbox), scrollbar_option_menu );


	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}


static void
scrollbar_menu_item_cb(GtkWidget *w, gpointer data)
{
	gboolean	value = GPOINTER_TO_INT(data);

	temp_gui_scrollbar_on_right = value;
	set_scrollbar_placement(value);
}

void
gui_prefs_ok(GtkWidget *w)
{
	prefs.gui_scrollbar_on_right = temp_gui_scrollbar_on_right;
	gui_prefs_delete(w);
}

void
gui_prefs_save(GtkWidget *w)
{
	gui_prefs_ok(w);
}

void
gui_prefs_cancel(GtkWidget *w)
{
	/* Reset scrollbar placement value back to what the
	 * current preferences says it should be */
	temp_gui_scrollbar_on_right = prefs.gui_scrollbar_on_right;
	set_scrollbar_placement(prefs.gui_scrollbar_on_right);

	gui_prefs_delete(w);
}

void
gui_prefs_delete(GtkWidget *w)
{
}
