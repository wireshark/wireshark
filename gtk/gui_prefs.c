/* gui_prefs.c
 * Dialog box for GUI preferences
 *
 * $Id: gui_prefs.c,v 1.5 2000/08/11 13:33:02 deniel Exp $
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

#include "globals.h"
#include "gui_prefs.h"
#include "gtkglobals.h"
#include "prefs_dlg.h"

static void scrollbar_menu_item_cb(GtkWidget *w, gpointer data);
static void plist_sel_browse_cb(GtkWidget *w, gpointer data);
static void ptree_sel_browse_cb(GtkWidget *w, gpointer data);
static void ptree_line_style_cb(GtkWidget *w, gpointer data);
static void ptree_expander_style_cb(GtkWidget *w, gpointer data);

static gboolean temp_gui_scrollbar_on_right;
static gboolean temp_gui_plist_sel_browse;
static gboolean temp_gui_ptree_sel_browse;
static gint temp_gui_ptree_line_style;
static gint temp_gui_ptree_expander_style;

GtkWidget*
gui_prefs_show(void)
{
	GtkWidget	*main_tb, *main_vb, *label;
	GtkWidget	*menu_item_false, *menu_item_true,
			*menu_item_0, *menu_item_1, *menu_item_2, *menu_item_3,
			*scrollbar_menu, *scrollbar_option_menu;

	temp_gui_scrollbar_on_right = prefs.gui_scrollbar_on_right;
	temp_gui_plist_sel_browse = prefs.gui_plist_sel_browse;
	temp_gui_ptree_sel_browse = prefs.gui_ptree_sel_browse;
	temp_gui_ptree_line_style = prefs.gui_ptree_line_style;
	temp_gui_ptree_expander_style = prefs.gui_ptree_expander_style;

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width( GTK_CONTAINER(main_vb), 5 );

	/* Main table */
	main_tb = gtk_table_new(5, 2, FALSE);
	gtk_box_pack_start( GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0 );
	gtk_table_set_row_spacings( GTK_TABLE(main_tb), 10 );
	gtk_table_set_col_spacings( GTK_TABLE(main_tb), 15 );


	/* Scrollbar placment */
	label = gtk_label_new("Vertical Scrollbar Placement:");
	gtk_misc_set_alignment( GTK_MISC(label), 1.0, 0.5 );
	gtk_table_attach_defaults( GTK_TABLE(main_tb), label, 0, 1, 0, 1 );

	/* Create a simple menu containing the LEFT/RIGHT choices for
	 * the scrollbar placement option */
	scrollbar_menu = gtk_menu_new();
	menu_item_false  = gtk_menu_item_new_with_label("Left");
	menu_item_true = gtk_menu_item_new_with_label("Right");
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_false );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_true );

	gtk_signal_connect( GTK_OBJECT(menu_item_false), "activate",
			scrollbar_menu_item_cb, GINT_TO_POINTER(FALSE) );
	gtk_signal_connect( GTK_OBJECT(menu_item_true), "activate",
			scrollbar_menu_item_cb, GINT_TO_POINTER(TRUE) );

	/* Create the option menu from the option */
	scrollbar_option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu( GTK_OPTION_MENU(scrollbar_option_menu),
			scrollbar_menu );
	gtk_option_menu_set_history( GTK_OPTION_MENU(scrollbar_option_menu),
			temp_gui_scrollbar_on_right);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), scrollbar_option_menu,
			1, 2, 0, 1 );


	/* Packet list selection browseable */
	label = gtk_label_new("Packet-list selection bar movement:");
	gtk_misc_set_alignment( GTK_MISC(label), 1.0, 0.5 );
	gtk_table_attach_defaults( GTK_TABLE(main_tb), label, 0, 1, 1, 2 );

	/* Create a simple menu containing the LEFT/RIGHT choices */
	scrollbar_menu = gtk_menu_new();
	menu_item_false  = gtk_menu_item_new_with_label("Selects");
	menu_item_true = gtk_menu_item_new_with_label("Browses");
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_false );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_true );

	gtk_signal_connect( GTK_OBJECT(menu_item_false), "activate",
			plist_sel_browse_cb, GINT_TO_POINTER(FALSE) );
	gtk_signal_connect( GTK_OBJECT(menu_item_true), "activate",
			plist_sel_browse_cb, GINT_TO_POINTER(TRUE) );

	/* Create the option menu from the option */
	scrollbar_option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu( GTK_OPTION_MENU(scrollbar_option_menu),
			scrollbar_menu );
	gtk_option_menu_set_history( GTK_OPTION_MENU(scrollbar_option_menu),
			temp_gui_plist_sel_browse);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), scrollbar_option_menu,
			1, 2, 1, 2 );


	/* Proto tree selection browseable */
	label = gtk_label_new("Protocol-tree selection bar movement:");
	gtk_misc_set_alignment( GTK_MISC(label), 1.0, 0.5 );
	gtk_table_attach_defaults( GTK_TABLE(main_tb), label, 0, 1, 2, 3 );

	/* Create a simple menu containing the LEFT/RIGHT choices */
	scrollbar_menu = gtk_menu_new();
	menu_item_false  = gtk_menu_item_new_with_label("Selects");
	menu_item_true = gtk_menu_item_new_with_label("Browses");
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_false );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_true );

	gtk_signal_connect( GTK_OBJECT(menu_item_false), "activate",
			ptree_sel_browse_cb, GINT_TO_POINTER(FALSE) );
	gtk_signal_connect( GTK_OBJECT(menu_item_true), "activate",
			ptree_sel_browse_cb, GINT_TO_POINTER(TRUE) );

	/* Create the option menu from the option */
	scrollbar_option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu( GTK_OPTION_MENU(scrollbar_option_menu),
			scrollbar_menu );
	gtk_option_menu_set_history( GTK_OPTION_MENU(scrollbar_option_menu),
			temp_gui_ptree_sel_browse);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), scrollbar_option_menu,
			1, 2, 2, 3 );


	/* Proto tree line style */
	label = gtk_label_new("Protocol-tree line style:");
	gtk_misc_set_alignment( GTK_MISC(label), 1.0, 0.5 );
	gtk_table_attach_defaults( GTK_TABLE(main_tb), label, 0, 1, 3, 4 );

	/* Create a menu */
	scrollbar_menu = gtk_menu_new();
	menu_item_0 = gtk_menu_item_new_with_label("None");
	menu_item_1 = gtk_menu_item_new_with_label("Solid");
	menu_item_2 = gtk_menu_item_new_with_label("Dotted");
	menu_item_3 = gtk_menu_item_new_with_label("Tabbed");
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_0 );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_1 );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_2 );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_3 );

	gtk_signal_connect( GTK_OBJECT(menu_item_0), "activate",
			ptree_line_style_cb, GINT_TO_POINTER(0) );
	gtk_signal_connect( GTK_OBJECT(menu_item_1), "activate",
			ptree_line_style_cb, GINT_TO_POINTER(1) );
	gtk_signal_connect( GTK_OBJECT(menu_item_2), "activate",
			ptree_line_style_cb, GINT_TO_POINTER(2) );
	gtk_signal_connect( GTK_OBJECT(menu_item_3), "activate",
			ptree_line_style_cb, GINT_TO_POINTER(3) );

	/* Create the option menu from the option */
	scrollbar_option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu( GTK_OPTION_MENU(scrollbar_option_menu),
			scrollbar_menu );
	gtk_option_menu_set_history( GTK_OPTION_MENU(scrollbar_option_menu),
			temp_gui_ptree_line_style);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), scrollbar_option_menu,
			1, 2, 3, 4 );


	/* Proto tree expander style */
	label = gtk_label_new("Protocol-tree expander style:");
	gtk_misc_set_alignment( GTK_MISC(label), 1.0, 0.5 );
	gtk_table_attach_defaults( GTK_TABLE(main_tb), label, 0, 1, 4, 5 );

	/* Create a menu */
	scrollbar_menu = gtk_menu_new();
	menu_item_0 = gtk_menu_item_new_with_label("None");
	menu_item_1 = gtk_menu_item_new_with_label("Square");
	menu_item_2 = gtk_menu_item_new_with_label("Triangle");
	menu_item_3 = gtk_menu_item_new_with_label("Circular");
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_0 );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_1 );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_2 );
	gtk_menu_append( GTK_MENU(scrollbar_menu), menu_item_3 );

	gtk_signal_connect( GTK_OBJECT(menu_item_0), "activate",
			ptree_expander_style_cb, GINT_TO_POINTER(0) );
	gtk_signal_connect( GTK_OBJECT(menu_item_1), "activate",
			ptree_expander_style_cb, GINT_TO_POINTER(1) );
	gtk_signal_connect( GTK_OBJECT(menu_item_2), "activate",
			ptree_expander_style_cb, GINT_TO_POINTER(2) );
	gtk_signal_connect( GTK_OBJECT(menu_item_3), "activate",
			ptree_expander_style_cb, GINT_TO_POINTER(3) );

	/* Create the option menu from the option */
	scrollbar_option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu( GTK_OPTION_MENU(scrollbar_option_menu),
			scrollbar_menu );
	gtk_option_menu_set_history( GTK_OPTION_MENU(scrollbar_option_menu),
			temp_gui_ptree_expander_style);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), scrollbar_option_menu,
			1, 2, 4, 5 );

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}


static void
scrollbar_menu_item_cb(GtkWidget *w, gpointer data)
{
	gboolean	value = GPOINTER_TO_INT(data);

	temp_gui_scrollbar_on_right = value;
	set_scrollbar_placement_all(value);
}

static void
plist_sel_browse_cb(GtkWidget *w, gpointer data)
{
	gboolean	value = GPOINTER_TO_INT(data);

	temp_gui_plist_sel_browse = value;
	set_plist_sel_browse(value);
}

static void
ptree_sel_browse_cb(GtkWidget *w, gpointer data)
{
	gboolean	value = GPOINTER_TO_INT(data);

	temp_gui_ptree_sel_browse = value;
	set_ptree_sel_browse_all(value);
}

static void
ptree_line_style_cb(GtkWidget *w, gpointer data)
{
	gint	value = GPOINTER_TO_INT(data);

	temp_gui_ptree_line_style = value;
	set_ptree_line_style_all(value);
}

static void
ptree_expander_style_cb(GtkWidget *w, gpointer data)
{
	gint	value = GPOINTER_TO_INT(data);

	temp_gui_ptree_expander_style = value;
	set_ptree_expander_style_all(value);
}


void
gui_prefs_ok(GtkWidget *w)
{
	prefs.gui_scrollbar_on_right = temp_gui_scrollbar_on_right;
	prefs.gui_plist_sel_browse = temp_gui_plist_sel_browse;
	prefs.gui_ptree_sel_browse = temp_gui_ptree_sel_browse;
	prefs.gui_ptree_line_style = temp_gui_ptree_line_style;
	prefs.gui_ptree_expander_style = temp_gui_ptree_expander_style;

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
	/* Reset GUI preference values back to what the
	 * current preferences says they should be */
	temp_gui_scrollbar_on_right = prefs.gui_scrollbar_on_right;
	temp_gui_plist_sel_browse = prefs.gui_plist_sel_browse;
	temp_gui_ptree_sel_browse = prefs.gui_ptree_sel_browse;
	temp_gui_ptree_line_style = prefs.gui_ptree_line_style;
	temp_gui_ptree_expander_style = prefs.gui_ptree_expander_style;

	set_scrollbar_placement_all(prefs.gui_scrollbar_on_right);
	set_plist_sel_browse(prefs.gui_plist_sel_browse);
	set_ptree_sel_browse_all(prefs.gui_ptree_sel_browse);
	set_ptree_line_style_all(prefs.gui_ptree_line_style);
	set_ptree_expander_style_all(prefs.gui_ptree_expander_style);

	gui_prefs_delete(w);
}

void
gui_prefs_delete(GtkWidget *w)
{
}
