/* gui_prefs.c
 * Dialog box for GUI preferences
 *
 * $Id: gui_prefs.c,v 1.9 2000/08/21 22:35:59 guy Exp $
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
#include "prefs.h"
#include "prefs-int.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "proto_draw.h"

static void create_option_menu(GtkWidget *main_vb, const gchar *key,
    GtkWidget *main_tb, int table_position,
    const gchar *label_text, const enum_val *enumvals, gint current_val);
static void font_browse_cb(GtkWidget *w, gpointer data);
static void font_browse_ok_cb(GtkWidget *w, GtkFontSelectionDialog *fs);
static void font_browse_destroy(GtkWidget *win, gpointer data);
static gint fetch_enum_value(gpointer control, const enum_val *enumvals);

#define SCROLLBAR_PLACEMENT_KEY		"scrollbar_placement"
#define PLIST_SEL_BROWSE_KEY		"plist_sel_browse"
#define PTREE_SEL_BROWSE_KEY		"ptree_sel_browse"
#define PTREE_LINE_STYLE_KEY		"ptree_line_style"
#define PTREE_EXPANDER_STYLE_KEY	"ptree_expander_style"

#define FONT_DIALOG_PTR_KEY	"font_dialog_ptr"
#define FONT_CALLER_PTR_KEY	"font_caller_ptr"

static const enum_val scrollbar_placement_vals[] = {
	{ "Left",  FALSE },
	{ "Right", TRUE },
	{ NULL,    0 }
};

static const enum_val selection_mode_vals[] = {
	{ "Selects", FALSE },
	{ "Browses", TRUE },
	{ NULL,      0 }
};

static const enum_val line_style_vals[] = {
	{ "None",   0 },
	{ "Solid",  1 },
	{ "Dotted", 2 },
	{ "Tabbed", 3 },
	{ NULL,     0 }
};

static const enum_val expander_style_vals[] = {
	{ "None",     0 },
	{ "Square",   1 },
	{ "Triangle", 2 },
	{ "Circular", 3 },
	{ NULL,       0 }
};

GtkWidget*
gui_prefs_show(void)
{
	GtkWidget	*main_tb, *main_vb, *font_bt;

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width( GTK_CONTAINER(main_vb), 5 );

	/* Main table */
	main_tb = gtk_table_new(6, 2, FALSE);
	gtk_box_pack_start( GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0 );
	gtk_table_set_row_spacings( GTK_TABLE(main_tb), 10 );
	gtk_table_set_col_spacings( GTK_TABLE(main_tb), 15 );

	/* Scrollbar placement */
	create_option_menu(main_vb, SCROLLBAR_PLACEMENT_KEY, main_tb, 0,
	    "Vertical Scrollbar Placement:", scrollbar_placement_vals,
	    prefs.gui_scrollbar_on_right);

	/* Packet list selection browseable */
	create_option_menu(main_vb, PLIST_SEL_BROWSE_KEY, main_tb, 1,
	    "Packet-list selection bar movement:", selection_mode_vals,
	    prefs.gui_plist_sel_browse);

	/* Proto tree selection browseable */
	create_option_menu(main_vb, PTREE_SEL_BROWSE_KEY, main_tb, 2,
	    "Protocol-tree selection bar movement:", selection_mode_vals,
	    prefs.gui_ptree_sel_browse);

	/* Proto tree line style */
	create_option_menu(main_vb, PTREE_LINE_STYLE_KEY, main_tb, 3,
	    "Protocol-tree line style:", line_style_vals,
	    prefs.gui_ptree_line_style);

	/* Proto tree expander style */
	create_option_menu(main_vb, PTREE_EXPANDER_STYLE_KEY, main_tb, 4,
	    "Protocol-tree expander style:", expander_style_vals,
	    prefs.gui_ptree_expander_style);

	/* "Font..." button - click to open a font selection dialog box. */
	font_bt = gtk_button_new_with_label("Font...");
	gtk_signal_connect(GTK_OBJECT(font_bt), "clicked",
	    GTK_SIGNAL_FUNC(font_browse_cb), NULL);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), font_bt, 1, 2, 5, 6 );

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}

static void
create_option_menu(GtkWidget *main_vb, const gchar *key,
    GtkWidget *main_tb, int table_position,
    const gchar *label_text, const enum_val *enumvals, gint current_val)
{
	GtkWidget *label, *menu, *menu_item, *option_menu;
	int menu_index, index;
	const enum_val *enum_valp;

	label = gtk_label_new(label_text);
	gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1,
	    table_position, table_position + 1);

	menu = gtk_menu_new();
	menu_index = -1;
	for (enum_valp = enumvals, index = 0;
	    enum_valp->name != NULL; enum_valp++, index++) {
		menu_item = gtk_menu_item_new_with_label(enum_valp->name);
		gtk_menu_append(GTK_MENU(menu), menu_item);
		if (enum_valp->value == current_val)
			menu_index = index;
	}

	/* Create the option menu from the option */
	option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);

	/* Set its current value to the variable's current value */
	if (menu_index != -1)
		gtk_option_menu_set_history(GTK_OPTION_MENU(option_menu),
		    menu_index);

	gtk_table_attach_defaults(GTK_TABLE(main_tb), option_menu,
	    1, 2, table_position, table_position + 1);

	gtk_object_set_data(GTK_OBJECT(main_vb), key, option_menu);
}

/* Create a font dialog for browsing. */
static void
font_browse_cb(GtkWidget *w, gpointer data)
{
	GtkWidget *caller = gtk_widget_get_toplevel(w);
	GtkWidget *font_browse_w;
	static gchar *fixedwidths[] = { "c", "m", NULL };

	/* Has a font dialog box already been opened for that top-level
	   widget? */
	font_browse_w = gtk_object_get_data(GTK_OBJECT(caller),
	    FONT_DIALOG_PTR_KEY);

	if (font_browse_w != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(font_browse_w);
		return;
	}

	/* Now create a new dialog. */
	font_browse_w = gtk_font_selection_dialog_new("Ethereal: Select Font");
	gtk_window_set_transient_for(GTK_WINDOW(font_browse_w),
	    GTK_WINDOW(top_level));

	/* Call a handler when we're destroyed, so we can inform
	   our caller, if any, that we've been destroyed. */
	gtk_signal_connect(GTK_OBJECT(font_browse_w), "destroy",
	    GTK_SIGNAL_FUNC(font_browse_destroy), NULL);

	/* Set its filter to show only fixed_width fonts. */
	gtk_font_selection_dialog_set_filter(
	    GTK_FONT_SELECTION_DIALOG(font_browse_w),
	    GTK_FONT_FILTER_BASE,	/* user can't change the filter */
	    GTK_FONT_ALL,		/* bitmap or scalable are fine */
	    NULL,			/* all foundries are OK */
	    NULL,			/* all weights are OK (XXX - normal only?) */
	    NULL,			/* all slants are OK (XXX - Roman only?) */
	    NULL,			/* all setwidths are OK */
	    fixedwidths,		/* ONLY fixed-width fonts */
	    NULL);			/* all charsets are OK (XXX - ISO 8859/1 only?) */

	/* Set the font to the current font.
	   XXX - this doesn't seem to work right. */
	gtk_font_selection_dialog_set_font_name(
	    GTK_FONT_SELECTION_DIALOG(font_browse_w), prefs.gui_font_name);

	/* Set the FONT_CALLER_PTR_KEY for the new dialog to point to
	   our caller. */
	gtk_object_set_data(GTK_OBJECT(font_browse_w), FONT_CALLER_PTR_KEY,
	    caller);

	/* Set the FONT_DIALOG_PTR_KEY for the caller to point to us */
	gtk_object_set_data(GTK_OBJECT(caller), FONT_DIALOG_PTR_KEY,
	    font_browse_w);
  
	/* Connect the ok_button to font_browse_ok_cb function and pass along a
	   pointer to the font selection box widget */
	gtk_signal_connect(
	    GTK_OBJECT(GTK_FONT_SELECTION_DIALOG(font_browse_w)->ok_button),
	    "clicked", (GtkSignalFunc)font_browse_ok_cb, font_browse_w);

	/* Connect the cancel_button to destroy the widget */
	gtk_signal_connect_object(
	    GTK_OBJECT(GTK_FONT_SELECTION_DIALOG(font_browse_w)->cancel_button),
	    "clicked", (GtkSignalFunc)gtk_widget_destroy,
	    GTK_OBJECT(font_browse_w));

	/* Catch the "key_press_event" signal in the window, so that we can
	   catch the ESC key being pressed and act as if the "Cancel" button
	   had been selected. */
	dlg_set_cancel(font_browse_w,
	    GTK_FONT_SELECTION_DIALOG(font_browse_w)->cancel_button);

	gtk_widget_show(font_browse_w);
}

static void
font_browse_ok_cb(GtkWidget *w, GtkFontSelectionDialog *fs)
{
	if (prefs.gui_font_name != NULL)
		g_free(prefs.gui_font_name);
	prefs.gui_font_name =
	    g_strdup(gtk_font_selection_dialog_get_font_name(
	      GTK_FONT_SELECTION_DIALOG(fs)));

	gtk_widget_hide(GTK_WIDGET(fs));
	gtk_widget_destroy(GTK_WIDGET(fs));
}

static void
font_browse_destroy(GtkWidget *win, gpointer data)
{
	GtkWidget *caller;

	/* Get the widget that requested that we be popped up, if any.
	   (It should arrange to destroy us if it's destroyed, so
	   that we don't get a pointer to a non-existent window here.) */
	caller = gtk_object_get_data(GTK_OBJECT(win), FONT_CALLER_PTR_KEY);

	if (caller != NULL) {
		/* Tell it we no longer exist. */
		gtk_object_set_data(GTK_OBJECT(caller), FONT_DIALOG_PTR_KEY,
		    NULL);
	}

	/* Now nuke this window. */
	gtk_grab_remove(GTK_WIDGET(win));
	gtk_widget_destroy(GTK_WIDGET(win));
}

static gint
fetch_enum_value(gpointer control, const enum_val *enumvals)
{
	GtkWidget *label;
	char *label_string;

	/* Get the label for the currently active entry in the option menu.
	   Yes, this is how you do it.  See FAQ 6.8 in the GTK+ FAQ. */
	label = GTK_BIN(control)->child;

	/* Get the label string, and translate it to a value. */
	gtk_label_get(GTK_LABEL(label), &label_string);
	return find_val_for_string(label_string, enumvals, 1);
}

void
gui_prefs_fetch(GtkWidget *w)
{
	/* XXX - currently, "prefs.gui_font_name" doesn't directly
	   affect the behavior of existing or newly-created windows,
	   so we can get away with setting it when the user presses
	   "OK" on the font selection dialog - it doesn't affect
	   anything until the "apply" function is called. */

	prefs.gui_scrollbar_on_right = fetch_enum_value(
	    gtk_object_get_data(GTK_OBJECT(w), SCROLLBAR_PLACEMENT_KEY),
	    scrollbar_placement_vals);
	prefs.gui_plist_sel_browse = fetch_enum_value(
	    gtk_object_get_data(GTK_OBJECT(w), PLIST_SEL_BROWSE_KEY),
	    selection_mode_vals);
	prefs.gui_ptree_sel_browse = fetch_enum_value(
	    gtk_object_get_data(GTK_OBJECT(w), PTREE_SEL_BROWSE_KEY),
	    selection_mode_vals);
	prefs.gui_ptree_line_style = fetch_enum_value(
	    gtk_object_get_data(GTK_OBJECT(w), PTREE_LINE_STYLE_KEY),
	    line_style_vals);
	prefs.gui_ptree_expander_style = fetch_enum_value(
	    gtk_object_get_data(GTK_OBJECT(w), PTREE_EXPANDER_STYLE_KEY),
	    expander_style_vals);
}

void
gui_prefs_apply(GtkWidget *w)
{
	GdkFont *font;

	font = gdk_font_load(prefs.gui_font_name);
	if (font == NULL) {
		/* XXX - make this a dialog box, and don't let them
		   continue! */
		fprintf(stderr, "Can't open font %s\n", prefs.gui_font_name);
	}

	set_scrollbar_placement_all(prefs.gui_scrollbar_on_right);
	set_plist_sel_browse(prefs.gui_plist_sel_browse);
	set_ptree_sel_browse_all(prefs.gui_ptree_sel_browse);
	set_ptree_line_style_all(prefs.gui_ptree_line_style);
	set_ptree_expander_style_all(prefs.gui_ptree_expander_style);
	if (font != NULL) {
		set_plist_font(font);
		set_ptree_font_all(font);
#if 0
		gdk_font_unref(m_r_font);
		m_r_font = font;
		/* Do the windows that directly use m_r_font here. */
#endif
	}
}

void
gui_prefs_destroy(GtkWidget *w)
{
	GtkWidget *caller = gtk_widget_get_toplevel(w);
	GtkWidget *fs;

	/* Is there a font selection dialog associated with this
	   Preferences dialog? */
	fs = gtk_object_get_data(GTK_OBJECT(caller), FONT_DIALOG_PTR_KEY);

	if (fs != NULL) {
		/* Yes.  Destroy it. */
		gtk_widget_destroy(fs);
	}
}
