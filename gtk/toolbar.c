/* toolbar.c
 * The main toolbar
 * Copyright 2003, Ulf Lamping <ulf.lamping@web.de>
 *
 * $Id: toolbar.c,v 1.3 2003/10/15 22:37:19 guy Exp $
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

/*
 * This file implements a "main" toolbar for Ethereal (suitable for gtk1 and
 * gtk2).
 *
 * As it is desirable to have the same toolbar implementation for gtk1 and gtk2 
 * in Ethereal, only those library calls available in the gtk1 libraries 
 * are used inside this file.
 *
 * Hint: gtk2 in comparison to gtk1 has a better way to handle with "common"
 * icons; gtk2 calls this kind of icons "stock-icons"
 * (stock-icons including: icons for "open", "save", "print", ...)
 * Perhaps we should use the stock icons mechanism when using gtk2.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#include "capture_dlg.h"
#include "file_dlg.h"
#include "find_dlg.h"
#include "goto_dlg.h"
#include "color.h"
#include "color_dlg.h"
#include "filter_prefs.h"
#include "prefs.h"
#include "prefs_dlg.h"
#include "main.h"
#include "help_dlg.h"
#include "gtkglobals.h"
#include "toolbar.h"


/* All of the icons used here are coming (or are derived) from GTK2 stock icons.
 * They were converted using "The Gimp" with standard conversion from png to xpm.
 * All stock icons can be (currently) found at: 
 * "ftp://ftp.gtk.org/pub/gtk/v2.0/gtk+-2.0.6.tar.bz2"
 * in the directory "gtk+-2.0.6\gtk\stock-icons" */
#include "../image/toolbar/stock_stop_24.xpm"
#include "../image/toolbar/stock_open_24.xpm"
#include "../image/toolbar/stock_save_24.xpm"
#include "../image/toolbar/stock_close_24.xpm"
#include "../image/toolbar/stock_refresh_24.xpm"
#include "../image/toolbar/stock_print_24.xpm"
#include "../image/toolbar/stock_search_24.xpm"
#include "../image/toolbar/stock_right_arrow_24.xpm"
#include "../image/toolbar/stock_jump_to_24.xpm"
#include "../image/toolbar/stock_colorselector_24.xpm"
#include "../image/toolbar/stock_preferences_24.xpm"
#include "../image/toolbar/stock_help_24.xpm"
/* this icons are derived from the original stock icons */
#include "../image/toolbar/capture_24.xpm"
#include "../image/toolbar/cfilter_24.xpm"
#include "../image/toolbar/dfilter_24.xpm"


#define E_TB_MAIN_KEY             "toolbar_main"
#define E_TB_MAIN_HB_KEY          "toolbar_main_handlebox"


gboolean toolbar_init = FALSE;

GtkWidget *new_button, *stop_button;
GtkWidget *open_button, *save_button, *close_button, *reload_button;
GtkWidget *print_button, *find_button, *find_next_button, *go_to_button;
GtkWidget *capture_filter_button, *display_filter_button;
GtkWidget *color_display_button, *prefs_button, *help_button;

void toolbar_redraw_all(void);
void get_main_toolbar(GtkWidget *window, GtkWidget **toolbar);


/*
 * Create all toolbars (currently only the main toolbar)
 */
void
create_toolbar(GtkWidget    *main_vbox)
{
    GtkWidget   *main_tb, *main_tb_hb;


    /* Main Toolbar */
    get_main_toolbar(top_level, &main_tb);
#if GTK_MAJOR_VERSION < 2
    gtk_toolbar_set_space_size(GTK_TOOLBAR(main_tb), 3);
#endif

    /* To make it nice we'll put the toolbar into a handle box, 
     * so that it can be detached from the main window */
    /* XXX - this is coming from gtk examples (is this really helpful for someone?) */
    main_tb_hb = gtk_handle_box_new();
    gtk_container_add(GTK_CONTAINER(main_tb_hb) , main_tb);
    gtk_container_set_border_width(GTK_CONTAINER(main_tb_hb), 3);
    gtk_box_pack_start(GTK_BOX(main_vbox), main_tb_hb, FALSE, TRUE, 0);
    gtk_widget_show(main_tb_hb);

    gtk_object_set_data(GTK_OBJECT(top_level), E_TB_MAIN_KEY, main_tb);
    gtk_object_set_data(GTK_OBJECT(top_level), E_TB_MAIN_HB_KEY, main_tb_hb);
    /* make current preferences effective */
    toolbar_redraw_all();
}


/*
 * Redraw all toolbars (currently only the main toolbar)
 */
void
toolbar_redraw_all(void)
{
  GtkWidget     *main_tb, *main_tb_hb;
  gboolean      gui_toolbar_main_show;
  gint          gui_toolbar_main_style;


  /* Possible toolbar styles (from GTK): 
  typedef enum
  {
    GTK_TOOLBAR_ICONS,
    GTK_TOOLBAR_TEXT,
    GTK_TOOLBAR_BOTH,
    GTK_TOOLBAR_BOTH_HORIZ
  } GtkToolbarStyle;
  */

  /* default: show toolbar */
  /* XXX: get this info from a preference setting */
  gui_toolbar_main_show = TRUE;
  /* gui_toolbar_main_style = prefs.gui_toolbar_main_show; */

  /* default style: icons only */
  gui_toolbar_main_style = GTK_TOOLBAR_ICONS;
  /* XXX: get this style from a preference setting */
  /* gui_toolbar_main_style = prefs.gui_toolbar_main_style; */

  main_tb_hb = gtk_object_get_data(GTK_OBJECT(top_level), E_TB_MAIN_HB_KEY);

  /* does the user want the toolbar? */
  if (gui_toolbar_main_show) {
	/* yes, set the style he/she prefers (texts, icons, both) */
    main_tb = gtk_object_get_data(GTK_OBJECT(top_level), E_TB_MAIN_KEY);
    gtk_toolbar_set_style(GTK_TOOLBAR(main_tb), gui_toolbar_main_style);
    gtk_widget_show(main_tb_hb);
  } else {
	/* no */
    gtk_widget_hide(main_tb_hb);
  }

  /* resize ALL elements in the top_level container */
#if GTK_MAJOR_VERSION >= 2
  gtk_container_resize_children(GTK_CONTAINER(top_level));
#else
  gtk_container_queue_resize(GTK_CONTAINER(top_level));
#endif
}


/* set toolbar state "have a capture file" */
void set_toolbar_for_capture_file(gboolean have_capture_file) {
	if (toolbar_init) {
		gtk_widget_set_sensitive(save_button, have_capture_file);
		gtk_widget_set_sensitive(close_button, have_capture_file);
		gtk_widget_set_sensitive(reload_button, have_capture_file);
	}
}


/* set toolbar state "have a capture in progress" */
void set_toolbar_for_capture_in_progress(gboolean capture_in_progress) {

	if (toolbar_init) {
		gtk_widget_set_sensitive(new_button, !capture_in_progress);
		gtk_widget_set_sensitive(open_button, !capture_in_progress);
		/*
		 * XXX - this doesn't yet work in Win32, as in the menus :-(
		 */
#ifndef _WIN32
		if (capture_in_progress) {
			gtk_widget_hide(new_button);
			gtk_widget_show(stop_button);
		} else {
			gtk_widget_show(new_button);
			gtk_widget_hide(stop_button);
		}
#else
		gtk_widget_set_sensitive(new_button, !capture_in_progress);
#endif
	}
}


/* set toolbar state "have packets captured" */
void set_toolbar_for_captured_packets(gboolean have_captured_packets) {

	if (toolbar_init) {
		gtk_widget_set_sensitive(print_button, have_captured_packets);
		gtk_widget_set_sensitive(find_button, have_captured_packets);
		gtk_widget_set_sensitive(find_next_button, have_captured_packets);
		gtk_widget_set_sensitive(go_to_button, have_captured_packets);
/* XXX - I don't see a reason why this should be done (as it is in the menus) */
/*		gtk_widget_set_sensitive(color_display_button, have_captured_packets);*/
	}
}


/* helper function: add a separator to the toolbar */
void toolbar_append_separator(GtkWidget *toolbar) {
	/* XXX - the usage of a gtk_separator doesn't seem to work for a toolbar.
	 * (at least in the win32 port of gtk 1.3)
	 * So simply add a few spaces */
	gtk_toolbar_append_space(GTK_TOOLBAR(toolbar)); /* space after item */
	gtk_toolbar_append_space(GTK_TOOLBAR(toolbar)); /* space after item */
	gtk_toolbar_append_space(GTK_TOOLBAR(toolbar)); /* space after item */
}


/* get the main toolbar (remember: call this only once!) */
void get_main_toolbar(GtkWidget *window, GtkWidget **toolbar) {
	GdkPixmap *icon;
	GtkWidget *iconw;
	GdkBitmap * mask;


	/* Display filter construct dialog has only a "Save" and a "Close" button.
	 * XXX - Adding the "Ok" and "Apply" buttons would need some more work here */	
	static construct_args_t args = {
		"Ethereal: Edit Display Filter",
		FALSE,
		FALSE
	};


	/* this function should be only called once! */
	g_assert(!toolbar_init);

	/* we need to realize the window because we use pixmaps for 
	 * items on the toolbar in the context of it */
	/* (coming from the gtk example, please don't ask me why ;-) */
	gtk_widget_realize(window);

	/* toolbar will be horizontal, with both icons and text (as default here) */
	/* (this will usually be overwritten by the preferences setting) */
	*toolbar = gtk_toolbar_new ( GTK_ORIENTATION_HORIZONTAL, GTK_TOOLBAR_BOTH);
	
	/* start capture button */
	icon = gdk_pixmap_create_from_xpm_d(
			window->window, &mask, &window->style->white, capture_24_xpm);
	iconw = gtk_pixmap_new ( icon, mask ); /* icon widget */
	
	new_button = 
	gtk_toolbar_append_item ( GTK_TOOLBAR (*toolbar), /* our toolbar */
	                          "New",                 /* button label */
	                          "Start new capture...",/* this button's tooltip */
	                          "Private",             /* tooltip private info */
	                          iconw,                 /* icon widget */
	                          GTK_SIGNAL_FUNC (capture_prep_cb), /* a signal */
	                           NULL );
	/* either start OR stop button can be valid at a time, so no space needed here */
	/*gtk_toolbar_append_space(GTK_TOOLBAR(*toolbar));*/
	
	/* stop capture button (hidden by default) */
	icon = gdk_pixmap_create_from_xpm_d(
			window->window, &mask, &window->style->white, stock_stop_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	stop_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Stop", "Stop running capture", "Private",
								iconw, GTK_SIGNAL_FUNC(capture_stop_cb), NULL);
	gtk_widget_hide(stop_button);
	toolbar_append_separator(*toolbar);
	
	/* open capture button */
	icon = gdk_pixmap_create_from_xpm_d(
			window->window, &mask, &window->style->white, stock_open_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	open_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Open", "Open capture file...", "Private",
								iconw, GTK_SIGNAL_FUNC(file_open_cmd_cb), NULL);
	gtk_toolbar_append_space(GTK_TOOLBAR(*toolbar));
	
	/* save capture button */
	icon = gdk_pixmap_create_from_xpm_d(
			window->window, &mask, &window->style->white, stock_save_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	save_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Save", "Save capture file", "Private",
								iconw, GTK_SIGNAL_FUNC (file_save_cmd_cb), NULL);
	gtk_toolbar_append_space(GTK_TOOLBAR(*toolbar));
	
	/* close capture button */
	icon = gdk_pixmap_create_from_xpm_d (
				window->window, &mask, &window->style->white, stock_close_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	close_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Close", "Close capture file", "Private",
								iconw, GTK_SIGNAL_FUNC(file_close_cmd_cb), NULL);
	gtk_toolbar_append_space(GTK_TOOLBAR(*toolbar));
	
	/* reload capture file button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_refresh_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	reload_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Reload", "Reload capture file", "Private",
								iconw, GTK_SIGNAL_FUNC (file_reload_cmd_cb), NULL);
	toolbar_append_separator(*toolbar);
	
	/* print frame(s) button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_print_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	print_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Print", "Print frame(s)", "Private",
								iconw, GTK_SIGNAL_FUNC (file_print_cmd_cb), NULL);
	gtk_toolbar_append_space (GTK_TOOLBAR(*toolbar));
	
	/* find frame button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_search_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	find_button = gtk_toolbar_append_item (GTK_TOOLBAR (*toolbar),
								"Find", "Find frame...", "Private",
								iconw, GTK_SIGNAL_FUNC (find_frame_cb), NULL);
	gtk_toolbar_append_space (GTK_TOOLBAR(*toolbar));
	
	/* find next frame button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_right_arrow_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	find_next_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Next", "Find next frame", "Private",
								iconw, GTK_SIGNAL_FUNC (find_next_cb), NULL);
	gtk_toolbar_append_space (GTK_TOOLBAR(*toolbar));
	
	/* go to frame button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_jump_to_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	go_to_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"GoTo", "Go to frame number...", "Private",
								iconw, GTK_SIGNAL_FUNC (goto_frame_cb), NULL);
	toolbar_append_separator(*toolbar);
	
	/* capture filter button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, cfilter_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	capture_filter_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"CFilter", "Edit Capture Filters...", "Private",
								iconw, GTK_SIGNAL_FUNC (cfilter_dialog_cb), NULL);
	gtk_toolbar_append_space (GTK_TOOLBAR(*toolbar));

	/* display filter button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, dfilter_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	display_filter_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"DFilter", "Edit Display Filters...", "Private",
								iconw, GTK_SIGNAL_FUNC (display_filter_construct_cb), &args);
	gtk_toolbar_append_space (GTK_TOOLBAR(*toolbar));

	/* color filter button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_colorselector_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	color_display_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Color", "Apply Color Filters...", "Private",
								iconw, GTK_SIGNAL_FUNC (color_display_cb), NULL);
	gtk_toolbar_append_space (GTK_TOOLBAR(*toolbar));

	/* preferences button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_preferences_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	prefs_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Prefs", "Edit Preferences...", "Private",
								iconw, GTK_SIGNAL_FUNC (prefs_cb), NULL);
	toolbar_append_separator(*toolbar);

	/* help button */
	icon = gdk_pixmap_create_from_xpm_d(
				window->window, &mask, &window->style->white, stock_help_24_xpm);
	iconw = gtk_pixmap_new(icon, mask);

	help_button = gtk_toolbar_append_item(GTK_TOOLBAR(*toolbar),
								"Help", "Show Help Dialog...", "Private",
								iconw, GTK_SIGNAL_FUNC (help_cb), NULL);

	/* disable all "sensitive" items by default */
	toolbar_init = TRUE;
	set_toolbar_for_captured_packets(FALSE);
	set_toolbar_for_capture_file(FALSE);
	set_toolbar_for_capture_in_progress(FALSE);

	/* everything is well done here :-) */
	gtk_widget_show (*toolbar);
}
