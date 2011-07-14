/* toolbar.c
 * The main toolbar
 * Copyright 2003, Ulf Lamping <ulf.lamping@web.de>
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

/*
 * This file implements the "main" toolbar for Wireshark.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>

#include "../color.h"
#include "../color_filters.h"

#ifdef HAVE_LIBPCAP
#include "gtk/capture_dlg.h"
#include "gtk/capture_if_dlg.h"
#endif /* HAVE_LIBPCAP */
#include "gtk/filter_dlg.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/find_dlg.h"
#include "gtk/goto_dlg.h"
#include "gtk/color_dlg.h"
#include "gtk/prefs_dlg.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/main_toolbar.h"
#include "gtk/help_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/stock_icons.h"
#include "gtk/keys.h"
#include "gtk/recent.h"
#include "gtk/packet_history.h"
#include "gtk/new_packet_list.h"

static gboolean toolbar_init = FALSE;

#ifdef HAVE_LIBPCAP
static GtkToolItem *capture_options_button, *new_button, *stop_button, *clear_button, *if_button;
static GtkToolItem *capture_filter_button, *autoscroll_button;
#endif /* HAVE_LIBPCAP */
static GtkToolItem *open_button, *save_button, *close_button, *reload_button;
static GtkToolItem *print_button, *find_button, *history_forward_button, *history_back_button;
static GtkToolItem *go_to_button, *go_to_top_button, *go_to_bottom_button;
static GtkToolItem *display_filter_button;
static GtkToolItem *zoom_in_button, *zoom_out_button, *zoom_100_button, *colorize_button;
static GtkToolItem *resize_columns_button;
static GtkToolItem *color_display_button, *prefs_button, *help_button;

#define SAVE_BUTTON_TOOLTIP_TEXT "Save this capture file..."
#define SAVE_AS_BUTTON_TOOLTIP_TEXT "Save this capture file as..."


/*
 * Redraw all toolbars 
 */
void
toolbar_redraw_all(void)
{
    GtkWidget     *main_tb;
    GtkWidget     *filter_tb;

    main_tb = g_object_get_data(G_OBJECT(top_level), E_TB_MAIN_KEY);

    gtk_toolbar_set_style(GTK_TOOLBAR(main_tb),
                          prefs.gui_toolbar_main_style);

	filter_tb = g_object_get_data(G_OBJECT(top_level), E_TB_FILTER_KEY);

	/* In case the filter toolbar hasn't been built */
	if(filter_tb)
		gtk_toolbar_set_style(GTK_TOOLBAR(filter_tb),
                          prefs.gui_toolbar_filter_style);
}

/* Enable or disable toolbar items based on whether you have a capture file
   you've finished reading. */
void set_toolbar_for_capture_file(gboolean have_capture_file) {
    if (toolbar_init) {
	gtk_widget_set_sensitive(GTK_WIDGET(save_button), have_capture_file);
        gtk_widget_set_sensitive(GTK_WIDGET(close_button), have_capture_file);
        gtk_widget_set_sensitive(GTK_WIDGET(reload_button), have_capture_file);
    }
}

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void set_toolbar_for_unsaved_capture_file(gboolean have_unsaved_capture_file) {

    if (toolbar_init) {
        if(have_unsaved_capture_file) {
	gtk_tool_button_set_stock_id(GTK_TOOL_BUTTON(save_button),
	    GTK_STOCK_SAVE);
        gtk_widget_set_tooltip_text(GTK_WIDGET(save_button),SAVE_BUTTON_TOOLTIP_TEXT);
        g_object_set_data(G_OBJECT(save_button), "save", GINT_TO_POINTER(1));
        } else {
	gtk_tool_button_set_stock_id(GTK_TOOL_BUTTON(save_button),
	    GTK_STOCK_SAVE_AS);
        gtk_widget_set_tooltip_text(GTK_WIDGET(save_button), SAVE_AS_BUTTON_TOOLTIP_TEXT);
        g_object_set_data(G_OBJECT(save_button), "save", GINT_TO_POINTER(0));
        }
        /*gtk_widget_set_sensitive((GTK_WIDGET(save_button), have_unsaved_capture_file);
        gtk_widget_set_sensitive(GTK_WIDGET(save_as_button), !have_unsaved_capture_file);*/
    }
}

/* fudge to call correct file_save or file_save_as fcn based upon the
   value of the "save" key associated with the save button
*/

static void file_save_or_save_as_cmd_cb(GtkWidget *w, gpointer data) {
    if (GPOINTER_TO_INT(g_object_get_data(G_OBJECT(save_button),"save")) == 1) {
        file_save_cmd_cb(w, data);
    }
    else {
        file_save_as_cmd_cb(w, data);
    }
}

/** The packet history has changed, we need to update the menu.
 *
 * @param back_history some back history entries available
 * @param forward_history some forward history entries available
 */
void set_toolbar_for_packet_history(gboolean back_history, gboolean forward_history) {
    gtk_widget_set_sensitive(GTK_WIDGET(history_back_button), back_history);
    gtk_widget_set_sensitive(GTK_WIDGET(history_forward_button), forward_history);
}


/* set toolbar state "have a capture in progress" */
void set_toolbar_for_capture_in_progress(gboolean capture_in_progress) {

    if (toolbar_init) {
#ifdef HAVE_LIBPCAP
	gtk_widget_set_sensitive(GTK_WIDGET(capture_options_button), !capture_in_progress);
        gtk_widget_set_sensitive(GTK_WIDGET(new_button), !capture_in_progress);
        gtk_widget_set_sensitive(GTK_WIDGET(stop_button), capture_in_progress);
	gtk_widget_set_sensitive(GTK_WIDGET(clear_button), capture_in_progress);
        /*if (capture_in_progress) {
            gtk_widget_hide(GTK_WIDGET(new_button));
            gtk_widget_show(GTK_WIDGET(stop_button));
        } else {
            gtk_widget_show(GTK_WIDGET(new_button));
            gtk_widget_hide(GTK_WIDGET(stop_button));
        }*/
#endif /* HAVE_LIBPCAP */
        gtk_widget_set_sensitive(GTK_WIDGET(open_button), !capture_in_progress);
    }
}

/* set toolbar state "have packets captured" */
void set_toolbar_for_captured_packets(gboolean have_captured_packets) {

    if (toolbar_init) {
	gtk_widget_set_sensitive(GTK_WIDGET(print_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(find_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(history_back_button),
				 have_captured_packets);
	gtk_widget_set_sensitive(GTK_WIDGET(history_forward_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(go_to_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(go_to_top_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(go_to_bottom_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(zoom_in_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(zoom_out_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(zoom_100_button),
				 have_captured_packets);
        gtk_widget_set_sensitive(GTK_WIDGET(resize_columns_button),
				 have_captured_packets);

        /* XXX - I don't see a reason why this should be done (as it is in the
         * menus) */
        /* gtk_widget_set_sensitive(GTK_WIDGET(color_display_button),
	   have_captured_packets);*/
    }
}


/* helper function: add a separator to the toolbar */
static void toolbar_append_separator(GtkWidget *toolbar) {
    GtkToolItem *tool_item = gtk_separator_tool_item_new();
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar), tool_item, -1);
    gtk_widget_show(GTK_WIDGET(tool_item));
}



#define toolbar_item(new_item, toolbar, stock, tooltip_text, callback, user_data) { \
    new_item = gtk_tool_button_new_from_stock(stock); \
    gtk_widget_set_tooltip_text(GTK_WIDGET(new_item), tooltip_text); \
    g_signal_connect(new_item, "clicked", G_CALLBACK(callback), user_data); \
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar), new_item, -1); \
    gtk_widget_show(GTK_WIDGET(new_item)); \
    }

#define toolbar_toggle_button(new_item, window, toolbar, stock, tooltip_text, callback, user_data) { \
    new_item = gtk_toggle_tool_button_new_from_stock(stock); \
    gtk_widget_set_tooltip_text(GTK_WIDGET(new_item), tooltip_text);	\
    g_signal_connect(new_item, "toggled", G_CALLBACK(callback), user_data); \
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar), new_item, -1); \
    gtk_widget_show_all(GTK_WIDGET(new_item)); \
    }

#define TOGGLE_BUTTON               GTK_TOGGLE_TOOL_BUTTON
#define TOGGLE_BUTTON_GET_ACTIVE    gtk_toggle_tool_button_get_active
#define TOGGLE_BUTTON_SET_ACTIVE    gtk_toggle_tool_button_set_active

static void
colorize_toggle_cb(GtkWidget *toggle_button, gpointer user_data _U_)  {
    menu_colorize_changed(TOGGLE_BUTTON_GET_ACTIVE(TOGGLE_BUTTON(toggle_button)));
}

void
toolbar_colorize_changed(gboolean packet_list_colorize) {
    if(TOGGLE_BUTTON_GET_ACTIVE(TOGGLE_BUTTON(colorize_button)) != packet_list_colorize) {
        TOGGLE_BUTTON_SET_ACTIVE(TOGGLE_BUTTON(colorize_button), packet_list_colorize);
    }
}

#ifdef HAVE_LIBPCAP
static void
auto_scroll_live_toggle_cb(GtkWidget *autoscroll_button_lcl, gpointer user_data _U_) {
    menu_auto_scroll_live_changed(TOGGLE_BUTTON_GET_ACTIVE(TOGGLE_BUTTON(autoscroll_button_lcl)));
}

void
toolbar_auto_scroll_live_changed(gboolean auto_scroll_live_lcl) {
    if(TOGGLE_BUTTON_GET_ACTIVE(TOGGLE_BUTTON(autoscroll_button)) != auto_scroll_live_lcl) {
        TOGGLE_BUTTON_SET_ACTIVE(TOGGLE_BUTTON(autoscroll_button), auto_scroll_live_lcl);
    }
}
#endif


/*
 * Create all toolbars (currently only the main toolbar)
 */
GtkWidget *
toolbar_new(void)
{
    GtkWidget *main_tb;
    GtkWidget *window = top_level;

    /* this function should be only called once! */
    g_assert(!toolbar_init);

    /* we need to realize the window because we use pixmaps for
     * items on the toolbar in the context of it */
    /* (coming from the gtk example, please don't ask me why ;-) */
    gtk_widget_realize(window);

    /* toolbar will be horizontal, with both icons and text (as default here) */
    /* (this will usually be overwritten by the preferences setting) */
    main_tb = gtk_toolbar_new();
#if GTK_CHECK_VERSION(2,16,0)
    gtk_orientable_set_orientation(GTK_ORIENTABLE(main_tb),
                                GTK_ORIENTATION_HORIZONTAL);
#else
    gtk_toolbar_set_orientation(GTK_TOOLBAR(main_tb),
                                GTK_ORIENTATION_HORIZONTAL);
#endif

    g_object_set_data(G_OBJECT(top_level), E_TB_MAIN_KEY, main_tb);


#ifdef HAVE_LIBPCAP
    toolbar_item(if_button, main_tb,
	WIRESHARK_STOCK_CAPTURE_INTERFACES, "List the available capture interfaces...", capture_if_cb, NULL);

    toolbar_item(capture_options_button, main_tb,
	WIRESHARK_STOCK_CAPTURE_OPTIONS, "Show the capture options...", capture_prep_cb, NULL);

    toolbar_item(new_button, main_tb,
	WIRESHARK_STOCK_CAPTURE_START, "Start a new live capture", capture_start_cb, NULL);

    toolbar_item(stop_button, main_tb,
	WIRESHARK_STOCK_CAPTURE_STOP, "Stop the running live capture", capture_stop_cb, NULL);

    toolbar_item(clear_button, main_tb,
	WIRESHARK_STOCK_CAPTURE_RESTART, "Restart the running live capture", capture_restart_cb, NULL);

    toolbar_append_separator(main_tb);
#endif /* HAVE_LIBPCAP */

    toolbar_item(open_button, main_tb,
	GTK_STOCK_OPEN, "Open a capture file...", file_open_cmd_cb, NULL);

    /* Only create a separate button in GTK < 2.4.  With GTK 2.4+, we will
     * just modify the save_button to read/show save or save as as needed.
     * We'll also fudge in an object key ("save") for the save button with data which  specifies
     * whether the button is currently "save" (1)or "save as" (0).
     * The fcn file_save_or_save_as_cmd_cb
     * will then call the appropriate file_save_cmd_cb or file_save_as_cmd_cb
     */

    toolbar_item(save_button, main_tb,
	GTK_STOCK_SAVE, SAVE_BUTTON_TOOLTIP_TEXT, file_save_or_save_as_cmd_cb, NULL);
    g_object_set_data(G_OBJECT(save_button), "save", GINT_TO_POINTER(1));

    toolbar_item(close_button, main_tb,
	GTK_STOCK_CLOSE, "Close this capture file", file_close_cmd_cb, NULL);

    toolbar_item(reload_button, main_tb,
	GTK_STOCK_REFRESH, "Reload this capture file", file_reload_cmd_cb, NULL);

    toolbar_item(print_button, main_tb,
	GTK_STOCK_PRINT, "Print packet(s)...", file_print_cmd_cb, NULL);

    toolbar_append_separator(main_tb);

    toolbar_item(find_button, main_tb,
	GTK_STOCK_FIND, "Find a packet...", find_frame_cb, NULL);

    toolbar_item(history_back_button, main_tb,
	GTK_STOCK_GO_BACK, "Go back in packet history", history_back_cb, NULL);

    toolbar_item(history_forward_button, main_tb,
	GTK_STOCK_GO_FORWARD, "Go forward in packet history", history_forward_cb, NULL);

    toolbar_item(go_to_button, main_tb,
	GTK_STOCK_JUMP_TO, "Go to the packet with number...", goto_frame_cb, NULL);

    toolbar_item(go_to_top_button, main_tb,
	GTK_STOCK_GOTO_TOP, "Go to the first packet", goto_top_frame_cb, NULL);

    toolbar_item(go_to_bottom_button, main_tb,
	GTK_STOCK_GOTO_BOTTOM, "Go to the last packet", goto_bottom_frame_cb, NULL);

    toolbar_append_separator(main_tb);

    toolbar_toggle_button(colorize_button, window, main_tb,
	WIRESHARK_STOCK_COLORIZE, "Colorize Packet List", colorize_toggle_cb, NULL);

#ifdef HAVE_LIBPCAP
    toolbar_toggle_button(autoscroll_button, window, main_tb,
	WIRESHARK_STOCK_AUTOSCROLL, "Auto Scroll Packet List in Live Capture", auto_scroll_live_toggle_cb, NULL);
#endif

    toolbar_append_separator(main_tb);

    toolbar_item(zoom_in_button, main_tb,
	GTK_STOCK_ZOOM_IN, "Zoom in", view_zoom_in_cb, NULL);

    toolbar_item(zoom_out_button, main_tb,
	GTK_STOCK_ZOOM_OUT, "Zoom out", view_zoom_out_cb, NULL);

    toolbar_item(zoom_100_button, main_tb,
	GTK_STOCK_ZOOM_100, "Zoom 100%", view_zoom_100_cb, NULL);

    toolbar_item(resize_columns_button, main_tb,
    WIRESHARK_STOCK_RESIZE_COLUMNS, "Resize All Columns", new_packet_list_resize_columns_cb, NULL);

    toolbar_append_separator(main_tb);

#ifdef HAVE_LIBPCAP
    toolbar_item(capture_filter_button, main_tb,
	WIRESHARK_STOCK_CAPTURE_FILTER, "Edit capture filter...", cfilter_dialog_cb, NULL);
#endif /* HAVE_LIBPCAP */

    toolbar_item(display_filter_button, main_tb,
	WIRESHARK_STOCK_DISPLAY_FILTER, "Edit/apply display filter...", dfilter_dialog_cb, NULL);

    toolbar_item(color_display_button, main_tb,
	GTK_STOCK_SELECT_COLOR, "Edit coloring rules...", color_display_cb, NULL);

    /* the preference button uses it's own Stock icon label "Prefs", as "Preferences" is too long */
    toolbar_item(prefs_button, main_tb,
	GTK_STOCK_PREFERENCES, "Edit preferences...", prefs_cb, NULL);

    toolbar_append_separator(main_tb);

    toolbar_item(help_button, main_tb,
	GTK_STOCK_HELP, "Show some help...", topic_cb, GINT_TO_POINTER(HELP_CONTENT));

    /* disable all "sensitive" items by default */
    toolbar_init = TRUE;
    set_toolbar_for_unsaved_capture_file(FALSE);
    set_toolbar_for_captured_packets(FALSE);
    set_toolbar_for_capture_file(FALSE);
#ifdef HAVE_LIBPCAP
    set_toolbar_for_capture_in_progress(FALSE);
#endif /* HAVE_LIBPCAP */

    /* make current preferences effective */
    toolbar_redraw_all();

    return main_tb;
}

void
set_toolbar_object_data(gchar *key, gpointer data)
{
    g_object_set_data(G_OBJECT(open_button), key, data);
    g_object_set_data(G_OBJECT(reload_button), key, data);
}
