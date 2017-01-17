/* main_toolbar.c
 * The main toolbar
 * Copyright 2003, Ulf Lamping <ulf.lamping@web.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This file implements the "main" toolbar for Wireshark.
 */

#include "config.h"


#include <epan/prefs.h>

#include "../../cfile.h"

#include <gtk/gtk.h>

#ifdef HAVE_LIBPCAP
#include "ui/gtk/capture_dlg.h"
#include "ui/gtk/capture_if_dlg.h"
#endif /* HAVE_LIBPCAP */
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/capture_file_dlg.h"
#include "ui/gtk/find_dlg.h"
#include "ui/gtk/goto_dlg.h"
#include "ui/gtk/color_dlg.h"
#include "ui/gtk/prefs_dlg.h"
#include "ui/gtk/main.h"
#include "ui/gtk/main_toolbar.h"
#include "ui/gtk/main_toolbar_private.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/packet_history.h"
#include "ui/gtk/packet_list.h"
#include "ui/capture_globals.h"

#include <epan/plugin_if.h>

#include "ui/gtk/old-gtk-compat.h"

static gboolean toolbar_init = FALSE;

#ifdef HAVE_LIBPCAP
static GtkToolItem *capture_options_button, *new_button, *stop_button, *clear_button, *if_button;
static GtkToolItem *capture_filter_button, *autoscroll_button;
#endif /* HAVE_LIBPCAP */
static GtkToolItem *open_button, *save_button, *close_button, *reload_button;
static GtkToolItem *find_button, *history_forward_button, *history_back_button;
static GtkToolItem *go_to_button, *go_to_top_button, *go_to_bottom_button;
static GtkToolItem *display_filter_button;
static GtkToolItem *zoom_in_button, *zoom_out_button, *zoom_100_button, *colorize_button;
static GtkToolItem *resize_columns_button;
static GtkToolItem *color_display_button, *prefs_button, *help_button;

/*
 * Redraw all toolbars
 */
void
toolbar_redraw_all(void)
{
    GtkWidget     *main_tb;
    GtkWidget     *filter_tb;

    main_tb = (GtkWidget *)g_object_get_data(G_OBJECT(top_level), E_TB_MAIN_KEY);

    gtk_toolbar_set_style(GTK_TOOLBAR(main_tb),
                          (GtkToolbarStyle)prefs.gui_toolbar_main_style);

    filter_tb = (GtkWidget *)g_object_get_data(G_OBJECT(top_level), E_TB_FILTER_KEY);

    /* In case the filter toolbar hasn't been built */
    if(filter_tb)
        gtk_toolbar_set_style(GTK_TOOLBAR(filter_tb),
                              (GtkToolbarStyle)prefs.gui_toolbar_filter_style);
}

#ifdef HAVE_LIBPCAP
void set_start_button_sensitive(gboolean enable) {
    gtk_widget_set_sensitive(GTK_WIDGET(new_button), enable);
}
#endif

/* Enable or disable toolbar items based on whether you have a capture file
   and, if so, whether you've finished reading it and whether there's stuff
   in it that hasn't yet been saved to a permanent file. */
void set_toolbar_for_capture_file(capture_file *cf) {
    if (toolbar_init) {
        if (cf == NULL || cf->state == FILE_READ_IN_PROGRESS) {
            /* We have no open capture file, or we have one but we're in
               the process of reading it.  Disable everything having to
               do with the file. */
            gtk_widget_set_sensitive(GTK_WIDGET(save_button), FALSE);
            gtk_widget_set_sensitive(GTK_WIDGET(close_button), FALSE);
            gtk_widget_set_sensitive(GTK_WIDGET(reload_button), FALSE);
        } else {
            /* We have an open capture file and we're finished reading it.
               Enable "Save" if and only if we have something to save and
               can do so.  Enable "Close" and "Reload" unconditionally. */
            gtk_widget_set_sensitive(GTK_WIDGET(save_button), cf_can_save(cf));
            gtk_widget_set_sensitive(GTK_WIDGET(close_button), TRUE);
            gtk_widget_set_sensitive(GTK_WIDGET(reload_button), TRUE);
        }
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
        if (!capture_in_progress) {
            gtk_widget_set_sensitive(GTK_WIDGET(new_button), (global_capture_opts.num_selected > 0));
        }
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

/* set toolbar state "stopping a capture" */
void set_toolbar_for_capture_stopping(void) {

    if (toolbar_init) {
#ifdef HAVE_LIBPCAP
        gtk_widget_set_sensitive(GTK_WIDGET(stop_button), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(clear_button), FALSE);
        /*if (capture_in_progress) {
            gtk_widget_hide(GTK_WIDGET(new_button));
            gtk_widget_show(GTK_WIDGET(stop_button));
        } else {
            gtk_widget_show(GTK_WIDGET(new_button));
            gtk_widget_hide(GTK_WIDGET(stop_button));
        }*/
#endif /* HAVE_LIBPCAP */
    }
}

/* set toolbar state "have packets captured" */
void set_toolbar_for_captured_packets(gboolean have_captured_packets) {

    if (toolbar_init) {
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
    new_item = ws_gtk_tool_button_new_from_stock(stock); \
    gtk_widget_set_tooltip_text(GTK_WIDGET(new_item), tooltip_text); \
    g_signal_connect(new_item, "clicked", G_CALLBACK(callback), user_data); \
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar), new_item, -1); \
    gtk_widget_show(GTK_WIDGET(new_item)); \
    }

#define toolbar_toggle_button(new_item, window, toolbar, stock, tooltip_text, callback, user_data) { \
    new_item = ws_gtk_toggle_tool_button_new_from_stock(stock); \
    gtk_widget_set_tooltip_text(GTK_WIDGET(new_item), tooltip_text);   \
    g_signal_connect(new_item, "toggled", G_CALLBACK(callback), user_data); \
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar), new_item, -1); \
    gtk_widget_show_all(GTK_WIDGET(new_item)); \
    }

#define TOGGLE_BUTTON               GTK_TOGGLE_TOOL_BUTTON
#define TOGGLE_BUTTON_GET_ACTIVE    gtk_toggle_tool_button_get_active
#define TOGGLE_BUTTON_SET_ACTIVE    gtk_toggle_tool_button_set_active

static void
colorize_toggle_cb(GtkWidget *toggle_button, gpointer user_data _U_)  {
    main_colorize_changed(TOGGLE_BUTTON_GET_ACTIVE(TOGGLE_BUTTON(toggle_button)));
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
    main_auto_scroll_live_changed(TOGGLE_BUTTON_GET_ACTIVE(TOGGLE_BUTTON(autoscroll_button_lcl)));
}

void
toolbar_auto_scroll_live_changed(gboolean auto_scroll_live_lcl) {
    if(TOGGLE_BUTTON_GET_ACTIVE(TOGGLE_BUTTON(autoscroll_button)) != auto_scroll_live_lcl) {
        TOGGLE_BUTTON_SET_ACTIVE(TOGGLE_BUTTON(autoscroll_button), auto_scroll_live_lcl);
    }
}
#endif

static void
plugin_if_maintoolbar_goto_frame(gconstpointer user_data)
{
    if (user_data) {
        GHashTable * data_set = (GHashTable *) user_data;
        gpointer framenr;

        if (g_hash_table_lookup_extended(data_set, "frame_nr", NULL, &framenr)) {
            if (GPOINTER_TO_UINT(framenr) != 0)
                cf_goto_frame(&cfile, GPOINTER_TO_UINT(framenr));
        }
    }
}

#ifdef HAVE_LIBPCAP

static void plugin_if_maintoolbar_get_ws_info(gconstpointer user_data)
{
    GHashTable * data_set = (GHashTable *)user_data;
    ws_info_t *ws_info = NULL;
    capture_file *cf;

    if (!g_hash_table_lookup_extended(data_set, "ws_info", NULL, (void**)&ws_info))
        return;

    cf = &cfile;

    if (cf->state != FILE_CLOSED) {
        ws_info->ws_info_supported = TRUE;
        ws_info->cf_state = cf->state;
        ws_info->cf_count = cf->count;

        g_free(ws_info->cf_filename);
        ws_info->cf_filename = g_strdup(cf->filename);

        if (cf->state == FILE_READ_DONE && cf->current_frame) {
            ws_info->cf_framenr = cf->current_frame->num;
            ws_info->frame_passed_dfilter = (cf->current_frame->flags.passed_dfilter == 1);
        } else {
            ws_info->cf_framenr = 0;
            ws_info->frame_passed_dfilter = FALSE;
        }
    } else if (ws_info->cf_state != FILE_CLOSED) {
        /* Initialise the ws_info structure */
        ws_info->ws_info_supported = TRUE;
        ws_info->cf_count = 0;

        g_free(ws_info->cf_filename);
        ws_info->cf_filename = NULL;

        ws_info->cf_framenr = 0;
        ws_info->frame_passed_dfilter = FALSE;
        ws_info->cf_state = FILE_CLOSED;
    }
}

#endif /* HAVE_LIBPCAP */

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
    gtk_orientable_set_orientation(GTK_ORIENTABLE(main_tb),
                                GTK_ORIENTATION_HORIZONTAL);

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

    toolbar_item(save_button, main_tb,
        WIRESHARK_STOCK_SAVE, "Save this capture file", file_save_cmd_cb, NULL);

    toolbar_item(close_button, main_tb,
        GTK_STOCK_CLOSE, "Close this capture file", file_close_cmd_cb, NULL);

    toolbar_item(reload_button, main_tb,
        GTK_STOCK_REFRESH, "Reload this capture file", file_reload_cmd_cb, NULL);

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
    WIRESHARK_STOCK_RESIZE_COLUMNS, "Resize All Columns", packet_list_resize_columns_cb, NULL);

    toolbar_append_separator(main_tb);

#ifdef HAVE_LIBPCAP
    toolbar_item(capture_filter_button, main_tb,
        WIRESHARK_STOCK_CAPTURE_FILTER, "Edit capture filter...", cfilter_dialog_cb, NULL);
#endif /* HAVE_LIBPCAP */

    toolbar_item(display_filter_button, main_tb,
        WIRESHARK_STOCK_DISPLAY_FILTER, "Edit/apply display filter...", dfilter_dialog_cb, NULL);

    toolbar_item(color_display_button, main_tb,
        GTK_STOCK_SELECT_COLOR, "Edit coloring rules...", color_display_cb, NULL);

    /* the preference button uses its own Stock icon label "Prefs", as "Preferences" is too long */
    toolbar_item(prefs_button, main_tb,
        GTK_STOCK_PREFERENCES, "Edit preferences...", prefs_cb, NULL);

    toolbar_append_separator(main_tb);

    toolbar_item(help_button, main_tb,
        GTK_STOCK_HELP, "Show some help...", topic_cb, GINT_TO_POINTER(HELP_CONTENT));

    /* disable all "sensitive" items by default */
    toolbar_init = TRUE;
    set_toolbar_for_captured_packets(FALSE);
    set_toolbar_for_capture_file(NULL);
#ifdef HAVE_LIBPCAP
    set_toolbar_for_capture_in_progress(FALSE);
#endif /* HAVE_LIBPCAP */

    /* make current preferences effective */
    toolbar_redraw_all();

    plugin_if_register_gui_cb(PLUGIN_IF_GOTO_FRAME, plugin_if_maintoolbar_goto_frame);
#ifdef HAVE_LIBPCAP
    plugin_if_register_gui_cb(PLUGIN_IF_GET_WS_INFO, plugin_if_maintoolbar_get_ws_info);
#endif /* HAVE_LIBPCAP */

    return main_tb;
}

void
set_toolbar_object_data(const gchar *key, gpointer data)
{
    g_object_set_data(G_OBJECT(open_button), key, data);
    g_object_set_data(G_OBJECT(reload_button), key, data);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
