/* toolbar.c
 * The main toolbar
 * Copyright 2003, Ulf Lamping <ulf.lamping@web.de>
 *
 * $Id: toolbar.c,v 1.21 2004/01/20 02:21:17 ulfl Exp $
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
 * (stock-icons including: icons for "open", "save", "print", ...).
 * The gtk2 version of this code uses them.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#ifdef HAVE_LIBPCAP
#include "capture_dlg.h"
#endif /* HAVE_LIBPCAP */
#include "filter_prefs.h"
#include "file_dlg.h"
#include "find_dlg.h"
#include "goto_dlg.h"
#include "color.h"
#include "color_dlg.h"
#include "prefs.h"
#include "prefs_dlg.h"
#include "main.h"
#include "help_dlg.h"
#include "gtkglobals.h"
#include "toolbar.h"
#include "keys.h"
#include "compat_macros.h"
#include "recent.h"

/* All of the icons used here are coming (or are derived) from GTK2 stock icons.
 * They were converted using "The Gimp" with standard conversion from png to xpm.
 * All stock icons can be (currently) found at: 
 * "ftp://ftp.gtk.org/pub/gtk/v2.0/gtk+-2.0.6.tar.bz2"
 * in the directory "gtk+-2.0.6\gtk\stock-icons" */
#if GTK_MAJOR_VERSION < 2
#ifdef HAVE_LIBPCAP
#include "../image/toolbar/stock_stop_24.xpm"
#endif /* HAVE_LIBPCAP */
#include "../image/toolbar/stock_open_24.xpm"
#include "../image/toolbar/stock_save_24.xpm"
#include "../image/toolbar/stock_save_as_24.xpm"
#include "../image/toolbar/stock_close_24.xpm"
#include "../image/toolbar/stock_refresh_24.xpm"
#include "../image/toolbar/stock_print_24.xpm"
#include "../image/toolbar/stock_search_24.xpm"
#include "../image/toolbar/stock_right_arrow_24.xpm"
#include "../image/toolbar/stock_jump_to_24.xpm"
#include "../image/toolbar/stock_colorselector_24.xpm"
#include "../image/toolbar/stock_help_24.xpm"
#endif /* GTK_MAJOR_VERSION */

/* these icons are derived from the original stock icons */
#ifdef HAVE_LIBPCAP
#include "../image/toolbar/capture_24.xpm"
#include "../image/toolbar/cfilter_24.xpm"
#endif /* HAVE_LIBPCAP */
#include "../image/toolbar/dfilter_24.xpm"
#include "../image/toolbar/stock_preferences_24.xpm"


/* XXX: add this key to some .h file, as it adds a key to the top level Widget? */
#define E_TB_MAIN_KEY             "toolbar_main"


static gboolean toolbar_init = FALSE;

#ifdef HAVE_LIBPCAP
static GtkWidget *new_button, *stop_button;
static GtkWidget *capture_filter_button;
#endif /* HAVE_LIBPCAP */
static GtkWidget *open_button, *save_button, *save_as_button, *close_button, *reload_button;
static GtkWidget *print_button, *find_button, *find_next_button, *go_to_button;
static GtkWidget *display_filter_button;
static GtkWidget *color_display_button, *prefs_button, *help_button;

static void get_main_toolbar(GtkWidget *window, GtkWidget **toolbar);



#if GTK_MAJOR_VERSION >= 2
typedef struct stock_pixmap_tag{
    const char *    name;
    char **         xpm_data;
} stock_pixmap_t;

/* generate application specific stock items */
void ethereal_stock_icons(void) {
    GtkIconFactory * factory;
    gint32 i;


    /* register non-standard pixmaps with the gtk-stock engine */
    static const GtkStockItem stock_items[] = {
#ifdef HAVE_LIBPCAP
        { ETHEREAL_STOCK_CAPTURE_START,         ETHEREAL_STOCK_LABEL_CAPTURE_START,         0, 0, NULL },
        { ETHEREAL_STOCK_CAPTURE_FILTER,        ETHEREAL_STOCK_LABEL_CAPTURE_FILTER,        0, 0, NULL },
        { ETHEREAL_STOCK_CAPTURE_FILTER_ENTRY,  ETHEREAL_STOCK_LABEL_CAPTURE_FILTER_ENTRY,  0, 0, NULL },
#endif
        { ETHEREAL_STOCK_DISPLAY_FILTER,        ETHEREAL_STOCK_LABEL_DISPLAY_FILTER,        0, 0, NULL },
        { ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY,  ETHEREAL_STOCK_LABEL_DISPLAY_FILTER_ENTRY,  0, 0, NULL },
        { ETHEREAL_STOCK_PREFS,                 ETHEREAL_STOCK_LABEL_PREFS,                 0, 0, NULL },
    };

    static const stock_pixmap_t pixmaps[] = {
#ifdef HAVE_LIBPCAP
        { ETHEREAL_STOCK_CAPTURE_START,         capture_24_xpm },
        { ETHEREAL_STOCK_CAPTURE_FILTER,        cfilter_24_xpm },
        { ETHEREAL_STOCK_CAPTURE_FILTER_ENTRY,  cfilter_24_xpm },
#endif
        { ETHEREAL_STOCK_DISPLAY_FILTER,        dfilter_24_xpm },
        { ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY,  dfilter_24_xpm },
        { ETHEREAL_STOCK_PREFS,                 stock_preferences_24_xpm },
        { NULL, NULL }
    };

    /* Register our stock items */
    gtk_stock_add (stock_items, G_N_ELEMENTS (stock_items));

    /* Add our custom icon factory to the list of defaults */
    factory = gtk_icon_factory_new();
    gtk_icon_factory_add_default(factory);

    /* Create the stock items to add into our icon factory */
    for (i = 0; pixmaps[i].name != NULL; i++) {
        GdkPixbuf * pixbuf;
        GtkIconSet *icon_set;

        pixbuf = gdk_pixbuf_new_from_xpm_data((const char **) (pixmaps[i].xpm_data));
        g_assert(pixbuf);
        icon_set = gtk_icon_set_new_from_pixbuf (pixbuf);
        gtk_icon_factory_add (factory, pixmaps[i].name, icon_set);
        gtk_icon_set_unref (icon_set);
        g_object_unref (G_OBJECT (pixbuf));
    }

    /* Drop our reference to the factory, GTK will hold a reference.*/
    g_object_unref (G_OBJECT (factory));
}
#endif


/*
 * Redraw all toolbars (currently only the main toolbar)
 */
void
toolbar_redraw_all(void)
{
    GtkWidget     *main_tb;

    main_tb = OBJECT_GET_DATA(top_level, E_TB_MAIN_KEY);

    gtk_toolbar_set_style(GTK_TOOLBAR(main_tb),
                          prefs.gui_toolbar_main_style);

#if GTK_MAJOR_VERSION < 2
    /* In GTK+ 1.2[.x], the toolbar takes the maximum vertical size it ever
     * had, even if you change the style in such a way as to reduce its
     * height, unless we queue a resize (which resizes ALL elements in the
     * top-level container).
     *
     * In GTK+ 2.x, this isn't necessary - it does the right thing. */
    gtk_container_queue_resize(GTK_CONTAINER(top_level));
#endif /* GTK_MAJOR_VERSION */
}

/* Enable or disable toolbar items based on whether you have a capture file
   you've finished reading. */
void set_toolbar_for_capture_file(gboolean have_capture_file) {
    if (toolbar_init) {
        gtk_widget_set_sensitive(save_button, have_capture_file);
        gtk_widget_set_sensitive(save_as_button, have_capture_file);
        gtk_widget_set_sensitive(close_button, have_capture_file);
        gtk_widget_set_sensitive(reload_button, have_capture_file);
    }
}

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void set_toolbar_for_unsaved_capture_file(gboolean have_unsaved_capture_file) {
    if (toolbar_init) {
        if(have_unsaved_capture_file) {
            gtk_widget_hide(save_as_button);
            gtk_widget_show(save_button);
        } else {
            gtk_widget_show(save_as_button);
            gtk_widget_hide(save_button);
        }
        /*gtk_widget_set_sensitive(save_button, have_unsaved_capture_file);
        gtk_widget_set_sensitive(save_as_button, !have_unsaved_capture_file);*/
    }
}

/* set toolbar state "have a capture in progress" */
void set_toolbar_for_capture_in_progress(gboolean capture_in_progress) {

    if (toolbar_init) {
#ifdef HAVE_LIBPCAP
        gtk_widget_set_sensitive(new_button, !capture_in_progress);
#endif
        gtk_widget_set_sensitive(open_button, !capture_in_progress);

#ifdef HAVE_LIBPCAP
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
#else /* _WIN32 */
        gtk_widget_set_sensitive(new_button, !capture_in_progress);
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */
    }
}

/* set toolbar state "have packets captured" */
void set_toolbar_for_captured_packets(gboolean have_captured_packets) {

    if (toolbar_init) {
        gtk_widget_set_sensitive(print_button, have_captured_packets);
        gtk_widget_set_sensitive(find_button, have_captured_packets);
        gtk_widget_set_sensitive(find_next_button, have_captured_packets);
        gtk_widget_set_sensitive(go_to_button, have_captured_packets);
        /* XXX - I don't see a reason why this should be done (as it is in the
         * menus) */
        /* gtk_widget_set_sensitive(color_display_button, have_captured_packets);*/
    }
}


/* helper function: add a separator to the toolbar */
static void toolbar_append_separator(GtkWidget *toolbar) {
#if GTK_MAJOR_VERSION < 2
    /* XXX - the usage of a gtk_separator doesn't seem to work for a toolbar.
     * (at least in the win32 port of gtk 1.3)
     * So simply add a few spaces */
    gtk_toolbar_append_space(GTK_TOOLBAR(toolbar)); /* space after item */
    gtk_toolbar_append_space(GTK_TOOLBAR(toolbar)); /* space after item */
#else
    /* GTK 2 uses (as it should be) a seperator when adding this space */
    gtk_toolbar_append_space(GTK_TOOLBAR(toolbar));
#endif /* GTK_MAJOR_VERSION */
}



#if GTK_MAJOR_VERSION < 2
#define toolbar_item(new_item, window, toolbar, stock, tooltip, xpm, callback) { \
    icon = gdk_pixmap_create_from_xpm_d(window->window, &mask, &window->style->white, xpm); \
    iconw = gtk_pixmap_new(icon, mask); \
    new_item = gtk_toolbar_append_item(GTK_TOOLBAR (toolbar), \
        stock, tooltip, "Private", iconw, GTK_SIGNAL_FUNC(callback), NULL);\
    }
#else
#define toolbar_item(new_item, window, toolbar, stock, tooltip, xpm, callback) { \
    new_item = gtk_toolbar_insert_stock(GTK_TOOLBAR(toolbar), \
        stock, tooltip, "Private", G_CALLBACK(callback), NULL, -1);\
    }
#endif /* GTK_MAJOR_VERSION */


/*
 * Create all toolbars (currently only the main toolbar)
 */
GtkWidget *
toolbar_new(void)
{
    GtkWidget *main_tb;
    GtkWidget *window = top_level;
#if GTK_MAJOR_VERSION < 2
    GdkPixmap *icon;
    GtkWidget *iconw;
    GdkBitmap * mask;
#endif /* GTK_MAJOR_VERSION */

    
#if GTK_MAJOR_VERSION >= 2
    /* create application specific stock icons */
    ethereal_stock_icons();
#endif

    /* this function should be only called once! */
    g_assert(!toolbar_init);

    /* we need to realize the window because we use pixmaps for 
     * items on the toolbar in the context of it */
    /* (coming from the gtk example, please don't ask me why ;-) */
    gtk_widget_realize(window);

    /* toolbar will be horizontal, with both icons and text (as default here) */
    /* (this will usually be overwritten by the preferences setting) */
#if GTK_MAJOR_VERSION < 2
    main_tb = gtk_toolbar_new(GTK_ORIENTATION_HORIZONTAL,
                               GTK_TOOLBAR_BOTH);
    gtk_toolbar_set_space_size(GTK_TOOLBAR(main_tb), 3);
#else
    main_tb = gtk_toolbar_new();
    gtk_toolbar_set_orientation(GTK_TOOLBAR(main_tb),
                                GTK_ORIENTATION_HORIZONTAL);
#endif /* GTK_MAJOR_VERSION */

    OBJECT_SET_DATA(top_level, E_TB_MAIN_KEY, main_tb);


#ifdef HAVE_LIBPCAP
    /* either start OR stop button can be valid at a time, so no space 
     * between them is needed here (stop button is hidden by default) */

    toolbar_item(new_button, window, main_tb, 
        ETHEREAL_STOCK_CAPTURE_START, "Start a new live capture...", capture_24_xpm, capture_prep_cb);
#ifndef _WIN32
    toolbar_item(stop_button, window, main_tb, 
        GTK_STOCK_STOP, "Stop the running live capture", stock_stop_24_xpm, capture_stop_cb);
#endif /* _WIN32 */
    toolbar_append_separator(main_tb);
#endif /* HAVE_LIBPCAP */

    toolbar_item(open_button, window, main_tb, 
        GTK_STOCK_OPEN, "Open a capture file...", stock_open_24_xpm, file_open_cmd_cb);
    toolbar_item(save_button, window, main_tb, 
        GTK_STOCK_SAVE, "Save this capture file...", stock_save_24_xpm, file_save_cmd_cb);
    toolbar_item(save_as_button, window, main_tb, 
        GTK_STOCK_SAVE_AS, "Save this capture file as...", stock_save_as_24_xpm, file_save_as_cmd_cb);
    toolbar_item(close_button, window, main_tb, 
        GTK_STOCK_CLOSE, "Close this capture file", stock_close_24_xpm, file_close_cmd_cb);
    toolbar_item(reload_button, window, main_tb, 
        GTK_STOCK_REFRESH, "Reload this capture file", stock_refresh_24_xpm, file_reload_cmd_cb);
    toolbar_item(print_button, window, main_tb, 
        GTK_STOCK_PRINT, "Print packet(s)...", stock_print_24_xpm, file_print_cmd_cb);
    toolbar_append_separator(main_tb);

    toolbar_item(find_button, window, main_tb, 
        GTK_STOCK_FIND, "Find a packet...", stock_search_24_xpm, find_frame_cb);
    toolbar_item(find_next_button, window, main_tb, 
        GTK_STOCK_GO_FORWARD, "Find the next matching packet", stock_right_arrow_24_xpm, find_next_cb);
    toolbar_item(go_to_button, window, main_tb, 
        GTK_STOCK_JUMP_TO, "Go to the packet with number...", stock_jump_to_24_xpm, goto_frame_cb);
    toolbar_append_separator(main_tb);
    
#ifdef HAVE_LIBPCAP
    toolbar_item(capture_filter_button, window, main_tb, 
        ETHEREAL_STOCK_CAPTURE_FILTER, "Edit capture filter...", cfilter_24_xpm, cfilter_dialog_cb);
#endif /* HAVE_LIBPCAP */
    toolbar_item(display_filter_button, window, main_tb, 
        ETHEREAL_STOCK_DISPLAY_FILTER, "Edit/apply display filter...", dfilter_24_xpm, dfilter_dialog_cb);
    toolbar_item(color_display_button, window, main_tb, 
        GTK_STOCK_SELECT_COLOR, "Edit coloring rules...", stock_colorselector_24_xpm, color_display_cb);
    /* the preference button uses it's own Stock icon label "Prefs", as "Preferences" is too long */
    toolbar_item(prefs_button, window, main_tb, 
        ETHEREAL_STOCK_PREFS, "Edit preferences...", stock_preferences_24_xpm, prefs_cb);
    toolbar_append_separator(main_tb);

    toolbar_item(help_button, window, main_tb, 
        GTK_STOCK_HELP, "Show some help...", stock_help_24_xpm, help_cb);

    /* disable all "sensitive" items by default */
    toolbar_init = TRUE;
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
    OBJECT_SET_DATA(open_button, key, data);
    OBJECT_SET_DATA(reload_button, key, data);
}
