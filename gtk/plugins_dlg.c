/* plugins_dlg.c
 * Dialog boxes for plugins
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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

#include <gtk/gtk.h>

#include "globals.h"
#include <epan/plugins.h>
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "plugins_dlg.h"

#ifdef HAVE_PLUGINS

static void plugins_destroy_cb(GtkWidget *, gpointer);

/*
 * Keep a static pointer to the current "Plugins" window, if any, so that
 * if somebody tries to do "Help->About Plugins" while there's already a
 * "Plugins" window up, we just pop up the existing one, rather than
 * creating a new one.
*/
static GtkWidget *plugins_window = NULL;



/*
 * Fill the list widget with a list of the plugin modules.
 */
static void
plugins_scan(GtkWidget *list)
{
    plugin     *pt_plug;
    GString    *type;
    const char       *sep;

    pt_plug = plugin_list;
    while (pt_plug)
    {
        type = g_string_new("");
        sep = "";
        if (pt_plug->register_protoinfo)
        {
            type = g_string_append(type, sep);
            type = g_string_append(type, "dissector");
            sep = ",";
        }
        if (pt_plug->register_tap_listener)
        {
            type = g_string_append(type, sep);
            type = g_string_append(type, "tap");
            sep = ",";
        }
        simple_list_append(list, 0, pt_plug->name, 1, pt_plug->version,
                           2, type->str, -1);
        g_string_free(type, TRUE);
        pt_plug = pt_plug->next;
    }
}


GtkWidget *
about_plugins_page_new(void)
{
    GtkWidget *scrolledwindow;
    GtkWidget *plugins_list;
    const gchar     *titles[] = {"Name", "Version", "Type"};

    
    scrolledwindow = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow), 
                                   GTK_SHADOW_IN);
#endif

    plugins_list = simple_list_new(3 , titles);
    plugins_scan(plugins_list);

    gtk_container_add(GTK_CONTAINER(scrolledwindow), plugins_list);

    return scrolledwindow;
}

static void
tools_plugins_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    GtkWidget *main_vbox;
    GtkWidget *main_frame;
    GtkWidget *frame_hbox;
    GtkWidget *page;
    GtkWidget *bbox;
    GtkWidget *ok_bt;

    if (plugins_window != NULL) {
        /* There's already a "Plugins" dialog box; reactivate it. */
        reactivate_window(plugins_window);
        return;
    }

    plugins_window = dlg_window_new("Ethereal: Plugins");
    gtk_window_set_default_size(GTK_WINDOW(plugins_window), 250, 200);

    main_vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(plugins_window), main_vbox);

    main_frame = gtk_frame_new("Plugins List");
    gtk_box_pack_start(GTK_BOX(main_vbox), main_frame, TRUE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_frame), 5);

    frame_hbox = gtk_hbox_new(FALSE,0);
    gtk_container_add(GTK_CONTAINER(main_frame), frame_hbox);
    gtk_container_set_border_width(GTK_CONTAINER(frame_hbox), 5);

    page = about_plugins_page_new();
    gtk_box_pack_start(GTK_BOX(frame_hbox), page, TRUE, TRUE, 0);

    /* button row */
    bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
    gtk_box_pack_end(GTK_BOX(main_vbox), bbox, FALSE, FALSE, 3);

    ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
    window_set_cancel_button(plugins_window, ok_bt, window_cancel_button_cb);

    SIGNAL_CONNECT(plugins_window, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(plugins_window, "destroy", plugins_destroy_cb, NULL);

    gtk_widget_show_all(plugins_window);
    window_present(plugins_window);
}

static void
plugins_destroy_cb(GtkWidget *w _U_, gpointer data _U_)
{
    /* Note that we no longer have a Plugins window. */
    plugins_window = NULL;
}


#endif /* HAVE_PLUGINS */
