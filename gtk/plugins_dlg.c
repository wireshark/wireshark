/* plugins_dlg.c
 * Dialog boxes for plugins
 *
 * $Id: plugins_dlg.c,v 1.33 2004/01/21 21:19:33 ulfl Exp $
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
#if GTK_MAJOR_VERSION >= 2
#include "ui_util.h"
#endif
#include "compat_macros.h"

#ifdef HAVE_PLUGINS

static void plugins_close_cb(GtkWidget *, gpointer);
#if GTK_MAJOR_VERSION < 2
static void plugins_scan(GtkWidget *);
#else
static void plugins_scan(GtkListStore *);
#endif

void
tools_plugins_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    GtkWidget *plugins_window;
    GtkWidget *main_vbox;
    GtkWidget *main_frame;
    GtkWidget *frame_hbox;
    GtkWidget *scrolledwindow;
    GtkWidget *plugins_list;
    GtkWidget *bbox;
    GtkWidget *ok_bt;
    gchar     *titles[] = {"Name", "Version"};
#if GTK_MAJOR_VERSION >= 2
    GtkListStore *store;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
#endif

    plugins_window = dlg_window_new("Ethereal: Plugins");

    main_vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(plugins_window), main_vbox);
    gtk_widget_show(main_vbox);

    main_frame = gtk_frame_new("Plugins List");
    gtk_box_pack_start(GTK_BOX(main_vbox), main_frame, TRUE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_frame), 5);
    gtk_widget_show(main_frame);

    frame_hbox = gtk_hbox_new(FALSE,0);
    gtk_container_add(GTK_CONTAINER(main_frame), frame_hbox);
    gtk_container_set_border_width(GTK_CONTAINER(frame_hbox), 5);
    gtk_widget_show(frame_hbox);

    scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(frame_hbox), scrolledwindow, TRUE, TRUE, 0);
    WIDGET_SET_SIZE(scrolledwindow, 250, 200);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_show(scrolledwindow);

#if GTK_MAJOR_VERSION < 2
    plugins_list = gtk_clist_new_with_titles(2, titles);
    gtk_container_add(GTK_CONTAINER(scrolledwindow), plugins_list);
    gtk_clist_set_selection_mode(GTK_CLIST(plugins_list), GTK_SELECTION_SINGLE);
    gtk_clist_column_titles_passive(GTK_CLIST(plugins_list));
    gtk_clist_column_titles_show(GTK_CLIST(plugins_list));
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_list), 0, TRUE);
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_list), 1, TRUE);
    plugins_scan(plugins_list);
#else
    store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
    plugins_scan(store);
    plugins_list = tree_view_new(GTK_TREE_MODEL(store));
    g_object_unref(G_OBJECT(store));
    gtk_container_add(GTK_CONTAINER(scrolledwindow), plugins_list);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes(titles[0], renderer,
                                                      "text", 0, NULL);
    gtk_tree_view_column_set_sort_column_id(column, 0);
    gtk_tree_view_append_column(GTK_TREE_VIEW(plugins_list), column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes(titles[1], renderer,
                                                      "text", 1, NULL);
    gtk_tree_view_column_set_sort_column_id(column, 1);
    gtk_tree_view_append_column(GTK_TREE_VIEW(plugins_list), column);
#endif
    gtk_widget_show(plugins_list);

    bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
    gtk_box_pack_end(GTK_BOX(main_vbox), bbox, FALSE, FALSE, 3);
    gtk_widget_show(bbox);

    ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
    SIGNAL_CONNECT(ok_bt, "clicked", plugins_close_cb, plugins_window);
    gtk_widget_grab_default(ok_bt);

    /* Catch the "key_press_event" signal in the window, so that we can catch
       the ESC key being pressed and act as if the "OK" button had
       been selected. */
	dlg_set_cancel(plugins_window, ok_bt);

    gtk_widget_show(plugins_window);

}

/*
 * Fill the list widget with a list of the plugin modules.
 */
#if GTK_MAJOR_VERSION < 2
static void
plugins_scan(GtkWidget *list)
#else
static void
plugins_scan(GtkListStore *store)
#endif
{
    plugin     *pt_plug;
#if GTK_MAJOR_VERSION < 2
    gchar      *plugent[2];               /* new entry added in clist */
#else
    GtkTreeIter iter;
#endif

    pt_plug = plugin_list;
    while (pt_plug)
    {
#if GTK_MAJOR_VERSION < 2
	plugent[0] = pt_plug->name;
	plugent[1] = pt_plug->version;
	gtk_clist_append(GTK_CLIST(list), plugent);
#else
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter, 0, pt_plug->name, 1, pt_plug->version,
                           -1);
#endif
	pt_plug = pt_plug->next;
    }
}

static void
plugins_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}
#endif
