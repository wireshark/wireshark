/* plugins_dlg.c
 * Dialog boxes for plugins
 *
 * $Id: plugins_dlg.c,v 1.22 2001/01/28 21:17:29 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1999 Gerald Combs
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "globals.h"
#include "plugins.h"
#include "dlg_utils.h"

#ifdef HAVE_PLUGINS

static void plugins_close_cb(GtkWidget *, gpointer);
static void plugins_scan(GtkWidget *);

void
tools_plugins_cmd_cb(GtkWidget *widget, gpointer data)
{
    GtkWidget *plugins_window;
    GtkWidget *main_vbox;
    GtkWidget *main_frame;
    GtkWidget *frame_hbox;
    GtkWidget *scrolledwindow;
    GtkWidget *plugins_clist;
    GtkWidget *frame_vbnbox;
    GtkWidget *main_hbnbox;
    GtkWidget *close_bn;
    gchar     *titles[] = {"Name", "Version"};

    plugins_window = dlg_window_new("Ethereal: Plugins");

    main_vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(plugins_window), main_vbox);
    gtk_widget_show(main_vbox);

    main_frame = gtk_frame_new("Plugins List");
    gtk_box_pack_start(GTK_BOX(main_vbox), main_frame, TRUE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_frame), 10);
    gtk_widget_show(main_frame);

    frame_hbox = gtk_hbox_new(FALSE,0);
    gtk_container_add(GTK_CONTAINER(main_frame), frame_hbox);
    gtk_container_set_border_width(GTK_CONTAINER(frame_hbox), 5);
    gtk_widget_show(frame_hbox);

    scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(frame_hbox), scrolledwindow, TRUE, TRUE, 0);
    gtk_widget_set_usize(scrolledwindow, 400, 150);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow),
	    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_show(scrolledwindow);

    plugins_clist = gtk_clist_new_with_titles(2, titles);
    gtk_container_add(GTK_CONTAINER(scrolledwindow), plugins_clist);
    gtk_clist_set_selection_mode(GTK_CLIST(plugins_clist), GTK_SELECTION_SINGLE);
    gtk_clist_column_titles_passive(GTK_CLIST(plugins_clist));
    gtk_clist_column_titles_show(GTK_CLIST(plugins_clist));
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_clist), 0, TRUE);
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_clist), 1, TRUE);
    plugins_scan(plugins_clist);
    gtk_widget_show(plugins_clist);

    frame_vbnbox = gtk_vbutton_box_new();
    gtk_box_pack_start(GTK_BOX(frame_hbox), frame_vbnbox, FALSE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(frame_vbnbox), 20);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(frame_vbnbox), GTK_BUTTONBOX_SPREAD);
    gtk_widget_show(frame_vbnbox);

    main_hbnbox = gtk_hbutton_box_new();
    gtk_box_pack_start(GTK_BOX(main_vbox), main_hbnbox, FALSE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_hbnbox), 10);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(main_hbnbox), GTK_BUTTONBOX_SPREAD);
    gtk_widget_show(main_hbnbox);

    close_bn = gtk_button_new_with_label("Close");
    gtk_container_add(GTK_CONTAINER(main_hbnbox), close_bn);
    gtk_widget_show(close_bn);
    gtk_signal_connect(GTK_OBJECT(close_bn), "clicked",
	    GTK_SIGNAL_FUNC(plugins_close_cb), GTK_OBJECT(plugins_window));

    gtk_widget_show(plugins_window);

}

/*
 * Fill the clist widget with a list of the plugin modules.
 */
static void
plugins_scan(GtkWidget *clist)
{
    plugin   *pt_plug;
    gchar    *plugent[2];               /* new entry added in clist */

    pt_plug = plugin_list;
    while (pt_plug)
    {
	plugent[0] = pt_plug->name;
	plugent[1] = pt_plug->version;
	gtk_clist_append(GTK_CLIST(clist), plugent);
	pt_plug = pt_plug->next;
    }
}

static void
plugins_close_cb(GtkWidget *close_bt, gpointer parent_w)
{
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}
#endif
