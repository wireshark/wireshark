/* plugins_dlg.c
 * Dialog boxes for plugins
 *
 * $Id: plugins_dlg.c,v 1.2 1999/12/09 20:55:49 oabad Exp $
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

#ifdef HAVE_DLFCN_H

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "globals.h"
#include "plugins.h"
#include "keys.h"
#include "prefs_dlg.h"
#include "ui_util.h"

static gint selected_row;
static gchar *selected_name;
static gchar *selected_version;
static gchar *selected_enabled;
static gchar std_plug_dir[] = "/usr/share/ethereal/plugins";
static gchar local_plug_dir[] = "/usr/local/share/ethereal/plugins";
static gchar *user_plug_dir = NULL;

static void plugins_close_cb(GtkWidget *, gpointer);
static void plugins_scan(GtkWidget *);
static void plugins_scan_dir(const char *);
static void plugins_clist_select_cb(GtkWidget *, gint, gint,
	GdkEventButton *, gpointer);
static void plugins_clist_unselect_cb(GtkWidget *, gint, gint,
	GdkEventButton *, gpointer);
static void plugins_enable_cb(GtkWidget *, gpointer);
static void plugins_disable_cb(GtkWidget *, gpointer);
static void plugins_filter_cb(GtkWidget *, gpointer);
static void filter_ok_cb(GtkWidget *, gpointer);
static void filter_cancel_cb(GtkWidget *, gpointer);

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
    GtkWidget *enable_bn;
    GtkWidget *disable_bn;
    GtkWidget *filter_bn;
    GtkWidget *main_hbnbox;
    GtkWidget *close_bn;
    gchar     *titles[] = {"Name", "Description", "Version", "Enabled"};

    plugins_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(plugins_window), "Ethereal: Plugins");

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

    plugins_clist = gtk_clist_new_with_titles(4, titles);
    gtk_container_add(GTK_CONTAINER(scrolledwindow), plugins_clist);
    gtk_clist_set_selection_mode(GTK_CLIST(plugins_clist), GTK_SELECTION_SINGLE);
    gtk_clist_column_titles_passive(GTK_CLIST(plugins_clist));
    gtk_clist_column_titles_show(GTK_CLIST(plugins_clist));
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_clist), 0, TRUE);
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_clist), 1, TRUE);
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_clist), 2, TRUE);
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_clist), 3, TRUE);
    plugins_scan(plugins_clist);
    gtk_signal_connect(GTK_OBJECT(plugins_clist), "select_row",
	    GTK_SIGNAL_FUNC(plugins_clist_select_cb), NULL);
    gtk_signal_connect(GTK_OBJECT(plugins_clist), "unselect_row",
	    GTK_SIGNAL_FUNC(plugins_clist_unselect_cb), NULL);
    gtk_widget_show(plugins_clist);
    selected_row = -1;

    frame_vbnbox = gtk_vbutton_box_new();
    gtk_box_pack_start(GTK_BOX(frame_hbox), frame_vbnbox, FALSE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(frame_vbnbox), 20);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(frame_vbnbox), GTK_BUTTONBOX_START);
    gtk_widget_show(frame_vbnbox);

    enable_bn = gtk_button_new_with_label("Enable");
    gtk_container_add(GTK_CONTAINER(frame_vbnbox), enable_bn);
    gtk_signal_connect(GTK_OBJECT(enable_bn), "clicked",
	    GTK_SIGNAL_FUNC(plugins_enable_cb), GTK_OBJECT(plugins_clist));
    gtk_widget_show(enable_bn);
    disable_bn = gtk_button_new_with_label("Disable");
    gtk_container_add(GTK_CONTAINER(frame_vbnbox), disable_bn);
    gtk_signal_connect(GTK_OBJECT(disable_bn), "clicked",
	    GTK_SIGNAL_FUNC(plugins_disable_cb), GTK_OBJECT(plugins_clist));
    gtk_widget_show(disable_bn);
    filter_bn = gtk_button_new_with_label("Filter");
    gtk_container_add(GTK_CONTAINER(frame_vbnbox), filter_bn);
    gtk_signal_connect(GTK_OBJECT(filter_bn), "clicked",
	    GTK_SIGNAL_FUNC(plugins_filter_cb), GTK_OBJECT(plugins_clist));
    gtk_widget_show(filter_bn);

    main_hbnbox = gtk_hbutton_box_new();
    gtk_box_pack_start(GTK_BOX(main_vbox), main_hbnbox, FALSE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_hbnbox), 10);
    gtk_widget_show(main_hbnbox);

    close_bn = gtk_button_new_with_label("Close");
    gtk_container_add(GTK_CONTAINER(main_hbnbox), close_bn);
    gtk_widget_show(close_bn);
    gtk_signal_connect(GTK_OBJECT(close_bn), "clicked",
	    GTK_SIGNAL_FUNC(plugins_close_cb), GTK_OBJECT(plugins_window));

    gtk_widget_show(plugins_window);
}

/*
 * scan /usr/share/ethereal/plugins, /usr/local/share/ethereal/plugins and
 * ~/.ethereal/plugins and fill the clist widget
 */
static void
plugins_scan(GtkWidget *clist)
{
    plugin *pt_plug;
    gchar  *plugent[4];               /* new entry added in clist */

    if (plugin_list == NULL)          /* first intialisation */
    {
	plugins_scan_dir(std_plug_dir);
	plugins_scan_dir(local_plug_dir);
	if (!user_plug_dir)
	{
	    user_plug_dir = (gchar *)g_malloc(strlen(getenv("HOME")) + 19);
	    sprintf(user_plug_dir, "%s/.ethereal/plugins", getenv("HOME"));
	}
	plugins_scan_dir(user_plug_dir);
    }

    pt_plug = plugin_list;
    while (pt_plug)
    {
	plugent[0] = pt_plug->name;
	plugent[1] = (gchar *)dlsym(pt_plug->handle, "desc");
	plugent[2] = pt_plug->version;
	plugent[3] = (pt_plug->enabled ? "Yes" : "No");
	gtk_clist_append(GTK_CLIST(clist), plugent);
	pt_plug = pt_plug->next;
    }
}

static void
plugins_scan_dir(const char *dirname)
{
    DIR           *dir;             /* scanned directory */
    struct dirent *file;            /* current file */
    gchar          filename[512];   /* current file name */
    void          *handle;          /* handle returned by dlopen */
    gchar         *name;
    gchar         *version;
    gchar         *protocol;
    gchar         *filter_string;
    dfilter       *filter = NULL;
    void         (*dissector) (const u_char *, int, frame_data *, proto_tree *);
    int            cr;

    if ((dir = opendir(dirname)) != NULL)
    {
	while ((file = readdir(dir)) != NULL)
	{
	    sprintf(filename, "%s/%s", dirname, file->d_name);

	    if ((handle = dlopen(filename, RTLD_LAZY)) == NULL) continue;
	    name = (gchar *)file->d_name;
	    if ((version = (gchar *)dlsym(handle, "version")) == NULL)
	    {
		dlclose(handle);
		continue;
	    }
	    if ((protocol = (gchar *)dlsym(handle, "protocol")) == NULL)
	    {
		dlclose(handle);
		continue;
	    }
	    if ((filter_string = (gchar *)dlsym(handle, "filter_string")) == NULL)
	    {
		dlclose(handle);
		continue;
	    }
	    if (dfilter_compile(filter_string, &filter) != 0) {
		dlclose(handle);
		continue;
	    }
	    if ((dissector = (void (*)(const u_char *, int,
				frame_data *,
				proto_tree *)) dlsym(handle, "dissector")) == NULL)
	    {
		if (filter != NULL)
		    dfilter_destroy(filter);
		dlclose(handle);
		continue;
	    }

	    if ((cr = add_plugin(handle, g_strdup(file->d_name), version,
				 protocol, filter_string, filter, dissector)))
	    {
		if (cr == EEXIST)
		    simple_dialog(ESD_TYPE_WARN, NULL, "The plugin : %s, version %s\n"
			"was found in multiple directories", name, version);
		else
		    simple_dialog(ESD_TYPE_WARN, NULL, "Memory allocation problem");
		if (filter != NULL)
		    dfilter_destroy(filter);
		dlclose(handle);
		continue;
	    }
	}
	closedir(dir);
    }
}

static void
plugins_close_cb(GtkWidget *close_bt, gpointer parent_w)
{
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}

void plugins_clist_select_cb(GtkWidget *clist, gint row, gint column,
	GdkEventButton *event, gpointer data)
{
    selected_row = row;
    gtk_clist_get_text(GTK_CLIST(clist), selected_row, 0, &selected_name);
    gtk_clist_get_text(GTK_CLIST(clist), selected_row, 2, &selected_version);
    gtk_clist_get_text(GTK_CLIST(clist), selected_row, 3, &selected_enabled);
}

void plugins_clist_unselect_cb(GtkWidget *clist, gint row, gint column,
	GdkEventButton *event, gpointer data)
{
    selected_row = -1;
}

static void
plugins_enable_cb(GtkWidget *button, gpointer clist)
{
    plugin    *pt_plug;
    void     (*proto_init) ();

    /* nothing selected */
    if (selected_row == -1) return;
    /* already enabled */
    if (!strcmp(selected_enabled, "Yes")) return;

    if ((pt_plug = enable_plugin(selected_name, selected_version)) == NULL)
    {
	simple_dialog(ESD_TYPE_WARN, NULL, "Plugin not found");
	return;
    }
    proto_init = (void (*)())dlsym(pt_plug->handle, "proto_init");
    if (proto_init)
	proto_init();

    gtk_clist_set_text(GTK_CLIST(clist), selected_row, 3, "Yes");
}

static void
plugins_disable_cb(GtkWidget *button, gpointer clist)
{
    plugin    *pt_plug;

    /* nothing selected */
    if (selected_row == -1) return;
    /* already disabled */
    if (!strcmp(selected_enabled, "No")) return;

    if ((pt_plug = disable_plugin(selected_name, selected_version)) == NULL)
    {
	simple_dialog(ESD_TYPE_WARN, NULL, "Plugin not found");
	return;
    }
    gtk_clist_set_text(GTK_CLIST(clist), selected_row, 3, "No");
}

static void
plugins_filter_cb(GtkWidget *button, gpointer clist)
{
    GtkWidget *filter_window;
    GtkWidget *filter_vbox;
    GtkWidget *filter_frame;
    GtkWidget *filter_entry;
    GtkWidget *filter_hbnbox;
    GtkWidget *ok_bn;
    GtkWidget *cancel_bn;
    plugin    *pt_plug;

    if (selected_row == -1) return;
    pt_plug = find_plugin(selected_name, selected_version);

    filter_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(filter_window), "Ethereal: Plugin Filter");
    gtk_window_set_modal(GTK_WINDOW(filter_window), TRUE);

    filter_vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(filter_window), filter_vbox);
    gtk_widget_show(filter_vbox);

    filter_frame = gtk_frame_new("Plugin Filter");
    gtk_box_pack_start(GTK_BOX(filter_vbox), filter_frame, TRUE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(filter_frame), 10);
    gtk_widget_show(filter_frame);

    filter_entry = gtk_entry_new();
    gtk_object_set_data(GTK_OBJECT(filter_window), PLUGINS_DFILTER_TE,
	                filter_entry);
    gtk_container_add(GTK_CONTAINER(filter_frame), filter_entry);
    gtk_entry_set_text(GTK_ENTRY(filter_entry), pt_plug->filter_string);
    if (!strcmp(selected_enabled, "Yes"))
	gtk_entry_set_editable(GTK_ENTRY(filter_entry), TRUE);
    else
	gtk_entry_set_editable(GTK_ENTRY(filter_entry), FALSE);
    gtk_widget_show(filter_entry);

    filter_hbnbox = gtk_hbutton_box_new();
    gtk_box_pack_start(GTK_BOX(filter_vbox), filter_hbnbox, FALSE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(filter_hbnbox), 10);
    gtk_widget_show(filter_hbnbox);

    ok_bn = gtk_button_new_with_label("Ok");
    gtk_container_add(GTK_CONTAINER(filter_hbnbox), ok_bn);
    gtk_widget_show(ok_bn);
    gtk_signal_connect(GTK_OBJECT(ok_bn), "clicked",
	    GTK_SIGNAL_FUNC(filter_ok_cb), GTK_OBJECT(filter_window));

    cancel_bn = gtk_button_new_with_label("Cancel");
    gtk_container_add(GTK_CONTAINER(filter_hbnbox), cancel_bn);
    gtk_widget_show(cancel_bn);
    gtk_signal_connect(GTK_OBJECT(cancel_bn), "clicked",
	    GTK_SIGNAL_FUNC(filter_cancel_cb), GTK_OBJECT(filter_window));

    gtk_widget_show(filter_window);
}

static void
filter_ok_cb(GtkWidget *close_bt, gpointer parent_w)
{
    GtkWidget *filter_entry;
    gchar     *filter_string;
    dfilter   *filter = NULL;

    if (!strcmp(selected_enabled, "Yes"))
    {
	filter_entry = gtk_object_get_data(GTK_OBJECT(parent_w), PLUGINS_DFILTER_TE);
	filter_string = gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if (dfilter_compile(filter_string, &filter) != 0)
	{
	    simple_dialog(ESD_TYPE_WARN, NULL, dfilter_error_msg);
	}
	else
	    plugin_replace_filter(selected_name, selected_version,
		                  filter_string, filter);
    }
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
filter_cancel_cb(GtkWidget *close_bt, gpointer parent_w)
{
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}
#endif
