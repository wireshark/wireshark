/* plugins_dlg.c
 * Dialog boxes for plugins
 *
 * $Id: plugins_dlg.c,v 1.17 2000/08/21 20:11:51 deniel Exp $
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

#include "globals.h"
#include "plugins.h"
#include "keys.h"
#include "dlg_utils.h"
#include "prefs_dlg.h"
#include "simple_dialog.h"

#ifdef PLUGINS_NEED_ADDRESS_TABLE
#include "plugins/plugin_api.h"
extern plugin_address_table_t	patable;
#endif

#ifdef HAVE_PLUGINS

static gint selected_row;
static gchar *selected_name;
static gchar *selected_version;
static gchar *selected_enabled;

static void plugins_close_cb(GtkWidget *, gpointer);
static void plugins_save_cb(GtkWidget *, gpointer);
static void plugins_scan(GtkWidget *);
static void plugins_clist_select_cb(GtkWidget *, gint, gint,
	GdkEventButton *, gpointer);
static void plugins_clist_unselect_cb(GtkWidget *, gint, gint,
	GdkEventButton *, gpointer);
static void plugins_enable_cb(GtkWidget *, gpointer);
static void plugins_disable_cb(GtkWidget *, gpointer);
static void plugins_filter_cb(GtkWidget *, gpointer);
static void filter_ok_cb(GtkWidget *, gpointer);
static void filter_cancel_cb(GtkWidget *, gpointer);
static void filter_default_cb(GtkWidget *, gpointer);

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
    GtkWidget *save_bn;
    gchar     *titles[] = {"Name", "Description", "Version", "Enabled"};

    plugins_window = dlg_window_new();
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
    gtk_button_box_set_layout(GTK_BUTTON_BOX(frame_vbnbox), GTK_BUTTONBOX_SPREAD);
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
    gtk_button_box_set_layout(GTK_BUTTON_BOX(main_hbnbox), GTK_BUTTONBOX_SPREAD);
    gtk_widget_show(main_hbnbox);

    save_bn = gtk_button_new_with_label("Save status");
    gtk_container_add(GTK_CONTAINER(main_hbnbox), save_bn);
    gtk_widget_show(save_bn);
    gtk_signal_connect(GTK_OBJECT(save_bn), "clicked",
	    GTK_SIGNAL_FUNC(plugins_save_cb), GTK_OBJECT(plugins_window));

    close_bn = gtk_button_new_with_label("Close");
    gtk_container_add(GTK_CONTAINER(main_hbnbox), close_bn);
    gtk_widget_show(close_bn);
    gtk_signal_connect(GTK_OBJECT(close_bn), "clicked",
	    GTK_SIGNAL_FUNC(plugins_close_cb), GTK_OBJECT(plugins_window));

    gtk_widget_show(plugins_window);

}

/*
 * Scan
 *
 *	/usr/lib/ethereal/plugins/0.8
 *
 *	/usr/local/lib/ethereal/plugins/0.8
 *
 *	PLUGIN_DIR, if it's different from both of the above
 *
 *	~/.ethereal/plugins
 *
 * and fill the clist widget.
 */
static void
plugins_scan(GtkWidget *clist)
{
    plugin   *pt_plug;
    gchar    *plugent[4];               /* new entry added in clist */
    gpointer symbol;

    pt_plug = plugin_list;
    while (pt_plug)
    {
	plugent[0] = pt_plug->name;

	/* Get, from the string named "desc" in the module, the
	   description of the plugin. */
	if (g_module_symbol(pt_plug->handle, "desc", &symbol) == FALSE) {
		/* This plugin fails; continue next plugin */
		goto NEXT_PLUGIN;
	}

	plugent[1] = symbol;
	plugent[2] = pt_plug->version;
	plugent[3] = (pt_plug->enabled ? "Yes" : "No");
	gtk_clist_append(GTK_CLIST(clist), plugent);
   NEXT_PLUGIN:
	pt_plug = pt_plug->next;
    }
}

static void
plugins_close_cb(GtkWidget *close_bt, gpointer parent_w)
{
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
plugins_save_cb(GtkWidget *close_bt, gpointer parent_w)
{
    if (save_plugin_status())
	simple_dialog(ESD_TYPE_WARN, NULL, "Can't open ~/.ethereal/plugins.status\n"
		                           "for writing");
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
    gpointer symbol;
    void     (*plugin_init)(void*);

    /* nothing selected */
    if (selected_row == -1) return;
    /* already enabled */
    if (strcmp(selected_enabled, "Yes") == 0) return;

    if ((pt_plug = enable_plugin(selected_name, selected_version)) == NULL)
    {
	simple_dialog(ESD_TYPE_CRIT, NULL, "Plugin not found");
	return;
    }

    /* Try to get the initialization routine for the plugin, and, if it
       has one, call it. */
    if (g_module_symbol(pt_plug->handle, "plugin_init", &symbol) == TRUE) {
	plugin_init = symbol;
#ifdef PLUGINS_NEED_ADDRESS_TABLE
		    plugin_init(&patable);
#else
		    plugin_init(NULL);
#endif
	}
#ifdef PLUGINS_NEED_ADDRESS_TABLE
	else {
		simple_dialog(ESD_TYPE_WARN, NULL, "Failed to find plugin_init()");
		return;
	}
#endif


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
	simple_dialog(ESD_TYPE_CRIT, NULL, "Plugin not found");
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
    GtkWidget *default_bn;
    plugin    *pt_plug;

    if (selected_row == -1) return;
    pt_plug = find_plugin(selected_name, selected_version);

    filter_window = dlg_window_new();
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

    default_bn = gtk_button_new_with_label("Default");
    gtk_container_add(GTK_CONTAINER(filter_hbnbox), default_bn);
    gtk_widget_show(default_bn);
    gtk_signal_connect(GTK_OBJECT(default_bn), "clicked",
	    GTK_SIGNAL_FUNC(filter_default_cb), GTK_OBJECT(filter_window));

    gtk_widget_show(filter_window);
}

static void
filter_ok_cb(GtkWidget *button, gpointer parent_w)
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
	    simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
	}
	else
	    plugin_replace_filter(selected_name, selected_version,
		                  filter_string, filter);
    }
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
filter_cancel_cb(GtkWidget *button, gpointer parent_w)
{
    gtk_grab_remove(GTK_WIDGET(parent_w));
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
filter_default_cb(GtkWidget *button, gpointer parent_w)
{
    GtkWidget *filter_entry;
    gpointer   symbol;
    gchar     *filter_string;
    plugin    *pt_plug;

    filter_entry = gtk_object_get_data(GTK_OBJECT(parent_w), PLUGINS_DFILTER_TE);
    pt_plug = find_plugin(selected_name, selected_version);

    /* Get the display-filter string that specifies which packets should
       be dissected by this module's dissector. */
    g_module_symbol(pt_plug->handle, "filter_string", &symbol);
    filter_string = symbol;
    gtk_entry_set_text(GTK_ENTRY(filter_entry), filter_string);
}
#endif
