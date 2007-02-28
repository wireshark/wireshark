/* export_object_http.c
 * Routines for tracking & saving objects found in HTTP streams
 * See also: export_object.c / export_object.h for common code
 * Copyright 2007, Stephen Fisher <stephentfisher@yahoo.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <gtk/gtk.h>

/* This feature has not been ported to GTK1 */
#if GTK_MAJOR_VERSION >= 2

#include "export_object.h"

#include <epan/dissectors/packet-http.h>
#include <epan/emem.h>
#include <epan/epan.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <file.h>
#include <globals.h>
#include <simple_dialog.h>
#include <stat_menu.h>
#include <gtk/compat_macros.h>
#include <gtk/dlg_utils.h>
#include <gtk/file_dlg.h>
#include <gtk/gui_utils.h>
#include <gtk/gui_stat_menu.h>

static void
eo_http_reset(void *tapdata)
{
	export_object_list_t *object_list = tapdata;

	if(object_list->entries) {
		g_slist_free(object_list->entries);
		object_list->entries = NULL;
	}

	object_list->iter = NULL;
	object_list->row_selected = -1;
}

static int
eo_http_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
	       const void *data)
{
	export_object_list_t *object_list = tapdata;
	const http_info_value_t *stat_info = data;
	export_object_entry_t *entry;

	if(stat_info->content_type &&
	   g_ascii_strncasecmp(stat_info->content_type, "<NULL>", 6) != 0) {
		entry = g_malloc(sizeof(export_object_entry_t));

		entry->pkt_num = pinfo->fd->num;
		entry->hostname = g_strdup(stat_info->http_host);
		entry->content_type = g_strdup(stat_info->content_type);

		if(stat_info->request_uri)
			entry->filename =
				g_path_get_basename(stat_info->request_uri);
		else
			entry->filename = NULL;

		entry->payload_len = stat_info->payload_len;
		entry->payload_data = g_memdup(stat_info->payload_data,
					       stat_info->payload_len);

		object_list->entries =
			g_slist_append(object_list->entries, entry);
		return 1;
	} else {
		return 0;
	}
}

static void
eo_http_draw(void *tapdata)
{
	export_object_list_t *object_list = tapdata;
	export_object_entry_t *eo_entry;

	GSList *slist_entry = NULL;
	GSList *last_slist_entry = NULL;
	gint last_slist_entry_num;
	GtkTreeIter new_iter;
	gchar *column_text[EO_NUM_COLUMNS];

	last_slist_entry = g_slist_last(object_list->entries);
	last_slist_entry_num = g_slist_position(object_list->entries,
						last_slist_entry);

	while(object_list->slist_pos <= last_slist_entry_num &&
	      last_slist_entry_num != -1) {
		slist_entry = g_slist_nth(object_list->entries,
					  object_list->slist_pos);
		eo_entry = slist_entry->data;
		
		column_text[0] = g_strdup_printf("%u", eo_entry->pkt_num);
		column_text[1] = g_strdup_printf("%s", eo_entry->hostname);
		column_text[2] = g_strdup_printf("%s", eo_entry->content_type);
		column_text[3] = g_strdup_printf("%u", eo_entry->payload_len);
		column_text[4] = g_strdup_printf("%s", eo_entry->filename);

		gtk_tree_store_append(object_list->store, &new_iter,
				      object_list->iter);

		gtk_tree_store_set(object_list->store, &new_iter,
				   EO_PKT_NUM_COLUMN, column_text[0],
				   EO_HOSTNAME_COLUMN, column_text[1],
				   EO_CONTENT_TYPE_COLUMN, column_text[2],
				   EO_BYTES_COLUMN, column_text[3],
				   EO_FILENAME_COLUMN, column_text[4],
				   -1);

		g_free(column_text[0]);
		g_free(column_text[1]);
		g_free(column_text[2]);
		g_free(column_text[3]);
		g_free(column_text[4]);

		object_list->slist_pos++;
	}
}

void
eo_http_cb(GtkWidget *widget _U_, gpointer data _U_)
{
	GString *error_msg;
	GtkWidget *sw;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkTreeSelection *selection;
	GtkWidget *vbox, *bbox, *close_bt, *save_bt, *save_all_bt;
	GtkTooltips *button_bar_tips;

	export_object_list_t *object_list = g_malloc0(sizeof(export_object_list_t));

	button_bar_tips = gtk_tooltips_new();

	/* Data will be gathered via a tap callback */
	error_msg = register_tap_listener("http", object_list, NULL,
					  eo_http_reset,
					  eo_http_packet,
					  eo_http_draw);

	if (error_msg) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Can't register http tap: %s\n", error_msg->str);
		g_string_free(error_msg, TRUE);
		return;
	}

	object_list->dlg = dlg_window_new("Wireshark: HTTP Content List");

	gtk_window_set_default_size(GTK_WINDOW(object_list->dlg),
				    DEF_WIDTH, DEF_HEIGHT);

	vbox = gtk_vbox_new(FALSE, 5);

        gtk_container_border_width(GTK_CONTAINER(vbox), 5);
        gtk_container_add(GTK_CONTAINER(object_list->dlg), vbox);

	sw = scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw),
					    GTK_SHADOW_IN);

	gtk_container_add(GTK_CONTAINER(vbox), sw);

	object_list->store = gtk_tree_store_new(EO_NUM_COLUMNS,
						 G_TYPE_STRING, G_TYPE_STRING,
						 G_TYPE_STRING, G_TYPE_STRING,
						 G_TYPE_STRING);

	object_list->tree = tree_view_new(GTK_TREE_MODEL(object_list->store));

	object_list->tree_view = GTK_TREE_VIEW(object_list->tree);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Packet num",
							  renderer,
							  "text",
							  EO_PKT_NUM_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(object_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Hostname",
							  renderer,
							  "text",
							  EO_HOSTNAME_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(object_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Content Type",
							  renderer,
							  "text",
							  EO_CONTENT_TYPE_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(object_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Bytes",
							  renderer,
							  "text",
							  EO_BYTES_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(object_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Filename",
							  renderer,
							  "text",
							  EO_FILENAME_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(object_list->tree_view, column);

	gtk_container_add(GTK_CONTAINER(sw), object_list->tree);

	selection = gtk_tree_view_get_selection(object_list->tree_view);
        SIGNAL_CONNECT(selection, "changed", eo_remember_row_num, object_list);

	bbox = gtk_hbox_new(FALSE, 5);

	/* Save All button */
	save_all_bt = gtk_button_new_with_mnemonic("Save _All");
	SIGNAL_CONNECT(save_all_bt, "clicked", eo_save_all_clicked_cb,
		       object_list);
	gtk_tooltips_set_tip(GTK_TOOLTIPS(button_bar_tips), save_all_bt,
			     "Save all displayed objects with their displayed "
			     "filenames.", NULL);
	gtk_box_pack_end(GTK_BOX(bbox), save_all_bt, FALSE, FALSE, 0);

	/* Save button */
	save_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_SAVE);
	SIGNAL_CONNECT(save_bt, "clicked", eo_save_clicked_cb, object_list);
	gtk_tooltips_set_tip(GTK_TOOLTIPS(button_bar_tips), save_bt,
			     "Saves the currently selected content to a file.",
			     NULL);
	gtk_box_pack_end(GTK_BOX(bbox), save_bt, FALSE, FALSE, 0);

	/* Close button */
        close_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
       	window_set_cancel_button(object_list->dlg, close_bt,
				 window_cancel_button_cb);
	gtk_tooltips_set_tip(GTK_TOOLTIPS(button_bar_tips), close_bt,
			     "Close this dialog.", NULL);
	gtk_box_pack_end(GTK_BOX(bbox), close_bt, FALSE, FALSE, 0);

	/* Pack the buttons into the "button box" */
        gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
        gtk_widget_show(bbox);

	/* Setup delete/destroy signal handlers */
        SIGNAL_CONNECT(object_list->dlg, "delete_event",
		       window_delete_event_cb, NULL);
	SIGNAL_CONNECT(object_list->dlg, "destroy",
		       eo_win_destroy_cb, NULL);

	/* Show the window */
	gtk_widget_show_all(object_list->dlg);
	window_present(object_list->dlg);

	cf_retap_packets(&cfile, FALSE);
}
#endif /* GTK_MAJOR_VERSION >= 2 */
