/* export_object.c
 * Common routines for tracking & saving objects found in streams of data
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

#include <alert_box.h>
#include <simple_dialog.h>

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <gtk/file_dlg.h>
#include <gtk/gui_utils.h>
#include <gtk/main.h>
#include <wiretap/file_util.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static void
eo_remember_this_row(GtkTreeModel *model _U_, GtkTreePath *path,
		     GtkTreeIter *iter _U_, gpointer arg)
{
	export_object_list_t *object_list = arg;
	export_object_entry_t *entry;

	gint *path_index;

	if((path_index = gtk_tree_path_get_indices(path)) == NULL)
		return;

	object_list->row_selected = path_index[0];

	entry = g_slist_nth_data(object_list->entries,
				 object_list->row_selected);
       
	cf_goto_frame(&cfile, entry->pkt_num);
}

void
eo_remember_row_num(GtkTreeSelection *sel, gpointer data)
{
	gtk_tree_selection_selected_foreach(sel, eo_remember_this_row, data);
}


void
eo_win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
        export_object_list_t *object_list = data;

        protect_thread_critical_region();
        remove_tap_listener(object_list);
        unprotect_thread_critical_region();

	g_free(object_list);
}

void
eo_save_entry(gchar *save_as_filename, export_object_entry_t *entry)
{
	int to_fd;

	to_fd = eth_open(save_as_filename, O_WRONLY | O_CREAT | O_TRUNC |
			 O_BINARY, 0644);
	if(to_fd == -1) {
		open_failure_alert_box(save_as_filename, errno, TRUE);
		g_free(save_as_filename);
		return;
	}

	if(eth_write(to_fd, entry->payload_data, entry->payload_len) < 0) {
		write_failure_alert_box(save_as_filename, errno);
		eth_close(to_fd);
		g_free(save_as_filename);
		return;
	}

	if (eth_close(to_fd) < 0) {
		write_failure_alert_box(save_as_filename, errno);
		g_free(save_as_filename);
		return;
	}

	g_free(save_as_filename);
}


void
eo_save_clicked_cb(GtkWidget *widget _U_, gpointer arg)
{
	GtkWidget *save_as_w;
	export_object_list_t *object_list = arg;
	export_object_entry_t *entry = NULL;

	entry = g_slist_nth_data(object_list->entries,
				 object_list->row_selected);

	if(!entry) {
		simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "No object was selected for saving.  Please click on an object and click on save again.");
		return;
	}

	save_as_w = file_selection_new("Wireshark: Save Object As ...",
				       FILE_SELECTION_SAVE);

	gtk_window_set_transient_for(GTK_WINDOW(save_as_w),
				     GTK_WINDOW(object_list->dlg));

	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(save_as_w),
					  entry->filename);

	if(gtk_dialog_run(GTK_DIALOG(save_as_w)) == GTK_RESPONSE_ACCEPT)
		eo_save_entry(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(save_as_w)), entry);

	window_destroy(save_as_w);
}

void
eo_save_all_clicked_cb(GtkWidget *widget _U_, gpointer arg)
{
	gchar *save_as_fullpath = NULL;
	export_object_list_t *object_list = arg;
	export_object_entry_t *entry;
	GtkWidget *save_in_w;
	GSList *last_slist_entry;
	gint last_slist_entry_num, i;

	save_in_w = file_selection_new("Wireshark: Save All Objects In ...",
				       FILE_SELECTION_CREATE_FOLDER);

	gtk_window_set_transient_for(GTK_WINDOW(save_in_w),
				     GTK_WINDOW(object_list->dlg));

	if(gtk_dialog_run(GTK_DIALOG(save_in_w)) == GTK_RESPONSE_ACCEPT) {

		/* Find the last entry in the SList, then start at the beginning
		   saving each one. */
		last_slist_entry = g_slist_last(object_list->entries);
		last_slist_entry_num = g_slist_position(object_list->entries,
							last_slist_entry);

		for(i = 0; i <= last_slist_entry_num; i++) {
			
			entry = g_slist_nth_data(object_list->entries, i);

			save_as_fullpath = g_strdup_printf("%s%c%s", gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(save_in_w)), G_DIR_SEPARATOR, entry->filename);
			
			eo_save_entry(save_as_fullpath, entry);

		}

	}

	window_destroy(save_in_w);
}

#endif /* GTK_MAJOR_VERSION >= 2 */
