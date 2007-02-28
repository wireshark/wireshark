/* export_object.h
 * Declarations of routines for tracking & saving content found in HTTP streams
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

#ifndef __EXPORT_OBJECT_H__
#define __EXPORT_OBJECT_H__

/* Common between protocols */
enum {
	EO_PKT_NUM_COLUMN,
	EO_HOSTNAME_COLUMN,
	EO_CONTENT_TYPE_COLUMN,
	EO_BYTES_COLUMN,
	EO_FILENAME_COLUMN,
	EO_NUM_COLUMNS /* must be last */
};

typedef struct _export_object_list_t {
	GSList *entries;
	GtkWidget *tree, *dlg;
	GtkTreeView *tree_view;
	GtkTreeIter *iter;
	GtkTreeStore *store;
	gint slist_pos, row_selected;
} export_object_list_t;

typedef struct _export_object_entry_t {
	guint32 pkt_num;
	gchar *hostname;
	gchar *content_type;
	gchar *filename;
	guint payload_len;
	guint8 *payload_data;
} export_object_entry_t;

void eo_remember_row_num(GtkTreeSelection *sel, gpointer data);
void eo_win_destroy_cb(GtkWindow *win _U_, gpointer data);
void eo_save_entry_cb(GtkWidget *widget, export_object_entry_t *entry);
void eo_save_clicked_cb(GtkWidget *widget _U_, gpointer arg);
void eo_save_all_clicked_cb(GtkWidget *widget _U_, gpointer arg);

/* Protocol specific */
void eo_http_cb(GtkWidget *widget _U_, gpointer data _U_);

#endif /* __EXPORT_OBJECT_H__ */
