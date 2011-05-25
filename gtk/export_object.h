/* export_object.h
 * Common routines for tracking & saving objects found in streams of data
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
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
typedef struct _export_object_list_t {
	GSList *entries;
	GtkWidget *tree, *dlg;
	GtkTreeView *tree_view;
	GtkTreeIter *iter;
	GtkTreeStore *store;
	gint row_selected;
} export_object_list_t;

typedef struct _export_object_entry_t {
	guint32 pkt_num;
	gchar *hostname;
	gchar *content_type;
	gchar *filename;
        /* We need to store a 64 bit integer to hold a file length
           (was guint payload_len;) */
        gint64 payload_len;
	guint8 *payload_data;
} export_object_entry_t;

/* When a protocol needs intermediate data structures to construct the
export objects, then it must specifiy a function that cleans up all 
those data structures. This function is passed to export_object_window
and called when tap reset or windows closes occurs. If no function is needed
a NULL value should be passed instead */
typedef void (*eo_protocoldata_reset_cb)(void);


void export_object_window(const gchar *tapname, const gchar *name,
			  tap_packet_cb tap_packet,
			  eo_protocoldata_reset_cb eo_protocoldata_resetfn);

/* Protocol specific */
void eo_http_cb(GtkWidget *widget _U_, gpointer data _U_);
void eo_dicom_cb(GtkWidget *widget _U_, gpointer data _U_);
void eo_smb_cb(GtkWidget *widget _U_, gpointer data _U_);

#endif /* __EXPORT_OBJECT_H__ */
