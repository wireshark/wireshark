/* packet_list_store.h
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

/* Uncomment to track some statistics (const strings, etc.) */
/* #define PACKET_LIST_STATISTICS */

#ifndef __PACKET_LIST_STORE_H__
#define __PACKET_LIST_STORE_H__

#include <glib.h>

#include "epan/column-info.h"
#include "epan/frame_data.h"

/** @file
 *  The packet list store
 *  @ingroup main_window_group
 */
extern GType packet_list_get_type(void);
#define PACKETLIST_TYPE_LIST (packet_list_get_type())
#define PACKET_LIST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), PACKETLIST_TYPE_LIST, PacketList))
#define PACKETLIST_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_CART((klass), PACKETLIST_TYPE_LIST))
#define PACKETLIST_IS_LIST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), PACKETLIST_TYPE_LIST))
#define PACKETLIST_IS_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE(klass), PACKETLIST_TYPE_LIST)
#define PACKETLIST_LIST_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), PACKETLIST_TYPE_LIST, PacketListClass))

typedef struct _PacketList PacketList;
typedef struct _PacketListClass PacketListClass;

#define PACKET_LIST_RECORD_GET(rows, pos) ((PacketListRecord*) g_ptr_array_index((rows), (pos)))
#define PACKET_LIST_RECORD_SET(rows, pos, item) g_ptr_array_index((rows), (pos)) = (item)
#define PACKET_LIST_RECORD_APPEND(rows, item) g_ptr_array_add((rows), (item))
#define PACKET_LIST_RECORD_COUNT(rows) ((rows) ? (rows)->len : 0)
#define PACKET_LIST_RECORD_INDEX_VALID(rows, idx) ((rows) ? (((guint) (idx)) < (rows)->len) : FALSE)

/** PacketList: Everything for our model implementation. */
struct _PacketList
{
	GObject parent; /** MUST be first */

	/** Array of pointers to the PacketListRecord structure for each visible row. */
	GPtrArray *visible_rows;
	/** Array of pointers to the PacketListRecord structure for each row. */
	GPtrArray *physical_rows;

	/** Has the entire file been columnized? */
	gboolean columnized;

	gint n_cols;		/* copy of cfile.cinfo.num_cols */
	gint n_text_cols;	/* number of cols not based on frame, which we need to store text */
	gint *col_to_text;	/* mapping from column number to col_text index, when -1 column is based on frame_data */
	GtkWidget *view;

	gint sort_id;
	GtkSortType sort_order;

	GStringChunk *string_pool;

	/** Random integer to check whether an iter belongs to our model. */
	gint stamp;

#ifdef PACKET_LIST_STATISTICS
	/** Statistics */
	guint const_strings;
#endif
};

/** PacketListClass: more boilerplate GObject stuff */
struct _PacketListClass
{
	GObjectClass parent_class;
};

GType packet_list_list_get_type(void);
PacketList *packet_list_new(void);
void packet_list_store_clear(PacketList *packet_list);
guint packet_list_recreate_visible_rows_list(PacketList *packet_list);
gint packet_list_append_record(PacketList *packet_list, frame_data *fdata);
gboolean packet_list_do_packet_list_dissect_and_cache_all(PacketList *packet_list, gint sort_col_id);
void packet_list_reset_colorized(PacketList *packet_list);
const char* packet_list_get_widest_column_string(PacketList *packet_list, gint col);

#endif /* __PACKET_LIST_STORE_H__ */
