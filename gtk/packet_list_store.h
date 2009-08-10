/* packet_list_store.h
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

#ifndef __NEW_PACKET_LIST_H__
#define __NEW_PACKET_LIST_H__

#ifdef NEW_PACKET_LIST

#include "epan/column_info.h"
#include "epan/frame_data.h"

#define PACKETLIST_TYPE_LIST (packet_list_get_type())
#define PACKET_LIST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), PACKETLIST_TYPE_LIST, PacketList))
#define PACKETLIST_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_CART((klass), PACKETLIST_TYPE_LIST))
#define PACKETLIST_IS_LIST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), PACKETLIST_TYPE_LIST))
#define PACKETLIST_IS_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE(klass), PACKETLIST_TYPE_LIST)
#define PACKETLIST_LIST_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), PACKETLIST_TYPE_LIST, PacketListClass))

typedef struct {
	gchar **col_text;
	frame_data *fdata;
} row_data_t;

typedef struct _PacketListRecord PacketListRecord;
typedef struct _PacketList PacketList;
typedef struct _PacketListClass PacketListClass;

/* PacketListRecord: represents a row */
struct _PacketListRecord
{
	gboolean dissected;
	frame_data *fdata;
	gchar **col_text;

	/* admin stuff used by the custom list model */
	guint pos; /* position within the array */
};

/* PacketListRecord: Everything for our model implementation. */
struct _PacketList
{
	GObject parent; /* MUST be first */

	guint num_rows;
	PacketListRecord **rows; /* Dynamically allocated array of pointers to
				  * the PacketListRecord structure for each
				  * row. */

	gint n_columns;
	GType column_types[NUM_COL_FMTS];
	GtkWidget *view; /* XXX - Does this really belong here?? */

	gint sort_id;
	GtkSortType sort_order;

	gint stamp; /* Random integer to check whether an iter belongs to our
		     * model. */
};


/* PacketListClass: more boilerplate GObject stuff */
struct _PacketListClass
{
	GObjectClass parent_class;
};

GType packet_list_list_get_type(void);
PacketList *new_packet_list_new(void);
void new_packet_list_store_clear(PacketList *packet_list);
void packet_list_append_record(PacketList *packet_list, row_data_t *row_data);
void packet_list_change_record(PacketList *packet_list, guint row, gint col, column_info *cinfo);

#endif /* NEW_PACKET_LIST */

#endif /* __NEW_PACKET_LIST_H__ */
