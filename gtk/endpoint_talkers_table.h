/* endpoint_talkers_table.h
 * endpoint_talkers_table   2003 Ronnie Sahlberg
 * Helper routines common to all endpoint talkers taps.
 *
 * $Id: endpoint_talkers_table.h,v 1.2 2003/08/26 01:46:23 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <gtk/gtk.h>

typedef struct _endpoint_talker_t {
	address src_address;
	address dst_address;
	guint32 src_port;
	guint32 dst_port;

	guint32 rx_frames;
	guint32 tx_frames;
	guint32 rx_bytes;
	guint32 tx_bytes;
} endpoint_talker_t;

typedef struct _endpoints_table {
	GtkWidget *scrolled_window;
	GtkCList *table;
	gboolean has_ports;
	guint32 num_endpoints;
	endpoint_talker_t *endpoints;
	char *(*port_to_str)(guint32);
} endpoints_table;

void reset_ett_table_data(endpoints_table *et);

void init_ett_table(endpoints_table *et, GtkWidget *vbox, char *(*port_to_str)(guint32));

void add_ett_table_data(endpoints_table *et, address *src, address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes);

void draw_ett_table_data(endpoints_table *et);

