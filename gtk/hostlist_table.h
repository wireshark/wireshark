/* hostlist_table.h   2004 Ian Schorr
 * modified from endpoint_talkers_table   2003 Ronnie Sahlberg
 * Helper routines common to all host talkers taps.
 *
 * $Id: hostlist_table.h,v 1.2 2004/05/02 21:16:08 ulfl Exp $
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

typedef struct _hostlist_talker_t {
	address src_address;
	guint32 sat;
	guint32 port_type;
	guint32 src_port;

	guint32 rx_frames;
	guint32 tx_frames;
	guint32 rx_bytes;
	guint32 tx_bytes;
} hostlist_talker_t;

typedef struct _hostlist_table {
	char *name;
	GtkWidget *win;
	GtkWidget *page_lb;
	GtkWidget *scrolled_window;
	GtkCList *table;
	GtkItemFactory *item_factory;
	GtkWidget *menu;
	gboolean has_ports;
	guint32 num_hosts;
	hostlist_talker_t *hosts;
} hostlist_table;

extern void register_hostlist_table(gboolean hide_ports, char *table_name, char *tap_name, char *filter, void *packet_func);

extern void init_hostlist_table(gboolean hide_ports, char *table_name, char *tap_name, char *filter, void *packet_func);

#define SAT_NONE		0
#define SAT_ETHER		1
#define SAT_FDDI		2
#define SAT_TOKENRING	3


void add_hostlist_table_data(hostlist_table *hl, address *src, guint32 src_port, gboolean sender, int num_frames, int num_bytes, int sat, int port_type);
