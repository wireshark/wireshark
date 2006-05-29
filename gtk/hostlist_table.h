/* hostlist_table.h   2004 Ian Schorr
 * modified from endpoint_talkers_table   2003 Ronnie Sahlberg
 * Helper routines common to all host talkers taps.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "sat.h"

/** @file
 *  Hostlist definitions.
 */

/** Hostlist information */
typedef struct _hostlist_talker_t {
	address address;        /**< address */
	SAT_E   sat;            /**< address type */
	guint32 port_type;      /**< port_type (e.g. PT_TCP) */
	guint32 port;           /**< port */

	guint64 rx_frames;      /**< number of received packets */
	guint64 tx_frames;      /**< number of transmitted packets */
	guint64 rx_bytes;       /**< number of received bytes */
	guint64 tx_bytes;       /**< number of transmitted bytes */
} hostlist_talker_t;

/** Hostlist widget */
typedef struct _hostlist_table {
	const char          *name;              /**< the name of the table */
	GtkWidget           *win;               /**< GTK window */
	GtkWidget           *page_lb;           /**< label */
	GtkWidget           *scrolled_window;   /**< the scrolled window */
	GtkCList            *table;             /**< the GTK table */
	guint32             num_columns;        /**< number of columns in the above table */
	const char          *default_titles[8]; /**< Column headers */
	GtkWidget           *menu;              /**< context menu */
	gboolean            has_ports;          /**< table has ports */
	guint32             num_hosts;          /**< number of hosts (0 or 1) */
	hostlist_talker_t   *hosts;             /**< array of host values */
	gboolean            resolve_names;      /**< resolve address names? */
} hostlist_table;

/** Register the hostlist table for the multiple hostlist window.
 *
 * @param hide_ports hide the port columns
 * @param table_name the table name to be displayed
 * @param tap_name the registered tap name
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void register_hostlist_table(gboolean hide_ports, char *table_name, char *tap_name, char *filter, tap_packet_cb packet_func);

/** Init the hostlist table for the single hostlist window.
 *
 * @param hide_ports hide the port columns
 * @param table_name the table name to be displayed
 * @param tap_name the registered tap name
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void init_hostlist_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func);

/** Callback for "Endpoints" statistics item.
 *
 * @param w unused
 * @param d unused
 */
extern void init_hostlist_notebook_cb(GtkWidget *w, gpointer d);

/** Add some data to the table.
 *
 * @param hl the table to add the data to
 * @param addr address
 * @param port port
 * @param sender TRUE, if this is a sender
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param sat address type
 * @param port_type the port type (e.g. PT_TCP)
 */
void add_hostlist_table_data(hostlist_table *hl, const address *addr,
                             guint32 port, gboolean sender, int num_frames, int num_bytes, SAT_E sat, int port_type);
