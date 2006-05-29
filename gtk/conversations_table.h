/* conversations_table.h
 * conversations_table   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
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
#ifndef __CONVERSATIONS_TABLE_H__
#define __CONVERSATIONS_TABLE_H__
#include "sat.h"

/** @file
 *  Conversation definitions.
 */

/** Conversation information */
typedef struct _conversation_t {
	address src_address;    /**< source address */
	address dst_address;    /**< destination address */
	SAT_E   sat;            /**< address type */
	guint32 port_type;      /**< port_type (e.g. PT_TCP) */
	guint32 src_port;       /**< source port */
	guint32 dst_port;       /**< destination port */

	guint64 rx_frames;      /**< number of received packets */
	guint64 tx_frames;      /**< number of transmitted packets */
	guint64 rx_bytes;       /**< number of received bytes */
	guint64 tx_bytes;       /**< number of transmitted bytes */
} conversation_t;

/** Conversation widget */
typedef struct _conversations_table {
	const char          *name;              /**< the name of the table */
	GtkWidget           *win;               /**< GTK window */
	GtkWidget           *page_lb;           /**< label */
	GtkWidget           *scrolled_window;   /**< the scrolled window */
	GtkCList            *table;             /**< the GTK table */
        guint32             num_columns;         /**< number of columns in the above table */
        const char          *default_titles[10]; /**< Column headers */
	GtkWidget           *menu;              /**< context menu */
	gboolean            has_ports;          /**< table has ports */
	guint32             num_conversations;  /**< number of conversations */
	conversation_t      *conversations;     /**< array of conversation values */
	gboolean            resolve_names;      /**< resolve address names? */
} conversations_table;

/** Register the conversation table for the multiple conversation window.
 *
 * @param hide_ports hide the port columns
 * @param table_name the table name to be displayed
 * @param tap_name the registered tap name
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void register_conversation_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func);

/** Init the conversation table for the single conversation window.
 *
 * @param hide_ports hide the port columns
 * @param table_name the table name to be displayed
 * @param tap_name the registered tap name
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void init_conversation_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func);

/** Callback for "Conversations" statistics item.
 *
 * @param widget unused
 * @param data unused
 */
extern void init_conversation_notebook_cb(GtkWidget *widget, gpointer data);

/** Add some data to the conversation table.
 *
 * @param ct the table to add the data to
 * @param src source address
 * @param dst destination address
 * @param src_port source port
 * @param dst_port destination port
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param sat address type
 * @param port_type the port type (e.g. PT_TCP)
 */
extern void add_conversation_table_data(conversations_table *ct, const address *src, const address *dst, 
                        guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, SAT_E sat, int port_type);
#endif /* __CONVERSATIONS_TABLE_H__ */

