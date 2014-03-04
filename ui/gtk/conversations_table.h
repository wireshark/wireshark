/* conversations_table.h
 * conversations_table   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CONVERSATIONS_TABLE_H__
#define __CONVERSATIONS_TABLE_H__

#include <epan/conv_id.h>
#include "sat.h"

/** @file
 *  Conversation definitions.
 */

/** Conversation information */
typedef struct _conversation_t {
    address     src_address;    /**< source address */
    address     dst_address;    /**< destination address */
    SAT_E       sat;            /**< address type */
    guint32     port_type;      /**< port_type (e.g. PT_TCP) */
    guint32     src_port;       /**< source port */
    guint32     dst_port;       /**< destination port */
    conv_id_t   conv_id;        /**< conversation id */

    guint64     rx_frames;      /**< number of received packets */
    guint64     tx_frames;      /**< number of transmitted packets */
    guint64     rx_bytes;       /**< number of received bytes */
    guint64     tx_bytes;       /**< number of transmitted bytes */

    nstime_t    start_time;     /**< start time for the conversation */
    nstime_t    stop_time;      /**< stop time for the conversation */

    gboolean    modified;       /**< new to redraw the row */
    GtkTreeIter iter;
    gboolean    iter_valid;     /**< not a new row */
} conv_t;

/** Conversation widget */
typedef struct _conversations_table {
    const char  *name;               /**< the name of the table */
    const char  *filter;             /**< the filter used */
    gboolean    use_dfilter;         /**< use display filter */
    GtkWidget   *win;                /**< GTK window */
    GtkWidget   *page_lb;            /**< page label */
    GtkWidget   *name_lb;            /**< name label */
    GtkWidget   *scrolled_window;    /**< the scrolled window */
    GtkTreeView *table;              /**< the GTK table */
    const char  *default_titles[14]; /**< Column headers */
    GtkWidget   *menu;               /**< context menu */
    gboolean    has_ports;           /**< table has ports */
    guint32     num_conversations;   /**< number of conversations */
    GArray      *conversations;      /**< array of conversation values */
    GHashTable  *hashtable;          /**< conversations hash table */

    gboolean    fixed_col;           /**< if switched to fixed column */
    gboolean    resolve_names;       /**< resolve address names? */

    int         reselection_idx;     /**< conversation index to reselect */
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
 * @param ts timestamp
 * @param sat address type
 * @param port_type the port type (e.g. PT_TCP)
 */
extern void add_conversation_table_data(conversations_table *ct, const address *src, const address *dst,
            guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, nstime_t *ts,
            SAT_E sat, int port_type);

/** Add some data to the conversation table, passing a value to be used in
 *  addition to the address and port quadruple to uniquely identify the
 *  conversation.
 *
 * @param ct the table to add the data to
 * @param src source address
 * @param dst destination address
 * @param src_port source port
 * @param dst_port destination port
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param ts timestamp
 * @param sat address type
 * @param port_type the port type (e.g. PT_TCP)
 * @param conv_id a value to help differentiate the conversation in case the address and port quadruple is not sufficiently unique
 */
extern void
add_conversation_table_data_with_conv_id(
    conversations_table *ct,
    const address *src,
    const address *dst,
    guint32 src_port,
    guint32 dst_port,
    conv_id_t conv_id,
    int num_frames,
    int num_bytes,
    nstime_t *ts,
    SAT_E sat,
    int port_type);

#endif /* __CONVERSATIONS_TABLE_H__ */
