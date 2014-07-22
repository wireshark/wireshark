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
#include <ui/conversation_hash.h>

/** @file
 *  Conversation definitions.
 */

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
    conv_hash_t hash;                /**< conversations hash table */

    gboolean    fixed_col;           /**< if switched to fixed column */
    gboolean    resolve_names;       /**< resolve address names? */

    int         reselection_idx;     /**< conversation index to reselect */
} conversations_table;

/** Register the conversation table for the multiple conversation window.
 *
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void register_conversation_table(conversation_type_e conv_type, const char *filter, tap_packet_cb packet_func);

/** Init the conversation table for the single conversation window.
 *
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void init_conversation_table(conversation_type_e conv_type, const char *filter, tap_packet_cb packet_func);

/** Callback for "Conversations" statistics item.
 *
 * @param widget unused
 * @param data unused
 */
extern void init_conversation_notebook_cb(GtkWidget *widget, gpointer data);

#endif /* __CONVERSATIONS_TABLE_H__ */
