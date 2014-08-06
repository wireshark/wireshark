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
#include <epan/conversation_table.h>
#include <ui/traffic_table_ui.h>

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

/** Init the conversation table for the single conversation window.
 *
 * @param ct the registered conversation
 * @param filter the optional filter name or NULL
 */
extern void init_conversation_table(struct register_ct* ct, const char *filter);

/** Callback for "Conversations" statistics item.
 *
 * @param widget unused
 * @param data unused
 */
extern void init_conversation_notebook_cb(GtkWidget *widget, gpointer data);

/** Function called to instantiate the "GTK conversation table display"
 *
 * @param table conversation table to be created
 */
extern void conversation_endpoint_cb(register_ct_t* table);

#endif /* __CONVERSATIONS_TABLE_H__ */
