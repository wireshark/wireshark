/* hostlist_table.h   2004 Ian Schorr
 * modified from endpoint_talkers_table   2003 Ronnie Sahlberg
 * Helper routines common to all host talkers taps.
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

#ifndef __HOSTLIST_TABLE_H__
#define __HOSTLIST_TABLE_H__

#include <epan/conversation_table.h>

/** @file
 *  Hostlist definitions.
 */

typedef enum
{
    HOST_ADR_COLUMN,
    HOST_PORT_COLUMN,
    HOST_PACKETS_COLUMN,
    HOST_BYTES_COLUMN,
    HOST_PKT_AB_COLUMN,
    HOST_BYTES_AB_COLUMN,
    HOST_PKT_BA_COLUMN,
    HOST_BYTES_BA_COLUMN,
#ifdef HAVE_GEOIP
    HOST_GEOIP1_COLUMN,
    HOST_GEOIP2_COLUMN,
    HOST_GEOIP3_COLUMN,
    HOST_GEOIP4_COLUMN,
    HOST_GEOIP5_COLUMN,
    HOST_GEOIP6_COLUMN,
    HOST_GEOIP7_COLUMN,
    HOST_GEOIP8_COLUMN,
    HOST_GEOIP9_COLUMN,
    HOST_GEOIP10_COLUMN,
    HOST_GEOIP11_COLUMN,
    HOST_GEOIP12_COLUMN,
    HOST_GEOIP13_COLUMN,
#endif
    HOST_NUM_COLUMNS,
    HOST_INDEX_COLUMN = HOST_NUM_COLUMNS
} hostlist_column_type_e;



#define NUM_BUILTIN_COLS 8
#ifdef HAVE_GEOIP
# define NUM_GEOIP_COLS 13
#else
# define NUM_GEOIP_COLS 0
#endif
#define NUM_HOSTLIST_COLS (NUM_BUILTIN_COLS + NUM_GEOIP_COLS)

/** Hostlist widget */
typedef struct _hostlist_table {
	const char          *name;              /**< the name of the table */
	const char          *filter;            /**< the filter used */
	gboolean             use_dfilter;       /**< use display filter */
	GtkWidget           *win;               /**< GTK window */
	GtkWidget           *page_lb;           /**< page label */
	GtkWidget           *name_lb;           /**< name label */
	GtkWidget           *scrolled_window;   /**< the scrolled window */
	GtkTreeView         *table;             /**< the GTK table */
	const char          *default_titles[NUM_HOSTLIST_COLS]; /**< Column headers */
	GtkWidget           *menu;              /**< context menu */
	gboolean            has_ports;          /**< table has ports */
    conv_hash_t         hash;               /**< hostlist hash table */
	gboolean 	        fixed_col;      	/**< if switched to fixed column */
	gboolean            resolve_names;      /**< resolve address names? */
	gboolean            geoip_visible;      /**< if geoip columns are visible */
} hostlist_table;

/** Init the hostlist table for the single hostlist window.
 *
 * @param ct the registered hostlist (conversation)
 * @param filter the optional filter name or NULL
 */
extern void init_hostlist_table(struct register_ct* ct, const char *filter);

/** Callback for "Endpoints" statistics item.
 *
 * @param w unused
 * @param d unused
 */
extern void init_hostlist_notebook_cb(GtkWidget *w, gpointer d);

/** Function called to instantiate the "GTK hostlist display"
 *
 * @param table conversation table to be created
 */
extern void hostlist_endpoint_cb(register_ct_t* table);

#endif /* __HOSTLIST_TABLE_H__ */
