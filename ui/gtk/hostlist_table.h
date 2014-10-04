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
#include <ui/traffic_table_ui.h>

/** @file
 *  Hostlist definitions.
 */

#ifdef HAVE_GEOIP
typedef enum {
    ENDP_COLUMN_GEOIP1 = ENDP_NUM_COLUMNS,
    ENDP_COLUMN_GEOIP2,
    ENDP_COLUMN_GEOIP3,
    ENDP_COLUMN_GEOIP4,
    ENDP_COLUMN_GEOIP5,
    ENDP_COLUMN_GEOIP6,
    ENDP_COLUMN_GEOIP7,
    ENDP_COLUMN_GEOIP8,
    ENDP_COLUMN_GEOIP9,
    ENDP_COLUMN_GEOIP10,
    ENDP_COLUMN_GEOIP11,
    ENDP_COLUMN_GEOIP12,
    ENDP_COLUMN_GEOIP13
} geoip_column_type_e;
#define ENDP_NUM_GEOIP_COLUMNS 13
#else
#define ENDP_NUM_GEOIP_COLUMNS 0
#endif
#define ENDP_INDEX_COLUMN (ENDP_NUM_COLUMNS+ENDP_NUM_GEOIP_COLUMNS)

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
    const char          *default_titles[ENDP_NUM_COLUMNS+ENDP_NUM_GEOIP_COLUMNS]; /**< Column headers */
    GtkWidget           *menu;              /**< context menu */
    gboolean            has_ports;          /**< table has ports */
    conv_hash_t         hash;               /**< hostlist hash table */
    gboolean            fixed_col;          /**< if switched to fixed column */
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

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
