/* expert_comp_table.h
 * expert_comp_table   2005 Greg Morris
 * Portions copied from service_response_time_table.h by Ronnie Sahlberg 
 * Helper routines common to all composite expert statistics
 * tap.
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

#ifndef __EXPERT_COMP_TABLE_H__
#define __EXPERT_COMP_TABLE_H__

#include <gtk/gtk.h>
#include <epan/expert.h>

typedef struct expert_tapdata_s expert_tapdata_t;

/** @file
 *  Helper routines common to all error statistics tap.
 */

/** Procedure data */
typedef struct _error_procedure_t {
	char    *entries[2];       /**< column entries */
    char    *fvalue_value;     /**< filter value */
    GtkTreeIter      iter;
    guint count;             /**< number of expert items encountered
                                    for this entry */
} error_procedure_t;

/** Statistics table */
typedef struct _error_equiv_table {
	GtkWidget *scrolled_window;         /**< window widget */
    GtkTreeSelection *select;           /**< item selected */
    GtkTreeView      *tree_view;        /**< Tree view */
	GtkWidget *menu;                    /**< context menu */
	guint      num_procs;               /**< number of elements on procedures array */
	GArray			  *procs_array;		/**< the procedures array error_procedure_t *procedures */
	GStringChunk*	  text;
}error_equiv_table;

/** Init an err table data structure.
 *
 * @param err the err table to init
 * @param num_procs number of procedures
 * @param vbox the corresponding GtkVBox to fill in
 */
void init_error_table(error_equiv_table *err, guint num_procs, GtkWidget *vbox);

/** Init an err table row data structure.
 *
 * @param err the err table
 * @param expert_data data
 */
void init_error_table_row(error_equiv_table *err, const expert_info_t *expert_data);

/** Draw the err table data.
 *
 * @param err the err table
 */
void draw_error_table_data(error_equiv_table *err);

/** Reset the err table data.
 *
 * @param err the err table
 */
void reset_error_table_data(error_equiv_table *err);

/** Free the err table data.
 *
 * @param err the err table
 */
void free_error_table_data(error_equiv_table *err);

#endif /* __EXPERT_COMP_TABLE_H__ */
