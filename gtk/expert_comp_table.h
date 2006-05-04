/* expert_comp_table.h
 * expert_comp_table   2005 Greg Morris
 * Portions copied from service_response_time_table.h by Ronnie Sahlberg 
 * Helper routines common to all composite expert statistics
 * tap.
 *
 * $Id$
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
#include <epan/expert.h>

/** @file
 *  Helper routines common to all error statistics tap.
 */

/** Procedure data */
typedef struct _error_procedure_t {
	char    *entries[4];       /**< column entries */
    char    *fvalue_value;     /**< filter value */
#if (GTK_MAJOR_VERSION < 2)
	guint32 packet_num;        /**< first packet number */
#else
    GtkTreeIter      iter;
#endif
    guint16 count;             /**< number of expert items encountered
                                    for this entry */
} error_procedure_t;

/** Statistics table */
typedef struct _error_equiv_table {
	GtkWidget *scrolled_window;         /**< window widget */
#if (GTK_MAJOR_VERSION < 2)
    GtkCList *table;                    /**< table widget */
#else
    GtkTreeSelection *select;           /**< item selected */
    GtkTreeView      *tree_view;        /**< Tree view */
#endif
	GtkWidget *menu;                    /**< context menu */
	guint16 num_procs;                  /**< number of elements on procedures array */
	error_procedure_t *procedures;      /**< the procedures array */
}error_equiv_table;

typedef struct _expert_tapdata_s {
	GtkWidget	*win;
	GtkWidget	*scrolled_window;
	GtkCList	*table;
	GtkWidget	*label;
	GList		*all_events;
	GList		*new_events;
	guint32		disp_events;
	guint32		chat_events;
	guint32		note_events;
	guint32		warn_events;
	guint32		error_events;
	int			severity_report_level;
} expert_tapdata_t;

/** Init an err table data structure.
 *
 * @param err the err table to init
 * @param num_procs number of procedures
 * @param vbox the corresponding GtkVBox to fill in
 */
void init_error_table(error_equiv_table *err, guint16 num_procs, GtkWidget *vbox);

/** Init an err table row data structure.
 *
 * @param err the err table
 * @param expert data
 */
void init_error_table_row(error_equiv_table *err, const expert_info_t *expert_data);

/** Add err response to table row data. This will not draw the data!
 *
 * @param err the err table
 * @param expert data
 */
void add_error_table_data(error_equiv_table *err, const expert_info_t *expert_data);

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

/* Function is located in expert_dlg.c */
extern void expert_dlg_init_table(expert_tapdata_t * etd, GtkWidget *vbox);
extern void expert_dlg_reset(void *tapdata);
extern int expert_dlg_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pointer);
extern void expert_dlg_draw(void *data);
