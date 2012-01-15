/* service_response_time_table.h
 * service_response_time_table   2003 Ronnie Sahlberg
 * Helper routines common to all service response time statistics
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

#ifndef __SERVICE_RESPONSE_TIME_TABLE_H__
#define __SERVICE_RESPONSE_TIME_TABLE_H__

#include <gtk/gtk.h>
#include "epan/nstime.h"
#include "../timestats.h"

/** @file
 *  Helper routines common to all service response time statistics tap.
 */

/** Procedure data */
typedef struct _srt_procedure_t {
	int  index;
	timestat_t stats;   /**< stats */
	char *procedure;   /**< column entries */
	GtkTreeIter iter;
} srt_procedure_t;

/** Statistics table */
typedef struct _srt_stat_table {
	GtkWidget *scrolled_window; /**< window widget */
	GtkTreeView  *table;        /**< Tree view */
	GtkWidget *menu;            /**< context menu */
	char *filter_string;        /**< append procedure number (%d) to this string 
				to create a display filter */
	int num_procs;              /**< number of elements on procedures array */
	srt_procedure_t *procedures;/**< the procedures array */
} srt_stat_table;

/** Init an srt table data structure.
 *
 * @param rst the srt table to init
 * @param num_procs number of procedures
 * @param vbox the corresponding GtkVBox to fill in
 * @param filter_string filter string or NULL
 */
void init_srt_table(srt_stat_table *rst, int num_procs, GtkWidget *vbox,
                    const char *filter_string);

/** Init an srt table row data structure.
 *
 * @param rst the srt table
 * @param index number of procedure
 * @param procedure the procedures name
 */
void init_srt_table_row(srt_stat_table *rst, int index, const char *procedure);

/** Add srt response to table row data. This will not draw the data!
 *
 * @param rst the srt table
 * @param index number of procedure
 * @param req_time the time of the corresponding request
 * @param pinfo current packet info
 */
void add_srt_table_data(srt_stat_table *rst, int index, const nstime_t *req_time, packet_info *pinfo);

/** Draw the srt table data.
 *
 * @param rst the srt table
 */
void draw_srt_table_data(srt_stat_table *rst);

/** Reset the srt table data.
 *
 * @param rst the srt table
 */
void reset_srt_table_data(srt_stat_table *rst);

/** Free the srt table data.
 *
 * @param rst the srt table
 */
void free_srt_table_data(srt_stat_table *rst);

#endif /* __SERVICE_RESPONSE_TIME_TABLE_H__ */
