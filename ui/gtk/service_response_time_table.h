/* service_response_time_table.h
 * service_response_time_table   2003 Ronnie Sahlberg
 * Helper routines common to all service response time statistics
 * tap.
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

#ifndef __SERVICE_RESPONSE_TIME_TABLE_H__
#define __SERVICE_RESPONSE_TIME_TABLE_H__

#include <gtk/gtk.h>
#include "wsutil/nstime.h"
#include "ui/service_response_time.h"

/** Suggested width of SRT window */
#define SRT_PREFERRED_WIDTH 650

/** Suggested height of SRT window */
#define SRT_PREFERRED_HEIGHT 400

/** Limit filter string length for sanity */
#define MAX_FILTER_STRING_LENGTH 1000

/** @file
 *  Helper routines common to all service response time statistics taps.
 */

/** Statistics table */
typedef struct _gtk_srt_stat_table {
	GtkWidget *scrolled_window; /**< window widget */
	GtkTreeView  *table;        /**< Tree view */
	GtkWidget *menu;            /**< context menu */
	srt_stat_table stat_table;
} gtk_srt_stat_table;

typedef struct _gtk_srt_table_t {
	GtkTreeView  *table;        /**< Tree view */
	GtkWidget *scrolled_window; /**< window widget */
	GtkWidget *menu;            /**< context menu */
	srt_stat_table* rst;        /**< Used to match tables with its GUI data */
} gtk_srt_table_t;

typedef struct _gtk_srt_t {
	GtkWidget *vbox;
	GtkWidget *win;
	GtkWidget *main_nb;            /** Used for tab displays */
	GArray    *gtk_srt_array;      /**< array of gtk_srt_table_t */
} gtk_srt_t;

/** Init an srt table data structure.
 *
 * @param rst the srt table to init
 * @param gui_data contains GTK specific data
 */
void init_gtk_srt_table(srt_stat_table* rst, void* gui_data);

/** Draw the srt table data.
 *
 * @param rst the srt table
 * @param gtk_data contains GTK specific data
 */
void draw_srt_table_data(srt_stat_table *rst, gtk_srt_t* gtk_data);

/** Clean up memory of the srt table.
 *
 * @param rst the srt table
 * @param gui_data contains GTK specific data
 */
void free_table_data(srt_stat_table* rst, void* gui_data);

/** Reset srt table data.
 * Called when a tap listener is reset
 *
 * @param rst the srt table
 * @param gui_data contains GTK specific data
 */
void reset_table_data(srt_stat_table* rst, void* gui_data);

/** Register function to register dissectors that support SRT for GTK.
 *
 * @param data register_srt_t* representing dissetor SRT table
 * @param user_data is unused
 */
void register_service_response_tables(gpointer data, gpointer user_data);

#endif /* __SERVICE_RESPONSE_TIME_TABLE_H__ */
