/* service_response_time_table.h
 * service_response_time_table   2003 Ronnie Sahlberg
 * Helper routines common to all service response time statistics
 * tap.
 *
 * $Id: service_response_time_table.h,v 1.1 2003/06/21 01:42:46 sahlberg Exp $
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
#include "epan/nstime.h"


typedef struct _srt_procedure_t {
	char *entries[6];
	int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} srt_procedure_t;

typedef struct _srt_stat_table {
	GtkWidget *scrolled_window;
	GtkCList *table;
	int num_procs;
	srt_procedure_t *procedures;
} srt_stat_table;

void init_srt_table(srt_stat_table *rst, int num_procs, GtkWidget *vbox);

void init_srt_table_row(srt_stat_table *rst, int index, char *procedure);

void add_srt_table_data(srt_stat_table *rst, int index, nstime_t *req_time, packet_info *pinfo);

void draw_srt_table_data(srt_stat_table *rst);

void reset_srt_table_data(srt_stat_table *rst);

void free_srt_table_data(srt_stat_table *rst);

