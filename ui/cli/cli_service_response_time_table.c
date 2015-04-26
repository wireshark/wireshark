/* cli_service_response_time_table.c
 * TShark service_response_time_table based on GTK version by Ronnie Sahlberg
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

#include "config.h"

#include <stdio.h>

#include "epan/packet_info.h"
#include "epan/value_string.h"

#include "ui/cli/cli_service_response_time_table.h"

#define NANOSECS_PER_SEC 1000000000


void
init_srt_table(const char *name, srt_stat_table *rst, int num_procs, const char* proc_column_name, const char *filter_string)
{
	int i;

	if(filter_string){
		rst->filter_string=g_strdup(filter_string);
	} else {
		rst->filter_string=NULL;
	}

	rst->name = name;
	rst->proc_column_name = proc_column_name;
	rst->num_procs=num_procs;
	rst->procedures=(srt_procedure_t *)g_malloc(sizeof(srt_procedure_t)*num_procs);
	for(i=0;i<num_procs;i++){
		time_stat_init(&rst->procedures[i].stats);
		rst->procedures[i].index = 0;
		rst->procedures[i].procedure = NULL;
	}
}

void
init_srt_table_row(srt_stat_table *rst, int indx, const char *procedure)
{
	/* we have discovered a new procedure. Extend the table accordingly */
	if(indx>=rst->num_procs){
		int old_num_procs=rst->num_procs;
		int i;

		rst->num_procs=indx+1;
		rst->procedures=(srt_procedure_t *)g_realloc(rst->procedures, sizeof(srt_procedure_t)*(rst->num_procs));
		for(i=old_num_procs;i<rst->num_procs;i++){
			time_stat_init(&rst->procedures[i].stats);
			rst->procedures[i].index = i;
			rst->procedures[i].procedure=NULL;
		}
	}
	rst->procedures[indx].index = indx;
	rst->procedures[indx].procedure=g_strdup(procedure);
}

void
add_srt_table_data(srt_stat_table *rst, int indx, const nstime_t *req_time, packet_info *pinfo)
{
	srt_procedure_t *rp;
	nstime_t t, delta;

	g_assert(indx >= 0 && indx < rst->num_procs);
	rp=&rst->procedures[indx];

	/* calculate time delta between request and reply */
	t=pinfo->fd->abs_ts;
	nstime_delta(&delta, &t, req_time);

	time_stat_update(&rp->stats, &delta, pinfo);
}

void
draw_srt_table_data(srt_stat_table *rst, gboolean draw_header, gboolean draw_footer)
{
	int i;
	guint64 td;
	guint64 sum;

	if (draw_header) {
		printf("\n");
		printf("===================================================================\n");
		printf("%s SRT Statistics:\n", rst->name);
		printf("Filter: %s\n", rst->filter_string ? rst->filter_string : "");
	}

	printf("Index  %-22s Calls    Min SRT    Max SRT    Avg SRT    Sum SRT\n", (rst->proc_column_name != NULL) ? rst->proc_column_name : "Procedure");
	for(i=0;i<rst->num_procs;i++){
		/* ignore procedures with no calls (they don't have rows) */
		if(rst->procedures[i].stats.num==0){
			continue;
		}
		/* Scale the average SRT in units of 1us and round to the nearest us.
		   tot.secs is a time_t which may be 32 or 64 bits (or even floating)
		   depending uon the platform.  After casting tot.secs to 64 bits, it
		   would take a capture with a duration of over 136 *years* to
		   overflow the secs portion of td. */
		td = ((guint64)(rst->procedures[i].stats.tot.secs))*NANOSECS_PER_SEC + rst->procedures[i].stats.tot.nsecs;
		sum = (td + 500) / 1000;
		td = ((td / rst->procedures[i].stats.num) + 500) / 1000;

		printf("%5u  %-22s %6u %3d.%06d %3d.%06d %3d.%06d %3d.%06d\n",
		       i, rst->procedures[i].procedure,
		       rst->procedures[i].stats.num,
		       (int)rst->procedures[i].stats.min.secs, (rst->procedures[i].stats.min.nsecs+500)/1000,
		       (int)rst->procedures[i].stats.max.secs, (rst->procedures[i].stats.max.nsecs+500)/1000,
		       (int)(td/1000000), (int)(td%1000000),
		       (int)(sum/1000000), (int)(sum%1000000)
		);
	}

	if (draw_footer)
		printf("==================================================================\n");
}

void
free_srt_table_data(srt_stat_table *rst)
{
	int i;

	for(i=0;i<rst->num_procs;i++){
		g_free(rst->procedures[i].procedure);
		rst->procedures[i].procedure=NULL;
	}
	g_free(rst->filter_string);
	rst->filter_string=NULL;
	g_free(rst->procedures);
	rst->procedures=NULL;
	rst->num_procs=0;
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
