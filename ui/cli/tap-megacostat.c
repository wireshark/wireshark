/* tap-megacostat.c
 * mgcpstat   2003 Lars Roland
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>

#include <string.h>
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "epan/value_string.h"
#include "epan/gcp.h"
#include "timestats.h"
#include <epan/prefs-int.h>

#include "tap-megaco-common.h"



static void
megacostat_draw(void *pms)
{
	megacostat_t *ms=(megacostat_t *)pms;
	int i;

	/* printing results */
	printf("\n");
	printf("=====================================================================================================\n");
	printf("MEGACO Response Time Delay (RTD) Statistics:\n");
	printf("Filter for statistics: %s\n",ms->filter?ms->filter:"");
        printf("Duplicate requests: %u\n",ms->req_dup_num);
        printf("Duplicate responses: %u\n",ms->rsp_dup_num);
        printf("Open requests: %u\n",ms->open_req_num);
        printf("Discarded responses: %u\n",ms->disc_rsp_num);
        printf(" Type   | Messages   |    Min RTD    |    Max RTD    |    Avg RTD    | Min in Frame | Max in Frame |\n");
        for(i=0;i<NUM_TIMESTATS;i++) {
        	if(ms->rtd[i].num) {
        		printf("%5s   | %7u    | %8.2f msec | %8.2f msec | %8.2f msec |  %10u  |  %10u  |\n",
        			val_to_str(i,megaco_message_type,"Other"),ms->rtd[i].num,
				nstime_to_msec(&(ms->rtd[i].min)), nstime_to_msec(&(ms->rtd[i].max)),
				get_average(&(ms->rtd[i].tot), ms->rtd[i].num),
				ms->rtd[i].min_num, ms->rtd[i].max_num
			);
		}
	}
        printf("=====================================================================================================\n");
}


static void
megacostat_init(const char *optarg, void* userdata _U_)
{
	megacostat_t *ms;
	int i;
	GString *error_string;
	pref_t *megaco_ctx_track,*h248_ctx_track;

	megaco_ctx_track = prefs_find_preference(prefs_find_module("megaco"),"ctx_info");
	h248_ctx_track = prefs_find_preference(prefs_find_module("h248"),"ctx_info");

	if (!megaco_ctx_track || !h248_ctx_track) {
		/* No such preferences */
		return;
	}

	if (!*megaco_ctx_track->varp.boolp || !*h248_ctx_track->varp.boolp) {
		printf("Track Context option at Protocols -> MEGACO and Protocols -> H248 preferences\n");
		printf("has to be set to true to enable measurement of service response times.\n");
		exit(1);
	}

	ms=g_malloc(sizeof(megacostat_t));
	if(!strncmp(optarg,"megaco,rtd,",11)){
		ms->filter=g_strdup(optarg+11);
	} else {
		ms->filter=NULL;
	}

	for(i=0;i<NUM_TIMESTATS;i++) {
		ms->rtd[i].num=0;
		ms->rtd[i].min_num=0;
		ms->rtd[i].max_num=0;
		ms->rtd[i].min.secs=0;
        	ms->rtd[i].min.nsecs=0;
        	ms->rtd[i].max.secs=0;
        	ms->rtd[i].max.nsecs=0;
        	ms->rtd[i].tot.secs=0;
        	ms->rtd[i].tot.nsecs=0;
	}

	ms->open_req_num=0;
	ms->disc_rsp_num=0;
	ms->req_dup_num=0;
	ms->rsp_dup_num=0;

	error_string=register_tap_listener("megaco", ms, ms->filter, 0, NULL, megacostat_packet, megacostat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(ms->filter);
		g_free(ms);

		fprintf(stderr, "tshark: Couldn't register megaco,rtd tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_megacostat(void)
{
	/* We don't register this tap, if we don't have the megaco plugin loaded.*/
	if (find_tap_id("megaco")) {
		register_stat_cmd_arg("megaco,rtd", megacostat_init, NULL);
	}
}

