/* tap-mgcpstat.c
 * mgcpstat   2003 Lars Roland
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "epan/value_string.h"
#include "register.h"
#include "plugins/mgcp/packet-mgcp.h"
#include "timestats.h"

#define NUM_TIMESTATS 11

/* used to keep track of the statistics for an entire program interface */
typedef struct _mgcpstat_t {
	char *filter;
        timestat_t rtd[NUM_TIMESTATS];
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
} mgcpstat_t;

static const value_string mgcp_mesage_type[] = {
  {  0,	"Overall"},
  {  1,	"EPCF   "},
  {  2,	"CRCX   "},
  {  3,	"MDCX   "},
  {  4,	"DLCX   "},
  {  5,	"RQNT   "},
  {  6,	"NTFY   "},
  {  7,	"AUEP   "},
  {  8, "AUCX   "},
  {  9, "RSIP   "},
};

static int
mgcpstat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pmi)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	const mgcp_info_t *mi=pmi;
	nstime_t delta;

	switch (mi->mgcp_type) {

	case MGCP_REQUEST:
		if(mi->is_duplicate){
			/* Duplicate is ignored */
			ms->req_dup_num++;
			return 0;
		}
		else {
			ms->open_req_num++;
			return 0;
		}
	break;

	case MGCP_RESPONSE:
		if(mi->is_duplicate){
			/* Duplicate is ignored */
			ms->rsp_dup_num++;
			return 0;
		}
		else if (!mi->request_available) {
			/* no request was seen */
			ms->disc_rsp_num++;
			return 0;
		}
		else {
			ms->open_req_num--;
			/* calculate time delta between request and response */
			nstime_delta(&delta, &pinfo->fd->abs_ts, &mi->req_time);

			time_stat_update(&(ms->rtd[0]),&delta, pinfo);

			if (strncasecmp(mi->code, "EPCF", 4) == 0 ) {
				time_stat_update(&(ms->rtd[1]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "CRCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[2]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "MDCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[3]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "DLCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[4]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RQNT", 4) == 0 ) {
				time_stat_update(&(ms->rtd[5]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "NTFY", 4) == 0 ) {
				time_stat_update(&(ms->rtd[6]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUEP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[7]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[8]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RSIP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[9]),&delta, pinfo);
			}
			else {
				time_stat_update(&(ms->rtd[10]),&delta, pinfo);
			}

			return 1;
		}
	break;

	default:
		return 0;
	break;
	}
}

static void
mgcpstat_draw(void *pms)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	int i;

	/* printing results */
	printf("\n");
	printf("=====================================================================================================\n");
	printf("MGCP Response Time Delay (RTD) Statistics:\n");
	printf("Filter for statistics: %s\n",ms->filter?ms->filter:"");
        printf("Duplicate requests: %u\n",ms->req_dup_num);
        printf("Duplicate responses: %u\n",ms->rsp_dup_num);
        printf("Open requests: %u\n",ms->open_req_num);
        printf("Discarded responses: %u\n",ms->disc_rsp_num);
        printf("Type    | Messages   |    Min RTD    |    Max RTD    |    Avg RTD    | Min in Frame | Max in Frame |\n");
        for(i=0;i<NUM_TIMESTATS;i++) {
        	if(ms->rtd[i].num) {
        		printf("%s | %7u    | %8.2f msec | %8.2f msec | %8.2f msec |  %10u  |  %10u  |\n",
        			val_to_str(i,mgcp_mesage_type,"Other  "),ms->rtd[i].num,
				nstime_to_msec(&(ms->rtd[i].min)), nstime_to_msec(&(ms->rtd[i].max)),
				get_average(&(ms->rtd[i].tot), ms->rtd[i].num),
				ms->rtd[i].min_num, ms->rtd[i].max_num
			);
		}
	}
        printf("=====================================================================================================\n");
}


static void
mgcpstat_init(const char *optarg)
{
	mgcpstat_t *ms;
	int i;
	const char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"mgcp,rtd,",9)){
		filter=optarg+9;
	} else {
		filter="";
	}

	ms=g_malloc(sizeof(mgcpstat_t));
	ms->filter=g_malloc(strlen(filter)+1);
	strcpy(ms->filter, filter);

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

	error_string=register_tap_listener("mgcp", ms, filter, NULL, mgcpstat_packet, mgcpstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(ms->filter);
		g_free(ms);

		fprintf(stderr, "tethereal: Couldn't register mgcp,rtd tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_mgcpstat(void)
{
	/* We don't register this tap, if we don't have the mgcp plugin loaded.*/
	if (find_tap_id("mgcp")) {
		register_stat_cmd_arg("mgcp,rtd", mgcpstat_init);
	}
}

