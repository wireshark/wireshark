/* tap-radiusstat.c
 * Copyright 2006 Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * 
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
#include <epan/dissectors/packet-radius.h>
#include "timestats.h"

#define NUM_TIMESTATS 8

/* used to keep track of the statistics for an entire program interface */
typedef struct _radiusstat_t {
	char *filter;
	timestat_t rtd[NUM_TIMESTATS];
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
} radiusstat_t;

static const value_string radius_message_code[] = {
  {  0,	"Overall       "},
  {  1,	"Access        "},
  {  2,	"Accounting    "},
  {  3,	"Access Passw  "},
  {  4, "Ascend Acce Ev"},
  {  5, "Diconnect     "},
  {  6, "Change Filter "},
  {  7, "Other         "},
};

static int
radiusstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	radiusstat_t *rs=(radiusstat_t *)prs;
	const radius_info_t *ri=pri;
	nstime_t delta;

	switch (ri->code) {

	case RADIUS_ACCESS_REQUEST:
	case RADIUS_ACCOUNTING_REQUEST:
	case RADIUS_ACCESS_PASSWORD_REQUEST:
	case RADIUS_ASCEND_ACCESS_EVENT_REQUEST:
	case RADIUS_DISCONNECT_REQUEST:
	case RADIUS_CHANGE_FILTER_REQUEST:
		if(ri->is_duplicate){
			/* Duplicate is ignored */
			rs->req_dup_num++;
			return 0;
		}
		else {
			rs->open_req_num++;
			return 0;
		}
	break;

	case RADIUS_ACCESS_ACCEPT:
	case RADIUS_ACCESS_REJECT:
	case RADIUS_ACCOUNTING_RESPONSE:
	case RADIUS_ACCESS_PASSWORD_ACK:
	case RADIUS_ACCESS_PASSWORD_REJECT:
	case RADIUS_ASCEND_ACCESS_EVENT_RESPONSE:
	case RADIUS_DISCONNECT_REQUEST_ACK:
	case RADIUS_DISCONNECT_REQUEST_NAK:
	case RADIUS_CHANGE_FILTER_REQUEST_ACK:
	case RADIUS_CHANGE_FILTER_REQUEST_NAK:
		if(ri->is_duplicate){
			/* Duplicate is ignored */
			rs->rsp_dup_num++;
			return 0;
		}
		else if (!ri->request_available) {
			/* no request was seen */
			rs->disc_rsp_num++;
			return 0;
		}
		else {
			rs->open_req_num--;
			/* calculate time delta between request and response */
			nstime_delta(&delta, &pinfo->fd->abs_ts, &ri->req_time);

			time_stat_update(&(rs->rtd[0]),&delta, pinfo);
			if (ri->code == RADIUS_ACCESS_ACCEPT || ri->code == RADIUS_ACCESS_REJECT) {
				time_stat_update(&(rs->rtd[1]),&delta, pinfo);
			}
			else if (ri->code == RADIUS_ACCOUNTING_RESPONSE) {
				time_stat_update(&(rs->rtd[2]),&delta, pinfo);
			}



			else {
				time_stat_update(&(rs->rtd[7]),&delta, pinfo);
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
radiusstat_draw(void *prs)
{
	radiusstat_t *rs=(radiusstat_t *)prs;
	int i;

	/* printing results */
	printf("\n");
	printf("===========================================================================================================\n");
	printf("RADIUS Response Time Delay (RTD) Statistics:\n");
	printf("Filter for statistics: %s\n",rs->filter?rs->filter:"");
        printf("Duplicate requests: %u\n",rs->req_dup_num);
        printf("Duplicate responses: %u\n",rs->rsp_dup_num);
        printf("Open requests: %u\n",rs->open_req_num);
        printf("Discarded responses: %u\n",rs->disc_rsp_num);
        printf("Type           | Messages   |    Min RTD    |    Max RTD    |    Avg RTD    | Min in Frame | Max in Frame |\n");
        for(i=0;i<NUM_TIMESTATS;i++) {
        	if(rs->rtd[i].num) {
        		printf("%s | %7u    | %8.2f msec | %8.2f msec | %8.2f msec |  %10u  |  %10u  |\n",
        			val_to_str(i,radius_message_code,"Other  "),rs->rtd[i].num,
				nstime_to_msec(&(rs->rtd[i].min)), nstime_to_msec(&(rs->rtd[i].max)),
				get_average(&(rs->rtd[i].tot), rs->rtd[i].num),
				rs->rtd[i].min_num, rs->rtd[i].max_num
			);
		}
	}
        printf("===========================================================================================================\n");
}


static void
radiusstat_init(const char *optarg, void* userdata _U_)
{
	radiusstat_t *rs;
	int i;
	const char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"radius,rtd,",11)){
		filter=optarg+11;
	} else {
		filter="";
	}

	rs=g_malloc(sizeof(radiusstat_t));
	rs->filter=g_malloc(strlen(filter)+1);
	strcpy(rs->filter, filter);

	for(i=0;i<NUM_TIMESTATS;i++) {
		rs->rtd[i].num=0;
		rs->rtd[i].min_num=0;
		rs->rtd[i].max_num=0;
		rs->rtd[i].min.secs=0;
        rs->rtd[i].min.nsecs=0;
        rs->rtd[i].max.secs=0;
        rs->rtd[i].max.nsecs=0;
        rs->rtd[i].tot.secs=0;
        rs->rtd[i].tot.nsecs=0;
	}

	rs->open_req_num=0;
	rs->disc_rsp_num=0;
	rs->req_dup_num=0;
	rs->rsp_dup_num=0;

	error_string=register_tap_listener("radius", rs, filter, NULL, radiusstat_packet, radiusstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr, "tshark: Couldn't register radius,rtd tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_radiusstat(void)
{
	register_stat_cmd_arg("radius,rtd", radiusstat_init, NULL);
}

