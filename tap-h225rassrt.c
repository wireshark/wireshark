/* tap_h225rassrt.c
 * h225 RAS Service Response Time statistics for ethereal
 * Copyright 2003 Lars Roland
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
#include <epan/dissectors/packet-h225.h>
#include "timestats.h"

/* following values represent the size of their valuestring arrays */
#define NUM_RAS_STATS 7

static const value_string ras_message_category[] = {
  {  0,	"Gatekeeper    "},
  {  1,	"Registration  "},
  {  2,	"UnRegistration"},
  {  3,	"Admission     "},
  {  4,	"Bandwidth     "},
  {  5,	"Disengage     "},
  {  6,	"Location      "},
  {  0, NULL }
};

typedef enum _ras_type {
	RAS_REQUEST,
	RAS_CONFIRM,
	RAS_REJECT,
	RAS_OTHER
}ras_type;

typedef enum _ras_category {
	RAS_GATEKEEPER,
	RAS_REGISTRATION,
	RAS_UNREGISTRATION,
	RAS_ADMISSION,
	RAS_BANDWIDTH,
	RAS_DISENGAGE,
	RAS_LOCATION,
	RAS_OTHERS
}ras_category;

/* Summary of response-time calculations*/
typedef struct _h225_rtd_t {
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
	timestat_t stats;
} h225_rtd_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _h225rassrt_t {
	char *filter;
	h225_rtd_t ras_rtd[NUM_RAS_STATS];
} h225rassrt_t;


static void
h225rassrt_reset(void *phs)
{
	h225rassrt_t *hs=(h225rassrt_t *)phs;
	int i;

	for(i=0;i<NUM_RAS_STATS;i++) {
		hs->ras_rtd[i].stats.num = 0;
		hs->ras_rtd[i].stats.min_num = 0;
		hs->ras_rtd[i].stats.max_num = 0;
		hs->ras_rtd[i].stats.min.secs = 0;
        	hs->ras_rtd[i].stats.min.nsecs = 0;
        	hs->ras_rtd[i].stats.max.secs = 0;
        	hs->ras_rtd[i].stats.max.nsecs = 0;
        	hs->ras_rtd[i].stats.tot.secs = 0;
        	hs->ras_rtd[i].stats.tot.nsecs = 0;
		hs->ras_rtd[i].open_req_num = 0;
		hs->ras_rtd[i].disc_rsp_num = 0;
		hs->ras_rtd[i].req_dup_num = 0;
		hs->ras_rtd[i].rsp_dup_num = 0;
	}

}

static int
h225rassrt_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *phi)
{
	h225rassrt_t *hs=(h225rassrt_t *)phs;
	const h225_packet_info *pi=phi;

	ras_type rasmsg_type = RAS_OTHER;
	ras_category rascategory = RAS_OTHERS;

	if (pi->msg_type != H225_RAS || pi->msg_tag == -1) {
		/* No RAS Message or uninitialized msg_tag -> return */
		return 0;
	}

	if (pi->msg_tag < 21) {
		/* */
		rascategory = pi->msg_tag / 3;
		rasmsg_type = pi->msg_tag % 3;
	}
	else {
		/* No SRT yet (ToDo) */
		return 0;
	}

	switch(rasmsg_type) {

	case RAS_REQUEST:
		if(pi->is_duplicate){
			hs->ras_rtd[rascategory].req_dup_num++;
		}
		else {
			hs->ras_rtd[rascategory].open_req_num++;
		}
		break;

	case RAS_CONFIRM:
		/* no break - delay calculation is identical for Confirm and Reject  */
	case RAS_REJECT:
		if(pi->is_duplicate){
			/* Duplicate is ignored */
			hs->ras_rtd[rascategory].rsp_dup_num++;
		}
		else if (!pi->request_available) {
			/* no request was seen, ignore response  */
			hs->ras_rtd[rascategory].disc_rsp_num++;
		}
		else {
			hs->ras_rtd[rascategory].open_req_num--;
			time_stat_update(&(hs->ras_rtd[rascategory].stats),&(pi->delta_time), pinfo);
		}
		break;

	default:
		return 0;
		break;
	}
	return 1;
}

static void
h225rassrt_draw(void *phs)
{
	h225rassrt_t *hs=(h225rassrt_t *)phs;
	int i;
	timestat_t *rtd_temp;

	printf("======================================== H225 RAS Service Response Time ========================================\n");
	printf("H225 RAS Service Response Time (SRT) Statistics:\n");
	printf("RAS-Messages   | Measurements |     Min SRT    |     Max SRT    |     Avg SRT    | Min in Frame | Max in Frame |\n");
	for(i=0;i<NUM_RAS_STATS;i++) {
		rtd_temp = &(hs->ras_rtd[i].stats);
		if(rtd_temp->num){
			printf("%s | %10u   | %9.2f msec | %9.2f msec | %9.2f msec |  %10u  |  %10u  |\n",
		        	val_to_str(i,ras_message_category,"Unknown       "),rtd_temp->num,
				nstime_to_msec(&(rtd_temp->min)), nstime_to_msec(&(rtd_temp->max)),
				get_average(&(rtd_temp->tot), rtd_temp->num),
				rtd_temp->min_num, rtd_temp->max_num
			);
		}
	}
        printf("================================================================================================================\n");
	printf("RAS-Messages   |   Open REQ   |  Discarded RSP  |   Repeated REQ  |   Repeated RSP  |\n");
	for(i=0;i<NUM_RAS_STATS;i++) {
		rtd_temp = &(hs->ras_rtd[i].stats);
		if(rtd_temp->num){
			printf("%s | %10u   |    %10u   |    %10u   |    %10u   |\n",
				val_to_str(i,ras_message_category,"Unknown       "),
				hs->ras_rtd[i].open_req_num, hs->ras_rtd[i].disc_rsp_num,
				hs->ras_rtd[i].req_dup_num, hs->ras_rtd[i].rsp_dup_num
			);
		}
	}
	printf("================================================================================================================\n");

}


static void
h225rassrt_init(const char *optarg)
{
	h225rassrt_t *hs;
	const char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"h225,srt,",9)){
		filter=optarg+9;
	} else {
		filter="";
	}

	hs = g_malloc(sizeof(h225rassrt_t));
	hs->filter=g_malloc(strlen(filter)+1);
	strcpy(hs->filter, filter);

	h225rassrt_reset(hs);

    	error_string=register_tap_listener("h225", hs, filter, NULL, h225rassrt_packet, h225rassrt_draw);
    	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(hs->filter);
		g_free(hs);

		fprintf(stderr, "tethereal: Couldn't register h225,srt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_h225rassrt(void)
{
	register_stat_cmd_arg("h225,srt", h225rassrt_init);
}
