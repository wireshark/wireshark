/* tap-mgcpstat.c
 * mgcpstat   2003 Lars Roland
 *
 * $Id: tap-mgcpstat.c,v 1.3 2003/03/12 00:36:22 guy Exp $
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
#include "tap.h"
#include "epan/value_string.h"
#include "register.h"
#include "plugins/mgcp/packet-mgcp.h"


/* Summary of response-time calculations*/
typedef struct _rtd_t {
	long int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} rtd_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _mgcpstat_t {
	char *filter;
        rtd_t rtd;
	long int open_req_num;
	long int disc_rsp_num;
	long int req_dup_num;
	long int rsp_dup_num;
} mgcpstat_t;

/* A Function to update a mgcp_rtd_t struct */

void
rtd_stat_update(rtd_t *rtd,nstime_t delta)
{
	rtd->num++;
	if((rtd->max.secs==0)
	&& (rtd->max.nsecs==0) ){
		rtd->max.secs=delta.secs;
		rtd->max.nsecs=delta.nsecs;
	}
	
	if((rtd->min.secs==0)
	&& (rtd->min.nsecs==0) ){
		rtd->min.secs=delta.secs;
		rtd->min.nsecs=delta.nsecs;
	}
	
	if( (delta.secs<rtd->min.secs)
	||( (delta.secs==rtd->min.secs)
	  &&(delta.nsecs<rtd->min.nsecs) ) ){
		rtd->min.secs=delta.secs;
		rtd->min.nsecs=delta.nsecs;
	}
	
	if( (delta.secs>rtd->max.secs)
	||( (delta.secs==rtd->max.secs)
	  &&(delta.nsecs>rtd->max.nsecs) ) ){
		rtd->max.secs=delta.secs;
		rtd->max.nsecs=delta.nsecs;
	}
		
	rtd->tot.secs += delta.secs;
	rtd->tot.nsecs += delta.nsecs;
	if(rtd->tot.nsecs>1000000000){
		rtd->tot.nsecs-=1000000000;
		rtd->tot.secs++;	
	}
	
	
}

static int
mgcpstat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, void *pmi)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	mgcp_info_t *mi=pmi;
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
			delta.secs=pinfo->fd->abs_secs-mi->req_time.secs;
			delta.nsecs=pinfo->fd->abs_usecs*1000-mi->req_time.nsecs;
			if(delta.nsecs<0){
				delta.nsecs+=1000000000;
				delta.secs--;
			}
			
			rtd_stat_update(&(ms->rtd),delta);
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
	
#ifdef G_HAVE_UINT64
	guint64 avg;
#else
	guint32 avg;
#endif
 

	/* calculating average rtd */
	/* scale it to units of 10us.*/
	/* for long captures with a large tot time, this can overflow on 32bit */
	avg=(int)ms->rtd.tot.secs;
	avg=avg*100000+(int)ms->rtd.tot.nsecs/10000;
	if(ms->rtd.num){
		avg/=ms->rtd.num;
	} else {
		avg=0;
	}

	/* printing results */
	printf("\n");
	printf("===================================================================\n");
	printf("MGCP Response Time Delay (RTD) Statistics:\n");
	printf("Filter: %s\n",ms->filter?ms->filter:"");
        printf("Duplicate requests: %ld\n",ms->req_dup_num);
        printf("Duplicate responses: %ld\n",ms->rsp_dup_num);
        printf("Open requests: %ld\n",ms->open_req_num);
        printf("Discarded responses: %ld\n",ms->disc_rsp_num);
        printf("Messages   |     Min RTD     |     Max RTD     |     Avg RTD \n");
        printf("%7ld    |  %5d.%03d msec |  %5d.%03d msec | %5d.%02d0 msec\n",
        	ms->rtd.num,
		(int)((ms->rtd.min.secs*1000)+(ms->rtd.min.nsecs/1000000)),(ms->rtd.min.nsecs%1000000)/1000,
		(int)((ms->rtd.max.secs*1000)+(ms->rtd.max.nsecs/1000000)),(ms->rtd.max.nsecs%1000000)/1000,
		avg/100, avg%100
	);
        printf("===================================================================\n");
}


static void
mgcpstat_init(char *optarg)
{
	mgcpstat_t *ms;
	char *filter=NULL;


	if(!strncmp(optarg,"mgcp,rtd,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	ms=g_malloc(sizeof(mgcpstat_t));
	if(filter){
		ms->filter=g_malloc(strlen(filter)+1);
		strcpy(ms->filter, filter);
	} else {
		ms->filter=NULL;
	}

	ms->rtd.num=0;
	ms->rtd.min.secs=0;
        ms->rtd.min.nsecs=0;
        ms->rtd.max.secs=0;
        ms->rtd.max.nsecs=0;
        ms->rtd.tot.secs=0;
        ms->rtd.tot.nsecs=0;

	ms->open_req_num=0;
	ms->disc_rsp_num=0;
	ms->req_dup_num=0;
	ms->rsp_dup_num=0;

	if(register_tap_listener("mgcp", ms, filter, NULL, mgcpstat_packet, mgcpstat_draw)){
		/* error, we failed to attach to the tap. clean up */
		g_free(ms->filter);
		g_free(ms);

		fprintf(stderr,"tethereal: mgcpstat_init() failed to attach to tap.\n");
		exit(1);
	}
}


void
register_tap_listener_mgcpstat(void)
{
	register_ethereal_tap("mgcp,rtd", mgcpstat_init, NULL, NULL);
}

