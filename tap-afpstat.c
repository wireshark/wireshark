/* tap-afpstat.c
 * Based on
 * smbstat   2003 Ronnie Sahlberg
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/value_string.h>
#include <epan/dissectors/packet-afp.h>
#include "register.h"
#include "timestats.h"

/* used to keep track of the statistics for an entire program interface */
typedef struct _afpstat_t {
	char *filter;
	timestat_t proc[256];
} afpstat_t;

static int
afpstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv)
{
	afpstat_t *ss=(afpstat_t *)pss;
	const afp_request_val *request_val=prv;
	nstime_t t, deltat;
	timestat_t *sp=NULL;

	/* if we havnt seen the request, just ignore it */
	if(!request_val){
		return 0;
	}

	sp=&(ss->proc[request_val->command]);

	/* calculate time delta between request and reply */
	t=pinfo->fd->abs_ts;
	nstime_delta(&deltat, &t, &request_val->req_time);

	if(sp){
		time_stat_update(sp,&deltat, pinfo);
	}

	return 1;
}

static void
afpstat_draw(void *pss)
{
	afpstat_t *ss=(afpstat_t *)pss;
	guint32 i;
#ifdef G_HAVE_UINT64
	guint64 td;
#else
	guint32 td;
#endif
	printf("\n");
	printf("===================================================================\n");
	printf("AFP RTT Statistics:\n");
	printf("Filter: %s\n",ss->filter?ss->filter:"");
	printf("Commands                   Calls   Min RTT   Max RTT   Avg RTT\n");
	for(i=0;i<256;i++){
		/* nothing seen, nothing to do */
		if(ss->proc[i].num==0){
			continue;
		}

		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)ss->proc[i].tot.secs;
		td=td*100000+(int)ss->proc[i].tot.nsecs/10000;
		if(ss->proc[i].num){
			td/=ss->proc[i].num;
		} else {
			td=0;
		}

		printf("%-25s %6d %3d.%05d %3d.%05d %3d.%05d\n",
			val_to_str(i, CommandCode_vals, "Unknown (%u)"),
			ss->proc[i].num,
			(int)ss->proc[i].min.secs,ss->proc[i].min.nsecs/10000,
			(int)ss->proc[i].max.secs,ss->proc[i].max.nsecs/10000,
			td/100000, td%100000
		);
	}
	printf("===================================================================\n");
}


static void
afpstat_init(const char *optarg, void* userdata _U_)
{
	afpstat_t *ss;
	guint32 i;
	const char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"afp,rtt,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	ss=g_malloc(sizeof(afpstat_t));
	if(filter){
		ss->filter=g_malloc(strlen(filter)+1);
		strcpy(ss->filter, filter);
	} else {
		ss->filter=NULL;
	}

	for(i=0;i<256;i++){
		ss->proc[i].num=0;
		ss->proc[i].min_num=0;
		ss->proc[i].max_num=0;
		ss->proc[i].min.secs=0;
		ss->proc[i].min.nsecs=0;
		ss->proc[i].max.secs=0;
		ss->proc[i].max.nsecs=0;
		ss->proc[i].tot.secs=0;
		ss->proc[i].tot.nsecs=0;
	}

	error_string=register_tap_listener("afp", ss, filter, NULL, afpstat_packet, afpstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(ss->filter);
		g_free(ss);

		fprintf(stderr, "tshark: Couldn't register afp,rtt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

void
register_tap_listener_afpstat(void)
{
	register_stat_cmd_arg("afp,rtt", afpstat_init,NULL);
}
