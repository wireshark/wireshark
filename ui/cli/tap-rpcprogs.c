/* tap-rpcprogs.c
 * rpcstat   2002 Ronnie Sahlberg
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

/* This module provides rpc call/reply SRT statistics to tshark.
 * It is only used by tshark and not wireshark
 */

#include "config.h"

#include <stdio.h>

#include <string.h>
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-rpc.h>

#define MICROSECS_PER_SEC   1000000
#define NANOSECS_PER_SEC    1000000000

/* used to keep track of statistics for a specific program/version */
typedef struct _rpc_program_t {
	struct _rpc_program_t *next;
	guint32 program;
	guint32 version;
	int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} rpc_program_t;

static rpc_program_t *prog_list=NULL;
static int already_enabled=0;

static int
rpcprogs_packet(void *dummy1 _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	const rpc_call_info_value *ri=pri;
	nstime_t delta;
	rpc_program_t *rp=NULL;

	if(!prog_list){
		/* the list was empty */
		rp=g_malloc(sizeof(rpc_program_t));
		rp->next=NULL;
		rp->program=ri->prog;
		rp->version=ri->vers;
		rp->num=0;
		rp->min.secs=0;
		rp->min.nsecs=0;
		rp->max.secs=0;
		rp->max.nsecs=0;
		rp->tot.secs=0;
		rp->tot.nsecs=0;
		prog_list=rp;
	} else if((ri->prog==prog_list->program)
		&&(ri->vers==prog_list->version)){
		rp=prog_list;
	} else if( (ri->prog<prog_list->program)
		||((ri->prog==prog_list->program)&&(ri->vers<prog_list->version))){
		/* we should be first entry in list */
		rp=g_malloc(sizeof(rpc_program_t));
		rp->next=prog_list;
		rp->program=ri->prog;
		rp->version=ri->vers;
		rp->num=0;
		rp->min.secs=0;
		rp->min.nsecs=0;
		rp->max.secs=0;
		rp->max.nsecs=0;
		rp->tot.secs=0;
		rp->tot.nsecs=0;
		prog_list=rp;
	} else {
		/* we go somewhere else in the list */
		for(rp=prog_list;rp;rp=rp->next){
			if((rp->next)
			&& (rp->next->program==ri->prog)
			&& (rp->next->version==ri->vers)){
				rp=rp->next;
				break;
			}
			if((!rp->next)
			|| (rp->next->program>ri->prog)
			|| (  (rp->next->program==ri->prog)
			    &&(rp->next->version>ri->vers))){
				rpc_program_t *trp;
				trp=g_malloc(sizeof(rpc_program_t));
				trp->next=rp->next;
				trp->program=ri->prog;
				trp->version=ri->vers;
				trp->num=0;
				trp->min.secs=0;
				trp->min.nsecs=0;
				trp->max.secs=0;
				trp->max.nsecs=0;
				trp->tot.secs=0;
				trp->tot.nsecs=0;
				rp->next=trp;
				rp=trp;
				break;
			}
		}
	}


	/* we are only interested in reply packets */
	if(ri->request || !rp){
		return 0;
	}

	/* calculate time delta between request and reply */
	nstime_delta(&delta, &pinfo->fd->abs_ts, &ri->req_time);

	if((rp->max.secs==0)
	&& (rp->max.nsecs==0) ){
		rp->max.secs=delta.secs;
		rp->max.nsecs=delta.nsecs;
	}

	if((rp->min.secs==0)
	&& (rp->min.nsecs==0) ){
		rp->min.secs=delta.secs;
		rp->min.nsecs=delta.nsecs;
	}

	if( (delta.secs<rp->min.secs)
	||( (delta.secs==rp->min.secs)
	  &&(delta.nsecs<rp->min.nsecs) ) ){
		rp->min.secs=delta.secs;
		rp->min.nsecs=delta.nsecs;
	}

	if( (delta.secs>rp->max.secs)
	||( (delta.secs==rp->max.secs)
	  &&(delta.nsecs>rp->max.nsecs) ) ){
		rp->max.secs=delta.secs;
		rp->max.nsecs=delta.nsecs;
	}

	rp->tot.secs += delta.secs;
	rp->tot.nsecs += delta.nsecs;
	if(rp->tot.nsecs > NANOSECS_PER_SEC){
		rp->tot.nsecs -= NANOSECS_PER_SEC;
		rp->tot.secs++;
	}
	rp->num++;

	return 1;
}


static void
rpcprogs_draw(void *dummy _U_)
{
	guint64 td;
	rpc_program_t *rp;
	char str[64];

	printf("\n");
	printf("==========================================================\n");
	printf("ONC-RPC Program Statistics:\n");
	printf("Program    Version  Calls    Min SRT    Max SRT    Avg SRT\n");
	for(rp=prog_list;rp;rp=rp->next){
		/* Only display procs with non-zero calls */
		if(rp->num==0){
			continue;
		}
		/* Scale the average SRT in units of 1us and round to the nearest us. */
		td = ((guint64)(rp->tot.secs)) * NANOSECS_PER_SEC + rp->tot.nsecs;
		td = ((td / rp->num) + 500) / 1000;

		g_snprintf(str, sizeof(str), "%s(%d)",rpc_prog_name(rp->program),rp->program);
		printf("%-15s %2d %6d %3d.%06d %3d.%06d %3" G_GINT64_MODIFIER "u.%06" G_GINT64_MODIFIER "u\n",
			str,
			rp->version,
			rp->num,
			(int)(rp->min.secs),(rp->min.nsecs+500)/1000,
			(int)(rp->max.secs),(rp->max.nsecs+500)/1000,
			td/MICROSECS_PER_SEC, td%MICROSECS_PER_SEC
		);
	}
	printf("===================================================================\n");
}


static void
rpcprogs_init(const char *optarg _U_, void* userdata _U_)
{
	GString *error_string;

	if(already_enabled){
		return;
	}
	already_enabled=1;

	error_string=register_tap_listener("rpc", NULL, NULL, 0, NULL, rpcprogs_packet, rpcprogs_draw);
	if(error_string){
		fprintf(stderr,"tshark: Couldn't register rpc,programs tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_rpcprogs(void)
{
	register_stat_cmd_arg("rpc,programs", rpcprogs_init, NULL);
}


