/* tap-rpcprogs.c
 * rpcstat   2002 Ronnie Sahlberg
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

/* This module provides rpc call/reply SRT statistics to tethereal.
 * It is only used by tethereal and not ethereal
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
#include <epan/dissectors/packet-rpc.h>
#include "register.h"

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
	if(ri->request){
		return 0;
	}

	/* calculate time delta between request and reply */
	delta.secs=pinfo->fd->abs_secs-ri->req_time.secs;
	delta.nsecs=pinfo->fd->abs_usecs*1000-ri->req_time.nsecs;
	if(delta.nsecs<0){
		delta.nsecs+=1000000000;
		delta.secs--;
	}

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
	if(rp->tot.nsecs>1000000000){
		rp->tot.nsecs-=1000000000;
		rp->tot.secs++;
	}
	rp->num++;

	return 1;
}


static void
rpcprogs_draw(void *dummy _U_)
{
#ifdef G_HAVE_UINT64
	guint64 td;
#else
	guint32 td;
#endif
	rpc_program_t *rp;
	char str[64];

	printf("\n");
	printf("===================================================================\n");
	printf("ONC-RPC Program Statistics:\n");
	printf("Program    Version  Calls   Min SRT   Max SRT   Avg SRT\n");
	for(rp=prog_list;rp;rp=rp->next){
		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)rp->tot.secs;
		td=td*100000+(int)rp->tot.nsecs/10000;
		if(rp->num){
			td/=rp->num;
		} else {
			td=0;
		}

		g_snprintf(str, sizeof(str), "%s(%d)",rpc_prog_name(rp->program),rp->program);
		printf("%-15s %2d %6d %3d.%05d %3d.%05d %3d.%05d\n",
			str,
			rp->version,
			rp->num,
			(int)rp->min.secs,rp->min.nsecs/10000,
			(int)rp->max.secs,rp->max.nsecs/10000,
			td/100000, td%100000
		);
	}
	printf("===================================================================\n");
}


static void
rpcprogs_init(const char *optarg _U_)
{
	GString *error_string;

	if(already_enabled){
		return;
	}
	already_enabled=1;

	error_string=register_tap_listener("rpc", NULL, NULL, NULL, rpcprogs_packet, rpcprogs_draw);
	if(error_string){
		fprintf(stderr,"tethereal: Couldn't register rpc,programs tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_rpcprogs(void)
{
	register_stat_cmd_arg("rpc,programs", rpcprogs_init);
}


