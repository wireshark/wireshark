/* tap-rpcstat.c
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

/* This module provides rpc call/reply RTT statistics to tethereal.
 * It is only used by tethereal and not ethereal
 *
 * It serves as an example on how to use the tap api.
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
#include <epan/stat.h>
#include <epan/dissectors/packet-rpc.h>
#include "register.h"

/* used to keep track of statistics for a specific procedure */
typedef struct _rpc_procedure_t {
	const char *proc;
	int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} rpc_procedure_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _rpcstat_t {
	const char *prog;
	char *filter;
	guint32 program;
	guint32 version;
	guint32 num_procedures;
	rpc_procedure_t *procedures;
} rpcstat_t;



/* This callback is never used by tethereal but it is here for completeness.
 * When registering below, we could just have left this function as NULL.
 *
 * When used by ethereal, this function will be called whenever we would need
 * to reset all state. Such as when ethereal opens a new file, when it
 * starts a new capture, when it rescans the packetlist after some prefs have
 * changed etc.
 * So if your aplication has some state it needs to clean up in those
 * situations, here is a good place to put that code.
 */
static void
rpcstat_reset(void *prs)
{
	rpcstat_t *rs=prs;
	guint32 i;

	for(i=0;i<rs->num_procedures;i++){
		rs->procedures[i].num=0;	
		rs->procedures[i].min.secs=0;
		rs->procedures[i].min.nsecs=0;
		rs->procedures[i].max.secs=0;
		rs->procedures[i].max.nsecs=0;
		rs->procedures[i].tot.secs=0;
		rs->procedures[i].tot.nsecs=0;
	}
}


/* This callback is invoked whenever the tap system has seen a packet
 * we might be interested in.
 * The function is to be used to only update internal state information
 * in the *tapdata structure, and if there were state changes which requires
 * the window to be redrawn, return 1 and (*draw) will be called sometime
 * later.
 *
 * This function should be as lightweight as possible since it executes together
 * with the normal ethereal dissectors. Try to push as much processing as
 * possible into (*draw) instead since that function executes asynchronously
 * and does not affect the main threads performance.
 *
 * If it is possible, try to do all "filtering" explicitely as we do below in 
 * this example since you will get MUCH better performance than applying
 * a similar display-filter in the register call.
 *
 * The third parameter is tap dependant. Since we register this one to the "rpc"
 * tap the third parameters type is rpc_call_info_value.
 *
 *
 * The filtering we do is just to check the rpc_call_info_value struct that
 * we were called for the proper program and version. We didnt apply a filter
 * when we registered so we will be called for ALL rpc packets and not just
 * the ones we are collecting stats for.
 * 
 *
 * function returns :
 *  0: no updates, no need to call (*draw) later
 * !0: state has changed, call (*draw) sometime later
 */
static int
rpcstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	rpcstat_t *rs=prs;
	const rpc_call_info_value *ri=pri;
	nstime_t delta;
	rpc_procedure_t *rp;

	if(ri->proc>=rs->num_procedures){
		/* dont handle this since its outside of known table */
		return 0;
	}
	/* we are only interested in reply packets */
	if(ri->request){
		return 0;
	}
	/* we are only interested in certain program/versions */
	if( (ri->prog!=rs->program) || (ri->vers!=rs->version) ){
		return 0;
	}

	rp=&(rs->procedures[ri->proc]);

	/* calculate time delta between request and reply */
	delta.secs=pinfo->fd->abs_secs-ri->req_time.secs;
	delta.nsecs=pinfo->fd->abs_usecs*1000-ri->req_time.nsecs;
	if(delta.nsecs<0){
		delta.nsecs+=1000000000;
		delta.secs--;
	}

	if(rp->num==0){
		rp->max.secs=delta.secs;
		rp->max.nsecs=delta.nsecs;
	}

	if(rp->num==0){
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

/* This callback is used when tethereal wants us to draw/update our
 * data to the output device. Since this is tethereal only output is
 * stdout.
 * Tethereal will only call this callback once, which is when tethereal has
 * finished reading all packets and exists.
 * If used with ethereal this may be called any time, perhaps once every 3 
 * seconds or so.
 * This function may even be called in parallell with (*reset) or (*draw)
 * so make sure there are no races. The data in the rpcstat_t can thus change
 * beneath us. Beware.
 */
static void
rpcstat_draw(void *prs)
{
	rpcstat_t *rs=prs;
	guint32 i;
#ifdef G_HAVE_UINT64
	guint64 td;
#else
	guint32 td;
#endif
	printf("\n");
	printf("===================================================================\n");
	printf("%s Version %d RTT Statistics:\n", rs->prog, rs->version);
	printf("Filter: %s\n",rs->filter?rs->filter:"");
	printf("Procedure        Calls   Min RTT   Max RTT   Avg RTT\n");
	for(i=0;i<rs->num_procedures;i++){
		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)rs->procedures[i].tot.secs;
		td=td*100000+(int)rs->procedures[i].tot.nsecs/10000;
		if(rs->procedures[i].num){
			td/=rs->procedures[i].num;
		} else {
			td=0;
		}

		printf("%-15s %6d %3d.%05d %3d.%05d %3d.%05d\n",
			rs->procedures[i].proc,
			rs->procedures[i].num,
			(int)rs->procedures[i].min.secs,rs->procedures[i].min.nsecs/10000,
			(int)rs->procedures[i].max.secs,rs->procedures[i].max.nsecs/10000,
			td/100000, td%100000
		);
	}
	printf("===================================================================\n");
}

static guint32 rpc_program=0;
static guint32 rpc_version=0;
static gint32 rpc_min_proc=-1;
static gint32 rpc_max_proc=-1;

static void *
rpcstat_find_procs(gpointer *key, gpointer *value _U_, gpointer *user_data _U_)
{
	rpc_proc_info_key *k=(rpc_proc_info_key *)key;

	if(k->prog!=rpc_program){
		return NULL;
	}
	if(k->vers!=rpc_version){
		return NULL;
	}
	if(rpc_min_proc==-1){
		rpc_min_proc=k->proc;
		rpc_max_proc=k->proc;
	}
	if((gint32)k->proc<rpc_min_proc){
		rpc_min_proc=k->proc;
	}
	if((gint32)k->proc>rpc_max_proc){
		rpc_max_proc=k->proc;
	}

	return NULL;
}


/* When called, this function will create a new instance of rpcstat.
 * program and version are whick onc-rpc program/version we want to
 * collect statistics for.
 * This function is called from tethereal when it parses the -z rpc, arguments
 * and it creates a new instance to store statistics in and registers this
 * new instance for the rpc tap.
 */
static void
rpcstat_init(const char *optarg)
{
	rpcstat_t *rs;
	guint32 i;
	int program, version;
	int pos=0;
	const char *filter=NULL;
	GString *error_string;

	if(sscanf(optarg,"rpc,rtt,%d,%d,%n",&program,&version,&pos)==2){
		if(pos){
			filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tethereal: invalid \"-z rpc,rtt,<program>,<version>[,<filter>]\" argument\n");
		exit(1);
	}

	rs=g_malloc(sizeof(rpcstat_t));
	rs->prog=rpc_prog_name(program);
	rs->program=program;
	rs->version=version;
	if(filter){
		rs->filter=g_malloc(strlen(filter)+1);
		strcpy(rs->filter, filter);
	} else {
		rs->filter=NULL;
	}
	rpc_program=program;
	rpc_version=version;
	rpc_min_proc=-1;
	rpc_max_proc=-1;
	g_hash_table_foreach(rpc_procs, (GHFunc)rpcstat_find_procs, NULL);
	if(rpc_min_proc==-1){
		fprintf(stderr,"tethereal: Invalid -z rpc,rrt,%d,%d\n",rpc_program,rpc_version);
		fprintf(stderr,"   Program:%d version:%d isn't supported by tethereal.\n", rpc_program, rpc_version);
		exit(1);
	}


	rs->num_procedures=rpc_max_proc+1;
	rs->procedures=g_malloc(sizeof(rpc_procedure_t)*(rs->num_procedures+1));
	for(i=0;i<rs->num_procedures;i++){
		rs->procedures[i].proc=rpc_proc_name(program, version, i);
		rs->procedures[i].num=0;	
		rs->procedures[i].min.secs=0;
		rs->procedures[i].min.nsecs=0;
		rs->procedures[i].max.secs=0;
		rs->procedures[i].max.nsecs=0;
		rs->procedures[i].tot.secs=0;
		rs->procedures[i].tot.nsecs=0;
	}

/* It is possible to create a filter and attach it to the callbacks. Then the
 * callbacks would only be invoked if the filter matched.
 * Evaluating filters is expensive and if we can avoid it and not use them
 * we gain performance. 
 * In this case we do the filtering for protocol and version inside the 
 * callback itself but use whatever filter the user provided.
 * (Perhaps the user only want the stats for nis+ traffic for certain objects?)
 *
 */

	error_string=register_tap_listener("rpc", rs, filter, rpcstat_reset, rpcstat_packet, rpcstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->procedures);
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr, "tethereal: Couldn't register rpc,rtt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_rpcstat(void)
{
	register_stat_cmd_arg("rpc,rtt,", rpcstat_init);
}

