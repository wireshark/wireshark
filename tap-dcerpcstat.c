/* tap-dcerpcstat.c
 * dcerpcstat   2002 Ronnie Sahlberg
 *
 * $Id: tap-dcerpcstat.c,v 1.1 2002/10/23 03:49:10 guy Exp $
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
#include "packet-dcerpc.h"
#include "tap-dcerpcstat.h"

/* used to keep track of statistics for a specific procedure */
typedef struct _rpc_procedure_t {
	char *proc;
	int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} rpc_procedure_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _rpcstat_t {
	char *prog;
	char *filter;
	e_uuid_t uuid;
	guint16 ver;
	guint32 num_procedures;
	rpc_procedure_t *procedures;
} rpcstat_t;



static int
dcerpcstat_packet(rpcstat_t *rs, packet_info *pinfo, dcerpc_info *ri)
{
	nstime_t delta;
	rpc_procedure_t *rp;

	if(!ri->call_data){
		return 0;
	}
	if(ri->call_data->opnum>=rs->num_procedures){
		/* dont handle this since its outside of known table */
		return 0;
	}

	/* we are only interested in reply packets */
	if(ri->request){
		return 0;
	}

	/* we are only interested in certain program/versions */
	if( (ri->call_data->uuid.Data1!=rs->uuid.Data1)
          ||(ri->call_data->uuid.Data2!=rs->uuid.Data2)
          ||(ri->call_data->uuid.Data3!=rs->uuid.Data3)
          ||(ri->call_data->uuid.Data4[0]!=rs->uuid.Data4[0])
          ||(ri->call_data->uuid.Data4[1]!=rs->uuid.Data4[1])
          ||(ri->call_data->uuid.Data4[2]!=rs->uuid.Data4[2])
          ||(ri->call_data->uuid.Data4[3]!=rs->uuid.Data4[3])
          ||(ri->call_data->uuid.Data4[4]!=rs->uuid.Data4[4])
          ||(ri->call_data->uuid.Data4[5]!=rs->uuid.Data4[5])
          ||(ri->call_data->uuid.Data4[6]!=rs->uuid.Data4[6])
          ||(ri->call_data->uuid.Data4[7]!=rs->uuid.Data4[7])
	  ||(ri->call_data->ver!=rs->ver)){
		return 0;
	}

	rp=&(rs->procedures[ri->call_data->opnum]);

	/* calculate time delta between request and reply */
	delta.secs=pinfo->fd->abs_secs-ri->call_data->req_time.secs;
	delta.nsecs=pinfo->fd->abs_usecs*1000-ri->call_data->req_time.nsecs;
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
dcerpcstat_draw(rpcstat_t *rs)
{
	guint32 i;
#ifdef G_HAVE_UINT64
	guint64 td;
#else
	guint32 td;
#endif
	printf("\n");
	printf("===================================================================\n");
	printf("%s Version %d.%d RTT Statistics:\n", rs->prog, rs->ver&0xff,rs->ver>>8);
	printf("Filter: %s\n",rs->filter?rs->filter:"");
	printf("Procedure                  Calls   Min RTT   Max RTT   Avg RTT\n");
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

		printf("%-25s %6d %3d.%05d %3d.%05d %3d.%05d\n",
			rs->procedures[i].proc,
			rs->procedures[i].num,
			(int)rs->procedures[i].min.secs,rs->procedures[i].min.nsecs/10000,
			(int)rs->procedures[i].max.secs,rs->procedures[i].max.nsecs/10000,
			td/100000, td%100000
		);
	}
	printf("===================================================================\n");
}



void
dcerpcstat_init(e_uuid_t *uuid, int major, int minor, char *filter)
{
	rpcstat_t *rs;
	guint32 i, max_procs;
	dcerpc_sub_dissector *procs;

	rs=g_malloc(sizeof(rpcstat_t));
	rs->prog=dcerpc_get_proto_name(uuid, (minor<<8)|(major&0xff) );
	if(!rs->prog){
		g_free(rs);
		fprintf(stderr,"tethereal: dcerpcstat_init() Protocol with uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x v%d.%d not supported\n",uuid->Data1,uuid->Data2,uuid->Data3,uuid->Data4[0],uuid->Data4[1],uuid->Data4[2],uuid->Data4[3],uuid->Data4[4],uuid->Data4[5],uuid->Data4[6],uuid->Data4[7],major,minor);
		exit(1);
	}
	procs=dcerpc_get_proto_sub_dissector(uuid, (minor<<8)|(major&0xff) );
	rs->uuid=*uuid;
	rs->ver=(minor<<8)|(major&0xff);

	if(filter){
		rs->filter=g_malloc(strlen(filter)+1);
		strcpy(rs->filter, filter);
	} else {
		rs->filter=NULL;
	}

	for(i=0,max_procs=0;procs[i].name;i++){
		if(procs[i].num>max_procs){
			max_procs=procs[i].num;
		}
	}
	rs->num_procedures=max_procs+1;
	rs->procedures=g_malloc(sizeof(rpc_procedure_t)*(rs->num_procedures+1));
	for(i=0;i<rs->num_procedures;i++){
		int j;
		rs->procedures[i].proc="unknown";
		for(j=0;procs[j].name;j++){
			if(procs[j].num==i){
				rs->procedures[i].proc=procs[j].name;
			}
		}
		rs->procedures[i].num=0;	
		rs->procedures[i].min.secs=0;
		rs->procedures[i].min.nsecs=0;
		rs->procedures[i].max.secs=0;
		rs->procedures[i].max.nsecs=0;
		rs->procedures[i].tot.secs=0;
		rs->procedures[i].tot.nsecs=0;
	}

	if(register_tap_listener("dcerpc", rs, filter, NULL, (void*)dcerpcstat_packet, (void*)dcerpcstat_draw)){
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->procedures);
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr,"tethereal: dcerpcstat_init() failed to attach to tap.\n");
		exit(1);
	}
}

