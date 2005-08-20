/* tap-dcerpcstat.c
 * dcerpcstat   2002 Ronnie Sahlberg
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
#include <epan/dissectors/packet-dcerpc.h>
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
	e_uuid_t uuid;
	guint16 ver;
	guint32 num_procedures;
	rpc_procedure_t *procedures;
} rpcstat_t;



static int
dcerpcstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	const dcerpc_info *ri=pri;
	rpcstat_t *rs=prs;
	nstime_t delta;
	rpc_procedure_t *rp;

	if(!ri->call_data){
		return 0;
	}
	if(!ri->call_data->req_frame){
		/* we have not seen the request so we dont know the delta*/
		return 0;
	}
	if(ri->call_data->opnum>=rs->num_procedures){
		/* dont handle this since its outside of known table */
		return 0;
	}

	/* we are only interested in reply packets */
	if(ri->ptype != PDU_RESP){
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

static void
dcerpcstat_draw(void *prs)
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
	printf("%s Major Version %u RTT Statistics:\n", rs->prog, rs->ver);
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



static void
dcerpcstat_init(const char *optarg)
{
	rpcstat_t *rs;
	guint32 i, max_procs;
	dcerpc_sub_dissector *procs;
	e_uuid_t uuid;
	guint d1,d2,d3,d40,d41,d42,d43,d44,d45,d46,d47;
	int major, minor;
	guint16 ver;
	int pos=0;
        const char *filter=NULL;
        GString *error_string;
    
	/*
	 * XXX - DCE RPC statistics are maintained only by major version,
	 * not by major and minor version, so the minor version number is
	 * ignored.
	 *
	 * Should we just stop supporting minor version numbers here?
	 * Or should we allow it to be omitted?  Or should we keep
	 * separate statistics for different minor version numbers,
	 * and allow the minor version number to be omitted, and
	 * report aggregate statistics for all minor version numbers
	 * if it's omitted?
	 *
	 * XXX - should this be called "srt" rather than "rtt"?  The
	 * equivalent tap for Ethereal calls it "srt", for "Service
	 * Response Time", rather than "rtt" for "Round-Trip Time".
	 */
	if(sscanf(optarg,"dcerpc,rtt,%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d%n", &d1,&d2,&d3,&d40,&d41,&d42,&d43,&d44,&d45,&d46,&d47,&major,&minor,&pos)==13){
		uuid.Data1=d1;
		uuid.Data2=d2;
		uuid.Data3=d3;
		uuid.Data4[0]=d40;
		uuid.Data4[1]=d41;
		uuid.Data4[2]=d42;
		uuid.Data4[3]=d43;
		uuid.Data4[4]=d44;
		uuid.Data4[5]=d45;
		uuid.Data4[6]=d46;
		uuid.Data4[7]=d47;
		if(pos){
			filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tethereal: invalid \"-z dcerpc,rtt,<uuid>,<major version>.<minor version>[,<filter>]\" argument\n");
		exit(1);
	}
	if (major < 0 || major > 65535) {
		fprintf(stderr,"tethereal: dcerpcstat_init() Major version number %d is invalid - must be positive and <= 65535\n", major);
		exit(1);
	}
	if (minor < 0 || minor > 65535) {
		fprintf(stderr,"tethereal: dcerpcstat_init() Minor version number %d is invalid - must be positive and <= 65535\n", minor);
		exit(1);
	}
	ver = major;

	rs=g_malloc(sizeof(rpcstat_t));
	rs->prog=dcerpc_get_proto_name(&uuid, ver);
	if(!rs->prog){
		g_free(rs);
		fprintf(stderr,"tethereal: dcerpcstat_init() Protocol with uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x v%u not supported\n",uuid.Data1,uuid.Data2,uuid.Data3,uuid.Data4[0],uuid.Data4[1],uuid.Data4[2],uuid.Data4[3],uuid.Data4[4],uuid.Data4[5],uuid.Data4[6],uuid.Data4[7],ver);
		exit(1);
	}
	procs=dcerpc_get_proto_sub_dissector(&uuid, ver);
	rs->uuid=uuid;
	rs->ver=ver;

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

	error_string=register_tap_listener("dcerpc", rs, filter, NULL, dcerpcstat_packet, dcerpcstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->procedures);
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr, "tethereal: Couldn't register dcerpc,rtt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

void
register_tap_listener_dcerpcstat(void)
{
	register_stat_cmd_arg("dcerpc,rtt,", dcerpcstat_init);
}
