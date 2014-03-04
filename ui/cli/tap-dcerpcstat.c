/* tap-dcerpcstat.c
 * dcerpcstat   2002 Ronnie Sahlberg
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-dcerpc.h>

#define MICROSECS_PER_SEC   1000000
#define NANOSECS_PER_SEC    1000000000

void register_tap_listener_dcerpcstat(void);

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
	const dcerpc_info *ri=(const dcerpc_info *)pri;
	rpcstat_t *rs=(rpcstat_t *)prs;
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
	nstime_delta(&delta, &pinfo->fd->abs_ts, &ri->call_data->req_time);

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
	if(rp->tot.nsecs > NANOSECS_PER_SEC){
		rp->tot.nsecs -= NANOSECS_PER_SEC;
		rp->tot.secs++;
	}

	rp->num++;

	return 1;
}

static void
dcerpcstat_draw(void *prs)
{
	rpcstat_t *rs=(rpcstat_t *)prs;
	guint32 i;
	guint64 td;
	printf("\n");
	printf("=======================================================================\n");
	printf("%s Major Version %u SRT Statistics:\n", rs->prog, rs->ver);
	printf("Filter: %s\n",rs->filter?rs->filter:"");
	printf("Procedure                        Calls    Min SRT    Max SRT    Avg SRT\n");

	for(i=0;i<rs->num_procedures;i++){
		/* Only display procs with non-zero calls */
		if(rs->procedures[i].num==0){
			continue;
		}
		/* Scale the average SRT in units of 1us and round to the nearest us. */
		td = ((guint64)(rs->procedures[i].tot.secs)) * NANOSECS_PER_SEC + rs->procedures[i].tot.nsecs;
		td = ((td / rs->procedures[i].num) + 500) / 1000;

		printf("%-31s %6d %3d.%06d %3d.%06d %3" G_GINT64_MODIFIER "u.%06" G_GINT64_MODIFIER "u\n",
			rs->procedures[i].proc,
			rs->procedures[i].num,
			(int)(rs->procedures[i].min.secs),(rs->procedures[i].min.nsecs+500)/1000,
			(int)(rs->procedures[i].max.secs),(rs->procedures[i].max.nsecs+500)/1000,
			td/MICROSECS_PER_SEC, td%MICROSECS_PER_SEC
		);
	}
	printf("=======================================================================\n");
}



static void
dcerpcstat_init(const char *opt_arg, void* userdata _U_)
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
	 */
	if(sscanf(opt_arg,
		"dcerpc,srt,%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d%n",
		&d1,&d2,&d3,&d40,&d41,&d42,&d43,&d44,&d45,&d46,&d47,
		&major,&minor,&pos)==13){
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
			filter=opt_arg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tshark: invalid \"-z dcerpc,srt,<uuid>,<major version>.<minor version>[,<filter>]\" argument\n");
		exit(1);
	}
	if (major < 0 || major > 65535) {
		fprintf(stderr,"tshark: dcerpcstat_init() Major version number %d is invalid - must be positive and <= 65535\n", major);
		exit(1);
	}
	if (minor < 0 || minor > 65535) {
		fprintf(stderr,"tshark: dcerpcstat_init() Minor version number %d is invalid - must be positive and <= 65535\n", minor);
		exit(1);
	}
	ver = major;

	rs=g_new(rpcstat_t,1);
	rs->prog=dcerpc_get_proto_name(&uuid, ver);
	if(!rs->prog){
		g_free(rs);
		fprintf(stderr,"tshark: dcerpcstat_init() Protocol with uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x v%u not supported\n",uuid.Data1,uuid.Data2,uuid.Data3,uuid.Data4[0],uuid.Data4[1],uuid.Data4[2],uuid.Data4[3],uuid.Data4[4],uuid.Data4[5],uuid.Data4[6],uuid.Data4[7],ver);
		exit(1);
	}
	procs=dcerpc_get_proto_sub_dissector(&uuid, ver);
	rs->uuid=uuid;
	rs->ver=ver;

	if(filter){
		rs->filter=g_strdup(filter);
	} else {
		rs->filter=NULL;
	}

	for(i=0,max_procs=0;procs[i].name;i++){
		if(procs[i].num>max_procs){
			max_procs=procs[i].num;
		}
	}
	rs->num_procedures=max_procs+1;
	rs->procedures=(rpc_procedure_t *)g_malloc(sizeof(rpc_procedure_t)*(rs->num_procedures+1));
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

	error_string=register_tap_listener("dcerpc", rs, filter, 0, NULL, dcerpcstat_packet, dcerpcstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->procedures);
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr, "tshark: Couldn't register dcerpc,srt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

void
register_tap_listener_dcerpcstat(void)
{
	register_stat_cmd_arg("dcerpc,srt,", dcerpcstat_init,NULL);
}
