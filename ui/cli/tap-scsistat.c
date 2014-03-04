/* tap-scsistat.c	2010 Chris Costa and Cal Turney
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

#include <string.h>
#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-scsi.h>
#include <epan/dissectors/packet-fc.h>
#include <epan/dissectors/packet-scsi-sbc.h>
#include <epan/dissectors/packet-scsi-ssc.h>
#include <epan/dissectors/packet-scsi-smc.h>
#include <epan/dissectors/packet-scsi-osd.h>
#include <epan/dissectors/packet-scsi-mmc.h>

void register_tap_listener_scsistat(void);

static guint8 scsi_program = 0;

/* used to keep track of statistics for a specific procedure */
typedef struct _scsi_procedure_t {
	const char *proc;
	int         num;
	nstime_t    min;
	nstime_t    max;
	nstime_t    tot;
} scsi_procedure_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _scsistat_t {
	guint8            cmdset;
	char             *filter;
	value_string_ext *cdbnames_ext;
	const char       *prog;
#define MAX_PROCEDURES 256
	scsi_procedure_t *procedures;
} scsistat_t;

#define NANOSECS_PER_SEC 1000000000

static void
scsistat_reset(void *prs)
{
	scsistat_t *rs = (scsistat_t *)prs;
	guint32     i;

	for(i = 0; i < MAX_PROCEDURES; i++) {
		rs->procedures[i].num       = 0;
		rs->procedures[i].min.secs  = 0;
		rs->procedures[i].min.nsecs = 0;
		rs->procedures[i].max.secs  = 0;
		rs->procedures[i].max.nsecs = 0;
		rs->procedures[i].tot.secs  = 0;
		rs->procedures[i].tot.nsecs = 0;
	}
}

static int
scsistat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	scsistat_t             *rs = (scsistat_t *)prs;
	const scsi_task_data_t *ri = (const scsi_task_data_t *)pri;
	nstime_t                delta;
	scsi_procedure_t       *rp;

	/* we are only interested in response packets */
	if(ri->type != SCSI_PDU_TYPE_RSP) {
		return 0;
	}
	/* we are only interested in a specific commandset */
	if( (!ri->itl) || ((ri->itl->cmdset&SCSI_CMDSET_MASK) != rs->cmdset) ) {
		return 0;
	}
	/* check that the opcode looks sane */
	if( (!ri->itlq) || (ri->itlq->scsi_opcode > 255) ) {
		return 0;
	}

	rp = &(rs->procedures[ri->itlq->scsi_opcode]);

	/* calculate time delta between request and reply */
	nstime_delta(&delta, &pinfo->fd->abs_ts, &ri->itlq->fc_time);

	if(rp->num == 0) {
		rp->max.secs = delta.secs;
		rp->max.nsecs = delta.nsecs;
	}
	if(rp->num == 0) {
		rp->min.secs = delta.secs;
		rp->min.nsecs = delta.nsecs;
	}
	if( (delta.secs  < rp->min.secs)
	||( (delta.secs == rp->min.secs)
	  &&(delta.nsecs < rp->min.nsecs) ) ) {
		rp->min.secs = delta.secs;
		rp->min.nsecs = delta.nsecs;
	}
	if( (delta.secs  > rp->max.secs)
	||( (delta.secs == rp->max.secs)
	  &&(delta.nsecs > rp->max.nsecs) ) ) {
		rp->max.secs = delta.secs;
		rp->max.nsecs= delta.nsecs;
	}
	rp->tot.secs  += delta.secs;
	rp->tot.nsecs += delta.nsecs;
	if(rp->tot.nsecs > NANOSECS_PER_SEC) {
		rp->tot.nsecs -= NANOSECS_PER_SEC;
		rp->tot.secs++;
	}
	rp->num++;
	return 1;
}

static void
scsistat_draw(void *prs)
{
	scsistat_t *rs = (scsistat_t *)prs;
	guint32     i;
	guint64     td;

	printf("\n");
	printf("===========================================================\n");
	printf("SCSI %s SRT Statistics:\n", rs->prog);
	printf("Filter: %s\n", rs->filter?rs->filter:"");
	printf("Procedure            Calls   Min SRT    Max SRT    Avg SRT\n");
	for(i=0; i < MAX_PROCEDURES; i++) {
		if(rs->procedures[i].num == 0) {
			continue;
		}
		/* scale it to units of 1us.*/
		td = ((guint64)(rs->procedures[i].tot.secs)) * NANOSECS_PER_SEC + rs->procedures[i].tot.nsecs;
		td = ((td / rs->procedures[i].num) + 500) / 1000;

		printf("%-19s %6d %3d.%06u %3d.%06u %3d.%06u \n",
			rs->procedures[i].proc,
			rs->procedures[i].num,
			(int)(rs->procedures[i].min.secs),
			(rs->procedures[i].min.nsecs+500)/1000,
			(int)(rs->procedures[i].max.secs),
			(rs->procedures[i].max.nsecs+500)/1000,
			(int)(td/1000000), (int)(td%1000000)
		);
	}
	printf("===========================================================\n");
}

static void
scsistat_init(const char *opt_arg, void* userdata _U_)
{
	scsistat_t *rs;
	guint32     i;
	int         program, pos;
	const char *filter = NULL;
	GString    *error_string;

	pos = 0;
	if(sscanf(opt_arg, "scsi,srt,%d,%n", &program, &pos) == 1) {
		if(pos) {
			filter = opt_arg+pos;
		} else {
			filter = NULL;
		}
	} else {
		fprintf(stderr, "tshark: invalid \"-z scsi,srt,<cmdset>[,<filter>]\" argument\n");
		exit(1);
	}

	scsi_program = program;
	rs = g_new(scsistat_t,1);
	if(filter) {
		rs->filter = g_strdup(filter);
	} else {
		rs->filter = NULL;
	}
	rs->cmdset = program;

	switch(program) {
		case SCSI_DEV_SBC:
			rs->prog = "SBC (disk)";
			rs->cdbnames_ext = &scsi_sbc_vals_ext;
			break;
		case SCSI_DEV_SSC:
			rs->prog = "SSC (tape)";
			rs->cdbnames_ext = &scsi_ssc_vals_ext;
			break;
		case SCSI_DEV_CDROM:
			rs->prog = "MMC (cd/dvd)";
			rs->cdbnames_ext = &scsi_mmc_vals_ext;
			break;
		case SCSI_DEV_SMC:
			rs->prog = "SMC (tape robot)";
			rs->cdbnames_ext = &scsi_smc_vals_ext;
			break;
		case SCSI_DEV_OSD:
			rs->prog = "OSD (object based)";
			rs->cdbnames_ext = &scsi_osd_vals_ext;
			break;
		default:
			/* Default to the SBC (disk), since this is what EMC SCSI seem to always be */
			rs->cmdset = 0;
			rs->prog = "SBC (disk)";
			rs->cdbnames_ext = &scsi_sbc_vals_ext;
			break;
	}
	rs->procedures = g_new(scsi_procedure_t,MAX_PROCEDURES);
	for(i=0; i < MAX_PROCEDURES; i++) {
		rs->procedures[i].proc = val_to_str_ext(i, rs->cdbnames_ext, "Unknown-0x%02x");
		rs->procedures[i].num = 0;
		rs->procedures[i].min.secs = 0;
		rs->procedures[i].min.nsecs = 0;
		rs->procedures[i].max.secs = 0;
		rs->procedures[i].max.nsecs = 0;
		rs->procedures[i].tot.secs = 0;
		rs->procedures[i].tot.nsecs = 0;
	}
	error_string = register_tap_listener("scsi", rs, filter, 0, scsistat_reset, scsistat_packet, scsistat_draw);
	if(error_string) {
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->procedures);
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr, "tshark: Couldn't register scsi,srt tap: %s\n",
		        error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

void
register_tap_listener_scsistat(void)
{
	register_stat_cmd_arg("scsi,srt,", scsistat_init, NULL);
}

