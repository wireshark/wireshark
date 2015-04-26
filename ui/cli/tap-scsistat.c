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
#include <epan/stat_tap_ui.h>
#include <ui/cli/cli_service_response_time_table.h>
#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-scsi.h>
#include <epan/dissectors/packet-scsi-sbc.h>
#include <epan/dissectors/packet-scsi-ssc.h>
#include <epan/dissectors/packet-scsi-smc.h>
#include <epan/dissectors/packet-scsi-osd.h>
#include <epan/dissectors/packet-scsi-mmc.h>

void register_tap_listener_scsistat(void);

#define SCSI_NUM_PROCEDURES     256

/* used to keep track of the statistics for an entire program interface */
typedef struct _scsistat_t {
	guint8            cmdset;
	const char       *prog;
	srt_stat_table scsi_srt_table;
} scsistat_t;

static int
scsistat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	scsistat_t             *rs = (scsistat_t *)prs;
	const scsi_task_data_t *ri = (const scsi_task_data_t *)pri;

	/* we are only interested in response packets */
	if (ri->type != SCSI_PDU_TYPE_RSP) {
		return 0;
	}
	/* we are only interested in a specific commandset */
	if ( (!ri->itl) || ((ri->itl->cmdset&SCSI_CMDSET_MASK) != rs->cmdset) ) {
		return 0;
	}
	/* check that the opcode looks sane */
	if ( (!ri->itlq) || (ri->itlq->scsi_opcode > 255) ) {
		return 0;
	}

	add_srt_table_data(&rs->scsi_srt_table, ri->itlq->scsi_opcode, &ri->itlq->fc_time, pinfo);
	return 1;
}

static void
scsistat_draw(void *prs)
{
	scsistat_t *rs = (scsistat_t *)prs;

	draw_srt_table_data(&rs->scsi_srt_table, TRUE, TRUE);
}

static void
scsistat_init(const char *opt_arg, void* userdata _U_)
{
	scsistat_t *rs;
	guint32     i;
	int         program, pos;
	const char *filter = NULL;
	value_string_ext *cdbnames_ext;
	GString    *error_string;
	const char *table_name;

	pos = 0;
	if (sscanf(opt_arg, "scsi,srt,%d,%n", &program, &pos) == 1) {
		if (pos) {
			filter = opt_arg+pos;
		}
	} else {
		fprintf(stderr, "tshark: invalid \"-z scsi,srt,<cmdset>[,<filter>]\" argument\n");
		exit(1);
	}

	rs = g_new(scsistat_t,1);
	rs->cmdset = program;

	switch(program) {
		case SCSI_DEV_SBC:
			rs->prog = "SBC (disk)";
			table_name = "SCSI SBC (disk)";
			cdbnames_ext = &scsi_sbc_vals_ext;
			break;
		case SCSI_DEV_SSC:
			rs->prog = "SSC (tape)";
			table_name = "SCSI SSC (tape)";
			cdbnames_ext = &scsi_ssc_vals_ext;
			break;
		case SCSI_DEV_CDROM:
			rs->prog = "MMC (cd/dvd)";
			table_name = "SCSI MMC (cd/dvd)";
			cdbnames_ext = &scsi_mmc_vals_ext;
			break;
		case SCSI_DEV_SMC:
			rs->prog = "SMC (tape robot)";
			table_name = "SCSI SMC (tape robot)";
			cdbnames_ext = &scsi_smc_vals_ext;
			break;
		case SCSI_DEV_OSD:
			rs->prog = "OSD (object based)";
			table_name = "SCSI OSD (object based)";
			cdbnames_ext = &scsi_osd_vals_ext;
			break;
		default:
			/* Default to the SBC (disk), since this is what EMC SCSI seem to always be */
			rs->cmdset = 0;
			rs->prog = "SBC (disk)";
			table_name = "SCSI SBC (disk)";
			cdbnames_ext = &scsi_sbc_vals_ext;
			break;
	}

	init_srt_table(table_name, &rs->scsi_srt_table, SCSI_NUM_PROCEDURES, NULL, filter ? g_strdup(filter) : NULL);
	for (i = 0; i < SCSI_NUM_PROCEDURES; i++)
	{
		init_srt_table_row(&rs->scsi_srt_table, i, val_to_str_ext_const(i, cdbnames_ext, "<unknown>"));
	}

	error_string = register_tap_listener("scsi", rs, filter, 0, NULL, scsistat_packet, scsistat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		free_srt_table_data(&rs->scsi_srt_table);
		g_free(rs);

		fprintf(stderr, "tshark: Couldn't register scsi,srt tap: %s\n",
		        error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui scsistat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"scsi,srt",
	scsistat_init,
	0,
	NULL
};

void
register_tap_listener_scsistat(void)
{
	register_stat_tap_ui(&scsistat_ui, NULL);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
