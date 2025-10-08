/* tap-rpcprogs.c
 * rpcstat   2002 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This module provides rpc call/reply SRT statistics to tshark.
 * It is only used by tshark and not wireshark
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/uuid_types.h>
#include <epan/dissectors/packet-rpc.h>

#include <wsutil/cmdarg_err.h>

#define MICROSECS_PER_SEC   1000000
#define NANOSECS_PER_SEC    1000000000

void register_tap_listener_rpcprogs(void);

/* used to keep track of statistics for a specific program/version */
typedef struct _rpc_program_t {
	struct _rpc_program_t *next;
	uint32_t program;
	uint32_t version;
	int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} rpc_program_t;

typedef struct _rpc_tapdata_t {
	rpc_program_t *prog_list;
} rpc_tapdata_t;

static tap_packet_status
rpcprogs_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
	rpc_tapdata_t *rtd = (rpc_tapdata_t *)tapdata;
	const rpc_call_info_value *ri = (const rpc_call_info_value *)pri;
	nstime_t delta;
	rpc_program_t *rp = NULL;

	if (!rtd->prog_list) {
		/* the list was empty */
		rp = g_new(rpc_program_t, 1);
		rp->next      =	NULL;
		rp->program   =	ri->prog;
		rp->version   =	ri->vers;
		rp->num	      =	0;
		rp->min.secs  =	0;
		rp->min.nsecs =	0;
		rp->max.secs  =	0;
		rp->max.nsecs =	0;
		rp->tot.secs  =	0;
		rp->tot.nsecs =	0;
		rtd->prog_list = rp;
	} else if ((ri->prog == rtd->prog_list->program)
		&& (ri->vers == rtd->prog_list->version)) {
		rp = rtd->prog_list;
	} else if ( (ri->prog < rtd->prog_list->program)
		|| ((ri->prog == rtd->prog_list->program) && (ri->vers < rtd->prog_list->version))) {
		/* we should be first entry in list */
		rp = g_new(rpc_program_t, 1);
		rp->next      = rtd->prog_list;
		rp->program   = ri->prog;
		rp->version   = ri->vers;
		rp->num	      = 0;
		rp->min.secs  =	0;
		rp->min.nsecs =	0;
		rp->max.secs  =	0;
		rp->max.nsecs =	0;
		rp->tot.secs  =	0;
		rp->tot.nsecs =	0;
		rtd->prog_list = rp;
	} else {
		/* we go somewhere else in the list */
		for (rp=rtd->prog_list; rp; rp=rp->next) {
			if ((rp->next)
			 && (rp->next->program == ri->prog)
		         && (rp->next->version == ri->vers)) {
				rp = rp->next;
				break;
			}
			if ((!rp->next)
			 || (rp->next->program > ri->prog)
			 || (   (rp->next->program == ri->prog)
			     && (rp->next->version > ri->vers))) {
				rpc_program_t *trp;
				trp = g_new(rpc_program_t, 1);
				trp->next      = rp->next;
				trp->program   = ri->prog;
				trp->version   = ri->vers;
				trp->num       = 0;
				trp->min.secs  = 0;
				trp->min.nsecs = 0;
				trp->max.secs  = 0;
				trp->max.nsecs = 0;
				trp->tot.secs  = 0;
				trp->tot.nsecs = 0;
				rp->next       = trp;
				rp = trp;
				break;
			}
		}
	}


	/* we are only interested in reply packets */
	if (ri->request || !rp) {
		return TAP_PACKET_DONT_REDRAW;
	}

	/* calculate time delta between request and reply */
	nstime_delta(&delta, &pinfo->abs_ts, &ri->req_time);

	if ((rp->max.secs == 0)
	 && (rp->max.nsecs == 0) ) {
		rp->max.secs  = delta.secs;
		rp->max.nsecs = delta.nsecs;
	}

	if ((rp->min.secs == 0)
	 && (rp->min.nsecs == 0) ) {
		rp->min.secs  = delta.secs;
		rp->min.nsecs = delta.nsecs;
	}

	if ( (delta.secs < rp->min.secs)
	|| ( (delta.secs == rp->min.secs)
	  && (delta.nsecs < rp->min.nsecs) ) ) {
		rp->min.secs  = delta.secs;
		rp->min.nsecs = delta.nsecs;
	}

	if ( (delta.secs > rp->max.secs)
	|| ( (delta.secs == rp->max.secs)
	  && (delta.nsecs > rp->max.nsecs) ) ) {
		rp->max.secs  = delta.secs;
		rp->max.nsecs = delta.nsecs;
	}

	rp->tot.secs  += delta.secs;
	rp->tot.nsecs += delta.nsecs;
	if (rp->tot.nsecs > NANOSECS_PER_SEC) {
		rp->tot.nsecs -= NANOSECS_PER_SEC;
		rp->tot.secs++;
	}
	rp->num++;

	return TAP_PACKET_REDRAW;
}


static void
rpcprogs_draw(void *tapdata)
{
	rpc_tapdata_t *rtd = (rpc_tapdata_t *)tapdata;
	uint64_t td;
	rpc_program_t *rp;
	char str[64];

	printf("\n");
	printf("==========================================================\n");
	printf("ONC-RPC Program Statistics:\n");
	printf("Program    Version  Calls    Min SRT    Max SRT    Avg SRT\n");
	for (rp = rtd->prog_list; rp; rp = rp->next) {
		/* Only display procs with non-zero calls */
		if (rp->num == 0) {
			continue;
		}
		/* Scale the average SRT in units of 1us and round to the nearest us. */
		td = ((uint64_t)(rp->tot.secs)) * NANOSECS_PER_SEC + rp->tot.nsecs;
		td = ((td / rp->num) + 500) / 1000;

		snprintf(str, sizeof(str), "%s(%d)", uuid_type_get_uuid_name("rpc", GUINT_TO_POINTER(rp->program), NULL), rp->program);
		printf("%-15s %2u %6d %3d.%06d %3d.%06d %3" PRIu64 ".%06" PRIu64 "\n",
		       str,
		       rp->version,
		       rp->num,
		       (int)(rp->min.secs), (rp->min.nsecs+500)/1000,
		       (int)(rp->max.secs), (rp->max.nsecs+500)/1000,
		       td/MICROSECS_PER_SEC, td%MICROSECS_PER_SEC
		);
	}
	printf("===================================================================\n");
}

static void
rpcprogs_reset(void *tapdata)
{
	rpc_tapdata_t *rtd = (rpc_tapdata_t *)tapdata;
	rpc_program_t *rp = rtd->prog_list;
	while (rp != NULL) {
		rpc_program_t *next = rp->next;
		g_free(rp);
		rp = next;
	}
	rtd->prog_list = NULL;
}

static void
rpcprogs_finish(void *tapdata)
{
	rpcprogs_reset(tapdata);
	g_free((rpc_tapdata_t *)tapdata);
}

static bool
rpcprogs_init(const char *opt_arg _U_, void *userdata _U_)
{
	GString *error_string;

	rpc_tapdata_t *tapdata = g_new0(rpc_tapdata_t, 1);

	error_string = register_tap_listener("rpc", tapdata, NULL, TL_REQUIRES_NOTHING,
					rpcprogs_reset, rpcprogs_packet, rpcprogs_draw, rpcprogs_finish);
	if (error_string) {
		cmdarg_err("Couldn't register rpc,programs tap: %s",
			error_string->str);
		g_string_free(error_string, TRUE);
		return false;
	}

	return true;
}

static stat_tap_ui rpcprogs_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"rpc,programs",
	rpcprogs_init,
	0,
	NULL
};

void
register_tap_listener_rpcprogs(void)
{
	register_stat_tap_ui(&rpcprogs_ui, NULL);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
