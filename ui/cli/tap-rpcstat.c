/* tap-rpcstat.c
 * rpcstat   2002 Ronnie Sahlberg
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
 * It is only used by tshark and not wireshark.
 *
 * It serves as an example on how to use the tap api.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-rpc.h>
#include <ui/cli/cli_service_response_time_table.h>


void register_tap_listener_rpcstat(void);


/* used to keep track of the statistics for an entire program interface */
typedef struct _rpcstat_t {
	const char *prog;
	guint32 program;
	guint32 version;
	srt_stat_table rpc_srt_table;
} rpcstat_t;




/* This callback is invoked whenever the tap system has seen a packet we might
 * be interested in.  The function is to be used to only update internal state
 * information in the *tapdata structure, and if there were state changes which
 * requires the window to be redrawn, return 1 and (*draw) will be called
 * sometime later.
 *
 * This function should be as lightweight as possible since it executes
 * together with the normal wireshark dissectors.  Try to push as much
 * processing as possible into (*draw) instead since that function executes
 * asynchronously and does not affect the main thread's performance.
 *
 * If it is possible, try to do all "filtering" explicitly as we do below in
 * this example since you will get MUCH better performance than applying
 * a similar display-filter in the register call.
 *
 * The third parameter is tap dependent.  Since we register this one to the
 * "rpc" tap, the third parameter type is rpc_call_info_value.
 *
 * The filtering we do is just to check the rpc_call_info_value struct that we
 * were called for the proper program and version.  We didn't apply a filter
 * when we registered so we will be called for ALL rpc packets and not just
 * the ones we are collecting stats for.
 *
 * function returns :
 *  0: no updates, no need to call (*draw) later
 * !0: state has changed, call (*draw) sometime later
 */
static int
rpcstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri)
{
	rpcstat_t *rs = (rpcstat_t *)prs;
	const rpc_call_info_value *ri = (const rpc_call_info_value *)pri;

	if ((int)ri->proc >= rs->rpc_srt_table.num_procs) {
		/* don't handle this since its outside of known table */
		return 0;
	}
	/* we are only interested in reply packets */
	if (ri->request) {
		return 0;
	}
	/* we are only interested in certain program/versions */
	if ( (ri->prog != rs->program) || (ri->vers != rs->version) ) {
		return 0;
	}

	add_srt_table_data(&rs->rpc_srt_table, ri->proc, &ri->req_time, pinfo);
	return 1;
}

/* This callback is used when tshark wants us to draw/update our data to the
 * output device.  Since this is tshark, the only output is stdout.
 * TShark will only call this callback once, which is when tshark has finished
 * reading all packets and exits.
 * If used with wireshark this may be called any time, perhaps once every 3
 * seconds or so.
 * This function may even be called in parallel with (*reset) or (*draw), so
 * make sure there are no races.  The data in the rpcstat_t can thus change
 * beneath us.  Beware!
 */
static void
rpcstat_draw(void *prs)
{
	rpcstat_t *rs = (rpcstat_t *)prs;

	draw_srt_table_data(&rs->rpc_srt_table, TRUE, TRUE);
}

static guint32 rpc_program = 0;
static guint32 rpc_version = 0;
static gint32 rpc_min_proc = -1;
static gint32 rpc_max_proc = -1;

static void *
rpcstat_find_procs(gpointer *key, gpointer *value _U_, gpointer *user_data _U_)
{
	rpc_proc_info_key *k = (rpc_proc_info_key *)key;

	if (k->prog != rpc_program) {
		return NULL;
	}
	if (k->vers != rpc_version) {
		return NULL;
	}
	if (rpc_min_proc == -1) {
		rpc_min_proc = k->proc;
		rpc_max_proc = k->proc;
	}
	if ((gint32)k->proc < rpc_min_proc) {
		rpc_min_proc = k->proc;
	}
	if ((gint32)k->proc > rpc_max_proc) {
		rpc_max_proc = k->proc;
	}

	return NULL;
}


/* When called, this function will create a new instance of rpcstat.
 *
 * program and version are which onc-rpc program/version we want to collect
 * statistics for.
 *
 * This function is called from tshark when it parses the -z rpc, arguments and
 * it creates a new instance to store statistics in and registers this new
 * instance for the rpc tap.
 */
static void
rpcstat_init(const char *opt_arg, void *userdata _U_)
{
	rpcstat_t *rs;
	int i;
	int program, version;
	int pos = 0;
	const char *filter = NULL;
	GString *error_string;
	static char table_name[100];

	if (sscanf(opt_arg, "rpc,srt,%d,%d,%n", &program, &version, &pos) == 2) {
		if (pos) {
			filter = opt_arg+pos;
		}
	} else {
		fprintf(stderr, "tshark: invalid \"-z rpc,srt,<program>,<version>[,<filter>]\" argument\n");
		exit(1);
	}

	rs = g_new(rpcstat_t, 1);
	rs->prog    = rpc_prog_name(program);
	rs->program = program;
	rs->version = version;

	rpc_program  = program;
	rpc_version  = version;
	rpc_min_proc = -1;
	rpc_max_proc = -1;
	g_hash_table_foreach(rpc_procs, (GHFunc)rpcstat_find_procs, NULL);
	if (rpc_min_proc == -1) {
		fprintf(stderr, "tshark: Invalid -z rpc,srt,%u,%u\n", rpc_program, rpc_version);
		fprintf(stderr, "   Program:%u version:%u isn't supported by tshark.\n", rpc_program, rpc_version);
		exit(1);
	}

	g_snprintf(table_name, sizeof(table_name), "%s Version %u", rs->prog, rs->version);
	init_srt_table(table_name, &rs->rpc_srt_table, rpc_max_proc+1, NULL, filter ? g_strdup(filter) : NULL);
	for (i = 0; i < rs->rpc_srt_table.num_procs; i++)
	{
		init_srt_table_row(&rs->rpc_srt_table, i, rpc_proc_name(program, version, i));
	}

/* It is possible to create a filter and attach it to the callbacks.  Then the
 * callbacks would only be invoked if the filter matched.
 *
 * Evaluating filters is expensive and if we can avoid it and not use them,
 * then we gain performance.
 *
 * In this case, we do the filtering for protocol and version inside the
 * callback itself but use whatever filter the user provided.
 * (Perhaps the user only wants the stats for nis+ traffic for certain objects?)
 */

	error_string = register_tap_listener("rpc", rs, filter, 0, NULL, rpcstat_packet, rpcstat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		free_srt_table_data(&rs->rpc_srt_table);
		g_free(rs);

		fprintf(stderr, "tshark: Couldn't register rpc,srt tap: %s\n",
			error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui rpcstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"rpc,srt",
	rpcstat_init,
	0,
	NULL
};

void
register_tap_listener_rpcstat(void)
{
	register_stat_tap_ui(&rpcstat_ui, NULL);
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
