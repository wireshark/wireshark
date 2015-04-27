/* tap-smb2stat.c
 * Based off if smbstat by Ronnie Sahlberg
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
#include <epan/stat_tap_ui.h>
#include "epan/value_string.h"
#include <ui/cli/cli_service_response_time_table.h>
#include <epan/dissectors/packet-smb2.h>
#include "epan/timestats.h"

void register_tap_listener_smbstat(void);

#define SMB2_NUM_PROCEDURES     256

/* used to keep track of the statistics for an entire program interface */
typedef struct _smb2stat_t {
	srt_stat_table smb2_srt_table;
} smb2stat_t;

static int
smb2stat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	smb2stat_t *ss=(smb2stat_t *)pss;
	const smb2_info_t *si=(const smb2_info_t *)psi;

	/* we are only interested in response packets */
	if(!(si->flags&SMB2_FLAGS_RESPONSE)){
		return 0;
	}
	/* if we haven't seen the request, just ignore it */
	if(!si->saved){
		return 0;
	}
	/* SMB2 SRT can be very inaccurate in the presence of retransmissions. Retransmitted responses
	 * not only add additional (bogus) transactions but also the latency associated with them.
	 * This can greatly inflate the maximum and average SRT stats especially in the case of
	 * retransmissions triggered by the expiry of the rexmit timer (RTOs). Only calculating SRT
	 * for the last received response accomplishes this goal without requiring the TCP pref
	 * "Do not call subdissectors for error packets" to be set. */
	if(si->saved->frame_req
	&& si->saved->frame_res==pinfo->fd->num)
		add_srt_table_data(&ss->smb2_srt_table, si->opcode, &si->saved->req_time, pinfo);
	else
		return 0;

	return 1;

}

static void
smb2stat_draw(void *pss)
{
	smb2stat_t *ss = (smb2stat_t *)pss;

	draw_srt_table_data(&ss->smb2_srt_table, TRUE, TRUE);
}


static void
smb2stat_init(const char *opt_arg, void *userdata _U_)
{
	smb2stat_t *ss;
	guint32 i;
	const char *filter = NULL;
	GString *error_string;

	if (!strncmp(opt_arg, "smb2,srt,", 8)) {
		filter = opt_arg + 8;
	}

	ss = g_new(smb2stat_t, 1);

	init_srt_table("SMB2", &ss->smb2_srt_table, SMB2_NUM_PROCEDURES, "Commands", filter ? g_strdup(filter) : NULL);
	for (i = 0; i < SMB2_NUM_PROCEDURES; i++)
	{
		init_srt_table_row(&ss->smb2_srt_table, i, val_to_str_ext_const(i, &smb2_cmd_vals_ext, "<unknown>"));
	}

	error_string = register_tap_listener("smb2", ss, filter, 0, NULL, smb2stat_packet, smb2stat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		free_srt_table_data(&ss->smb2_srt_table);
		g_free(ss);

		fprintf(stderr, "tshark: Couldn't register smb2,srt tap: %s\n",
			error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui smb2stat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"smb2,srt",
	smb2stat_init,
	0,
	NULL
};

void
register_tap_listener_smb2stat(void)
{
	register_stat_tap_ui(&smb2stat_ui, NULL);
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
