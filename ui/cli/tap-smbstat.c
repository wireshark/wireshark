/* tap-smbstat.c
 * smbstat   2003 Ronnie Sahlberg
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
#include <epan/dissectors/packet-smb.h>
#include "epan/timestats.h"

void register_tap_listener_smbstat(void);

#define SMB_NUM_PROCEDURES     256

/* used to keep track of the statistics for an entire program interface */
typedef struct _smbstat_t {
	srt_stat_table smb_srt_table;
	srt_stat_table trans2_srt_table;
	srt_stat_table nt_srt_table;
} smbstat_t;

static int
smbstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	smbstat_t *ss = (smbstat_t *)pss;
	const smb_info_t *si = (const smb_info_t *)psi;

	/* we are only interested in reply packets */
	if (si->request) {
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if (!si->sip) {
		return 0;
	}

	if (si->cmd == 0xA0 && si->sip->extra_info_type == SMB_EI_NTI) {
		smb_nt_transact_info_t *sti = (smb_nt_transact_info_t *)si->sip->extra_info;

		/*nt transaction*/
		if (sti) {
			add_srt_table_data(&ss->nt_srt_table, sti->subcmd, &si->sip->req_time, pinfo);
		}
	} else if (si->cmd == 0x32 && si->sip->extra_info_type == SMB_EI_T2I) {
		smb_transact2_info_t *st2i = (smb_transact2_info_t *)si->sip->extra_info;

		/*transaction2*/
		if (st2i) {
			add_srt_table_data(&ss->trans2_srt_table, st2i->subcmd, &si->sip->req_time, pinfo);
		}
	} else {
		add_srt_table_data(&ss->smb_srt_table,si->cmd, &si->sip->req_time, pinfo);
	}

	return 1;
}

static void
smbstat_draw(void *pss)
{
	smbstat_t *ss = (smbstat_t *)pss;

	draw_srt_table_data(&ss->smb_srt_table, TRUE, FALSE);
	printf("\n");
	draw_srt_table_data(&ss->trans2_srt_table, FALSE, FALSE);
	printf("\n");
	draw_srt_table_data(&ss->nt_srt_table, FALSE, TRUE);
}


static void
smbstat_init(const char *opt_arg, void *userdata _U_)
{
	smbstat_t *ss;
	guint32 i;
	const char *filter = NULL;
	GString *error_string;

	if (!strncmp(opt_arg, "smb,srt,", 8)) {
		filter = opt_arg + 8;
	}

	ss = g_new(smbstat_t, 1);

	init_srt_table("SMB", &ss->smb_srt_table, SMB_NUM_PROCEDURES, "Commands", filter ? g_strdup(filter) : NULL);
	init_srt_table("SMB", &ss->trans2_srt_table, SMB_NUM_PROCEDURES, "Transaction2 Commands", filter ? g_strdup(filter) : NULL);
	init_srt_table("SMB", &ss->nt_srt_table, SMB_NUM_PROCEDURES, "NT Transaction Commands", filter ? g_strdup(filter) : NULL);
	for (i = 0; i < SMB_NUM_PROCEDURES; i++)
	{
		init_srt_table_row(&ss->smb_srt_table, i, val_to_str_ext_const(i, &smb_cmd_vals_ext, "<unknown>"));
		init_srt_table_row(&ss->trans2_srt_table, i, val_to_str_ext_const(i, &trans2_cmd_vals_ext, "<unknown>"));
		init_srt_table_row(&ss->nt_srt_table, i, val_to_str_ext_const(i, &nt_cmd_vals_ext, "<unknown>"));
	}

	error_string = register_tap_listener("smb", ss, filter, 0, NULL, smbstat_packet, smbstat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		free_srt_table_data(&ss->smb_srt_table);
		free_srt_table_data(&ss->trans2_srt_table);
		free_srt_table_data(&ss->nt_srt_table);
		g_free(ss);

		fprintf(stderr, "tshark: Couldn't register smb,srt tap: %s\n",
			error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui smbstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"smb,srt",
	smbstat_init,
	0,
	NULL
};

void
register_tap_listener_smbstat(void)
{
	register_stat_tap_ui(&smbstat_ui, NULL);
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
