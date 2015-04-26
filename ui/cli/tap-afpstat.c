/* tap-afpstat.c
 * Based on
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

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <ui/cli/cli_service_response_time_table.h>
#include <epan/value_string.h>
#include <epan/dissectors/packet-afp.h>
#include "epan/timestats.h"

void register_tap_listener_afpstat(void);

#define AFP_NUM_PROCEDURES     256

/* used to keep track of the statistics for an entire program interface */
typedef struct _afpstat_t {
	srt_stat_table afp_srt_table;
} afpstat_t;

static int
afpstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv)
{
	afpstat_t *ss = (afpstat_t *)pss;
	const afp_request_val *request_val = (const afp_request_val *)prv;

	/* if we havnt seen the request, just ignore it */
	if (!request_val) {
		return 0;
	}

	add_srt_table_data(&ss->afp_srt_table, request_val->command, &request_val->req_time, pinfo);

	return 1;
}

static void
afpstat_draw(void *pss)
{
	afpstat_t *ss = (afpstat_t *)pss;

	draw_srt_table_data(&ss->afp_srt_table, TRUE, TRUE);
}


static void
afpstat_init(const char *opt_arg, void *userdata _U_)
{
	afpstat_t *ss;
	guint32 i;
	const char *filter = NULL;
	GString *error_string;

	if (!strncmp(opt_arg, "afp,srt,", 8)) {
		filter = opt_arg+8;
	}

	ss = g_new(afpstat_t, 1);

	init_srt_table("AFP", &ss->afp_srt_table, AFP_NUM_PROCEDURES, NULL, filter ? g_strdup(filter) : NULL);
	for (i = 0; i < AFP_NUM_PROCEDURES; i++)
	{
		gchar* tmp_str = val_to_str_ext_wmem(NULL, i, &CommandCode_vals_ext, "Unknown(%u)");
		init_srt_table_row(&ss->afp_srt_table, i, tmp_str);
		wmem_free(NULL, tmp_str);
	}

	error_string = register_tap_listener("afp", ss, filter, 0, NULL, afpstat_packet, afpstat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		free_srt_table_data(&ss->afp_srt_table);
		g_free(ss);

		fprintf(stderr, "tshark: Couldn't register afp,srt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui afpstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"afp,srt",
	afpstat_init,
	0,
	NULL
};

void
register_tap_listener_afpstat(void)
{
	register_stat_tap_ui(&afpstat_ui, NULL);
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
