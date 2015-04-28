/* tap-ldapstat.c
 *
 * Based on afpstat
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
#include <epan/dissectors/packet-ldap.h>
#include "epan/timestats.h"

void register_tap_listener_ldapstat(void);

#define LDAP_NUM_PROCEDURES     24

/* used to keep track of the statistics for an entire program interface */
typedef struct _ldapstat_t {
	srt_stat_table ldap_srt_table;
} ldapstat_t;

static int
ldapstat_packet(void *pldap, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	const ldap_call_response_t *ldap=(const ldap_call_response_t *)psi;
	ldapstat_t *fs=(ldapstat_t *)pldap;

	/* we are only interested in reply packets */
	if(ldap->is_request){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!ldap->req_frame){
		return 0;
	}

	/* only use the commands we know how to handle */
	switch(ldap->protocolOpTag){
	case LDAP_REQ_BIND:
	case LDAP_REQ_SEARCH:
	case LDAP_REQ_MODIFY:
	case LDAP_REQ_ADD:
	case LDAP_REQ_DELETE:
	case LDAP_REQ_MODRDN:
	case LDAP_REQ_COMPARE:
	case LDAP_REQ_EXTENDED:
		break;
	default:
		return 0;
	}

	add_srt_table_data(&fs->ldap_srt_table, ldap->protocolOpTag, &ldap->req_time, pinfo);
	return 1;
}

static void
ldapstat_draw(void *pss)
{
	ldapstat_t *ss = (ldapstat_t *)pss;

	draw_srt_table_data(&ss->ldap_srt_table, TRUE, TRUE);
}


static void
ldapstat_init(const char *opt_arg, void *userdata _U_)
{
	ldapstat_t *ldap;
	const char *filter = NULL;
	GString *error_string;
	int i;

	if (!strncmp(opt_arg, "ldap,srt,", 9)) {
		filter = opt_arg+8;
	}

	ldap = g_new(ldapstat_t,1);

	init_srt_table("LDAP", &ldap->ldap_srt_table, LDAP_NUM_PROCEDURES, NULL, filter ? g_strdup(filter) : NULL);
	for (i = 0; i < LDAP_NUM_PROCEDURES; i++)
	{
		init_srt_table_row(&ldap->ldap_srt_table, i, val_to_str_const(i, ldap_procedure_names, "<unknown>"));
	}

	error_string = register_tap_listener("ldap", ldap, filter, 0, NULL, ldapstat_packet, ldapstat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		free_srt_table_data(&ldap->ldap_srt_table);
		g_free(ldap);

		fprintf(stderr, "tshark: Couldn't register ldap,srt tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui ldapstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"ldap,srt",
	ldapstat_init,
	0,
	NULL
};

void
register_tap_listener_ldapstat(void)
{
	register_stat_tap_ui(&ldapstat_ui, NULL);
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
