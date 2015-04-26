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
#include <epan/value_string.h>
#include <epan/dissectors/packet-ldap.h>
#include "epan/timestats.h"

void register_tap_listener_ldapstat(void);

#define LDAP_NUM_PROCEDURES     24

#define NANOSECS_PER_SEC G_GUINT64_CONSTANT(1000000000)

/* used to keep track of the statistics for an entire program interface */
typedef struct _ldapstat_t {
	char *filter;
	timestat_t proc[LDAP_NUM_PROCEDURES];
} ldapstat_t;

static int
ldapstat_packet(void *pldap, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	const ldap_call_response_t *ldap=(const ldap_call_response_t *)psi;
	ldapstat_t *fs=(ldapstat_t *)pldap;
	timestat_t *sp = NULL;
	nstime_t t, deltat;

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

	sp = &(fs->proc[ldap->protocolOpTag]);

	/* calculate time delta between request and reply */
	t = pinfo->fd->abs_ts;
	nstime_delta(&deltat, &t, &ldap->req_time);

	if (sp) {
		time_stat_update(sp, &deltat, pinfo);
	}
	return 1;
}

static void
ldapstat_draw(void *pss)
{
	ldapstat_t *ss = (ldapstat_t *)pss;
	guint32 i;
	guint64 td, sum;
	gchar* tmp_str;
	printf("\n");
	printf("===================================================================\n");
	printf("LDAP SRT Statistics:\n");
	printf("Filter: %s\n", ss->filter ? ss->filter : "");
	printf("Index  Procedure             Calls   Min SRT   Max SRT   Avg SRT    Sum SRT\n");
	for (i=0; i<LDAP_NUM_PROCEDURES; i++) {
		/* nothing seen, nothing to do */
		if (ss->proc[i].num == 0) {
			continue;
		}

		/* Scale the average SRT in units of 1us and round to the nearest us.
		   tot.secs is a time_t which may be 32 or 64 bits (or even floating)
		   depending uon the platform.  After casting tot.secs to 64 bits, it
		   would take a capture with a duration of over 136 *years* to
		   overflow the secs portion of td. */
		td = ((guint64)(ss->proc[i].tot.secs))*NANOSECS_PER_SEC + ss->proc[i].tot.nsecs;
		sum = (td + 500) / 1000;
		td = ((td / ss->proc[i].num) + 500) / 1000;

		tmp_str = val_to_str_wmem(NULL, i, ldap_procedure_names, "Unknown (%u)");
		printf("%5u  %-20s %6u %3d.%06d %3d.%06d %3d.%06d %3d.%06d\n",
		       i, tmp_str,
		       ss->proc[i].num,
		       (int)ss->proc[i].min.secs, (ss->proc[i].min.nsecs+500)/1000,
		       (int)ss->proc[i].max.secs, (ss->proc[i].max.nsecs+500)/1000,
		       (int)(td/1000000), (int)(td%1000000),
		       (int)(sum/1000000), (int)(sum%1000000)
		);
		wmem_free(NULL, tmp_str);
	}
	printf("===================================================================\n");
}


static void
ldapstat_init(const char *opt_arg, void *userdata _U_)
{
	ldapstat_t *ldap;
	const char *filter = NULL;
	GString *error_string;

	if (!strncmp(opt_arg, "ldap,srt,", 8)) {
		filter = opt_arg+8;
	}

	ldap=(ldapstat_t *)g_malloc0(sizeof(ldapstat_t));
	if (filter) {
		ldap->filter = g_strdup(filter);
	}

	error_string = register_tap_listener("ldap", ldap, filter, 0, NULL, ldapstat_packet, ldapstat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		g_free(ldap->filter);
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
