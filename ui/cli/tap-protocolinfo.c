/* tap-protocolinfo.c
 * protohierstat   2002 Ronnie Sahlberg
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

/* This module provides Protocol Column Info tap for tshark */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epan/epan_dissect.h"
#include "epan/column-utils.h"
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>

void register_tap_listener_protocolinfo(void);

typedef struct _pci_t {
	char *filter;
	int hf_index;
} pci_t;


static int
protocolinfo_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
	pci_t *rs = (pci_t *)prs;
	GPtrArray *gp;
	guint i;
	char *str;

	/*
	 * XXX - there needs to be a way for "protocolinfo_init()" to
	 * find out whether the columns are being generated and, if not,
	 * to report an error and exit, as the whole point of this tap
	 * is to modify the columns, and if the columns aren't being
	 * displayed, that makes this tap somewhat pointless.
	 *
	 * To prevent a crash, we check whether INFO column is writable
	 * and, if not, we report that error and exit.
	 */
	if (!col_get_writable(pinfo->cinfo, COL_INFO)) {
		fprintf(stderr, "tshark: the proto,colinfo tap doesn't work if the INFO column isn't being printed.\n");
		exit(1);
	}
	gp = proto_get_finfo_ptr_array(edt->tree, rs->hf_index);
	if (!gp) {
		return 0;
	}

	for (i=0; i<gp->len; i++) {
		str = (char *)proto_construct_match_selected_string((field_info *)gp->pdata[i], NULL);
		if (str) {
			col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", str);
			wmem_free(NULL, str);
		}
	}
	return 0;
}



static void
protocolinfo_init(const char *opt_arg, void *userdata _U_)
{
	pci_t *rs;
	const char *field = NULL;
	const char *filter = NULL;
	header_field_info *hfi;
	GString *error_string;

	if (!strncmp("proto,colinfo,", opt_arg, 14)) {
		filter = opt_arg+14;
		field = strchr(filter, ',');
		if (field) {
			field += 1;  /* skip the ',' */
		}
	}
	if (!field) {
		fprintf(stderr, "tshark: invalid \"-z proto,colinfo,<filter>,<field>\" argument\n");
		exit(1);
	}

	hfi = proto_registrar_get_byname(field);
	if (!hfi) {
		fprintf(stderr, "tshark: Field \"%s\" doesn't exist.\n", field);
		exit(1);
	}

	rs = g_new(pci_t, 1);
	rs->hf_index = hfi->id;
	if ((field-filter) > 1) {
		rs->filter = (char *)g_malloc(field-filter);
		g_strlcpy(rs->filter, filter, (field-filter));
	} else {
		rs->filter = NULL;
	}

	error_string = register_tap_listener("frame", rs, rs->filter, TL_REQUIRES_PROTO_TREE, NULL, protocolinfo_packet, NULL);
	if (error_string) {
		/* error, we failed to attach to the tap. complain and clean up */
		fprintf(stderr, "tshark: Couldn't register proto,colinfo tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		g_free(rs->filter);
		g_free(rs);

		exit(1);
	}
}

static stat_tap_ui protocolinfo_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"proto,colinfo",
	protocolinfo_init,
	0,
	NULL
};

void
register_tap_listener_protocolinfo(void)
{
	register_stat_tap_ui(&protocolinfo_ui, NULL);
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
