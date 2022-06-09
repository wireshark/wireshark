/* tap-protocolinfo.c
 * protohierstat   2002 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <ui/cmdarg_err.h>

void register_tap_listener_protocolinfo(void);

typedef struct _pci_t {
	char *filter;
	int hf_index;
} pci_t;


static tap_packet_status
protocolinfo_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_)
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
	 *
	 * XXX - report the error and just return TAP_PACKET_FAILED?
	 */
	if (!col_get_writable(pinfo->cinfo, COL_INFO)) {
		cmdarg_err("the proto,colinfo tap doesn't work if the INFO column isn't being printed.");
		exit(1);
	}
	gp = proto_get_finfo_ptr_array(edt->tree, rs->hf_index);
	if (!gp) {
		return TAP_PACKET_DONT_REDRAW;
	}

	for (i=0; i<gp->len; i++) {
		str = (char *)proto_construct_match_selected_string((field_info *)gp->pdata[i], NULL);
		if (str) {
			col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", str);
			wmem_free(NULL, str);
		}
	}
	return TAP_PACKET_DONT_REDRAW;
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
		cmdarg_err("invalid \"-z proto,colinfo,<filter>,<field>\" argument");
		exit(1);
	}

	hfi = proto_registrar_get_byname(field);
	if (!hfi) {
		cmdarg_err("Field \"%s\" doesn't exist.", field);
		exit(1);
	}

	rs = g_new(pci_t, 1);
	rs->hf_index = hfi->id;
	if ((field-filter) > 1) {
		rs->filter = (char *)g_malloc(field-filter);
		(void) g_strlcpy(rs->filter, filter, (field-filter));
	} else {
		rs->filter = NULL;
	}

	error_string = register_tap_listener("frame", rs, rs->filter, TL_REQUIRES_PROTO_TREE, NULL, protocolinfo_packet, NULL, NULL);
	if (error_string) {
		/* error, we failed to attach to the tap. complain and clean up */
		cmdarg_err("Couldn't register proto,colinfo tap: %s",
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
