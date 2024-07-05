/* tap-protohierstat.c
 * protohierstat   2002 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This module provides ProtocolHierarchyStatistics for tshark */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epan/epan_dissect.h"
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>

#include <wsutil/cmdarg_err.h>
#include "tap-protohierstat.h"

int pc_proto_id = -1;

void register_tap_listener_protohierstat(void);

phs_t *
new_phs_t(phs_t *parent, const char *filter)
{
	phs_t *rs;
	rs = g_new(phs_t, 1);
	rs->sibling    = NULL;
	rs->child      = NULL;
	rs->parent     = parent;
	rs->filter     = NULL;
	if (filter != NULL) {
		rs->filter = g_strdup(filter);
	}
	rs->protocol   = -1;
	rs->proto_name = NULL;
	rs->frames     = 0;
	rs->bytes      = 0;
	return rs;
}

void
free_phs(phs_t *rs)
{
	if (!rs) {
		return;
	}
	if (rs->filter) {
		g_free(rs->filter);
		rs->filter = NULL;
	}
	if (rs->sibling)
	{
		free_phs(rs->sibling);
		rs->sibling = NULL;
	}
	if (rs->child)
	{
		free_phs(rs->child);
		rs->child = NULL;
	}
	g_free(rs);
}

tap_packet_status
protohierstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_)
{
	phs_t *rs = (phs_t *)prs;
	phs_t *tmprs;
	proto_node *node;
	field_info *fi;

	if (!edt) {
		return TAP_PACKET_DONT_REDRAW;
	}
	if (!edt->tree) {
		return TAP_PACKET_DONT_REDRAW;
	}
	if (!edt->tree->first_child) {
		return TAP_PACKET_DONT_REDRAW;
	}

	for (node=edt->tree->first_child; node; node=node->next) {
		fi = PNODE_FINFO(node);

		/*
		 * If the first child is a tree of comments, skip over it.
		 * This keeps us from having a top-level "pkt_comment"
		 * entry that represents a nonexistent protocol,
		 * and matches how the GUI treats comments.
		 */
		if (G_UNLIKELY(fi->hfinfo->id == pc_proto_id)) {
			continue;
		}

		/* first time we saw a protocol at this leaf */
		if (rs->protocol == -1) {
			rs->protocol = fi->hfinfo->id;
			rs->proto_name = fi->hfinfo->abbrev;
			rs->frames = 1;
			rs->bytes = pinfo->fd->pkt_len;
			rs->child = new_phs_t(rs, NULL);
			rs = rs->child;
			continue;
		}

		/* find this protocol in the list of siblings */
		for (tmprs=rs; tmprs; tmprs=tmprs->sibling) {
			if (tmprs->protocol == fi->hfinfo->id) {
				break;
			}
		}

		/* not found, then we must add it to the end of the list */
		if (!tmprs) {
			for (tmprs=rs; tmprs->sibling; tmprs=tmprs->sibling)
				;
			tmprs->sibling = new_phs_t(rs->parent, NULL);
			rs = tmprs->sibling;
			rs->protocol = fi->hfinfo->id;
			rs->proto_name = fi->hfinfo->abbrev;
		} else {
			rs = tmprs;
		}

		rs->frames++;
		rs->bytes += pinfo->fd->pkt_len;

		if (!rs->child) {
			rs->child = new_phs_t(rs, NULL);
		}
		rs = rs->child;
	}
	return TAP_PACKET_REDRAW;
}

static void
phs_draw(phs_t *rs, int indentation)
{
	int i, stroff;
#define MAXPHSLINE 80
	char str[MAXPHSLINE];
	for (;rs;rs = rs->sibling) {
		if (rs->protocol == -1) {
			return;
		}
		str[0] = 0;
		stroff = 0;
		for (i=0; i<indentation; i++) {
			if (i > 15) {
				stroff += snprintf(str+stroff, MAXPHSLINE-stroff, "...");
				break;
			}
			stroff += snprintf(str+stroff, MAXPHSLINE-stroff, "  ");
		}
		snprintf(str+stroff, MAXPHSLINE-stroff, "%s", rs->proto_name);
		printf("%-40s frames:%u bytes:%" PRIu64 "\n", str, rs->frames, rs->bytes);
		phs_draw(rs->child, indentation+1);
	}
}

static void
protohierstat_draw(void *prs)
{
	phs_t *rs = (phs_t *)prs;

	printf("\n");
	printf("===================================================================\n");
	printf("Protocol Hierarchy Statistics\n");
	printf("Filter: %s\n\n", rs->filter ? rs->filter : "");
	phs_draw(rs, 0);
	printf("===================================================================\n");
}


static void
protohierstat_init(const char *opt_arg, void *userdata _U_)
{
	phs_t *rs;
	int pos = 0;
	const char *filter = NULL;
	GString *error_string;

	if (strcmp("io,phs", opt_arg) == 0) {
		/* No arguments */
	} else if (sscanf(opt_arg, "io,phs,%n", &pos) == 0) {
		if (pos) {
			filter = opt_arg+pos;
		}
	} else {
		cmdarg_err("invalid \"-z io,phs[,<filter>]\" argument");
		exit(1);
	}

	pc_proto_id = proto_registrar_get_id_byname("pkt_comment");

	rs = new_phs_t(NULL, filter);

	error_string = register_tap_listener("frame", rs, filter, TL_REQUIRES_PROTO_TREE, NULL, protohierstat_packet, protohierstat_draw, NULL);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		free_phs(rs);

		cmdarg_err("Couldn't register io,phs tap: %s",
			error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui protohierstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"io,phs",
	protohierstat_init,
	0,
	NULL
};

void
register_tap_listener_protohierstat(void)
{
	register_stat_tap_ui(&protohierstat_ui, NULL);
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
