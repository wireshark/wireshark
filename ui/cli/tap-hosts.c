/* tap-hosts.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Dump our collected IPv4- and IPv6-to-hostname mappings */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "globals.h"

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/addr_resolv.h>

#include <ui/cmdarg_err.h>

void register_tap_listener_hosts(void);

static gboolean dump_v4 = FALSE;
static gboolean dump_v6 = FALSE;

#define TAP_NAME "hosts"

static void
ipv4_hash_table_print_resolved(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	hashipv4_t *ipv4_hash_table_entry = (hashipv4_t *)value;

	if ((ipv4_hash_table_entry->flags & NAME_RESOLVED)) {
		printf("%s\t%s\n",
		       ipv4_hash_table_entry->ip,
		       ipv4_hash_table_entry->name);
	}
}

static void
ipv6_hash_table_print_resolved(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	hashipv6_t *ipv6_hash_table_entry = (hashipv6_t *)value;

	if ((ipv6_hash_table_entry->flags & NAME_RESOLVED)) {
		printf("%s\t%s\n",
		       ipv6_hash_table_entry->ip6,
		       ipv6_hash_table_entry->name);
	}
}

static void
hosts_draw(void *dummy _U_)
{

	wmem_map_t *ipv4_hash_table;
	wmem_map_t *ipv6_hash_table;

	printf("# TShark hosts output\n");
	printf("#\n");
	printf("# Host data gathered from %s\n",
	    cfile.is_tempfile ? "the temporary capture file" : cfile.filename);
	printf("\n");

	if (dump_v4) {
		ipv4_hash_table = get_ipv4_hash_table();
		if (ipv4_hash_table) {
			wmem_map_foreach( ipv4_hash_table, ipv4_hash_table_print_resolved, NULL);
		}
	}

	if (dump_v6) {
		ipv6_hash_table = get_ipv6_hash_table();
		if (ipv6_hash_table) {
			wmem_map_foreach( ipv6_hash_table, ipv6_hash_table_print_resolved, NULL);
		}
	}

}


static void
hosts_init(const char *opt_arg, void *userdata _U_)
{
	GString *error_string;
	gchar **tokens;
	gint opt_count;

	dump_v4 = FALSE;
	dump_v6 = FALSE;

	if (strcmp(TAP_NAME, opt_arg) == 0) {
		/* No arguments; dump everything */
		dump_v4 = TRUE;
		dump_v6 = TRUE;
	} else {
		tokens = g_strsplit(opt_arg, ",", 0);
		opt_count = 0;
		while (tokens[opt_count]) {
			if ((strcmp("ipv4", tokens[opt_count]) == 0) ||
				(strcmp("ip", tokens[opt_count]) == 0)) {
				dump_v4 = TRUE;
			} else if (strcmp("ipv6", tokens[opt_count]) == 0) {
				dump_v6 = TRUE;
			} else if (opt_count > 0) {
				cmdarg_err("invalid \"-z " TAP_NAME "[,ip|ipv4|ipv6]\" argument");
				exit(1);
			}
			opt_count++;
		}
		g_strfreev(tokens);
	}

	error_string = register_tap_listener("frame", NULL, NULL, TL_REQUIRES_PROTO_TREE,
					   NULL, NULL, hosts_draw, NULL);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		cmdarg_err("Couldn't register " TAP_NAME " tap: %s",
			error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui hosts_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	TAP_NAME,
	hosts_init,
	0,
	NULL
};

void
register_tap_listener_hosts(void)
{
	register_stat_tap_ui(&hosts_ui, NULL);
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
