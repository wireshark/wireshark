/* tap-hosts.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Dump our collected IPv4- and IPv6-to-hostname mappings */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include "globals.h"

#include <epan/packet.h>
#include <cfile.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/addr_resolv.h>

/* Needed for addrinfo */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#if defined(_WIN32) && defined(INET6)
# include <ws2tcpip.h>
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif


gboolean dump_v4 = FALSE;
gboolean dump_v6 = FALSE;

#define TAP_NAME "hosts"

#define HOSTNAME_POS 48
#define ADDRSTRLEN 46 /* Covers IPv4 & IPv6 */
static void
hosts_draw(void *dummy _U_)
{
	struct addrinfo *ai;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	char   addr_str[ADDRSTRLEN];
	int i, tab_count;

	printf("# TShark hosts output\n");
	printf("#\n");
	printf("# Host data gathered from %s\n", cfile.filename);
	printf("\n");

	/* Dump the v4 addresses first, then v6 */
	for (ai = get_addrinfo_list(); ai; ai = ai->ai_next) {
		if (!dump_v4 || ai->ai_family != AF_INET) {
			continue;
		}

		sa4 = (struct sockaddr_in *)(void *)ai->ai_addr;
		if (inet_ntop(AF_INET, &(sa4->sin_addr.s_addr), addr_str, ADDRSTRLEN)) {
			tab_count = (HOSTNAME_POS - (int)strlen(addr_str)) / 8;
			printf("%s", addr_str);
			for (i = 0; i < tab_count; i++)
				printf("\t");
			printf("%s\n", ai->ai_canonname);
		}
	}


	for (ai = get_addrinfo_list(); ai; ai = ai->ai_next) {
		if (!dump_v6 || ai->ai_family != AF_INET6) {
			continue;
		}

		sa6 = (struct sockaddr_in6 *)(void *)ai->ai_addr;
		if (inet_ntop(AF_INET6, sa6->sin6_addr.s6_addr, addr_str, ADDRSTRLEN)) {
			tab_count = (HOSTNAME_POS - (int)strlen(addr_str)) / 8;
			printf("%s", addr_str);
			for (i = 0; i < tab_count; i++)
				printf("\t");
			printf("%s\n", ai->ai_canonname);
		}
	}
}


static void
hosts_init(const char *optarg, void* userdata _U_)
{
	GString *error_string;
	gchar **tokens;
	gint opt_count;

	dump_v4 = FALSE;
	dump_v6 = FALSE;

	if(strcmp(TAP_NAME, optarg)==0) {
		/* No arguments; dump everything */
		dump_v4 = TRUE;
		dump_v6 = TRUE;
	} else {
		tokens = g_strsplit(optarg,",", 0);
		opt_count=0;
		while (tokens[opt_count]) {
			if (strcmp("ipv4", tokens[opt_count]) == 0) {
				dump_v4 = TRUE;
			} else if (strcmp("ipv6", tokens[opt_count]) == 0) {
				dump_v6 = TRUE;
			} else if (opt_count > 0) {
				fprintf(stderr, "tshark: invalid \"-z " TAP_NAME "[,ipv4|ipv6]\" argument\n");
				exit(1);
			}
			opt_count++;
		}
		g_strfreev(tokens);
	}

	error_string=register_tap_listener("frame", NULL, NULL, TL_REQUIRES_PROTO_TREE,
					   NULL, NULL, hosts_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		fprintf(stderr, "tshark: Couldn't register " TAP_NAME " tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

void
register_tap_listener_hosts(void)
{
	register_stat_cmd_arg(TAP_NAME, hosts_init, NULL);
}

