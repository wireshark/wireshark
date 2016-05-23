/* interface.c
 * Utility functions to get infos from interfaces
 *
 * Copyright 2016, Dario Lombardo
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

#include "interface.h"

#include <string.h>
#include <wsutil/inet_addr.h>

#ifdef HAVE_SYS_TYPES_H
    #include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
    #include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
    #include <arpa/inet.h>
#endif

#ifdef HAVE_IFADDRS_H
    #include <ifaddrs.h>
#endif

GSList *local_interfaces_to_list(void)
{
    GSList *interfaces = NULL;
#ifdef HAVE_GETIFADDRS
    struct ifaddrs *ifap;
    struct ifaddrs *ifa;
    int family;
    char ip[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifap)) {
	goto end;
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
	if (ifa->ifa_addr == NULL)
	    continue;

	family = ifa->ifa_addr->sa_family;

	memset(ip, 0x0, INET6_ADDRSTRLEN);

	switch (family) {
	    case AF_INET:
		{
		    struct sockaddr_in *addr4 = (struct sockaddr_in *)ifa->ifa_addr;
		    ws_inet_ntop4(&addr4->sin_addr, ip, sizeof(ip));
		    break;
		}

	    case AF_INET6:
		{
		    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		    ws_inet_ntop6(&addr6->sin6_addr, ip, sizeof(ip));
		    break;
		}

	    default:
		break;
	}

	/* skip loopback addresses */
	if (!g_strcmp0(ip, "127.0.0.1") || !g_strcmp0(ip, "::1"))
	    continue;

	if (*ip) {
	    interfaces = g_slist_prepend(interfaces, g_strdup(ip));
	}
    }
    freeifaddrs(ifap);
end:
#endif /* HAVE_GETIFADDRS */
    return interfaces;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
