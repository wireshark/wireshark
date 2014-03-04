/* hostlist_ipv6.c   2009 Clif Bratcher
 * Modified from hostlist_ip.c   2004 Ian Schorr
 * modified from endpoint_talkers_ip.c   2003 Ronnie Sahlberg
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

#include <string.h>

#include <gtk/gtk.h>

#include "epan/packet.h"
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-ipv6.h>

#include "../stat_menu.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/hostlist_table.h"

void register_tap_listener_ipv6_hostlist(void);

static int
ipv6_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    hostlist_table *hosts = (hostlist_table *)pit;
    const struct ip6_hdr *ip6h = (const struct ip6_hdr *)vip;
    address src;
    address dst;

    /* Addresses aren't implemented as 'address' type in struct ip6_hdr */
    SET_ADDRESS(&src, AT_IPv6, sizeof(struct e_in6_addr), &ip6h->ip6_src);
    SET_ADDRESS(&dst, AT_IPv6, sizeof(struct e_in6_addr), &ip6h->ip6_dst);

    add_hostlist_table_data(hosts, &src, 0, TRUE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);
    add_hostlist_table_data(hosts, &dst, 0, FALSE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);

    return 1;
}


static void
gtk_ipv6_hostlist_init(const char *opt_arg, void* userdata _U_)
{
    const char *filter=NULL;

    if(!strncmp(opt_arg,"hosts,ipv6,",10)){
        filter = opt_arg + 10;
    } else {
        filter = NULL;
    }

    init_hostlist_table(TRUE, "IPv6", "ipv6", filter, ipv6_hostlist_packet);
}

void
gtk_ipv6_hostlist_cb(GtkAction *action _U_, gpointer user_data _U_)
{
    gtk_ipv6_hostlist_init("hosts,ipv6", NULL);
}

void
register_tap_listener_ipv6_hostlist(void)
{
    register_stat_cmd_arg("hosts,ipv6", gtk_ipv6_hostlist_init, NULL);
    register_hostlist_table(TRUE, "IPv6", "ipv6", NULL /*filter*/, ipv6_hostlist_packet);
}
