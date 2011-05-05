/* hostlist_ipv6.c   2009 Clif Bratcher
 * Modified from hostlist_ip.c   2004 Ian Schorr
 * modified from endpoint_talkers_ip.c   2003 Ronnie Sahlberg
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include "epan/packet.h"
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-ipv6.h>

#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/hostlist_table.h"
#include "gtk/stock_icons.h"

static int
ipv6_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    hostlist_table *hosts = (hostlist_table *)pit;
    const struct ip6_hdr *ip6h = vip;
    address src;
    address dst;

    /* Addresses aren't implemented as 'address' type in struct ip6_hdr */
    src.type = dst.type = AT_IPv6;
    src.len  = dst.len = sizeof(struct e_in6_addr);
    src.data = &ip6h->ip6_src;
    dst.data = &ip6h->ip6_dst;

    add_hostlist_table_data(hosts, &src, 0, TRUE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);
    add_hostlist_table_data(hosts, &dst, 0, FALSE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);

    return 1;
}


static void
gtk_ipv6_hostlist_init(const char *optarg, void* userdata _U_)
{
    const char *filter=NULL;

    if(!strncmp(optarg,"hosts,ipv6,",10)){
        filter = optarg + 10;
    } else {
        filter = NULL;
    }

    init_hostlist_table(TRUE, "IPv6", "ipv6", filter, ipv6_hostlist_packet);
}


static void
gtk_ipv6_hostlist_cb(GtkWidget *w _U_, gpointer d _U_)
{
    gtk_ipv6_hostlist_init("hosts,ipv6", NULL);
}


void
register_tap_listener_ipv6_hostlist(void)
{
    register_stat_cmd_arg("hosts,ipv6", gtk_ipv6_hostlist_init, NULL);

#ifdef MAIN_MENU_USE_UIMANAGER
	register_stat_menu_item_stock(
		REGISTER_STAT_GROUP_ENDPOINT_LIST,		/* Group */
		"/Menubar/StatisticsMenu/EndpointListMenu/Endpoint-List-item", /* GUI path */
		"IPv6",                             /* Name */
		WIRESHARK_STOCK_ENDPOINTS,          /* stock_id */
		"IPv6",                             /* label */
		NULL,                               /* accelerator */
		NULL,                               /* tooltip */
		G_CALLBACK(gtk_ipv6_hostlist_cb),   /* callback */
		TRUE,                               /* enabled */
		NULL,                               /* selected_packet_enabled */
		NULL,                               /* selected_tree_row_enabled */
		NULL);                              /* callback_data */

#else
    register_stat_menu_item("IPv6", REGISTER_STAT_GROUP_ENDPOINT_LIST,
        gtk_ipv6_hostlist_cb, NULL, NULL, NULL);
#endif
    register_hostlist_table(TRUE, "IPv6", "ipv6", NULL /*filter*/, ipv6_hostlist_packet);
}
