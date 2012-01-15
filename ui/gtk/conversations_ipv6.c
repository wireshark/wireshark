/* conversations_ipv6.c   2009 Clif Bratcher
 * Modified from conversations_ip   2003 Ronnie Sahlberg
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-ipv6.h>

#include "../stat_menu.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/conversations_table.h"

static int
ipv6_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    const struct ip6_hdr *ip6h = vip;
    address src;
    address dst;

    /* Addresses aren't implemented as 'address' type in struct ip6_hdr */
    src.type = dst.type = AT_IPv6;
    src.len  = dst.len = sizeof(struct e_in6_addr);
    src.data = &ip6h->ip6_src;
    dst.data = &ip6h->ip6_dst;

    add_conversation_table_data((conversations_table *)pct, &src, &dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->fd->rel_ts, SAT_NONE, PT_NONE);

    return 1;
}


static void
ipv6_conversation_init(const char *optarg, void *userdata _U_)
{
    const char *filter=NULL;

    if(!strncmp(optarg, "conv,ipv6,", 10)) {
        filter = optarg + 10;
    }
    else {
        filter = NULL;
    }

    init_conversation_table(TRUE, "IPv6", "ipv6", filter, ipv6_conversation_packet);
}

void
ipv6_endpoints_cb(GtkAction *action _U_, gpointer user_data _U_)
{
    ipv6_conversation_init("conv,ipv6", NULL);
}

void
register_tap_listener_ipv6_conversation(void)
{
    register_stat_cmd_arg("conv,ipv6", ipv6_conversation_init, NULL);
    register_conversation_table(TRUE, "IPv6", "ipv6", NULL /*filter*/, ipv6_conversation_packet);
}
