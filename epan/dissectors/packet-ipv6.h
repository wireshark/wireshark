/* packet-ipv6.h
 * Definitions for IPv6 packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
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

#ifndef __PACKET_IPV6_H_DEFINED__
#define __PACKET_IPV6_H_DEFINED__

#include <epan/ipv6.h>
#include "packet-ip.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef ws_ip ipv6_ws_tap_info_t;

/* Packet info for IPv6 header and extensions */
typedef struct {
    guint32     jumbo_plen;
    guint16     ip6_plen;
    gint        frag_plen;
    proto_tree *ipv6_tree;
    gint        ipv6_item_len;
} ipv6_pinfo_t;

ipv6_pinfo_t *p_get_ipv6_pinfo(packet_info *pinfo);

void ipv6_dissect_next(guint nxt, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ws_ip *iph);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_IPV6_H_DEFINED__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
