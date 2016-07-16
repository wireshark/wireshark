/* packet-ip.h
 * Definitions for IP packet disassembly structures and routines
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


#ifndef __PACKET_IP_H__
#define __PACKET_IP_H__

#include "ws_symbol_export.h"

extern int proto_ip;

typedef struct _ws_ip
{
    guint8  ip_v_hl; /* combines ip_v and ip_hl */
    guint8  ip_tos;
    guint32 ip_len;
    guint16 ip_id;
    guint16 ip_off;
    guint8  ip_ttl;
    guint8  ip_nxt;  /* IPv4: protocol; IPv6: next header */
    guint16 ip_sum;
    address ip_src;
    address ip_dst;
} ws_ip;

/* Differentiated Services Codepoint  */
#define IPDSFIELD_DSCP_MASK     0xFC
#define IPDSFIELD_DSCP(dsfield) (((dsfield) & IPDSFIELD_DSCP_MASK) >> 2)

/* Explicit Congestion Notification */
#define IPDSFIELD_ECN_MASK      0x03
#define IPDSFIELD_ECN(dsfield)  ((dsfield) & IPDSFIELD_ECN_MASK)

gboolean capture_ip(const guchar *, int, int, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

gboolean ip_try_dissect(gboolean heur_first, tvbuff_t *tvb,
                        packet_info *pinfo, proto_tree *tree, ws_ip *iph);

/* Export the DSCP/ECN extended value-string table for other protocols */
WS_DLL_PUBLIC value_string_ext dscp_vals_ext;
WS_DLL_PUBLIC value_string_ext ecn_vals_ext;
WS_DLL_PUBLIC value_string_ext dscp_short_vals_ext;
WS_DLL_PUBLIC value_string_ext ecn_short_vals_ext;

#endif /* __PACKET_IP_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
