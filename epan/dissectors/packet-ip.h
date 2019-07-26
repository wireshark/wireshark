/* packet-ip.h
 * Definitions for IP packet disassembly structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __PACKET_IP_H__
#define __PACKET_IP_H__

#include "ws_symbol_export.h"

/*
 * IP Version numbers, from
 *
 *  https://www.iana.org/assignments/version-numbers/version-numbers.xhtml
 */
#define IP_VERSION_NUM_RESERVED          0       /* Reserved */
#define IP_VERSION_NUM_INET              4       /* IP (IP version 4)           */
#define IP_VERSION_NUM_ST                5       /* ST Datagram Mode            */
#define IP_VERSION_NUM_INET6             6       /* IP6 (IP version 6)          */
#define IP_VERSION_NUM_TPIX              7       /* TP/IX: The Next Internet    */
#define IP_VERSION_NUM_PIP               8       /* The P Internet Protocol     */
#define IP_VERSION_NUM_TUBA              9       /* TUBA     */

extern const value_string ip_version_vals[];

typedef struct _ws_ip4
{
    guint8  ip_ver;     /* 4 */
    guint8  ip_tos;     /* type of service */
    guint32 ip_len;     /* total length */
    guint16 ip_id;      /* identification */
    guint16 ip_off;     /* fragment offset */
    guint8  ip_ttl;     /* time-to-live */
    guint8  ip_proto;   /* protocol */
    guint16 ip_sum;     /* checksum */
    address ip_src;     /* source address */
    address ip_dst;     /* destination address */
} ws_ip4;

#define WS_IP4_PTR(p)         ((ws_ip4 *)(((p) && *(guint8 *)(p) == 4) ? (p) : NULL))

/* Differentiated Services Codepoint  */
#define IPDSFIELD_DSCP_MASK     0xFC
#define IPDSFIELD_DSCP(dsfield) (((dsfield) & IPDSFIELD_DSCP_MASK) >> 2)

/* Explicit Congestion Notification */
#define IPDSFIELD_ECN_MASK      0x03
#define IPDSFIELD_ECN(dsfield)  ((dsfield) & IPDSFIELD_ECN_MASK)

gboolean ip_try_dissect(gboolean heur_first, guint nxt, tvbuff_t *tvb,
                        packet_info *pinfo, proto_tree *tree, void *iph);

/* Export the DSCP/ECN extended value-string table for other protocols */
WS_DLL_PUBLIC value_string_ext dscp_vals_ext;
WS_DLL_PUBLIC value_string_ext ecn_vals_ext;
WS_DLL_PUBLIC value_string_ext dscp_short_vals_ext;
WS_DLL_PUBLIC value_string_ext ecn_short_vals_ext;

typedef struct _ws_ip6
{
    guint8  ip6_ver;     /* 6 */
    guint8  ip6_tc;      /* traffic class */
    guint32 ip6_flw;     /* flow label */
    guint32 ip6_len;     /* payload length */
    guint8  ip6_nxt;     /* next header */
    guint8  ip6_hop;     /* hop limit */
    address ip6_src;     /* source address */
    address ip6_dst;     /* destination address */
} ws_ip6;

#define WS_IP6_PTR(p)         ((ws_ip6 *)(((p) && *(guint8 *)(p) == 6) ? (p) : NULL))

struct ws_rthdr {
    struct ip6_rthdr hdr;
    proto_item *ti_len;
    proto_item *ti_type;
    proto_item *ti_segleft;
};

typedef ws_ip6 ipv6_tap_info_t;

/* Packet info for shared state between IPv6 header and extensions.
 *
 * frag_plen: This is the IPv6 header payload length of a fragment packet
 * minus per-fragment *extension* headers (anything up to and including the
 * Fragment extension header).
 *
 * See RFC 8200 Section 4.5:
 *   The Per-Fragment headers must consist of the IPv6 header plus any
 *   extension headers that must be processed by nodes en route to the
 *   destination, that is, all headers up to and including the Routing
 *   header if present, else the Hop-by-Hop Options header if present,
 *   else no extension headers.
 */
typedef struct {
    guint32     jumbo_plen;
    guint16     ip6_plen;       /* header payload length (can be zero) */
    gint        frag_plen;
    proto_tree *ipv6_tree;
    gint        ipv6_item_len;
} ipv6_pinfo_t;

ipv6_pinfo_t *p_get_ipv6_pinfo(packet_info *pinfo);

proto_tree *p_ipv6_pinfo_select_root(packet_info *pinfo, proto_tree *tree);

ipv6_pinfo_t *p_ipv6_pinfo_add_len(packet_info *pinfo, int exthdr_len);

void ipv6_dissect_next(guint nxt, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ws_ip6 *iph);

static inline int
ws_ip_protocol(void *iph)
{
    ws_ip4 *ip4;
    ws_ip6 *ip6;

    if (iph != NULL) {
        if ((ip4 = WS_IP4_PTR(iph)) != NULL)
            return ip4->ip_proto;
        if ((ip6 = WS_IP6_PTR(iph)) != NULL)
            return ip6->ip6_nxt;
    }
    return -1;
}

#endif /* __PACKET_IP_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
