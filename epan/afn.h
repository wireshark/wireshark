/* afn.h
 * RFC 1700 address family numbers
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __AFN_H__
#define __AFN_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Address family numbers, from
 *
 *  http://www.iana.org/assignments/address-family-numbers
 */
#define AFNUM_RESERVED          0       /* Reserved */
#define AFNUM_INET              1       /* IP (IP version 4) */
#define AFNUM_INET6             2       /* IP6 (IP version 6) */
#define AFNUM_NSAP              3       /* NSAP */
#define AFNUM_HDLC              4       /* HDLC (8-bit multidrop) */
#define AFNUM_BBN1822           5       /* BBN 1822 */
#define AFNUM_802               6       /* 802 (includes all 802 media plus Ethernet "canonical format") */
#define AFNUM_E163              7       /* E.163 */
#define AFNUM_E164              8       /* E.164 (SMDS, Frame Relay, ATM) */
#define AFNUM_F69               9       /* F.69 (Telex) */
#define AFNUM_X121              10      /* X.121 (X.25, Frame Relay) */
#define AFNUM_IPX               11      /* IPX */
#define AFNUM_ATALK             12      /* Appletalk */
#define AFNUM_DECNET            13      /* Decnet IV */
#define AFNUM_BANYAN            14      /* Banyan Vines */
#define AFNUM_E164NSAP          15      /* E.164 with NSAP format subaddress */
#define AFNUM_DNS               16      /* DNS (Domain Name System) */
#define AFNUM_DISTNAME          17      /* Distinguished Name */
#define AFNUM_AS_NUMBER         18      /* AS Number */
#define AFNUM_XTP_IP4           19      /* XTP over IP version 4 */
#define AFNUM_XTP_IP6           20      /* XTP over IP version 6 */
#define AFNUM_XTP               21      /* XTP native mode XTP */
#define AFNUM_FC_WWPN           22      /* Fibre Channel World-Wide Port Name */
#define AFNUM_FC_WWNN           23      /* Fibre Channel World-Wide Node Name */
#define AFNUM_GWID              24      /* GWID */
#define AFNUM_L2VPN             25      /* RFC4761 RFC6074 */
#define AFNUM_L2VPN_OLD        196
#define AFNUM_MPLS_TP_SEI       26      /* MPLS-TP Section Endpoint Identifier, RFC7212 */
#define AFNUM_MPLS_TP_LSPEI     27      /* MPLS-TP LSP Endpoint Identifier, RFC7212 */
#define AFNUM_MPLS_TP_PEI       28      /* MPLS-TP Pseudowire Endpoint Identifier, RFC7212 */
#define AFNUM_MT_IP             29      /* MT IP: Multi-Topology IP version 4, RFC7307 */
#define AFNUM_MT_IPV6           30      /* MT IPv6: Multi-Topology IP version 6, RFC7307 */
#define AFNUM_EIGRP_COMMON      16384   /* EIGRP Common Service Family, Donnie Savage */
#define AFNUM_EIGRP_IPV4        16385   /* EIGRP IPv4 Service Family, Donnie Savage */
#define AFNUM_EIGRP_IPV6        16386   /* EIGRP IPv6 Service Family, Donnie Savage */
#define AFNUM_LCAF              16387   /* LISP Canonical Address Format, David Meyer */
#define AFNUM_BGP_LS            16388   /* BGP-LS, RFC7752 */
#define AFNUM_EUI48             16389   /* 48-bit MAC, RFC7042 */
#define AFNUM_EUI64             16390   /* 64-bit MAC, RFC7042 */
#define AFNUM_OUI               16391   /* OUI, RFC7961 */
#define AFNUM_MAC_24            16392   /* MAC/24, RFC7961 */
#define AFNUM_MAC_40            16393   /* MAC/40, RFC7961 */
#define AFNUM_IPv6_64           16394   /* IPv6/64, RFC7961 */
#define AFNUM_RB_PID            16395   /* RBridge Port ID, RFC7961 */
#define AFNUM_TRILL_NICKNAME    16396   /* TRILL Nickname, RFC7455 */
extern const value_string afn_vals[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __AFN_H__ */

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
