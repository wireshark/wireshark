/* packet-gre.h
 * Routines and data exported by the dissection code for the
 * Generic Routing Encapsulation (GRE) protocol
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* bit positions for flags in header */
#define GRE_CHECKSUM            0x8000
#define GRE_ROUTING             0x4000
#define GRE_KEY                 0x2000
#define GRE_SEQUENCE            0x1000
#define GRE_STRICTSOURCE        0x0800
#define GRE_RECURSION           0x0700
#define GRE_ACK                 0x0080  /* only in special PPTPized GRE header */
#define GRE_RESERVED_PPP        0x0078  /* only in special PPTPized GRE header */
#define GRE_RESERVED            0x00F8
#define GRE_VERSION             0x0007

/* GRE type values that aren't also Ethernet type values */
#define GRE_KEEPALIVE		0x0000
#define GRE_CISCO_CDP		0x2000
#define GRE_NHRP		0x2001
#define GRE_WCCP		0x883E
#define GRE_ERSPAN_88BE		0x88BE
#define GRE_ERSPAN_22EB		0x22EB
#define GRE_MIKROTIK_EOIP	0x6400
#define GRE_AIROHIVE		0xFEAE
#define GRE_GREBONDING		0xB7EA
/* ************************************************************************* */
/*              Aruba GRE Encapsulation ID                                   */
/* ************************************************************************* */
#define GRE_ARUBA_8200		0x8200
#define GRE_ARUBA_8210		0x8210
#define GRE_ARUBA_8220		0x8220
#define GRE_ARUBA_8230		0x8230
#define GRE_ARUBA_8240		0x8240
#define GRE_ARUBA_8250		0x8250
#define GRE_ARUBA_8260		0x8260
#define GRE_ARUBA_8270		0x8270
#define GRE_ARUBA_8280		0x8280
#define GRE_ARUBA_8290		0x8290
#define GRE_ARUBA_82A0		0x82A0
#define GRE_ARUBA_82B0		0x82B0
#define GRE_ARUBA_82C0		0x82C0
#define GRE_ARUBA_82D0		0x82D0
#define GRE_ARUBA_82E0		0x82E0
#define GRE_ARUBA_82F0		0x82F0
#define GRE_ARUBA_8300		0x8300
#define GRE_ARUBA_8310		0x8310
#define GRE_ARUBA_8320		0x8320
#define GRE_ARUBA_8330		0x8330
#define GRE_ARUBA_8340		0x8340
#define GRE_ARUBA_8350		0x8350
#define GRE_ARUBA_8360		0x8360
#define GRE_ARUBA_8370		0x8370
#define GRE_ARUBA_9000		0x9000

extern const value_string gre_typevals[];

typedef struct gre_hdr_info {
	guint16		flags_and_ver;
	guint32		key;
} gre_hdr_info_t;
