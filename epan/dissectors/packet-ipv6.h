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

#include <epan/ipv6-utils.h>

/* this definition makes trouble with Microsoft Platform SDK: ws2tcpip.h and is used nowhere */
/*#define INET6_ADDRSTRLEN	46*/

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */
struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			guint32 ip6_un1_flow;	/* version, class, flow */
			guint16 ip6_un1_plen;	/* payload length */
			guint8  ip6_un1_nxt;	/* next header */
			guint8  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		guint8 ip6_un2_vfc;	/* 4 bits version, 4 bits class */
	} ip6_ctlun;
	struct e_in6_addr ip6_src;	/* source address */
	struct e_in6_addr ip6_dst;	/* destination address */
};

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

/* Offsets of fields within an IPv6 header. */
#define	IP6H_CTL		0
#define	IP6H_CTL_FLOW	0
#define	IP6H_CTL_PLEN	4
#define	IP6H_CTL_NXT	6
#define	IP6H_CTL_HLIM	7
#define	IP6H_CTL_VFC	0
#define	IP6H_SRC		8
#define	IP6H_DST		24

#define IPV6_FLOWINFO_MASK	0x0fffffff	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0x000fffff	/* flow label (20 bits) */

/*
 * Extension Headers
 */

struct	ip6_ext {
	guchar	ip6e_nxt;
	guchar	ip6e_len;
};

/* Routing header */
struct ip6_rthdr {
	guint8  ip6r_nxt;	/* next header */
	guint8  ip6r_len;	/* length in units of 8 octets */
	guint8  ip6r_type;	/* routing type */
	guint8  ip6r_segleft;	/* segments left */
	/* followed by routing type specific data */
};

/* Type 0 Routing header */
struct ip6_rthdr0 {
	guint8  ip6r0_nxt;		/* next header */
	guint8  ip6r0_len;		/* length in units of 8 octets */
	guint8  ip6r0_type;		/* always zero */
	guint8  ip6r0_segleft;	/* segments left */
	guint8  ip6r0_reserved;	/* reserved field */
	guint8  ip6r0_slmap[3];	/* strict/loose bit map */
	struct e_in6_addr  ip6r0_addr[1];	/* up to 23 addresses */
};

/* Fragment header */
struct ip6_frag {
	guint8  ip6f_nxt;		/* next header */
	guint8  ip6f_reserved;	/* reserved field */
	guint16 ip6f_offlg;		/* offset, reserved, and flag */
	guint32 ip6f_ident;		/* identification */
};

/* SHIM6 control message types */
#define SHIM6_TYPE_I1 			0x01	/* 0 000 0001 */
#define SHIM6_TYPE_R1 			0x02	/* 0 000 0010 */
#define SHIM6_TYPE_I2			0x03	/* 0 000 0011 */
#define SHIM6_TYPE_R2 			0x04	/* 0 000 0100 */
#define SHIM6_TYPE_R1BIS		0x05	/* 0 000 0101 */
#define SHIM6_TYPE_I2BIS		0x06	/* 0 000 0110 */
#define SHIM6_TYPE_UPD_REQ		0x40	/* 0 100 0000 = 64 */
#define SHIM6_TYPE_UPD_ACK		0x41	/* 0 100 0001 = 65 */
#define SHIM6_TYPE_KEEPALIVE	0x42	/* 0 100 0010 = 66 */
#define SHIM6_TYPE_PROBE 		0x43	/* 0 100 0011 = 67 */

/* SHIM6 Options */
#define SHIM6_OPT_RESPVAL       0x01    /* 0 000 0001 */
#define SHIM6_OPT_LOCLIST       0x02    /* 0 000 0010 */
#define SHIM6_OPT_LOCPREF       0x03    /* 0 000 0011 */
#define SHIM6_OPT_CGAPDM        0x04    /* 0 000 0100 */
#define SHIM6_OPT_CGASIG        0x05    /* 0 000 0101 */
#define SHIM6_OPT_ULIDPAIR      0x06    /* 0 000 0110 */
#define SHIM6_OPT_FII           0x07    /* 0 000 0111 */

/* SHIM6 Bitmasks */
#define SHIM6_BITMASK_P			0x80	/* 1 000 0000 */
#define SHIM6_BITMASK_TYPE		0x7F	/* 0 111 1111 */
#define SHIM6_BITMASK_PROTOCOL	0x01	/* 0 000 0001 */
#define SHIM6_BITMASK_SPECIFIC	0xFE	/* 1 111 1110 */
#define SHIM6_BITMASK_R			0x80	/* 1 000 0000 */
#define SHIM6_BITMASK_CT		0x7F	/* 0 111 1111 */
#define SHIM6_BITMASK_OPT_TYPE	0xFFFE	/* 1 111 1111    1 111 1110 */
#define SHIM6_BITMASK_CRITICAL	0x01	/* 0 000 0001 */
#define SHIM6_BITMASK_PRECVD	0xF0	/* 1 111 0000 */
#define SHIM6_BITMASK_PSENT		0x0F	/* 0 000 1111 */
#define SHIM6_BITMASK_STA		0xC0	/* 1 100 0000 */

/* SHIM6 Verification Methods */
#define SHIM6_VERIF_HBA			0x01	/* 0 000 0001 */
#define SHIM6_VERIF_CGA			0x02	/* 0 000 0010 */

/* SHIM6 Flags */
#define SHIM6_FLAG_BROKEN		0x01	/* 0 000 0001 */
#define SHIM6_FLAG_TEMPORARY	0x02	/* 0 000 0010 */

/* SHIM6 REAP States */
#define SHIM6_REAP_OPERATIONAL	0x00	/* 0 000 0000 */
#define SHIM6_REAP_EXPLORING	0x01	/* 0 000 0001 */
#define SHIM6_REAP_INBOUNDOK	0x02	/* 0 000 0010 */

/* SHIM6 header */
struct ip6_shim {
	guint8  ip6s_nxt;		/* next header */
	guint8  ip6s_len;		/* header extension length */
	guint8  ip6s_p;			/* P field and first 7 bits of remainder */
	/* followed by shim6 specific data*/
};

#define IP6F_OFF_MASK		0xfff8	/* mask out offset from _offlg */
#define IP6F_OFF_SHIFT		3	/* right-shift offset by this many bits */
#define IP6F_RESERVED_MASK	0x0006	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0001	/* more-fragments flag */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void capture_ipv6(const guchar *, int, int, packet_counts *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_IPV6_H_DEFINED__ */
