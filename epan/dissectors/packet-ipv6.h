/* packet-ipv6.h
 * Definitions for IPv6 packet disassembly
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

/* Hop-by-Hop options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_hbh {
	guint8 ip6h_nxt;	/* next header */
	guint8 ip6h_len;	/* length in units of 8 octets */
	/* followed by options */
};

/* Destination options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_dest {
	guint8 ip6d_nxt;	/* next header */
	guint8 ip6d_len;	/* length in units of 8 octets */
	/* followed by options */
};

/* Option types and related macros */
#define IP6OPT_PAD1			0x00	/* 00 0 00000 */
#define IP6OPT_PADN			0x01	/* 00 0 00001 */
#define IP6OPT_TEL			0x04	/* 00 0 00100 */
#define IP6OPT_RTALERT			0x05	/* 00 0 00101 */
#define IP6OPT_CALIPSO			0x07	/* 00 0 00111 */
#define IP6OPT_QUICKSTART		0x26	/* 00 1 00110 */
#define IP6OPT_ENDI			0x8A	/* 10 0 01010 */
#define IP6OPT_EXP_1E			0x1E	/* 00 0 11110 */
#define IP6OPT_EXP_3E			0x3E	/* 00 1 11110 */
#define IP6OPT_EXP_5E			0x5E	/* 01 0 11110 */
#define IP6OPT_RPL			0x63	/* 01 1 00011 */
#define IP6OPT_EXP_7E			0x7E	/* 01 1 11110 */
#define IP6OPT_EXP_9E			0x9E	/* 10 0 11110 */
#define IP6OPT_EXP_BE			0xBE	/* 10 1 11110 */
#define IP6OPT_JUMBO			0xC2	/* 11 0 00010 = 194 */
#define IP6OPT_HOME_ADDRESS		0xC9	/* 11 0 01001 */
#define IP6OPT_EXP_DE			0xDE	/* 11 0 11110 */
#define IP6OPT_EXP_FE			0xFE	/* 11 1 11110 */

#define IP6OPT_RTALERT_MLD		0	/* Datagram contains MLD message */
#define IP6OPT_RTALERT_RSVP		1	/* Datagram contains RSVP message */
#define IP6OPT_RTALERT_ACTNET		2	/* contains an Active Networks msg */


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
#define IP6F_RESERVED_MASK	0x0006	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0001	/* more-fragments flag */

void capture_ipv6(const guchar *, int, int, packet_counts *);


#endif /* __PACKET_IPV6_H_DEFINED__ */
