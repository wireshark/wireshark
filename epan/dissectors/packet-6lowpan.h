/* packet-6lowpan.h
 * Definitions for 6lowpan packet disassembly structures and routines
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Owen Kirby
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

/* 6LoWPAN Patterns */
#define LOWPAN_PATTERN_NALP             0x00
#define LOWPAN_PATTERN_NALP_BITS        2
#define LOWPAN_PATTERN_IPV6             0x41
#define LOWPAN_PATTERN_IPV6_BITS        8
#define LOWPAN_PATTERN_HC1              0x42    /* Deprecated - replaced with IPHC. */
#define LOWPAN_PATTERN_HC1_BITS         8
#define LOWPAN_PATTERN_BC0              0x50
#define LOWPAN_PATTERN_BC0_BITS         8
#define LOWPAN_PATTERN_IPHC             0x03    /* See draft-ietf-6lowpan-hc-05.txt */
#define LOWPAN_PATTERN_IPHC_BITS        3
#define LOWPAN_PATTERN_ESC              0x7f
#define LOWPAN_PATTERN_ESC_BITS         8
#define LOWPAN_PATTERN_MESH             0x02
#define LOWPAN_PATTERN_MESH_BITS        2
#define LOWPAN_PATTERN_FRAG1            0x18
#define LOWPAN_PATTERN_FRAGN            0x1c
#define LOWPAN_PATTERN_FRAG_BITS        5

/* 6LoWPAN HC1 Header */
#define LOWPAN_HC1_SOURCE_PREFIX        0x80
#define LOWPAN_HC1_SOURCE_IFC           0x40
#define LOWPAN_HC1_DEST_PREFIX          0x20
#define LOWPAN_HC1_DEST_IFC             0x10
#define LOWPAN_HC1_TRAFFIC_CLASS        0x08
#define LOWPAN_HC1_NEXT                 0x06
#define LOWPAN_HC1_MORE                 0x01

/* IPv6 header field lengths (in bits) */
#define LOWPAN_IPV6_TRAFFIC_CLASS_BITS  8
#define LOWPAN_IPV6_FLOW_LABEL_BITS     20
#define LOWPAN_IPV6_NEXT_HEADER_BITS    8
#define LOWPAN_IPV6_HOP_LIMIT_BITS      8
#define LOWPAN_IPV6_PREFIX_BITS         64
#define LOWPAN_IPV6_INTERFACE_BITS      64

/* HC_UDP header field lengths (in bits). */
#define LOWPAN_UDP_PORT_BITS            16
#define LOWPAN_UDP_PORT_COMPRESSED_BITS 4
#define LOWPAN_UDP_LENGTH_BITS          16
#define LOWPAN_UDP_CHECKSUM_BITS        16

/* HC1 Next Header compression modes. */
#define LOWPAN_HC1_NEXT_NONE            0x00
#define LOWPAN_HC1_NEXT_UDP             0x01
#define LOWPAN_HC1_NEXT_ICMP            0x02
#define LOWPAN_HC1_NEXT_TCP             0x03

/* HC_UDP Header */
#define LOWPAN_HC2_UDP_SRCPORT          0x80
#define LOWPAN_HC2_UDP_DSTPORT          0x40
#define LOWPAN_HC2_UDP_LENGTH           0x20
#define LOWPAN_HC2_UDP_RESERVED         0x1f

/* IPHC Base flags */
#define LOWPAN_IPHC_FLAG_FLOW           0x1800
#define LOWPAN_IPHC_FLAG_NHDR           0x0400
#define LOWPAN_IPHC_FLAG_HLIM           0x0300
#define LOWPAN_IPHC_FLAG_CONTEXT_ID     0x0080
#define LOWPAN_IPHC_FLAG_SRC_COMP       0x0040
#define LOWPAN_IPHC_FLAG_SRC_MODE       0x0030
#define LOWPAN_IPHC_FLAG_MCAST_COMP     0x0008
#define LOWPAN_IPHC_FLAG_DST_COMP       0x0004
#define LOWPAN_IPHC_FLAG_DST_MODE       0x0003
#define LOWPAN_IPHC_FLAG_SCI            0xf0
#define LOWPAN_IPHC_FLAG_DCI            0x0f
/* Offsets for extracting integer fields. */
#define LOWPAN_IPHC_FLAG_OFFSET_FLOW    11
#define LOWPAN_IPHC_FLAG_OFFSET_HLIM    8
#define LOWPAN_IPHC_FLAG_OFFSET_SRC_MODE 4
#define LOWPAN_IPHC_FLAG_OFFSET_DST_MODE 0

/* IPHC Flow encoding values. */
#define LOWPAN_IPHC_FLOW_CLASS_LABEL    0x0
#define LOWPAN_IPHC_FLOW_ECN_LABEL      0x1
#define LOWPAN_IPHC_FLOW_CLASS          0x2
#define LOWPAN_IPHC_FLOW_COMPRESSED     0x3

/* IPHC Hop limit encoding. */
#define LOWPAN_IPHC_HLIM_INLINE         0x0
#define LOWPAN_IPHC_HLIM_1              0x1
#define LOWPAN_IPHC_HLIM_64             0x2
#define LOWPAN_IPHC_HLIM_255            0x3

/* IPHC address modes. */
#define LOWPAN_IPHC_ADDR_FULL_INLINE    0x0
#define LOWPAN_IPHC_ADDR_64BIT_INLINE   0x1
#define LOWPAN_IPHC_ADDR_16BIT_INLINE   0x2
#define LOWPAN_IPHC_ADDR_COMPRESSED     0x3

/* IPHC Traffic class and flow label field sizes (in bits) */
#define LOWPAN_IPHC_ECN_BITS            2
#define LOWPAN_IPHC_DSCP_BITS           6
#define LOWPAN_IPHC_LABEL_BITS          20
/* Bitmasks for the reconstructed traffic class field. */
#define LOWPAN_IPHC_TRAFFIC_ECN         0x03
#define LOWPAN_IPHC_TRAFFIC_DSCP        0xfc

/* NHC Patterns. */
#define LOWPAN_NHC_PATTERN_EXT          0x0e
#define LOWPAN_NHC_PATTERN_EXT_BITS     4
#define LOWPAN_NHC_PATTERN_UDP          0x1e
#define LOWPAN_NHC_PATTERN_UDP_BITS     5

/* NHC Extension header fields. */
#define LOWPAN_NHC_EXT_EID              0x0e
#define LOWPAN_NHC_EXT_EID_OFFSET       1
#define LOWPAN_NHC_EXT_NHDR             0x01

#define LOWPAN_NHC_EID_HOP_BY_HOP       0x00
#define LOWPAN_NHC_EID_ROUTING          0x01
#define LOWPAN_NHC_EID_FRAGMENT         0x02
#define LOWPAN_NHC_EID_DEST_OPTIONS     0x03
#define LOWPAN_NHC_EID_MOBILITY         0x04
#define LOWPAN_NHC_EID_IPV6             0x07

/* NHC UDP fields. */
#define LOWPAN_NHC_UDP_CHECKSUM         0x04
#define LOWPAN_NHC_UDP_SRCPORT          0x02
#define LOWPAN_NHC_UDP_DSTPORT          0x01

/* 6LoWPAN Mesh Header */
#define LOWPAN_MESH_HEADER_V            0x20
#define LOWPAN_MESH_HEADER_F            0x10
#define LOWPAN_MESH_HEADER_HOPS         0x0f

/* 6LoWPAN First Fragment Header */
#define LOWPAN_FRAG_DGRAM_SIZE_BITS     11

/* Compressed port number offset. */
#define LOWPAN_PORT_8BIT_OFFSET         0xf000
#define LOWPAN_PORT_12BIT_OFFSET        (LOWPAN_PORT_8BIT_OFFSET | 0xb0)

/* 6LoWPAN interface identifier length. */
#define LOWPAN_IFC_ID_LEN               8
