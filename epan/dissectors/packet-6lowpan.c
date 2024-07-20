/* packet-6lowpan.c
 *
 * Add Selective Fragment Recovery per
 * https://tools.ietf.org/html/draft-ietf-6lo-fragment-recovery-02
 * By James Ko <jck@exegin.com>
 * Copyright 2019 Exegin Technologies Limited
 *
 * Routines for 6LoWPAN packet disassembly
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Owen Kirby
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>
#include <epan/etypes.h>
#include "packet-6lowpan.h"
#include "packet-btl2cap.h"
#include "packet-ipv6.h"
#include "packet-zbee.h"

void proto_register_6lowpan(void);
void proto_reg_handoff_6lowpan(void);

/* Definitions for 6lowpan packet disassembly structures and routines */

/* 6LoWPAN Patterns */
#define LOWPAN_PATTERN_NALP             0x00
#define LOWPAN_PATTERN_NALP_BITS        2
#define LOWPAN_PATTERN_IPV6             0x41
#define LOWPAN_PATTERN_IPV6_BITS        8
#define LOWPAN_PATTERN_HC1              0x42    /* Deprecated - replaced with IPHC. */
#define LOWPAN_PATTERN_HC1_BITS         8
#define LOWPAN_PATTERN_BC0              0x50
#define LOWPAN_PATTERN_BC0_BITS         8
#define LOWPAN_PATTERN_IPHC             0x03    /* See draft-ietf-6lowpan-hc-15.txt */
#define LOWPAN_PATTERN_IPHC_BITS        3
#define LOWPAN_PATTERN_ESC              0x7f
#define LOWPAN_PATTERN_ESC_BITS         8
#define LOWPAN_PATTERN_MESH             0x02
#define LOWPAN_PATTERN_MESH_BITS        2
#define LOWPAN_PATTERN_FRAG1            0x18
#define LOWPAN_PATTERN_FRAGN            0x1c
#define LOWPAN_PATTERN_FRAG_BITS        5
#define LOWPAN_PATTERN_RFRAG            0x74
#define LOWPAN_PATTERN_RFRAG_ACK        0x75
#define LOWPAN_PATTERN_RFRAG_BITS       7

#define LOWPAN_RFRAG_SEQUENCE_BITS      5
#define LOWPAN_RFRAG_FRAG_SZ_BITS      10

/* RFC8025 and RFC8138 */
#define LOWPAN_PATTERN_PAGING_DISPATCH          0xf
#define LOWPAN_PATTERN_PAGING_DISPATCH_BITS     4
#define LOWPAN_PATTERN_6LORHC                   0x04
#define LOWPAN_PATTERN_6LORHE                   0x05
#define LOWPAN_PATTERN_6LORHE_CLASS             0xe000
#define LOWPAN_PATTERN_6LORHE_CLASS_BITS        13
#define LOWPAN_PATTERN_6LORHE_LENGTH            0x1f00
#define LOWPAN_PATTERN_6LORHE_LENGTH_BITS       8
#define LOWPAN_PATTERN_6LORHE_TYPE              0x00ff
#define LOWPAN_PATTERN_6LORH_TYPE0              0x00
#define LOWPAN_PATTERN_6LORH_TYPE1              0x01
#define LOWPAN_PATTERN_6LORH_TYPE2              0x02
#define LOWPAN_PATTERN_6LORH_TYPE3              0x03
#define LOWPAN_PATTERN_6LORH_TYPE4              0x04
#define LOWPAN_PATTERN_6LORH_TYPE5              0x05
#define LOWPAN_PATTERN_6LORH_TYPE6              0x06
#define LOWPAN_PATTERN_6LORH_TYPE15             0x0F
#define LOWPAN_PATTERN_6LORH_TYPE16             0x10
#define LOWPAN_PATTERN_6LORH_TYPE17             0x11
#define LOWPAN_PATTERN_6LORH_TYPE18             0x12
#define LOWPAN_PATTERN_6LORH_TYPE19             0x13
#define LOWPAN_5_RPI_BIT_O                      0x1000
#define LOWPAN_5_RPI_BIT_R                      0x0800
#define LOWPAN_5_RPI_BIT_F                      0x0400
#define LOWPAN_5_RPI_BIT_I                      0x0200
#define LOWPAN_5_RPI_BIT_K                      0x0100
#define LOWPAN_5_RPI_BITS_IK                    0x0300
#define LOWPAN_6LORH_GENERAL_FORMAT             0x8000
#define LOWPAN_IP_IN_IP_6LORH                   6
#define BITS_IK_0                               0
#define BITS_IK_1                               1
#define BITS_IK_2                               2
#define BITS_IK_3                               3
#define BITS_IK_4                               4
#define IPV6_ADDR_COMPRESSED_1_BYTE             0
#define IPV6_ADDR_COMPRESSED_2_BYTE             1
#define IPV6_ADDR_COMPRESSED_4_BYTE             2
#define IPV6_ADDR_COMPRESSED_8_BYTE             3
#define IPV6_ADDR_COMPRESSED_16_BYTE            4

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
#define LOWPAN_IPHC_FLAG_OFFSET_SCI      4
#define LOWPAN_IPHC_FLAG_OFFSET_DCI      0

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
#define LOWPAN_IPHC_ADDR_SRC_UNSPEC     0x0
#define LOWPAN_IPHC_ADDR_FULL_INLINE    0x0
#define LOWPAN_IPHC_ADDR_64BIT_INLINE   0x1
#define LOWPAN_IPHC_ADDR_16BIT_INLINE   0x2
#define LOWPAN_IPHC_ADDR_COMPRESSED     0x3

/* IPHC multicast address modes. */
#define LOWPAN_IPHC_MCAST_FULL          0x0
#define LOWPAN_IPHC_MCAST_48BIT         0x1
#define LOWPAN_IPHC_MCAST_32BIT         0x2
#define LOWPAN_IPHC_MCAST_8BIT          0x3

#define LOWPAN_IPHC_MCAST_STATEFUL_48BIT 0x0

/* IPHC Traffic class and flow label field sizes (in bits) */
#define LOWPAN_IPHC_ECN_BITS            2
#define LOWPAN_IPHC_DSCP_BITS           6
#define LOWPAN_IPHC_LABEL_BITS          20

/* NHC Patterns. */
#define LOWPAN_NHC_PATTERN_EXT          0x0e
#define LOWPAN_NHC_PATTERN_EXT_BITS     4
#define LOWPAN_NHC_PATTERN_UDP          0x1e
#define LOWPAN_NHC_PATTERN_UDP_BITS     5
/* IP-in-IP tunneling is handled as a separate NHC pattern.  */
#define LOWPAN_NHC_PATTERN_EXT_IPV6     ((LOWPAN_NHC_PATTERN_EXT << LOWPAN_NHC_EXT_EID_BITS) | LOWPAN_NHC_EID_IPV6)
#define LOWPAN_NHC_PATTERN_EXT_IPV6_BITS (LOWPAN_NHC_PATTERN_EXT_BITS + LOWPAN_NHC_EXT_EID_BITS)

/* NHC Extension header fields. */
#define LOWPAN_NHC_EXT_EID              0x0e
#define LOWPAN_NHC_EXT_EID_OFFSET       1
#define LOWPAN_NHC_EXT_EID_BITS         3
#define LOWPAN_NHC_EXT_NHDR             0x01

/* Extension header ID codes. */
#define LOWPAN_NHC_EID_HOP_BY_HOP       0x00
#define LOWPAN_NHC_EID_ROUTING          0x01
#define LOWPAN_NHC_EID_FRAGMENT         0x02
#define LOWPAN_NHC_EID_DEST_OPTIONS     0x03
#define LOWPAN_NHC_EID_MOBILITY         0x04
#define LOWPAN_NHC_EID_IPV6             0x07

/* NHC UDP fields. */
#define LOWPAN_NHC_UDP_CHECKSUM         0x04
#define LOWPAN_NHC_UDP_PORTS            0x03

/* 6LoWPAN Mesh Header */
#define LOWPAN_MESH_HEADER_V            0x20
#define LOWPAN_MESH_HEADER_F            0x10
#define LOWPAN_MESH_HEADER_HOPS         0x0f

/* 6LoWPAN First Fragment Header */
#define LOWPAN_FRAG_DGRAM_SIZE_BITS     11

/* Uncompressed IPv6 Option types */
#define IP6OPT_PAD1                     0x00
#define IP6OPT_PADN                     0x01

/* UDP port compression encoding */
#define LOWPAN_NHC_UDP_PORT_INLINE      0x0
#define LOWPAN_NHC_UDP_PORT_8BIT_DST    0x1
#define LOWPAN_NHC_UDP_PORT_8BIT_SRC    0x2
#define LOWPAN_NHC_UDP_PORT_12BIT       0x3

/* Compressed port number offset. */
#define LOWPAN_PORT_8BIT_OFFSET         0xf000
#define LOWPAN_PORT_12BIT_OFFSET        0xf0b0

/* 6LoWPAN interface identifier length. */
#define LOWPAN_IFC_ID_LEN               8

/* Protocol fields handles. */
static int proto_6lowpan;
static int hf_6lowpan_pattern;
static int hf_6lowpan_nhc_pattern;
static int hf_6lowpan_padding;

/* Header compression fields. */
static int hf_6lowpan_hc1_encoding;
static int hf_6lowpan_hc1_source_prefix;
static int hf_6lowpan_hc1_source_ifc;
static int hf_6lowpan_hc1_dest_prefix;
static int hf_6lowpan_hc1_dest_ifc;
static int hf_6lowpan_hc1_class;
static int hf_6lowpan_hc1_next;
static int hf_6lowpan_hc1_more;
static int hf_6lowpan_hc2_udp_encoding;
static int hf_6lowpan_hc2_udp_src;
static int hf_6lowpan_hc2_udp_dst;
static int hf_6lowpan_hc2_udp_len;

/* 6loRH */
static int hf_6lowpan_pagenb;
static int hf_6lowpan_routing_header;
static int hf_6lowpan_6lorhe_length;
static int hf_6lowpan_6lorhe_size;
static int hf_6lowpan_6lorhc_size;
static int hf_6lowpan_6lorhe_type;
static int hf_6lowpan_6lorhe_hoplimit;
static int hf_6lowpan_6lorhe_bitmap;
static int hf_6lowpan_5_bit_o;
static int hf_6lowpan_5_bit_r;
static int hf_6lowpan_5_bit_f;
static int hf_6lowpan_5_bit_i;
static int hf_6lowpan_5_bit_k;
static int hf_6lowpan_sender_rank1;
static int hf_6lowpan_sender_rank2;
static int hf_6lowpan_rpl_instance;
static int hf_6lowpan_6lorhc_address_hop0;
static int hf_6lowpan_6lorhc_address_hop2;
static int hf_6lowpan_6lorhc_address_hop3;
static int hf_6lowpan_6lorhc_address_hop4;
static int hf_6lowpan_6lorhc_address_hop1;
static int hf_6lowpan_6lorhc_address_src;

/* IPHC header field. */
static int hf_6lowpan_iphc_flag_tf;
static int hf_6lowpan_iphc_flag_nhdr;
static int hf_6lowpan_iphc_flag_hlim;
static int hf_6lowpan_iphc_flag_cid;
static int hf_6lowpan_iphc_flag_sac;
static int hf_6lowpan_iphc_flag_sam;
static int hf_6lowpan_iphc_flag_mcast;
static int hf_6lowpan_iphc_flag_dac;
static int hf_6lowpan_iphc_flag_dam;
static int hf_6lowpan_iphc_sci;
static int hf_6lowpan_iphc_dci;

static int hf_6lowpan_iphc_sctx_prefix;
static int hf_6lowpan_iphc_sctx_origin;
static int hf_6lowpan_iphc_dctx_prefix;
static int hf_6lowpan_iphc_dctx_origin;

/* NHC IPv6 extension header fields. */
static int hf_6lowpan_nhc_ext_eid;
static int hf_6lowpan_nhc_ext_nh;
static int hf_6lowpan_nhc_ext_next;
static int hf_6lowpan_nhc_ext_length;
static int hf_6lowpan_nhc_ext_reserved;

/* NHC UDP compression header fields. */
static int hf_6lowpan_nhc_udp_checksum;
static int hf_6lowpan_nhc_udp_ports;

/* Inline IPv6 header fields. */
static int hf_6lowpan_traffic_class;
static int hf_6lowpan_flow_label;
static int hf_6lowpan_ecn;
static int hf_6lowpan_dscp;
static int hf_6lowpan_next_header;
static int hf_6lowpan_hop_limit;
static int hf_6lowpan_source;
static int hf_6lowpan_dest;

/* Inline UDP header fields. */
static int hf_6lowpan_udp_src;
static int hf_6lowpan_udp_dst;
static int hf_6lowpan_udp_len;
static int hf_6lowpan_udp_checksum;

/* Broadcast header fields. */
static int hf_6lowpan_bcast_seqnum;

/* Mesh header fields. */
static int hf_6lowpan_mesh_v;
static int hf_6lowpan_mesh_f;
static int hf_6lowpan_mesh_hops;
static int hf_6lowpan_mesh_hops8;
static int hf_6lowpan_mesh_orig16;
static int hf_6lowpan_mesh_orig64;
static int hf_6lowpan_mesh_dest16;
static int hf_6lowpan_mesh_dest64;

/* Fragmentation header fields. */
static int hf_6lowpan_frag_dgram_size;
static int hf_6lowpan_frag_dgram_tag;
static int hf_6lowpan_frag_dgram_offset;

/* Recoverable Fragmentation header fields. */
static int hf_6lowpan_rfrag_congestion;
static int hf_6lowpan_rfrag_ack_requested;
static int hf_6lowpan_rfrag_dgram_tag;
static int hf_6lowpan_rfrag_sequence;
static int hf_6lowpan_rfrag_size;
static int hf_6lowpan_rfrag_dgram_size;
static int hf_6lowpan_rfrag_offset;
static int hf_6lowpan_rfrag_ack_bitmap;

/* Protocol tree handles.  */
static int ett_6lowpan;
static int ett_6lowpan_hc1;
static int ett_6lowpan_hc1_encoding;
static int ett_6lowpan_hc2_udp;
static int ett_6lowpan_iphc;
static int ett_lowpan_routing_header_dispatch;
static int ett_6lowpan_nhc_ext;
static int ett_6lowpan_nhc_udp;
static int ett_6lowpan_bcast;
static int ett_6lowpan_mesh;
static int ett_6lowpan_mesh_flags;
static int ett_6lowpan_frag;

static expert_field ei_6lowpan_hc1_more_bits;
static expert_field ei_6lowpan_illegal_dest_addr_mode;
static expert_field ei_6lowpan_bad_ipv6_header_length;
static expert_field ei_6lowpan_bad_ext_header_length;

/* Subdissector handles. */
static dissector_handle_t       handle_6lowpan;
static dissector_handle_t       ipv6_handle;

/* Value Strings */
static const value_string lowpan_patterns [] = {
    { LOWPAN_PATTERN_NALP,          "Not a LoWPAN frame" },
    { LOWPAN_PATTERN_IPV6,          "Uncompressed IPv6" },
    { LOWPAN_PATTERN_HC1,           "Header compression" },
    { LOWPAN_PATTERN_BC0,           "Broadcast" },
    { LOWPAN_PATTERN_IPHC,          "IP header compression" },
    { LOWPAN_PATTERN_ESC,           "Escape" },
    { LOWPAN_PATTERN_MESH,          "Mesh" },
    { LOWPAN_PATTERN_FRAG1,         "First fragment" },
    { LOWPAN_PATTERN_FRAGN,         "Fragment" },
    { LOWPAN_PATTERN_RFRAG,         "Recoverable Fragment" },
    { LOWPAN_PATTERN_RFRAG_ACK,     "Recoverable Fragment ACK" },
    { 0, NULL }
};
static const true_false_string lowpan_compression = {
    "Compressed",
    "Inline"
};
static const value_string lowpan_hc1_next [] = {
    { LOWPAN_HC1_NEXT_NONE,         "Inline" },
    { LOWPAN_HC1_NEXT_UDP,          "UDP" },
    { LOWPAN_HC1_NEXT_ICMP,         "ICMP" },
    { LOWPAN_HC1_NEXT_TCP,          "TCP" },
    { 0, NULL }
};
static const value_string lowpan_iphc_traffic [] = {
    { LOWPAN_IPHC_FLOW_CLASS_LABEL, "Traffic class and flow label inline" },
    { LOWPAN_IPHC_FLOW_ECN_LABEL,   "ECN and flow label inline" },
    { LOWPAN_IPHC_FLOW_CLASS,       "Traffic class inline" },
    { LOWPAN_IPHC_FLOW_COMPRESSED,  "Version, traffic class, and flow label compressed" },
    { 0, NULL }
};
static const value_string lowpan_iphc_hop_limit [] = {
    { LOWPAN_IPHC_HLIM_INLINE,      "Inline" },
    { LOWPAN_IPHC_HLIM_1,           "1" },
    { LOWPAN_IPHC_HLIM_64,          "64" },
    { LOWPAN_IPHC_HLIM_255,         "255" },
    { 0, NULL }
};
static const true_false_string lowpan_iphc_addr_compression = {
    "Stateful",
    "Stateless"
};
static const value_string lowpan_iphc_addr_modes [] = {
    { LOWPAN_IPHC_ADDR_FULL_INLINE, "Inline" },
    { LOWPAN_IPHC_ADDR_64BIT_INLINE,"64-bits inline" },
    { LOWPAN_IPHC_ADDR_16BIT_INLINE,"16-bits inline" },
    { LOWPAN_IPHC_ADDR_COMPRESSED,  "Compressed" },
    { 0, NULL }
};
static const value_string lowpan_iphc_saddr_stateful_modes [] = {
    { LOWPAN_IPHC_ADDR_FULL_INLINE, "Unspecified address (::)" },
    { LOWPAN_IPHC_ADDR_64BIT_INLINE,"64-bits inline" },
    { LOWPAN_IPHC_ADDR_16BIT_INLINE,"16-bits inline" },
    { LOWPAN_IPHC_ADDR_COMPRESSED,  "Compressed" },
    { 0, NULL }
};
static const value_string lowpan_iphc_daddr_stateful_modes [] = {
    { LOWPAN_IPHC_ADDR_64BIT_INLINE,"64-bits inline" },
    { LOWPAN_IPHC_ADDR_16BIT_INLINE,"16-bits inline" },
    { LOWPAN_IPHC_ADDR_COMPRESSED,  "Compressed" },
    { 0, NULL }
};
static const value_string lowpan_iphc_mcast_modes [] = {
    { LOWPAN_IPHC_MCAST_FULL,       "Inline" },
    { LOWPAN_IPHC_MCAST_48BIT,      "48-bits inline" },
    { LOWPAN_IPHC_MCAST_32BIT,      "32-bits inline" },
    { LOWPAN_IPHC_MCAST_8BIT,       "8-bits inline" },
    { 0, NULL }
};
static const value_string lowpan_iphc_mcast_stateful_modes [] = {
    { LOWPAN_IPHC_MCAST_STATEFUL_48BIT, "48-bits inline" },
    { 0, NULL }
};
static const value_string lowpan_nhc_patterns [] = {
    { LOWPAN_NHC_PATTERN_EXT,       "IPv6 extension header" },
    { LOWPAN_NHC_PATTERN_UDP,       "UDP compression header" },
    { 0, NULL }
};
static const value_string lowpan_nhc_eid [] = {
    { LOWPAN_NHC_EID_HOP_BY_HOP,    "IPv6 hop-by-hop options" },
    { LOWPAN_NHC_EID_ROUTING,       "IPv6 routing" },
    { LOWPAN_NHC_EID_FRAGMENT,      "IPv6 fragment" },
    { LOWPAN_NHC_EID_DEST_OPTIONS,  "IPv6 destination options" },
    { LOWPAN_NHC_EID_MOBILITY,      "IPv6 mobility header" },
    { LOWPAN_NHC_EID_IPV6,          "IPv6 header" },
    { 0, NULL }
};
static const value_string lowpan_udp_ports [] = {
    { LOWPAN_NHC_UDP_PORT_INLINE,   "Inline" },
    { LOWPAN_NHC_UDP_PORT_8BIT_DST, "Source port inline, first 8 bits of destination port elided" },
    { LOWPAN_NHC_UDP_PORT_8BIT_SRC, "Destination port inline, first 8 bits of source port elided" },
    { LOWPAN_NHC_UDP_PORT_12BIT,    "12 bits of both ports elided" },
    { 0, NULL }
};
/* 6loRH */
static const value_string lowpan_patterns_rh_type [] = {
        { LOWPAN_PATTERN_6LORH_TYPE0,        "Routing Header 3, 1 byte compression" },
        { LOWPAN_PATTERN_6LORH_TYPE1,        "Routing Header 3, 2 byte compression" },
        { LOWPAN_PATTERN_6LORH_TYPE2,        "Routing Header 3, 4 byte compression" },
        { LOWPAN_PATTERN_6LORH_TYPE3,        "Routing Header 3, 8 byte compression" },
        { LOWPAN_PATTERN_6LORH_TYPE4,        "Routing Header 3, 16 byte compression" },
        { LOWPAN_PATTERN_6LORH_TYPE5,        "Routing Protocol Information" },
        { LOWPAN_PATTERN_6LORH_TYPE6,        "IP in IP" },
        { LOWPAN_PATTERN_6LORH_TYPE15,       "BIER Header, bit-by-bit encoding, no control fields, 32 bits word size" },
        { LOWPAN_PATTERN_6LORH_TYPE16,       "BIER Header, Bloom filter encoding, 2* 1-byte HashID control fields, 32 bits word size" },
        { LOWPAN_PATTERN_6LORH_TYPE17,       "BIER Header, bit-by-bit encoding, no control fields, 128 bits word size" },
        { LOWPAN_PATTERN_6LORH_TYPE18,       "BIER Header, Bloom filter encoding, 8* 1-byte HashID control fields, 128 bits word size" },
        { LOWPAN_PATTERN_6LORH_TYPE19,       "BIER Header, bit-by-bit encoding, 1-byte GroupID control fields, 128 bits word size" },
        { 0, NULL }
};
static const value_string lowpan_patterns_rh [] = {
        { LOWPAN_PATTERN_6LORHC,        "Critical Routing Header" },
        { LOWPAN_PATTERN_6LORHE,        "Elective Routing Header" },
        { 0, NULL }
};
static const true_false_string bit_I_RPL = {
    "Elided (RPL Instance ID: 0)",
    "Present"
};
static const true_false_string bit_K_RPL = {
    "1 byte",
    "2 bytes"
};

/* Reassembly Data */
static int hf_6lowpan_fragments;
static int hf_6lowpan_fragment;
static int hf_6lowpan_fragment_overlap;
static int hf_6lowpan_fragment_overlap_conflicts;
static int hf_6lowpan_fragment_multiple_tails;
static int hf_6lowpan_fragment_too_long_fragment;
static int hf_6lowpan_fragment_error;
static int hf_6lowpan_fragment_count;
static int hf_6lowpan_reassembled_in;
static int hf_6lowpan_reassembled_length;
static int ett_6lowpan_fragment;
static int ett_6lowpan_fragments;

static const fragment_items lowpan_frag_items = {
    /* Fragment subtrees */
    &ett_6lowpan_fragment,
    &ett_6lowpan_fragments,
    /* Fragment fields */
    &hf_6lowpan_fragments,
    &hf_6lowpan_fragment,
    &hf_6lowpan_fragment_overlap,
    &hf_6lowpan_fragment_overlap_conflicts,
    &hf_6lowpan_fragment_multiple_tails,
    &hf_6lowpan_fragment_too_long_fragment,
    &hf_6lowpan_fragment_error,
    &hf_6lowpan_fragment_count,
    /* Reassembled in field */
    &hf_6lowpan_reassembled_in,
    /* Reassembled length field */
    &hf_6lowpan_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "6LoWPAN fragments"
};

static reassembly_table lowpan_reassembly_table;
static GHashTable *lowpan_context_table;

/* Link-Local prefix used by 6LoWPAN (FF80::/10) */
static const uint8_t lowpan_llprefix[8] = {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Context hash table map key. */
typedef struct {
    uint16_t pan;    /* PAN Identifier */
    uint8_t cid;    /* Context Identifier */
} lowpan_context_key;

/* Context hash table map data. */
typedef struct {
    unsigned   frame;  /* Frame where the context was discovered. */
    uint8_t plen;   /* Prefix length. */
    ws_in6_addr prefix;   /* Compression context. */
} lowpan_context_data;

/* 6LoWPAN contexts. */
#define LOWPAN_CONTEXT_MAX              16
#define LOWPAN_CONTEXT_DEFAULT          0
#define LOWPAN_CONTEXT_LINK_LOCAL       LOWPAN_CONTEXT_MAX
#define LOWPAN_CONTEXT_LINK_LOCAL_BITS  10
static lowpan_context_data  lowpan_context_local;
static lowpan_context_data  lowpan_context_default;
static const char *        lowpan_context_prefs[LOWPAN_CONTEXT_MAX];

/* Preferences */
static bool rfc4944_short_address_format;
static bool iid_has_universal_local_bit;
static bool ipv6_summary_in_tree = true;

/* Helper macro to convert a bit offset/length into a byte count. */
#define BITS_TO_BYTE_LEN(bitoff, bitlen)    ((bitlen)?(((bitlen) + ((bitoff)&0x07) + 7) >> 3):(0))

/* Structure for rebuilding UDP datagrams. */
struct udp_hdr {
    uint16_t            src_port;
    uint16_t            dst_port;
    uint16_t            length;
    uint16_t            checksum;
};

/* Structure used to store decompressed header chains until reassembly. */
struct lowpan_nhdr {
    /* List Linking */
    struct lowpan_nhdr  *next;
    /* Next Header */
    uint8_t             proto;
    unsigned            length;
    unsigned            reported;
};
#define LOWPAN_NHDR_DATA(nhdr)  ((uint8_t *)(nhdr) + sizeof (struct lowpan_nhdr))

/* Dissector prototypes */
static void         proto_init_6lowpan          (void);
static void         prefs_6lowpan_apply         (void);
static int          dissect_6lowpan             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static tvbuff_t *   dissect_6lowpan_ipv6        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_hc1         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int dgram_size, const uint8_t *siid, const uint8_t *diid);
static tvbuff_t *   dissect_6lowpan_bc0         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_iphc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int dgram_size, const uint8_t *siid, const uint8_t *diid);
static struct lowpan_nhdr *
                    dissect_6lowpan_iphc_nhc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int dgram_size, const uint8_t *siid, const uint8_t *diid);
static tvbuff_t *   dissect_6lowpan_mesh        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t *siid, uint8_t *diid);
static tvbuff_t *   dissect_6lowpan_rfrag       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const uint8_t *siid, const uint8_t *diid);
static tvbuff_t *   dissect_6lowpan_rfrag_ack   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_frag_first  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const uint8_t *siid, const uint8_t *diid);
static tvbuff_t *   dissect_6lowpan_frag_middle (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void         dissect_6lowpan_unknown     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_6loRH       (tvbuff_t *tvb, unsigned offset, proto_tree *tree);


/* Helper functions. */
static bool         lowpan_dlsrc_to_ifcid   (packet_info *pinfo, uint8_t *ifcid);
static bool         lowpan_dldst_to_ifcid   (packet_info *pinfo, uint8_t *ifcid);
static void         lowpan_addr16_to_ifcid  (uint16_t addr, uint8_t *ifcid);
static void         lowpan_addr16_with_panid_to_ifcid(uint16_t panid, uint16_t addr, uint8_t *ifcid);
static void         lowpan_addr48_to_ifcid  (const uint8_t *addr, uint8_t *ifcid);
static tvbuff_t *   lowpan_reassemble_ipv6  (tvbuff_t *tvb, packet_info *pinfo, struct ws_ip6_hdr *ipv6, struct lowpan_nhdr *nhdr_list);
static uint8_t      lowpan_parse_nhc_proto  (tvbuff_t *tvb, int offset);

/* Context table helpers */
static unsigned     lowpan_context_hash     (const void *key);
static gboolean         lowpan_context_equal    (const void *a, const void *b);
static lowpan_context_data *lowpan_context_find(uint8_t cid, uint16_t pan);

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_pfxcpy
 *  DESCRIPTION
 *      A version of memcpy that takes a length in bits. If the
 *      length is not byte-aligned, the final byte will be
 *      manipulated so that only the desired number of bits are
 *      copied.
 *  PARAMETERS
 *      dst             ; Destination.
 *      src             ; Source.
 *      bits            ; Number of bits to copy.
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
lowpan_pfxcpy(void *dst, const void *src, size_t bits)
{
    memcpy(dst, src, bits>>3);
    if (bits & 0x7) {
        uint8_t mask = ((0xff00) >> (bits & 0x7));
        uint8_t last = ((const uint8_t *)src)[bits>>3] & mask;
        ((uint8_t *)dst)[bits>>3] &= ~mask;
        ((uint8_t *)dst)[bits>>3] |= last;
    }
} /* lowpan_pfxcpy */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_context_hash
 *  DESCRIPTION
 *      Context table hash function.
 *  PARAMETERS
 *      key             ; Pointer to a lowpan_context_key type.
 *  RETURNS
 *      unsigned        ; The hashed key value.
 *---------------------------------------------------------------
 */
static unsigned
lowpan_context_hash(const void *key)
{
    return (((const lowpan_context_key *)key)->cid) | (((const lowpan_context_key *)key)->pan << 8);
} /* lowpan_context_hash */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_context_equal
 *  DESCRIPTION
 *      Context table equals function.
 *  PARAMETERS
 *      key             ; Pointer to a lowpan_context_key type.
 *  RETURNS
 *      bool            ;
 *---------------------------------------------------------------
 */
static gboolean
lowpan_context_equal(const void *a, const void *b)
{
    return (((const lowpan_context_key *)a)->pan == ((const lowpan_context_key *)b)->pan) &&
           (((const lowpan_context_key *)a)->cid == ((const lowpan_context_key *)b)->cid);
} /* lowpan_context_equal */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_context_find
 *  DESCRIPTION
 *      Context table lookup function.
 *  PARAMETERS
 *      cid             ; Context identifier.
 *      pan             ; PAN identifier.
 *  RETURNS
 *      lowpan_context_data *;
 *---------------------------------------------------------------
 */
static lowpan_context_data *
lowpan_context_find(uint8_t cid, uint16_t pan)
{
    lowpan_context_key  key;
    lowpan_context_data *data;

    /* Check for the internal link-local context. */
    if (cid == LOWPAN_CONTEXT_LINK_LOCAL) return &lowpan_context_local;

    /* Lookup the context from the table. */
    key.pan = pan;
    key.cid = cid;
    data = (lowpan_context_data *)g_hash_table_lookup(lowpan_context_table, &key);
    if (data) return data;

    /* If we didn't find a match, try again with the broadcast PAN. */
    if (pan != IEEE802154_BCAST_PAN) {
        key.pan = IEEE802154_BCAST_PAN;
        data = (lowpan_context_data *)g_hash_table_lookup(lowpan_context_table, &key);
        if (data) return data;
    }

    /* If the lookup failed, return the default context (::/0) */
    return &lowpan_context_default;
} /* lowpan_context_find */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_context_insert
 *  DESCRIPTION
 *      Context table insert function.
 *  PARAMETERS
 *      cid             ; Context identifier.
 *      pan             ; PAN identifier.
 *      plen            ; Prefix length.
 *      prefix          ; Compression prefix.
 *      frame           ; Frame number.
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
void
lowpan_context_insert(uint8_t cid, uint16_t pan, uint8_t plen, ws_in6_addr *prefix, unsigned frame)
{
    lowpan_context_key  key;
    lowpan_context_data *data;
    void *              pkey;
    void *              pdata;

    /* Sanity! */
    if (plen > 128) return;
    if (!prefix) return;
    if (!lowpan_context_table) return;

    /* Search the context table for an existing entry. */
    key.pan = pan;
    key.cid = cid;
    if (g_hash_table_lookup_extended(lowpan_context_table, &key, NULL, &pdata)) {
        /* Context already exists. */
        data = (lowpan_context_data *)pdata;
        if ( (data->plen == plen) && (memcmp(&data->prefix, prefix, (plen+7)/8) == 0) ) {
            /* Context already exists with no change. */
            return;
        }
    }
    pkey = wmem_memdup(NULL, &key, sizeof(key));

    /* Create a new context */
    data = wmem_new(NULL, lowpan_context_data);
    data->frame = frame;
    data->plen = plen;
    memset(&data->prefix, 0, sizeof(ws_in6_addr)); /* Ensure zero padding */
    lowpan_pfxcpy(&data->prefix, prefix, plen);
    g_hash_table_insert(lowpan_context_table, pkey, data);
} /* lowpan_context_insert */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_context_free
 *  DESCRIPTION
 *     Frees the allocated memory for the context hash table
 *  PARAMETERS
 *      data            ; Pointer to key or value
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
lowpan_context_free(void *data)
{
    wmem_free(NULL, data);
} /* lowpan_context_free */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_addr16_to_ifcid
 *  DESCRIPTION
 *      Converts a short address to in interface identifier as
 *      per rfc 6282 section 3.2.2.
 *  PARAMETERS
 *      addr            ; 16-bit short address.
 *      ifcid           ; interface identifier (output).
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
lowpan_addr16_to_ifcid(uint16_t addr, uint8_t *ifcid)
{
    /* Note: The PANID is no longer used in building the IID. */
    ifcid[0] = 0x00; /* the U/L bit must be cleared. */
    ifcid[1] = 0x00;
    ifcid[2] = 0x00;
    ifcid[3] = 0xff;
    ifcid[4] = 0xfe;
    ifcid[5] = 0x00;
    ifcid[6] = (addr >> 8) & 0xff;
    ifcid[7] = (addr >> 0) & 0xff;
} /* lowpan_addr16_to_ifcid  */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_addr16_with_panid_to_ifcid
 *  DESCRIPTION
 *      Converts a short address to in interface identifier as
 *      per rfc 4944 section 6.
 *  PARAMETERS
 *      panid           ; 16-bit PAN ID.
 *      addr            ; 16-bit short address.
 *      ifcid           ; interface identifier (output).
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
lowpan_addr16_with_panid_to_ifcid(uint16_t panid, uint16_t addr, uint8_t *ifcid)
{
    /* Note: The PANID is used in building the IID following RFC 2464 section 4. */
    ifcid[0] = (panid >> 8) & 0xfd; /* the U/L bit must be cleared. */
    ifcid[1] = (panid >> 0) & 0xff;
    ifcid[2] = 0x00;
    ifcid[3] = 0xff;
    ifcid[4] = 0xfe;
    ifcid[5] = 0x00;
    ifcid[6] = (addr >> 8) & 0xff;
    ifcid[7] = (addr >> 0) & 0xff;
} /* lowpan_addr16_with_panid_to_ifcid  */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_addr48_to_ifcid
 *  DESCRIPTION
 *      Converts an IEEE 48-bit MAC identifier to an interface
 *      identifier as per RFC 4291 Appendix A.
 *  PARAMETERS
 *      addr            ; 48-bit MAC identifier.
 *      ifcid           ; interface identifier (output).
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
lowpan_addr48_to_ifcid(const uint8_t *addr, uint8_t *ifcid)
{
    static const uint8_t unknown_addr[] = { 0, 0, 0, 0, 0, 0 };

    /* Don't convert unknown addresses */
    if (memcmp(addr, unknown_addr, sizeof(unknown_addr)) != 0) {
        ifcid[0] = addr[0];
        ifcid[1] = addr[1];
        ifcid[2] = addr[2];
        ifcid[3] = 0xff;
        ifcid[4] = 0xfe;
        ifcid[5] = addr[3];
        ifcid[6] = addr[4];
        ifcid[7] = addr[5];
        if (iid_has_universal_local_bit) {
            ifcid[0] ^= 0x02; /* Invert the U/L bit. */
        }
    } else {
        memset(ifcid, 0, LOWPAN_IFC_ID_LEN);
    }
} /* lowpan_ether_to_ifcid */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_dlsrc_to_ifcid
 *  DESCRIPTION
 *      Finds an interface identifier from the data-link source
 *      addressing.
 *  PARAMETERS
 *      pinfo           ; packet information.
 *      ifcid           ; interface identifier (output).
 *  RETURNS
 *      bool            ; true if an interface identifier could
 *                          be found.
 *---------------------------------------------------------------
 */
static bool
lowpan_dlsrc_to_ifcid(packet_info *pinfo, uint8_t *ifcid)
{
    ieee802154_hints_t  *hints;

    /* Check the link-layer address field. */
    if (pinfo->dl_src.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_src.data, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return true;
    } else if (pinfo->dl_src.type == AT_ETHER) {
        lowpan_addr48_to_ifcid((const uint8_t *)pinfo->dl_src.data, ifcid);
        return true;
    }

    /* Lookup the IEEE 802.15.4 addressing hints. */
    hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);
    if (hints) {

        /* Convert the 16-bit short address to an IID using the PAN ID (RFC 4944) or not depending on the preference */
        if (rfc4944_short_address_format) {
            lowpan_addr16_with_panid_to_ifcid(hints->src_pan, hints->src16, ifcid);
        } else {
            lowpan_addr16_to_ifcid(hints->src16, ifcid);
        }

        return true;
    } else {
        /* Failed to find a link-layer source address. */
        memset(ifcid, 0, LOWPAN_IFC_ID_LEN);
        return false;
    }
} /* lowpan_dlsrc_to_ifcid */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_dldst_to_ifcid
 *  DESCRIPTION
 *      Finds an interface identifier from the data-link destination
 *      addressing.
 *  PARAMETERS
 *      pinfo           ; packet information.
 *      ifcid           ; interface identifier (output).
 *  RETURNS
 *      bool            ; true if an interface identifier could
 *                          be found.
 *---------------------------------------------------------------
 */
static bool
lowpan_dldst_to_ifcid(packet_info *pinfo, uint8_t *ifcid)
{
    ieee802154_hints_t  *hints;

    /* Check the link-layer address field. */
    if (pinfo->dl_dst.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_dst.data, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return true;
    } else if (pinfo->dl_dst.type == AT_ETHER) {
        lowpan_addr48_to_ifcid((const uint8_t *)pinfo->dl_dst.data, ifcid);
        return true;
    }

    /* Lookup the IEEE 802.15.4 addressing hints. */
    hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);
    if (hints) {

        /* Convert the 16-bit short address to an IID using the PAN ID (RFC 4944) or not depending on the preference */
        if (rfc4944_short_address_format) {
            lowpan_addr16_with_panid_to_ifcid(hints->src_pan, hints->dst16, ifcid);
        } else {
            lowpan_addr16_to_ifcid(hints->dst16, ifcid);
        }

        return true;
    } else {
        /* Failed to find a link-layer destination address. */
        memset(ifcid, 0, LOWPAN_IFC_ID_LEN);
        return false;
    }
} /* lowpan_dldst_to_ifcid */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_reassemble_ipv6
 *  DESCRIPTION
 *      Helper function to rebuild an IPv6 packet from the IPv6
 *      header structure, and a list of next header structures.
 *  PARAMETERS
 *      ipv6            ; IPv6 Header.
 *      nhdr_list       ; Next header list.
 *  RETURNS
 *      tvbuff_t *      ; Reassembled IPv6 packet.
 *---------------------------------------------------------------
 */
static tvbuff_t *
lowpan_reassemble_ipv6(tvbuff_t *tvb, packet_info *pinfo, struct ws_ip6_hdr *ipv6, struct lowpan_nhdr *nhdr_list)
{
    int                 length = 0;
    int                 reported = 0;
    uint8_t *            buffer;
    uint8_t *            cursor;
    struct lowpan_nhdr *nhdr;

    /* Compute the real and reported lengths. */
    for (nhdr = nhdr_list; nhdr; nhdr = nhdr->next) {
        length += nhdr->length;
        reported += nhdr->reported;
    }
    ipv6->ip6h_plen = g_ntohs(reported);

    /* Allocate a buffer for the packet and copy in the IPv6 header. */
    buffer = (uint8_t *)wmem_alloc(pinfo->pool, length + IPv6_HDR_SIZE);
    memcpy(buffer, ipv6, IPv6_HDR_SIZE);
    cursor = buffer + IPv6_HDR_SIZE;

    /* Add the next headers into the buffer. */
    for (nhdr = nhdr_list; nhdr; nhdr = nhdr->next) {
        memcpy(cursor, LOWPAN_NHDR_DATA(nhdr), nhdr->length);
        cursor += nhdr->length;
    };

    /* Return the reassembled packet. */
    return tvb_new_child_real_data(tvb, buffer, length + IPv6_HDR_SIZE, reported + IPv6_HDR_SIZE);
} /* lowpan_reassemble_ipv6 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_parse_nhc_proto
 *  DESCRIPTION
 *      Parses the start of an 6LoWPAN NHC header to determine the
 *      next header protocol identifier. Will return IP_PROTO_NONE
 *      if no valid protocol could be determined.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      offset          ; offset of the NHC.
 *  RETURNS
 *      uint8_t         ; IP_PROTO_* of the next header's protocol.
 *---------------------------------------------------------------
 */
static uint8_t
lowpan_parse_nhc_proto(tvbuff_t *tvb, int offset)
{
    /* Ensure that at least one byte exists. */
    if (!tvb_bytes_exist(tvb, offset, 1)) return IP_PROTO_NONE;

    /* Check for IPv6 extension headers. */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS) == LOWPAN_NHC_PATTERN_EXT) {
        uint8_t     eid = (tvb_get_uint8(tvb, offset) & LOWPAN_NHC_EXT_EID) >> LOWPAN_NHC_EXT_EID_OFFSET;
        switch (eid) {
            case LOWPAN_NHC_EID_HOP_BY_HOP:
                return IP_PROTO_HOPOPTS;
            case LOWPAN_NHC_EID_ROUTING:
                return IP_PROTO_ROUTING;
            case LOWPAN_NHC_EID_FRAGMENT:
                return IP_PROTO_FRAGMENT;
            case LOWPAN_NHC_EID_DEST_OPTIONS:
                return IP_PROTO_DSTOPTS;
            case LOWPAN_NHC_EID_MOBILITY:
                return IP_PROTO_MIPV6;
            case LOWPAN_NHC_EID_IPV6:
                return IP_PROTO_IPV6;
            default:
                /* Unknown protocol type. */
                return IP_PROTO_NONE;
        };
    }
    /* Check for compressed UDP headers. */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_UDP_BITS) == LOWPAN_NHC_PATTERN_UDP) {
        return IP_PROTO_UDP;
    }
    /* Unknown header type. */
    return IP_PROTO_NONE;
} /* lowpan_parse_nhc_proto */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_reassembly_id
 *  DESCRIPTION
 *      Creates an identifier that groups fragments based on the given datagram
 *      tag and the link layer destination address (to differentiate packets
 *      forwarded over different links in a mesh network).
 *  PARAMETERS
 *      pinfo           : packet info.
 *      dgram_tag       ; datagram tag (from the Fragmentation Header).
 *  RETURNS
 *      uint32_t        ; identifier for this group of fragments.
 *---------------------------------------------------------------
 */
static uint32_t
lowpan_reassembly_id(packet_info *pinfo, uint16_t dgram_tag)
{
    /* Start with the datagram tag for identification. If the packet is not
     * being forwarded, then this should be sufficient to prevent collisions
     * which could break reassembly. */
    uint32_t    frag_id = dgram_tag;
    ieee802154_hints_t  *hints;

    /* Forwarded packets in a mesh network have the same datagram tag, mix
     * the IEEE 802.15.4 destination link layer address. */
    if (pinfo->dl_dst.type == AT_EUI64) {
        /* IEEE 64-bit extended address */
        frag_id = add_address_to_hash(frag_id, &pinfo->dl_dst);
    } else {
        /* 16-bit short address */
        hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                    proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);
        if (hints) {
            frag_id |= hints->dst16 << 16;
        }
    }
    return frag_id;
} /* lowpan_reassembly_id */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_heur
 *  DESCRIPTION
 *      Heuristic dissector for 6LoWPAN. Checks if the pattern is
 *      a valid 6LoWPAN type, and not NALP.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; protocol display tree.
 *      data            : ieee802154_packet,
 *  RETURNS
 *      boolean         ; true if the tvbuff was dissected as a
 *                          6LoWPAN packet. If this returns false,
 *                          then no dissection will be attempted.
 *---------------------------------------------------------------
 */
static bool
dissect_6lowpan_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    unsigned offset = 0;

    /* Check for valid patterns. */
    for (;;) {
        /* Parse patterns until we find a match. */
        if (!tvb_reported_length_remaining(tvb, offset)) return false;
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_IPV6_BITS) == LOWPAN_PATTERN_IPV6) break;
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_HC1_BITS)  == LOWPAN_PATTERN_HC1) break;
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_BC0_BITS)  == LOWPAN_PATTERN_BC0) {
            /* Broadcast headers must be followed by another valid header. */
            offset += 2;
            continue;
        }
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) break;
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_MESH_BITS) == LOWPAN_PATTERN_MESH) {
            /* Mesh headers must be followed by another valid header. */
            uint8_t mesh = tvb_get_uint8(tvb, offset++);
            offset += (mesh & LOWPAN_MESH_HEADER_V) ? 2 : 8;
            offset += (mesh & LOWPAN_MESH_HEADER_F) ? 2 : 8;
            if ((mesh & LOWPAN_MESH_HEADER_HOPS) == LOWPAN_MESH_HEADER_HOPS) offset++;
            continue;
        }
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_RFRAG_BITS) == LOWPAN_PATTERN_RFRAG) break;
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_RFRAG_BITS) == LOWPAN_PATTERN_RFRAG_ACK) break;
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAG1) {
            /* First fragment headers must be followed by another valid header. */
            offset += 4;
            continue;
        }
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAGN) break;

        /* If we get here, then we couldn't match to any pattern. */
        return false;
    } /* for */

    /* If we get here, then we found a matching pattern. */
    dissect_6lowpan(tvb, pinfo, tree, data);
    return true;
} /* dissect_6lowpan_heur */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan
 *  DESCRIPTION
 *      Dissector routine for 6LoWPAN packets.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; protocol display tree.
 *      data            ; Packet data (ieee 802.15.4).
 *  RETURNS
 *      int             ; Length of data processed, or 0 if not 6LoWPAN.
 *---------------------------------------------------------------
 */
static int
dissect_6lowpan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *lowpan_tree;
    proto_item *lowpan_root;
    tvbuff_t   *next = tvb;
    unsigned    offset = 0;
    /* Interface identifier of the encapsulating layer. */
    uint8_t     src_iid[LOWPAN_IFC_ID_LEN];
    uint8_t     dst_iid[LOWPAN_IFC_ID_LEN];

    /* Get the interface identifiers from the encapsulating layer. */
    lowpan_dlsrc_to_ifcid(pinfo, src_iid);
    lowpan_dldst_to_ifcid(pinfo, dst_iid);

    /* Create the protocol tree. */
    lowpan_root = proto_tree_add_protocol_format(tree, proto_6lowpan, tvb, 0, -1, "6LoWPAN");
    lowpan_tree = proto_item_add_subtree(lowpan_root, ett_6lowpan);

    /* Add the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "6LoWPAN");

    /* Mesh and Broadcast headers always come first in a 6LoWPAN frame. */
    if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_MESH_BITS) == LOWPAN_PATTERN_MESH) {
        next = dissect_6lowpan_mesh(next, pinfo, lowpan_tree, src_iid, dst_iid);
        if (!next) return tvb_captured_length(tvb);
    }
    if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_BC0_BITS) == LOWPAN_PATTERN_BC0) {
        next = dissect_6lowpan_bc0(next, pinfo, lowpan_tree);
        if (!next) return tvb_captured_length(tvb);
    }

    /* After the mesh and broadcast headers, process dispatch codes recursively. */
    /* Recoverable Fragmentation headers.*/
    if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_RFRAG_BITS) == LOWPAN_PATTERN_RFRAG) {
        next = dissect_6lowpan_rfrag(next, pinfo, lowpan_tree, src_iid, dst_iid);
        if (!next) return tvb_captured_length(tvb);
    }
    else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_RFRAG_BITS) == LOWPAN_PATTERN_RFRAG_ACK) {
        next = dissect_6lowpan_rfrag_ack(next, pinfo, lowpan_tree);
        if (!next) return tvb_captured_length(tvb);
    }
    /* Fragmentation headers.*/
    if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAG1) {
        next = dissect_6lowpan_frag_first(next, pinfo, lowpan_tree, src_iid, dst_iid);
    }
    else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAGN) {
        next = dissect_6lowpan_frag_middle(next, pinfo, lowpan_tree);
    }
    /* Uncompressed IPv6 packets. */
    else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_IPV6_BITS) == LOWPAN_PATTERN_IPV6) {
        next = dissect_6lowpan_ipv6(next, pinfo, lowpan_tree);
    }
    else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_PAGING_DISPATCH_BITS) == LOWPAN_PATTERN_PAGING_DISPATCH) {
        proto_tree_add_bits_item(lowpan_tree, hf_6lowpan_pagenb, tvb, 4, 4, ENC_BIG_ENDIAN);
        offset += 1;
        next = dissect_6lowpan_6loRH(next, offset, lowpan_tree);
        if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
            next = dissect_6lowpan_iphc(next, pinfo, lowpan_tree, -1, src_iid, dst_iid);
            if (!next) return tvb_captured_length(tvb);
        }
        if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_HC1_BITS) == LOWPAN_PATTERN_HC1) {
            next = dissect_6lowpan_hc1(next, pinfo, lowpan_tree, -1, src_iid, dst_iid);
        }
    }
    /* Compressed IPv6 packets. */
    else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_HC1_BITS) == LOWPAN_PATTERN_HC1) {
        next = dissect_6lowpan_hc1(next, pinfo, lowpan_tree, -1, src_iid, dst_iid);
    }
    else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
        next = dissect_6lowpan_iphc(next, pinfo, lowpan_tree, -1, src_iid, dst_iid);
    }
    /* Unknown 6LoWPAN dispatch type */
    else {
        dissect_6lowpan_unknown(next, pinfo, lowpan_tree);
        return tvb_captured_length(tvb);
    }

    /* The last step should have returned an uncompressed IPv6 datagram. */
    if (next) {
        call_dissector(ipv6_handle, next, pinfo, tree);
    }
    return tvb_captured_length(tvb);
} /* dissect_6lowpan */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_6loRH
 *  DESCRIPTION
 *      Dissector routine for 6loRH fields in 6LoWPAN packets.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      offset          ; offset of the 6loRH fields
 *      tree            ; protocol display tree.
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_6loRH(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{

    uint16_t            check;
    int                 IK;
    uint16_t            loRH_flags;
    proto_tree *        loRH_tree;
    uint16_t            loRHE_length;
    uint8_t             loRHE_type;
    uint16_t            loRHE_class;
    uint8_t             rpl_instance;
    int                 condition = 1;
    int16_t             loRHE_unitnums;

    struct ws_ip6_hdr      ipv6;
    static int * const bits_RHC[] = {
        &hf_6lowpan_5_bit_o,
        &hf_6lowpan_5_bit_r,
        &hf_6lowpan_5_bit_f,
        &hf_6lowpan_5_bit_i,
        &hf_6lowpan_5_bit_k,
        NULL
    };

    loRH_flags  = tvb_get_ntohs(tvb, offset);
    check       = loRH_flags & 0xC000;

    if (check == LOWPAN_6LORH_GENERAL_FORMAT) {

        memset(&ipv6.ip6h_src, 0, sizeof(ipv6.ip6h_src));

        while(condition > 0){
            condition -= 1 ;
            /*Create the tree*/
            loRH_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_lowpan_routing_header_dispatch, NULL, "6LoRH:");

            /* Get and display the pattern. */
            proto_tree_add_bits_item(loRH_tree, hf_6lowpan_routing_header, tvb, 8*offset, LOWPAN_PATTERN_IPHC_BITS, ENC_BIG_ENDIAN);
            /*=====================================================
             * Parse 6LoRH Header flags.
             *=====================================================
             */

            loRHE_class     = (loRH_flags & LOWPAN_PATTERN_6LORHE_CLASS) >> LOWPAN_PATTERN_6LORHE_CLASS_BITS;
            loRHE_length    = (loRH_flags & LOWPAN_PATTERN_6LORHE_LENGTH) >> LOWPAN_PATTERN_6LORHE_LENGTH_BITS;
            loRHE_unitnums  = loRHE_length + 1;
            loRHE_type      = (loRH_flags & LOWPAN_PATTERN_6LORHE_TYPE);
            IK              = (loRH_flags & LOWPAN_5_RPI_BITS_IK) >> 8;

            proto_item_append_text(loRH_tree, " %s", val_to_str_const(loRHE_type, lowpan_patterns_rh_type, "Unknown"));

            switch (loRHE_class){
                case (LOWPAN_PATTERN_6LORHE):/*Elective Routing Header*/
                    condition = 1 ;
                    if (loRHE_type >= 15) { /* BIER implementation */
                        proto_tree_add_uint             (loRH_tree, hf_6lowpan_6lorhe_size, tvb, offset, 2, loRH_flags & LOWPAN_PATTERN_6LORHE_LENGTH);
                        proto_tree_add_uint             (loRH_tree, hf_6lowpan_6lorhe_type, tvb, offset, 2, loRHE_type);
                        offset += 2 ;
                        if (loRHE_type == 15) {
                            for (int i=0; i<loRHE_unitnums; i++) {
                                proto_tree_add_item(loRH_tree, hf_6lowpan_6lorhe_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
                                offset += 4;
                            }
                        }
                    }
                    else if (loRHE_type == LOWPAN_IP_IN_IP_6LORH) {
                        memset(&ipv6.ip6h_src, 0, sizeof(ipv6.ip6h_src));
                        proto_tree_add_item(loRH_tree, hf_6lowpan_6lorhe_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(loRH_tree, hf_6lowpan_6lorhe_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(loRH_tree, hf_6lowpan_6lorhe_hoplimit, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

                        if (loRHE_length > 1) {
                            for (int i = 0; i < 16; ++i) {
                                ipv6.ip6h_src.bytes[i] = tvb_get_uint8(tvb, offset + 3 + i);
                            }
                            proto_tree_add_ipv6(loRH_tree, hf_6lowpan_6lorhc_address_src, tvb, offset + 3, 16,
                                                &ipv6.ip6h_src);
                        }
                        offset += 2 + loRHE_length;
                    }
                    else {
                        condition -= 1;
                    }
                    break; /* case LOWPAN_PATTERN_6LORHE */

                case (LOWPAN_PATTERN_6LORHC): /*Critical Routing Header*/
                    condition = 1 ;
                    if (loRHE_type == 5){
                        proto_tree_add_bitmask_list (loRH_tree, tvb, offset, 2, bits_RHC, ENC_NA);
                        proto_tree_add_item         (loRH_tree, hf_6lowpan_6lorhe_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        switch (IK){
                            case  BITS_IK_0:
                                proto_tree_add_item             (loRH_tree, hf_6lowpan_rpl_instance, tvb, offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item             (loRH_tree, hf_6lowpan_sender_rank2, tvb, offset+1, 2, ENC_BIG_ENDIAN);
                                offset += 3;
                                break;
                            case BITS_IK_1:
                                proto_tree_add_item             (loRH_tree, hf_6lowpan_rpl_instance, tvb, offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item             (loRH_tree, hf_6lowpan_sender_rank1, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                                offset += 2;
                                break;
                            case BITS_IK_2:
                                rpl_instance = 0x00;
                                proto_tree_add_uint             (loRH_tree, hf_6lowpan_rpl_instance, tvb, offset, 0, rpl_instance);
                                proto_tree_add_item             (loRH_tree, hf_6lowpan_sender_rank2, tvb, offset, 2, ENC_BIG_ENDIAN);
                                offset += 2;
                                break;
                            case BITS_IK_3:
                                rpl_instance = 0x00;
                                proto_tree_add_uint             (loRH_tree, hf_6lowpan_rpl_instance, tvb, offset, 0, rpl_instance);
                                proto_tree_add_item             (loRH_tree, hf_6lowpan_sender_rank1, tvb, offset, 1, ENC_BIG_ENDIAN);
                                offset +=1;
                                break;
                            }
                        }
                    else if (loRHE_type <= 4){
                        memset(&ipv6.ip6h_src, 0, sizeof(ipv6.ip6h_src));
                        proto_tree_add_uint             (loRH_tree, hf_6lowpan_6lorhc_size, tvb, offset, 2, loRH_flags & LOWPAN_PATTERN_6LORHE_LENGTH);
                        proto_tree_add_uint             (loRH_tree, hf_6lowpan_6lorhe_type, tvb, offset, 2, loRHE_type);
                        offset += 2 ;
                        switch (loRHE_type){
                            case IPV6_ADDR_COMPRESSED_1_BYTE: /* IPv6 address compressed to 1 byte */
                                for (int i=0; i<loRHE_unitnums; i++) {
                                    for (int j = 0; j < 1; j++){
                                        ipv6.ip6h_src.bytes[15-j] = tvb_get_uint8(tvb, offset);
                                    }
                                    proto_tree_add_ipv6(tree, hf_6lowpan_6lorhc_address_hop0, tvb, offset, 1, &ipv6.ip6h_src);
                                    offset +=1;
                                }
                                break;

                            case IPV6_ADDR_COMPRESSED_2_BYTE: /* IPv6 address compressed to 2 bytes */
                                for (int i=0; i<loRHE_unitnums; i++) {
                                    for (int j = 0; j < 2; ++j){
                                        ipv6.ip6h_src.bytes[15-1+j] = tvb_get_uint8(tvb, offset);
                                        offset +=1;
                                    }
                                    proto_tree_add_ipv6(tree, hf_6lowpan_6lorhc_address_hop1, tvb, offset - 2, 2, &ipv6.ip6h_src);
                                }
                                break;

                            case IPV6_ADDR_COMPRESSED_4_BYTE: /* IPv6 address compressed to 4 bytes */
                                for (int i=0; i<loRHE_unitnums; i++) {
                                    for (int j = 0; j < 4; j++){
                                        ipv6.ip6h_src.bytes[15-3+j] = tvb_get_uint8(tvb, offset);
                                        offset +=1;
                                    }
                                    proto_tree_add_ipv6(tree, hf_6lowpan_6lorhc_address_hop2, tvb, offset - 4, 4, &ipv6.ip6h_src);
                                }
                                break;

                            case IPV6_ADDR_COMPRESSED_8_BYTE: /* IPv6 address compressed to 8 bytes */
                                for (int i=0; i<loRHE_unitnums; i++) {
                                    for (int j = 0; j < 8; j++){
                                        ipv6.ip6h_src.bytes[15-7+j] = tvb_get_uint8(tvb, offset);
                                        offset +=1;
                                    }
                                    proto_tree_add_ipv6(tree, hf_6lowpan_6lorhc_address_hop3, tvb, offset - 8, 8, &ipv6.ip6h_src);
                                }
                                break;
                            case IPV6_ADDR_COMPRESSED_16_BYTE: /* IPv6 address compressed to 16 bytes */
                                for (int i=0; i<loRHE_unitnums; i++) {
                                    for (int j = 0; j < 16; j++){
                                        ipv6.ip6h_src.bytes[j] = tvb_get_uint8(tvb, offset);
                                        offset +=1;
                                    }
                                    proto_tree_add_ipv6(tree, hf_6lowpan_6lorhc_address_hop4, tvb, offset - 16, 16, &ipv6.ip6h_src);
                                }
                                break; /**/
                            } /* switch loRHE_type */
                        } /* else if (loRHE_type <= 4) */
                    else {
                        condition -= 1;
                    }
                    break; /* case LOWPAN_PATTERN_6LORHC */

                    default:
                        condition -= 1 ;
                        break;
                }  /* switch loRHE_class */
            loRH_flags  = tvb_get_ntohs(tvb, offset);
            loRHE_class = (loRH_flags & LOWPAN_PATTERN_6LORHE_CLASS) >> 13;

            if ((loRHE_class) != LOWPAN_PATTERN_6LORHE){
                if ((loRHE_class) != LOWPAN_PATTERN_6LORHC){
                    condition -= 1;
                }
            }
        } /* while (condition > 0)*/
    }
    return tvb_new_subset_remaining(tvb, offset);
} /* dissect_6lowpan_6loRH */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_ipv6
 *  DESCRIPTION
 *      Dissector routine for an uncompressed IPv6 header type.
 *
 *      This is one of the final encapsulation types, and will
 *      returned an uncompressed IPv6 datagram (or fragment
 *      thereof).
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      offset          ; offset to the start of the header.
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_ipv6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    /* Get and display the pattern. */
    proto_tree_add_bits_item(tree, hf_6lowpan_pattern,
            tvb, 0, LOWPAN_PATTERN_IPV6_BITS, ENC_BIG_ENDIAN);

    /* Create a tvbuff subset for the ipv6 datagram. */
    return tvb_new_subset_remaining(tvb, 1);
} /* dissect_6lowpan_ipv6 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_hc1
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN HC1 header.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      dgram_size      ; Datagram size (or <0 if not fragmented).
 *      siid            ; Source Interface ID.
 *      diid            ; Destination Interface ID.
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_hc1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int dgram_size, const uint8_t *siid, const uint8_t *diid)
{
    int                 offset = 0;
    int                 bit_offset;
    int                 i;
    uint8_t             hc1_encoding;
    uint8_t             hc_udp_encoding = 0;
    uint8_t             next_header;
    proto_tree *        hc_tree;
    proto_item *        hc_item;
    tvbuff_t *          ipv6_tvb;
    /* IPv6 header. */
    uint8_t             ipv6_class;
    uint32_t            ipv6_flow;
    struct ws_ip6_hdr   ipv6;
    struct lowpan_nhdr *nhdr_list;
    static int * const hc1_encodings[] = {
        &hf_6lowpan_hc1_source_prefix,
        &hf_6lowpan_hc1_source_ifc,
        &hf_6lowpan_hc1_dest_prefix,
        &hf_6lowpan_hc1_dest_ifc,
        &hf_6lowpan_hc1_class,
        &hf_6lowpan_hc1_next,
        &hf_6lowpan_hc1_more,
        NULL
    };
    static int * const hc2_encodings[] = {
        &hf_6lowpan_hc2_udp_src,
        &hf_6lowpan_hc2_udp_dst,
        &hf_6lowpan_hc2_udp_len,
        NULL
    };

    /*=====================================================
     * Parse HC Encoding Flags
     *=====================================================
     */
    /* Create a tree for the HC1 Header. */
    hc_tree = proto_tree_add_subtree(tree, tvb, 0, 2, ett_6lowpan_hc1, &hc_item, "HC1 Encoding");

    /* Get and display the pattern. */
    proto_tree_add_bits_item(hc_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_HC1_BITS, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get and display the HC1 encoding bits. */
    hc1_encoding = tvb_get_uint8(tvb, offset);
    next_header = ((hc1_encoding & LOWPAN_HC1_NEXT) >> 1);
    proto_tree_add_bitmask(hc_tree, tvb, offset, hf_6lowpan_hc1_encoding,
                   ett_6lowpan_hc1_encoding, hc1_encodings, ENC_NA);
    offset += 1;

    /* Get and display the HC2 encoding bits, if present. */
    if (hc1_encoding & LOWPAN_HC1_MORE) {
        if (next_header == LOWPAN_HC1_NEXT_UDP) {
            hc_udp_encoding = tvb_get_uint8(tvb, offset);
            proto_tree_add_bitmask(tree, tvb, offset, hf_6lowpan_hc2_udp_encoding,
                   ett_6lowpan_hc2_udp, hc2_encodings, ENC_NA);
            offset += 1;
        }
        else {
            /* HC1 states there are more bits, but an illegal next header was defined. */
            expert_add_info(pinfo, hc_item, &ei_6lowpan_hc1_more_bits);
            return NULL;
        }
    }

    /*=====================================================
     * Parse Uncompressed IPv6 Header Fields
     *=====================================================
     */
    /*
     * And now all hell breaks loose. After the header encoding fields, we are
     * left with an assortment of optional fields from the IPv6 header,
     * depending on which fields are present or not, the headers may not be
     * aligned to an octet boundary.
     *
     * From now on we have to parse the uncompressed fields relative to a bit
     * offset.
     */
    bit_offset = offset << 3;

    /* Parse hop limit */
    ipv6.ip6h_hlim = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS);
    proto_tree_add_uint(tree, hf_6lowpan_hop_limit, tvb, bit_offset>>3,
            BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS), ipv6.ip6h_hlim);
    bit_offset += LOWPAN_IPV6_HOP_LIMIT_BITS;

    /*=====================================================
     * Parse/Decompress IPv6 Source Address
     *=====================================================
     */
    offset = bit_offset;
    if (!(hc1_encoding & LOWPAN_HC1_SOURCE_PREFIX)) {
        for (i=0; i<8; i++, bit_offset += 8) {
            ipv6.ip6h_src.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(ipv6.ip6h_src.bytes, lowpan_llprefix, sizeof(lowpan_llprefix));
    }
    if (!(hc1_encoding & LOWPAN_HC1_SOURCE_IFC)) {
        for (i=8; i<16; i++, bit_offset += 8) {
            ipv6.ip6h_src.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(&ipv6.ip6h_src.bytes[sizeof(ipv6.ip6h_src) - LOWPAN_IFC_ID_LEN], siid, LOWPAN_IFC_ID_LEN);
    }
    /* Display the source address. */
    proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset>>3,
            BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), &ipv6.ip6h_src);

    /*
     * Do not set the address columns until after defragmentation, since we have
     * to do decompression before reassembly, and changing the address will cause
     * wireshark to think that the middle fragments came from another device.
     */

    /*=====================================================
     * Parse/Decompress IPv6 Destination Address
     *=====================================================
     */
    offset = bit_offset;
    if (!(hc1_encoding & LOWPAN_HC1_DEST_PREFIX)) {
        for (i=0; i<8; i++, bit_offset += 8) {
            ipv6.ip6h_dst.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(ipv6.ip6h_dst.bytes, lowpan_llprefix, sizeof(lowpan_llprefix));
    }
    if (!(hc1_encoding & LOWPAN_HC1_DEST_IFC)) {
        for (i=8; i<16; i++, bit_offset += 8) {
            ipv6.ip6h_dst.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(&ipv6.ip6h_dst.bytes[sizeof(ipv6.ip6h_dst) - LOWPAN_IFC_ID_LEN], diid, LOWPAN_IFC_ID_LEN);
    }
    /* Display the destination address. */
    proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset>>3,
            BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), &ipv6.ip6h_dst);

    /*
     * Do not set the address columns until after defragmentation, since we have
     * to do decompression before reassembly, and changing the address will cause
     * wireshark to think that the middle fragments came from another device.
     */

    /* Parse the traffic class and flow label. */
    ipv6_class = 0;
    ipv6_flow = 0;
    if (!(hc1_encoding & LOWPAN_HC1_TRAFFIC_CLASS)) {
        /* Parse the traffic class. */
        ipv6_class = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_TRAFFIC_CLASS_BITS);
        proto_tree_add_uint(tree, hf_6lowpan_traffic_class, tvb, bit_offset>>3,
                BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_TRAFFIC_CLASS_BITS), ipv6_class);
        bit_offset += LOWPAN_IPV6_TRAFFIC_CLASS_BITS;

        /* Parse the flow label. */
        ipv6_flow = tvb_get_bits32(tvb, bit_offset, LOWPAN_IPV6_FLOW_LABEL_BITS, ENC_BIG_ENDIAN);
        proto_tree_add_uint(tree, hf_6lowpan_flow_label, tvb, bit_offset>>3,
                BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_FLOW_LABEL_BITS), ipv6_flow);
        bit_offset += LOWPAN_IPV6_FLOW_LABEL_BITS;
    }

    /* Rebuild the IPv6 flow label, traffic class and version fields. */
    ipv6.ip6h_vc_flow = ipv6_flow;
    ipv6.ip6h_vc_flow |= ((uint32_t)ipv6_class << LOWPAN_IPV6_FLOW_LABEL_BITS);
    ipv6.ip6h_vc_flow |= ((uint32_t)0x6 << (LOWPAN_IPV6_TRAFFIC_CLASS_BITS + LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6h_vc_flow = g_ntohl(ipv6.ip6h_vc_flow);

    /* Parse the IPv6 next header field. */
    if (next_header == LOWPAN_HC1_NEXT_UDP) {
        ipv6.ip6h_nxt = IP_PROTO_UDP;
    }
    else if (next_header == LOWPAN_HC1_NEXT_ICMP) {
        ipv6.ip6h_nxt = IP_PROTO_ICMPV6;
    }
    else if (next_header == LOWPAN_HC1_NEXT_TCP) {
        ipv6.ip6h_nxt = IP_PROTO_TCP;
    }
    else {
        /* Parse the next header field. */
        ipv6.ip6h_nxt = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_NEXT_HEADER_BITS);
        proto_tree_add_uint_format_value(tree, hf_6lowpan_next_header, tvb, bit_offset>>3,
                BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_NEXT_HEADER_BITS), ipv6.ip6h_nxt,
                "%s (0x%02x)", ipprotostr(ipv6.ip6h_nxt), ipv6.ip6h_nxt);
        bit_offset += LOWPAN_IPV6_NEXT_HEADER_BITS;
    }

    /*=====================================================
     * Parse and Reconstruct the UDP Header
     *=====================================================
     */
    if ((hc1_encoding & LOWPAN_HC1_MORE) && (next_header == LOWPAN_HC1_NEXT_UDP)) {
        struct udp_hdr  udp;
        int             length;

        /* Parse the source port. */
        offset = bit_offset;
        if (hc_udp_encoding & LOWPAN_HC2_UDP_SRCPORT) {
            udp.src_port = tvb_get_bits8(tvb, bit_offset, LOWPAN_UDP_PORT_COMPRESSED_BITS) + LOWPAN_PORT_12BIT_OFFSET;
            bit_offset += LOWPAN_UDP_PORT_COMPRESSED_BITS;
        }
        else {
            udp.src_port = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_PORT_BITS, ENC_BIG_ENDIAN);
            bit_offset += LOWPAN_UDP_PORT_BITS;
        }
        proto_tree_add_uint(tree, hf_6lowpan_udp_src, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), udp.src_port);
        udp.src_port = g_ntohs(udp.src_port);

        /* Parse the destination port. */
        offset = bit_offset;
        if (hc_udp_encoding & LOWPAN_HC2_UDP_DSTPORT) {
            udp.dst_port = tvb_get_bits8(tvb, bit_offset, LOWPAN_UDP_PORT_COMPRESSED_BITS) + LOWPAN_PORT_12BIT_OFFSET;
            bit_offset += LOWPAN_UDP_PORT_COMPRESSED_BITS;
        }
        else {
            udp.dst_port = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_PORT_BITS, ENC_BIG_ENDIAN);
            bit_offset += LOWPAN_UDP_PORT_BITS;
        }
        proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), udp.dst_port);
        udp.dst_port = g_ntohs(udp.dst_port);

        /* Parse the length, if present. */
        if (!(hc_udp_encoding & LOWPAN_HC2_UDP_LENGTH)) {
            udp.length = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_LENGTH_BITS, ENC_BIG_ENDIAN);
            proto_tree_add_uint(tree, hf_6lowpan_udp_len, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_LENGTH_BITS), udp.length);

            bit_offset += LOWPAN_UDP_LENGTH_BITS;
        }
        /* Compute the length from the fragmentation headers. */
        else if (dgram_size >= 0) {
            if (dgram_size < IPv6_HDR_SIZE) {
                /* Datagram size is too small */
                return NULL;
            }
            udp.length = dgram_size - IPv6_HDR_SIZE;
        }
        /* Compute the length from the tvbuff size. */
        else {
            udp.length = tvb_reported_length(tvb);
            udp.length -= BITS_TO_BYTE_LEN(0, bit_offset + LOWPAN_UDP_CHECKSUM_BITS);
            udp.length += (int)sizeof(struct udp_hdr);
        }
        udp.length = g_ntohs(udp.length);

        /* Parse the checksum. */
        udp.checksum = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_CHECKSUM_BITS, ENC_BIG_ENDIAN);
        proto_tree_add_uint(tree, hf_6lowpan_udp_checksum, tvb, bit_offset>>3,
                BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_CHECKSUM_BITS), udp.checksum);
        bit_offset += LOWPAN_UDP_CHECKSUM_BITS;
        udp.checksum = g_ntohs(udp.checksum);

        /* Construct the next header for the UDP datagram. */
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        length = tvb_captured_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)wmem_alloc(pinfo->pool, sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = IP_PROTO_UDP;
        nhdr_list->length = length + (int)sizeof(struct udp_hdr);
        nhdr_list->reported = g_ntohs(udp.length);

        /* Copy the UDP header into the buffer. */
        memcpy(LOWPAN_NHDR_DATA(nhdr_list), &udp, sizeof(struct udp_hdr));
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr_list) + sizeof(struct udp_hdr), offset, length);
    }
    /*=====================================================
     * Reconstruct the IPv6 Packet
     *=====================================================
     */
    else {
        int length;
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        length = tvb_captured_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)wmem_alloc(pinfo->pool, sizeof(struct lowpan_nhdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6h_nxt;
        nhdr_list->length = length;
        if (dgram_size < 0) {
            nhdr_list->reported = tvb_reported_length_remaining(tvb, offset);
        }
        else {
            nhdr_list->reported = dgram_size - IPv6_HDR_SIZE;
        }
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr_list), offset, nhdr_list->length);
    }

    /* Link the reassembled tvbuff together.  */
    ipv6_tvb = lowpan_reassemble_ipv6(tvb, pinfo, &ipv6, nhdr_list);

    /* Add a new data source for it. */
    add_new_data_source(pinfo, ipv6_tvb, "Decompressed 6LoWPAN HC1");

    return ipv6_tvb;
} /* dissect_6lowpan_hc1 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_iphc
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN IPHC header.
 *
 *      This header is still in the draft phase, but is expected
 *      to replace HC1.
 *
 *      See draft-ietf-6lowpan-hc-15.txt
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      dgram_size      ; Datagram size (or <0 if not fragmented).
 *      siid            ; Source Interface ID.
 *      diid            ; Destination Interface ID.
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed or NULL on error.
 *---------------------------------------------------------------
 */
static tvbuff_t *
// NOLINTNEXTLINE(misc-no-recursion)
dissect_6lowpan_iphc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int dgram_size, const uint8_t *siid, const uint8_t *diid)
{
    ieee802154_hints_t  *hints;
    uint16_t            hint_panid;
    int                 offset = 0;
    int                 length = 0;
    proto_tree *        iphc_tree;
    proto_item *        ti_dam = NULL;
    proto_item *        ti;
    /* IPHC header fields. */
    uint16_t            iphc_flags;
    uint8_t             iphc_traffic;
    uint8_t             iphc_hop_limit;
    uint8_t             iphc_src_mode;
    uint8_t             iphc_dst_mode;
    uint8_t             iphc_ctx = 0;
    /* Contexts to use for address decompression. */
    int                 iphc_sci = LOWPAN_CONTEXT_DEFAULT;
    int                 iphc_dci = LOWPAN_CONTEXT_DEFAULT;
    lowpan_context_data *sctx;
    lowpan_context_data *dctx;
    /* IPv6 header */
    uint8_t             ipv6_dscp = 0;
    uint8_t             ipv6_ecn = 0;
    uint32_t            ipv6_flowlabel = 0;
    struct ws_ip6_hdr   ipv6;
    tvbuff_t *          ipv6_tvb;
    /* Next header chain */
    struct lowpan_nhdr  *nhdr_list;

    /* Lookup the IEEE 802.15.4 addressing hints. */
    hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);
    hint_panid = (hints) ? (hints->src_pan) : (IEEE802154_BCAST_PAN);

    /* Create a tree for the IPHC header. */
    iphc_tree = proto_tree_add_subtree(tree, tvb, 0, 2, ett_6lowpan_iphc, NULL, "IPHC Header");

    /* Display the pattern. */
    proto_tree_add_bits_item(iphc_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_IPHC_BITS, ENC_BIG_ENDIAN);

    /*=====================================================
     * Parse IPHC Header flags.
     *=====================================================
     */
    iphc_flags      = tvb_get_ntohs(tvb, offset);
    iphc_traffic    = (iphc_flags & LOWPAN_IPHC_FLAG_FLOW) >> LOWPAN_IPHC_FLAG_OFFSET_FLOW;
    iphc_hop_limit  = (iphc_flags & LOWPAN_IPHC_FLAG_HLIM) >> LOWPAN_IPHC_FLAG_OFFSET_HLIM;
    iphc_src_mode   = (iphc_flags & LOWPAN_IPHC_FLAG_SRC_MODE) >> LOWPAN_IPHC_FLAG_OFFSET_SRC_MODE;
    iphc_dst_mode   = (iphc_flags & LOWPAN_IPHC_FLAG_DST_MODE) >> LOWPAN_IPHC_FLAG_OFFSET_DST_MODE;
    if (tree) {
        const value_string *am_vs;
        proto_tree_add_uint         (iphc_tree, hf_6lowpan_iphc_flag_tf,    tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_FLOW);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_nhdr,  tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_NHDR);
        proto_tree_add_uint         (iphc_tree, hf_6lowpan_iphc_flag_hlim,  tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_HLIM);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_cid,   tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_CONTEXT_ID);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_sac,   tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP);
        am_vs = iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP ? lowpan_iphc_saddr_stateful_modes : lowpan_iphc_addr_modes;
        proto_tree_add_uint_format_value(iphc_tree, hf_6lowpan_iphc_flag_sam, tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_SRC_MODE,
                                         "%s (0x%04x)", val_to_str_const(iphc_src_mode, am_vs, "Reserved"), iphc_src_mode);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_mcast, tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_dac,   tvb, offset, 2, iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP);
        /* Destination address mode changes meanings depending on multicast compression. */
        if (iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP) {
            if (iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP) {
                am_vs = lowpan_iphc_mcast_stateful_modes;
            } else {
                am_vs = lowpan_iphc_mcast_modes;
            }
        } else {
            if (iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP) {
                am_vs = lowpan_iphc_daddr_stateful_modes;
            } else {
                am_vs = lowpan_iphc_addr_modes;
            }
        }
        ti_dam = proto_tree_add_uint_format_value(iphc_tree, hf_6lowpan_iphc_flag_dam, tvb, offset, 2,
            iphc_flags & LOWPAN_IPHC_FLAG_DST_MODE, "%s (0x%04x)", val_to_str_const(iphc_dst_mode, am_vs, "Reserved"), iphc_dst_mode);
    }
    offset += 2;

    /* Display the context identifier extension, if present. */
    if (iphc_flags & LOWPAN_IPHC_FLAG_CONTEXT_ID) {
        iphc_ctx = tvb_get_uint8(tvb, offset);
        iphc_sci = (iphc_ctx & LOWPAN_IPHC_FLAG_SCI) >> LOWPAN_IPHC_FLAG_OFFSET_SCI;
        iphc_dci = (iphc_ctx & LOWPAN_IPHC_FLAG_DCI) >> LOWPAN_IPHC_FLAG_OFFSET_DCI;
        proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_sci, tvb, offset, 1, iphc_ctx & LOWPAN_IPHC_FLAG_SCI);
        proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_dci, tvb, offset, 1, iphc_ctx & LOWPAN_IPHC_FLAG_DCI);
        offset +=  1;
    }
    /* Use link-local contexts if stateless. */
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP)) {
        iphc_sci = LOWPAN_CONTEXT_LINK_LOCAL;
    }
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP)) {
        iphc_dci = LOWPAN_CONTEXT_LINK_LOCAL;
    }
    /* Lookup the contexts. */
    /*
     * Don't display their origin until after we decompress the address in case
     * the address modes indicate that we should use a different context.
     */
    sctx = lowpan_context_find(iphc_sci, hint_panid);
    dctx = lowpan_context_find(iphc_dci, hint_panid);

    /*=====================================================
     * Parse Traffic Class and Flow Label
     *=====================================================
     */
    offset <<= 3;
    /* Parse the ECN field. */
    if (iphc_traffic != LOWPAN_IPHC_FLOW_COMPRESSED) {
        ipv6_ecn = tvb_get_bits8(tvb, offset, LOWPAN_IPHC_ECN_BITS);
        proto_tree_add_bits_item(tree, hf_6lowpan_ecn, tvb, offset, LOWPAN_IPHC_ECN_BITS, ENC_BIG_ENDIAN);
        offset += LOWPAN_IPHC_ECN_BITS;
    }
    /* Parse the DSCP field. */
    if ((iphc_traffic == LOWPAN_IPHC_FLOW_CLASS_LABEL) || (iphc_traffic == LOWPAN_IPHC_FLOW_CLASS)) {
        ipv6_dscp = tvb_get_bits8(tvb, offset, LOWPAN_IPHC_DSCP_BITS);
        proto_tree_add_bits_item(tree, hf_6lowpan_dscp, tvb, offset, LOWPAN_IPHC_DSCP_BITS, LOWPAN_IPHC_DSCP_BITS);
        offset += LOWPAN_IPHC_DSCP_BITS;
    }
    /* Add a generated entry to show the IPv6 traffic class byte. */
    if (ipv6_dscp || ipv6_ecn) {
        proto_item *tclass_item;
        tclass_item = proto_tree_add_uint(tree, hf_6lowpan_traffic_class, tvb, 0, 0,
                                          (ipv6_dscp << LOWPAN_IPHC_ECN_BITS) | ipv6_ecn);
        proto_item_set_generated(tclass_item);
    }

    /* Parse the flow label. */
    if ((iphc_traffic == LOWPAN_IPHC_FLOW_CLASS_LABEL) || (iphc_traffic == LOWPAN_IPHC_FLOW_ECN_LABEL)) {
        /* Pad to 4-bits past the start of the byte. */
        unsigned pad_bits = ((4 - offset) & 0x7);
        if (pad_bits) {
            proto_tree_add_bits_item(tree, hf_6lowpan_padding, tvb, offset, pad_bits, ENC_BIG_ENDIAN);
        }
        offset += pad_bits;
        ipv6_flowlabel = tvb_get_bits32(tvb, offset, LOWPAN_IPHC_LABEL_BITS, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(tree, hf_6lowpan_flow_label, tvb, offset, LOWPAN_IPHC_LABEL_BITS, ENC_BIG_ENDIAN);
        offset += LOWPAN_IPHC_LABEL_BITS;
    }

    /* Rebuild the IPv6 flow label, traffic class and version fields. */
    ipv6.ip6h_vc_flow = ipv6_flowlabel;
    ipv6.ip6h_vc_flow |= ((uint32_t)ipv6_ecn << LOWPAN_IPV6_FLOW_LABEL_BITS);
    ipv6.ip6h_vc_flow |= ((uint32_t)ipv6_dscp << (LOWPAN_IPHC_ECN_BITS + LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6h_vc_flow |= ((uint32_t)0x6 << (LOWPAN_IPV6_TRAFFIC_CLASS_BITS + LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6h_vc_flow = g_ntohl(ipv6.ip6h_vc_flow);

    /* Convert back to byte offsets. */
    offset >>= 3;

    /*=====================================================
     * Parse Next Header and Hop Limit
     *=====================================================
     */
    /* Get the next header field, if present. */
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_NHDR)) {
        ipv6.ip6h_nxt = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format_value(tree, hf_6lowpan_next_header, tvb, offset, 1, ipv6.ip6h_nxt,
                "%s (0x%02x)", ipprotostr(ipv6.ip6h_nxt), ipv6.ip6h_nxt);
        offset += 1;
    }

    /* Get the hop limit field, if present. */
    if (iphc_hop_limit == LOWPAN_IPHC_HLIM_1) {
        ipv6.ip6h_hlim = 1;
    }
    else if (iphc_hop_limit == LOWPAN_IPHC_HLIM_64) {
        ipv6.ip6h_hlim = 64;
    }
    else if (iphc_hop_limit == LOWPAN_IPHC_HLIM_255) {
        ipv6.ip6h_hlim = 255;
    }
    else {
        ipv6.ip6h_hlim = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(tree, hf_6lowpan_hop_limit, tvb, offset, 1, ipv6.ip6h_hlim);
        offset += 1;
    }

    /*=====================================================
     * Parse and decompress the source address.
     *=====================================================
     */
    length = 0;
    memset(&ipv6.ip6h_src, 0, sizeof(ipv6.ip6h_src));
    /* (SAC=1 && SAM=00) -> the unspecified address (::). */
    if ((iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP) && (iphc_src_mode == LOWPAN_IPHC_ADDR_SRC_UNSPEC)) {
        sctx = &lowpan_context_default;
    }
    /* The IID is derived from the encapsulating layer. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_COMPRESSED) {
        memcpy(&ipv6.ip6h_src.bytes[sizeof(ipv6.ip6h_src) - LOWPAN_IFC_ID_LEN], siid, LOWPAN_IFC_ID_LEN);
    }
    /* Full Address inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
        if (!(iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP)) sctx = &lowpan_context_default;
        length = (int)sizeof(ipv6.ip6h_src);
        tvb_memcpy(tvb, &ipv6.ip6h_src, offset, length);
    }
    /* 64-bits inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
        length = 8;
        tvb_memcpy(tvb, &ipv6.ip6h_src.bytes[sizeof(ipv6.ip6h_src) - length], offset, length);
    }
    /* 16-bits inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
        length = 2;
        /* Format becomes ff:fe00:xxxx */
        ipv6.ip6h_src.bytes[11] = 0xff;
        ipv6.ip6h_src.bytes[12] = 0xfe;
        tvb_memcpy(tvb, &ipv6.ip6h_src.bytes[sizeof(ipv6.ip6h_src) - length], offset, length);

    }
    /* Copy the context bits. */
    lowpan_pfxcpy(&ipv6.ip6h_src, &sctx->prefix, sctx->plen);
    /* Update the IID of the encapsulating layer. */
    siid = &ipv6.ip6h_src.bytes[sizeof(ipv6.ip6h_src) - LOWPAN_IFC_ID_LEN];

    /* Display the source IPv6 address. */
    ti = proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset, length, &ipv6.ip6h_src);
    if (length == 0) {
        proto_item_set_generated(ti);
    }
    if (ipv6_summary_in_tree) {
        address src_addr = ADDRESS_INIT(AT_IPv6, sizeof(ipv6.ip6h_src), &ipv6.ip6h_src);
        proto_item_append_text(tree, ", Src: %s", address_with_resolution_to_str(pinfo->pool, &src_addr));
    }

    /* Add information about where the context came from. */
    /* TODO: We should display the prefix length too. */
    if (sctx->plen) {
        ti = proto_tree_add_ipv6(iphc_tree, hf_6lowpan_iphc_sctx_prefix, tvb, 0, 0, &sctx->prefix);
        proto_item_set_generated(ti);
        if ( sctx->frame ) {
            ti = proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_sctx_origin, tvb, 0, 0, sctx->frame);
            proto_item_set_generated(ti);
        }
    }
    offset += length;
    /*
     * Do not set the address columns until after defragmentation, since we have
     * to do decompression before reassembly, and changing the address will cause
     * wireshark to think that the middle fragments came from another device.
     */

    /*=====================================================
     * Parse and decompress a multicast address.
     *=====================================================
     */
    length = 0;
    memset(&ipv6.ip6h_dst, 0, sizeof(ipv6.ip6h_dst));
    /* Stateless multicast compression. */
    if ((iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP) && !(iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP)) {
        if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            length = (int)sizeof(ipv6.ip6h_dst);
            tvb_memcpy(tvb, &ipv6.ip6h_dst.bytes[sizeof(ipv6.ip6h_dst) - length], offset, length);
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_MCAST_48BIT) {
            ipv6.ip6h_dst.bytes[0] = 0xff;
            ipv6.ip6h_dst.bytes[1] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[11] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[12] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[13] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[14] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[15] = tvb_get_uint8(tvb, offset + (length++));
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_MCAST_32BIT) {
            ipv6.ip6h_dst.bytes[0] = 0xff;
            ipv6.ip6h_dst.bytes[1] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[13] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[14] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[15] = tvb_get_uint8(tvb, offset + (length++));
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_MCAST_8BIT) {
            ipv6.ip6h_dst.bytes[0] = 0xff;
            ipv6.ip6h_dst.bytes[1] = 0x02;
            ipv6.ip6h_dst.bytes[15] = tvb_get_uint8(tvb, offset + (length++));
        }
        else {
            /* Illegal destination address compression mode. */
            expert_add_info(pinfo, ti_dam, &ei_6lowpan_illegal_dest_addr_mode);
            return NULL;
        }
    }
    /* Stateful multicast compression. */
    else if ((iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP) && (iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP)) {
        if (iphc_dst_mode == LOWPAN_IPHC_MCAST_STATEFUL_48BIT) {
            /* RFC 3306 unicast-prefix based multicast address of the form:
             *      ffXX:XXLL:PPPP:PPPP:PPPP:PPPP:XXXX:XXXX
             * XX = inline byte.
             * LL = prefix/context length (up to 64-bits).
             * PP = prefix/context byte.
             */
            ipv6.ip6h_dst.bytes[0] = 0xff;
            ipv6.ip6h_dst.bytes[1] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[2] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[3] = (dctx->plen > 64) ? (64) : (dctx->plen);
            memcpy(&ipv6.ip6h_dst.bytes[4], &dctx->prefix, 8);
            ipv6.ip6h_dst.bytes[12] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[13] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[14] = tvb_get_uint8(tvb, offset + (length++));
            ipv6.ip6h_dst.bytes[15] = tvb_get_uint8(tvb, offset + (length++));
        }
        else {
            /* Illegal destination address compression mode. */
            expert_add_info(pinfo, ti_dam, &ei_6lowpan_illegal_dest_addr_mode);
            return NULL;
        }
    }

    /*=====================================================
     * Parse and decompress a unicast destination address.
     *=====================================================
     */
    else {
        /* (DAC=1 && DAM=00) -> reserved value. */
        if ((iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP) && (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE)) {
            /* Illegal destination address compression mode. */
            expert_add_info(pinfo, ti_dam, &ei_6lowpan_illegal_dest_addr_mode);
            return NULL;
        }
        /* The IID is derived from the link-layer source. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_COMPRESSED) {
            memcpy(&ipv6.ip6h_dst.bytes[sizeof(ipv6.ip6h_dst) - LOWPAN_IFC_ID_LEN], diid, LOWPAN_IFC_ID_LEN);
        }
        /* Full Address inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            dctx = &lowpan_context_default;
            length = (int)sizeof(ipv6.ip6h_dst);
            tvb_memcpy(tvb, &ipv6.ip6h_dst, offset, length);
        }
        /* 64-bits inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
            length = 8;
            tvb_memcpy(tvb, &ipv6.ip6h_dst.bytes[sizeof(ipv6.ip6h_dst) - length], offset, length);
        }
        /* 16-bits inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
            length = 2;
            /* Format becomes ff:fe00:xxxx */
            ipv6.ip6h_dst.bytes[11] = 0xff;
            ipv6.ip6h_dst.bytes[12] = 0xfe;
            tvb_memcpy(tvb, &ipv6.ip6h_dst.bytes[sizeof(ipv6.ip6h_dst) - length], offset, length);
        }
        /* Copy the context bits. */
        lowpan_pfxcpy(&ipv6.ip6h_dst, &dctx->prefix, dctx->plen);
        /* Update the interface id of the encapsulating layer. */
        diid = &ipv6.ip6h_dst.bytes[sizeof(ipv6.ip6h_dst) - LOWPAN_IFC_ID_LEN];
    }

    /* Display the destination IPv6 address. */
    ti = proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset, length, &ipv6.ip6h_dst);
    if (length == 0) {
        proto_item_set_generated(ti);
    }
    if (ipv6_summary_in_tree) {
        address dst_addr = ADDRESS_INIT(AT_IPv6, sizeof(ipv6.ip6h_dst), &ipv6.ip6h_dst);
        proto_item_append_text(tree, ", Dest: %s", address_with_resolution_to_str(pinfo->pool, &dst_addr));
    }

    /* Add information about where the context came from. */
    /* TODO: We should display the prefix length too. */
    if (dctx->plen) {
        ti = proto_tree_add_ipv6(iphc_tree, hf_6lowpan_iphc_dctx_prefix, tvb, 0, 0, &dctx->prefix);
        proto_item_set_generated(ti);
        if ( dctx->frame ) {
            ti = proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_dctx_origin, tvb, 0, 0, dctx->frame);
            proto_item_set_generated(ti);
        }
    }
    offset += length;
    /*
     * Do not set the address columns until after defragmentation, since we have
     * to do decompression before reassembly, and changing the address will cause
     * wireshark to think that the middle fragments came from another device.
     */

    /*=====================================================
     * Decompress extension headers.
     *=====================================================
     */
    /* Parse the list of extension headers. */
    if (iphc_flags & LOWPAN_IPHC_FLAG_NHDR) {
        /* Parse the next header protocol identifier. */
        ipv6.ip6h_nxt = lowpan_parse_nhc_proto(tvb, offset);

        /* Parse the 6LoWPAN NHC fields. */
        nhdr_list = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset, dgram_size - IPv6_HDR_SIZE, siid, diid);
    }
    /* Create an extension header for the remaining payload. */
    else {
        length = tvb_captured_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)wmem_alloc(pinfo->pool, sizeof(struct lowpan_nhdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6h_nxt;
        nhdr_list->length = length;
        if (dgram_size < 0) {
            nhdr_list->reported = tvb_reported_length_remaining(tvb, offset);
        }
        else {
            nhdr_list->reported = dgram_size - IPv6_HDR_SIZE;
        }
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr_list), offset, nhdr_list->length);
    }

    /*=====================================================
     * Rebuild the IPv6 packet.
     *=====================================================
     */
    /* Reassemble the IPv6 packet. */
    ipv6_tvb = lowpan_reassemble_ipv6(tvb, pinfo, &ipv6, nhdr_list);

    /* Add a new data source for it. */
    add_new_data_source(pinfo, ipv6_tvb, "Decompressed 6LoWPAN IPHC");

    return ipv6_tvb;
} /* dissect_6lowpan_iphc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_iphc_nhc
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN IPHC next header structure(s).
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      offset          ; packet buffer offset.
 *      dgram_size      ; Remaining datagram size (or <0 if unknown).
 *      siid            ; Source Interface ID.
 *      diid            ; Destination Interface ID.
 *  RETURNS
 *      lowpan_nhdr *   ; List of wmem_alloc'd next header structures.
 *---------------------------------------------------------------
 */
static struct lowpan_nhdr *
// NOLINTNEXTLINE(misc-no-recursion)
dissect_6lowpan_iphc_nhc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int dgram_size, const uint8_t *siid, const uint8_t *diid)
{
    int                 length;
    proto_item *        ti = NULL;
    proto_tree *        nhc_tree = NULL;
    struct lowpan_nhdr *nhdr;

    /*=====================================================
     * IP-in-IP Tunneling
     *=====================================================
     */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_IPV6_BITS) == LOWPAN_NHC_PATTERN_EXT_IPV6) {
        uint8_t         ext_flags;
        tvbuff_t       *iphc_tvb;

        /* Create a tree for the IPv6 extension header. */
        nhc_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_6lowpan_nhc_ext, &ti, "IPv6 extension header");
        /* Display the IPv6 Extension Header NHC ID pattern. */
        proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS, ENC_BIG_ENDIAN);

        /* Get and display the extension header compression flags. */
        ext_flags = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_eid, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_EID);
        proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_ext_nh, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_NHDR);
        if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
            /* TODO: Flag a warning, the NH bit MUST be 0 when EID==0x7 (IP-in-IP). */
        }
        offset += 1;

        /* Decode the remainder of the packet using IPHC encoding. */
        increment_dissection_depth(pinfo);
        iphc_tvb = dissect_6lowpan_iphc(tvb_new_subset_remaining(tvb, offset), pinfo, tree, dgram_size, siid, diid);
        decrement_dissection_depth(pinfo);

        if (!iphc_tvb) return NULL;

        /* Create the next header structure for the tunneled IPv6 header. */
        nhdr = (struct lowpan_nhdr *)wmem_alloc0(pinfo->pool, sizeof(struct lowpan_nhdr) + tvb_captured_length(iphc_tvb));
        nhdr->next = NULL;
        nhdr->proto = IP_PROTO_IPV6;
        nhdr->length = tvb_captured_length(iphc_tvb);
        nhdr->reported = tvb_reported_length(iphc_tvb);
        tvb_memcpy(iphc_tvb, LOWPAN_NHDR_DATA(nhdr), 0, nhdr->length);
        return nhdr;
    }
    /*=====================================================
     * IPv6 Extension Header
     *=====================================================
     */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS) == LOWPAN_NHC_PATTERN_EXT) {
        struct ws_ip6_ext  ipv6_ext = {0, 0};
        uint8_t         ext_flags;
        uint8_t         ext_hlen;
        uint8_t         ext_len;
        uint8_t         ext_proto;
        proto_item      *ti_ext_len = NULL;

        /* Parse the IPv6 extension header protocol. */
        ext_proto = lowpan_parse_nhc_proto(tvb, offset);

        /* Create a tree for the IPv6 extension header. */
        nhc_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_6lowpan_nhc_ext, NULL, "IPv6 extension header");
        /* Display the IPv6 Extension Header NHC ID pattern. */
        proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS, ENC_BIG_ENDIAN);

        /* Get and display the extension header compression flags. */
        ext_flags = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_eid, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_EID);
        proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_ext_nh, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_NHDR);
        offset += 1;

        /* Get and display the next header field, if present. */
        if (!(ext_flags & LOWPAN_NHC_EXT_NHDR)) {
            ipv6_ext.ip6e_nxt = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint_format_value(nhc_tree, hf_6lowpan_nhc_ext_next, tvb, offset, 1, ipv6_ext.ip6e_nxt,
                    "%s (0x%02x)", ipprotostr(ipv6_ext.ip6e_nxt), ipv6_ext.ip6e_nxt);
            proto_item_set_end(ti, tvb, offset+1);
            offset += 1;
        }

        if (ext_proto == IP_PROTO_FRAGMENT) {
            /* Fragment header has a reserved byte in place of the Length field. */
            ext_hlen = 1;
            length = (uint8_t)sizeof(struct ws_ip6_frag);
            ext_len = length - ext_hlen;

            proto_tree_add_item(nhc_tree, hf_6lowpan_nhc_ext_reserved, tvb, offset, 1, ENC_NA);

        } else {
            /* Get and display the extension header length. */
            ext_hlen = (uint8_t)sizeof(struct ws_ip6_ext);
            ext_len = tvb_get_uint8(tvb, offset);
            ti_ext_len = proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_length, tvb, offset, 1, ext_len);
            offset += 1;

            /* Compute the length of the extension header padded to an 8-byte alignment. */
            length = ext_hlen + ext_len;
            length = (length + 7) & ~0x7;
            ipv6_ext.ip6e_len = length>>3;          /* Convert to units of 8 bytes. */
            ipv6_ext.ip6e_len -= 1;                 /* Don't include the first 8 bytes. */
       }

        /* Create the next header structure for the IPv6 extension header. */
        nhdr = (struct lowpan_nhdr *)wmem_alloc0(pinfo->pool, sizeof(struct lowpan_nhdr) + length);
        nhdr->next = NULL;
        nhdr->proto = ext_proto;
        nhdr->length = length;
        nhdr->reported = length;

        /* Add the IPv6 extension header to the buffer. */
        if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
            ipv6_ext.ip6e_nxt = lowpan_parse_nhc_proto(tvb, offset+ext_len);
        }
        memcpy(LOWPAN_NHDR_DATA(nhdr), &ipv6_ext, ext_hlen);

        /*
         * If the extension header was truncated, display the remainder using
         * the data dissector, and end NHC dissection here.
         */
        if (!tvb_bytes_exist(tvb, offset, ext_len)) {
            /* Call the data dissector for the remainder. */
            call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, nhc_tree);

            /* Copy the remainder, and truncate the real buffer length. */
            nhdr->length = tvb_captured_length_remaining(tvb, offset) + ext_hlen;
            tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr) + ext_hlen, offset, tvb_captured_length_remaining(tvb, offset));

            /* There is nothing more we can do. */
            return nhdr;
        }

        if (ext_proto == IP_PROTO_FRAGMENT) {
            /* Display the extension header using the data dissector. */
            call_data_dissector(tvb_new_subset_length(tvb, offset+1, ext_len-1), pinfo, nhc_tree);
        } else {
            /* Display the extension header using the data dissector. */
            call_data_dissector(tvb_new_subset_length(tvb, offset, ext_len), pinfo, nhc_tree);
        }

        /* Copy the extension header into the struct. */
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr) + ext_hlen, offset, ext_len);
        offset += ext_len;

        /* Add padding option */
        if (length > ext_hlen + ext_len) {
            uint8_t padding = length - (ext_hlen + ext_len);
            uint8_t *pad_ptr = LOWPAN_NHDR_DATA(nhdr) + ext_hlen + ext_len;
            if (ext_proto != IP_PROTO_HOPOPTS && ext_proto != IP_PROTO_DSTOPTS) {
                expert_add_info(pinfo, ti_ext_len, &ei_6lowpan_bad_ext_header_length);
            }
            if (padding == 1) {
                pad_ptr[0] = IP6OPT_PAD1;
            } else {
                pad_ptr[0] = IP6OPT_PADN;
                pad_ptr[1] = padding - 2;
                /* No need to write pad data, as buffer is zero-initialised */
            }
        }

        if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
            /*
             * There are more LOWPAN_NHC structures to parse. Call ourself again
             * recursively to parse them and build the linked list.
             */
            increment_dissection_depth(pinfo);
            nhdr->next = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset, dgram_size - nhdr->reported, siid, diid);
            decrement_dissection_depth(pinfo);
        }
        else if (ipv6_ext.ip6e_nxt != IP_PROTO_NONE) {
            /* Create another next header structure for the remaining payload. */
            length = tvb_captured_length_remaining(tvb, offset);
            nhdr->next = (struct lowpan_nhdr *)wmem_alloc(pinfo->pool, sizeof(struct lowpan_nhdr) + length);
            nhdr->next->next = NULL;
            nhdr->next->proto = ipv6_ext.ip6e_nxt;
            nhdr->next->length = length;
            if (dgram_size < 0) {
                nhdr->next->reported = tvb_reported_length_remaining(tvb, offset);
            }
            else {
                nhdr->next->reported = dgram_size - nhdr->reported;
            }
            tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr->next), offset, nhdr->next->length);
        }

        /* Done. */
        return nhdr;
    }
    /*=====================================================
     * UDP Header
     *=====================================================
     */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_UDP_BITS) == LOWPAN_NHC_PATTERN_UDP) {
        struct udp_hdr  udp;
        int             src_bitlen;
        int             dst_bitlen;
        uint8_t         udp_flags;
        uint16_t        udp_src_port, udp_dst_port;

        /* Create a tree for the UDP header. */
        nhc_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_6lowpan_nhc_udp, NULL, "UDP header compression");
        /* Display the UDP NHC ID pattern. */
        proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_UDP_BITS, ENC_BIG_ENDIAN);

        /* Get and display the UDP header compression options */
        proto_tree_add_item(nhc_tree, hf_6lowpan_nhc_udp_checksum, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(nhc_tree, hf_6lowpan_nhc_udp_ports, tvb, offset, 1, ENC_NA);
        udp_flags = tvb_get_uint8(tvb, offset);
        offset += 1;

        /* Get and display the ports. */
        switch (udp_flags & LOWPAN_NHC_UDP_PORTS) {
            case LOWPAN_NHC_UDP_PORT_INLINE:
                udp_src_port = tvb_get_ntohs(tvb, offset);
                udp_dst_port = tvb_get_ntohs(tvb, offset+2);
                src_bitlen = 16;
                dst_bitlen = 16;
                break;

            case LOWPAN_NHC_UDP_PORT_8BIT_DST:
                udp_src_port = tvb_get_ntohs(tvb, offset);
                udp_dst_port = LOWPAN_PORT_8BIT_OFFSET + tvb_get_uint8(tvb, offset + 2);
                src_bitlen = 16;
                dst_bitlen = 8;
                break;

            case LOWPAN_NHC_UDP_PORT_8BIT_SRC:
                udp_src_port = LOWPAN_PORT_8BIT_OFFSET + tvb_get_uint8(tvb, offset);
                udp_dst_port = tvb_get_ntohs(tvb, offset + 1);
                src_bitlen = 8;
                dst_bitlen = 16;
                break;

            case LOWPAN_NHC_UDP_PORT_12BIT:
                udp_src_port = LOWPAN_PORT_12BIT_OFFSET + (tvb_get_uint8(tvb, offset) >> 4);
                udp_dst_port = LOWPAN_PORT_12BIT_OFFSET + (tvb_get_uint8(tvb, offset) & 0x0f);
                src_bitlen = 4;
                dst_bitlen = 4;
                break;

            default:
                DISSECTOR_ASSERT_NOT_REACHED();
                break;
        } /* switch */

        proto_tree_add_uint(tree, hf_6lowpan_udp_src, tvb, offset, BITS_TO_BYTE_LEN(offset<<3, src_bitlen), udp_src_port);
        proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset+(src_bitlen>>3), BITS_TO_BYTE_LEN((offset<<3)+src_bitlen, dst_bitlen), udp_dst_port);
        offset += ((src_bitlen + dst_bitlen)>>3);
        udp.src_port = g_htons(udp_src_port);
        udp.dst_port = g_htons(udp_dst_port);

        /* Get and display the checksum. */
        if (!(udp_flags & LOWPAN_NHC_UDP_CHECKSUM)) {
            /* Parse the checksum. */
            tvb_memcpy(tvb, &udp.checksum, offset, sizeof(udp.checksum));
            proto_tree_add_checksum(tree, tvb, offset, hf_6lowpan_udp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
            offset += 2;
        }
        else {
            /* Checksum must be != 0 or the UDP dissector will flag the packet with a PI_ERROR */
            udp.checksum = 0xffff;
        }

        /* Compute the datagram length. */
        if (dgram_size < 0) {
            length = tvb_reported_length_remaining(tvb, offset);
            udp.length = g_htons(length + (int)sizeof(struct udp_hdr));
        }
        else {
            udp.length = g_htons(dgram_size);
        }

        /*
         * Although rfc768 (udp) allows a packet to be sent with a checksum of
         * 0 to mean that no checksum was computed, apparently IPv6 specifically
         * disallows sending UDP datagrams without checksums. Likewise, 6LoWPAN
         * requires that we recompute the checksum.
         *
         * If the datagram is incomplete, then leave the checksum at 0xffff.
         */
#if 0
        /*
         * This has been disabled, since we might only be dissecting a fragment
         * of the packet, and thus we might not have the entire UDP payload at
         * this time.
         *
         * If we want to display the checksums, they will have to be recomputed
         * after packet reassembly. Lots of work for not much gain, since we can
         * just set the UDP checksum to 0xffff (anything != 0) and Wireshark
         * doesn't care.
         */
        if ((udp_flags & LOWPAN_NHC_UDP_CHECKSUM) && tvb_bytes_exist(tvb, offset, length)) {
            vec_t      cksum_vec[3];
            struct {
                ws_in6_addr   src;
                ws_in6_addr   dst;
                uint32_t            length;
                uint8_t             zero[3];
                uint8_t             proto;
            } cksum_phdr;

            /* Fill in the pseudo-header. */
            memcpy(&cksum_phdr.src, pinfo->src.data, sizeof(ws_in6_addr));
            memcpy(&cksum_phdr.dst, pinfo->dst.data, sizeof(ws_in6_addr));
            cksum_phdr.length = g_htonl(length + (int)sizeof(struct udp_hdr));
            memset(cksum_phdr.zero, 0, sizeof(cksum_phdr.zero));
            cksum_phdr.proto = IP_PROTO_UDP;

            /* Compute the checksum. */
            SET_CKSUM_VEC_PTR(cksum_vec[0], (const uint8_t *)&cksum_phdr, sizeof(cksum_phdr));
            SET_CKSUM_VEC_PTR(cksum_vec[1], (const uint8_t *)&udp, sizeof(struct udp_hdr));
            SET_CKSUM_VEC_TVB(cksum_vec[2], tvb, offset, length);
            udp.checksum = in_cksum(cksum_vec, 3);
            if (udp.checksum == 0) udp.checksum = 0xffff;
        }
#endif

        /* Create the next header structure for the UDP datagram. */
        length = tvb_captured_length_remaining(tvb, offset);
        nhdr = (struct lowpan_nhdr *)wmem_alloc(pinfo->pool, sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
        nhdr->next = NULL;
        nhdr->proto = IP_PROTO_UDP;
        nhdr->length = length + (int)sizeof(struct udp_hdr);
        nhdr->reported = g_ntohs(udp.length);

        /* Copy the UDP header and payload into the buffer. */
        memcpy(LOWPAN_NHDR_DATA(nhdr), &udp, sizeof(struct udp_hdr));
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr) + sizeof(struct udp_hdr), offset, tvb_captured_length_remaining(tvb, offset));
        return nhdr;
    }
    /*=====================================================
     * Unknown Next Header Type
     *=====================================================
     */
    return NULL;
} /* dissect_6lowpan_iphc_nhc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_bc0
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN broadcast header.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_bc0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    uint8_t             seqnum;
    proto_tree *        bcast_tree;

    /* Create a tree for the broadcast header. */
    bcast_tree = proto_tree_add_subtree(tree, tvb, 0, 2, ett_6lowpan_bcast, NULL, "Broadcast Header");

    /* Get and display the pattern. */
    proto_tree_add_bits_item(bcast_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_BC0_BITS, ENC_BIG_ENDIAN);

    /* Get and display the sequence number. */
    seqnum = tvb_get_uint8(tvb, 1);
    proto_tree_add_uint(bcast_tree, hf_6lowpan_bcast_seqnum, tvb, 1, 1, seqnum);

    /* Return the remaining buffer. */
    return tvb_new_subset_remaining(tvb, 2);
} /* dissect_6lowpan_bc0 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_mesh
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN mesh header.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      offset          ; offset to the start of the header.
 *      siid            ; Source Interface ID.
 *      diid            ; Destination Interface ID.
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_mesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t *siid, uint8_t *diid)
{
    int                 offset = 0;
    uint8_t             mesh_header;
    proto_tree *        mesh_tree;
    proto_tree *        flag_tree;
    proto_item *        ti;

    ieee802154_hints_t  *hints;

    /* Create a tree for the mesh header. */
    mesh_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_6lowpan_mesh, &ti, "Mesh Header");

    /* Get and display the mesh flags. */
    mesh_header = tvb_get_uint8(tvb, offset);

    /*  Create the mesh header subtree. */
    flag_tree = proto_tree_add_subtree(mesh_tree, tvb, offset, 1, ett_6lowpan_mesh, NULL, "Flags");

    /* Add the mesh header fields. */
    proto_tree_add_bits_item(flag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_MESH_BITS, ENC_BIG_ENDIAN);
    proto_tree_add_boolean(flag_tree, hf_6lowpan_mesh_v, tvb, offset, 1, mesh_header & LOWPAN_MESH_HEADER_V);
    proto_tree_add_boolean(flag_tree, hf_6lowpan_mesh_f, tvb, offset, 1, mesh_header & LOWPAN_MESH_HEADER_F);
    proto_tree_add_uint(flag_tree, hf_6lowpan_mesh_hops, tvb, offset, 1, mesh_header & LOWPAN_MESH_HEADER_HOPS);
    offset += 1;

    if ((mesh_header & LOWPAN_MESH_HEADER_HOPS) == LOWPAN_MESH_HEADER_HOPS) {
        proto_tree_add_item(mesh_tree, hf_6lowpan_mesh_hops8, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    /* Get and display the originator address. */
    if (!(mesh_header & LOWPAN_MESH_HEADER_V)) {
        proto_tree_add_item(mesh_tree, hf_6lowpan_mesh_orig64,
                tvb, offset, 8, ENC_BIG_ENDIAN);

        set_address_tvb(&pinfo->src, AT_EUI64, 8, tvb, offset);
        copy_address_shallow(&pinfo->net_src, &pinfo->src);

        /* Update source IID */
        tvb_memcpy(tvb, siid, offset, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        siid[0] ^= 0x02;
        offset += 8;
    }
    else {
        uint16_t        addr16 = tvb_get_ntohs(tvb, offset);
        uint8_t *        ifcid;

        proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_orig16, tvb, offset, 2, addr16);
        ifcid = (uint8_t *)wmem_alloc(pinfo->pool, 8);

        /* Lookup the IEEE 802.15.4 addressing hints wanting RFC 2464 compatibility. */
        hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                                proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);

        /* Convert the 16-bit short address to an IID using the PAN ID (RFC 4944) or not depending on the preference and the presence of hints from lower layers */
        if (hints && rfc4944_short_address_format) {
            lowpan_addr16_with_panid_to_ifcid(hints->src_pan, addr16, ifcid);
        } else {
            lowpan_addr16_to_ifcid(addr16, ifcid);
        }

        set_address(&pinfo->src,  AT_EUI64, 8, ifcid);
        copy_address_shallow(&pinfo->net_src, &pinfo->src);

        /* Update source IID */
        memcpy(siid, ifcid, LOWPAN_IFC_ID_LEN);
        offset += 2;
    }

    /* Get and display the destination address. */
    if (!(mesh_header & LOWPAN_MESH_HEADER_F)) {
        proto_tree_add_item(mesh_tree, hf_6lowpan_mesh_dest64,
                tvb, offset, 8, ENC_BIG_ENDIAN);

        set_address_tvb(&pinfo->dst, AT_EUI64, 8, tvb, offset);
        copy_address_shallow(&pinfo->net_dst, &pinfo->dst);

        /* Update destination IID */
        tvb_memcpy(tvb, diid, offset, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        diid[0] ^= 0x02;
        offset += 8;
    }
    else  {
        uint16_t        addr16 = tvb_get_ntohs(tvb, offset);
        uint8_t *        ifcid;

        proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_dest16, tvb, offset, 2, addr16);

        ifcid = (uint8_t *)wmem_alloc(pinfo->pool, 8);

        /* Lookup the IEEE 802.15.4 addressing hints wanting RFC 2464 compatibility. */
        hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                                proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);

        /* Convert the 16-bit short address to an IID using the PAN ID (RFC 4944) or not depending on the preference and the presence of hints from lower layers */
        if (hints && rfc4944_short_address_format) {
            lowpan_addr16_with_panid_to_ifcid(hints->src_pan, addr16, ifcid);
        } else {
            lowpan_addr16_to_ifcid(addr16, ifcid);
        }

        set_address(&pinfo->dst,  AT_EUI64, 8, ifcid);
        copy_address_shallow(&pinfo->net_dst, &pinfo->dst);

        /* Update destination IID */
        memcpy(diid, ifcid, LOWPAN_IFC_ID_LEN);
        offset += 2;
    }

    /* Adjust the mesh header length. */
    proto_item_set_end(ti, tvb, offset);

    /* Return the remaining buffer. */
    return tvb_new_subset_remaining(tvb, offset);
} /* dissect_6lowpan_mesh */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_frag_headers
 *  DESCRIPTION
 *      Dissector routine for headers in the first fragment.
 *      The first fragment can contain an uncompressed IPv6, HC1 or IPHC fragment.
 *  PARAMETERS
 *      tvb             ; fragment buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      siid            ; Source Interface ID.
 *      diid            ; Destination Interface ID.
 *  RETURNS
 *      tvbuff_t *      ; buffer containing the uncompressed IPv6 headers
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_frag_headers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *length_item, const uint8_t *siid, const uint8_t *diid)
{
    tvbuff_t *frag_tvb = NULL;

    /* The first fragment can contain an uncompressed IPv6, HC1 or IPHC fragment.  */
    if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_IPV6_BITS) == LOWPAN_PATTERN_IPV6) {
        frag_tvb = dissect_6lowpan_ipv6(tvb, pinfo, tree);
    }
    else if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_HC1_BITS) == LOWPAN_PATTERN_HC1) {
        /* Check if the datagram size is sane. */
        if (tvb_reported_length(tvb) < IPv6_HDR_SIZE) {
            expert_add_info_format(pinfo, length_item, &ei_6lowpan_bad_ipv6_header_length,
                "Length is less than IPv6 header length %u", IPv6_HDR_SIZE);
        }
        frag_tvb = dissect_6lowpan_hc1(tvb, pinfo, tree, tvb_reported_length(tvb), siid, diid);
    }
    else if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
        /* Check if the datagram size is sane. */
        if (tvb_reported_length(tvb) < IPv6_HDR_SIZE) {
            expert_add_info_format(pinfo, length_item, &ei_6lowpan_bad_ipv6_header_length,
                "Length is less than IPv6 header length %u", IPv6_HDR_SIZE);
        }
        frag_tvb = dissect_6lowpan_iphc(tvb, pinfo, tree, tvb_reported_length(tvb), siid, diid);
    }
    /* Unknown 6LoWPAN dispatch type */
    else {
        dissect_6lowpan_unknown(tvb, pinfo, tree);
    }
    return frag_tvb;
} /* dissect_6lowpan_frag_headers */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_rfrag
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN Recoverable Fragment headers.
 *
 *      If reassembly could be completed, this should return an
 *      uncompressed IPv6 packet. If reassembly had to be delayed
 *      for more packets, this will return NULL.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      siid            ; Source Interface ID.
 *      diid            ; Destination Interface ID.
 *  RETURNS
 *      tvbuff_t *      ; reassembled IPv6 packet.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_rfrag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const uint8_t *siid, const uint8_t *diid)
{
    int                 offset = 0;
    uint32_t            frag_size;
    uint32_t            dgram_tag;
    proto_tree *        frag_tree;
    proto_item *        ti;
    proto_item *        length_item;
    /* Reassembly parameters. */
    tvbuff_t *          new_tvb;
    tvbuff_t *          frag_tvb;
    fragment_head *     frag_data;
    bool                save_fragmented;
    uint16_t            sequence;
    uint32_t            frag_offset;

    /* Create a tree for the fragmentation header. */
    frag_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_6lowpan_frag, &ti, "RFRAG Header");

    /* Get and display the pattern and explicit congestion bit. */
    proto_tree_add_bits_item(frag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_RFRAG_BITS, ENC_BIG_ENDIAN);
    proto_tree_add_item(frag_tree, hf_6lowpan_rfrag_congestion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get and display the datagram tag. */
    proto_tree_add_item_ret_uint(frag_tree, hf_6lowpan_rfrag_dgram_tag, tvb, offset, 1, ENC_BIG_ENDIAN, &dgram_tag);
    offset += 1;

    proto_tree_add_item(frag_tree, hf_6lowpan_rfrag_ack_requested, tvb, offset, 2, ENC_BIG_ENDIAN);
    sequence = tvb_get_bits16(tvb, (offset * 8) + 1, LOWPAN_RFRAG_SEQUENCE_BITS, ENC_BIG_ENDIAN);
    proto_tree_add_item(frag_tree, hf_6lowpan_rfrag_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);

    frag_size = tvb_get_bits16(tvb, (offset * 8) + 1 + LOWPAN_RFRAG_SEQUENCE_BITS, LOWPAN_RFRAG_FRAG_SZ_BITS, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_uint(frag_tree, hf_6lowpan_rfrag_size, tvb, offset * 8, 2, frag_size);
    offset += 2;

    if (sequence) {
        proto_tree_add_item_ret_uint(frag_tree, hf_6lowpan_rfrag_offset, tvb, offset, 2, ENC_BIG_ENDIAN, &frag_offset);
    }
    else {
        proto_tree_add_item_ret_uint(frag_tree, hf_6lowpan_rfrag_dgram_size, tvb, offset, 2, ENC_BIG_ENDIAN, &frag_offset);
    }
    offset += 2;

    /* Adjust the fragmentation header length. */
    proto_item_set_end(ti, tvb, offset);

    frag_tvb = tvb_new_subset_length(tvb, offset, frag_size);
    if (sequence == 0) {
        dissect_6lowpan_frag_headers(frag_tvb, pinfo, tree, length_item, siid, diid);
    }

    /* Add this datagram to the fragment table. */
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = true;
    uint32_t frag_id = lowpan_reassembly_id(pinfo, dgram_tag);
    if (sequence == 0) {
        frag_data = fragment_add_check(&lowpan_reassembly_table,
                    frag_tvb, 0, pinfo, frag_id, NULL,
                    0, frag_size, true);
        fragment_set_tot_len(&lowpan_reassembly_table, pinfo, frag_id, NULL, frag_offset);
    }
    else {
        uint32_t dgram_size = fragment_get_tot_len(&lowpan_reassembly_table, pinfo, frag_id, NULL);
        frag_data = fragment_add_check(&lowpan_reassembly_table,
                    frag_tvb, 0, pinfo, frag_id, NULL,
                    frag_offset, frag_size, (frag_offset+frag_size) < dgram_size);
    }

    /* Attempt reassembly. */
    new_tvb = process_reassembled_data(frag_tvb, 0, pinfo,
                    "Reassembled 6LoWPAN", frag_data, &lowpan_frag_items,
                    NULL, tree);

    pinfo->fragmented = save_fragmented;

    if (new_tvb) {
        /* Reassembly was successful; return the completed datagram. */
        return new_tvb;
    } else {
        /* Reassembly was unsuccessful; show this fragment.  This may
           just mean that we don't yet have all the fragments, so
           we should not just continue dissecting. */
        call_data_dissector(frag_tvb, pinfo, proto_tree_get_root(tree));
        return NULL;
    }
} /* dissect_6lowpan_rfrag */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_rfrag_ack
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN ACK Dispatch type and header
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *  RETURNS
 *      tvbuff_t *      ; reassembled IPv6 packet.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_rfrag_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int                 offset = 0;
    proto_tree *        frag_tree;
    proto_item *        ti;
    (void)pinfo;

    /* Create a tree for the fragmentation header. */
    frag_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_6lowpan_frag, &ti, "RFRAG ACK Header");

    /* Get and display the pattern and explicit congestion bit. */
    proto_tree_add_bits_item(frag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_RFRAG_BITS, ENC_BIG_ENDIAN);
    proto_tree_add_item(frag_tree, hf_6lowpan_rfrag_congestion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get and display the datagram tag. */
    proto_tree_add_item(frag_tree, hf_6lowpan_rfrag_dgram_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bits_item(frag_tree, hf_6lowpan_rfrag_ack_bitmap, tvb, offset * 8, 32, ENC_BIG_ENDIAN);
    offset += 4;

    /* TODO: Match ACK bits to original fragments? */

    return tvb_new_subset_remaining(tvb, offset);
} /* dissect_6lowpan_rfrag_ack */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_frag_first
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN FRAG1 headers.
 *
 *      If reassembly could be completed, this should return an
 *      uncompressed IPv6 packet. If reassembly had to be delayed
 *      for more packets, this will return NULL.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      siid            ; Source Interface ID.
 *      diid            ; Destination Interface ID.
 *  RETURNS
 *      tvbuff_t *      ; reassembled IPv6 packet.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_frag_first(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const uint8_t *siid, const uint8_t *diid)
{
    int                 offset = 0;
    int                 frag_size;
    uint16_t            dgram_size;
    uint16_t            dgram_tag;
    proto_tree *        frag_tree;
    proto_item *        ti;
    proto_item *        length_item;
    /* Reassembly parameters. */
    tvbuff_t *          new_tvb;
    tvbuff_t *          frag_tvb;
    fragment_head *     frag_data;
    bool                save_fragmented;

    /* Create a tree for the fragmentation header. */
    frag_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_6lowpan_frag, &ti, "Fragmentation Header");

    /* Get and display the pattern and datagram size. */
    dgram_size = tvb_get_bits16(tvb, (offset * 8) + LOWPAN_PATTERN_FRAG_BITS, LOWPAN_FRAG_DGRAM_SIZE_BITS, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(frag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_FRAG_BITS, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_size, tvb, offset, 2, dgram_size);
    offset += 2;

    /* Get and display the datagram tag. */
    dgram_tag = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_tag, tvb, offset, 2, dgram_tag);
    offset += 2;

    /* Adjust the fragmentation header length. */
    proto_item_set_end(ti, tvb, offset);


    frag_tvb = tvb_new_subset_length(tvb, offset, dgram_size);
    frag_tvb = dissect_6lowpan_frag_headers(frag_tvb, pinfo, tree, length_item, siid, diid);
    /* Check call to dissect_6lowpan_xxx was successful */
    if (frag_tvb == NULL) {
        return NULL;
    }

    /* Add this datagram to the fragment table. */
    frag_size = tvb_captured_length(frag_tvb);
    tvb_set_reported_length(frag_tvb, frag_size);
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = true;
    uint32_t frag_id = lowpan_reassembly_id(pinfo, dgram_tag);
    frag_data = fragment_add_check(&lowpan_reassembly_table,
                    frag_tvb, 0, pinfo, frag_id, NULL,
                    0, frag_size, (frag_size < dgram_size));

    /* Attempt reassembly. */
    new_tvb = process_reassembled_data(frag_tvb, 0, pinfo,
                    "Reassembled 6LoWPAN", frag_data, &lowpan_frag_items,
                    NULL, tree);

    pinfo->fragmented = save_fragmented;

    if (new_tvb) {
        /* Reassembly was successful; return the completed datagram. */
        return new_tvb;
    } else {
        /* Reassembly was unsuccessful; show this fragment.  This may
           just mean that we don't yet have all the fragments, so
           we should not just continue dissecting. */
        call_data_dissector(frag_tvb, pinfo, proto_tree_get_root(tree));
        return NULL;
    }
} /* dissect_6lowpan_frag_first */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_frag_middle
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN FRAGN headers.
 *
 *      If reassembly could be completed, this should return an
 *      uncompressed IPv6 packet. If reassembly had to be delayed
 *      for more packets, this will return NULL.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *  RETURNS
 *      tvbuff_t *      ; reassembled IPv6 packet.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_frag_middle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int                 offset = 0;
    int                 frag_size;
    uint16_t            dgram_size;
    uint16_t            dgram_tag;
    uint16_t            dgram_offset = 0;
    proto_tree *        frag_tree;
    proto_item *        ti;
    /* Reassembly parameters. */
    tvbuff_t *          new_tvb;
    fragment_head *     frag_data;
    bool                save_fragmented;

    /* Create a tree for the fragmentation header. */
    frag_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_6lowpan_frag, &ti, "Fragmentation Header");

    /* Get and display the pattern and datagram size. */
    dgram_size = tvb_get_bits16(tvb, (offset * 8) + LOWPAN_PATTERN_FRAG_BITS, LOWPAN_FRAG_DGRAM_SIZE_BITS, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(frag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_FRAG_BITS, ENC_BIG_ENDIAN);
    proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_size, tvb, offset, 2, dgram_size);
    offset += 2;

    /* Get and display the datagram tag. */
    dgram_tag = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_tag, tvb, offset, 2, dgram_tag);
    offset += 2;

    /* Get and display the datagram offset. */
    dgram_offset = tvb_get_uint8(tvb, offset) * 8;
    proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_offset, tvb, offset, 1, dgram_offset);
    offset += 1;

    /* Adjust the fragmentation header length. */
    frag_size = tvb_reported_length_remaining(tvb, offset);
    proto_item_set_end(ti, tvb, offset);

    /* Add this datagram to the fragment table. */
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = true;
    uint32_t frag_id = lowpan_reassembly_id(pinfo, dgram_tag);
    frag_data = fragment_add_check(&lowpan_reassembly_table,
                    tvb, offset, pinfo, frag_id, NULL,
                    dgram_offset, frag_size, ((dgram_offset + frag_size) < dgram_size));

    /* Attempt reassembly. */
    new_tvb = process_reassembled_data(tvb, offset, pinfo,
                    "Reassembled 6LoWPAN", frag_data, &lowpan_frag_items,
                    NULL, tree);

    pinfo->fragmented = save_fragmented;

    /* If reassembly was successful, then return the completed datagram. */
    if (new_tvb) {
        return new_tvb;
    }
    /* If reassembly failed, display the payload fragment using the data dissector. */
    else {
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(new_tvb, pinfo, proto_tree_get_root(tree));
        return NULL;
    }
} /* dissect_6lowpan_frag_middle */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_unknown
 *  DESCRIPTION
 *      Dissector routine for 6LoWPAN packets after encountering
 *      an unknown header.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
void
dissect_6lowpan_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *          data_tvb;

    /* Get and display the pattern. */

    /* Give a special case for NALP. */
    if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
        proto_tree_add_bits_item(tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_IPHC_BITS, ENC_BIG_ENDIAN);
    }
    else {
        uint8_t pattern = tvb_get_uint8(tvb, 0);
        proto_tree_add_uint_bits_format_value(tree, hf_6lowpan_pattern, tvb, 0, 8, pattern, ENC_BIG_ENDIAN, "Unknown (0x%02x)", pattern);
    }

    /* Create a tvbuff subset for the remaining data. */
    data_tvb = tvb_new_subset_remaining(tvb, 1);
    call_data_dissector(data_tvb, pinfo, proto_tree_get_root(tree));
} /* dissect_6lowpan_unknown */

static void
proto_shutdown_6lowpan(void)
{
    g_hash_table_destroy(lowpan_context_table);
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_6lowpan
 *  DESCRIPTION
 *      Protocol registration routine for 6LoWPAN. Called during
 *      Wireshark initialization.
 *  PARAMETERS
 *      none            ;
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
void
proto_register_6lowpan(void)
{
    static hf_register_info hf[] = {
        /* Common 6LoWPAN fields. */
        { &hf_6lowpan_pattern,
          { "Pattern",                        "6lowpan.pattern",
            FT_UINT8, BASE_HEX, VALS(lowpan_patterns), 0x0, NULL, HFILL }},
        { &hf_6lowpan_nhc_pattern,
          { "Pattern",                        "6lowpan.nhc.pattern",
            FT_UINT8, BASE_HEX, VALS(lowpan_nhc_patterns), 0x0, NULL, HFILL }},
        { &hf_6lowpan_padding,
          { "Padding",                        "6lowpan.padding",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* HC1 header fields. */
        { &hf_6lowpan_hc1_encoding,
          { "HC1 Encoding",                  "6lowpan.hc1.encoding",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_hc1_source_prefix,
          { "Source prefix",                  "6lowpan.hc1.src_prefix",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_SOURCE_PREFIX, NULL, HFILL }},
        { &hf_6lowpan_hc1_source_ifc,
          { "Source interface",               "6lowpan.hc1.src_ifc",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_SOURCE_IFC, NULL, HFILL }},
        { &hf_6lowpan_hc1_dest_prefix,
          { "Destination prefix",             "6lowpan.hc1.dst_prefix",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_DEST_PREFIX, NULL, HFILL }},
        { &hf_6lowpan_hc1_dest_ifc,
          { "Destination interface",          "6lowpan.hc1.dst_ifc",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_DEST_IFC, NULL, HFILL }},
        { &hf_6lowpan_hc1_class,
          { "Traffic class and flow label",   "6lowpan.hc1.class",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_TRAFFIC_CLASS, NULL, HFILL }},
        { &hf_6lowpan_hc1_next,
          { "Next header",                    "6lowpan.hc1.next",
            FT_UINT8, BASE_HEX, VALS(lowpan_hc1_next), LOWPAN_HC1_NEXT, NULL, HFILL }},
        { &hf_6lowpan_hc1_more,
          { "More HC bits",                   "6lowpan.hc1.more",
            FT_BOOLEAN, 8, NULL, LOWPAN_HC1_MORE, NULL, HFILL }},

        /* HC_UDP header fields. */
        { &hf_6lowpan_hc2_udp_encoding,
          { "HC_UDP Encoding",                    "6lowpan.hc2.udp.encoding",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_hc2_udp_src,
          { "Source port",                    "6lowpan.hc2.udp.src",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC2_UDP_SRCPORT, NULL, HFILL }},
        { &hf_6lowpan_hc2_udp_dst,
          { "Destination port",               "6lowpan.hc2.udp.dst",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC2_UDP_DSTPORT, NULL, HFILL }},
        { &hf_6lowpan_hc2_udp_len,
          { "Length",                         "6lowpan.hc2.udp.length",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC2_UDP_LENGTH, NULL, HFILL }},

        /* IPHC header fields. */
        { &hf_6lowpan_iphc_flag_tf,
          { "Traffic class and flow label",   "6lowpan.iphc.tf",
            FT_UINT16, BASE_HEX, VALS(lowpan_iphc_traffic), LOWPAN_IPHC_FLAG_FLOW, "traffic class and flow control encoding", HFILL }},
        { &hf_6lowpan_iphc_flag_nhdr,
          { "Next header",                    "6lowpan.iphc.nh",
            FT_BOOLEAN, 16, TFS(&lowpan_compression), LOWPAN_IPHC_FLAG_NHDR, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_hlim,
          { "Hop limit",                      "6lowpan.iphc.hlim",
            FT_UINT16, BASE_HEX, VALS(lowpan_iphc_hop_limit), LOWPAN_IPHC_FLAG_HLIM, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_cid,
          { "Context identifier extension",   "6lowpan.iphc.cid",
            FT_BOOLEAN, 16, NULL, LOWPAN_IPHC_FLAG_CONTEXT_ID, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_sac,
          { "Source address compression",     "6lowpan.iphc.sac",
            FT_BOOLEAN, 16, TFS(&lowpan_iphc_addr_compression), LOWPAN_IPHC_FLAG_SRC_COMP, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_sam,
          { "Source address mode",            "6lowpan.iphc.sam",
            FT_UINT16, BASE_HEX, VALS(lowpan_iphc_addr_modes), LOWPAN_IPHC_FLAG_SRC_MODE, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_mcast,
          { "Multicast address compression",  "6lowpan.iphc.m",
            FT_BOOLEAN, 16, NULL, LOWPAN_IPHC_FLAG_MCAST_COMP, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_dac,
          { "Destination address compression","6lowpan.iphc.dac",
            FT_BOOLEAN, 16, TFS(&lowpan_iphc_addr_compression), LOWPAN_IPHC_FLAG_DST_COMP, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_dam,
          { "Destination address mode",       "6lowpan.iphc.dam",
            FT_UINT16, BASE_HEX, VALS(lowpan_iphc_addr_modes), LOWPAN_IPHC_FLAG_DST_MODE, NULL, HFILL }},
        { &hf_6lowpan_iphc_sci,
          { "Source context identifier",      "6lowpan.iphc.sci",
            FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_FLAG_SCI, NULL, HFILL }},
        { &hf_6lowpan_iphc_dci,
          { "Destination context identifier", "6lowpan.iphc.dci",
            FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_FLAG_DCI, NULL, HFILL }},

        /* Context information fields. */
        { &hf_6lowpan_iphc_sctx_prefix,
        { "Source context",                   "6lowpan.iphc.sctx.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_6lowpan_iphc_sctx_origin,
        { "Origin",                           "6lowpan.iphc.sctx.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_6lowpan_iphc_dctx_prefix,
        { "Destination context",              "6lowpan.iphc.dctx.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_6lowpan_iphc_dctx_origin,
        { "Origin",                           "6lowpan.iphc.dctx.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* NHC IPv6 extension header fields. */
        { &hf_6lowpan_nhc_ext_eid,
          { "Header ID",                      "6lowpan.nhc.ext.eid",
            FT_UINT8, BASE_HEX, VALS(lowpan_nhc_eid), LOWPAN_NHC_EXT_EID, NULL, HFILL }},
        { &hf_6lowpan_nhc_ext_nh,
          { "Next header",                    "6lowpan.nhc.ext.nh",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_EXT_NHDR, NULL, HFILL }},
        { &hf_6lowpan_nhc_ext_next,
          { "Next header",                    "6lowpan.nhc.ext.next",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_nhc_ext_length,
          { "Header length",                  "6lowpan.nhc.ext.length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_nhc_ext_reserved,
          { "Reserved octet",                  "6lowpan.nhc.ext.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* NHC UDP header fields. */
        { &hf_6lowpan_nhc_udp_checksum,
          { "Checksum",                       "6lowpan.nhc.udp.checksum",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_UDP_CHECKSUM, NULL, HFILL }},
        { &hf_6lowpan_nhc_udp_ports,
          { "Ports",                          "6lowpan.nhc.udp.ports",
            FT_UINT8, BASE_DEC, VALS(lowpan_udp_ports), LOWPAN_NHC_UDP_PORTS, NULL, HFILL }},

        /* Uncompressed IPv6 fields. */
        { &hf_6lowpan_traffic_class,
          { "Traffic class",                  "6lowpan.class",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_flow_label,
          { "Flow label",                     "6lowpan.flow",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_ecn,
          { "ECN",                            "6lowpan.ecn",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_dscp,
          { "DSCP",                           "6lowpan.dscp",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_next_header,
          { "Next header",                    "6lowpan.next",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_hop_limit,
          { "Hop limit",                      "6lowpan.hops",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_source,
          { "Source",                         "6lowpan.src",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_dest,
          { "Destination",                    "6lowpan.dst",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Destination IPv6 address", HFILL }},

        /* Uncompressed UDP fields. */
        { &hf_6lowpan_udp_src,
          { "Source port",                    "6lowpan.udp.src",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_udp_dst,
          { "Destination port",               "6lowpan.udp.dst",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_udp_len,
          { "UDP length",                     "6lowpan.udp.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_udp_checksum,
          { "UDP checksum",                   "6lowpan.udp.checksum",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* Broadcast header fields. */
        { &hf_6lowpan_bcast_seqnum,
          { "Sequence number",                "6lowpan.bcast.seqnum",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Mesh header fields. */
        { &hf_6lowpan_mesh_v,
          { "V",                              "6lowpan.mesh.v",
            FT_BOOLEAN, 8, NULL, LOWPAN_MESH_HEADER_V, "short originator address present", HFILL }},
        { &hf_6lowpan_mesh_f,
          { "D",                              "6lowpan.mesh.f",
            FT_BOOLEAN, 8, NULL, LOWPAN_MESH_HEADER_F, "short destination address present", HFILL }},
        { &hf_6lowpan_mesh_hops,
          { "Hops left",                      "6lowpan.mesh.hops",
            FT_UINT8, BASE_DEC, NULL, LOWPAN_MESH_HEADER_HOPS, NULL, HFILL }},
        { &hf_6lowpan_mesh_hops8,
          { "Deep Hops left (Flags.Hops left == 15)", "6lowpan.mesh.hops8",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_mesh_orig16,
          { "Originator",                     "6lowpan.mesh.orig16",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_mesh_orig64,
          { "Originator",                     "6lowpan.mesh.orig64",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_mesh_dest16,
          { "Destination",                    "6lowpan.mesh.dest16",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_mesh_dest64,
          { "Destination",                    "6lowpan.mesh.dest64",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* Fragmentation header fields. */
        { &hf_6lowpan_frag_dgram_size,
          { "Datagram size",                  "6lowpan.frag.size",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_frag_dgram_tag,
          { "Datagram tag",                   "6lowpan.frag.tag",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_frag_dgram_offset,
          { "Datagram offset",                "6lowpan.frag.offset",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Recoverable Fragmentation header fields. */
        { &hf_6lowpan_rfrag_congestion,
          { "Congestion",                     "6lowpan.rfrag.congestion",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_6lowpan_rfrag_ack_requested,
          { "Ack requested",                  "6lowpan.rfrag.ack_requested",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000, NULL, HFILL }},
        { &hf_6lowpan_rfrag_dgram_tag,
          { "Datagram tag",                   "6lowpan.rfrag.tag",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_rfrag_sequence,
          { "Fragment sequence",              "6lowpan.rfrag.sequence",
            FT_UINT16, BASE_DEC, NULL, 0x7C00, NULL, HFILL }},
        { &hf_6lowpan_rfrag_size,
          { "Fragment size",                  "6lowpan.rfrag.size",
            FT_UINT16, BASE_DEC, NULL, 0x03FF, NULL, HFILL }},
        { &hf_6lowpan_rfrag_dgram_size,
          { "Datagram size",                "6lowpan.rfrag.datagram_size",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_rfrag_offset,
          { "Fragment offset",                "6lowpan.rfrag.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_rfrag_ack_bitmap,
          { "Fragment ACK bitmask",                "6lowpan.rfrag.ack_bitmask",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* Reassembly fields. */
        { &hf_6lowpan_fragments,
          { "Message fragments",              "6lowpan.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment,
          { "Message fragment",               "6lowpan.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_overlap,
          { "Message fragment overlap",       "6lowpan.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_overlap_conflicts,
          { "Message fragment overlapping with conflicting data", "6lowpan.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_multiple_tails,
          { "Message has multiple tail fragments", "6lowpan.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_too_long_fragment,
          { "Message fragment too long",      "6lowpan.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_error,
          { "Message defragmentation error",  "6lowpan.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_count,
          { "Message fragment count",         "6lowpan.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_reassembled_in,
          { "Reassembled in",                 "6lowpan.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_reassembled_length,
          { "Reassembled 6LoWPAN length",     "6lowpan.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},

        /* 6loRH fields */
        { &hf_6lowpan_6lorhc_address_src,
          { "Encapsulator Address",           "6lowpan.src",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_6lorhc_address_hop0,
          { "Source/15, Delta",               "6lowpan.src",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_6lorhc_address_hop1,
          { "Source/14, Delta",               "6lowpan.src",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_6lorhc_address_hop2,
          { "Source/12, Delta",               "6lowpan.src",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_6lorhc_address_hop3,
          { "Source/8, Delta",                "6lowpan.src",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_6lorhc_address_hop4,
          { "Source/0 Delta",                 "6lowpan.src",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_sender_rank1,
          { "Sender Rank",                    "6lowpan.sender.rank",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_sender_rank2,
          { "Sender Rank",                    "6lowpan.sender.rank",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_rpl_instance,
          { "RPL Instance",                   "6lowpan.rpl.instance",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_5_bit_o,
          { "Packet direction (bit O)",             "6lowpan.6loRH.bitO",
            FT_BOOLEAN, 16, TFS(&tfs_down_up), LOWPAN_5_RPI_BIT_O, NULL, HFILL }},
        { &hf_6lowpan_5_bit_r,
          { "Rank-Error (bit R)",               "6lowpan.6loRH.bitR",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), LOWPAN_5_RPI_BIT_R, NULL, HFILL }},
        { &hf_6lowpan_5_bit_f,
          { "Forwarding-Error (bit F)",         "6lowpan.6loRH.bitF",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), LOWPAN_5_RPI_BIT_F, NULL, HFILL }},
        { &hf_6lowpan_5_bit_i,
          { "RPL Instance (bit I)",                 "6lowpan.6loRH.bitI",
            FT_BOOLEAN, 16, TFS(&bit_I_RPL), LOWPAN_5_RPI_BIT_I, NULL, HFILL }},
        { &hf_6lowpan_5_bit_k,
          { "Sender Rank Compression size (bit K)",     "6lowpan.6loRH.bitK",
            FT_BOOLEAN, 16, TFS(&bit_K_RPL), LOWPAN_5_RPI_BIT_K, NULL, HFILL }},
        { &hf_6lowpan_6lorhe_hoplimit,
          { "6loRH Hop Limit",                "6lowpan.rhhop.limit",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_6lorhe_bitmap,
          { "6loRH BIER Bitmap",              "6lowpan.bitmap",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_6lorhe_type,
          { "6loRH Type",                     "6lowpan.rhtype",
            FT_UINT16, BASE_HEX, VALS(lowpan_patterns_rh_type), LOWPAN_PATTERN_6LORHE_TYPE, NULL, HFILL }},
        { &hf_6lowpan_6lorhc_size,
          { "6loRH Hop Number-1",             "6lowpan.HopNuevo",
            FT_UINT16, BASE_HEX, NULL, LOWPAN_PATTERN_6LORHE_LENGTH, NULL, HFILL }},
        { &hf_6lowpan_6lorhe_size,
          { "6loRH Bitmap Word Number-1",     "6lowpan.WordNuevo",
            FT_UINT16, BASE_HEX, NULL, LOWPAN_PATTERN_6LORHE_LENGTH, NULL, HFILL }},
        { &hf_6lowpan_6lorhe_length,
          { "6loRH Elective Length",          "6lowpan.rhElength",
            FT_UINT16, BASE_DEC, NULL, LOWPAN_PATTERN_6LORHE_LENGTH, NULL, HFILL }},
        { &hf_6lowpan_routing_header,
          { "Routing Header 6lo",             "6lowpan.routingheader",
            FT_UINT8, BASE_HEX, VALS(lowpan_patterns_rh), 0x0, NULL, HFILL }},
        { &hf_6lowpan_pagenb,
          { "Page Number",                    "6lowpan.pagenb",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_6lowpan,
        &ett_6lowpan_hc1,
        &ett_6lowpan_hc1_encoding,
        &ett_6lowpan_hc2_udp,
        &ett_6lowpan_iphc,
        &ett_lowpan_routing_header_dispatch,
        &ett_6lowpan_nhc_ext,
        &ett_6lowpan_nhc_udp,
        &ett_6lowpan_bcast,
        &ett_6lowpan_mesh,
        &ett_6lowpan_mesh_flags,
        &ett_6lowpan_frag,
        /* Reassembly subtrees. */
        &ett_6lowpan_fragment,
        &ett_6lowpan_fragments
    };

    static ei_register_info ei[] = {
        { &ei_6lowpan_hc1_more_bits, { "6lowpan.hc1_more_bits", PI_MALFORMED, PI_ERROR, "HC1 more bits expected for illegal next header type.", EXPFILL }},
        { &ei_6lowpan_illegal_dest_addr_mode, { "6lowpan.illegal_dest_addr_mode", PI_MALFORMED, PI_ERROR, "Illegal destination address mode", EXPFILL }},
        { &ei_6lowpan_bad_ipv6_header_length, { "6lowpan.bad_ipv6_header_length", PI_MALFORMED, PI_ERROR, "Length is less than IPv6 header length", EXPFILL }},
        { &ei_6lowpan_bad_ext_header_length, { "6lowpan.bad_ext_header_length", PI_MALFORMED, PI_ERROR, "Extension header not 8-octet aligned", EXPFILL }},
    };

    int         i;
    module_t    *prefs_module;
    expert_module_t* expert_6lowpan;

    lowpan_context_table = g_hash_table_new_full(lowpan_context_hash, lowpan_context_equal, lowpan_context_free, lowpan_context_free);

    proto_6lowpan = proto_register_protocol("IPv6 over Low power Wireless Personal Area Networks", "6LoWPAN", "6lowpan");
    proto_register_field_array(proto_6lowpan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_6lowpan = expert_register_protocol(proto_6lowpan);
    expert_register_field_array(expert_6lowpan, ei, array_length(ei));

    /* Register the dissector with wireshark. */
    handle_6lowpan = register_dissector("6lowpan", dissect_6lowpan, proto_6lowpan);

    /* Initialize the fragment reassembly table. */
    reassembly_table_register(&lowpan_reassembly_table, &addresses_reassembly_table_functions);

    /* Register the dissector init function */
    register_init_routine(proto_init_6lowpan);
    register_shutdown_routine(proto_shutdown_6lowpan);

    /* Initialize the context preferences. */
    memset((char*)lowpan_context_prefs, 0, sizeof(lowpan_context_prefs));

    /* Register preferences. */
    prefs_module = prefs_register_protocol(proto_6lowpan, prefs_6lowpan_apply);

    prefs_register_bool_preference(prefs_module, "rfc4944_short_address_format",
                                   "Derive IID according to RFC 4944",
                                   "Derive IID from a short 16-bit address according to RFC 4944 (using the PAN ID).",
                                   &rfc4944_short_address_format);
    prefs_register_bool_preference(prefs_module, "iid_has_universal_local_bit",
                                   "IID has Universal/Local bit",
                                   "Linux kernels before version 4.12 does toggle the Universal/Local bit.",
                                   &iid_has_universal_local_bit);
    prefs_register_bool_preference(prefs_module, "summary_in_tree",
                                   "Show IPv6 summary in protocol tree",
                                   "Whether the IPv6 summary line should be shown in the protocol tree",
                                   &ipv6_summary_in_tree);

    for (i = 0; i < LOWPAN_CONTEXT_MAX; i++) {
        char *pref_name, *pref_title;

        /*
         * Inspired by the IEEE 802.11 dissector - the preferences are expecting
         * that each pref has a unique string passed in, and will crash if we
         * try to reuse any for multiple preferences.
         */
        pref_name  = wmem_strdup_printf(wmem_epan_scope(), "context%d", i);
        pref_title = wmem_strdup_printf(wmem_epan_scope(), "Context %d", i);
        prefs_register_string_preference(prefs_module, pref_name, pref_title,
            "IPv6 prefix to use for stateful address decompression.",
            &lowpan_context_prefs[i]);
    }
} /* proto_register_6lowpan */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_init_6lowpan
 *  DESCRIPTION
 *      6LoWPAN initialization function.
 *  PARAMETERS
 *      none            ;
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
proto_init_6lowpan(void)
{
    /* Initialize the link-local context. */
    lowpan_context_local.frame = 0;
    lowpan_context_local.plen = LOWPAN_CONTEXT_LINK_LOCAL_BITS;
    memcpy(&lowpan_context_local.prefix, lowpan_llprefix, sizeof(lowpan_llprefix));

    /* Reload static contexts from our preferences. */
    prefs_6lowpan_apply();
} /* proto_init_6lowpan */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      prefs_6lowpan_apply
 *  DESCRIPTION
 *      Prefs "apply" callback. Parses the context table for
 *      IPv6 addresses/prefixes.
 *  PARAMETERS
 *      none            ;
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
void
prefs_6lowpan_apply(void)
{
    int                 i;
    ws_in6_addr   prefix;
    char                *prefix_str;
    char                *prefix_len_str;
    uint32_t            prefix_len;
    char                prefix_buf[48]; /* max length of IPv6 str. plus a bit */

    for (i = 0; i < LOWPAN_CONTEXT_MAX; i++) {
        if (!lowpan_context_prefs[i]) continue;
        (void) g_strlcpy(prefix_buf, lowpan_context_prefs[i], 48);
        if ((prefix_str = strtok(prefix_buf, "/")) == NULL) continue;
        if ((prefix_len_str = strtok(NULL, "/")) == NULL) continue;
        if (sscanf(prefix_len_str, "%u", &prefix_len) != 1) continue;
        if (!str_to_ip6(prefix_str, &prefix)) continue;
        /* Set the prefix */
        lowpan_context_insert(i, IEEE802154_BCAST_PAN, prefix_len, &prefix, 0);
    } /* for */
} /* prefs_6lowpan_apply */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_6lowpan
 *  DESCRIPTION
 *      Protocol handoff routine for 6LoWPAN. Called after all
 *      protocols have been loaded.
 *  PARAMETERS
 *      none            ;
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_6lowpan(void)
{
    ipv6_handle = find_dissector_add_dependency("ipv6", proto_6lowpan);

    /* Register the 6LoWPAN dissector with IEEE 802.15.4 */
    dissector_add_for_decode_as(IEEE802154_PROTOABBREV_WPAN_PANID, handle_6lowpan);
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_6lowpan_heur, "6LoWPAN over IEEE 802.15.4", "6lowpan_wlan", proto_6lowpan, HEURISTIC_ENABLE);

    /* Register Ethertype (RFC 7973) */
    dissector_add_uint("ethertype", ETHERTYPE_6LOWPAN, handle_6lowpan);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_LE_IPSP, handle_6lowpan);
    dissector_add_for_decode_as("btl2cap.cid", handle_6lowpan);
} /* proto_reg_handoff_6lowpan */


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
