/* packet-6lowpan.c
 * Routines for 6LoWPAN packet disassembly
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Owen Kirby
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
#include "config.h"
#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>
#include "packet-ipv6.h"
#include "packet-6lowpan.h"
#include "packet-btl2cap.h"
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
#define LOWPAN_NHC_UDP_SRCPORT          0x02
#define LOWPAN_NHC_UDP_DSTPORT          0x01

/* 6LoWPAN Mesh Header */
#define LOWPAN_MESH_HEADER_V            0x20
#define LOWPAN_MESH_HEADER_F            0x10
#define LOWPAN_MESH_HEADER_HOPS         0x0f

/* 6LoWPAN First Fragment Header */
#define LOWPAN_FRAG_DGRAM_SIZE_BITS     11

/* Uncompressed IPv6 Option types */
#define IP6OPT_PAD1                     0x00
#define IP6OPT_PADN                     0x01

/* Compressed port number offset. */
#define LOWPAN_PORT_8BIT_OFFSET         0xf000
#define LOWPAN_PORT_12BIT_OFFSET        (LOWPAN_PORT_8BIT_OFFSET | 0xb0)

/* 6LoWPAN interface identifier length. */
#define LOWPAN_IFC_ID_LEN               8
/* Protocol fields handles. */
static int proto_6lowpan = -1;
static int hf_6lowpan_pattern = -1;
static int hf_6lowpan_nhc_pattern = -1;
static int hf_6lowpan_padding = -1;

/* Header compression fields. */
static int hf_6lowpan_hc1_encoding = -1;
static int hf_6lowpan_hc1_source_prefix = -1;
static int hf_6lowpan_hc1_source_ifc = -1;
static int hf_6lowpan_hc1_dest_prefix = -1;
static int hf_6lowpan_hc1_dest_ifc = -1;
static int hf_6lowpan_hc1_class = -1;
static int hf_6lowpan_hc1_next = -1;
static int hf_6lowpan_hc1_more = -1;
static int hf_6lowpan_hc2_udp_encoding = -1;
static int hf_6lowpan_hc2_udp_src = -1;
static int hf_6lowpan_hc2_udp_dst = -1;
static int hf_6lowpan_hc2_udp_len = -1;

/* IPHC header field. */
static int hf_6lowpan_iphc_flag_tf = -1;
static int hf_6lowpan_iphc_flag_nhdr = -1;
static int hf_6lowpan_iphc_flag_hlim = -1;
static int hf_6lowpan_iphc_flag_cid = -1;
static int hf_6lowpan_iphc_flag_sac = -1;
static int hf_6lowpan_iphc_flag_sam = -1;
static int hf_6lowpan_iphc_flag_mcast = -1;
static int hf_6lowpan_iphc_flag_dac = -1;
static int hf_6lowpan_iphc_flag_dam = -1;
static int hf_6lowpan_iphc_sci = -1;
static int hf_6lowpan_iphc_dci = -1;

static int hf_6lowpan_iphc_sctx_prefix = -1;
static int hf_6lowpan_iphc_sctx_origin = -1;
static int hf_6lowpan_iphc_dctx_prefix = -1;
static int hf_6lowpan_iphc_dctx_origin = -1;

/* NHC IPv6 extension header fields. */
static int hf_6lowpan_nhc_ext_eid = -1;
static int hf_6lowpan_nhc_ext_nh = -1;
static int hf_6lowpan_nhc_ext_next = -1;
static int hf_6lowpan_nhc_ext_length = -1;
static int hf_6lowpan_nhc_ext_reserved = -1;

/* NHC UDP compression header fields. */
static int hf_6lowpan_nhc_udp_checksum = -1;
static int hf_6lowpan_nhc_udp_src = -1;
static int hf_6lowpan_nhc_udp_dst = -1;

/* Inline IPv6 header fields. */
static int hf_6lowpan_traffic_class = -1;
static int hf_6lowpan_flow_label = -1;
static int hf_6lowpan_ecn = -1;
static int hf_6lowpan_dscp = -1;
static int hf_6lowpan_next_header = -1;
static int hf_6lowpan_hop_limit = -1;
static int hf_6lowpan_source = -1;
static int hf_6lowpan_dest = -1;

/* Inline UDP header fields. */
static int hf_6lowpan_udp_src = -1;
static int hf_6lowpan_udp_dst = -1;
static int hf_6lowpan_udp_len = -1;
static int hf_6lowpan_udp_checksum = -1;

/* Broadcast header fields. */
static int hf_6lowpan_bcast_seqnum = -1;

/* Mesh header fields. */
static int hf_6lowpan_mesh_v = -1;
static int hf_6lowpan_mesh_f = -1;
static int hf_6lowpan_mesh_hops = -1;
static int hf_6lowpan_mesh_hops8 = -1;
static int hf_6lowpan_mesh_orig16 = -1;
static int hf_6lowpan_mesh_orig64 = -1;
static int hf_6lowpan_mesh_dest16 = -1;
static int hf_6lowpan_mesh_dest64 = -1;

/* Fragmentation header fields. */
static int hf_6lowpan_frag_dgram_size = -1;
static int hf_6lowpan_frag_dgram_tag = -1;
static int hf_6lowpan_frag_dgram_offset = -1;

/* Protocol tree handles.  */
static gint ett_6lowpan = -1;
static gint ett_6lowpan_hc1 = -1;
static gint ett_6lowpan_hc1_encoding = -1;
static gint ett_6lowpan_hc2_udp = -1;
static gint ett_6lowpan_iphc = -1;
static gint ett_6lowpan_nhc_ext = -1;
static gint ett_6lowpan_nhc_udp = -1;
static gint ett_6lowpan_bcast = -1;
static gint ett_6lowpan_mesh = -1;
static gint ett_6lowpan_mesh_flags = -1;
static gint ett_6lowpan_frag = -1;

static expert_field ei_6lowpan_hc1_more_bits = EI_INIT;
static expert_field ei_6lowpan_illegal_dest_addr_mode = EI_INIT;
static expert_field ei_6lowpan_bad_ipv6_header_length = EI_INIT;
static expert_field ei_6lowpan_bad_ext_header_length = EI_INIT;

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
/* Reassembly Data */
static int hf_6lowpan_fragments = -1;
static int hf_6lowpan_fragment = -1;
static int hf_6lowpan_fragment_overlap = -1;
static int hf_6lowpan_fragment_overlap_conflicts = -1;
static int hf_6lowpan_fragment_multiple_tails = -1;
static int hf_6lowpan_fragment_too_long_fragment = -1;
static int hf_6lowpan_fragment_error = -1;
static int hf_6lowpan_fragment_count = -1;
static int hf_6lowpan_reassembled_in = -1;
static int hf_6lowpan_reassembled_length = -1;
static gint ett_6lowpan_fragment = -1;
static gint ett_6lowpan_fragments = -1;

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
static GHashTable *lowpan_context_table = NULL;

/* Link-Local prefix used by 6LoWPAN (FF80::/10) */
static const guint8 lowpan_llprefix[8] = {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Context hash table map key. */
typedef struct {
    guint16 pan;    /* PAN Identifier */
    guint8  cid;    /* Context Identifier */
} lowpan_context_key;

/* Context hash table map data. */
typedef struct {
    guint   frame;  /* Frame where the context was discovered. */
    guint8  plen;   /* Prefix length. */
    struct e_in6_addr prefix;   /* Compression context. */
} lowpan_context_data;

/* 6LoWPAN contexts. */
#define LOWPAN_CONTEXT_MAX              16
#define LOWPAN_CONTEXT_DEFAULT          0
#define LOWPAN_CONTEXT_LINK_LOCAL       LOWPAN_CONTEXT_MAX
#define LOWPAN_CONTEXT_LINK_LOCAL_BITS  10
static lowpan_context_data  lowpan_context_local;
static lowpan_context_data  lowpan_context_default;
static const gchar *        lowpan_context_prefs[LOWPAN_CONTEXT_MAX];

/* Preferences */
static gboolean rfc4944_short_address_format = FALSE;

/* Helper macro to convert a bit offset/length into a byte count. */
#define BITS_TO_BYTE_LEN(bitoff, bitlen)    ((bitlen)?(((bitlen) + ((bitoff)&0x07) + 7) >> 3):(0))

/* Structure for rebuilding UDP datagrams. */
struct udp_hdr {
    guint16             src_port;
    guint16             dst_port;
    guint16             length;
    guint16             checksum;
};

/* Structure used to store decompressed header chains until reassembly. */
struct lowpan_nhdr {
    /* List Linking */
    struct lowpan_nhdr  *next;
    /* Next Header */
    guint8              proto;
    guint               length;
    guint               reported;
};
#define LOWPAN_NHDR_DATA(nhdr)  ((guint8 *)(nhdr) + sizeof (struct lowpan_nhdr))

/* Dissector prototypes */
static void         proto_init_6lowpan          (void);
static void         proto_cleanup_6lowpan(void);
static void         prefs_6lowpan_apply         (void);
static int          dissect_6lowpan             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static tvbuff_t *   dissect_6lowpan_ipv6        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_hc1         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, const guint8 *siid, const guint8 *diid);
static tvbuff_t *   dissect_6lowpan_bc0         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_iphc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, const guint8 *siid, const guint8 *diid);
static struct lowpan_nhdr *
                    dissect_6lowpan_iphc_nhc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint dgram_size, const guint8 *siid, const guint8 *diid);
static tvbuff_t *   dissect_6lowpan_mesh        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 *siid, guint8 *diid);
static tvbuff_t *   dissect_6lowpan_frag_first  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint8 *siid, const guint8 *diid);
static tvbuff_t *   dissect_6lowpan_frag_middle (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void         dissect_6lowpan_unknown     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Helper functions. */
static gboolean     lowpan_dlsrc_to_ifcid   (packet_info *pinfo, guint8 *ifcid);
static gboolean     lowpan_dldst_to_ifcid   (packet_info *pinfo, guint8 *ifcid);
static void         lowpan_addr16_to_ifcid  (guint16 addr, guint8 *ifcid);
static void         lowpan_addr16_with_panid_to_ifcid(guint16 panid, guint16 addr, guint8 *ifcid);
static tvbuff_t *   lowpan_reassemble_ipv6  (tvbuff_t *tvb, packet_info *pinfo, struct ws_ip6_hdr *ipv6, struct lowpan_nhdr *nhdr_list);
static guint8       lowpan_parse_nhc_proto  (tvbuff_t *tvb, gint offset);

/* Context table helpers */
static guint        lowpan_context_hash     (gconstpointer key);
static gboolean     lowpan_context_equal    (gconstpointer a, gconstpointer b);
static lowpan_context_data *lowpan_context_find(guint8 cid, guint16 pan);

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
        guint8 mask = ((0xff00) >> (bits & 0x7));
        guint8 last = ((const guint8 *)src)[bits>>3] & mask;
        ((guint8 *)dst)[bits>>3] &= ~mask;
        ((guint8 *)dst)[bits>>3] |= last;
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
 *      guint           ; The hashed key value.
 *---------------------------------------------------------------
 */
static guint
lowpan_context_hash(gconstpointer key)
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
 *      gboolean        ;
 *---------------------------------------------------------------
 */
static gboolean
lowpan_context_equal(gconstpointer a, gconstpointer b)
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
lowpan_context_find(guint8 cid, guint16 pan)
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
lowpan_context_insert(guint8 cid, guint16 pan, guint8 plen, struct e_in6_addr *prefix, guint frame)
{
    lowpan_context_key  key;
    lowpan_context_data *data;
    gpointer            pkey;
    gpointer            pdata;

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
    memset(&data->prefix, 0, sizeof(struct e_in6_addr)); /* Ensure zero paddeding */
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
lowpan_context_free(gpointer data)
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
lowpan_addr16_to_ifcid(guint16 addr, guint8 *ifcid)
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
lowpan_addr16_with_panid_to_ifcid(guint16 panid, guint16 addr, guint8 *ifcid)
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
 *      lowpan_dlsrc_to_ifcid
 *  DESCRIPTION
 *      Finds an interface identifier from the data-link source
 *      addressing.
 *  PARAMETERS
 *      pinfo           ; packet information.
 *      ifcid           ; interface identifier (output).
 *  RETURNS
 *      gboolean        ; TRUE if an interface identifier could
 *                          be found.
 *---------------------------------------------------------------
 */
static gboolean
lowpan_dlsrc_to_ifcid(packet_info *pinfo, guint8 *ifcid)
{
    ieee802154_hints_t  *hints;

    /* Check the link-layer address field. */
    if (pinfo->dl_src.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_src.data, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return TRUE;
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

        return TRUE;
    } else {
        /* Failed to find a link-layer source address. */
        memset(ifcid, 0, LOWPAN_IFC_ID_LEN);
        return FALSE;
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
 *      gboolean        ; TRUE if an interface identifier could
 *                          be found.
 *---------------------------------------------------------------
 */
static gboolean
lowpan_dldst_to_ifcid(packet_info *pinfo, guint8 *ifcid)
{
    ieee802154_hints_t  *hints;

    /* Check the link-layer address field. */
    if (pinfo->dl_dst.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_dst.data, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return TRUE;
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

        return TRUE;
    } else {
        /* Failed to find a link-layer destination address. */
        memset(ifcid, 0, LOWPAN_IFC_ID_LEN);
        return FALSE;
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
    gint                length = 0;
    gint                reported = 0;
    guint8 *            buffer;
    guint8 *            cursor;
    struct lowpan_nhdr *nhdr;

    /* Compute the real and reported lengths. */
    for (nhdr = nhdr_list; nhdr; nhdr = nhdr->next) {
        length += nhdr->length;
        reported += nhdr->reported;
    }
    ipv6->ip6_plen = g_ntohs(reported);

    /* Allocate a buffer for the packet and copy in the IPv6 header. */
    buffer = (guint8 *)wmem_alloc(pinfo->pool, length + IPv6_HDR_SIZE);
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
 *      guint8          ; IP_PROTO_* of the next header's protocol.
 *---------------------------------------------------------------
 */
static guint8
lowpan_parse_nhc_proto(tvbuff_t *tvb, gint offset)
{
    /* Ensure that at least one byte exists. */
    if (!tvb_bytes_exist(tvb, offset, 1)) return IP_PROTO_NONE;

    /* Check for IPv6 extension headers. */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS) == LOWPAN_NHC_PATTERN_EXT) {
        guint8      eid = (tvb_get_guint8(tvb, offset) & LOWPAN_NHC_EXT_EID) >> LOWPAN_NHC_EXT_EID_OFFSET;
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
 *      boolean         ; TRUE if the tvbuff was dissected as a
 *                          6LoWPAN packet. If this returns FALSE,
 *                          then no dissection will be attempted.
 *---------------------------------------------------------------
 */
static gboolean
dissect_6lowpan_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint    offset = 0;

    /* Check for valid patterns. */
    for (;;) {
        /* Parse patterns until we find a match. */
        if (!tvb_reported_length_remaining(tvb, offset)) return FALSE;
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
            guint8 mesh = tvb_get_guint8(tvb, offset++);
            offset += (mesh & LOWPAN_MESH_HEADER_V) ? 2 : 8;
            offset += (mesh & LOWPAN_MESH_HEADER_F) ? 2 : 8;
            if ((mesh & LOWPAN_MESH_HEADER_HOPS) == LOWPAN_MESH_HEADER_HOPS) offset++;
            continue;
        }
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAG1) {
            /* First fragment headers must be followed by another valid header. */
            offset += 4;
            continue;
        }
        if (tvb_get_bits8(tvb, offset*8, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAGN) break;

        /* If we get here, then we couldn't match to any pattern. */
        return FALSE;
    } /* for */

    /* If we get here, then we found a matching pattern. */
    dissect_6lowpan(tvb, pinfo, tree, data);
    return TRUE;
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
    /* Interface identifier of the encapsulating layer. */
    guint8      src_iid[LOWPAN_IFC_ID_LEN];
    guint8      dst_iid[LOWPAN_IFC_ID_LEN];

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
dissect_6lowpan_hc1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, const guint8 *siid, const guint8 *diid)
{
    gint                offset = 0;
    gint                bit_offset;
    int                 i;
    guint8              hc1_encoding;
    guint8              hc_udp_encoding = 0;
    guint8              next_header;
    proto_tree *        hc_tree;
    proto_item *        hc_item;
    tvbuff_t *          ipv6_tvb;
    /* IPv6 header. */
    guint8              ipv6_class;
    guint32             ipv6_flow;
    struct ws_ip6_hdr   ipv6;
    struct lowpan_nhdr *nhdr_list;
    static const int * hc1_encodings[] = {
        &hf_6lowpan_hc1_source_prefix,
        &hf_6lowpan_hc1_source_ifc,
        &hf_6lowpan_hc1_dest_prefix,
        &hf_6lowpan_hc1_dest_ifc,
        &hf_6lowpan_hc1_class,
        &hf_6lowpan_hc1_next,
        &hf_6lowpan_hc1_more,
        NULL
    };
    static const int * hc2_encodings[] = {
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
    hc1_encoding = tvb_get_guint8(tvb, offset);
    next_header = ((hc1_encoding & LOWPAN_HC1_NEXT) >> 1);
    proto_tree_add_bitmask(hc_tree, tvb, offset, hf_6lowpan_hc1_encoding,
                   ett_6lowpan_hc1_encoding, hc1_encodings, ENC_NA);
    offset += 1;

    /* Get and display the HC2 encoding bits, if present. */
    if (hc1_encoding & LOWPAN_HC1_MORE) {
        if (next_header == LOWPAN_HC1_NEXT_UDP) {
            hc_udp_encoding = tvb_get_guint8(tvb, offset);
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
    ipv6.ip6_hlim = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS);
    proto_tree_add_uint(tree, hf_6lowpan_hop_limit, tvb, bit_offset>>3,
            BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS), ipv6.ip6_hlim);
    bit_offset += LOWPAN_IPV6_HOP_LIMIT_BITS;

    /*=====================================================
     * Parse/Decompress IPv6 Source Address
     *=====================================================
     */
    offset = bit_offset;
    if (!(hc1_encoding & LOWPAN_HC1_SOURCE_PREFIX)) {
        for (i=0; i<8; i++, bit_offset += 8) {
            ipv6.ip6_src.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(ipv6.ip6_src.bytes, lowpan_llprefix, sizeof(lowpan_llprefix));
    }
    if (!(hc1_encoding & LOWPAN_HC1_SOURCE_IFC)) {
        for (i=8; i<16; i++, bit_offset += 8) {
            ipv6.ip6_src.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(&ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - LOWPAN_IFC_ID_LEN], siid, LOWPAN_IFC_ID_LEN);
    }
    /* Display the source address. */
    proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset>>3,
            BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), &ipv6.ip6_src);

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
            ipv6.ip6_dst.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(ipv6.ip6_dst.bytes, lowpan_llprefix, sizeof(lowpan_llprefix));
    }
    if (!(hc1_encoding & LOWPAN_HC1_DEST_IFC)) {
        for (i=8; i<16; i++, bit_offset += 8) {
            ipv6.ip6_dst.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(&ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - LOWPAN_IFC_ID_LEN], diid, LOWPAN_IFC_ID_LEN);
    }
    /* Display the destination address. */
    proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset>>3,
            BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), &ipv6.ip6_dst);

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
    ipv6.ip6_ctl_flow = ipv6_flow;
    ipv6.ip6_ctl_flow |= ((guint32)ipv6_class << LOWPAN_IPV6_FLOW_LABEL_BITS);
    ipv6.ip6_ctl_flow |= ((guint32)0x6 << (LOWPAN_IPV6_TRAFFIC_CLASS_BITS + LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6_ctl_flow = g_ntohl(ipv6.ip6_ctl_flow);

    /* Parse the IPv6 next header field. */
    if (next_header == LOWPAN_HC1_NEXT_UDP) {
        ipv6.ip6_nxt = IP_PROTO_UDP;
    }
    else if (next_header == LOWPAN_HC1_NEXT_ICMP) {
        ipv6.ip6_nxt = IP_PROTO_ICMPV6;
    }
    else if (next_header == LOWPAN_HC1_NEXT_TCP) {
        ipv6.ip6_nxt = IP_PROTO_TCP;
    }
    else {
        /* Parse the next header field. */
        ipv6.ip6_nxt = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_NEXT_HEADER_BITS);
        proto_tree_add_uint_format_value(tree, hf_6lowpan_next_header, tvb, bit_offset>>3,
                BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_NEXT_HEADER_BITS), ipv6.ip6_nxt,
                "%s (0x%02x)", ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);
        bit_offset += LOWPAN_IPV6_NEXT_HEADER_BITS;
    }

    /*=====================================================
     * Parse and Reconstruct the UDP Header
     *=====================================================
     */
    if ((hc1_encoding & LOWPAN_HC1_MORE) && (next_header == LOWPAN_HC1_NEXT_UDP)) {
        struct udp_hdr  udp;
        gint            length;

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
        length = (gint)tvb_ensure_captured_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)wmem_alloc(wmem_packet_scope(), sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
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
        gint length;
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        length = (gint)tvb_ensure_captured_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)wmem_alloc(wmem_packet_scope(), sizeof(struct lowpan_nhdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6_nxt;
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
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_iphc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, const guint8 *siid, const guint8 *diid)
{
    ieee802154_hints_t  *hints;
    guint16             hint_panid;
    gint                offset = 0;
    gint                length = 0;
    proto_tree *        iphc_tree;
    proto_item *        ti_dam = NULL;
    /* IPHC header fields. */
    guint16             iphc_flags;
    guint8              iphc_traffic;
    guint8              iphc_hop_limit;
    guint8              iphc_src_mode;
    guint8              iphc_dst_mode;
    guint8              iphc_ctx = 0;
    /* Contexts to use for address decompression. */
    gint                iphc_sci = LOWPAN_CONTEXT_DEFAULT;
    gint                iphc_dci = LOWPAN_CONTEXT_DEFAULT;
    lowpan_context_data *sctx;
    lowpan_context_data *dctx;
    /* IPv6 header */
    guint8              ipv6_dscp = 0;
    guint8              ipv6_ecn = 0;
    guint32             ipv6_flowlabel = 0;
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
        iphc_ctx = tvb_get_guint8(tvb, offset);
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
        PROTO_ITEM_SET_GENERATED(tclass_item);
    }

    /* Parse the flow label. */
    if ((iphc_traffic == LOWPAN_IPHC_FLOW_CLASS_LABEL) || (iphc_traffic == LOWPAN_IPHC_FLOW_ECN_LABEL)) {
        /* Pad to 4-bits past the start of the byte. */
        guint pad_bits = ((4 - offset) & 0x7);
        if (pad_bits) {
            proto_tree_add_bits_item(tree, hf_6lowpan_padding, tvb, offset, pad_bits, ENC_BIG_ENDIAN);
        }
        offset += pad_bits;
        ipv6_flowlabel = tvb_get_bits32(tvb, offset, LOWPAN_IPHC_LABEL_BITS, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(tree, hf_6lowpan_flow_label, tvb, offset, LOWPAN_IPHC_LABEL_BITS, ENC_BIG_ENDIAN);
        offset += LOWPAN_IPHC_LABEL_BITS;
    }

    /* Rebuild the IPv6 flow label, traffic class and version fields. */
    ipv6.ip6_ctl_flow = ipv6_flowlabel;
    ipv6.ip6_ctl_flow |= ((guint32)ipv6_ecn << LOWPAN_IPV6_FLOW_LABEL_BITS);
    ipv6.ip6_ctl_flow |= ((guint32)ipv6_dscp << (LOWPAN_IPHC_ECN_BITS + LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6_ctl_flow |= ((guint32)0x6 << (LOWPAN_IPV6_TRAFFIC_CLASS_BITS + LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6_ctl_flow = g_ntohl(ipv6.ip6_ctl_flow);

    /* Convert back to byte offsets. */
    offset >>= 3;

    /*=====================================================
     * Parse Next Header and Hop Limit
     *=====================================================
     */
    /* Get the next header field, if present. */
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_NHDR)) {
        ipv6.ip6_nxt = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format_value(tree, hf_6lowpan_next_header, tvb, offset, 1, ipv6.ip6_nxt,
                "%s (0x%02x)", ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);
        offset += 1;
    }

    /* Get the hop limit field, if present. */
    if (iphc_hop_limit == LOWPAN_IPHC_HLIM_1) {
        ipv6.ip6_hlim = 1;
    }
    else if (iphc_hop_limit == LOWPAN_IPHC_HLIM_64) {
        ipv6.ip6_hlim = 64;
    }
    else if (iphc_hop_limit == LOWPAN_IPHC_HLIM_255) {
        ipv6.ip6_hlim = 255;
    }
    else {
        ipv6.ip6_hlim = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_6lowpan_hop_limit, tvb, offset, 1, ipv6.ip6_hlim);
        offset += 1;
    }

    /*=====================================================
     * Parse and decompress the source address.
     *=====================================================
     */
    length = 0;
    memset(&ipv6.ip6_src, 0, sizeof(ipv6.ip6_src));
    /* (SAC=1 && SAM=00) -> the unspecified address (::). */
    if ((iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP) && (iphc_src_mode == LOWPAN_IPHC_ADDR_SRC_UNSPEC)) {
        sctx = &lowpan_context_default;
    }
    /* The IID is derived from the encapsulating layer. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_COMPRESSED) {
        memcpy(&ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - LOWPAN_IFC_ID_LEN], siid, LOWPAN_IFC_ID_LEN);
    }
    /* Full Address inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
        if (!(iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP)) sctx = &lowpan_context_default;
        length = (int)sizeof(ipv6.ip6_src);
        tvb_memcpy(tvb, &ipv6.ip6_src, offset, length);
    }
    /* 64-bits inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
        length = 8;
        tvb_memcpy(tvb, &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - length], offset, length);
    }
    /* 16-bits inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
        length = 2;
        /* Format becomes ff:fe00:xxxx */
        ipv6.ip6_src.bytes[11] = 0xff;
        ipv6.ip6_src.bytes[12] = 0xfe;
        tvb_memcpy(tvb, &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - length], offset, length);

    }
    /* Copy the context bits. */
    lowpan_pfxcpy(&ipv6.ip6_src, &sctx->prefix, sctx->plen);
    /* Update the IID of the encapsulating layer. */
    siid = &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - LOWPAN_IFC_ID_LEN];

    /* Display the source IPv6 address. */
    proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset, length, &ipv6.ip6_src);

    /* Add information about where the context came from. */
    /* TODO: We should display the prefix length too. */
    if (sctx->plen) {
        proto_item *ti;
        ti = proto_tree_add_ipv6(iphc_tree, hf_6lowpan_iphc_sctx_prefix, tvb, 0, 0, &sctx->prefix);
        PROTO_ITEM_SET_GENERATED(ti);
        if ( sctx->frame ) {
            ti = proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_sctx_origin, tvb, 0, 0, sctx->frame);
            PROTO_ITEM_SET_GENERATED(ti);
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
    memset(&ipv6.ip6_dst, 0, sizeof(ipv6.ip6_dst));
    /* Stateless multicast compression. */
    if ((iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP) && !(iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP)) {
        if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            length = (int)sizeof(ipv6.ip6_dst);
            tvb_memcpy(tvb, &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - length], offset, length);
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_MCAST_48BIT) {
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[11] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[12] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[13] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[14] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_MCAST_32BIT) {
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[13] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[14] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_MCAST_8BIT) {
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = 0x02;
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
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
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[2] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[3] = (dctx->plen > 64) ? (64) : (dctx->plen);
            memcpy(&ipv6.ip6_dst.bytes[4], &dctx->prefix, 8);
            ipv6.ip6_dst.bytes[12] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[13] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[14] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
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
            memcpy(&ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - LOWPAN_IFC_ID_LEN], diid, LOWPAN_IFC_ID_LEN);
        }
        /* Full Address inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            dctx = &lowpan_context_default;
            length = (int)sizeof(ipv6.ip6_dst);
            tvb_memcpy(tvb, &ipv6.ip6_dst, offset, length);
        }
        /* 64-bits inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
            length = 8;
            tvb_memcpy(tvb, &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - length], offset, length);
        }
        /* 16-bits inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
            length = 2;
            /* Format becomes ff:fe00:xxxx */
            ipv6.ip6_dst.bytes[11] = 0xff;
            ipv6.ip6_dst.bytes[12] = 0xfe;
            tvb_memcpy(tvb, &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - length], offset, length);
        }
        /* Copy the context bits. */
        lowpan_pfxcpy(&ipv6.ip6_dst, &dctx->prefix, dctx->plen);
        /* Update the interface id of the encapsulating layer. */
        diid = &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - LOWPAN_IFC_ID_LEN];
    }

    /* Display the destination IPv6 address. */
    proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset, length, &ipv6.ip6_dst);

    /* Add information about where the context came from. */
    /* TODO: We should display the prefix length too. */
    if (dctx->plen) {
        proto_item *ti;
        ti = proto_tree_add_ipv6(iphc_tree, hf_6lowpan_iphc_dctx_prefix, tvb, 0, 0, &dctx->prefix);
        PROTO_ITEM_SET_GENERATED(ti);
        if ( dctx->frame ) {
            ti = proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_dctx_origin, tvb, 0, 0, dctx->frame);
            PROTO_ITEM_SET_GENERATED(ti);
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
        ipv6.ip6_nxt = lowpan_parse_nhc_proto(tvb, offset);

        /* Parse the 6LoWPAN NHC fields. */
        nhdr_list = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset, dgram_size - IPv6_HDR_SIZE, siid, diid);
    }
    /* Create an extension header for the remaining payload. */
    else {
        length = (gint)tvb_ensure_captured_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)wmem_alloc(wmem_packet_scope(), sizeof(struct lowpan_nhdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6_nxt;
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
dissect_6lowpan_iphc_nhc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint dgram_size, const guint8 *siid, const guint8 *diid)
{
    gint                length;
    proto_item *        ti = NULL;
    proto_tree *        nhc_tree = NULL;
    struct lowpan_nhdr *nhdr;

    /*=====================================================
     * IP-in-IP Tunneling
     *=====================================================
     */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_IPV6_BITS) == LOWPAN_NHC_PATTERN_EXT_IPV6) {
        guint8          ext_flags;
        tvbuff_t       *iphc_tvb;

        /* Create a tree for the IPv6 extension header. */
        nhc_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_6lowpan_nhc_ext, &ti, "IPv6 extension header");
        /* Display the IPv6 Extension Header NHC ID pattern. */
        proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS, ENC_BIG_ENDIAN);

        /* Get and display the extension header compression flags. */
        ext_flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_eid, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_EID);
        proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_ext_nh, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_NHDR);
        if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
            /* TODO: Flag a warning, the NH bit MUST be 0 when EID==0x7 (IP-in-IP). */
        }
        offset += 1;

        /* Decode the remainder of the packet using IPHC encoding. */
        iphc_tvb = dissect_6lowpan_iphc(tvb_new_subset_remaining(tvb, offset), pinfo, tree, dgram_size, siid, diid);
        if (!iphc_tvb) return NULL;

        /* Create the next header structure for the tunneled IPv6 header. */
        nhdr = (struct lowpan_nhdr *)wmem_alloc0(wmem_packet_scope(), sizeof(struct lowpan_nhdr) + tvb_captured_length(iphc_tvb));
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
        struct ip6_ext  ipv6_ext = {0, 0};
        guint8          ext_flags;
        guint8          ext_hlen;
        guint8          ext_len;
        guint8          ext_proto;
        proto_item      *ti_ext_len = NULL;

        /* Parse the IPv6 extension header protocol. */
        ext_proto = lowpan_parse_nhc_proto(tvb, offset);

        /* Create a tree for the IPv6 extension header. */
        nhc_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_6lowpan_nhc_ext, NULL, "IPv6 extension header");
        /* Display the IPv6 Extension Header NHC ID pattern. */
        proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS, ENC_BIG_ENDIAN);

        /* Get and display the extension header compression flags. */
        ext_flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_eid, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_EID);
        proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_ext_nh, tvb, offset, 1, ext_flags & LOWPAN_NHC_EXT_NHDR);
        offset += 1;

        /* Get and display the next header field, if present. */
        if (!(ext_flags & LOWPAN_NHC_EXT_NHDR)) {
            ipv6_ext.ip6e_nxt = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format_value(nhc_tree, hf_6lowpan_nhc_ext_next, tvb, offset, 1, ipv6_ext.ip6e_nxt,
                    "%s (0x%02x)", ipprotostr(ipv6_ext.ip6e_nxt), ipv6_ext.ip6e_nxt);
            proto_item_set_end(ti, tvb, offset+1);
            offset += 1;
        }

        if (ext_proto == IP_PROTO_FRAGMENT) {
            /* Fragment header has a reserved byte in place of the Length field. */
            ext_hlen = 1;
            length = (guint8)sizeof(struct ip6_frag);
            ext_len = length - ext_hlen;

            proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_reserved, tvb, offset, 1, tvb_get_guint8(tvb, offset));

        } else {
            /* Get and display the extension header length. */
            ext_hlen = (guint8)sizeof(struct ip6_ext);
            ext_len = tvb_get_guint8(tvb, offset);
            ti_ext_len = proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_length, tvb, offset, 1, ext_len);
            offset += 1;

            /* Compute the length of the extension header padded to an 8-byte alignment. */
            length = ext_hlen + ext_len;
            length = (length + 7) & ~0x7;
            ipv6_ext.ip6e_len = length>>3;          /* Convert to units of 8 bytes. */
            ipv6_ext.ip6e_len -= 1;                 /* Don't include the first 8 bytes. */
       }

        /* Create the next header structure for the IPv6 extension header. */
        nhdr = (struct lowpan_nhdr *)wmem_alloc0(wmem_packet_scope(), sizeof(struct lowpan_nhdr) + length);
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
            guint8 padding = length - (ext_hlen + ext_len);
            guint8 *pad_ptr = LOWPAN_NHDR_DATA(nhdr) + ext_hlen + ext_len;
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
            nhdr->next = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset, dgram_size - nhdr->reported, siid, diid);
        }
        else if (ipv6_ext.ip6e_nxt != IP_PROTO_NONE) {
            /* Create another next header structure for the remaining payload. */
            length = (gint)tvb_ensure_captured_length_remaining(tvb, offset);
            nhdr->next = (struct lowpan_nhdr *)wmem_alloc(wmem_packet_scope(), sizeof(struct lowpan_nhdr) + length);
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
        gint            src_bitlen;
        gint            dst_bitlen;
        guint8          udp_flags;

        /* Create a tree for the UDP header. */
        nhc_tree = proto_tree_add_subtree(tree, tvb, 0, 1, ett_6lowpan_nhc_udp, NULL, "UDP header compression");
        /* Display the UDP NHC ID pattern. */
        proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_UDP_BITS, ENC_BIG_ENDIAN);

        /* Get and display the UDP header compression options */
        udp_flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_udp_checksum, tvb, offset, 1, udp_flags & LOWPAN_NHC_UDP_CHECKSUM);
        proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_udp_src, tvb, offset, 1, udp_flags & LOWPAN_NHC_UDP_SRCPORT);
        proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_udp_dst, tvb, offset, 1, udp_flags & LOWPAN_NHC_UDP_DSTPORT);
        offset += 1;

        /* Get and display the ports. */
        switch (udp_flags & (LOWPAN_NHC_UDP_SRCPORT | LOWPAN_NHC_UDP_DSTPORT)) {
            case (LOWPAN_NHC_UDP_SRCPORT | LOWPAN_NHC_UDP_DSTPORT):
                udp.src_port = LOWPAN_PORT_12BIT_OFFSET + (tvb_get_guint8(tvb, offset) >> 4);
                udp.dst_port = LOWPAN_PORT_12BIT_OFFSET + (tvb_get_guint8(tvb, offset) & 0x0f);
                src_bitlen = 4;
                dst_bitlen = 4;
                break;

            case LOWPAN_NHC_UDP_SRCPORT:
                udp.src_port = LOWPAN_PORT_8BIT_OFFSET + tvb_get_guint8(tvb, offset);
                udp.dst_port = tvb_get_ntohs(tvb, offset + 1);
                src_bitlen = 8;
                dst_bitlen = 16;
                break;

            case LOWPAN_NHC_UDP_DSTPORT:
                udp.src_port = tvb_get_ntohs(tvb, offset);
                udp.dst_port = LOWPAN_PORT_8BIT_OFFSET + tvb_get_guint8(tvb, offset + 2);
                src_bitlen = 16;
                dst_bitlen = 8;
                break;

            default:
                udp.src_port = tvb_get_ntohs(tvb, offset);
                udp.dst_port = tvb_get_ntohs(tvb, offset+2);
                src_bitlen = 16;
                dst_bitlen = 16;
                break;
        } /* switch */

        proto_tree_add_uint(tree, hf_6lowpan_udp_src, tvb, offset, BITS_TO_BYTE_LEN(offset<<3, src_bitlen), udp.src_port);
        proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset+(src_bitlen>>3), BITS_TO_BYTE_LEN((offset<<3)+src_bitlen, dst_bitlen), udp.dst_port);
        offset += ((src_bitlen + dst_bitlen)>>3);
        udp.src_port = g_ntohs(udp.src_port);
        udp.dst_port = g_ntohs(udp.dst_port);

        /* Get and display the checksum. */
        if (!(udp_flags & LOWPAN_NHC_UDP_CHECKSUM)) {
            /* Parse the checksum. */
            udp.checksum = tvb_get_ntohs(tvb, offset);
            proto_tree_add_checksum(tree, tvb, offset, hf_6lowpan_udp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
            offset += 2;
        }
        else {
            udp.checksum = 0;
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
         * If the datagram is incomplete, then leave the checksum at 0.
         */
#if 0
        /*
         * This has been disabled, since we might only be dissecting a fragment
         * of the packet, and thus we might not have the entire UDP payload at
         * this time.
         *
         * If we want to display the checksums, they will have to be recomputed
         * after packet reassembly. Lots of work for not much gain, since we can
         * just set the UDP checksum to 0 and Wireshark doesn't care.
         */
        if ((udp_flags & LOWPAN_NHC_UDP_CHECKSUM) && tvb_bytes_exist(tvb, offset, length)) {
            vec_t      cksum_vec[3];
            struct {
                struct e_in6_addr   src;
                struct e_in6_addr   dst;
                guint32             length;
                guint8              zero[3];
                guint8              proto;
            } cksum_phdr;

            /* Fill in the pseudo-header. */
            memcpy(&cksum_phdr.src, pinfo->src.data, sizeof(struct e_in6_addr));
            memcpy(&cksum_phdr.dst, pinfo->dst.data, sizeof(struct e_in6_addr));
            cksum_phdr.length = g_htonl(length + (int)sizeof(struct udp_hdr));
            memset(cksum_phdr.zero, 0, sizeof(cksum_phdr.zero));
            cksum_phdr.proto = IP_PROTO_UDP;

            /* Compute the checksum. */
            SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)&cksum_phdr, sizeof(cksum_phdr));
            SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)&udp, sizeof(struct udp_hdr));
            SET_CKSUM_VEC_TVB(cksum_vec[2], tvb, offset, length);
            udp.checksum = in_cksum(cksum_vec, 3);
            if (udp.checksum == 0) udp.checksum = 0xffff;
        }
#endif

        /* Create the next header structure for the UDP datagram. */
        length = (gint)tvb_ensure_captured_length_remaining(tvb, offset);
        nhdr = (struct lowpan_nhdr *)wmem_alloc(wmem_packet_scope(), sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
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
    guint8              seqnum;
    proto_tree *        bcast_tree;

    /* Create a tree for the broadcast header. */
    bcast_tree = proto_tree_add_subtree(tree, tvb, 0, 2, ett_6lowpan_bcast, NULL, "Broadcast Header");

    /* Get and display the pattern. */
    proto_tree_add_bits_item(bcast_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_BC0_BITS, ENC_BIG_ENDIAN);

    /* Get and display the sequence number. */
    seqnum = tvb_get_guint8(tvb, 1);
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
dissect_6lowpan_mesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 *siid, guint8 *diid)
{
    gint                offset = 0;
    guint8              mesh_header;
    proto_tree *        mesh_tree;
    proto_tree *        flag_tree;
    proto_item *        ti;

    ieee802154_hints_t  *hints;

    /* Create a tree for the mesh header. */
    mesh_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_6lowpan_mesh, &ti, "Mesh Header");

    /* Get and display the mesh flags. */
    mesh_header = tvb_get_guint8(tvb, offset);

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
        guint16         addr16 = tvb_get_ntohs(tvb, offset);
        guint8 *        ifcid;

        proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_orig16, tvb, offset, 2, addr16);
        ifcid = (guint8 *)wmem_alloc(pinfo->pool, 8);

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
        guint16         addr16 = tvb_get_ntohs(tvb, offset);
        guint8 *        ifcid;

        proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_dest16, tvb, offset, 2, addr16);

        ifcid = (guint8 *)wmem_alloc(pinfo->pool, 8);

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
dissect_6lowpan_frag_first(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint8 *siid, const guint8 *diid)
{
    gint                offset = 0;
    gint                frag_size;
    guint16             dgram_size;
    guint16             dgram_tag;
    proto_tree *        frag_tree;
    proto_item *        ti;
    proto_item *        length_item;
    /* Reassembly parameters. */
    tvbuff_t *          new_tvb;
    tvbuff_t *          frag_tvb;
    fragment_head *     frag_data;
    gboolean            save_fragmented;

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

    /* The first fragment can contain an uncompressed IPv6, HC1 or IPHC fragment.  */
    frag_tvb = tvb_new_subset_remaining(tvb, offset);
    if (tvb_get_bits8(frag_tvb, 0, LOWPAN_PATTERN_IPV6_BITS) == LOWPAN_PATTERN_IPV6) {
        frag_tvb = dissect_6lowpan_ipv6(frag_tvb, pinfo, tree);
    }
    else if (tvb_get_bits8(frag_tvb, 0, LOWPAN_PATTERN_HC1_BITS) == LOWPAN_PATTERN_HC1) {
        /* Check if the datagram size is sane. */
        if (dgram_size < IPv6_HDR_SIZE) {
            expert_add_info_format(pinfo, length_item, &ei_6lowpan_bad_ipv6_header_length,
                "Length is less than IPv6 header length %u", IPv6_HDR_SIZE);
        }
        frag_tvb = dissect_6lowpan_hc1(frag_tvb, pinfo, tree, dgram_size, siid, diid);
    }
    else if (tvb_get_bits8(frag_tvb, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
        /* Check if the datagram size is sane. */
        if (dgram_size < IPv6_HDR_SIZE) {
            expert_add_info_format(pinfo, length_item, &ei_6lowpan_bad_ipv6_header_length,
                "Length is less than IPv6 header length %u", IPv6_HDR_SIZE);
        }
        frag_tvb = dissect_6lowpan_iphc(frag_tvb, pinfo, tree, dgram_size, siid, diid);
    }
    /* Unknown 6LoWPAN dispatch type */
    else {
        dissect_6lowpan_unknown(frag_tvb, pinfo, tree);
        return NULL;
    }

    /* Check call to dissect_6lowpan_xxx was successful */
    if (frag_tvb == NULL) {
        return NULL;
    }

    /* Add this datagram to the fragment table. */
    frag_size = tvb_captured_length(frag_tvb);
    tvb_set_reported_length(frag_tvb, frag_size);
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    frag_data = fragment_add_check(&lowpan_reassembly_table,
                    frag_tvb, 0, pinfo, dgram_tag, NULL,
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
    gint                offset = 0;
    gint                frag_size;
    guint16             dgram_size;
    guint16             dgram_tag;
    guint16             dgram_offset = 0;
    proto_tree *        frag_tree;
    proto_item *        ti;
    /* Reassembly parameters. */
    tvbuff_t *          new_tvb;
    fragment_head *     frag_data;
    gboolean            save_fragmented;

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
    dgram_offset = tvb_get_guint8(tvb, offset) * 8;
    proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_offset, tvb, offset, 1, dgram_offset);
    offset += 1;

    /* Adjust the fragmentation header length. */
    frag_size = tvb_reported_length_remaining(tvb, offset);
    proto_item_set_end(ti, tvb, offset);

    /* Add this datagram to the fragment table. */
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    frag_data = fragment_add_check(&lowpan_reassembly_table,
                    tvb, offset, pinfo, dgram_tag, NULL,
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
        guint8 pattern = tvb_get_guint8(tvb, 0);
        proto_tree_add_uint_bits_format_value(tree, hf_6lowpan_pattern, tvb, 0, 8, pattern, "Unknown (0x%02x)", pattern);
    }

    /* Create a tvbuff subset for the remaining data. */
    data_tvb = tvb_new_subset_remaining(tvb, 1);
    call_data_dissector(data_tvb, pinfo, proto_tree_get_root(tree));
} /* dissect_6lowpan_unknown */

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
        { &hf_6lowpan_nhc_udp_src,
          { "Source port",                    "6lowpan.nhc.udp.src",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_UDP_SRCPORT, NULL, HFILL }},
        { &hf_6lowpan_nhc_udp_dst,
          { "Destination port",               "6lowpan.nhc.udp.dst",
            FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_UDP_DSTPORT, NULL, HFILL }},

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
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_6lowpan,
        &ett_6lowpan_hc1,
        &ett_6lowpan_hc1_encoding,
        &ett_6lowpan_hc2_udp,
        &ett_6lowpan_iphc,
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

    /* Register the dissector init function */
    register_init_routine(proto_init_6lowpan);
    register_cleanup_routine(proto_cleanup_6lowpan);

    /* Initialize the context preferences. */
    memset((gchar*)lowpan_context_prefs, 0, sizeof(lowpan_context_prefs));

    /* Register preferences. */
    prefs_module = prefs_register_protocol(proto_6lowpan, prefs_6lowpan_apply);

    prefs_register_bool_preference(prefs_module, "rfc4944_short_address_format",
                                   "Derive IID according to RFC 4944",
                                   "Derive IID from a short 16-bit address according to RFC 4944 (using the PAN ID).",
                                   &rfc4944_short_address_format);

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
    /* Initialize the fragment reassembly table. */
    reassembly_table_init(&lowpan_reassembly_table,
                          &addresses_reassembly_table_functions);

    /* Initialize the link-local context. */
    lowpan_context_local.frame = 0;
    lowpan_context_local.plen = LOWPAN_CONTEXT_LINK_LOCAL_BITS;
    memcpy(&lowpan_context_local.prefix, lowpan_llprefix, sizeof(lowpan_llprefix));

    /* Reload static contexts from our preferences. */
    prefs_6lowpan_apply();
} /* proto_init_6lowpan */

static void
proto_cleanup_6lowpan(void)
{
    reassembly_table_destroy(&lowpan_reassembly_table);
}

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
    struct e_in6_addr   prefix;
    gchar               *prefix_str;
    gchar               *prefix_len_str;
    guint32             prefix_len;
    gchar               prefix_buf[48]; /* max length of IPv6 str. plus a bit */

    for (i = 0; i < LOWPAN_CONTEXT_MAX; i++) {
        if (!lowpan_context_prefs[i]) continue;
        g_strlcpy(prefix_buf, lowpan_context_prefs[i], 48);
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

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_LE_IPSP, handle_6lowpan);
    dissector_add_for_decode_as("btl2cap.cid", handle_6lowpan);
} /* proto_reg_handoff_6lowpan */


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
