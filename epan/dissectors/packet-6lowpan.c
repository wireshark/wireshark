/* packet-6lowpan.c
 * Routines for 6LoWPAN packet disassembly
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Need to get headers for AF_INET6 and inet_pton() */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include "packet-ipv6.h"
#include "packet-ieee802154.h"

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
#define LOWPAN_IPHC_MCAST_48BIT         0x1
#define LOWPAN_IPHC_MCAST_32BIT         0x2
#define LOWPAN_IPHC_MCAST_8BIT          0x3

#define LOWPAN_IPHC_MCAST_STATEFUL_48BIT 0x1

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

/* Compressed port number offset. */
#define LOWPAN_PORT_8BIT_OFFSET         0xf000
#define LOWPAN_PORT_12BIT_OFFSET        (LOWPAN_PORT_8BIT_OFFSET | 0xb0)

/* 6LoWPAN interface identifier length. */
#define LOWPAN_IFC_ID_LEN               8
/* Protocol fields handles. */
static int proto_6lowpan = -1;
static int hf_6lowpan_pattern = -1;
static int hf_6lowpan_nhc_pattern = -1;

/* Header compression fields. */
static int hf_6lowpan_hc1_source_prefix = -1;
static int hf_6lowpan_hc1_source_ifc = -1;
static int hf_6lowpan_hc1_dest_prefix = -1;
static int hf_6lowpan_hc1_dest_ifc = -1;
static int hf_6lowpan_hc1_class = -1;
static int hf_6lowpan_hc1_next = -1;
static int hf_6lowpan_hc1_more = -1;
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

/* NHC IPv6 extension header fields. */
static int hf_6lowpan_nhc_ext_eid = -1;
static int hf_6lowpan_nhc_ext_nh = -1;
static int hf_6lowpan_nhc_ext_next = -1;
static int hf_6lowpan_nhc_ext_length = -1;

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
static gint ett_6lowpan_hc2_udp = -1;
static gint ett_6lowpan_iphc = -1;
static gint ett_6lowpan_nhc_ext = -1;
static gint ett_6lowpan_nhc_udp = -1;
static gint ett_6lowpan_bcast = -1;
static gint ett_6lowpan_mesh = -1;
static gint ett_6lowpan_mesh_flags = -1;
static gint ett_6lowpan_frag = -1;
static gint ett_6lopwan_traffic_class = -1;

/* Subdissector handles. */
static dissector_handle_t       data_handle;
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
static const value_string lowpan_iphc_mcast_modes [] = {
    { LOWPAN_IPHC_MCAST_48BIT,      "48-bits inline" },
    { LOWPAN_IPHC_MCAST_32BIT,      "32-bits inline" },
    { LOWPAN_IPHC_MCAST_8BIT,       "8-bits inline" },
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
    /* Tag */
    "6LoWPAN fragments"
};

static GHashTable *lowpan_fragment_table = NULL;
static GHashTable *lowpan_reassembled_table = NULL;

/* Link-Local prefix used by 6LoWPAN (FF80::) */
static const guint8 lowpan_llprefix[8] = {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* 6LoWPAN context table preferences. */
#define LOWPAN_CONTEXT_COUNT        16
#define LOWPAN_CONTEXT_DEFAULT      0
#define LOWPAN_CONTEXT_LINK_LOCAL   LOWPAN_CONTEXT_COUNT                    /* An internal context used for the link-local prefix. */
static struct e_in6_addr    lowpan_context_table[LOWPAN_CONTEXT_COUNT+1];   /* The 17-th context stores the link-local prefix. */
static gchar *              lowpan_context_prefs[LOWPAN_CONTEXT_COUNT];     /* Array of strings set by the preferences. */

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
static void         prefs_6lowpan_apply         (void);
static gboolean     dissect_6lowpan_heur        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void         dissect_6lowpan             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_ipv6        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_hc1         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, guint8 *siid, guint8 *diid);
static tvbuff_t *   dissect_6lowpan_bc0         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_iphc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, guint8 *siid, guint8 *diid);
static struct lowpan_nhdr *
                    dissect_6lowpan_iphc_nhc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint dgram_size, guint8 *siid, guint8 *diid);
static tvbuff_t *   dissect_6lowpan_mesh        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_frag_first  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 *siid, guint8 *diid);
static tvbuff_t *   dissect_6lowpan_frag_middle (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void         dissect_6lowpan_unknown     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Helper functions. */
static gboolean     lowpan_dlsrc_to_ifcid   (packet_info *pinfo, guint8 *ifcid);
static gboolean     lowpan_dldst_to_ifcid   (packet_info *pinfo, guint8 *ifcid);
static void         lowpan_addr16_to_ifcid  (guint16 addr, guint8 *ifcid);
static tvbuff_t *   lowpan_reassemble_ipv6  (tvbuff_t *tvb, struct ip6_hdr * ipv6, struct lowpan_nhdr * nhdr_list);
static guint8       lowpan_parse_nhc_proto  (tvbuff_t *tvb, gint offset);

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_addr16_to_ifcid
 *  DESCRIPTION
 *      Converts a short address to in interface identifier as
 *      per rfc 4944 section 6.
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
    ieee802154_packet * packet = (ieee802154_packet *)pinfo->private_data;

    /* Check the link-layer address field. */
    if (pinfo->dl_src.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_src.data, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return TRUE;
    }

    /* Derive the IID from the IEEE 802.15.4 packet structure. */
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64     addr;
        addr = pntoh64(&packet->src64);
        memcpy(ifcid, &addr, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return TRUE;
    }
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        lowpan_addr16_to_ifcid(packet->src16, ifcid);
        return TRUE;
    }

    /* Failed to find a link-layer source address. */
    return FALSE;
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
    ieee802154_packet * packet = (ieee802154_packet *)pinfo->private_data;

    /* Check the link-layer address field. */
    if (pinfo->dl_dst.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_dst.data, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return TRUE;
    }

    /* Derive the IID from the IEEE 802.15.4 packet structure. */
    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64     addr;
        addr = pntoh64(&packet->dst64);
        memcpy(ifcid, &addr, LOWPAN_IFC_ID_LEN);
        /* RFC2464: Invert the U/L bit when using an EUI64 address. */
        ifcid[0] ^= 0x02;
        return TRUE;
    }
    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        lowpan_addr16_to_ifcid(packet->dst16, ifcid);
        return TRUE;
    }

    /* Failed to find a link-layer source address. */
    return FALSE;
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
lowpan_reassemble_ipv6(tvbuff_t *tvb, struct ip6_hdr *ipv6, struct lowpan_nhdr *nhdr_list)
{
    gint                length = 0;
    gint                reported = 0;
    guint8 *            buffer;
    guint8 *            cursor;
    struct lowpan_nhdr *nhdr;
    tvbuff_t           *ret;

    /* Compute the real and reported lengths. */
    for (nhdr = nhdr_list; nhdr; nhdr = nhdr->next) {
        length += nhdr->length;
        reported += nhdr->reported;
    }
    ipv6->ip6_plen = g_ntohs(reported);

    /* Allocate a buffer for the packet and copy in the IPv6 header. */
    buffer = (guint8 *)g_malloc(length + sizeof(struct ip6_hdr));
    memcpy(buffer, ipv6, sizeof(struct ip6_hdr));
    cursor = buffer + sizeof(struct ip6_hdr);

    /* Add the next headers into the buffer. */
    for (nhdr = nhdr_list; nhdr; nhdr = nhdr->next) {
        memcpy(cursor, LOWPAN_NHDR_DATA(nhdr), nhdr->length);
        cursor += nhdr->length;
    };

    /* Return the reassembed packet. */
    ret = tvb_new_child_real_data(tvb, buffer, length + sizeof(struct ip6_hdr), reported + sizeof(struct ip6_hdr));
    tvb_set_free_cb(ret, g_free);
    return ret;
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
    if (!tvb_bytes_exist(tvb, offset, sizeof(guint8))) return IP_PROTO_NONE;

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
 *  RETURNS
 *      boolean         ; TRUE if the tvbuff was dissected as a
 *                          6LoWPAN packet. If this returns FALSE,
 *                          then no dissection will be attempted.
 *---------------------------------------------------------------
 */
static gboolean
dissect_6lowpan_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Check for valid patterns. */
    do {
        /* Parse patterns until we find a match. */
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_IPV6_BITS) == LOWPAN_PATTERN_IPV6) break;
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_HC1_BITS)  == LOWPAN_PATTERN_HC1) break;
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_BC0_BITS)  == LOWPAN_PATTERN_BC0) break;
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) break;
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_MESH_BITS) == LOWPAN_PATTERN_MESH) break;
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAG1) break;
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAGN) break;

        /* If we get here, then we couldn't match to any pattern. */
        return FALSE;
    } while(0);

    /* If we get here, then we found a matching pattern. */
    dissect_6lowpan(tvb, pinfo, tree);
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
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
dissect_6lowpan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *volatile    lowpan_tree = NULL;
    proto_item *volatile    lowpan_root = NULL;
    tvbuff_t *              next = tvb;
    /* Interface identifier of the encapsulating layer. */
    guint8                  src_iid[LOWPAN_IFC_ID_LEN];
    guint8                  dst_iid[LOWPAN_IFC_ID_LEN];

    /* Get the interface identifiers from the encapsulating layer. */
    lowpan_dlsrc_to_ifcid(pinfo, src_iid);
    lowpan_dldst_to_ifcid(pinfo, dst_iid);

    /* Create the protocol tree. */
    if (tree) {
        lowpan_root = proto_tree_add_protocol_format(tree, proto_6lowpan, tvb, 0, tvb_length(tvb), "6LoWPAN");
        lowpan_tree = proto_item_add_subtree(lowpan_root, ett_6lowpan);
    }
    /* Add the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "6LoWPAN");

    /* Mesh and Broadcast headers always come first in a 6LoWPAN frame. */
    if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_MESH_BITS) == LOWPAN_PATTERN_MESH) {
        next = dissect_6lowpan_mesh(next, pinfo, lowpan_tree);
        if (!next) return;
    }
    if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_BC0_BITS) == LOWPAN_PATTERN_BC0) {
        next = dissect_6lowpan_bc0(next, pinfo, lowpan_tree);
        if (!next) return;
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
        /* Add a new data source. */
        if (next) add_new_data_source(pinfo, next, "6LoWPAN");
    }
    else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
        next = dissect_6lowpan_iphc(next, pinfo, lowpan_tree, -1, src_iid, dst_iid);
        /* Add a new data source. */
        if (next) add_new_data_source(pinfo, next, "6LoWPAN");
    }
    /* Unknown 6LoWPAN dispatch type */
    else {
        dissect_6lowpan_unknown(next, pinfo, lowpan_tree);
        return;
    }

    /* The last step should have returned an uncompressed IPv6 datagram. */
    if (next) {
        call_dissector(ipv6_handle, next, pinfo, tree);
    }
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
    if (tree) {
        proto_tree_add_bits_item(tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_IPV6_BITS, ENC_BIG_ENDIAN);
    }

    /* Create a tvbuff subset for the ipv6 datagram. */
    return tvb_new_subset_remaining(tvb, sizeof(guint8));
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
dissect_6lowpan_hc1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, guint8 *siid, guint8 *diid)
{
    gint                offset = 0;
    gint                bit_offset;
    int                 i;
    guint8              hc1_encoding;
    guint8              hc_udp_encoding = 0;
    guint8              next_header;
    proto_tree *        hc_tree = NULL;
    proto_item *        ti;
    tvbuff_t *          ipv6_tvb;
    /* IPv6 header. */
    guint8              ipv6_class;
    struct ip6_hdr      ipv6;
    struct lowpan_nhdr *nhdr_list;

    /*=====================================================
     * Parse HC Encoding Flags
     *=====================================================
     */
    /* Create a tree for the HC1 Header. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint16), "HC1 Encoding");
        hc_tree = proto_item_add_subtree(ti, ett_6lowpan_hc1);

        /* Get and display the pattern. */
        proto_tree_add_bits_item(hc_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_HC1_BITS, ENC_BIG_ENDIAN);
    }
    offset += sizeof(guint8);

    /* Get and display the HC1 encoding bits. */
    hc1_encoding = tvb_get_guint8(tvb, offset);
    next_header = ((hc1_encoding & LOWPAN_HC1_NEXT) >> 1);
    if (tree) {
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_source_prefix, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_SOURCE_PREFIX);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_source_ifc, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_SOURCE_IFC);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_dest_prefix, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_DEST_PREFIX);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_dest_ifc, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_DEST_IFC);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_class, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_TRAFFIC_CLASS);
        proto_tree_add_uint(hc_tree, hf_6lowpan_hc1_next, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_NEXT);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_more, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_MORE);
    }
    offset += sizeof(guint8);

    /* Get and display the HC2 encoding bits, if present. */
    if (hc1_encoding & LOWPAN_HC1_MORE) {
        if (next_header == LOWPAN_HC1_NEXT_UDP) {
            hc_udp_encoding = tvb_get_guint8(tvb, offset);
            if (tree) {
                ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "HC_UDP Encoding");
                hc_tree = proto_item_add_subtree(ti, ett_6lowpan_hc2_udp);
                proto_tree_add_boolean(hc_tree, hf_6lowpan_hc2_udp_src, tvb, offset, sizeof(guint8), hc_udp_encoding & LOWPAN_HC2_UDP_SRCPORT);
                proto_tree_add_boolean(hc_tree, hf_6lowpan_hc2_udp_dst, tvb, offset, sizeof(guint8), hc_udp_encoding & LOWPAN_HC2_UDP_DSTPORT);
                proto_tree_add_boolean(hc_tree, hf_6lowpan_hc2_udp_len, tvb, offset, sizeof(guint8), hc_udp_encoding & LOWPAN_HC2_UDP_LENGTH);
            }
            offset += sizeof(guint8);
        }
        else {
            /* HC1 states there are more bits, but an illegal next header was defined. */
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "HC1 more bits expected for illegal next header type.");
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
    ipv6.ip6_hops = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS);
    if (tree) {
        proto_tree_add_uint(tree, hf_6lowpan_hop_limit, tvb, bit_offset>>3,
                BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS), ipv6.ip6_hops);
    }
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
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), (guint8 *)&ipv6.ip6_src);
    }
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
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), (guint8 *)&ipv6.ip6_dst);
    }
    /*
     * Do not set the address columns until after defragmentation, since we have
     * to do decompression before reassembly, and changing the address will cause
     * wireshark to think that the middle fragments came from another device.
     */

    /* Parse the traffic class and flow label. */
    ipv6_class = 0;
    ipv6.ip6_flow = 0;
    if (!(hc1_encoding & LOWPAN_HC1_TRAFFIC_CLASS)) {
        /* Parse the traffic class. */
        ipv6_class = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_TRAFFIC_CLASS_BITS);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_traffic_class, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_TRAFFIC_CLASS_BITS), ipv6_class);
        }
        bit_offset += LOWPAN_IPV6_TRAFFIC_CLASS_BITS;

        /* Parse the flow label. */
        ipv6.ip6_flow = tvb_get_bits32(tvb, bit_offset, LOWPAN_IPV6_FLOW_LABEL_BITS, ENC_BIG_ENDIAN);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_flow_label, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_FLOW_LABEL_BITS), ipv6.ip6_flow);
        }
        bit_offset += LOWPAN_IPV6_FLOW_LABEL_BITS;
    }
    ipv6.ip6_flow = g_ntohl(ipv6.ip6_flow | (ipv6_class << LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6_vfc = ((0x6 << 4) | (ipv6_class >> 4));

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
        if (tree) {
            proto_tree_add_uint_format(tree, hf_6lowpan_next_header, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_NEXT_HEADER_BITS), ipv6.ip6_nxt,
                    "Next header: %s (0x%02x)", ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);
        }
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
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_src, tvb, offset>>3,
                    BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), udp.src_port);
        }
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
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset>>3,
                    BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), udp.dst_port);
        }
        udp.dst_port = g_ntohs(udp.dst_port);

        /* Parse the length, if present. */
        if (!(hc_udp_encoding & LOWPAN_HC2_UDP_LENGTH)) {
            udp.length = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_LENGTH_BITS, ENC_BIG_ENDIAN);
            if (tree) {
                proto_tree_add_uint(tree, hf_6lowpan_udp_len, tvb, bit_offset>>3,
                        BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_LENGTH_BITS), udp.length);

            }
            bit_offset += LOWPAN_UDP_LENGTH_BITS;
        }
        /* Compute the length from the fragmentation headers. */
        else if (dgram_size >= 0) {
            if (dgram_size < (gint)sizeof(struct ip6_hdr)) {
                /* Datagram size is too small */
                return NULL;
            }
            udp.length = dgram_size - (gint)sizeof(struct ip6_hdr);
        }
        /* Compute the length from the tvbuff size. */
        else {
            udp.length = tvb_reported_length(tvb);
            udp.length -= BITS_TO_BYTE_LEN(0, bit_offset + LOWPAN_UDP_CHECKSUM_BITS);
            udp.length += sizeof(struct udp_hdr);
        }
        udp.length = g_ntohs(udp.length);

        /* Parse the checksum. */
        udp.checksum = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_CHECKSUM_BITS, ENC_BIG_ENDIAN);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_checksum, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_CHECKSUM_BITS), udp.checksum);
        }
        bit_offset += LOWPAN_UDP_CHECKSUM_BITS;
        udp.checksum = g_ntohs(udp.checksum);

        /* Construct the next header for the UDP datagram. */
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        length = (gint)tvb_ensure_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)ep_alloc(sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = IP_PROTO_UDP;
        nhdr_list->length = length + sizeof(struct udp_hdr);
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
        length = (gint)tvb_ensure_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)ep_alloc(sizeof(struct lowpan_nhdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6_nxt;
        nhdr_list->length = length;
        if (dgram_size < 0) {
            nhdr_list->reported = tvb_reported_length_remaining(tvb, offset);
        }
        else {
            nhdr_list->reported = dgram_size - sizeof(struct ip6_hdr);
        }
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr_list), offset, nhdr_list->length);
    }

    /* Link the reassembled tvbuff together.  */
    ipv6_tvb = lowpan_reassemble_ipv6(tvb, &ipv6, nhdr_list);
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
dissect_6lowpan_iphc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, guint8 *siid, guint8 *diid)
{
    gint                offset = 0;
    gint                length = 0;
    proto_tree *        iphc_tree = NULL;
    proto_item *        ti = NULL;
    proto_item *        ti_dam = NULL;
    /* IPHC header fields. */
    guint16             iphc_flags;
    guint8              iphc_traffic;
    guint8              iphc_hop_limit;
    guint8              iphc_src_mode;
    guint8              iphc_dst_mode;
    guint8              iphc_ctx = 0;
    /* Default contexts to use for address decompression. */
    gint                iphc_sci = LOWPAN_CONTEXT_DEFAULT;
    gint                iphc_dci = LOWPAN_CONTEXT_DEFAULT;
    /* IPv6 header */
    guint8              ipv6_class = 0;
    struct ip6_hdr      ipv6;
    tvbuff_t *          ipv6_tvb;
    /* Next header chain */
    struct lowpan_nhdr *nhdr_list;

    /* Create a tree for the IPHC header. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint16), "IPHC Header");
        iphc_tree = proto_item_add_subtree(ti, ett_6lowpan_iphc);

        /* Display the pattern. */
        proto_tree_add_bits_item(iphc_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_IPHC_BITS, ENC_BIG_ENDIAN);
    }

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
        const value_string *dam_vs;
        proto_tree_add_uint         (iphc_tree, hf_6lowpan_iphc_flag_tf,    tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_FLOW);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_nhdr,  tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_NHDR);
        proto_tree_add_uint         (iphc_tree, hf_6lowpan_iphc_flag_hlim,  tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_HLIM);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_cid,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_CONTEXT_ID);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_sac,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP);
        proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_flag_sam,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_SRC_MODE);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_mcast, tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_dac,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP);
        /* Destination address mode changes meanings depending on multicast compression. */
        dam_vs = (iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP) ? (lowpan_iphc_mcast_modes) : (lowpan_iphc_addr_modes);
        ti_dam = proto_tree_add_uint_format_value(iphc_tree, hf_6lowpan_iphc_flag_dam, tvb, offset, sizeof(guint16),
            iphc_flags & LOWPAN_IPHC_FLAG_DST_MODE, "%s (0x%04x)", val_to_str(iphc_dst_mode, dam_vs, "Reserved"), iphc_dst_mode);
    }
    offset += sizeof(guint16);

    /* Display the context identifier extension, if present. */
    if (iphc_flags & LOWPAN_IPHC_FLAG_CONTEXT_ID) {
        iphc_ctx = tvb_get_guint8(tvb, offset);
        iphc_sci = (iphc_ctx & LOWPAN_IPHC_FLAG_SCI) >> LOWPAN_IPHC_FLAG_OFFSET_SCI;
        iphc_dci = (iphc_ctx & LOWPAN_IPHC_FLAG_DCI) >> LOWPAN_IPHC_FLAG_OFFSET_DCI;
        if (tree) {
            proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_sci, tvb, offset, sizeof(guint8), iphc_ctx & LOWPAN_IPHC_FLAG_SCI);
            proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_dci, tvb, offset, sizeof(guint8), iphc_ctx & LOWPAN_IPHC_FLAG_DCI);
        }
        offset +=  sizeof(guint8);
    }
    /* Use link-local contexts if stateless. */
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP)) {
        iphc_sci = LOWPAN_CONTEXT_LINK_LOCAL;
    }
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP)) {
        iphc_dci = LOWPAN_CONTEXT_LINK_LOCAL;
    }

    /*=====================================================
     * Parse Traffic Class and Flow Label
     *=====================================================
     */
    offset <<= 3;
    /* Parse the ECN field. */
    if (iphc_traffic != LOWPAN_IPHC_FLOW_COMPRESSED) {
        ipv6_class |= tvb_get_bits8(tvb, offset, LOWPAN_IPHC_ECN_BITS);
        offset += LOWPAN_IPHC_ECN_BITS;
    }
    /* Parse the DSCP field. */
    if ((iphc_traffic == LOWPAN_IPHC_FLOW_CLASS_LABEL) || (iphc_traffic == LOWPAN_IPHC_FLOW_CLASS)) {
        ipv6_class |= (tvb_get_bits8(tvb, offset, LOWPAN_IPHC_DSCP_BITS) << LOWPAN_IPHC_ECN_BITS);
        offset += LOWPAN_IPHC_DSCP_BITS;
    }
    /* Display the traffic class field only if included inline. */
    if ((tree) && (iphc_traffic != LOWPAN_IPHC_FLOW_COMPRESSED)) {
        /* Create a tree for the traffic class. */
        proto_tree *    tf_tree;
        ti = proto_tree_add_uint(tree, hf_6lowpan_traffic_class, tvb, offset>>3, sizeof(guint8), ipv6_class);
        tf_tree = proto_item_add_subtree(ti, ett_6lopwan_traffic_class);

        /* Add the ECN and DSCP fields. */
        proto_tree_add_uint(tf_tree, hf_6lowpan_ecn, tvb, offset>>3, sizeof(guint8), ipv6_class & LOWPAN_IPHC_TRAFFIC_ECN);
        proto_tree_add_uint(tf_tree, hf_6lowpan_dscp, tvb, offset>>3, sizeof(guint8), ipv6_class & LOWPAN_IPHC_TRAFFIC_DSCP);
    }

    /* Parse and display the traffic label. */
    if ((iphc_traffic == LOWPAN_IPHC_FLOW_CLASS_LABEL) || (iphc_traffic == LOWPAN_IPHC_FLOW_ECN_LABEL)) {
        /* Pad to 4-bits past the start of the byte. */
        offset += ((4 - offset) & 0x7);
        ipv6.ip6_flow = tvb_get_bits32(tvb, offset, LOWPAN_IPHC_LABEL_BITS, ENC_BIG_ENDIAN);
        if (tree) {
            proto_tree_add_bits_item(tree, hf_6lowpan_flow_label, tvb, offset, LOWPAN_IPHC_LABEL_BITS, ENC_BIG_ENDIAN);
        }
        offset += LOWPAN_IPHC_LABEL_BITS;
    }
    else ipv6.ip6_flow = 0;

    /* Rebuild the IPv6 flow label and traffic class fields. */
    ipv6.ip6_flow = g_ntohl(ipv6.ip6_flow) | (ipv6_class << LOWPAN_IPV6_FLOW_LABEL_BITS);
    ipv6.ip6_vfc = (0x6 << 4) | (ipv6_class >> 4);

    /* Convert back to byte offsets. */
    offset >>= 3;

    /*=====================================================
     * Parse Next Header and Hop Limit
     *=====================================================
     */
    /* Get the next header field, if present. */
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_NHDR)) {
        ipv6.ip6_nxt = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint_format(tree, hf_6lowpan_next_header, tvb, offset, sizeof(guint8), ipv6.ip6_nxt,
                    "Next header: %s (0x%02x)", ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);
        }
        offset += sizeof(guint8);
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
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_hop_limit, tvb, offset, sizeof(guint8), ipv6.ip6_hlim);
        }
        offset += sizeof(guint8);
    }

    /*=====================================================
     * Parse and decompress the source address.
     *=====================================================
     */
    /* Copy the address from the context table. */
    memcpy(&ipv6.ip6_src, &lowpan_context_table[iphc_sci], sizeof(ipv6.ip6_src));
    /* (SAC=1 && SAM=00) -> the unspecified address (::). */
    if ((iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP) && (iphc_src_mode == LOWPAN_IPHC_ADDR_SRC_UNSPEC)) {
        length = 0;
        memset(&ipv6.ip6_src, 0, sizeof(ipv6.ip6_src));
    }
    /* The IID is derived from the encapsulating layer. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_COMPRESSED) {
        length = 0;
        memcpy(&ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - LOWPAN_IFC_ID_LEN], siid, LOWPAN_IFC_ID_LEN);
    }
    /* Full Address inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
        length = sizeof(ipv6.ip6_src);
    }
    /* 64-bits inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
        length = sizeof(guint64);
    }
    /* 16-bits inline. */
    else if (iphc_src_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
        length = sizeof(guint16);
        /* Format becomes ff:fe00:xxxx */
        ipv6.ip6_src.bytes[11] = 0xff;
        ipv6.ip6_src.bytes[12] = 0xfe;

    }
    if (length) {
        tvb_memcpy(tvb, &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - length], offset, length);
    }
    /* Update the IID of the encapsulating layer. */
    siid = &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - LOWPAN_IFC_ID_LEN];

    /* Display the source IPv6 address. */
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset, length, (guint8 *)&ipv6.ip6_src);
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
    /* Stateless multicast compression. */
    if ((iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP) && !(iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP)) {
        length = 0;
        memset(&ipv6.ip6_dst, 0, sizeof(ipv6.ip6_dst));
        if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            length = sizeof(ipv6.ip6_dst);
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
            expert_add_info_format(pinfo, ti_dam, PI_MALFORMED, PI_ERROR, "Illegal destination address mode");
            return NULL;
        }
    }
    /* Stateful multicast compression. */
    else if ((iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP) && (iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP)) {
        length = 0;
        memset(&ipv6.ip6_dst, 0, sizeof(ipv6.ip6_dst));
        if (iphc_dst_mode == LOWPAN_IPHC_MCAST_STATEFUL_48BIT) {
            /* RFC 3306 unicast-prefix based multicast address. */
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[2] = tvb_get_guint8(tvb, offset + (length++));
            /* TODO: Recover the stuff derived from context. */
            ipv6.ip6_dst.bytes[12] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[13] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[14] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
        else {
            /* Illegal destination address compression mode. */
            expert_add_info_format(pinfo, ti_dam, PI_MALFORMED, PI_ERROR, "Illegal destination address mode");
            return NULL;
        }
    }

    /*=====================================================
     * Parse and decompress a unicast destination address.
     *=====================================================
     */
    else {
        /* Copy the address from the context table. */
        length = 0;
        memcpy(&ipv6.ip6_dst, &lowpan_context_table[iphc_dci], sizeof(ipv6.ip6_dst));
        /* (DAC=1 && DAM=00) -> reserved value. */
        if ((iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP) && (iphc_dst_mode == 0)) {
            /* Illegal destination address compression mode. */
            expert_add_info_format(pinfo, ti_dam, PI_MALFORMED, PI_ERROR, "Illegal destination address mode");
            return NULL;
        }
        /* The IID is derived from the link-layer source. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_COMPRESSED) {
            length = 0;
            memcpy(&ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - LOWPAN_IFC_ID_LEN], diid, LOWPAN_IFC_ID_LEN);
        }
        /* Full Address inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            length = sizeof(ipv6.ip6_dst);
        }
        /* 64-bits inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
            length = sizeof(guint64);
        }
        /* 16-bits inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
            length = sizeof(guint16);
            /* Format becomes ff:fe00:xxxx */
            ipv6.ip6_dst.bytes[11] = 0xff;
            ipv6.ip6_dst.bytes[12] = 0xfe;
        }
        if (length) {
            tvb_memcpy(tvb, &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - length], offset, length);
        }
        /* Update the interface id of the encapsulating layer. */
        diid = &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - LOWPAN_IFC_ID_LEN];
    }

    /* Display the destination IPv6 address. */
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset, length, (guint8 *)&ipv6.ip6_dst);
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
        nhdr_list = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset, dgram_size - sizeof(struct ip6_hdr), siid, diid);
    }
    /* Create an extension header for the remaining payload. */
    else {
        length = (gint)tvb_ensure_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)ep_alloc(sizeof(struct lowpan_nhdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6_nxt;
        nhdr_list->length = length;
        if (dgram_size < 0) {
            nhdr_list->reported = tvb_reported_length_remaining(tvb, offset);
        }
        else {
            nhdr_list->reported = dgram_size - sizeof(struct ip6_hdr);
        }
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr_list), offset, nhdr_list->length);
    }

    /*=====================================================
     * Rebuild the IPv6 packet.
     *=====================================================
     */
    /* Reassemble the IPv6 packet. */
    ipv6_tvb = lowpan_reassemble_ipv6(tvb, &ipv6, nhdr_list);
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
 *      lowpan_nhdr *   ; List of ep_alloc'd next header structures.
 *---------------------------------------------------------------
 */
static struct lowpan_nhdr *
dissect_6lowpan_iphc_nhc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint dgram_size, guint8 *siid, guint8 *diid)
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
        if (tree) {
            ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint16), "IPv6 extension header");
            nhc_tree = proto_item_add_subtree(ti, ett_6lowpan_nhc_ext);
            /* Display the NHC-UDP pattern. */
            proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS, ENC_BIG_ENDIAN);
        }

        /* Get and display the extension header compression flags. */
        ext_flags = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_eid, tvb, offset, sizeof(guint8), ext_flags & LOWPAN_NHC_EXT_EID);
            proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_ext_nh, tvb, offset, sizeof(guint8), ext_flags & LOWPAN_NHC_EXT_NHDR);
            if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
                /* TODO: Flag a warning, the NH bit MUST be 0 when EID==0x7 (IP-in-IP). */
            }
        }
        offset += sizeof(guint8);

        /* Decode the remainder of the packet using IPHC encoding. */
        iphc_tvb = dissect_6lowpan_iphc(tvb_new_subset_remaining(tvb, offset), pinfo, tree, dgram_size, siid, diid);
        if (!iphc_tvb) return NULL;

        /* Create the next header structure for the tunneled IPv6 header. */
        nhdr = (struct lowpan_nhdr *)ep_alloc0(sizeof(struct lowpan_nhdr) + tvb_length(iphc_tvb));
        nhdr->next = NULL;
        nhdr->proto = IP_PROTO_IPV6;
        nhdr->length = tvb_length(iphc_tvb);
        nhdr->reported = tvb_reported_length(iphc_tvb);
        tvb_memcpy(iphc_tvb, LOWPAN_NHDR_DATA(nhdr), 0, nhdr->length);
        return nhdr;
    }
    /*=====================================================
     * IPv6 Extension Header
     *=====================================================
     */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS) == LOWPAN_NHC_PATTERN_EXT) {
        struct ip6_ext  ipv6_ext;
        guint8          ext_flags;
        guint8          ext_len;
        guint8          ext_proto;

        /* Parse the IPv6 extension header protocol. */
        ext_proto = lowpan_parse_nhc_proto(tvb, offset);

        /* Create a tree for the IPv6 extension header. */
        if (tree) {
            ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint16), "IPv6 extension header");
            nhc_tree = proto_item_add_subtree(ti, ett_6lowpan_nhc_ext);
            /* Display the NHC-UDP pattern. */
            proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS, ENC_BIG_ENDIAN);
        }

        /* Get and display the extension header compression flags. */
        ext_flags = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_eid, tvb, offset, sizeof(guint8), ext_flags & LOWPAN_NHC_EXT_EID);
            proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_ext_nh, tvb, offset, sizeof(guint8), ext_flags & LOWPAN_NHC_EXT_NHDR);
        }
        offset += sizeof(guint8);

        /* Get and display the next header field, if present. */
        if (!(ext_flags & LOWPAN_NHC_EXT_NHDR)) {
            ipv6_ext.ip6e_nxt = tvb_get_guint8(tvb, offset);
            if (tree) {
                proto_tree_add_uint_format(nhc_tree, hf_6lowpan_nhc_ext_next, tvb, offset, sizeof(guint8), ipv6_ext.ip6e_nxt,
                            "Next header: %s (0x%02x)", ipprotostr(ipv6_ext.ip6e_nxt), ipv6_ext.ip6e_nxt);
                proto_item_set_end(ti, tvb, offset+sizeof(guint8));
            }
            offset += sizeof(guint8);
        }

        /* Get and display the extension header length. */
        ext_len = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(nhc_tree, hf_6lowpan_nhc_ext_length, tvb, offset, sizeof(guint8), ext_len);
        }
        offset += sizeof(guint8);

        /* Compute the length of the extension header padded to an 8-byte alignment. */
        length = sizeof(struct ip6_ext) + ext_len;
        length = (length + 7) & ~0x7;

        /* Create the next header structure for the IPv6 extension header. */
        nhdr = (struct lowpan_nhdr *)ep_alloc0(sizeof(struct lowpan_nhdr) + length);
        nhdr->next = NULL;
        nhdr->proto = ext_proto;
        nhdr->length = length;
        nhdr->reported = length;

        /* Add the IPv6 extension header to the buffer. */
        if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
            ipv6_ext.ip6e_nxt = lowpan_parse_nhc_proto(tvb, offset+ext_len);
        }
        ipv6_ext.ip6e_len = nhdr->reported>>3;  /* Convert to units of 8 bytes. */
        ipv6_ext.ip6e_len -= 1;                 /* Don't include the first 8 bytes. */
        memcpy(LOWPAN_NHDR_DATA(nhdr), &ipv6_ext, sizeof(struct ip6_ext));

        /*
         * If the extension header was truncated, display the remainder using
         * the data dissector, and end NHC dissection here.
         */
        if (!tvb_bytes_exist(tvb, offset, ext_len)) {
            /* Call the data dissector for the remainder. */
            call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo, nhc_tree);

            /* Copy the remainder, and truncate the real buffer length. */
            nhdr->length = tvb_length_remaining(tvb, offset) + sizeof(struct ip6_ext);
            tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr) + sizeof(struct ip6_ext), offset, tvb_length_remaining(tvb, offset));

            /* There is nothing more we can do. */
            return nhdr;
        }

        /* Display the extension header using the data dissector. */
        call_dissector(data_handle, tvb_new_subset(tvb, offset, ext_len, ext_len), pinfo, nhc_tree);

        /* Copy the extension header into the struct. */
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr) + sizeof(struct ip6_ext), offset, ext_len);
        offset += ext_len;

        if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
            /*
             * There are more LOWPAN_NHC structures to parse. Call ourself again
             * recursively to parse them and build the linked list.
             */
            nhdr->next = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset, dgram_size - ext_len - sizeof(struct ip6_ext), siid, diid);
        }
        else {
            /* Create another next header structure for the remaining payload. */
            length = (gint)tvb_ensure_length_remaining(tvb, offset);
            nhdr->next = (struct lowpan_nhdr *)ep_alloc(sizeof(struct lowpan_nhdr) + length);
            nhdr->next->next = NULL;
            nhdr->next->proto = ipv6_ext.ip6e_nxt;
            nhdr->next->length = length;
            if (dgram_size < 0) {
                nhdr->next->reported = tvb_reported_length_remaining(tvb, offset);
            }
            else {
                nhdr->next->reported = dgram_size - ext_len - sizeof(struct ip6_ext);
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
        if (tree) {
            ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint8), "UDP header compression");
            nhc_tree = proto_item_add_subtree(ti, ett_6lowpan_nhc_udp);
            /* Display the NHC-UDP pattern. */
            proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_UDP_BITS, ENC_BIG_ENDIAN);
        }

        /* Get and display the UDP header compression options */
        udp_flags = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_udp_checksum, tvb, offset, sizeof(guint8), udp_flags & LOWPAN_NHC_UDP_CHECKSUM);
            proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_udp_src, tvb, offset, sizeof(guint8), udp_flags & LOWPAN_NHC_UDP_SRCPORT);
            proto_tree_add_boolean(nhc_tree, hf_6lowpan_nhc_udp_dst, tvb, offset, sizeof(guint8), udp_flags & LOWPAN_NHC_UDP_DSTPORT);
        }
        offset += sizeof(guint8);

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
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_src, tvb, offset, BITS_TO_BYTE_LEN(offset<<3, src_bitlen), udp.src_port);
            proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset+(src_bitlen>>3), BITS_TO_BYTE_LEN((offset<<3)+src_bitlen, dst_bitlen), udp.dst_port);
        }
        offset += ((src_bitlen + dst_bitlen)>>3);
        udp.src_port = g_ntohs(udp.src_port);
        udp.dst_port = g_ntohs(udp.dst_port);

        /* Get and display the checksum. */
        if (!(udp_flags & LOWPAN_NHC_UDP_CHECKSUM)) {
            /* Parse the checksum. */
            udp.checksum = tvb_get_ntohs(tvb, offset);
            if (tree) {
                proto_tree_add_uint(tree, hf_6lowpan_udp_checksum, tvb, offset, sizeof(guint16), udp.checksum);
            }
            offset += sizeof(guint16);
            udp.checksum = g_ntohs(udp.checksum);
        }
        else {
            udp.checksum = 0;
        }

        /* Compute the datagram length. */
        if (dgram_size < 0) {
            length = tvb_reported_length_remaining(tvb, offset);
            udp.length = g_htons(length + sizeof(struct udp_hdr));
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
         * If the datagram is incomplete, then leave the checsum at 0.
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
            cksum_phdr.length = g_htonl(length + sizeof(struct udp_hdr));
            memset(cksum_phdr.zero, 0, sizeof(cksum_phdr.zero));
            cksum_phdr.proto = IP_PROTO_UDP;

            /* Compute the checksum. */
            cksum_vec[0].ptr = (const guint8 *)&cksum_phdr;
            cksum_vec[0].len = sizeof(cksum_phdr);
            cksum_vec[1].ptr = (const guint8 *)&udp;
            cksum_vec[1].len = sizeof(struct udp_hdr);
            cksum_vec[2].ptr = tvb_get_ptr(tvb, offset, length);
            cksum_vec[2].len = length;
            udp.checksum = in_cksum(cksum_vec, 3);
            if (udp.checksum == 0) udp.checksum = 0xffff;
        }
#endif

        /* Create the next header structure for the UDP datagram. */
        length = (gint)tvb_ensure_length_remaining(tvb, offset);
        nhdr = (struct lowpan_nhdr *)ep_alloc(sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
        nhdr->next = NULL;
        nhdr->proto = IP_PROTO_UDP;
        nhdr->length = length + sizeof(struct udp_hdr);
        nhdr->reported = g_ntohs(udp.length);

        /* Copy the UDP header and payload into the buffer. */
        memcpy(LOWPAN_NHDR_DATA(nhdr), &udp, sizeof(struct udp_hdr));
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr) + sizeof(struct udp_hdr), offset, tvb_length_remaining(tvb, offset));
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
    proto_item *        ti;

    /* Create a tree for the broadcast header. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint16), "Broadcast Header");
        bcast_tree = proto_item_add_subtree(ti, ett_6lowpan_bcast);

        /* Get and display the pattern. */
        proto_tree_add_bits_item(bcast_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_BC0_BITS, ENC_BIG_ENDIAN);

        /* Get and display the sequence number. */
        seqnum = tvb_get_guint8(tvb, sizeof(guint8));
        proto_tree_add_uint(bcast_tree, hf_6lowpan_bcast_seqnum, tvb, sizeof(guint8), sizeof(guint8), seqnum);
    }

    /* Return the remaining buffer. */
    return tvb_new_subset_remaining(tvb, sizeof(guint16));
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
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_mesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint                offset = 0;
    guint8              mesh_header;
    proto_tree *        mesh_tree = NULL;
    proto_item *        ti = NULL;
    const guint8 *      src_ifcid;
    const guint8 *      dst_ifcid;

    /* Create a tree for the mesh header. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, 0, "Mesh Header");
        mesh_tree = proto_item_add_subtree(ti, ett_6lowpan_mesh);
    }

    /* Get and display the mesh flags. */
    mesh_header = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_item *    flag_item;
        proto_tree *    flag_tree;

        /*  Create the mesh header subtree. */
        flag_item = proto_tree_add_text(mesh_tree, tvb, offset, sizeof(guint8), "Flags");
        flag_tree = proto_item_add_subtree(flag_item, ett_6lowpan_mesh);

        /* Add the mesh header fields. */
        proto_tree_add_bits_item(flag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_MESH_BITS, ENC_BIG_ENDIAN);
        proto_tree_add_boolean(flag_tree, hf_6lowpan_mesh_v, tvb, offset, sizeof(guint8), mesh_header & LOWPAN_MESH_HEADER_V);
        proto_tree_add_boolean(flag_tree, hf_6lowpan_mesh_f, tvb, offset, sizeof(guint8), mesh_header & LOWPAN_MESH_HEADER_F);
        if ((mesh_header & LOWPAN_MESH_HEADER_HOPS)==15)
        {
          guint8 HopsLeft;
          proto_tree_add_uint(flag_tree, hf_6lowpan_mesh_hops, tvb, offset, sizeof(guint8), mesh_header & LOWPAN_MESH_HEADER_HOPS);
          offset += sizeof(guint8);
          HopsLeft=tvb_get_guint8(tvb, offset);
          proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_hops8, tvb, offset, sizeof(guint8), HopsLeft);
        }
        else
          proto_tree_add_uint(flag_tree, hf_6lowpan_mesh_hops, tvb, offset, sizeof(guint8), mesh_header & LOWPAN_MESH_HEADER_HOPS);
    }
    offset += sizeof(guint8);

    /* Get and display the originator address. */
    if (!(mesh_header & LOWPAN_MESH_HEADER_V)) {
        guint64         addr64 = tvb_get_ntoh64(tvb, offset);
        if (tree) {
            proto_tree_add_uint64(mesh_tree, hf_6lowpan_mesh_orig64, tvb, offset, sizeof(guint64), addr64);
        }
        src_ifcid = tvb_get_ptr(tvb, offset, sizeof(guint64));
        offset += sizeof(guint64);
    }
    else {
        guint16         addr16 = tvb_get_ntohs(tvb, offset);
        guint8 *        ifcid;
        if (tree) {
            proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_orig16, tvb, offset, sizeof(guint16), addr16);
        }
        ifcid = (guint8 *)ep_alloc(sizeof(guint64));
        lowpan_addr16_to_ifcid(addr16, ifcid);
        src_ifcid = ifcid;
        offset += sizeof(guint16);
    }
    SET_ADDRESS(&pinfo->src,  AT_EUI64, sizeof(guint64), src_ifcid);
    SET_ADDRESS(&pinfo->net_src,  AT_EUI64, sizeof(guint64), src_ifcid);

    /* Get and display the destination address. */
    if (!(mesh_header & LOWPAN_MESH_HEADER_F)) {
        guint64         addr64 = tvb_get_ntoh64(tvb, offset);
        if (tree) {
            proto_tree_add_uint64(mesh_tree, hf_6lowpan_mesh_dest64, tvb, offset, sizeof(guint64), addr64);
        }
        dst_ifcid = tvb_get_ptr(tvb, offset, sizeof(guint64));
        offset += sizeof(guint64);
    }
    else  {
        guint16         addr16 = tvb_get_ntohs(tvb, offset);
        guint8 *        ifcid;
        if (tree) {
            proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_dest16, tvb, offset, sizeof(guint16), addr16);
        }
        ifcid = (guint8 *)ep_alloc(sizeof(guint64));
        lowpan_addr16_to_ifcid(addr16, ifcid);
        dst_ifcid = ifcid;
        offset += sizeof(guint16);
    }
    SET_ADDRESS(&pinfo->dst,  AT_EUI64, sizeof(guint64), dst_ifcid);
    SET_ADDRESS(&pinfo->net_dst,  AT_EUI64, sizeof(guint64), dst_ifcid);

    /* Adjust the mesh header length. */
    if (tree) {
        proto_item_set_end(ti, tvb, offset);
    }

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
dissect_6lowpan_frag_first(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 *siid, guint8 *diid)
{
    gint                offset = 0;
    gint                frag_size;
    guint16             dgram_size;
    guint16             dgram_tag;
    proto_tree *        frag_tree = NULL;
    proto_item *        ti = NULL;
    proto_item *        length_item = NULL;
    /* Reassembly parameters. */
    tvbuff_t *          new_tvb = NULL;
    tvbuff_t *          frag_tvb = NULL;
    fragment_data *     frag_data = NULL;
    gboolean            save_fragmented;

    /* Create a tree for the fragmentation header. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, 0, "Fragmentation Header");
        frag_tree = proto_item_add_subtree(ti, ett_6lowpan_frag);
    }

    /* Get and display the pattern and datagram size. */
    dgram_size = tvb_get_bits16(tvb, (offset * 8) + LOWPAN_PATTERN_FRAG_BITS, LOWPAN_FRAG_DGRAM_SIZE_BITS, ENC_BIG_ENDIAN);
    if (tree) {
        proto_tree_add_bits_item(frag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_FRAG_BITS, ENC_BIG_ENDIAN);
        length_item = proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_size, tvb, offset, sizeof(guint16), dgram_size);
    }
    offset += sizeof(guint16);

    /* Get and display the datagram tag. */
    dgram_tag = tvb_get_ntohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_tag, tvb, offset, sizeof(guint16), dgram_tag);
    }
    offset += sizeof(guint16);

    /* Adjust the fragmentation header length. */
    if (tree) {
        proto_item_set_end(ti, tvb, offset);
    }

    /* The first fragment can contain an uncompressed IPv6, HC1 or IPHC fragment.  */
    frag_tvb = tvb_new_subset_remaining(tvb, offset);
    if (tvb_get_bits8(frag_tvb, 0, LOWPAN_PATTERN_IPV6_BITS) == LOWPAN_PATTERN_IPV6) {
        frag_tvb = dissect_6lowpan_ipv6(frag_tvb, pinfo, tree);
    }
    else if (tvb_get_bits8(frag_tvb, 0, LOWPAN_PATTERN_HC1_BITS) == LOWPAN_PATTERN_HC1) {
        /* Check if the datagram size is sane. */
        if (dgram_size < (gint)sizeof(struct ip6_hdr)) {
            expert_add_info_format(pinfo, length_item, PI_MALFORMED,
                PI_ERROR, "Length is less than IPv6 header length %u",
                (guint)sizeof(struct ip6_hdr));
        }
        frag_tvb = dissect_6lowpan_hc1(frag_tvb, pinfo, tree, dgram_size, siid, diid);
    }
    else if (tvb_get_bits8(frag_tvb, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
        /* Check if the datagram size is sane. */
        if (dgram_size < (gint)sizeof(struct ip6_hdr)) {
            expert_add_info_format(pinfo, length_item, PI_MALFORMED,
                PI_ERROR, "Length is less than IPv6 header length %u",
                (guint)sizeof(struct ip6_hdr));
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
    frag_size = tvb_length(frag_tvb);
    tvb_set_reported_length(frag_tvb, frag_size);
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    frag_data = fragment_add_check(frag_tvb, 0, pinfo, dgram_tag,
                    lowpan_fragment_table, lowpan_reassembled_table,
                    0, frag_size, (frag_size < dgram_size));

    /* Attempt reassembly. */
    new_tvb = process_reassembled_data(frag_tvb, 0, pinfo,
                    "6LowPAN", frag_data, &lowpan_frag_items,
                    NULL, tree);

    pinfo->fragmented = save_fragmented;

    /* If reassembly was successful, then return the completed datagram. */
    if (new_tvb) {
        return new_tvb;
    }
    /* If reassembly failed, display the payload fragment using the data dissector. */
    else {
        /*
         * BUG?: We could actually continue dissecting, since frag_tvb should contain
         * a truncated IPv6 packet, and we know the reported length from dgram_size.
         *
         * But this seems to cause problems with the TCP dissector if we resubmit the
         * datagram for reassembly again once we have the entire IPv6 packet.
         */
        call_dissector(data_handle, frag_tvb, pinfo, proto_tree_get_root(tree));
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
    proto_tree *        frag_tree = NULL;
    proto_item *        ti = NULL;
    /* Reassembly parameters. */
    tvbuff_t *          new_tvb = NULL;
    fragment_data *     frag_data = NULL;
    gboolean            save_fragmented;

    /* Create a tree for the fragmentation header. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, 0, "Fragmentation Header");
        frag_tree = proto_item_add_subtree(ti, ett_6lowpan_frag);
    }

    /* Get and display the pattern and datagram size. */
    dgram_size = tvb_get_bits16(tvb, (offset * 8) + LOWPAN_PATTERN_FRAG_BITS, LOWPAN_FRAG_DGRAM_SIZE_BITS, ENC_BIG_ENDIAN);
    if (tree) {
        proto_tree_add_bits_item(frag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_FRAG_BITS, ENC_BIG_ENDIAN);
        proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_size, tvb, offset, sizeof(guint16), dgram_size);
    }
    offset += sizeof(guint16);

    /* Get and display the datagram tag. */
    dgram_tag = tvb_get_ntohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_tag, tvb, offset, sizeof(guint16), dgram_tag);
    }
    offset += sizeof(guint16);

    /* Get and display the datagram offset. */
    dgram_offset = tvb_get_guint8(tvb, offset) * 8;
    if (tree) {
        proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_offset, tvb, offset, sizeof(guint8), dgram_offset);
    }
    offset += sizeof(guint8);

    /* Adjust the fragmentation header length. */
    frag_size = tvb_reported_length_remaining(tvb, offset);
    if (tree) {
        proto_item_set_end(ti, tvb, offset);
    }

    /* Add this datagram to the fragment table. */
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    frag_data = fragment_add_check(tvb, offset, pinfo, dgram_tag,
                    lowpan_fragment_table, lowpan_reassembled_table,
                    dgram_offset, frag_size, ((dgram_offset + frag_size) < dgram_size));

    /* Attempt reassembly. */
    new_tvb = process_reassembled_data(tvb, offset, pinfo,
                    "6LowPAN", frag_data, &lowpan_frag_items,
                    NULL, tree);

    pinfo->fragmented = save_fragmented;

    /* If reassembly was successful, then return the completed datagram. */
    if (new_tvb) {
        return new_tvb;
    }
    /* If reassembly failed, display the payload fragment using the data dissector. */
    else {
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(data_handle, new_tvb, pinfo, proto_tree_get_root(tree));
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
    if (tree) {
        proto_tree_add_bits_item(tree, hf_6lowpan_pattern, tvb, 0, 8, ENC_BIG_ENDIAN);
    }

    /* Create a tvbuff subset for the remaining data. */
    data_tvb = tvb_new_subset_remaining(tvb, sizeof(guint8));
    call_dissector(data_handle, data_tvb, pinfo, proto_tree_get_root(tree));
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

        /* HC1 header fields. */
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
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_ecn,
          { "ECN",                            "6lowpan.ecn",
            FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_TRAFFIC_ECN, NULL, HFILL }},
        { &hf_6lowpan_dscp,
          { "DSCP",                           "6lowpan.dscp",
            FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_TRAFFIC_DSCP, NULL, HFILL }},
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
          { "Reassembled 6LowPAN length",     "6lowpan.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_6lowpan,
        &ett_6lowpan_hc1,
        &ett_6lowpan_hc2_udp,
        &ett_6lowpan_iphc,
        &ett_6lowpan_nhc_ext,
        &ett_6lowpan_nhc_udp,
        &ett_6lowpan_bcast,
        &ett_6lowpan_mesh,
        &ett_6lowpan_mesh_flags,
        &ett_6lowpan_frag,
        &ett_6lopwan_traffic_class,
        /* Reassembly subtrees. */
        &ett_6lowpan_fragment,
        &ett_6lowpan_fragments
    };

    int         i;
    module_t    *prefs_module;
    static gchar init_context_str[] = "2002:db8::ff:fe00:0";

    proto_6lowpan = proto_register_protocol("IPv6 over IEEE 802.15.4", "6LoWPAN", "6lowpan");
    proto_register_field_array(proto_6lowpan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissector with wireshark. */
    register_dissector("6lowpan", dissect_6lowpan, proto_6lowpan);

    /* Register the dissector init function */
    register_init_routine(proto_init_6lowpan);

    /* Initialize the context table. */
    memset(lowpan_context_table, 0, sizeof(lowpan_context_table));
    memset(lowpan_context_prefs, 0, sizeof(lowpan_context_prefs));

    /* Initialize the link-local prefix. */
    lowpan_context_table[LOWPAN_CONTEXT_LINK_LOCAL].bytes[0] = 0xfe;
    lowpan_context_table[LOWPAN_CONTEXT_LINK_LOCAL].bytes[1] = 0x80;

    /* Initialize the default values of the context table. */
    lowpan_context_prefs[LOWPAN_CONTEXT_DEFAULT] = init_context_str;
    lowpan_context_table[LOWPAN_CONTEXT_DEFAULT].bytes[0] = 0x20;
    lowpan_context_table[LOWPAN_CONTEXT_DEFAULT].bytes[1] = 0x02;
    lowpan_context_table[LOWPAN_CONTEXT_DEFAULT].bytes[2] = 0x0d;
    lowpan_context_table[LOWPAN_CONTEXT_DEFAULT].bytes[3] = 0xb8;
    lowpan_context_table[LOWPAN_CONTEXT_DEFAULT].bytes[11] = 0xff;
    lowpan_context_table[LOWPAN_CONTEXT_DEFAULT].bytes[12] = 0xfe;

    /* Register preferences. */
    prefs_module = prefs_register_protocol(proto_6lowpan, prefs_6lowpan_apply);
    for (i = 0; i < LOWPAN_CONTEXT_COUNT; i++) {
        GString *pref_name, *pref_title, *pref_desc;
        pref_name = g_string_new("");
        pref_title = g_string_new("");
        pref_desc = g_string_new("");

        /*
         * Inspired by the IEEE 802.11 dissector - the preferences are expecting
         * that each pref has a unique string passed in, and will crash if we
         * try to reuse any for multiple preferences. Allocate them off the heap
         * and leave them allocated. OMG, an intentional memory leak; I must be
         * an evil developer. Good thing we have MMU's in this day and age.
         */
        g_string_printf(pref_name, "context%d", i);
        g_string_printf(pref_title, "Context %d", i);
        g_string_printf(pref_desc, "IPv6 prefix to use for stateful address decompression.");
        prefs_register_string_preference(prefs_module, pref_name->str, pref_title->str,
            pref_desc->str, (const char **) &lowpan_context_prefs[i]);
        /* Don't free the ->str */
        g_string_free(pref_name, FALSE);
        g_string_free(pref_title, FALSE);
        g_string_free(pref_desc, FALSE);
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
    fragment_table_init(&lowpan_fragment_table);
    reassembled_table_init(&lowpan_reassembled_table);
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
    int     i;

    for (i = 0; i < LOWPAN_CONTEXT_COUNT; i++) {
        if (!(lowpan_context_prefs[i]) || (inet_pton(AF_INET6, lowpan_context_prefs[i], &lowpan_context_table[i]) != 1)) {
            /* Missing, or invalid IPv6 address, clear the context. */
            memset(&lowpan_context_table[i], 0, sizeof(struct e_in6_addr));
        }
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
    data_handle = find_dissector("data");
    ipv6_handle = find_dissector("ipv6");

    /* Register the 6LoWPAN dissector with IEEE 802.15.4 */
    heur_dissector_add("wpan", dissect_6lowpan_heur, proto_6lowpan);
} /* proto_reg_handoff_6lowpan */

