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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include "epan/dissectors/packet-ipv6.h"
#include "epan/dissectors/packet-ieee802154.h"
#include "packet-6lowpan.h"

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

/* Dissector prototypes */
static void         proto_init_6lowpan      (void);
static gboolean     dissect_6lowpan_heur    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void         dissect_6lowpan         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_ipv6    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_hc1     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_bc0     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_iphc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static struct lowpan_nhdr * dissect_6lowpan_iphc_nhc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
static tvbuff_t *   dissect_6lowpan_mesh    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static tvbuff_t *   dissect_6lowpan_frag    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean first);
static tvbuff_t *   dissect_6lowpan_unknown (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Helper functions. */
static gboolean     lowpan_dlsrc_to_ifcid   (packet_info *pinfo, guint8 *ifcid);
static gboolean     lowpan_dldst_to_ifcid   (packet_info *pinfo, guint8 *ifcid);
static void         lowpan_addr16_to_ifcid  (guint16 addr, guint16 pan, guint8 *ifcid);
static tvbuff_t *   lowpan_reassemble_ipv6  (struct ip6_hdr * ipv6, struct lowpan_nhdr * nhdr_list);
static guint8       lowpan_parse_nhc_proto  (tvbuff_t *tvb, gint offset);

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
static int hf_6lowpan_reassembled_in = -1;
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
    /* Reassembled in field */
    &hf_6lowpan_reassembled_in,
    /* Tag */
    "6LoWPAN fragments"
};

static GHashTable *lowpan_fragment_table = NULL;
static GHashTable *lowpan_reassembled_table = NULL;

/* Link-Local prefix used by 6LoWPAN. */
static const guint8 lowpan_llprefix[8] = {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Helper macro to convert a bit offset/length into a byte count. */
#define BITS_TO_BYTE_LEN(bitoff, bitlen)    ((bitlen)?(((bitlen) + ((bitoff)&0x07) + 7) >> 3):(0))

/* Structure for rebuilding UDP datagrams. */
struct udp_hdr {
    guint16             src_port;
    guint16             dst_port;
    guint16             length;
    guint16             checksum;
};

/* Structure used to store decompressed header chains until reaseembly. */
struct lowpan_nhdr {
    /* List Linking */
    struct lowpan_nhdr  *next;
    /* Next Header */
    guint8              proto;
    guint               length;
    guint               reported;
    guint8              hdr[];
};

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      lowpan_addr16_to_ifcid
 *  DESCRIPTION
 *      Converts a short address to in interface identifier as
 *      per rfc 4944 section 6.
 *  PARAMETERS
 *      addr            ; 16-bit short address.
 *      pan             ; 16-bit PAN identifier.
 *      ifcid           ; interface identifier (output).
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
lowpan_addr16_to_ifcid(guint16 addr, guint16 pan, guint8 *ifcid)
{
    /* Build an EUI-64 from the short address and PAN identifier. */
    ifcid[0] = (pan >> 8) & 0xff;
    ifcid[1] = (pan >> 0) & 0xff;
    ifcid[2] = 0x00;
    ifcid[3] = 0xff;
    ifcid[4] = 0xfe;
    ifcid[5] = 0x00;
    ifcid[6] = (addr >> 8) & 0xff;
    ifcid[7] = (addr >> 0) & 0xff;

    /* Clear the universal/local bit. */
    ifcid[0] &= ~(0x02);
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
    ieee802154_packet * packet = pinfo->private_data;

    /* Check the link-layer address field. */
    if (pinfo->dl_src.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_src.data, LOWPAN_IFC_ID_LEN);
        return TRUE;
    }

    /* Sanity-Check to ensure the parent dissector was IEEE 802.15.4 */
    if (!pinfo->layer_names) return FALSE;
    if (!pinfo->layer_names->str) return FALSE;
    if (strstr(pinfo->layer_names->str, "wpan")) return FALSE;

    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64     addr;
        addr = pntoh64(&packet->src.addr64);
        memcpy(ifcid, &addr, LOWPAN_IFC_ID_LEN);
        return TRUE;
    }
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        lowpan_addr16_to_ifcid(packet->src.addr16, packet->src_pan, ifcid);
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
    ieee802154_packet * packet = pinfo->private_data;

    /* Check the link-layer address field. */
    if (pinfo->dl_dst.type == AT_EUI64) {
        memcpy(ifcid, pinfo->dl_dst.data, LOWPAN_IFC_ID_LEN);
        return TRUE;
    }

    /* Sanity-Check to ensure the parent dissector was IEEE 802.15.4 */
    if (!pinfo->layer_names) return FALSE;
    if (!pinfo->layer_names->str) return FALSE;
    if (strstr(pinfo->layer_names->str, "wpan")) return FALSE;

    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64     addr;
        addr = pntoh64(&packet->dst.addr64);
        memcpy(ifcid, &addr, LOWPAN_IFC_ID_LEN);
        return TRUE;
    }
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        lowpan_addr16_to_ifcid(packet->dst.addr16, packet->dst_pan, ifcid);
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
lowpan_reassemble_ipv6(struct ip6_hdr *ipv6, struct lowpan_nhdr *nhdr_list)
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
    buffer = g_malloc(length + sizeof(struct ip6_hdr));
    memcpy(buffer, ipv6, sizeof(struct ip6_hdr));
    cursor = buffer + sizeof(struct ip6_hdr);

    /* Add the next headers into the buffer. */
    for (nhdr = nhdr_list; nhdr; nhdr = nhdr->next) {
        memcpy(cursor, nhdr->hdr, nhdr->length);
        cursor += nhdr->length;
    };

    /* Return the reassembed packet. */
    return tvb_new_real_data(buffer, length + sizeof(struct ip6_hdr), reported + sizeof(struct ip6_hdr));
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
                /* I don't understand this option. */
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
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_HC1_BITS) == LOWPAN_PATTERN_HC1) break;
        if (tvb_get_bits8(tvb, 0, LOWPAN_PATTERN_BC0_BITS) == LOWPAN_PATTERN_BC0) break;
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

    /* Create the protocol tree. */
    if (tree) {
        lowpan_root = proto_tree_add_protocol_format(tree, proto_6lowpan, tvb, 0, tvb_length(tvb), "6LoWPAN");
        lowpan_tree = proto_item_add_subtree(lowpan_root, ett_6lowpan);
    }
    /* Add the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "6LoWPAN");

    /* Dissect headers in a loop until we find the end of the buffer. */
    while (next) {
        /* Parse patterns until we find a match. */
        if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_IPV6_BITS) == LOWPAN_PATTERN_IPV6) {
            next = dissect_6lowpan_ipv6(next, pinfo, lowpan_tree);
        }
        else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_HC1_BITS) == LOWPAN_PATTERN_HC1) {
            next = dissect_6lowpan_hc1(next, pinfo, lowpan_tree);
        }
        else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_BC0_BITS) == LOWPAN_PATTERN_BC0) {
            next = dissect_6lowpan_bc0(next, pinfo, lowpan_tree);
        }
        else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_IPHC_BITS) == LOWPAN_PATTERN_IPHC) {
            next = dissect_6lowpan_iphc(next, pinfo, lowpan_tree);
        }
        else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_MESH_BITS) == LOWPAN_PATTERN_MESH) {
            next = dissect_6lowpan_mesh(next, pinfo, lowpan_tree);
        }
        else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAG1) {
            next = dissect_6lowpan_frag(next, pinfo, lowpan_tree, TRUE);
        }
        else if (tvb_get_bits8(next, 0, LOWPAN_PATTERN_FRAG_BITS) == LOWPAN_PATTERN_FRAGN) {
            next = dissect_6lowpan_frag(next, pinfo, lowpan_tree, FALSE);
        }
        else {
            next = dissect_6lowpan_unknown(next, pinfo, lowpan_tree);
        }
    } /* while */
} /* dissect_6lowpan */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_ipv6
 *  DESCRIPTION
 *      Dissector routine for an uncompressed IPv6 header type.
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
dissect_6lowpan_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *          ipv6_tvb;

    /* Get and display the pattern. */
    if (tree) {
        proto_tree_add_bits_item(tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_IPV6_BITS, FALSE);
    }

    /* Create a tvbuff subset for the ipv6 datagram. */
    ipv6_tvb = tvb_new_subset(tvb, sizeof(guint8), -1, tvb_reported_length(tvb) - sizeof(guint8));
    call_dissector(ipv6_handle, ipv6_tvb, pinfo, proto_tree_get_root(tree));

    /* No data remaining, we gave it all to the IPv6 dissector. */
    return NULL;
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
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_hc1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint                offset = 0;
    gint                bit_offset;
    int                 i;
    guint8              hc1_encoding;
    guint8              hc_udp_encoding = 0;
    guint8              next_header;
    proto_tree *        hc_tree;
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
    }

    /* Get and display the pattern. */
    if (tree) {
        proto_tree_add_bits_item(hc_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_HC1_BITS, FALSE);
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
                ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint8), "HC_UDP Encoding");
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
        ipv6.ip6_flow = tvb_get_bits32(tvb, bit_offset, LOWPAN_IPV6_FLOW_LABEL_BITS, FALSE);
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
    /* Try to recover the source interface identifier from the packet info. */
    else if (pinfo->src.type == AT_EUI64) {
        memcpy(&ipv6.ip6_src.bytes[8], pinfo->src.data, 8);
    }
    /* Try to recover the source interface identifier from the link layer. */
    else {
        lowpan_dlsrc_to_ifcid(pinfo, &ipv6.ip6_src.bytes[8]);
    }
    /* Display the source address. */
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), (guint8 *)&ipv6.ip6_src);
    }

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
    /* Try to recover the destination interface identifier from the packet info. */
    else if (pinfo->dst.type == AT_EUI64) {
        memcpy(&ipv6.ip6_dst.bytes[8], pinfo->dst.data, 8);
    }
    /* Try to recover the source interface identifier from the link layer. */
    else {
        lowpan_dldst_to_ifcid(pinfo, &ipv6.ip6_dst.bytes[8]);
    }
    /* Display the destination address. */
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), (guint8 *)&ipv6.ip6_dst);
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
            udp.src_port = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_PORT_BITS, FALSE);
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
            udp.dst_port = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_PORT_BITS, FALSE);
            bit_offset += LOWPAN_UDP_PORT_BITS;
        }
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset>>3,
                    BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), udp.dst_port);
        }
        udp.dst_port = g_ntohs(udp.dst_port);

        /* Parse the length, if present. */
        if (!(hc1_encoding & LOWPAN_HC2_UDP_LENGTH)) {
            udp.length = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_LENGTH_BITS, FALSE);
            if (tree) {
                proto_tree_add_uint(tree, hf_6lowpan_udp_len, tvb, bit_offset>>3,
                        BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_LENGTH_BITS), udp.length);

            }
            bit_offset += LOWPAN_UDP_LENGTH_BITS;
        }
        /* Compute the length from the tvbuff size. */
        else {
            udp.length = tvb_reported_length(tvb);
            udp.length -= BITS_TO_BYTE_LEN(0, bit_offset + LOWPAN_UDP_CHECKSUM_BITS);
            udp.length += sizeof(struct udp_hdr);
        }
        udp.length = g_ntohs(udp.length);

        /* Parse the checksum. */
        udp.checksum = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_CHECKSUM_BITS, FALSE);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_checksum, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_CHECKSUM_BITS), udp.checksum);
        }
        bit_offset += LOWPAN_UDP_CHECKSUM_BITS;
        udp.checksum = g_ntohs(udp.checksum);

        /* Construct the next header for the UDP datagram. */
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        length = tvb_length_remaining(tvb, offset);
        nhdr_list = ep_alloc(sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = IP_PROTO_UDP;
        nhdr_list->length = length + sizeof(struct udp_hdr);
        nhdr_list->reported = g_ntohs(udp.length);

        /* Copy the UDP header into the buffer. */
        memcpy(nhdr_list->hdr, &udp, sizeof(struct udp_hdr));
        tvb_memcpy(tvb, nhdr_list->hdr + sizeof(struct udp_hdr), offset, length);
    }
    /*=====================================================
     * Reconstruct the IPv6 Packet
     *=====================================================
     */
    else {
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        nhdr_list = ep_alloc(sizeof(struct lowpan_nhdr) + tvb_length_remaining(tvb, offset));
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6_nxt;
        nhdr_list->length = tvb_length_remaining(tvb, offset);
        nhdr_list->reported = tvb_reported_length_remaining(tvb, offset);
        tvb_memcpy(tvb, nhdr_list->hdr, offset, nhdr_list->length);
    }

    /* Link the reassembled tvbuff together.  */
    ipv6_tvb = lowpan_reassemble_ipv6(&ipv6, nhdr_list);
    tvb_set_child_real_data_tvbuff(tvb, ipv6_tvb);
    add_new_data_source(pinfo, ipv6_tvb, "6LoWPAN header decompression");

    /* Pass the reassembled packet to the IPv6 dissector. */
    call_dissector(ipv6_handle, ipv6_tvb, pinfo, proto_tree_get_root(tree));
    return NULL;
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
 *      See draft-ietf-6lowpan-hc-05.txt
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *  RETURNS
 *      tvbuff_t *      ; The remaining payload to be parsed.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_iphc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint                offset = 0;
    gint                length;
    proto_tree *        iphc_tree;
    proto_item *        ti = NULL;
    proto_item *        ti_sam = NULL;
    proto_item *        ti_dam = NULL;
    gboolean            addr_err;
    /* IPHC header fields. */
    guint16             iphc_flags;
    guint8              iphc_traffic;
    guint8              iphc_hop_limit;
    guint8              iphc_src_mode;
    guint8              iphc_dst_mode;
    guint8              iphc_ctx = 0;
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
        proto_tree_add_bits_item(iphc_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_IPHC_BITS, FALSE);
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
        proto_tree_add_uint         (iphc_tree, hf_6lowpan_iphc_flag_tf,    tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_FLOW);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_nhdr,  tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_NHDR);
        proto_tree_add_uint         (iphc_tree, hf_6lowpan_iphc_flag_hlim,  tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_HLIM);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_cid,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_CONTEXT_ID);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_sac,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP);
        ti_sam = proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_flag_sam,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_SRC_MODE);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_mcast, tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP);
        proto_tree_add_boolean      (iphc_tree, hf_6lowpan_iphc_flag_dac,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP);
        ti_dam = proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_flag_dam,   tvb, offset, sizeof(guint16), iphc_flags & LOWPAN_IPHC_FLAG_DST_MODE);
    }
    offset += sizeof(guint16);

    /* Display the context identifier extension, if present. */
    if (iphc_flags & LOWPAN_IPHC_FLAG_CONTEXT_ID) {
        iphc_ctx = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_sci, tvb, offset, sizeof(guint8), iphc_ctx & LOWPAN_IPHC_FLAG_SCI);
            proto_tree_add_uint(iphc_tree, hf_6lowpan_iphc_dci, tvb, offset, sizeof(guint8), iphc_ctx & LOWPAN_IPHC_FLAG_DCI);
        }
        offset +=  sizeof(guint8);
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
    /* Display the traffic class field. */
    if (tree) {
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
        ipv6.ip6_flow = tvb_get_bits32(tvb, offset, LOWPAN_IPHC_LABEL_BITS, FALSE);
        if (tree) {
            proto_tree_add_bits_item(tree, hf_6lowpan_flow_label, tvb, offset, LOWPAN_IPHC_LABEL_BITS, FALSE);
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
    addr_err = FALSE;
    length = 0;
    memset(&ipv6.ip6_src, 0, sizeof(ipv6.ip6_src));
    /*-----------------------
     * Stateless compression
     *-----------------------
     */
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_SRC_COMP)) {
        /* Load the link-local prefix. */
        ipv6.ip6_src.bytes[0] = 0xff;
        ipv6.ip6_src.bytes[1] = 0xfe;
        /* Full Address inline. */
        if (iphc_src_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            length = sizeof(ipv6.ip6_src);
            tvb_memcpy(tvb, &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - length], offset, length);
        }
        /* Partial address inline. */
        else if (iphc_src_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
            length = sizeof(guint64);
            tvb_memcpy(tvb, &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - length], offset, length);
        }
        else if (iphc_src_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
            length = sizeof(guint16);
            tvb_memcpy(tvb, &ipv6.ip6_src.bytes[sizeof(ipv6.ip6_src) - length], offset, length);
        }
        /* Try to recover the source interface identifier from the link layer. */
        else {
            lowpan_dlsrc_to_ifcid(pinfo, &ipv6.ip6_src.bytes[8]);
        }
    }
    /*-----------------------
     * Stateful compression
     *-----------------------
     */
    else {
        /*
         * TODO: Stateful address recovery.
         * For now, just set the address to 0 and ignore the context bits.
         */
        addr_err = TRUE;
        if (iphc_src_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) length = sizeof(guint64);
        else if (iphc_src_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) length = sizeof(guint16);
        else if (iphc_src_mode == LOWPAN_IPHC_ADDR_COMPRESSED) length = 0;
        else {
            /* Illegal source address compression mode. */
            expert_add_info_format(pinfo, ti_sam, PI_MALFORMED, PI_ERROR, "Illegal source address mode");
            return NULL;
        }
    }

    /* Display the source IPv6 address. */
    if (tree) {
        ti = proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset, length, (guint8 *)&ipv6.ip6_src);
    }
    if (addr_err) {
        expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Failed to recover source IPv6 address");
    }
    offset += length;

    /*=====================================================
     * Parse and decompress the destination address.
     *=====================================================
     */
    addr_err = FALSE;
    length = 0;
    memset(&ipv6.ip6_dst, 0, sizeof(ipv6.ip6_dst));
    /*---------------------------------
     * Stateless unicast compression
     *---------------------------------
     */
    if (!(iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP) && !(iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP)) {
        /* Load the link-local prefix. */
        ipv6.ip6_dst.bytes[0] = 0xff;
        ipv6.ip6_dst.bytes[1] = 0xfe;
        /* Full Address inline. */
        if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            length = sizeof(ipv6.ip6_dst);
            tvb_memcpy(tvb, &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - length], offset, length);
        }
        /* Partial address inline. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
            length = sizeof(guint64);
            tvb_memcpy(tvb, &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - length], offset, length);
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
            length = sizeof(guint16);
            tvb_memcpy(tvb, &ipv6.ip6_dst.bytes[sizeof(ipv6.ip6_dst) - length], offset, length);
        }
        /* Try to recover the source interface identifier from the link layer. */
        else {
            lowpan_dldst_to_ifcid(pinfo, &ipv6.ip6_dst.bytes[8]);
        }
    }
    /*---------------------------------
     * Stateless multicast compression
     *---------------------------------
     */
    else if (!(iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP) && (iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP)) {
        if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[11] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[12] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[13] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[14] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[13] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[14] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) {
            guint8          temp = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = (temp >> 4);
            ipv6.ip6_dst.bytes[14] = (temp & 0xf);
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_COMPRESSED) {
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = 0x02;
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
    }
    /*---------------------------------
     * Stateful unicast compression
     *---------------------------------
     */
    else if ((iphc_flags & LOWPAN_IPHC_FLAG_DST_COMP) && !(iphc_flags & LOWPAN_IPHC_FLAG_MCAST_COMP)) {
        /* TODO: Stateful address recovery. */
        addr_err = TRUE;
        if (iphc_dst_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) length = sizeof(guint64);
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_16BIT_INLINE) length = sizeof(guint16);
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_COMPRESSED) length = 0;
        else {
            /* Illegal destination address compression mode. */
            expert_add_info_format(pinfo, ti_dam, PI_MALFORMED, PI_ERROR, "Illegal destination address mode");
            return NULL;
        }
    }
    /*---------------------------------
     * Stateful multicast compression
     *---------------------------------
     */
    else {
        /* If full inline, it's neither stateful, nor compressed. */
        if (iphc_dst_mode == LOWPAN_IPHC_ADDR_FULL_INLINE) {
            length = sizeof(ipv6.ip6_dst);
            tvb_memcpy(tvb, &ipv6.ip6_dst, offset, length);
        }
        /* If 64-bit inline, then there are 48-bits inline, and the
         * remainder is derived from context. */
        else if (iphc_dst_mode == LOWPAN_IPHC_ADDR_64BIT_INLINE) {
            ipv6.ip6_dst.bytes[0] = 0xff;
            ipv6.ip6_dst.bytes[1] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[2] = tvb_get_guint8(tvb, offset + (length++));
            /* TODO: Recover the stuff derived from context. */
            addr_err = TRUE;
            ipv6.ip6_dst.bytes[12] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[13] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[14] = tvb_get_guint8(tvb, offset + (length++));
            ipv6.ip6_dst.bytes[15] = tvb_get_guint8(tvb, offset + (length++));
        }
        else {
            /* Illegal destination address compression mode. */
            addr_err = TRUE;
            expert_add_info_format(pinfo, ti_dam, PI_MALFORMED, PI_ERROR, "Illegal destination address mode");
            return NULL;
        }

    }

    /* Display the destination IPv6 address. */
    if (tree) {
        ti = proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset, length, (guint8 *)&ipv6.ip6_dst);
    }
    if (addr_err) {
        expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Failed to recover destination IPv6 address");
    }
    offset += length;

    /*=====================================================
     * Decompress extension headers.
     *=====================================================
     */
    /* Parse the list of extension headers. */
    if (iphc_flags & LOWPAN_IPHC_FLAG_NHDR) {
        /* Parse the next header protocol identifer. */
        ipv6.ip6_nxt = lowpan_parse_nhc_proto(tvb, offset);

        /* Parse the 6LoWPAN NHC fields. */
        nhdr_list = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset);
    }
    /* Create an extension header for the remaining payload. */
    else {
        nhdr_list = ep_alloc(sizeof(struct lowpan_nhdr) + tvb_length_remaining(tvb, offset));
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6_nxt;
        nhdr_list->length = tvb_length_remaining(tvb, offset);
        nhdr_list->reported = tvb_reported_length_remaining(tvb, offset);
        tvb_memcpy(tvb, nhdr_list->hdr, offset, nhdr_list->length);
    }

    /*=====================================================
     * Rebuild the IPv6 packet.
     *=====================================================
     */
    /* Reassemble the IPv6 packet. */
    ipv6_tvb = lowpan_reassemble_ipv6(&ipv6, nhdr_list);
    tvb_set_child_real_data_tvbuff(tvb, ipv6_tvb);
    add_new_data_source(pinfo, ipv6_tvb, "6LoWPAN header decompression");

    /* Pass the reassembled packe to the IPv6 dissector. */
    call_dissector(ipv6_handle, ipv6_tvb, pinfo, proto_tree_get_root(tree));
    return NULL;
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
 *  RETURNS
 *      lowpan_nhdr *   ; List of ep_alloc'd next header structures.
 *---------------------------------------------------------------
 */
static struct lowpan_nhdr *
dissect_6lowpan_iphc_nhc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint                length;
    proto_item *        ti = NULL;
    proto_tree *        nhc_tree = NULL;
    struct lowpan_nhdr *nhdr;

    /* IPv6 Extension Header. */
    if (tvb_get_bits8(tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS) == LOWPAN_NHC_PATTERN_EXT) {
        struct ip6_ext  ipv6_ext;
        guint8          ext_flags;
        guint8          ext_len;
        guint8          ext_proto;

        /* Parse the IPv6 extension header protocol. */
        ext_proto = lowpan_parse_nhc_proto(tvb, offset);

        /* Create a tree for the IPv6 extnesion header. */
        if (tree) {
            ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint16), "IPv6 extension header");
            nhc_tree = proto_item_add_subtree(ti, ett_6lowpan_nhc_ext);
            /* Display the NHC-UDP pattern. */
            proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_EXT_BITS, FALSE);
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
        length += ((length + 7) & 0x7);

        /* Create the next header structure for the IPv6 extension header. */
        nhdr = ep_alloc0(sizeof(struct lowpan_nhdr) + sizeof(struct ip6_ext) + length);
        nhdr->next = NULL;
        nhdr->proto = ext_proto;
        nhdr->length = length + sizeof(struct ip6_ext);
        nhdr->reported = length + sizeof(struct ip6_ext);

        /* Add the IPv6 extension header to the buffer. */
        if (ext_flags & LOWPAN_NHC_EXT_NHDR) {
            ipv6_ext.ip6e_nxt = lowpan_parse_nhc_proto(tvb, offset+ext_len);
        }
        ipv6_ext.ip6e_len = nhdr->reported>>3;  /* Convert to units of 8 bytes. */
        memcpy(nhdr->hdr, &ipv6_ext, sizeof(struct ip6_ext));

        /*
         * If the extension header was truncated, display the remainder using
         * the data dissector, and end NHC dissection here.
         */
        if (!tvb_bytes_exist(tvb, offset, ext_len)) {
            /* Call the data dissector for the remainder. */
            call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo, nhc_tree);

            /* Copy the remainder, and truncate the real buffer length. */
            nhdr->length = tvb_length_remaining(tvb, offset) + sizeof(struct ip6_ext);
            tvb_memcpy(tvb, nhdr->hdr + sizeof(struct ip6_ext), offset, tvb_length_remaining(tvb, offset));

            /* There is nothing more we can do. */
            return nhdr;
        }

        /* Display the extension header using the data dissector. */
        call_dissector(data_handle, tvb_new_subset(tvb, offset, ext_len, ext_len), pinfo, nhc_tree);

        /* Copy the extension header into the struct. */
        tvb_memcpy(tvb, nhdr->hdr + sizeof(struct ip6_ext), offset, ext_len);
        offset += ext_len;

        if (!(ext_flags & LOWPAN_NHC_EXT_NHDR)) {
            /* Create another next header structure for the remaining payload. */
            nhdr->next = ep_alloc(sizeof(struct lowpan_nhdr) + tvb_length_remaining(tvb, offset));
            nhdr->next->next = NULL;
            nhdr->next->proto = ipv6_ext.ip6e_nxt;
            nhdr->next->length = tvb_length_remaining(tvb, offset);
            nhdr->next->reported = tvb_reported_length_remaining(tvb, offset);
            tvb_memcpy(tvb, nhdr->next->hdr, offset, length);
        }
        else {
            /*
             * There are more LOWPAN_NHC structures to parse. Call ourself agian
             * recursively to parse them and build the linked list.
             */
            nhdr->next = dissect_6lowpan_iphc_nhc(tvb, pinfo, tree, offset);
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
            proto_tree_add_bits_item(nhc_tree, hf_6lowpan_nhc_pattern, tvb, offset<<3, LOWPAN_NHC_PATTERN_UDP_BITS, FALSE);
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
                udp.src_port = LOWPAN_PORT_12BIT_OFFSET;
                udp.dst_port = LOWPAN_PORT_12BIT_OFFSET;
                src_bitlen = 4;
                dst_bitlen = 4;
                break;

            case LOWPAN_NHC_UDP_SRCPORT:
                udp.src_port = LOWPAN_PORT_8BIT_OFFSET;
                udp.dst_port = 0;
                src_bitlen = 8;
                dst_bitlen = 16;
                break;

            case LOWPAN_NHC_UDP_DSTPORT:
                udp.src_port = 0;
                udp.dst_port = LOWPAN_PORT_8BIT_OFFSET;
                src_bitlen = 16;
                dst_bitlen = 8;
                break;

            default:
                udp.src_port = 0;
                udp.dst_port = 0;
                src_bitlen = 16;
                dst_bitlen = 16;
                break;
        } /* switch */

        /* Source port */
        udp.src_port += tvb_get_bits16(tvb, offset<<3, src_bitlen, FALSE);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_src, tvb, offset, BITS_TO_BYTE_LEN(offset<<3, src_bitlen), udp.src_port);
        }
        /* Destination port */
        udp.dst_port += tvb_get_bits16(tvb, (offset<<3)+src_bitlen, dst_bitlen, FALSE);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset, BITS_TO_BYTE_LEN((offset<<3)+src_bitlen, dst_bitlen), udp.dst_port);
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
        length = tvb_reported_length_remaining(tvb, offset);
        udp.length = g_ntohs(length + sizeof(struct udp_hdr));

        /*
         * Although rfc768 (udp) allows a packet to be sent with a checksum of
         * 0 to mean that no checksum was computed, apparently IPv6 specifically
         * disallows sending UDP datagrams without checksums. Likewise, 6LoWPAN
         * requires that we recompute the checksum.
         *
         * Although, if the datagram is incomplete, then leave the checsum at 0.
         */
        if ((udp_flags & LOWPAN_NHC_UDP_CHECKSUM) && tvb_bytes_exist(tvb, offset, length)) {
            vec_t      cksum_vec[3];
            struct {
                struct e_in6_addr   src;
                struct e_in6_addr   dst;
                guint8              zero;
                guint8              proto;
                guint16             length;
            } cksum_phdr;
            guint16                 cksum;

            /* Fill in the pseudo-header. */
            memcpy(&cksum_phdr.src, pinfo->src.data, sizeof(struct e_in6_addr));
            memcpy(&cksum_phdr.dst, pinfo->dst.data, sizeof(struct e_in6_addr));
            cksum_phdr.zero = 0;
            cksum_phdr.proto = IP_PROTO_UDP;
            cksum_phdr.length = udp.length;

            /* Compute the checksum. */
            cksum_vec[0].ptr = (const guint8 *)&cksum_phdr;
            cksum_vec[0].len = sizeof(cksum_phdr);
            cksum_vec[1].ptr = (const guint8 *)&udp;
            cksum_vec[1].len = sizeof(struct udp_hdr);
            cksum_vec[2].ptr = tvb_get_ptr(tvb, offset, length);
            cksum_vec[2].len = length;
            cksum = in_cksum(cksum_vec, 3);
            udp.checksum = g_ntohs((cksum)?(cksum):(~cksum));
        }

        /* Create the next header structure for the UDP datagram. */
        nhdr = ep_alloc(sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + tvb_length_remaining(tvb, offset));
        nhdr->next = NULL;
        nhdr->proto = IP_PROTO_UDP;
        nhdr->length = tvb_length_remaining(tvb, offset) + sizeof(struct udp_hdr);
        nhdr->reported = g_ntohs(udp.length);

        /* Copy the UDP header into the buffer. */
        memcpy(nhdr->hdr, &udp, sizeof(struct udp_hdr));
        tvb_memcpy(tvb, nhdr->hdr + sizeof(struct udp_hdr), offset, length);
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
    }

    /* Get and display the pattern. */
    if (tree) {
        proto_tree_add_bits_item(bcast_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_BC0_BITS, FALSE);
    }

    /* Get and display the sequence number. */
    seqnum = tvb_get_guint8(tvb, sizeof(guint8));
    if (tree) {
        proto_tree_add_uint(bcast_tree, hf_6lowpan_bcast_seqnum, tvb, sizeof(guint8), sizeof(guint8), seqnum);
    }

    /* Return the remaining buffer. */
    return tvb_new_subset(tvb, sizeof(guint16), -1, -1);
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
    guint16             src_pan = IEEE802154_BCAST_PAN;
    guint16             dst_pan = IEEE802154_BCAST_PAN;
    const guint8 *      src_ifcid;
    const guint8 *      dst_ifcid;

    /*
     * If 16-bit addresses are used, we need to consult the MAC layer to
     * retrieve the PAN identifiers used if we want to reconstruct the
     * interface identifier.
     */
    if (pinfo->layer_names && pinfo->layer_names->str) {
        /* Ensure the MAC layer is IEEE 802.15.4 */
        if (strstr(pinfo->layer_names->str, "wpan") != NULL) {
            ieee802154_packet * packet = pinfo->private_data;
            if (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE) src_pan = packet->src_pan;
            if (packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) dst_pan = packet->dst_pan;
        }
    }

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
        proto_tree_add_bits_item(flag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_MESH_BITS, FALSE);
        proto_tree_add_boolean(flag_tree, hf_6lowpan_mesh_v, tvb, offset, sizeof(guint8), mesh_header & LOWPAN_MESH_HEADER_V);
        proto_tree_add_boolean(flag_tree, hf_6lowpan_mesh_f, tvb, offset, sizeof(guint8), mesh_header & LOWPAN_MESH_HEADER_F);
        proto_tree_add_uint(flag_tree, hf_6lowpan_mesh_hops, tvb, offset, sizeof(guint8), mesh_header & LOWPAN_MESH_HEADER_HOPS);
    }
    offset += sizeof(guint8);

    /* Get and display the originator address. */
    if (mesh_header & LOWPAN_MESH_HEADER_V) {
        guint64         addr64 = tvb_get_ntoh64(tvb, offset);
        if (tree) {
            proto_tree_add_uint64(mesh_tree, hf_6lowpan_mesh_orig64, tvb, offset, sizeof(guint64), addr64);
        }
        src_ifcid = tvb_get_ptr(tvb, offset, sizeof(guint64));
        offset += sizeof(guint64);
    }
    else {
        guint16         addr16 = tvb_get_ntohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_orig16, tvb, offset, sizeof(guint16), addr16);
        }
        src_ifcid = ep_alloc(sizeof(guint64));
        lowpan_addr16_to_ifcid(addr16, src_pan, (guint8 *)src_ifcid);
        offset += sizeof(guint16);
    }
    SET_ADDRESS(&pinfo->src,  AT_EUI64, sizeof(guint64), src_ifcid);
    SET_ADDRESS(&pinfo->net_src,  AT_EUI64, sizeof(guint64), src_ifcid);

    /* Get and display the destination address. */
    if (mesh_header & LOWPAN_MESH_HEADER_F) {
        guint64         addr64 = tvb_get_ntoh64(tvb, offset);
        if (tree) {
            proto_tree_add_uint64(mesh_tree, hf_6lowpan_mesh_dest64, tvb, offset, sizeof(guint64), addr64);
        }
        dst_ifcid = tvb_get_ptr(tvb, offset, sizeof(guint64));
        offset += sizeof(guint64);
    }
    else  {
        guint16         addr16 = tvb_get_ntohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(mesh_tree, hf_6lowpan_mesh_dest16, tvb, offset, sizeof(guint16), addr16);
        }
        dst_ifcid = ep_alloc(sizeof(guint64));
        lowpan_addr16_to_ifcid(addr16, dst_pan, (guint8 *)dst_ifcid);
        offset += sizeof(guint16);
    }
    SET_ADDRESS(&pinfo->dst,  AT_EUI64, sizeof(guint64), dst_ifcid);
    SET_ADDRESS(&pinfo->net_dst,  AT_EUI64, sizeof(guint64), dst_ifcid);

    /* Adjust the mesh header length. */
    if (tree) {
        proto_item_set_end(ti, tvb, offset);
    }

    /* Return the remaining buffer. */
    return tvb_new_subset(tvb, offset, -1, -1);
} /* dissect_6lowpan_mesh */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_6lowpan_frag
 *  DESCRIPTION
 *      Dissector routine for a 6LoWPAN FRAG headers.
 *  PARAMETERS
 *      tvb             ; packet buffer.
 *      pinfo           ; packet info.
 *      tree            ; 6LoWPAN display tree.
 *      first           ; TRUE if dispatch was FRAG1, FALSE if FRAGN.
 *  RETURNS
 *      tvbuff_t *      ; reassembled/next buffer.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_6lowpan_frag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean first)
{
    gint                offset = 0;
    gint                frag_size;
    guint16             dgram_size;
    guint16             dgram_tag;
    guint8              dgram_offset = 0;
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
    dgram_size = tvb_get_bits16(tvb, (offset * 8) + LOWPAN_PATTERN_FRAG_BITS, LOWPAN_FRAG_DGRAM_SIZE_BITS, FALSE);
    if (tree) {
        proto_tree_add_bits_item(frag_tree, hf_6lowpan_pattern, tvb, offset * 8, LOWPAN_PATTERN_FRAG_BITS, FALSE);
        proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_size, tvb, offset, sizeof(guint16), dgram_size);
    }
    offset += sizeof(guint16);

    /* Get and display the datagram tag. */
    dgram_tag = tvb_get_ntohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_tag, tvb, offset, sizeof(guint16), dgram_tag);
    }
    offset += sizeof(guint16);

    if (!first) {
        dgram_offset = tvb_get_guint8(tvb, offset) * 8;
        if (tree) {
            proto_tree_add_uint(frag_tree, hf_6lowpan_frag_dgram_offset, tvb, offset, sizeof(guint8), dgram_offset);
        }
        offset += sizeof(guint8);
    }

    /* Adjust the fragmentation header length. */
    frag_size = tvb_length_remaining(tvb, offset);
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
                    "Reassembled Message", frag_data, &lowpan_frag_items,
                    NULL, tree);

    /* If reassembly was successful, then return the completed datagram. */
    if (new_tvb) {
        return new_tvb;
    }
    /*
     * Otherwise, we were unable to reassemble the packet. If this is the
     * first fragment, we can still return the remainder for more processing.
     */
    else if (first) {
        return tvb_new_subset(tvb, offset, -1, dgram_size);
    }
    /*
     * If reassembly failed, and this is not the first fragment, then display
     * the payload fragment using the data dissector.
     */
    else {
        tvbuff_t *      data_tvb = tvb_new_subset(tvb, offset, -1, dgram_size);
        call_dissector(data_handle, data_tvb, pinfo, proto_tree_get_root(tree));
        return NULL;
    }
} /* dissect_6lowpan_frag */

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
static tvbuff_t *
dissect_6lowpan_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *          data_tvb;

    /* Get and display the pattern. */
    if (tree) {
        proto_tree_add_bits_item(tree, hf_6lowpan_pattern, tvb, 0, 8, FALSE);
    }

    /* Create a tvbuff subset for the remaining data. */
    data_tvb = tvb_new_subset(tvb, sizeof(guint8), -1, tvb_reported_length(tvb) - sizeof(guint8));
    call_dissector(data_handle, data_tvb, pinfo, proto_tree_get_root(tree));

    /* No data remaining, we gave it all to the data dissector. */
    return NULL;
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
        { "Pattern",                        "6lowpan.pattern", FT_UINT8, BASE_HEX, VALS(lowpan_patterns), 0x0, NULL, HFILL }},
        { &hf_6lowpan_nhc_pattern,
        { "Pattern",                        "6lowpan.nhc.pattern", FT_UINT8, BASE_HEX, VALS(lowpan_nhc_patterns), 0x0, NULL, HFILL }},

        /* HC1 header fields. */
        { &hf_6lowpan_hc1_source_prefix,
        { "Source prefix",                  "6lowpan.hc1.src_prefix", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_SOURCE_PREFIX, NULL, HFILL }},
        { &hf_6lowpan_hc1_source_ifc,
        { "Source interface",               "6lowpan.hc1.src_ifc", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_SOURCE_IFC, NULL, HFILL }},
        { &hf_6lowpan_hc1_dest_prefix,
        { "Destination prefix",             "6lowpan.hc1.dst_prefix", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_DEST_PREFIX, NULL, HFILL }},
        { &hf_6lowpan_hc1_dest_ifc,
        { "Destination interface",          "6lowpan.hc1.dst_ifc", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_DEST_IFC, NULL, HFILL }},
        { &hf_6lowpan_hc1_class,
        { "Traffic class and flow label",   "6lowpan.hc1.class", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC1_TRAFFIC_CLASS, NULL, HFILL }},
        { &hf_6lowpan_hc1_next,
        { "Next header",                    "6lowpan.hc1.next", FT_UINT8, BASE_HEX, VALS(lowpan_hc1_next), LOWPAN_HC1_NEXT, NULL, HFILL }},
        { &hf_6lowpan_hc1_more,
        { "More HC bits",                   "6lowpan.hc1.more", FT_BOOLEAN, 8, NULL, LOWPAN_HC1_MORE, NULL, HFILL }},

        /* HC_UDP header fields. */
        { &hf_6lowpan_hc2_udp_src,
        { "Source port",                    "6lowpan.hc2.udp.src", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC2_UDP_SRCPORT, NULL, HFILL }},
        { &hf_6lowpan_hc2_udp_dst,
        { "Destination port",               "6lowpan.hc2.udp.dst", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC2_UDP_DSTPORT, NULL, HFILL }},
        { &hf_6lowpan_hc2_udp_len,
        { "Length",                         "6lowpan.hc2.udp.length", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_HC2_UDP_LENGTH, NULL, HFILL }},

        /* IPHC header fields. */
        { &hf_6lowpan_iphc_flag_tf,
        { "Traffic class and flow lable",   "6lowpan.iphc.tf", FT_UINT16, BASE_HEX, VALS(lowpan_iphc_traffic), LOWPAN_IPHC_FLAG_FLOW, "traffic class and flow control encoding", HFILL }},
        { &hf_6lowpan_iphc_flag_nhdr,
        { "Next header",                    "6lowpan.iphc.nh", FT_BOOLEAN, 16, TFS(&lowpan_compression), LOWPAN_IPHC_FLAG_NHDR, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_hlim,
        { "Hop limit",                      "6lowpan.iphc.hlim", FT_UINT16, BASE_HEX, VALS(lowpan_iphc_hop_limit), LOWPAN_IPHC_FLAG_HLIM, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_cid,
        { "Context identifier extension",   "6lowpan.iphc.cid", FT_BOOLEAN, 16, NULL, LOWPAN_IPHC_FLAG_CONTEXT_ID, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_sac,
        { "Source address compression",     "6lowpan.iphc.sac", FT_BOOLEAN, 16, TFS(&lowpan_iphc_addr_compression), LOWPAN_IPHC_FLAG_SRC_COMP, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_sam,
        { "Source address mode",            "6lowpan.iphc.sac", FT_UINT16, BASE_HEX, VALS(lowpan_iphc_addr_modes), LOWPAN_IPHC_FLAG_SRC_MODE, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_mcast,
        { "Multicast address compression",  "6lowpan.iphc.m", FT_BOOLEAN, 16, NULL, LOWPAN_IPHC_FLAG_MCAST_COMP, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_dac,
        { "Destination address compression","6lowpan.iphc.dac", FT_BOOLEAN, 16, TFS(&lowpan_iphc_addr_compression), LOWPAN_IPHC_FLAG_DST_COMP, NULL, HFILL }},
        { &hf_6lowpan_iphc_flag_dam,
        { "Destination address mode",       "6lowpan.iphc.dam", FT_UINT16, BASE_HEX, VALS(lowpan_iphc_addr_modes), LOWPAN_IPHC_FLAG_DST_MODE, NULL, HFILL }},
        { &hf_6lowpan_iphc_sci,
        { "Source context identifier",      "6lowpan.iphc.sci", FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_FLAG_SCI, NULL, HFILL }},
        { &hf_6lowpan_iphc_dci,
        { "Destination context identifier", "6lowpan.iphc.dci", FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_FLAG_DCI, NULL, HFILL }},

        /* NHC IPv6 extnesion header fields. */
        { &hf_6lowpan_nhc_ext_eid,
        { "Header ID",                      "6lowpan.nhc.ext.eid", FT_UINT8, BASE_HEX, VALS(lowpan_nhc_eid), LOWPAN_NHC_EXT_EID, NULL, HFILL }},
        { &hf_6lowpan_nhc_ext_nh,
        { "Next header",                    "6lowpan.nhc.ext.nh", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_EXT_NHDR, NULL, HFILL }},
        { &hf_6lowpan_nhc_ext_next,
        { "Next header",                    "6lowpan.nhc.ext.next", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_nhc_ext_length,
        { "Header length",                  "6lowpan.nhc.ext.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* NHC UDP header fields. */
        { &hf_6lowpan_nhc_udp_checksum,
        { "Checksum",                       "6lowpan.nhc.udp.checksum", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_UDP_CHECKSUM, NULL, HFILL }},
        { &hf_6lowpan_nhc_udp_src,
        { "Source port",                    "6lowpan.nhc.udp.src", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_UDP_SRCPORT, NULL, HFILL }},
        { &hf_6lowpan_nhc_udp_dst,
        { "Destination port",               "6lowpan.nhc.udp.dst", FT_BOOLEAN, 8, TFS(&lowpan_compression), LOWPAN_NHC_UDP_DSTPORT, NULL, HFILL }},

        /* Uncompressed IPv6 fields. */
        { &hf_6lowpan_traffic_class,
        { "Traffic class",                  "6lowpan.class", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_flow_label,
        { "Flow label",                     "6lowpan.flow", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_ecn,
        { "ECN",                            "6lowpan.ecn", FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_TRAFFIC_ECN, NULL, HFILL }},
        { &hf_6lowpan_dscp,
        { "DSCP",                           "6lowpan.dscp", FT_UINT8, BASE_HEX, NULL, LOWPAN_IPHC_TRAFFIC_DSCP, NULL, HFILL }},
        { &hf_6lowpan_next_header,
        { "Next header",                    "6lowpan.next", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_hop_limit,
        { "Hop limit",                      "6lowpan.hops", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_source,
        { "Source",                         "6lowpan.src", FT_IPv6, BASE_NONE, NULL, 0x0, "Source IPv6 address", HFILL }},
        { &hf_6lowpan_dest,
        { "Destination",                    "6lowpan.dst", FT_IPv6, BASE_NONE, NULL, 0x0, "Destination IPv6 address", HFILL }},

        /* Uncompressed UDP fields. */
        { &hf_6lowpan_udp_src,
        { "Source port",                    "6lowpan.udp.src", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_udp_dst,
        { "Destination port",               "6lowpan.udp.dst", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_udp_len,
        { "UDP length",                     "6lowpan.udp.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_udp_checksum,
        { "UDP checksum",                   "6lowpan.udp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* Broadcast header fields. */
        { &hf_6lowpan_bcast_seqnum,
        { "Sequence number",                "6lowpan.bcast.seqnum", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Mesh header fields. */
        { &hf_6lowpan_mesh_v,
        { "V",                              "6lowpan.mesh.v", FT_BOOLEAN, 8, NULL, LOWPAN_MESH_HEADER_V, "extended originator address present", HFILL }},
        { &hf_6lowpan_mesh_f,
        { "D",                              "6lowpan.mesh.f", FT_BOOLEAN, 8, NULL, LOWPAN_MESH_HEADER_F, "extended destination address present", HFILL }},
        { &hf_6lowpan_mesh_hops,
        { "Hops left",                      "6lowpan.mesh.hops", FT_UINT8, BASE_DEC, NULL, LOWPAN_MESH_HEADER_HOPS, NULL, HFILL }},
        { &hf_6lowpan_mesh_orig16,
        { "Originator",                     "6lowpan.mesh.orig16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_mesh_orig64,
        { "Originator",                     "6lowpan.mesh.orig64", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_mesh_dest16,
        { "Destination",                    "6lowpan.mesh.dest16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_mesh_dest64,
        { "Destination",                    "6lowpan.mesh.dest64", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* Fragmentation header fields. */
        { &hf_6lowpan_frag_dgram_size,
        { "Datagram size",                  "6lowpan.frag.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_frag_dgram_tag,
        { "Datagram tag",                   "6lowpan.frag.tag", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_6lowpan_frag_dgram_offset,
        { "Datagram offset",                "6lowpan.frag.offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Reassembly fields. */
        { &hf_6lowpan_fragments,
        { "Message fragments",              "6lowpan.fragments", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment,
        { "Message fragment",               "6lowpan.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_overlap,
        { "Message fragment overlap",       "6lowpan.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_overlap_conflicts,
        { "Message fragment overlapping with conflicting data", "6lowpan.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_multiple_tails,
        { "Message has multiple tail fragments", "6lowpan.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_too_long_fragment,
        { "Message fragment too long",      "6lowpan.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_fragment_error,
        { "Message defragmentation error",  "6lowpan.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_6lowpan_reassembled_in,
        { "Reassembled in",                 "6lowpan.reassembled.in",FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }}
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

    proto_6lowpan = proto_register_protocol("IPv6 over IEEE 802.15.4", "6LoWPAN", "6lowpan");
    proto_register_field_array(proto_6lowpan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissector with wireshark. */
    register_dissector("6lowpan", dissect_6lowpan, proto_6lowpan);

    /* Register the dissector init function */
    register_init_routine(proto_init_6lowpan);
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
 *      proto_reg_handoff_6lowpan
 *  DESCRIPTION
 *      Protocol handoff routine for 6LoWPAN. Called after all
 *      protocols have been loaded, and whenever any preferences
 *      are changed.
 *  PARAMETERS
 *      none            ;
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
void
proto_reg_handoff_6lowpan(void)
{
    static gboolean             init = FALSE;

    if (!init) {
        data_handle     = find_dissector("data");
        ipv6_handle     = find_dissector("ipv6");
        init = TRUE;
    }

    /* Register the 6LoWPAN dissector with IEEE 802.15.4 */
    heur_dissector_add("wpan", dissect_6lowpan_heur, proto_6lowpan);
} /* proto_reg_handoff_6lowpan */
