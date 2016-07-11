/* packet-stt.c
 *
 * Routines for Stateless Transport Tunneling (STT) packet dissection
 * Remi Vichery <remi.vichery@gmail.com>
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
 *
 * Protocol ref:
 * http://tools.ietf.org/html/draft-davie-stt-07
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/in_cksum.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>

#include "packet-ip.h"

static gboolean pref_reassemble = TRUE;
static gboolean pref_check_checksum = FALSE;

/* IANA  ref:
 * http://www.iana.org/assignments/service-names-port-numbers/service-
 * names-port-numbers.xml
 */
#define TCP_PORT_STT  7471

/* Length of entire overloaded TCP header. */
#define STT_TCP_HDR_LEN 20

/* Sum of STT header field sizes plus trailing padding. */
#define STT_HEADER_SIZE 18

#define STT_TCP_OFF_DPORT 2
#define STT_TCP_OFF_PKT_LEN 4
#define STT_TCP_OFF_SEG_OFF 6
#define STT_TCP_OFF_PKT_ID 8

#define STT_PCP_MASK    0xE000
#define STT_V_MASK      0x1000
#define STT_VLANID_MASK 0x0FFF

#define FLAG_OFFLOAD_MASK 0x02

void proto_register_stt(void);
void proto_reg_handoff_stt(void);

static int proto_stt = -1;

static int hf_stt_stream_id = -1;
static int hf_stt_dport = -1;
static int hf_stt_pkt_len = -1;
static int hf_stt_seg_off = -1;
static int hf_stt_pkt_id = -1;
static int hf_stt_checksum = -1;
static int hf_stt_checksum_status = -1;
static int hf_stt_tcp_data = -1;
static int hf_stt_tcp_data_offset = -1;
static int hf_stt_tcp_flags = -1;
static int hf_stt_tcp_rsvd = -1;
static int hf_stt_tcp_ns = -1;
static int hf_stt_tcp_cwr = -1;
static int hf_stt_tcp_ece = -1;
static int hf_stt_tcp_urg = -1;
static int hf_stt_tcp_ack = -1;
static int hf_stt_tcp_psh = -1;
static int hf_stt_tcp_rst = -1;
static int hf_stt_tcp_syn = -1;
static int hf_stt_tcp_fin = -1;
static int hf_stt_tcp_window = -1;
static int hf_stt_tcp_urg_ptr = -1;

static int hf_stt_version = -1;
static int hf_stt_flags = -1;
static int hf_stt_flag_rsvd = -1;
static int hf_stt_flag_tcp = -1;
static int hf_stt_flag_ipv4 = -1;
static int hf_stt_flag_partial = -1;
static int hf_stt_flag_verified = -1;
static int hf_stt_l4_offset = -1;
static int hf_stt_reserved_8 = -1;
static int hf_stt_mss = -1;
static int hf_stt_vlan = -1;
static int hf_stt_pcp = -1;
static int hf_stt_v = -1;
static int hf_stt_vlan_id= -1;
static int hf_stt_context_id = -1;
static int hf_stt_padding = -1;

static int hf_segments = -1;
static int hf_segment = -1;
static int hf_segment_overlap = -1;
static int hf_segment_overlap_conflict = -1;
static int hf_segment_multiple_tails = -1;
static int hf_segment_too_long_fragment = -1;
static int hf_segment_error = -1;
static int hf_segment_count = -1;
static int hf_reassembled_in = -1;
static int hf_reassembled_length = -1;

static int ett_stt = -1;
static int ett_stt_tcp_data = -1;
static int ett_stt_tcp_flags = -1;
static int ett_stt_flgs = -1;
static int ett_stt_vlan = -1;
static int ett_segment = -1;
static int ett_segments = -1;

static reassembly_table stt_reassembly_table;

static expert_field ei_stt_ver_unknown = EI_INIT;
static expert_field ei_stt_checksum_bad = EI_INIT;
static expert_field ei_stt_data_offset_bad = EI_INIT;
static expert_field ei_stt_l4_offset = EI_INIT;
static expert_field ei_stt_mss = EI_INIT;

static dissector_handle_t eth_handle;

/* From Table G-2 of IEEE standard 802.1Q-2005 */
static const value_string pri_vals[] = {
  { 1, "Background"                        },
  { 0, "Best Effort (default)"             },
  { 2, "Excellent Effort"                  },
  { 3, "Critical Applications"             },
  { 4, "Video, < 100ms latency and jitter" },
  { 5, "Voice, < 10ms latency and jitter"  },
  { 6, "Internetwork Control"              },
  { 7, "Network Control"                   },
  { 0, NULL                                }
};

static const fragment_items frag_items = {
    &ett_segment,
    &ett_segments,
    &hf_segments,
    &hf_segment,
    &hf_segment_overlap,
    &hf_segment_overlap_conflict,
    &hf_segment_multiple_tails,
    &hf_segment_too_long_fragment,
    &hf_segment_error,
    &hf_segment_count,
    &hf_reassembled_in,
    &hf_reassembled_length,
    NULL, /* Reassembled data */
    "STT segments"
};

static void
stt_segment_init(void)
{
    reassembly_table_init(&stt_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
stt_segment_cleanup(void)
{
    reassembly_table_destroy(&stt_reassembly_table);
}

static tvbuff_t *
handle_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               guint32 pkt_id, guint16 pkt_len, guint16 seg_off)
{
    fragment_head *frags;
    int offset;
    guint32 frag_data_len;
    gboolean more_frags;

    /* Skip fake TCP header after the first segment. */
    if (seg_off == 0) {
        offset = 0;
    } else {
        offset = STT_TCP_HDR_LEN;
        /* We saved the TCP header on the first packet (only), which skews the
         * segment offset. */
        seg_off += STT_TCP_HDR_LEN;
    }

    frag_data_len = tvb_reported_length_remaining(tvb, offset);
    more_frags = seg_off + frag_data_len < pkt_len;

    frags = fragment_add_check(&stt_reassembly_table, tvb, offset, pinfo,
                               pkt_id, NULL, seg_off, frag_data_len,
                               more_frags);

    /* Update reassembly fields in UI if reassembly is complete. */
    if (frags) {
        return process_reassembled_data(tvb, offset, pinfo, "Reassembled STT",
                                    frags, &frag_items, NULL, tree);
    }

    return NULL;
}

static void
dissect_stt_checksum(tvbuff_t *tvb, packet_info *pinfo, proto_tree *stt_tree)
{
    gboolean can_checksum = !pinfo->fragmented &&
                   tvb_bytes_exist(tvb, 0, tvb_reported_length(tvb));

    if (can_checksum && pref_check_checksum) {
        vec_t      cksum_vec[4];
        guint32    phdr[2];

        /* Set up the fields of the pseudo-header. */
        SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)pinfo->src.data,
                          pinfo->src.len);
        SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)pinfo->dst.data,
                          pinfo->dst.len);
        switch (pinfo->src.type) {
        case AT_IPv4:
            phdr[0] = g_htonl((IP_PROTO_TCP<<16) + tvb_reported_length(tvb));
            SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)phdr, 4);
            break;

        case AT_IPv6:
            phdr[0] = g_htonl(tvb_reported_length(tvb));
            phdr[1] = g_htonl(IP_PROTO_TCP);
            SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)phdr, 8);
            break;

        default:
            /* STT runs only atop IPv4 and IPv6.... */
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
        }
        SET_CKSUM_VEC_TVB(cksum_vec[3], tvb, 0, tvb_reported_length(tvb));

        proto_tree_add_checksum(stt_tree, tvb, 16, hf_stt_checksum, hf_stt_checksum_status, &ei_stt_checksum_bad, pinfo,
                             in_cksum(cksum_vec, 4), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    } else {
        proto_tree_add_checksum(stt_tree, tvb, 16, hf_stt_checksum, hf_stt_checksum_status, &ei_stt_checksum_bad, pinfo,
                             0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }
}

static int
dissect_tcp_flags(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    static const int *flags[] = {
        &hf_stt_tcp_rsvd,
        &hf_stt_tcp_ns,
        &hf_stt_tcp_cwr,
        &hf_stt_tcp_ece,
        &hf_stt_tcp_urg,
        &hf_stt_tcp_ack,
        &hf_stt_tcp_psh,
        &hf_stt_tcp_rst,
        &hf_stt_tcp_syn,
        &hf_stt_tcp_fin,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_stt_tcp_flags,
                           ett_stt_tcp_flags, flags, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static void
dissect_tcp_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *stt_tree)
{
    int offset = 0;
    proto_tree *tcp_tree;
    proto_item *tcp_item, *data_offset_item;
    int data_offset;

    proto_tree_add_item(stt_tree, hf_stt_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(stt_tree, hf_stt_dport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(stt_tree, hf_stt_pkt_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(stt_tree, hf_stt_seg_off, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(stt_tree, hf_stt_pkt_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    tcp_item = proto_tree_add_item(stt_tree, hf_stt_tcp_data, tvb, offset,
                                   8, ENC_NA);
    tcp_tree = proto_item_add_subtree(tcp_item, ett_stt_tcp_data);
    proto_item_set_text(tcp_item, "TCP Data");

    data_offset = hi_nibble(tvb_get_guint8(tvb, offset)) * 4;
    data_offset_item = proto_tree_add_uint_format_value(tcp_tree,
                                                        hf_stt_tcp_data_offset,
                                                        tvb, offset, 1,
                                                        data_offset,
                                                        "%u bytes", data_offset);
    if (data_offset != STT_TCP_HDR_LEN) {
        expert_add_info(pinfo, data_offset_item, &ei_stt_data_offset_bad);
    }

    offset = dissect_tcp_flags(tcp_tree, tvb, offset);

    proto_tree_add_item(tcp_tree, hf_stt_tcp_window, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 2;

    dissect_stt_checksum(tvb, pinfo, stt_tree);
    offset += 2;

    proto_tree_add_item(tcp_tree, hf_stt_tcp_urg_ptr, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
}

static int
dissect_stt_flags(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    static const int *flags[] = {
        &hf_stt_flag_rsvd,
        &hf_stt_flag_tcp,
        &hf_stt_flag_ipv4,
        &hf_stt_flag_partial,
        &hf_stt_flag_verified,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_stt_flags,
                           ett_stt_flgs, flags, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static void
dissect_stt_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *stt_tree,
                 proto_item *stt_item)
{
    proto_tree *vlan_tree;
    proto_item *ver_item, *l4_offset_item, *vlan_item, *mss_item;
    guint8 flags;
    guint32 version, l4_offset, mss, attributes;
    guint64 context_id;
    int offset = STT_TCP_HDR_LEN;

    /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Version      | Flags         |  L4 Offset    |  Reserved     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Max. Segment Size          | PCP |V|     VLAN ID           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                     Context ID (64 bits)                      +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Padding                   |    Data                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
       |                                                               |
    */

    /* Protocol version */
    ver_item = proto_tree_add_item_ret_uint(stt_tree, hf_stt_version, tvb,
                                            offset, 1, ENC_BIG_ENDIAN, &version);
    if (version != 0) {
        expert_add_info_format(pinfo, ver_item, &ei_stt_ver_unknown,
                               "Unknown version %u", version);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown STT version %u", version);
    }
    offset++;

    /* Flags */
    flags = tvb_get_guint8(tvb, offset);
    offset = dissect_stt_flags(stt_tree, tvb, offset);

    /* Layer 4 offset */
    l4_offset_item = proto_tree_add_item_ret_uint(stt_tree, hf_stt_l4_offset,
                                                  tvb, offset, 1,
                                                  ENC_BIG_ENDIAN, &l4_offset);
    /* Display an error if offset is != 0 when offloading is not in use */
    if ( !(flags & FLAG_OFFLOAD_MASK) && (l4_offset != 0) ) {
        expert_add_info_format(pinfo, l4_offset_item, &ei_stt_l4_offset, "Incorrect offset, should be equal to zero");
    }
    /* Display an error if offset equals 0 when there is offloading */
    if ( (flags & FLAG_OFFLOAD_MASK) && (l4_offset == 0) ) {
        expert_add_info_format(pinfo, l4_offset_item, &ei_stt_l4_offset, "Incorrect offset, should be greater than zero");
    }
    offset ++;

    /* Reserved field (1 byte). MUST be 0 on transmission,
    ignored on receipt. */
    proto_tree_add_item(stt_tree, hf_stt_reserved_8, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset ++;

    /* Maximum Segment Size. MUST be 0 if segmentation offload
    is not in use. */
    mss_item = proto_tree_add_item_ret_uint(stt_tree, hf_stt_mss, tvb,
                                            offset, 2, ENC_BIG_ENDIAN, &mss);
    /* Display an error if MSS is != 0 when offloading is not in use */
    if ( !(flags & FLAG_OFFLOAD_MASK) && (mss != 0) ) {
        expert_add_info_format(pinfo, mss_item, &ei_stt_mss, "Incorrect max segment size, should be equal to zero");
    }
    offset += 2;

    /* Tag Control Information like header. If V flag is set, it
       indicates the presence of a valid VLAN ID in the following field
       and valid PCP in the preceding field. */
    vlan_item = proto_tree_add_item_ret_uint(stt_tree, hf_stt_vlan, tvb, offset,
                                             2, ENC_BIG_ENDIAN, &attributes);
    vlan_tree = proto_item_add_subtree(vlan_item, ett_stt_vlan);
    proto_item_set_text(vlan_item, "VLAN Priority %u, ID %u",
                        (attributes >> 13), (attributes & STT_VLANID_MASK));

    proto_tree_add_item(vlan_tree, hf_stt_pcp, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(vlan_tree, hf_stt_v, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(vlan_tree, hf_stt_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (attributes & STT_V_MASK) {
        /* Display priority code point and VLAN ID when V flag is set */
        proto_item_append_text(stt_item, ", Priority: %u, VLAN ID: %u",
                               attributes >> 13,
                               attributes & STT_VLANID_MASK);
    }
    /* Show if any part of this is set to aid debugging bad implementations. */
    if (attributes == 0) {
        PROTO_ITEM_SET_HIDDEN(vlan_item);
    }
    offset += 2;

    /* Context ID */
    context_id = tvb_get_ntoh64(tvb, offset);
    proto_tree_add_item(stt_tree, hf_stt_context_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    proto_item_append_text(stt_item, ", Context ID: 0x%" G_GINT64_MODIFIER "x",
                           context_id);
    offset += 8;

    /* Padding */
    proto_tree_add_item(stt_tree, hf_stt_padding, tvb, offset,
                        2, ENC_BIG_ENDIAN);
}

static void
dissect_stt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *stt_item;
    proto_tree *stt_tree;
    tvbuff_t *next_tvb;
    guint16 seg_off, pkt_len, rx_bytes;
    guint8 sub_off;
    gboolean frag_save, is_seg;

    /* Make entry in Protocol column on summary display. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STT");
    col_clear(pinfo->cinfo, COL_INFO);

    stt_item = proto_tree_add_item(tree, proto_stt, tvb, 0,
                                   STT_TCP_HDR_LEN, ENC_NA);
    stt_tree = proto_item_add_subtree(stt_item, ett_stt);

    dissect_tcp_tree(tvb, pinfo, stt_tree);

    frag_save = pinfo->fragmented;

    seg_off = tvb_get_ntohs(tvb, STT_TCP_OFF_SEG_OFF);
    pkt_len = tvb_get_ntohs(tvb, STT_TCP_OFF_PKT_LEN);
    rx_bytes = tvb_reported_length_remaining(tvb, STT_TCP_HDR_LEN);
    is_seg = pkt_len > rx_bytes;

    if (is_seg) {
        guint32 pkt_id = tvb_get_ntohl(tvb, STT_TCP_OFF_PKT_ID);

        pinfo->fragmented = TRUE;
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "STT Segment (ID: 0x%x Len: %hu, Off: %hu)",
                      pkt_id, pkt_len, seg_off);

        /* Reassemble segments unless the user has disabled reassembly. */
        if (pref_reassemble && tvb_bytes_exist(tvb, 0, rx_bytes)) {
            tvbuff_t *reasm_tvb;

            reasm_tvb = handle_segment(tvb, pinfo, stt_tree, pkt_id,
                                       pkt_len, seg_off);
            if (reasm_tvb) {
                tvb = reasm_tvb;
                pinfo->fragmented = frag_save;
                is_seg = FALSE;
            }
        } else if (seg_off == 0) {
           /* If we're not reassembling, move ahead as if we have the
            *  whole frame. */
            is_seg = FALSE;
        }
    }

    /* Only full packets have a STT header (following the fake TCP header). */
    if (!is_seg) {
        sub_off = STT_TCP_HDR_LEN + STT_HEADER_SIZE;
        dissect_stt_tree(tvb, pinfo, stt_tree, stt_item);
    } else {
        sub_off = STT_TCP_HDR_LEN;
    }

    if (seg_off == 0) {
        proto_item_set_len(stt_item, sub_off);
    }
    next_tvb = tvb_new_subset_remaining(tvb, sub_off);

    /* Only dissect inner frame if not segmented or if we aren't
       doing reassembly. */
    if (!is_seg) {
        call_dissector(eth_handle, next_tvb, pinfo, tree);
    } else {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    pinfo->fragmented = frag_save;
}

static gboolean
dissect_stt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 void *data)
{
    ws_ip *iph = (ws_ip*)data;

    /* Make sure we at least have a TCP header */
    if (iph->ip_nxt != IP_PROTO_TCP ||
        tvb_captured_length(tvb) < STT_TCP_HDR_LEN) {
        return FALSE;
    }

    /* Check the TCP destination port */
    if (tvb_get_ntohs(tvb, STT_TCP_OFF_DPORT) != TCP_PORT_STT) {
        return FALSE;
    }

    dissect_stt(tvb, pinfo, tree);
    return TRUE;
}

/* Register STT with Wireshark */
void
proto_register_stt(void)
{
    expert_module_t* expert_stt;
    module_t *stt_prefs;

    static hf_register_info hf[] = {
        /* Overloaded fake TCP header fields. */
        { &hf_stt_stream_id,
          { "Stream ID", "stt.stream_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_stt_dport,
          { "Destination Port", "stt.dport",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_stt_pkt_len,
          { "Packet Length", "stt.pkt_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_stt_seg_off,
          { "Segment Offset", "stt.seg_off",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_stt_pkt_id,
          { "Packet ID", "stt.pkt_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_stt_tcp_data,
          { "TCP Data", "stt.tcp",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_data_offset,
          { "Data Offset", "stt.tcp.data_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_flags,
          { "Flags", "stt.tcp.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_rsvd,
          { "Reserved", "stt.tcp.flags.rsvd",
            FT_BOOLEAN, 12, NULL, 0x0E00,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_ns,
          { "Nonce", "stt.tcp.flags.ns",
            FT_BOOLEAN, 12, NULL, 0x0100,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_cwr,
          { "Congestion Window Reduced (CWR)", "stt.tcp.flags.cwr",
            FT_BOOLEAN, 12, NULL, 0x0080,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_ece,
          { "ECN-Echo", "stt.tcp.flags.ece",
            FT_BOOLEAN, 12, NULL, 0x0040,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_urg,
          { "Urgent", "stt.tcp.flags.urg",
            FT_BOOLEAN, 12, NULL, 0x0020,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_ack,
          { "Acknowledgement", "stt.tcp.flags.ack",
            FT_BOOLEAN, 12, NULL, 0x0010,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_psh,
          { "Push", "stt.tcp.flags.psh",
            FT_BOOLEAN, 12, NULL, 0x0008,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_rst,
          { "Reset", "stt.tcp.flags.rst",
            FT_BOOLEAN, 12, NULL, 0x0004,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_syn,
          { "Syn", "stt.tcp.flags.syn",
            FT_BOOLEAN, 12, NULL, 0x0002,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_fin,
          { "Fin", "stt.tcp.flags.fin",
            FT_BOOLEAN, 12, NULL, 0x0001,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_window,
          { "Window", "stt.tcp.window",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_tcp_urg_ptr,
          { "Urgent Pointer", "stt.tcp.urg_ptr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL,
          },
        },

        /* STT header fields. */
        { &hf_stt_version,
          { "Version", "stt.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_stt_flags,
          { "Flags", "stt.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_rsvd,
          { "Reserved", "stt.flags.rsvd",
            FT_BOOLEAN, 8, NULL, 0xF0,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_tcp,
          { "TCP payload", "stt.flags.tcp",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_ipv4,
          { "IPv4 packet", "stt.flags.ipv4",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_partial,
          { "Checksum partial", "stt.flags.csum_partial",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_verified,
          { "Checksum verified", "stt.flags.csum_verified",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL,
          },
        },
        { &hf_stt_l4_offset,
          { "L4 Offset", "stt.l4offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_reserved_8,
          { "Reserved", "stt.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_mss,
          { "Max Segment Size", "stt.mss",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_vlan,
          { "VLAN", "stt.vlan",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_pcp,
          { "PCP", "stt.vlan.pcp",
            FT_UINT16, BASE_DEC, VALS(pri_vals), STT_PCP_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_v,
          { "V flag", "stt.vlan.v",
            FT_UINT16, BASE_DEC, NULL, STT_V_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_vlan_id,
          { "VLAN ID", "stt.vlan.id",
            FT_UINT16, BASE_DEC, NULL, STT_VLANID_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_context_id,
          { "Context ID", "stt.context_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL,
          },
        },
        { &hf_stt_padding,
          { "Padding", "stt.padding",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL,
          },
        },

        /* Checksum validation fields */
        { &hf_stt_checksum,
          { "Checksum", "stt.checksum",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL
          },
        },
        { &hf_stt_checksum_status,
          { "Checksum Status", "stt.checksum.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL
          },
        },

        /* Segment reassembly information. */
        { &hf_segment_overlap,
          { "Segment overlap", "stt.segment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL
          },
        },
        { &hf_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "stt.segment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping segments contained conflicting data", HFILL
          },
        },
        { &hf_segment_multiple_tails,
          { "Multiple tail segments found", "stt.segment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the packet", HFILL
          },
        },
        { &hf_segment_too_long_fragment,
          { "Segment too long", "stt.segment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of the packet", HFILL
          },
        },
        { &hf_segment_error,
          { "Reassembling error", "stt.segment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembling error due to illegal segments", HFILL
          },
        },
        { &hf_segment_count,
          { "Segment count", "stt.segment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_segment,
          { "STT Segment", "stt.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL
          },
        },
        { &hf_segments,
          { "Reassembled STT Segments", "stt.segments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "STT Segments", HFILL
          },
        },
        { &hf_reassembled_in,
          { "Reassembled PDU in frame", "stt.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The STT packet is reassembled in this frame", HFILL
          },
        },
        { &hf_reassembled_length,
          { "Reassembled STT length", "stt.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL
          },
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_stt,
        &ett_stt_tcp_data,
        &ett_stt_tcp_flags,
        &ett_stt_flgs,
        &ett_stt_vlan,
        &ett_segment,
        &ett_segments
    };

    static ei_register_info ei[] = {
        { &ei_stt_checksum_bad,
          { "stt.checksum_bad.expert", PI_CHECKSUM,
            PI_ERROR, "Bad checksum", EXPFILL
          }
        },
        { &ei_stt_data_offset_bad,
          { "stt.data_offset_bad.expert", PI_PROTOCOL,
            PI_WARN, "TCP Data Offset should be 20 bytes", EXPFILL
          }
        },
        { &ei_stt_ver_unknown,
          { "stt.version_unknown.expert", PI_PROTOCOL,
            PI_WARN, "Unknown version", EXPFILL
          }
        },
        { &ei_stt_l4_offset,
          { "stt.l4offset_bad.expert", PI_PROTOCOL,
            PI_WARN, "Bad L4 Offset", EXPFILL
          }
        },
        { &ei_stt_mss,
          { "stt.mss_bad.expert", PI_PROTOCOL,
            PI_WARN, "Bad MSS", EXPFILL
          }
        },
    };

    /* Register the protocol name and description */
    proto_stt = proto_register_protocol("Stateless Transport Tunneling",
                                          "STT", "stt");

    expert_stt = expert_register_protocol(proto_stt);
    expert_register_field_array(expert_stt, ei, array_length(ei));

    /* Required function calls to register the header fields and
    subtrees used */
    proto_register_field_array(proto_stt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    stt_prefs = prefs_register_protocol(proto_stt, NULL);
    prefs_register_bool_preference(stt_prefs, "reassemble",
                                   "Reassemble segmented STT packets",
                                   "Reassembles greater than MTU sized STT packets broken into segments on transmit",
                                   &pref_reassemble);
    prefs_register_bool_preference(stt_prefs, "check_checksum",
                                   "Validate the STT checksum if possible",
                                   "Whether to validate the STT checksum or not.",
                                   &pref_check_checksum);

    register_init_routine(stt_segment_init);
    register_cleanup_routine(stt_segment_cleanup);
}

void
proto_reg_handoff_stt(void)
{
    /*
     * The I-D doesn't explicity indicate that the FCS isn't present
     * in the tunneled Ethernet frames, but it is missing from the
     * captures attached to bug 10282.
     */
    eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_stt);

    heur_dissector_add("ip", dissect_stt_heur, "Stateless Transport Tunneling over IP", "stt_ip", proto_stt, HEURISTIC_ENABLE);
}

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
