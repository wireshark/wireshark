/* packet-rohc.c
 * Routines for RObust Header Compression (ROHC) dissection.
 *
 * Copyright 2011, Anders Broman <anders.broman[at]ericsson.com>
 *                 Per Liedberg  <per.liedberg [at]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref:
 * https://www.ietf.org/rfc/rfc3095             RObust Header Compression (ROHC): Framework and four profiles: RTP, UDP, ESP, and uncompressed
 * https://datatracker.ietf.org/doc/rfc4815/    RObust Header Compression (ROHC): Corrections and Clarifications to RFC 3095
 * https://datatracker.ietf.org/doc/rfc5225/    RObust Header Compression Version 2 (ROHCv2): Profiles for RTP, UDP, IP, ESP and UDP-Lite
 *
 * Only RTP (1) and UDP (2) are currently implemented.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/rtp_pt.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include "packet-rohc.h"

void proto_register_rohc(void);
void proto_reg_handoff_rohc(void);

static int
dissect_compressed_list(int expected_encoding_type _U_, packet_info *pinfo _U_,
                        proto_tree *tree, tvbuff_t *tvb, int offset);

/* cid -> rohc_cid_context_t* */
static GHashTable *rohc_cid_hash;

/* Initialize the protocol and registered fields */
static int proto_rohc;


static int hf_rohc_padding;
static int hf_rohc_add_cid;
static int hf_rohc_feedback;
static int hf_rohc_code;
static int hf_rohc_size;
static int hf_rohc_ir_packet;
static int hf_rohc_ir_dyn_packet;
static int hf_rohc_small_cid;
static int hf_rohc_large_cid;
static int hf_rohc_acktype;
static int hf_rohc_mode;
static int hf_rohc_sn;
static int hf_rohc_profile_spec_octet;
static int hf_rohc_fb1_sn;
static int hf_rohc_opt_type;
static int hf_rohc_opt_len;
static int hf_rohc_crc;
static int hf_rohc_opt_sn;
static int hf_rohc_ext;
static int hf_rohc_ext_sn;
static int hf_rohc_opt_clock;
static int hf_rohc_opt_jitter;
static int hf_rohc_opt_loss;
static int hf_rohc_profile;
static int hf_rohc_d_bit;
static int hf_rohc_ip_version;
static int hf_rohc_ip_version_ip_profile;
static int hf_rohc_ip_protocol;
static int hf_rohc_static_ipv4;
static int hf_rohc_ipv4_src;
static int hf_rohc_ipv4_dst;
static int hf_rohc_ipv6_flow;
static int hf_rohc_ipv6_nxt_hdr;
static int hf_rohc_ipv6_src;
static int hf_rohc_ipv6_dst;
static int hf_rohc_static_udp;
static int hf_rohc_udp_src_port;
static int hf_rohc_udp_dst_port;
static int hf_rohc_static_rtp;
static int hf_rohc_rtp_ssrc;
static int hf_rohc_dynamic_ipv4;
static int hf_rohc_dynamic_udp;
static int hf_rohc_rtp_tos;
static int hf_rohc_rtp_ttl;
static int hf_rohc_rtp_id;
static int hf_rohc_rtp_df;
static int hf_rohc_rtp_rnd;
static int hf_rohc_rtp_nbo;
static int hf_rohc_dynamic_udp_checksum;
static int hf_rohc_dynamic_rtp;
static int hf_rohc_rtp_v;
static int hf_rohc_rtp_p;
static int hf_rohc_rtp_rx;
static int hf_rohc_rtp_cc;
static int hf_rohc_rtp_m;
static int hf_rohc_rtp_pt;
static int hf_rohc_rtp_sn;
static int hf_rohc_rtp_timestamp;
static int hf_rohc_rtp_x;
static int hf_rohc_rtp_mode;
static int hf_rohc_rtp_tis;
static int hf_rohc_rtp_tss;
static int hf_rohc_rtp_ts_stride;
static int hf_rohc_rtp_time_stride;
static int hf_rohc_var_len;
static int hf_rohc_ipv6_tc;
static int hf_rohc_ipv6_hop_limit;
static int hf_rohc_ir_pkt_frame;
static int hf_rohc_ir_previous_frame;
static int hf_rohc_ir_profile;
static int hf_rohc_ir_ip_version;
static int hf_rohc_ir_mode;
static int hf_rohc_comp_sn;
static int hf_rohc_r_0_crc;
static int hf_rohc_x;
static int hf_rohc_ts;
static int hf_rohc_comp_ip_id;
static int hf_rohc_comp_ip_id2;
static int hf_rohc_t;
static int hf_rohc_ext3_flags;
static int hf_rohc_ext3_s;
static int hf_rohc_ext3_r_ts;
static int hf_rohc_ext3_tsc;
static int hf_rohc_ext3_udp_mode;
static int hf_rohc_ext3_i;
static int hf_rohc_ext3_ip;
static int hf_rohc_ext3_ip2;
static int hf_rohc_ext3_rtp;
static int hf_rohc_ext3_inner_ip_flags;
static int hf_rohc_ext3_inner_tos;
static int hf_rohc_ext3_inner_ttl;
static int hf_rohc_ext3_inner_df;
static int hf_rohc_ext3_inner_pr;
static int hf_rohc_ext3_inner_ipx;
static int hf_rohc_ext3_inner_nbo;
static int hf_rohc_ext3_inner_rnd;
static int hf_rohc_ext3_inner_ip2;
static int hf_rohc_ext3_outer_ip_flags;
static int hf_rohc_ext3_outer_tos;
static int hf_rohc_ext3_outer_ttl;
static int hf_rohc_ext3_outer_df;
static int hf_rohc_ext3_outer_pr;
static int hf_rohc_ext3_outer_ipx;
static int hf_rohc_ext3_outer_nbo;
static int hf_rohc_ext3_outer_rnd;
static int hf_rohc_ext3_outer_i2;
static int hf_rohc_ext3_rtp_flags;
static int hf_rohc_ext3_rtp_mode;
static int hf_rohc_ext3_r_pt;
static int hf_rohc_ext3_m;
static int hf_rohc_ext3_r_x;
static int hf_rohc_ext3_csrc;
static int hf_rohc_ext3_tss;
static int hf_rohc_ext3_tis;
static int hf_rohc_ext3_r_p;

static int hf_rohc_compressed_list;
static int hf_rohc_compressed_list_et;
static int hf_rohc_compressed_list_gp;
static int hf_rohc_compressed_list_ps;
static int hf_rohc_compressed_list_res;
static int hf_rohc_compressed_list_count;
static int hf_rohc_compressed_list_cc;
static int hf_rohc_compressed_list_xi_1;
static int hf_rohc_compressed_list_gen_id;
static int hf_rohc_compressed_list_ref_id;
static int hf_rohc_compressed_list_mask_size;
static int hf_rohc_compressed_list_ins_bit_mask;
static int hf_rohc_compressed_list_rem_bit_mask;
static int hf_rohc_spare_bits;
static int hf_rohc_ip_id;
static int hf_rohc_udp_checksum;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_rohc_no_configuration_info;
static int hf_rohc_unknown_option_data;
static int hf_rohc_error_packet;
static int hf_rohc_configured_by_ir_packet;

static int ett_rohc;
static int ett_rohc_conf;
static int ett_rohc_fb;
static int ett_rohc_feedback;
static int ett_rohc_ir;
static int ett_rohc_ir_dyn;
static int ett_rohc_static_ipv4;
static int ett_rohc_static_udp;
static int ett_rohc_static_rtp;
static int ett_rohc_rtp_static;
static int ett_rohc_rtp_dynamic;
static int ett_rohc_dynamic_ipv4;
static int ett_rohc_dynamic_udp;
static int ett_rohc_dynamic_rtp;
static int ett_rohc_compressed_list;
static int ett_rohc_packet;
static int ett_rohc_ext;
static int ett_rohc_ext3_flags;
static int ett_rohc_ext3_inner_ip_flags;
static int ett_rohc_ext3_outer_ip_flags;
static int ett_rohc_ext3_rtp_flags;

static expert_field ei_rohc_profile_spec_octet;
static expert_field ei_rohc_rohc_opt_clock;
static expert_field ei_rohc_opt_jitter;
static expert_field ei_rohc_feedback_type_2_is_not_applicable_for_uncompressed_profile;
static expert_field ei_rohc_not_dissected_yet;
static expert_field ei_rohc_profile_specific;
static expert_field ei_rohc_profile_not_supported;
static expert_field ei_rohc_ip_version;
static expert_field ei_rohc_desegmentation_not_implemented;

static dissector_handle_t rohc_handle;

static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

enum rohc_d_mode
{
  NO_CONTEXT = 1,
  STATIC_CONTEXT = 2,
  FULL_CONTEXT = 3
};

typedef struct _rohc_cid_context_t
{
    uint8_t            rohc_ip_version;
    bool               large_cid_present;
    enum rohc_mode     mode;
    enum rohc_d_mode   d_mode;                 /* Decompressor mode (not used) */
    bool               rnd;
    bool               udp_checksum_present;
    uint16_t           profile;
    int                prev_ir_frame_number;   /* The frame number of the previous IR packet seen. -1 if not set */
    int                ir_frame_number;        /* The frame number of the latest IR packet seen. -1 if not set */

} rohc_cid_context_t;

static const value_string rohc_profile_vals[] =
{
    { 0x0000,    "Uncompressed" },           /*RFC 5795*/
    { 0x0001,    "RTP" },                    /*RFC 3095*/
    { 0x0002,    "UDP" },                    /*RFC 3095*/
    { 0x0003,    "ESP" },                    /*RFC 3095*/
    { 0x0004,    "IP" },                     /*RFC 3843*/
    { 0x0005,    "LLA" },                    /*RFC 3242*/
    { 0x0105,    "LLA with R-mode" },        /*RFC 3408*/
    { 0x0006,    "TCP" },                    /*RFC 4996*/
    { 0x0007,    "RTP/UDP-Lite" },           /*RFC 4019*/
    { 0x0008,    "UDP-Lite" },               /*RFC 4019*/
    { 0x0101,    "v2 RTP" },                 /*RFC 5225*/
    { 0x0102,    "v2 UDP" },                 /*RFC 5225*/
    { 0x0103,    "v2 ESP" },                 /*RFC 5225*/
    { 0x0104,    "v2 IP" },                  /*RFC 5225*/
    { 0x0107,    "v2 RTP/UDP-Lite" },        /*RFC 5225*/
    { 0x0108,    "v2 UDP-Lite" },            /*RFC 5225*/
    { 0, NULL },
};

/* Defaults if not supplied */
static uint16_t g_profile = ROHC_PROFILE_UNKNOWN;
static uint8_t g_version = 4;

static const value_string rohc_acktype_vals[] =
{
    { 0,    "ACK" },
    { 1,    "NACK" },
    { 2,    "STATIC-NACK" },
    { 3,    "reserved (MUST NOT be used.  Otherwise unparsable.)" },
    { 0, NULL },
};

static const value_string rohc_mode_vals[] =
{
    { 0,    "Reserved" },
    { 1,    "Unidirectional" },
    { 2,    "Bidirectional Optimistic" },
    { 3,    "Bidirectional Reliable" },
    { 0, NULL },
};

static const value_string rohc_opt_type_vals[] =
{
    { 1,    "CRC" },
    { 2,    "REJECT" },
    { 3,    "SN-NOT-VALID" },
    { 4,    "SN" },
    { 5,    "CLOCK" },
    { 6,    "JITTER" },
    { 7,    "LOSS" },
    { 0, NULL },
};



static const value_string rohc_ip_version_vals[] =
{
    { 0,    "Unknown" },
    { 4,    "IPv4" },
    { 6,    "IPv6" },
    { 0, NULL },
};

static const value_string rohc_ip_version_ip_profile_vals[] =
{
    { 0x4,    "IPv4" },
    { 0x6,    "IPv6" },
    { 0xc,    "IPv4" },
    { 0xe,    "IPv6" },
    { 0, NULL },
};

static const value_string rohc_var_len_vals[] =
{
    { 0,    "One octet" },
    { 2,    "Two octets" },
    { 6,    "Three octets" },
    { 7,    "Four octets" },
    { 0, NULL },
};

static const value_string compressed_list_encoding_type_vals[] =
{
    { 0,    "Generic scheme" },
    { 1,    "Insertion only scheme" },
    { 2,    "Removal only scheme" },
    { 3,    "Remove then insert scheme" },
    { 0, NULL },
};

static const value_string compressed_list_ps_vals[] =
{
    { 0,    "4-bit XI fields" },
    { 1,    "8-bit XI fields" },
    { 0, NULL },
};

/* RTP extension 3 flags masks */
#define ROHC_RTP_EXT3_FLAGS_MASK        0x7f
#define ROHC_RTP_EXT3_S_MASK            0x20
#define ROHC_RTP_EXT3_R_TS_MASK         0x10
#define ROHC_RTP_EXT3_TSC_MASK          0x08
#define ROHC_RTP_EXT3_I_MASK            0x04
#define ROHC_RTP_EXT3_IP_MASK           0x02
#define ROHC_RTP_EXT3_RTP_MASK          0x01
/* RTP Inner IP header flags masks */
#define ROHC_RTP_EXT3_INNER_TOS_MASK    0x80
#define ROHC_RTP_EXT3_INNER_TTL_MASK    0x40
#define ROHC_RTP_EXT3_INNER_DF_MASK     0x20
#define ROHC_RTP_EXT3_INNER_PR_MASK     0x10
#define ROHC_RTP_EXT3_INNER_IPX_MASK    0x08
#define ROHC_RTP_EXT3_INNER_NBO_MASK    0x04
#define ROHC_RTP_EXT3_INNER_RND_MASK    0x02
#define ROHC_RTP_EXT3_INNER_IP2_MASK    0x01
/* RTP Outer IP header flags masks */
#define ROHC_RTP_EXT3_OUTER_TOS_MASK    0x80
#define ROHC_RTP_EXT3_OUTER_TTL_MASK    0x40
#define ROHC_RTP_EXT3_OUTER_DF_MASK     0x20
#define ROHC_RTP_EXT3_OUTER_PR_MASK     0x10
#define ROHC_RTP_EXT3_OUTER_IPX_MASK    0x08
#define ROHC_RTP_EXT3_OUTER_NBO_MASK    0x04
#define ROHC_RTP_EXT3_OUTER_RND_MASK    0x02
#define ROHC_RTP_EXT3_OUTER_I2_MASK     0x01
/* RTP header flags masks */
#define ROHC_RTP_EXT3_RTP_MODE_MASK     0xc0
#define ROHC_RTP_EXT3_R_PT_MASK         0x20
#define ROHC_RTP_EXT3_M_MASK            0x10
#define ROHC_RTP_EXT3_R_X_MASK          0x08
#define ROHC_RTP_EXT3_CSRC_MASK         0x04
#define ROHC_RTP_EXT3_TSS_MASK          0x02
#define ROHC_RTP_EXT3_TIS_MASK          0x01
/* RTP header fields masks */
#define ROHC_RTP_EXT3_R_P_MASK          0x80

/* UDP extension 3 flag masks */
#define ROHC_UDP_EXT3_UDP_MODE_MASK     0x18
#define ROHC_UDP_EXT3_IP2_MASK          0x01


/* 4.5.6.  Self-describing variable-length values */
static uint32_t
get_self_describing_var_len_val(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, uint8_t *val_len)
{
    uint8_t oct;
    uint32_t val = 0;
    int     num_bits = 0, bit_offset = offset <<3;

    /* Get first byte */
    oct = tvb_get_uint8(tvb, offset);

    if ((oct&0x80)==0) {
        /* First bit is 0 - 1 octet */
        *val_len = 1;
        val = (oct&0x7f);
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        num_bits = 7;
        bit_offset++;
    } else if ((oct&0xc0)==0x80) {
        /* First bits are 10: 2 octets */
        *val_len = 2;
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset+=2;
        num_bits = 14;
        val = tvb_get_ntohs(tvb, offset)&0x3fff;
    } else if ((oct&0xe0)==0xc0) {
        /* First bits are 110: 3 octets */
        *val_len = 3;
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset+=3;
        num_bits = 21;
        val = tvb_get_ntoh24(tvb, offset)&0x1fffff;
    } else if ((oct&0xe0)==0xe0) {
        /* First bits are 111: 4 octets */
        *val_len = 4;
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset+=3;
        num_bits = 29;
        val = tvb_get_ntohl(tvb, offset)&0x1fffffff;
    }

    /* Add the field */
    proto_tree_add_bits_item(tree, hf_index, tvb, bit_offset, num_bits, ENC_BIG_ENDIAN);

    return val;
}

/* 5.7.1. Packet type 0: UO-0, R-0, R-0-CRC */
static int
dissect_rohc_pkt_type_0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t pkt_type, rohc_cid_context_t *rohc_cid_context)
{
    uint8_t val_len = 0;
    uint64_t sn;
    proto_tree *pkt_tree;

    switch (rohc_cid_context->mode) {
        case RELIABLE_BIDIRECTIONAL: /* R-mode */
            if ((pkt_type&0xc0)==0x00) {
            /*   R-0
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 0   0 |          SN           |
                *   +===+===+===+===+===+===+===+===+
                */
                if (rohc_cid_context->large_cid_present == true) {
                    /* Handle Large CID:s here */
                    get_self_describing_var_len_val(tvb, tree, offset+1, hf_rohc_large_cid, &val_len);
                }
                /* R-0 subtree */
                col_append_str(pinfo->cinfo, COL_INFO, "R-0");
                pkt_tree = proto_tree_add_subtree(tree, tvb, offset, 1+val_len, ett_rohc_packet, NULL, "R-0 packet");

                /* SN */
                sn = tvb_get_bits8(tvb,(offset<<3)+2, 6);
                proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
                offset += 1 + val_len;

                /* Show SN in info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", (unsigned)sn);
            } else if ((pkt_type&0xc0)==0x40) {
            /*   R-0-CRC
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 0   1 |          SN           |
                *   +===+===+===+===+===+===+===+===+
                *   |SN |            CRC            |
                *   +---+---+---+---+---+---+---+---+
                */
                crumb_spec_t rohc_sn_crumbs[] = {
                    { 2, 6},
                    { 8, 1},
                    { 0, 0}
                };
                if (rohc_cid_context->large_cid_present) {
                    /* Handle Large CID:s here */
                    get_self_describing_var_len_val(tvb, tree, offset+1, hf_rohc_large_cid, &val_len);
                    rohc_sn_crumbs[1].crumb_bit_offset += val_len*8;
                }
                /* R-0-CRC subtree */
                col_append_str(pinfo->cinfo, COL_INFO, "R-0-CRC");
                pkt_tree = proto_tree_add_subtree(tree, tvb, offset, 2+val_len, ett_rohc_packet, NULL, "R-0-CRC packet");
                /* SN */
                proto_tree_add_split_bits_item_ret_val(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3),
                                                       rohc_sn_crumbs, &sn);
                offset += (1 + val_len);

                /* CRC */
                proto_tree_add_bits_item(pkt_tree, hf_rohc_r_0_crc, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
                offset++;

                /* Show SN in info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", (unsigned)sn);
            }
            break;
        case UNIDIRECTIONAL: /* U-mode */
            /* Fall trough */
        case OPTIMISTIC_BIDIRECTIONAL: /* O-mode */
            /*   UO-0
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 0 |      SN       |    CRC    |
                *   +===+===+===+===+===+===+===+===+
                */
            if (rohc_cid_context->large_cid_present == true) {
                /* Handle Large CID:s here */
                get_self_describing_var_len_val(tvb, tree, offset+1, hf_rohc_large_cid, &val_len);
            }
            /* UO-0 subtree */
            col_append_str(pinfo->cinfo, COL_INFO, "UO-0");
            pkt_tree = proto_tree_add_subtree(tree, tvb, offset, 1+val_len, ett_rohc_packet, NULL, "UO-0 packet");

            /* SN */
            sn = tvb_get_bits8(tvb,(offset<<3)+1, 4);
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+1, 4, ENC_BIG_ENDIAN);

            /* CRC */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_r_0_crc, tvb, (offset<<3)+5, 3, ENC_BIG_ENDIAN);
            offset += 1 + val_len;

            /* Show SN in info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", (unsigned)sn);
            break;

        default:
            col_append_str(pinfo->cinfo, COL_INFO, "Packet type 0");
            break;
    }

    return offset;
}

/* 5.7.5. Extension formats */
/* UDP profile extension variations as described in 5.11.4 */
static int
dissect_rohc_ext_format(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                        uint8_t t, /* T-bit from base compressed header */
                        rohc_cid_context_t *rohc_cid_context)
{
    /* Extension subtree */
    int start_offset = offset;
    proto_item *ext_ti = proto_tree_add_string_format(tree,
                                                      hf_rohc_ext,
                                                      tvb, offset, 0,
                                                      "", "Extension");
    proto_tree *ext_tree = proto_item_add_subtree(ext_ti, ett_rohc_ext);


    uint8_t ext_type = (tvb_get_uint8(tvb, offset) & 0xc0) >> 6;

    if (ext_type != 3) {
        /* SN (common to extensions 0,1,2) */
        proto_tree_add_bits_item(ext_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 3, ENC_BIG_ENDIAN);
    }

    if (ext_type == 0) {
        /*   Extension 0:
             RTP
            *     0   1   2   3   4   5   6   7
            *   +---+---+---+---+---+---+---+---+
            *   | 0   0 |    SN     |    +T     |
            *   +---+---+---+---+---+---+---+---+
            *
             UDP
            *
            *  +---+---+---+---+---+---+---+---+
            *  | 0   0 |    SN     |   IP-ID   |
            *  +---+---+---+---+---+---+---+---+
            *
            */
        proto_item_append_text(ext_ti, " 0");

        if ((t == 0) || (rohc_cid_context->profile == ROHC_PROFILE_UDP)) {
            /* IP-ID */
            proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+5, 3, ENC_BIG_ENDIAN);
        } else {
            /* TS */
            proto_tree_add_bits_item(ext_tree, hf_rohc_ts, tvb, (offset<<3)+5, 3, ENC_BIG_ENDIAN);
        }
        offset++;

    } else if (ext_type == 1) {
        /*   Extension 1:
             RTP
            *
            *   +---+---+---+---+---+---+---+---+
            *   | 0   1 |    SN     |    +T     |
            *   +---+---+---+---+---+---+---+---+
            *   |              -T               |
            *   +---+---+---+---+---+---+---+---+
            *
             UDP
            *   +---+---+---+---+---+---+---+---+
            *   | 0   1 |    SN     |   IP-ID   |
            *   +---+---+---+---+---+---+---+---+
            *   |             IP-ID             |
            *   +---+---+---+---+---+---+---+---+
            */
        proto_item_append_text(ext_ti, " 1");

        if (rohc_cid_context->profile == ROHC_PROFILE_UDP) {
            /* IP-ID */
            proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+5, 11, ENC_BIG_ENDIAN);
            offset++;
        } else {
            /* RTP profile */
            if (t == 0) {
                /* +T is IP-ID */
                proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+5, 3, ENC_BIG_ENDIAN);
                offset++;
                /* -T is TS */
                proto_tree_add_bits_item(ext_tree, hf_rohc_ts, tvb, (offset<<3), 8, ENC_BIG_ENDIAN);
            } else if (t == 1) {
                /* +T is TS */
                proto_tree_add_bits_item(ext_tree, hf_rohc_ts, tvb, (offset<<3)+5, 3, ENC_BIG_ENDIAN);
                offset++;
                /* -T is IP-ID */
                proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id, tvb, (offset<<3), 8, ENC_BIG_ENDIAN);
            }
            offset++;
        }

    } else if (ext_type == 2) {
        /*   Extension 2:
             RTP
            *
            *   +---+---+---+---+---+---+---+---+
            *   | 1   0 |    SN     |    +T     |
            *   +---+---+---+---+---+---+---+---+
            *   |              +T               |
            *   +---+---+---+---+---+---+---+---+
            *   |              -T               |
            *   +---+---+---+---+---+---+---+---+
            *
             UDP
            *   +---+---+---+---+---+---+---+---+
            *   | 1   0 |    SN     |   IP-ID2  |
            *   +---+---+---+---+---+---+---+---+
            *   |            IP-ID2             |
            *   +---+---+---+---+---+---+---+---+
            *   |             IP-ID             |
            *   +---+---+---+---+---+---+---+---+
            */
        proto_item_append_text(ext_ti, " 2");

        if (rohc_cid_context->profile == ROHC_PROFILE_UDP) {
            /* IP-ID2 */
            proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id2, tvb, (offset<<3)+5, 11, ENC_BIG_ENDIAN);
            offset += 2;
            /* IP ID */
            proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id, tvb, (offset<<3), 8, ENC_BIG_ENDIAN);
            offset++;
        } else {
            /* RTP Profile */
            if (t == 0) {
                /* +T is IP-ID */
                proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+5, 11, ENC_BIG_ENDIAN);
                offset += 2;
                /* -T is TS */
                proto_tree_add_bits_item(ext_tree, hf_rohc_ts, tvb, (offset<<3), 8, ENC_BIG_ENDIAN);
            } else if (t == 1) {
                /* +T is TS */
                proto_tree_add_bits_item(ext_tree, hf_rohc_ts, tvb, (offset<<3)+5, 11, ENC_BIG_ENDIAN);
                offset += 2;
                /* -T is IP-ID */
                proto_tree_add_bits_item(ext_tree, hf_rohc_comp_ip_id, tvb, (offset<<3), 8, ENC_BIG_ENDIAN);
            }
            offset++;
        }

    } else {
        if ((rohc_cid_context->profile == ROHC_PROFILE_RTP) ||
            (rohc_cid_context->profile == ROHC_PROFILE_UDP)) {
            /* Extension 3:
             *
             *    0     1     2     3     4     5     6     7
             * +-----+-----+-----+-----+-----+-----+-----+-----+
             * |  1     1  |  S  |R-TS | Tsc |  I  | ip  | rtp |            (FLAGS)
             * +-----+-----+-----+-----+-----+-----+-----+-----+
             * |            Inner IP header flags        | ip2 |  if ip = 1
             * ..... ..... ..... ..... ..... ..... ..... .....
             * |            Outer IP header flags              |  if ip2 = 1
             * ..... ..... ..... ..... ..... ..... ..... .....
             * |                      SN                       |  if S = 1
             *  ..... ..... ..... ..... ..... ..... ..... .....
             * /       TS (encoded as in section 4.5.6)        /  1-4 octets,
             *  ..... ..... ..... ..... ..... ..... ..... .....   if R-TS = 1
             * |                                               |
             * /            Inner IP header fields             /  variable,
             * |                                               |  if ip = 1
             *  ..... ..... ..... ..... ..... ..... ..... .....
             * |                     IP-ID                     |  2 octets, if I = 1
             *  ..... ..... ..... ..... ..... ..... ..... .....
             * |                                               |
             * /            Outer IP header fields             /  variable,
             * |                                               |  if ip2 = 1
             *  ..... ..... ..... ..... ..... ..... ..... .....
             * |                                               |
             * /          RTP header flags and fields          /  variable,
             * |                                               |  if rtp = 1
             *  ..... ..... ..... ..... ..... ..... ..... .....
             */
            proto_item_append_text(ext_ti, " 3");

            static int * const ext3_rtp_flags[] = {
                &hf_rohc_ext3_s,
                &hf_rohc_ext3_r_ts,
                &hf_rohc_ext3_tsc,
                &hf_rohc_ext3_i,
                &hf_rohc_ext3_ip,
                &hf_rohc_ext3_rtp,
                NULL
            };
            static int * const ext3_udp_flags[] = {
                &hf_rohc_ext3_s,
                &hf_rohc_ext3_udp_mode,
                &hf_rohc_ext3_i,
                &hf_rohc_ext3_ip,
                &hf_rohc_ext3_ip2,
                NULL
            };

            uint64_t ext3_flags_value = 0;
            uint64_t ext3_inner_ip_flags_value = 0;
            uint64_t ext3_outer_ip_flags_value = 0;

            /* FLAGS */
            proto_tree_add_bitmask_ret_uint64(ext_tree, tvb, offset, hf_rohc_ext3_flags, ett_rohc_ext3_flags,
                                              (rohc_cid_context->profile == ROHC_PROFILE_RTP) ? ext3_rtp_flags : ext3_udp_flags,
                                              ENC_BIG_ENDIAN, &ext3_flags_value);
            offset++;

            if (ext3_flags_value & ROHC_RTP_EXT3_IP_MASK) {
                static int * const inner_ip_flags[] = {
                    &hf_rohc_ext3_inner_tos,
                    &hf_rohc_ext3_inner_ttl,
                    &hf_rohc_ext3_inner_df,
                    &hf_rohc_ext3_inner_pr,
                    &hf_rohc_ext3_inner_ipx,
                    &hf_rohc_ext3_inner_nbo,
                    &hf_rohc_ext3_inner_rnd,
                    &hf_rohc_ext3_inner_ip2,
                    NULL
                };
                /* Inner IP header flags
                 *
                 * These correspond to the inner IP header if there are two, and the
                 * single IP header otherwise.
                 *
                 *    0     1     2     3     4     5     6     7
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * | TOS | TTL | DF  | PR  | IPX | NBO | RND | ip2 |  if ip = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 */
                proto_tree_add_bitmask_ret_uint64(ext_tree, tvb, offset, hf_rohc_ext3_inner_ip_flags, ett_rohc_ext3_inner_ip_flags, inner_ip_flags, ENC_BIG_ENDIAN, &ext3_inner_ip_flags_value);
                rohc_cid_context->rnd = ((ext3_inner_ip_flags_value & ROHC_RTP_EXT3_INNER_RND_MASK) != 0);
                offset++;
            }
            if (ext3_inner_ip_flags_value & ROHC_RTP_EXT3_INNER_IP2_MASK) {
                static int * const outer_ip_flags[] = {
                    &hf_rohc_ext3_outer_tos,
                    &hf_rohc_ext3_outer_ttl,
                    &hf_rohc_ext3_outer_df,
                    &hf_rohc_ext3_outer_pr,
                    &hf_rohc_ext3_outer_ipx,
                    &hf_rohc_ext3_outer_nbo,
                    &hf_rohc_ext3_outer_rnd,
                    &hf_rohc_ext3_outer_i2,
                    NULL
                };
                /* Outer IP header flags
                 *
                 * The fields in this part of the Extension 3 header refer to the
                 * outermost IP header:
                 *
                 *    0     1     2     3     4     5     6     7
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * | TOS2| TTL2| DF2 | PR2 |IPX2 |NBO2 |RND2 |  I2 |  if ip2 = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 */
                proto_tree_add_bitmask_ret_uint64(ext_tree, tvb, offset, hf_rohc_ext3_outer_ip_flags, ett_rohc_ext3_outer_ip_flags, outer_ip_flags, ENC_BIG_ENDIAN, &ext3_outer_ip_flags_value);
                /* TODO Update rnd when adding support for inner/outer behavior */
                rohc_cid_context->rnd = ((ext3_outer_ip_flags_value & ROHC_RTP_EXT3_OUTER_RND_MASK) != 0);
                offset++;
            }
            if (ext3_flags_value & ROHC_RTP_EXT3_S_MASK) {
                proto_tree_add_bits_item(ext_tree, hf_rohc_comp_sn, tvb, (offset<<3), 8, ENC_BIG_ENDIAN);
                offset++;
            }
            if (ext3_flags_value & ROHC_RTP_EXT3_R_TS_MASK) {
                uint8_t val_len = 0;
                get_self_describing_var_len_val(tvb, ext_tree, offset, hf_rohc_ts, &val_len);
                offset += val_len;
            }
            if (ext3_flags_value & ROHC_RTP_EXT3_IP_MASK) {
                /* Inner IP header fields
                 *
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * |         Type of Service/Traffic Class         |  if TOS = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * |         Time to Live/Hop Limit                |  if TTL = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * |         Protocol/Next Header                  |  if PR = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * /         IP extension headers                  /  variable,
                 *  ..... ..... ..... ..... ..... ..... ..... .....   if IPX = 1
                 */
                if (ext3_inner_ip_flags_value & ROHC_RTP_EXT3_INNER_TOS_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_rtp_tos, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                if (ext3_inner_ip_flags_value & ROHC_RTP_EXT3_INNER_TTL_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_rtp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                if (ext3_inner_ip_flags_value & ROHC_RTP_EXT3_INNER_PR_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_ip_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                if (ext3_inner_ip_flags_value & ROHC_RTP_EXT3_INNER_IPX_MASK) {
                    offset = dissect_compressed_list(0, pinfo, ext_tree, tvb, offset);
                }
            }
            if (ext3_flags_value & ROHC_RTP_EXT3_I_MASK) {
                proto_tree_add_item(ext_tree, hf_rohc_comp_ip_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            if (ext3_inner_ip_flags_value & ROHC_RTP_EXT3_INNER_IP2_MASK) {
                /* Outer IP header fields
                 *
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * |      Type of Service/Traffic Class            |  if TOS2 = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * |         Time to Live/Hop Limit                |  if TTL2 = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * |         Protocol/Next Header                  |  if PR2 = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * /         IP extension header(s)                /  variable,
                 *  ..... ..... ..... ..... ..... ..... ..... .....    if IPX2 = 1
                 * |                  IP-ID                        |  2 octets,
                 *  ..... ..... ..... ..... ..... ..... ..... .....    if I2 = 1
                 */
                if (ext3_outer_ip_flags_value & ROHC_RTP_EXT3_OUTER_TOS_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_rtp_tos, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                if (ext3_outer_ip_flags_value & ROHC_RTP_EXT3_OUTER_TTL_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_rtp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                if (ext3_outer_ip_flags_value & ROHC_RTP_EXT3_OUTER_PR_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_ip_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                if (ext3_outer_ip_flags_value & ROHC_RTP_EXT3_OUTER_IPX_MASK) {
                    offset = dissect_compressed_list(0, pinfo, ext_tree, tvb, offset);
                }
                if (ext3_outer_ip_flags_value & ROHC_RTP_EXT3_OUTER_I2_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_comp_ip_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
            }
            if ((rohc_cid_context->profile == ROHC_PROFILE_RTP) &&
                (ext3_flags_value & ROHC_RTP_EXT3_RTP_MASK)) {

                uint64_t ext3_rtp_flags_value = 0;
                static int * const rtp_flags[] = {
                    &hf_rohc_ext3_rtp_mode,
                    &hf_rohc_ext3_r_pt,
                    &hf_rohc_ext3_m,
                    &hf_rohc_ext3_r_x,
                    &hf_rohc_ext3_csrc,
                    &hf_rohc_ext3_tss,
                    &hf_rohc_ext3_tis,
                    NULL
                };
                /* RTP header flags and fields
                 *
                 *    0     1     2     3     4     5     6     7
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * |   Mode    |R-PT |  M  | R-X |CSRC | TSS | TIS |  if rtp = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * | R-P |             RTP PT                      |  if R-PT = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * /           Compressed CSRC list                /  if CSRC = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 * /                  TS_STRIDE                    /  1-4 oct if TSS = 1
                 *  ..... ..... ..... ..... ..... ..... ..... ....
                 * /           TIME_STRIDE (milliseconds)          /  1-4 oct if TIS = 1
                 *  ..... ..... ..... ..... ..... ..... ..... .....
                 */
                proto_tree_add_bitmask_ret_uint64(ext_tree, tvb, offset, hf_rohc_ext3_rtp_flags, ett_rohc_ext3_rtp_flags, rtp_flags, ENC_BIG_ENDIAN, &ext3_rtp_flags_value);
                rohc_cid_context->mode = (enum rohc_mode)((ext3_rtp_flags_value & ROHC_RTP_EXT3_RTP_MODE_MASK)>>6);
                offset++;

                if (ext3_rtp_flags_value & ROHC_RTP_EXT3_R_PT_MASK) {
                    proto_tree_add_item(ext_tree, hf_rohc_ext3_r_p, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ext_tree, hf_rohc_rtp_pt, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                if (ext3_rtp_flags_value & ROHC_RTP_EXT3_CSRC_MASK) {
                    offset = dissect_compressed_list(0, pinfo, ext_tree, tvb, offset);
                }
                if (ext3_rtp_flags_value & ROHC_RTP_EXT3_TSS_MASK) {
                    uint8_t val_len = 0;
                    get_self_describing_var_len_val(tvb, ext_tree, offset, hf_rohc_rtp_ts_stride, &val_len);
                    offset += val_len;
                }
                if (ext3_rtp_flags_value & ROHC_RTP_EXT3_TIS_MASK) {
                    uint8_t val_len = 0;
                    get_self_describing_var_len_val(tvb, ext_tree, offset, hf_rohc_rtp_time_stride, &val_len);
                    offset += val_len;
                }
            }
        } else {
            proto_tree_add_expert_format(ext_tree, pinfo, &ei_rohc_not_dissected_yet, tvb, offset, -1,
                                         "extension 3 [Not dissected yet for profile %u]", rohc_cid_context->profile);
            if (tvb_captured_length_remaining(tvb, offset) > 0)
                offset += tvb_captured_length_remaining(tvb, offset);
        }
    }

    proto_item_set_len(ext_ti, offset-start_offset);
    return offset;
}

/* 5.7.2. Packet type 1 (R-mode): R-1, R-1-TS, R-1-ID */
static int
dissect_rohc_pkt_type_1_r_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, rohc_cid_context_t *rohc_cid_context)
{
    proto_item *ti;
    proto_tree *pkt_tree;
    uint8_t val_len = 0, x, sn, t = 0xff;
    int start_offset = offset;

    if (rohc_cid_context->large_cid_present == true) {
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, tree, offset+1, hf_rohc_large_cid, &val_len);
    }

    if ((rohc_cid_context->rohc_ip_version != 4) ||
        (rohc_cid_context->rnd) ||
        (rohc_cid_context->profile == ROHC_PROFILE_UDP)) {
        /*   R-1 (RTP profile)
            *
            *     0   1   2   3   4   5   6   7
            *   +---+---+---+---+---+---+---+---+
            *   | 1   0 |          SN           |
            *   +===+===+===+===+===+===+===+===+
            *   | M | X |          TS           |
            *   +---+---+---+---+---+---+---+---+
            */
        /*   R-1 (UDP profile)
            *
            *     0   1   2   3   4   5   6   7
            *   +---+---+---+---+---+---+---+---+
            *   | 1   0 |          SN           |
            *   +===+===+===+===+===+===+===+===+
            *   | X |           IP-ID           |
            *   +---+---+---+---+---+---+---+---+
            */
        col_append_str(pinfo->cinfo, COL_INFO, "R-1");

        /* Create R-1 subtree */
        pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "R-1 packet");

        /* SN */
        sn = tvb_get_bits8(tvb, (offset<<3)+2, 6);
        proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
        offset += 1 + val_len;

        /* Show SN in info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
        if (rohc_cid_context->profile == ROHC_PROFILE_UDP) {
            /* UDP Profile */

            /* X */
            x= tvb_get_bits8(tvb, (offset<<3), 1);
            proto_tree_add_bits_item(pkt_tree, hf_rohc_x, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);

            /* IP-ID */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
        } else {
            /* RTP Profile */

            /* M */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_rtp_m, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);

            /* X */
            x = tvb_get_bits8(tvb, (offset<<3)+1, 1);
            proto_tree_add_bits_item(pkt_tree, hf_rohc_x, tvb, (offset<<3)+1, 1, ENC_BIG_ENDIAN);

            /* TS */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_ts, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
        }
        offset++;
    } else {
        /* Packet type depends upon value of T bit */
        t = tvb_get_bits8(tvb, ((offset+1+val_len)<<3)+2, 1);
        if (t == 0) {
            /*   R-1-ID
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 1   0 |          SN           |
                *   +===+===+===+===+===+===+===+===+
                *   | M | X |T=0|       IP-ID       |
                *   +---+---+---+---+---+---+---+---+
                */
            col_append_str(pinfo->cinfo, COL_INFO, "R-1-ID");
            /* Create R-1-ID subtree */
            pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "R-1-ID packet");
        } else {
            /*   R-1-TS
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 1   0 |          SN           |
                *   +===+===+===+===+===+===+===+===+
                *   | M | X |T=1|        TS         |
                *   +---+---+---+---+---+---+---+---+
                */
            col_append_str(pinfo->cinfo, COL_INFO, "R-1-TS");
            /* Create R-1-TS subtree */
            pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "R-1-TS packet");
        }

        /* SN */
        sn = tvb_get_bits8(tvb, (offset<<3)+2, 6);
        proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
        offset += 1 + val_len;
        /* Show SN in info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

        /* M */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_rtp_m, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);

        /* X */
        x = tvb_get_bits8(tvb, (offset<<3)+1, 1);
        proto_tree_add_bits_item(pkt_tree, hf_rohc_x, tvb, (offset<<3)+1, 1, ENC_BIG_ENDIAN);

        /* T */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_t, tvb, (offset<<3)+2, 1, ENC_BIG_ENDIAN);
        if (t == 0) {
            /* IP-ID */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
        } else {
            /* TS */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_ts, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
        }
        offset++;
    }

    if (x) {
        offset = dissect_rohc_ext_format(tvb, pinfo, pkt_tree, offset, t, rohc_cid_context);
    }
    proto_item_set_len(ti, offset-start_offset);

    return offset;
}

/* 5.7.3. Packet type 1 (U/O-mode): UO-1, UO-1-ID, UO-1-TS */
static int
dissect_rohc_pkt_type_1_u_o_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, rohc_cid_context_t *rohc_cid_context)
{
    proto_item *ti;
    proto_tree *pkt_tree;
    uint8_t val_len = 0, x = 0, sn, t = 0xff;
    int start_offset = offset;

    if (rohc_cid_context->large_cid_present == true) {
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, tree, offset+1, hf_rohc_large_cid, &val_len);
    }

    if ((rohc_cid_context->rohc_ip_version != 4) ||
        (rohc_cid_context->rnd) ||
        (rohc_cid_context->profile == ROHC_PROFILE_UDP)) {
        /*   UO-1 (RTP profile)
            *
            *     0   1   2   3   4   5   6   7
            *   +---+---+---+---+---+---+---+---+
            *   | 1   0 |          TS           |
            *   +===+===+===+===+===+===+===+===+
            *   | M |      SN       |    CRC    |
            *   +---+---+---+---+---+---+---+---+
            */
        /*   UO-1 (UDP profile)
            *
            *     0   1   2   3   4   5   6   7
            *   +---+---+---+---+---+---+---+---+
            *   | 1   0 |         IP-ID         |
            *   +===+===+===+===+===+===+===+===+
            *   |        SN         |    CRC    |
            *   +---+---+---+---+---+---+---+---+
            */
        col_append_str(pinfo->cinfo, COL_INFO, "UO-1");

        /* Create subtree */
        pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "UO-1 packet");
        if (rohc_cid_context->profile == ROHC_PROFILE_UDP) {
            /* IP-ID */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
            offset += 1 + val_len;

            /* SN */
            sn = tvb_get_bits8(tvb, (offset<<3), 5);
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3), 5, ENC_BIG_ENDIAN);
        } else {
            /* RTP Profile */

            /* TS */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_ts, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
            offset += 1 + val_len;

            /* M */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_rtp_m, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);

            /* SN */
            sn = tvb_get_bits8(tvb, (offset<<3)+1, 4);
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+1, 4, ENC_BIG_ENDIAN);
        }
        /* Show SN in info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

        /* CRC (common to both) */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_crc, tvb, (offset<<3)+5, 3, ENC_BIG_ENDIAN);
        offset++;
    } else {
        /* Type depends upon t bit */
        t = tvb_get_bits8(tvb, ((offset)<<3)+2, 1);
        if (t == 0) {
            /*   UO-1-ID
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 1   0 |T=0|       IP-ID       |
                *   +===+===+===+===+===+===+===+===+
                *   | X |      SN       |    CRC    |
                *   +---+---+---+---+---+---+---+---+
                */
            col_append_str(pinfo->cinfo, COL_INFO, "UO-1-ID");

            /* UO-1-ID subtree */
            pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "UO-1-ID packet");

            /* T */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_t, tvb, (offset<<3)+2, 1, ENC_BIG_ENDIAN);

            /* IP-ID */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
            offset += 1 + val_len;

            /* X */
            x = tvb_get_bits8(tvb, (offset<<3), 1);
            proto_tree_add_bits_item(pkt_tree, hf_rohc_x, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);
        } else {
            /*   UO-1-TS
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 1   0 |T=1|        TS         |
                *   +===+===+===+===+===+===+===+===+
                *   | M |      SN       |    CRC    |
                *   +---+---+---+---+---+---+---+---+
                */
            col_append_str(pinfo->cinfo, COL_INFO, "UO-1-TS");

            /* UO-1-TS subtree */
            pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "UO-1-TS packet");

            /* T */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_t, tvb, (offset<<3)+2, 1, ENC_BIG_ENDIAN);

            /* TS */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_ts, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
            offset += 1 + val_len;

            /* M */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_rtp_m, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);
        }

        /* SN */
        sn = tvb_get_bits8(tvb, (offset<<3)+1, 4);
        proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+1, 4, ENC_BIG_ENDIAN);
        /* Show SN in info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

        /* CRC */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_crc, tvb, (offset<<3)+5, 3, ENC_BIG_ENDIAN);
        offset++;
    }
    if (x) {
        offset = dissect_rohc_ext_format(tvb, pinfo, pkt_tree, offset, t, rohc_cid_context);
    }
    proto_item_set_len(ti, offset-start_offset);

    return offset;
}

/* 5.7.4. Packet type 2: UOR-2 */
static int
dissect_rohc_pkt_type_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, rohc_cid_context_t *rohc_cid_context)
{
    proto_item *ti;
    proto_tree *pkt_tree;
    uint8_t val_len = 0, x, sn, t = 0xff;
    int start_offset = offset;

    if (rohc_cid_context->large_cid_present == true) {
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, tree, offset+1, hf_rohc_large_cid, &val_len);
    }

    if ((rohc_cid_context->rohc_ip_version != 4) ||
        (rohc_cid_context->rnd) ||
        (rohc_cid_context->profile == ROHC_PROFILE_UDP)) {
        /*   UOR-2 (RTP profile)
            *
            *     0   1   2   3   4   5   6   7
            *   +---+---+---+---+---+---+---+---+
            *   | 1   1   0 |        TS         |
            *   +===+===+===+===+===+===+===+===+
            *   |TS | M |          SN           |
            *   +---+---+---+---+---+---+---+---+
            *   | X |            CRC            |
            *   +---+---+---+---+---+---+---+---+
            */
        /*   UOR-2 (UDP profile)
            *
            *     0   1   2   3   4   5   6   7
            *   +---+---+---+---+---+---+---+---+
            *   | 1   1   0 |        SN         |
            *   +===+===+===+===+===+===+===+===+
            *   | X |            CRC            |
            *   +---+---+---+---+---+---+---+---+
            */
        col_append_str(pinfo->cinfo, COL_INFO, "UOR-2");

        /* UOR-2 subtree */
        pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "UOR-2 packet");
        if (rohc_cid_context->profile == ROHC_PROFILE_UDP) {
            /* UDP profile */

            /* SN */
            sn = tvb_get_bits8(tvb, (offset<<3)+3, 5);
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
            offset += 1 + val_len;
            /* Show SN in info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
        } else {
            /* RTP profile */

            /* TS */
            crumb_spec_t rohc_ts_crumbs[] = {
                { 2, 6},
                { 8, 1},
                { 0, 0}
            };
            rohc_ts_crumbs[1].crumb_bit_offset += val_len*8;

            proto_tree_add_split_bits_item_ret_val(pkt_tree, hf_rohc_ts, tvb, (offset<<3),
                                                   rohc_ts_crumbs, NULL);
            offset += 1 + val_len;

            /* M */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_rtp_m, tvb, (offset<<3)+1, 1, ENC_BIG_ENDIAN);
            sn = tvb_get_bits8(tvb, (offset<<3)+2, 6);

            /* SN */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
            offset++;
            /* Show SN in info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
        }

        /* X - common to both */
        x = tvb_get_bits8(tvb, (offset<<3), 1);
        proto_tree_add_bits_item(pkt_tree, hf_rohc_x, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);

        /* CRC - common to both */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_crc, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
        offset++;
    } else {
        /* Packet type depends upon T bit */
        t = tvb_get_bits8(tvb, ((offset+1+val_len)<<3), 1);
        if (t == 0) {
            /*   UOR-2-ID
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 1   1   0 |       IP-ID       |
                *   +===+===+===+===+===+===+===+===+
                *   |T=0| M |          SN           |
                *   +---+---+---+---+---+---+---+---+
                *   | X |            CRC            |
                *   +---+---+---+---+---+---+---+---+
                */
            col_append_str(pinfo->cinfo, COL_INFO, "UOR-2-ID");

            /* UOR-2-ID subtree */
            pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "UOR-2-ID packet");

            /* IP-ID */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_ip_id, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
        } else {
            /*   UOR-2-TS
                *
                *     0   1   2   3   4   5   6   7
                *   +---+---+---+---+---+---+---+---+
                *   | 1   1   0 |        TS         |
                *   +===+===+===+===+===+===+===+===+
                *   |T=1| M |          SN           |
                *   +---+---+---+---+---+---+---+---+
                *   | X |            CRC            |
                *   +---+---+---+---+---+---+---+---+
                */
            col_append_str(pinfo->cinfo, COL_INFO, "UOR-2-TS");

            /* UOR-2-TS subtree */
            pkt_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rohc_packet, &ti, "UOR-2-TS packet");

            /* TS */
            proto_tree_add_bits_item(pkt_tree, hf_rohc_ts, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
        }
        offset += 1 + val_len;

        /* T - commonto  both */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_t, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);

        /* M - common to both */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_rtp_m, tvb, (offset<<3)+1, 1, ENC_BIG_ENDIAN);

        /* SN - common to both */
        sn = tvb_get_bits8(tvb, (offset<<3)+2, 6);
        proto_tree_add_bits_item(pkt_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
        offset++;
        /* Show SN in info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);

        /* X - common to both */
        x = tvb_get_bits8(tvb, (offset<<3), 1);
        proto_tree_add_bits_item(pkt_tree, hf_rohc_x, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);

        /* CRC - common to both */
        proto_tree_add_bits_item(pkt_tree, hf_rohc_crc, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
        offset++;
    }
    if (x) {
        offset = dissect_rohc_ext_format(tvb, pinfo, pkt_tree, offset, t, rohc_cid_context);
    }
    proto_item_set_len(ti, offset-start_offset);

    return offset;
}

static void
dissect_rohc_feedback_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, int16_t feedback_data_len,
                           rohc_info *p_rohc_info, uint16_t cid, bool cid_context)
{
    proto_item         *ti;
    proto_tree         *rohc_feedback_tree;
    uint8_t             opt, opt_len, oct;
    rohc_cid_context_t *rohc_cid_context = NULL;
    int                 key = cid;
    uint32_t            sn;

    /* Look up context using cid */
    if (!PINFO_FD_VISITED(pinfo)) {
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, GUINT_TO_POINTER(key));
        if (rohc_cid_context) {
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0, rohc_cid_context);
        }
    } else{
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0);
    }

    if (!rohc_cid_context) {
        if (cid_context) {
            /* Reuse info coming from private data */
            rohc_cid_context = wmem_new(pinfo->pool, rohc_cid_context_t);
            /*rohc_cid_context->d_mode;*/
            rohc_cid_context->rnd = p_rohc_info->rnd;
            rohc_cid_context->udp_checksum_present = p_rohc_info->udp_checksum_present;
            rohc_cid_context->profile = p_rohc_info->profile;
            rohc_cid_context->mode = p_rohc_info->mode;
            rohc_cid_context->rohc_ip_version = p_rohc_info->rohc_ip_version;
            rohc_cid_context->large_cid_present = p_rohc_info->large_cid_present;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = -1;
        } else {
            /* No context info, not much we can do */
            proto_item_append_text(p_rohc_info->last_created_item, " (type %d)", (feedback_data_len==1) ? 1 : 2);
            proto_tree_add_expert_format(tree, pinfo, &ei_rohc_profile_not_supported, tvb, offset, feedback_data_len, "profile-specific information [Profile not known]");
            return;
        }
    }

    if (feedback_data_len==1) {
        /* FEEDBACK-1 */
        proto_item_append_text(p_rohc_info->last_created_item, " (type 1)");
        oct = tvb_get_uint8(tvb, offset);
        switch (rohc_cid_context->profile) {
            case ROHC_PROFILE_UNCOMPRESSED: /* 0 */
                ti = proto_tree_add_item(tree, hf_rohc_profile_spec_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
                if (oct) {
                    expert_add_info_format(pinfo, ti, &ei_rohc_profile_spec_octet, "Invalid profile-specific octet value (0x%02X)", oct);
                }
                break;
            case ROHC_PROFILE_RTP: /* 1 */
            case ROHC_PROFILE_UDP: /* 2 */
                /*
                 *     0   1   2   3   4   5   6   7
                 *   +---+---+---+---+---+---+---+---+
                 *   |              SN               |
                 *   +---+---+---+---+---+---+---+---+
                 *
                 */

                /* SN */
                proto_tree_add_item(tree, hf_rohc_fb1_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", oct);
                break;
            default:
                proto_tree_add_expert(tree, pinfo, &ei_rohc_profile_specific, tvb, offset, feedback_data_len);
                break;
        }
        return;
    }
    /*  FEEDBACK-2 */
    proto_item_append_text(p_rohc_info->last_created_item, " (type 2)");
    switch (rohc_cid_context->profile) {
        case ROHC_PROFILE_UNCOMPRESSED: /* 0 */
            expert_add_info(pinfo, p_rohc_info->last_created_item, &ei_rohc_feedback_type_2_is_not_applicable_for_uncompressed_profile);
            break;
        case ROHC_PROFILE_RTP: /* 1 */
        case ROHC_PROFILE_UDP: /* 2 */
            /*      0   1   2   3   4   5   6   7
             *    +---+---+---+---+---+---+---+---+
             *   |Acktype| Mode  |      SN       |
             *   +---+---+---+---+---+---+---+---+
             *   |              SN               |
             *   +---+---+---+---+---+---+---+---+
             *   /       Feedback options        /
             *   +---+---+---+---+---+---+---+---+
             */

            /* Subtree */
            rohc_feedback_tree = proto_tree_add_subtree_format(tree, tvb, offset, feedback_data_len, ett_rohc_feedback, NULL,
                                     "%s profile-specific information",
                                     (rohc_cid_context->profile == ROHC_PROFILE_RTP) ? "RTP" : "UDP");
            /* Set mode at first pass? Do we need a new context for the following frames?
             *
             */

            /* Acktype */
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_acktype, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Mode */
            rohc_cid_context->mode = (enum rohc_mode)((tvb_get_uint8(tvb,offset) & 0x30)>>4);
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* SN */
            sn = tvb_get_ntohs(tvb, offset) & 0x0fff;
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            feedback_data_len-=2;

            /*     0   1   2   3   4   5   6   7
             *   +---+---+---+---+---+---+---+---+
             *   |   Opt Type    |    Opt Len    |
             *   +---+---+---+---+---+---+---+---+
             *   /          option data          /  Opt Len octets
             *   +---+---+---+---+---+---+---+---+
             */
            while (feedback_data_len>0) {
                opt = opt_len = tvb_get_uint8(tvb,offset);
                opt = opt >> 4;
                opt_len = opt_len &0x0f;
                /* Opt Type */
                ti = proto_tree_add_item(rohc_feedback_tree, hf_rohc_opt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* Opt Len */
                proto_tree_add_item(rohc_feedback_tree, hf_rohc_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                feedback_data_len--;

                /* optional data */
                switch (opt) {
                    case 1:
                        /* CRC */
                        proto_tree_add_item(rohc_feedback_tree, hf_rohc_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
                        oct = tvb_get_uint8(tvb, offset);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "CRC=%u ", oct);
                        break;
                    case 2:
                        /* REJECT */
                        col_append_str(pinfo->cinfo, COL_INFO, "Reject ");
                        break;
                    case 3:
                        /* SN-Not-Valid */
                        col_append_str(pinfo->cinfo, COL_INFO, "SN-Not-Valid ");
                        break;
                    case 4:
                        /* SN */
                        proto_tree_add_item(rohc_feedback_tree, hf_rohc_opt_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
                        sn = (sn << 8) | tvb_get_uint8(tvb, offset);
                        ti = proto_tree_add_uint(rohc_feedback_tree, hf_rohc_ext_sn, tvb, 0, 0, sn);
                        proto_item_set_generated(ti);
                        break;
                    case 5:
                        /* Clock */
                        if (rohc_cid_context->profile == ROHC_PROFILE_RTP) {
                            proto_tree_add_item(rohc_feedback_tree, hf_rohc_opt_clock, tvb, offset, 1, ENC_BIG_ENDIAN);
                            oct = tvb_get_uint8(tvb, offset);
                            col_append_fstr(pinfo->cinfo, COL_INFO, "Clock=%u ", oct);
                        } else {
                            expert_add_info(pinfo, ti, &ei_rohc_rohc_opt_clock);
                        }
                        break;
                    case 6:
                        /* Jitter */
                        if (rohc_cid_context->profile == ROHC_PROFILE_RTP) {
                            proto_tree_add_item(rohc_feedback_tree, hf_rohc_opt_jitter, tvb, offset, 1, ENC_BIG_ENDIAN);
                            oct = tvb_get_uint8(tvb, offset);
                            col_append_fstr(pinfo->cinfo, COL_INFO, "Jitter=%u ", oct);
                        } else {
                            expert_add_info(pinfo, ti, &ei_rohc_opt_jitter);
                        }
                        break;
                    case 7:
                        /* Loss */
                        proto_tree_add_item(rohc_feedback_tree, hf_rohc_opt_loss, tvb, offset, 1, ENC_BIG_ENDIAN);
                        oct = tvb_get_uint8(tvb, offset);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "Loss=%u ", oct);
                        break;

                    default:
                        proto_tree_add_item(rohc_feedback_tree, hf_rohc_unknown_option_data, tvb, offset, opt_len, ENC_NA);
                        break;
                }
                feedback_data_len = feedback_data_len - opt_len;
                offset = offset + opt_len;

            }
            col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", sn);
            break;

        default:
            rohc_feedback_tree = proto_tree_add_subtree(tree, tvb, offset, feedback_data_len,
                        ett_rohc_feedback, NULL, "profile-specific information[Not dissected yet]");
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_acktype, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
    }
}


static const true_false_string rohc_cmp_lst_mask_size_vals = { "15-bit mask", "7-bit mask" };


/* 5.8.6.  Compressed list formats */
static int
dissect_compressed_list(int expected_encoding_type _U_, packet_info *pinfo _U_,
                        proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *list_ti /* , *et_ti */;
    proto_item *list_tree;
    uint8_t     first_byte = tvb_get_uint8(tvb, offset);
    uint8_t     ET, GP , PS, CC , bit_mask_size;
    int         start_offset = offset;

    /* Compressed list root */
    list_ti = proto_tree_add_item(tree, hf_rohc_compressed_list, tvb, offset, -1, ENC_NA);
    list_tree = proto_item_add_subtree(list_ti, ett_rohc_compressed_list);

    /* Fixed fields from first byte */
    ET = (first_byte & 0xc0) >> 6;
    /* et_ti = proto_tree_add_item(list_tree, hf_rohc_compressed_list_et, tvb, offset, 1, ENC_BIG_ENDIAN); */
    proto_tree_add_item(list_tree, hf_rohc_compressed_list_et, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(list_ti, " (type=%d - %s)",
                           ET, val_to_str_const(ET, compressed_list_encoding_type_vals, "Unknown"));
#if 0
    if (ET != expected_encoding_type) {
        expert_add_info_format(pinfo, et_ti, PI_MALFORMED, PI_ERROR,
                               "Wrong compressed list encoding type (expected %d, got %d)",
                               expected_encoding_type, ET);
        return offset+1;
    }
#endif
    GP = (first_byte & 0x20) >> 5;
    proto_tree_add_item(list_tree, hf_rohc_compressed_list_gp, tvb, offset, 1, ENC_BIG_ENDIAN);

    switch (ET) {
        case 0:
            /* 5.8.6.1 Encoding Type 0 (generic scheme)
             *
             *    0   1   2   3   4   5   6   7
             *  +---+---+---+---+---+---+---+---+
             *  | ET=0  |GP |PS |    CC = m     |
             *  +---+---+---+---+---+---+---+---+
             *  :            gen_id             :  1 octet, if GP = 1
             *  +---+---+---+---+---+---+---+---+
             *  |        XI 1, ..., XI m        |  m octets, or m * 4 bits
             *  /                --- --- --- ---/
             *  |               :    Padding    :  if PS = 0 and m is odd
             *  +---+---+---+---+---+---+---+---+
             *  |                               |
             *  /       item 1, ..., item n     /  variable
             *  |                               |
             *  +---+---+---+---+---+---+---+---+
             *
             */
            /* PS = (first_byte & 0x10) >> 4;
             *       PS: Indicates size of XI fields:
             *       PS = 0 indicates 4-bit XI fields;
             *       PS = 1 indicates 8-bit XI fields.
             */
            PS = (first_byte & 0x10) >> 4;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_ps, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* CC: CSRC counter from original RTP header. */
            CC = first_byte & 0x0f;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_cc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* GP: Indicates presence of gen_id field. */
            if (GP) {
                proto_tree_add_item(list_tree, hf_rohc_compressed_list_gen_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            if (CC!=0) {
                /* TODO: calculate how many bytes to skip for items */
                /*
                 *       XI 1, ..., XI m: m XI items.  The format of an XI item is as
                 *            follows:
                 *
                 *                 +---+---+---+---+
                 *        PS = 0:  | X |   Index   |
                 *                 +---+---+---+---+
                 *
                 *                    0   1   2   3   4   5   6   7
                 *                  +---+---+---+---+---+---+---+---+
                 *         PS = 1:  | X |           Index           |
                 *                  +---+---+---+---+---+---+---+---+
                 *
                 *         X = 1 indicates that the item corresponding to the Index
                 *               is sent in the item 0, ..., item n list.
                 *         X = 0 indicates that the item corresponding to the Index is
                 *               not sent.
                 */
                if (PS) {
                    /* PS = 1 indicates 8-bit XI fields. */
                } else {
                    /* PS = 0 indicates 4-bit XI fields; */
                }
            }

            break;

        case 1:
            /*
             * 5.8.6.2.  Encoding Type 1 (insertion only scheme)
             *
             *      0   1   2   3   4   5   6   7
             *    +---+---+---+---+---+---+---+---+
             *    | ET=1  |GP |PS |     XI 1      |
             *    +---+---+---+---+---+---+---+---+
             *    :            gen_id             :  1 octet, if GP = 1
             *    +---+---+---+---+---+---+---+---+
             *    |            ref_id             |
             *    +---+---+---+---+---+---+---+---+
             *    /      insertion bit mask       /  1-2 octets
             *    +---+---+---+---+---+---+---+---+
             *    |            XI list            |  k octets, or (k - 1) * 4 bits
             *    /                --- --- --- ---/
             *    |               :    Padding    :  if PS = 0 and k is even
             *    +---+---+---+---+---+---+---+---+
             *    |                               |
             *    /       item 1, ..., item n     /  variable
             *    |                               |
             *    +---+---+---+---+---+---+---+---+
             *
             */
            PS = (first_byte & 0x10) >> 4;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_ps, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*      XI 1: When PS = 0, the first 4-bit XI item is placed here.
             *            When PS = 1, the field is set to zero when sending, and
             *            ignored when receiving.
             */
            if (PS==0) {
                proto_tree_add_item(list_tree, hf_rohc_compressed_list_xi_1, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            offset++;
            /* GP: Indicates presence of gen_id field. */
            if (GP) {
                proto_tree_add_item(list_tree, hf_rohc_compressed_list_gen_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_ref_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /*
             *      insertion bit mask: Bit mask indicating the positions where new
             *                items are to be inserted.  See Insertion Only scheme in
             *                section 5.8.3.  The bit mask can have either of the
             *                following two formats:
             *
             *
             *           0   1   2   3   4   5   6   7
             *         +---+---+---+---+---+---+---+---+
             *         | 0 |        7-bit mask         |  bit 1 is the first bit
             *         +---+---+---+---+---+---+---+---+
             *
             *         +---+---+---+---+---+---+---+---+
             *         | 1 |                           |  bit 1 is the first bit
             *         +---+      15-bit mask          +
             *         |                               |  bit 7 is the last bit
             *         +---+---+---+---+---+---+---+---+
             */
            bit_mask_size = (tvb_get_uint8(tvb,offset)&0x80)>>7;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_mask_size, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (bit_mask_size) {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_ins_bit_mask, tvb, (offset<<3)+1, 15, ENC_BIG_ENDIAN);
                offset+=2;
            } else {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_ins_bit_mask, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
                offset++;
            }

            /*
             *      XI list: XI fields for items to be inserted.  When the insertion
             *         bit mask has k ones, the total number of XI fields is k.  When
             *         PS = 1, all XI fields are in the XI list.  When PS = 0, the
             *         first XI field is in the XI 1 field, and the remaining k - 1
             *         XI fields are in the XI list.
             *
             *      Padding: Present when PS = 0 and k is even.
             */
            /* TODO: */
            break;
        case 2:
            /*
             *  5.8.6.3.  Encoding Type 2 (removal only scheme)
             *
             *          0   1   2   3   4   5   6   7
             *        +---+---+---+---+---+---+---+---+
             *        | ET=2  |GP |res|     Count     |
             *        +---+---+---+---+---+---+---+---+
             *        :            gen_id             :  1 octet, if GP = 1
             *        +---+---+---+---+---+---+---+---+
             *        |            ref_id             |
             *        +---+---+---+---+---+---+---+---+
             *        /       removal bit mask        /  1-2 octets
             *        +---+---+---+---+---+---+---+---+
             *
             */
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_res, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Count: Number of elements in ref_list. */
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_count, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* GP: Indicates presence of gen_id field. */
            if (GP) {
                proto_tree_add_item(list_tree, hf_rohc_compressed_list_gen_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_ref_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
             /*
              *  removal bit mask: Indicates the elements in ref_list to be
              *  removed in order to obtain the current list.  See section
              *  5.8.3.  The removal bit mask has the same format as the
              *  insertion bit mask of section 5.8.6.3.
              */

            bit_mask_size = (tvb_get_uint8(tvb,offset)&0x80)>>7;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_mask_size, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (bit_mask_size) {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_rem_bit_mask, tvb, (offset<<3)+1, 15, ENC_BIG_ENDIAN);
                offset+=2;
            } else {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_rem_bit_mask, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
                offset++;
            }
            break;
        case 3:
            /*
             * 5.8.6.4.  Encoding Type 3 (remove then insert scheme)
             *
             *        See section 5.8.3 for a description of the Remove then insert
             *        scheme.
             *
             *          0   1   2   3   4   5   6   7
             *        +---+---+---+---+---+---+---+---+
             *        | ET=3  |GP |PS |     XI 1      |
             *        +---+---+---+---+---+---+---+---+
             *        :            gen_id             :  1 octet, if GP = 1
             *        +---+---+---+---+---+---+---+---+
             *        |            ref_id             |
             *        +---+---+---+---+---+---+---+---+
             *        /       removal bit mask        /  1-2 octets
             *        +---+---+---+---+---+---+---+---+
             *        /      insertion bit mask       /  1-2 octets
             *        +---+---+---+---+---+---+---+---+
             *        |            XI list            |  k octets, or (k - 1) * 4 bits
             *        /                --- --- --- ---/
             *        |               :    Padding    :  if PS = 0 and k is even
             *        +---+---+---+---+---+---+---+---+
             *        |                               |
             *        /       item 1, ..., item n     /  variable
             *        |                               |
             *        +---+---+---+---+---+---+---+---+
             *
             */
            PS = (first_byte & 0x10) >> 4;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_ps, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*      XI 1: When PS = 0, the first 4-bit XI item is placed here.
             *            When PS = 1, the field is set to zero when sending, and
             *            ignored when receiving.
             */
            if (PS==0) {
                proto_tree_add_item(list_tree, hf_rohc_compressed_list_xi_1, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            offset++;
            /* GP: Indicates presence of gen_id field. */
            if (GP) {
                proto_tree_add_item(list_tree, hf_rohc_compressed_list_gen_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_ref_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

             /*
              *  removal bit mask: Indicates the elements in ref_list to be
              *  removed in order to obtain the current list.  See section
              *  5.8.3.  The removal bit mask has the same format as the
              *  insertion bit mask of section 5.8.6.3.
              */

            bit_mask_size = (tvb_get_uint8(tvb,offset)&0x80)>>7;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_mask_size, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (bit_mask_size) {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_rem_bit_mask, tvb, (offset<<3)+1, 15, ENC_BIG_ENDIAN);
                offset+=2;
            } else {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_rem_bit_mask, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
                offset++;
            }

            /*
             *      insertion bit mask: Bit mask indicating the positions where new
             *                items are to be inserted.  See Insertion Only scheme in
             *                section 5.8.3.  The bit mask can have either of the
             *                following two formats:
             *
             *
             *           0   1   2   3   4   5   6   7
             *         +---+---+---+---+---+---+---+---+
             *         | 0 |        7-bit mask         |  bit 1 is the first bit
             *         +---+---+---+---+---+---+---+---+
             *
             *         +---+---+---+---+---+---+---+---+
             *         | 1 |                           |  bit 1 is the first bit
             *         +---+      15-bit mask          +
             *         |                               |  bit 7 is the last bit
             *         +---+---+---+---+---+---+---+---+
             */
            bit_mask_size = (tvb_get_uint8(tvb,offset)&0x80)>>7;
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_mask_size, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (bit_mask_size) {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_ins_bit_mask, tvb, (offset<<3)+1, 15, ENC_BIG_ENDIAN);
                offset+=2;
            } else {
                proto_tree_add_bits_item(list_tree, hf_rohc_compressed_list_ins_bit_mask, tvb, (offset<<3)+1, 7, ENC_BIG_ENDIAN);
                offset++;
            }
            /* TODO: */
            offset++;
            break;
    }

    proto_item_set_len(list_ti, offset-start_offset);

    return offset;
}

static int
dissect_rohc_ir_profile_dynamic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                int offset, uint8_t profile, rohc_cid_context_t *rohc_cid_context)
{
    proto_item *item, *root_ti;
    proto_tree *sub_tree = NULL, *dynamic_ipv4_tree, *dynamic_udp_tree, *dynamic_rtp_tree;
    uint8_t     oct, rx, /* cc, */ val_len = 0;
    int         start_offset, tree_start_offset;
    uint8_t     tos, ttl, nbo;
    uint16_t    id;
    /*uint8_t    contributing_csrcs;*/
    uint16_t    sequence_number;
    uint32_t    timestamp;
#if 0
    uint8_t     tis = 0, tss=0;
    uint64_t    ts_stride = 0;
#endif
    start_offset = offset;

    /* Create subtree according to profile */
    switch (profile) {
        case ROHC_PROFILE_UNCOMPRESSED:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_dynamic, &item, "Profile 0x0000 Uncompressed");
            break;

        case ROHC_PROFILE_RTP:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_dynamic, &item, "Profile 0x0001 RTP Dynamic Chain");
            break;

        case ROHC_PROFILE_UDP:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_dynamic, &item, "Profile 0x0002 UDP Dynamic Chain");
            break;

        case ROHC_PROFILE_IP:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_dynamic, &item, "Profile 0x0004 IP Dynamic Chain");
            break;

        default:
            proto_tree_add_expert(tree, pinfo, &ei_rohc_profile_not_supported, tvb, offset, 0);
            return -1;
    }

    /* IP dynamic */
    /* for all profiles except uncompressed */
    if (profile != ROHC_PROFILE_UNCOMPRESSED) {
        switch (rohc_cid_context->rohc_ip_version) {
            case 4:
                /* 5.7.7.4.  Initialization of IPv4 Header [IPv4, section 3.1].
                 * Dynamic part:
                 */
                /* Create dynamic IPv4 subtree */
                tree_start_offset = offset;
                root_ti = proto_tree_add_item(sub_tree, hf_rohc_dynamic_ipv4, tvb, offset, -1, ENC_NA);
                dynamic_ipv4_tree = proto_item_add_subtree(root_ti, ett_rohc_dynamic_ipv4);

                /* Type of Service */
                tos = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_tos, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Time to Live */
                ttl = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Identification */
                id = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset+=2;
                /*    +---+---+---+---+---+---+---+---+
                 *    | DF|RND|NBO|         0         |
                 *    +---+---+---+---+---+---+---+---+
                 */
                rohc_cid_context->rnd = (tvb_get_uint8(tvb, offset) & 0x40) >> 6;
                nbo = (tvb_get_uint8(tvb, offset) & 0x20) >> 5;
                /* DF */
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_df, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* RND */
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_rnd, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* NBO */
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_nbo, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* Spare */
                proto_tree_add_bits_item(dynamic_ipv4_tree, hf_rohc_spare_bits, tvb, (offset<<3)+3, 5, ENC_BIG_ENDIAN);
                offset++;

                /*   +---+---+---+---+---+---+---+---+
                 *   / Generic extension header list /  variable length
                 *   +---+---+---+---+---+---+---+---+
                 *   Generic extension header list: Encoded according to section
                 *   5.8.6.1, with all header items present in uncompressed form.
                 */
                offset = dissect_compressed_list(0, pinfo, dynamic_ipv4_tree, tvb, offset);

                /* Set proper length for subtree */
                proto_item_set_len(root_ti, offset-tree_start_offset);

                /* Add summary to ipv4 root item */
                proto_item_append_text(root_ti, " (ToS=%u, TTL=%u, ID=%u, RND=%u, NBO=%u)",
                                       tos, ttl, id, rohc_cid_context->rnd, nbo);
                break;
            case 6:

                /* Dynamic part:
                 *    +---+---+---+---+---+---+---+---+
                 *    |         Traffic Class         |   1 octet
                 *    +---+---+---+---+---+---+---+---+
                 *    |           Hop Limit           |   1 octet
                 *    +---+---+---+---+---+---+---+---+
                 *    / Generic extension header list /   variable length
                 *    +---+---+---+---+---+---+---+---+
                 */

                /* Traffic Class */
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_tc, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Hop Limit */
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* XXX TODO: use the IPv6 dissector to dissect Generic extension header list ?*/
                proto_tree_add_expert(sub_tree, pinfo, &ei_rohc_not_dissected_yet, tvb, offset, -1);
                return -1;
            default:
                break;
        }
    }

    /* UDP dynamic */
    if ( (profile == ROHC_PROFILE_UDP)  ||
         (profile == ROHC_PROFILE_RTP)      ) {
        /* 5.7.7.5.  Initialization of UDP Header
         * Dynamic part:
         *
         *      +---+---+---+---+---+---+---+---+
         *      /           Checksum            /   2 octets
         *      +---+---+---+---+---+---+---+---+
         */
        /* Create dynamic UDP subtree */
        root_ti = proto_tree_add_item(sub_tree, hf_rohc_dynamic_udp, tvb, offset, 2, ENC_NA);
        dynamic_udp_tree = proto_item_add_subtree(root_ti, ett_rohc_dynamic_udp);
        id = tvb_get_ntohs(tvb, offset);
        rohc_cid_context->udp_checksum_present = (id) ? true : false;
        /* Checksum */
        proto_tree_add_checksum(dynamic_udp_tree, tvb, offset, hf_rohc_dynamic_udp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        offset += 2;
        if (profile == ROHC_PROFILE_UDP) {
            /* IP-ID 5.11.1 */
            proto_tree_add_item(dynamic_udp_tree, hf_rohc_comp_ip_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        proto_item_set_len(item, offset - start_offset);
    }

    /* RTP  dynamic*/
    if (profile == ROHC_PROFILE_RTP) {
        /* 5.7.7.6.  Initialization of RTP Header
         * Dynamic part:
         * Checksum
         *      P, X, CC, PT, M, sequence number, timestamp, timestamp stride,
         *      CSRC identifiers.
         *
         *        0   1   2   3   4   5   6   7
         *      +---+---+---+---+---+---+---+---+
         *      |  V=2  | P | RX|      CC       |  (RX is NOT the RTP X bit)
         *      +---+---+---+---+---+---+---+---+
         *      | M |            PT             |
         *      +---+---+---+---+---+---+---+---+
         *      /      RTP Sequence Number      /  2 octets
         *      +---+---+---+---+---+---+---+---+
         *      /   RTP Timestamp (absolute)    /  4 octets
         *      +---+---+---+---+---+---+---+---+
         *      /      Generic CSRC list        /  variable length
         *      +---+---+---+---+---+---+---+---+
         *      : Reserved  | X |  Mode |TIS|TSS:  if RX = 1
         *      +---+---+---+---+---+---+---+---+
         *      :         TS_Stride             :  1-4 octets, if TSS = 1
         *      +---+---+---+---+---+---+---+---+
         *      :         Time_Stride           :  1-4 octets, if TIS = 1
         *      +---+---+---+---+---+---+---+---+
         */

        /* Create dynamic RTP subtree */
        root_ti = proto_tree_add_item(sub_tree, hf_rohc_dynamic_rtp, tvb, offset, -1, ENC_NA);
        dynamic_rtp_tree = proto_item_add_subtree(root_ti, ett_rohc_dynamic_rtp);

        tree_start_offset = offset;
        /* V */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_v, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* P */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_p, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* RX */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* CC */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_cc, tvb, offset, 1, ENC_BIG_ENDIAN);
        oct = tvb_get_uint8(tvb,offset);
        /* cc = oct & 0x0f; */
        rx = (oct >> 4)& 0x01;
        offset++;

        /* M */
        proto_tree_add_bits_item(dynamic_rtp_tree, hf_rohc_rtp_m, tvb, (offset<<3), 1, ENC_BIG_ENDIAN);
        /* PT */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_pt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* RTP Sequence Number */
        sequence_number = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* RTP Timestamp (absolute) */
        timestamp = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        /* RFC 4815
         * This field is always at least one octet in size, even if the
         *    list is empty (as opposed to the CSRC list in the uncompressed RTP
         *    header, which is not present when the RTP CC field is set to 0).
         * :
         * Generic CSRC list: CSRC list encoded according to section
         * 5.8.6.1, with all CSRC items present.
         * FORMAL ADDITION TO RFC 3095:
         *
         *      "The first octet in the dynamic part of the RTP header contains a
         *       CC field, as defined in Section 5.7.7.6.  A second occurrence
         *       appears in the 'Generic CSRC list', which is also in the dynamic
         *       part of the RTP header, where Encoding Type 0 is used according
         *       to the format defined in RFC 3095-5.8.6.1.
         *
         *       The compressor MUST set both occurrences of the CC field to the
         *       same value.
         *
         *       The decompressor MUST use the value of the CC field from the
         *       Encoding Type 0 within the Generic CRSC list, and it MUST thus
         *       ignore the first occurrence of the CC field."
         */

        offset = dissect_compressed_list(0, pinfo, dynamic_rtp_tree, tvb, offset);
        /* : Reserved  | X |  Mode |TIS|TSS:  if RX = 1 */
        if (rx==0) {
            return offset;
        }
        /* X */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_x, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* Mode */
        rohc_cid_context->mode = (enum rohc_mode)((tvb_get_uint8(tvb,offset) &  0x0c)>>2);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* TIS */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_tis, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* TSS */
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_tss, tvb, offset, 1, ENC_BIG_ENDIAN);
        oct = tvb_get_uint8(tvb,offset);
        offset++;

        /* TS_Stride             :  1-4 octets, if TSS = 1 */
        if ((oct&0x01)== 1) {
            /* TS_Stride encoded as
             * 4.5.6.  Self-describing variable-length values
             */
            get_self_describing_var_len_val(tvb, dynamic_rtp_tree, offset, hf_rohc_rtp_ts_stride, &val_len);
            offset = offset + val_len;
        }

        /* Time_Stride           :  1-4 octets, if TIS = 1 */
        if ((oct&0x02)==2) {
            /* Time_Stride encoded as
             * 4.5.6.  Self-describing variable-length values
             */
            get_self_describing_var_len_val(tvb, dynamic_rtp_tree, offset, hf_rohc_rtp_time_stride, &val_len);
            offset = offset + val_len;
        }
        /* Set proper length for subtree */
        proto_item_set_len(root_ti, offset-tree_start_offset);

        /* Add summary to root item */
        proto_item_append_text(root_ti, " (seqnum = %u, timestamp = %u)",
                               sequence_number, timestamp);

        proto_item_set_len(item, offset - start_offset);
    }
    return offset;
}

static int
dissect_rohc_ir_rtp_udp_ip_profile_static(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, int offset, bool d, uint8_t profile, rohc_cid_context_t *rohc_cid_context)
{
    proto_item *item, *ipv4_item, *udp_item, *rtp_item, *ver_item;
    proto_tree *sub_tree = NULL, *static_ipv4_tree, *static_udp_tree, *static_rtp_tree;
    uint8_t     version, protocol;
    int         start_offset, tree_start_offset;

    start_offset = offset;

    /* Create subtree root according to profile */
    switch (profile) {

        case ROHC_PROFILE_UNCOMPRESSED:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_static, &item, "Profile 0x0000 Uncompressed");
            break;

        case ROHC_PROFILE_RTP:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_static, &item, "Profile 0x0001 RTP Static Chain");
            break;

        case ROHC_PROFILE_UDP:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_static, &item, "Profile 0x0002 UDP Static Chain");
            break;

        case ROHC_PROFILE_IP:
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_rohc_rtp_static, &item, "Profile 0x0004 IP Static Chain");
            break;

        default:
            proto_tree_add_expert(tree, pinfo, &ei_rohc_profile_not_supported, tvb, offset, 0);
            return -1;
    }

    /* IP static*/
    /* for all profiles except uncompressed */
    if (profile != ROHC_PROFILE_UNCOMPRESSED) {
        version = tvb_get_uint8(tvb,offset)>>4;
        if (profile == ROHC_PROFILE_IP) {
            /* RFC 3843 chapter 3.1; alternate encoding can set IP version field MSB to 1 */
            version &= 0x07;
            ver_item = proto_tree_add_item(sub_tree, hf_rohc_ip_version_ip_profile, tvb, offset, 1, ENC_BIG_ENDIAN);
        } else {
            ver_item = proto_tree_add_item(sub_tree, hf_rohc_ip_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        rohc_cid_context->rohc_ip_version = version;

        switch (version) {
            case 4:
            {
                /* 5.7.7.4.  Initialization of IPv4 Header [IPv4, section 3.1].
                 * Static part:
                 */
                uint32_t source, dest;

                offset++;
                tree_start_offset = offset;
                /* Create static IPv4 subtree */
                ipv4_item = proto_tree_add_item(sub_tree, hf_rohc_static_ipv4, tvb, offset, -1, ENC_NA);
                static_ipv4_tree = proto_item_add_subtree(ipv4_item, ett_rohc_static_ipv4);
                /* Protocol */
                protocol = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(static_ipv4_tree, hf_rohc_ip_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Source Address */
                source = tvb_get_ipv4(tvb, offset);
                proto_tree_add_item(static_ipv4_tree, hf_rohc_ipv4_src, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                /* Destination Address */
                dest = tvb_get_ipv4(tvb, offset);
                proto_tree_add_item(static_ipv4_tree, hf_rohc_ipv4_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                /* Set proper length for subtree */
                proto_item_set_len(ipv4_item, offset-tree_start_offset);

                /* Add summary to root item */
                proto_item_append_text(ipv4_item, " (prot=%s: %s -> %s)",
                                       val_to_str_ext_const(protocol, &ipproto_val_ext, "Unknown"),
                                       get_hostname(source),
                                       get_hostname(dest));
                break;
            }
            case 6:
                /* 5.7.7.3.  Initialization of IPv6 Header [IPv6]*/
                /*   Static part:
                 *
                 *      +---+---+---+---+---+---+---+---+
                 *      |  Version = 6  |Flow Label(msb)|   1 octet
                 *      +---+---+---+---+---+---+---+---+
                 *      /        Flow Label (lsb)       /   2 octets
                 *      +---+---+---+---+---+---+---+---+
                 *      |          Next Header          |   1 octet
                 *      +---+---+---+---+---+---+---+---+
                 *      /        Source Address         /   16 octets
                 *      +---+---+---+---+---+---+---+---+
                 *      /      Destination Address      /   16 octets
                 *      +---+---+---+---+---+---+---+---+
                 */

                /* Flow Label */
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_flow, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset+=3;

                /* Next Header */
                protocol = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_nxt_hdr, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                /* Source Address */
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_src, tvb, offset, 16, ENC_NA);
                offset+=16;

                /*  Destination Address */
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_dst, tvb, offset, 16, ENC_NA);
                offset+=16;
                break;

            default:
                expert_add_info(pinfo, ver_item, &ei_rohc_ip_version);
                return -1;
        }
    } else {
        protocol = 0; /* Something other than UDP (which is checked for below) */
    }

    if (protocol == IP_PROTO_UDP) {
        /* UDP static */
        if ((profile == ROHC_PROFILE_RTP) ||
            (profile == ROHC_PROFILE_UDP)) {
            /* 5.7.7.5.  Initialization of UDP Header [RFC-768].
             * Static part
             */
            uint16_t source_port, dest_port;
            uint32_t ssrc;

            /* Create static UDP subtree */
            tree_start_offset = offset;
            udp_item = proto_tree_add_item(sub_tree, hf_rohc_static_udp, tvb, offset, -1, ENC_NA);
            static_udp_tree = proto_item_add_subtree(udp_item, ett_rohc_static_udp);
            /* Source Port */
            source_port = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(static_udp_tree, hf_rohc_udp_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            /* Destination Port */
            dest_port = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(static_udp_tree, hf_rohc_udp_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            /* Set proper length for subtree */
            proto_item_set_len(udp_item, offset-tree_start_offset);
            /* Add summary to root item */
            proto_item_append_text(udp_item, " (%u -> %u)", source_port, dest_port);

            if (profile == ROHC_PROFILE_UDP) {
                proto_item_set_len(item, offset - start_offset);
                if (d) {
                    /* UDP Dynamic */
                    offset = dissect_rohc_ir_profile_dynamic(tvb, pinfo, tree, offset, profile, rohc_cid_context);
                }
                return offset;
            }

            /* RTP static */
            /* 5.7.7.6.  Initialization of RTP Header [RTP]. */
            /* Create static RTP subtree */
            rtp_item = proto_tree_add_item(sub_tree, hf_rohc_static_rtp, tvb, offset, 4, ENC_NA);
            static_rtp_tree = proto_item_add_subtree(rtp_item, ett_rohc_static_rtp);

            /* SSRC */
            ssrc = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(static_rtp_tree, hf_rohc_rtp_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Add summary to root item */
            proto_item_append_text(rtp_item, " (SSRC=0x%08x)", ssrc);

            proto_item_set_len(item, offset - start_offset);

            /* D:   D = 1 indicates that the dynamic chain is present. */
            if (d==true) {
                offset = dissect_rohc_ir_profile_dynamic(tvb, pinfo, tree, offset, profile, rohc_cid_context);
            }
        }
    } else if (profile == ROHC_PROFILE_IP) {
        proto_item_set_len(item, offset - start_offset);
        if (d==true) {
            offset = dissect_rohc_ir_profile_dynamic(tvb, pinfo, tree, offset, profile, rohc_cid_context);
        }
        return offset;
    } else {
        proto_tree_add_expert(sub_tree, pinfo, &ei_rohc_not_dissected_yet, tvb, offset, -1);
    }
    return offset;
}

static int
dissect_rohc_ir_packet(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                       int offset, uint16_t cid, bool is_add_cid, rohc_info *p_rohc_info)
{
    proto_item         *ir_item, *item;
    proto_tree         *ir_tree;
    int                 ir_item_start;
    int                 x_bit_offset;
    bool                d = false;
    uint8_t             oct, profile, val_len = 0;
    int16_t             feedback_data_len = 0;
    tvbuff_t           *next_tvb;
    rohc_cid_context_t *rohc_cid_context = NULL;

    /* The cid value must have been dissected and valid
     * offset must point to the IR octet  see below ( | 1   1   1   1   1   1   0 | D |  )
     * TODO: CRC validation
     */

     /*
      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
    |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
    | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
    /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
    |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
    |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
    |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
    |         Dynamic chain         |  present if D = 1, variable length
    |                               |
     - - - - - - - - - - - - - - - -
    |                               |
    |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

    */
    oct = tvb_get_uint8(tvb,offset);

    if (!p_rohc_info->large_cid_present && !is_add_cid) {
        item = proto_tree_add_uint(tree, hf_rohc_small_cid, tvb, 0, 0, cid);
        proto_item_set_generated(item);
    }
    ir_item = proto_tree_add_item(tree, hf_rohc_ir_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
    ir_tree = proto_item_add_subtree(ir_item, ett_rohc_ir);
    ir_item_start = offset;
    d = oct & 0x01;
    x_bit_offset = offset;
    offset++;
    if (p_rohc_info->large_cid_present) {
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, ir_tree, offset, hf_rohc_large_cid, &val_len);
        offset = offset + val_len;
    }

    /* Read profile */
    profile = tvb_get_uint8(tvb,offset);

    /* D (all profiles?) */
    if ((profile==ROHC_PROFILE_RTP) || (profile==ROHC_PROFILE_UDP)) {
        proto_tree_add_item(ir_tree, hf_rohc_d_bit, tvb, x_bit_offset, 1, ENC_BIG_ENDIAN);
    }

    /* Profile.
     *  In the IR packet, the profile identifier is abbreviated to the 8 least
     * significant bits.  It selects the highest-number profile in the
     * channel state parameter PROFILES that matches the 8 LSBs given. */
    proto_tree_add_item(ir_tree, hf_rohc_profile, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* CRC */
    proto_tree_add_item(ir_tree, hf_rohc_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* See if we have an entry for this CID
     * Update it if we do otherwise create it
     * and fill in the info.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        int key = cid;
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, GUINT_TO_POINTER(key));
        if (rohc_cid_context != NULL) {
            /* This is not the first IR packet seen*/
            int tmp_prev_ir_frame_number = rohc_cid_context->ir_frame_number;
            int tmp_prev_rohc_ip_version = rohc_cid_context->rohc_ip_version;
            int tmp_prev_mode = rohc_cid_context->mode;
            bool tmp_prev_rnd = rohc_cid_context->rnd;
            bool tmp_prev_udp_checksum_present = rohc_cid_context->udp_checksum_present;

            /*ws_warning("IR pkt found CID %u",cid);*/

            rohc_cid_context = wmem_new(wmem_file_scope(), rohc_cid_context_t);
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = tmp_prev_ir_frame_number;
            rohc_cid_context->ir_frame_number = pinfo->num;
            rohc_cid_context->rohc_ip_version = tmp_prev_rohc_ip_version;
            rohc_cid_context->mode = (enum rohc_mode)tmp_prev_mode;
            rohc_cid_context->rnd = tmp_prev_rnd;
            rohc_cid_context->udp_checksum_present = tmp_prev_udp_checksum_present;
            rohc_cid_context->large_cid_present = p_rohc_info->large_cid_present;

            g_hash_table_replace(rohc_cid_hash, GUINT_TO_POINTER(key), rohc_cid_context);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0, rohc_cid_context);
        } else {
            rohc_cid_context = wmem_new(wmem_file_scope(), rohc_cid_context_t);
            rohc_cid_context->large_cid_present = p_rohc_info->large_cid_present;
            rohc_cid_context->mode = 0;
            /*rohc_cid_context->d_mode;*/
            rohc_cid_context->rnd = false;
            rohc_cid_context->udp_checksum_present = false;
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = pinfo->num;
            rohc_cid_context->rohc_ip_version = p_rohc_info->rohc_ip_version;
            rohc_cid_context->mode = p_rohc_info->mode;

            /*ws_warning("IR pkt New CID %u",cid);*/

            g_hash_table_insert(rohc_cid_hash, GUINT_TO_POINTER(key), rohc_cid_context);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0, rohc_cid_context);
        }
    } else {
        /* get the stored data */
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0);
    }

    switch (profile) {
        case ROHC_PROFILE_UNCOMPRESSED:
            /* Just an ip frame */
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                oct = tvb_get_uint8(tvb, offset);
                if ((oct&0xf0) == 0x60) {
                    next_tvb = tvb_new_subset_remaining(tvb, offset);
                    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
                    offset += tvb_captured_length_remaining(tvb, offset);
                }
                else if ((oct&0xf0) == 0x40) {
                    next_tvb = tvb_new_subset_remaining(tvb, offset);
                    call_dissector(ip_handle, next_tvb, pinfo, tree);
                    offset += tvb_captured_length_remaining(tvb, offset);
                }
                col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "ROHC/");
            }
            break;
        case ROHC_PROFILE_RTP:
        case ROHC_PROFILE_UDP:
        case ROHC_PROFILE_IP:
            offset = dissect_rohc_ir_rtp_udp_ip_profile_static(tvb, ir_tree, pinfo, offset, d, profile, rohc_cid_context);
            break;

        default:
            proto_tree_add_expert(ir_tree, pinfo, &ei_rohc_profile_specific, tvb, offset, feedback_data_len);
            offset = -1;
            break;
    }

    if (offset != -1) {
        /* Set length of IR header */
        proto_item_set_len(ir_item, offset-ir_item_start);
    }

    return offset;
}

static int
dissect_rohc_ir_dyn_packet(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                           int offset, uint16_t cid, bool is_add_cid, rohc_info *p_rohc_info)
{
    proto_item         *ir_item, *item;
    proto_tree         *ir_tree;
    int                 ir_item_start;
    uint8_t             profile, val_len = 0;
    int16_t             feedback_data_len = 0;
    rohc_cid_context_t *rohc_cid_context;

    /* Add-CID */
    if (!p_rohc_info->large_cid_present && !is_add_cid) {
        item = proto_tree_add_uint(tree, hf_rohc_small_cid, tvb, 0, 0, cid);
        proto_item_set_generated(item);
    }

    ir_item = proto_tree_add_item(tree, hf_rohc_ir_dyn_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
    ir_tree = proto_item_add_subtree(ir_item, ett_rohc_ir_dyn);
    ir_item_start = offset;
    offset++;

    if (p_rohc_info->large_cid_present) {
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, ir_tree, offset, hf_rohc_large_cid, &val_len);
        offset = offset + val_len;
    }

    /* Profile */
    profile = tvb_get_uint8(tvb,offset);
    proto_tree_add_item(ir_tree, hf_rohc_profile, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* See if we have an entry for this CID
     * Update it if we do otherwise create it
     * and fill in the info.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        int key = cid;
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, GUINT_TO_POINTER(key));

        if (rohc_cid_context) {
            /* This is not the first IR packet seen*/
            int tmp_prev_ir_frame_number = rohc_cid_context->ir_frame_number;
            int tmp_prev_rohc_ip_version = rohc_cid_context->rohc_ip_version;
            int tmp_prev_mode = rohc_cid_context->mode;
            bool tmp_prev_rnd = rohc_cid_context->rnd;
            bool tmp_prev_udp_checksum_present = rohc_cid_context->udp_checksum_present;

            /*ws_warning("IR pkt found CID %u",cid);*/

            rohc_cid_context = wmem_new(wmem_file_scope(), rohc_cid_context_t);
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = tmp_prev_ir_frame_number;
            rohc_cid_context->ir_frame_number = pinfo->num;
            rohc_cid_context->rohc_ip_version = tmp_prev_rohc_ip_version;
            rohc_cid_context->mode = (enum rohc_mode)tmp_prev_mode;
            rohc_cid_context->rnd = tmp_prev_rnd;
            rohc_cid_context->udp_checksum_present = tmp_prev_udp_checksum_present;
            rohc_cid_context->large_cid_present = p_rohc_info->large_cid_present;

            g_hash_table_replace(rohc_cid_hash, GUINT_TO_POINTER(key), rohc_cid_context);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0, rohc_cid_context);
        } else {
            rohc_cid_context = wmem_new(wmem_file_scope(), rohc_cid_context_t);
            rohc_cid_context->rohc_ip_version = 0;
            rohc_cid_context->large_cid_present = p_rohc_info->large_cid_present;
            /*rohc_cid_context->d_mode;*/
            rohc_cid_context->rnd = false;
            rohc_cid_context->udp_checksum_present = false;
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = pinfo->num;
            rohc_cid_context->mode = p_rohc_info->mode;

            /*ws_warning("IR pkt New CID %u",cid);*/

            g_hash_table_insert(rohc_cid_hash, GUINT_TO_POINTER(key), rohc_cid_context);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0, rohc_cid_context);
        }
    } else {
        /* get the stored data */
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0);
    }

    /* CRC */
    proto_tree_add_item(ir_tree, hf_rohc_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Profile specific information */
    switch (profile ) {
        case ROHC_PROFILE_RTP:
        case ROHC_PROFILE_UDP:
            offset = dissect_rohc_ir_profile_dynamic(tvb, pinfo, ir_tree, offset, profile, rohc_cid_context);
            break;

        default:
            proto_tree_add_expert(ir_tree, pinfo, &ei_rohc_profile_specific, tvb, offset, feedback_data_len);
            break;
    }

    /* Set length of IR-DYN header */
    if (offset != -1) {
        proto_item_set_len(ir_item, offset-ir_item_start);
    }

    return offset;
}

/******************************/
/* Main dissection function.  */
static int
dissect_rohc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data /* rohc_info* */)
{
    proto_item         *ti, *item, *conf_item;
    proto_tree         *rohc_tree, *sub_tree = NULL, *conf_tree;
    int                 offset               = 0, length;
    uint8_t             oct, code, size, val_len = 0;
    int16_t             feedback_data_len, cid = 0;
    bool                is_add_cid           = false;
    rohc_info          *p_rohc_info          = NULL;
    rohc_info           g_rohc_info;
    tvbuff_t           *next_tvb=NULL, *payload_tvb;
    rohc_cid_context_t *rohc_cid_context     = NULL;

    if (data == NULL) {
        /* No rohc_info passed in, set some defaults */
        g_rohc_info.rohc_compression     = false;
        g_rohc_info.rohc_ip_version      = g_version;
        g_rohc_info.cid_inclusion_info   = false;
        g_rohc_info.large_cid_present    = false;
        g_rohc_info.mode                 = RELIABLE_BIDIRECTIONAL;
        g_rohc_info.rnd                  = false;
        g_rohc_info.udp_checksum_present = false;
        g_rohc_info.profile              = g_profile;
        g_rohc_info.last_created_item    = NULL;
        p_rohc_info = &g_rohc_info;
    } else {
        /* Use info passed in */
        p_rohc_info = (rohc_info *)data;
        /* TODO: contents not referenced again, so why do this? */
        memset(&g_rohc_info, 0, sizeof(rohc_info));
    }

    length = tvb_reported_length(tvb);

    /* If this is ROHC ethertype clear col */
    if (pinfo->src.type == AT_ETHER) {
        col_set_str(pinfo->cinfo, COL_INFO, "ROHC");
        col_clear(pinfo->cinfo, COL_INFO);
    } else {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "|ROHC");
        /* Append a space if we add stuff to existing col info */
        col_append_str(pinfo->cinfo, COL_INFO, " ");
    }

    /* Add ROHC root */
    ti = proto_tree_add_item(tree, proto_rohc, tvb, 0, -1, ENC_NA);
    rohc_tree = proto_item_add_subtree(ti, ett_rohc);

    /* Put configuration data into the tree */
    conf_tree = proto_tree_add_subtree_format(rohc_tree, tvb, offset, 0, ett_rohc_conf, &item,
                                              "Global Configuration: (%s)",
                                              p_rohc_info->large_cid_present ? "Large CID" : "Small CID");
    proto_item_set_generated(item);

    /* Look for cid context info attached to frame */
    rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0 /* key */);
    if (rohc_cid_context) {
        /* Do we have info from an IR frame? */
        if (rohc_cid_context->ir_frame_number>0) {
            /* Show was configured by IR Packet */
            conf_item = proto_tree_add_item(conf_tree, hf_rohc_configured_by_ir_packet, tvb, offset, 0, ENC_NA);
            proto_item_set_generated(conf_item);
            /* No. of IR setup frame */
            conf_item = proto_tree_add_uint(conf_tree, hf_rohc_ir_pkt_frame, tvb, 0, 0, rohc_cid_context->ir_frame_number);
            proto_item_set_generated(conf_item);

            /* Any previous IR frame number */
            if (rohc_cid_context->prev_ir_frame_number>0) {
                conf_item = proto_tree_add_uint(conf_tree, hf_rohc_ir_previous_frame, tvb, 0, 0, rohc_cid_context->prev_ir_frame_number);
                proto_item_set_generated(conf_item);
            }

            /* Profile */
            conf_item = proto_tree_add_uint(conf_tree, hf_rohc_ir_profile, tvb, offset, 0, rohc_cid_context->profile);
            proto_item_set_generated(conf_item);
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s: ", val_to_str_const(rohc_cid_context->profile, rohc_profile_vals, "Unknown"));

            /* IP Version number */
            conf_item = proto_tree_add_uint(conf_tree, hf_rohc_ir_ip_version, tvb, offset, 0, rohc_cid_context->rohc_ip_version);
            proto_item_set_generated(conf_item);

            /* IR mode */
            if (rohc_cid_context->mode == 0) {
                conf_item = proto_tree_add_uint_format_value(conf_tree, hf_rohc_ir_mode, tvb, offset, 0, 0, "not known");
                proto_item_set_generated(conf_item);
            } else {
                conf_item = proto_tree_add_uint(conf_tree, hf_rohc_ir_mode, tvb, offset, 0, rohc_cid_context->mode);
                proto_item_set_generated(conf_item);
            }

        } else {
            /* No IR frame number stored in context */
            conf_item = proto_tree_add_item(conf_tree, hf_rohc_no_configuration_info, tvb, offset, 0, ENC_NA);
            proto_item_set_generated(conf_item);
        }
    }


start_over:
    /* N.B. These steps are the procedure described in 5.2.6.  ROHC initial decompressor processing */

    /*    1) If the first octet is a Padding Octet (11100000),
     *       strip away all initial Padding Octets and goto next step.
     */
    cid = 0;
    oct = tvb_get_uint8(tvb,offset);
    if (oct== 0xe0) {
        while (oct == 0xe0) {
            offset++;
            oct = tvb_get_uint8(tvb,offset);
        }
        proto_tree_add_item(rohc_tree, hf_rohc_padding, tvb, 0, offset, ENC_NA);
    }

    /* 2) If the first remaining octet starts with 1110, it is an Add-CID octet:
     *    remember the Add-CID octet; remove the octet.
     */
    if ((oct&0xf0) == 0xe0) {
        is_add_cid = true;
        cid = oct & 0x0f;
        proto_tree_add_item(rohc_tree, hf_rohc_add_cid, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, offset, 1, cid);
        offset++;

        oct = tvb_get_uint8(tvb,offset);
    }

    /* feedback ?
     * Feedback (begins with 11110)
     */
    if ((oct&0xf8) == 0xf0) {
        /* 3) If the first remaining octet starts with 11110, and an Add-CID
         *    octet was found in step 2), an error has occurred;
         *    the header MUST be discarded without further action.
         */

        int feedback_start = offset;

        if (is_add_cid) {
            p_rohc_info->last_created_item = proto_tree_add_item(rohc_tree, hf_rohc_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, "Error packet");
            proto_tree_add_item(rohc_tree, hf_rohc_error_packet, tvb, offset, -1, ENC_NA);
            return tvb_captured_length(tvb);
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, "Feedback ");
            /* 4) If the first remaining octet starts with 11110, and an Add-CID
             *    octet was not found in step 2), this is feedback:
             *        find the size of the feedback data, call it s;
             *        remove the feedback type octet;
             *        remove the Size octet if Code is 0;
             *        send feedback data of length s to the same-side associated
             *        compressor;
             *        if packet exhausted, stop; otherwise goto 2).
             */

            /* Feedback subtree */
            p_rohc_info->last_created_item = proto_tree_add_item(rohc_tree, hf_rohc_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
            sub_tree = proto_item_add_subtree(p_rohc_info->last_created_item, ett_rohc_fb);
            /* Code */
            proto_tree_add_item(sub_tree, hf_rohc_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            code = oct&0x7;
            offset++;
            if (code==0) {
                /* Separate size field */
                size = tvb_get_uint8(tvb,offset);
                proto_tree_add_item(sub_tree, hf_rohc_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            } else {
                /* Size is in code field itself. */
                size = code;
            }
            feedback_data_len = size;
            /* CID */
            if (!p_rohc_info->large_cid_present) {
                /* Check for Add-CID octet */
                oct = tvb_get_uint8(tvb,offset);
                if ((oct&0xf0) == 0xe0) {
                    cid = oct & 0x0f;
                    proto_tree_add_item(sub_tree, hf_rohc_add_cid, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(sub_tree, hf_rohc_small_cid, tvb, offset, 1, cid);
                    offset++;
                    feedback_data_len--;
                } else {
                    item = proto_tree_add_uint(sub_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
                    proto_item_set_generated(item);
                }
            } else {
                /* Read Large CID here */
                get_self_describing_var_len_val(tvb, sub_tree, offset, hf_rohc_large_cid, &val_len);
                /* feedback_data_len - "length of large CID" */
                feedback_data_len = feedback_data_len - val_len;
                offset += val_len;
            }

            /* Dissect feedback */
            dissect_rohc_feedback_data(tvb, sub_tree, pinfo, offset, feedback_data_len, p_rohc_info, cid, p_rohc_info != &g_rohc_info);
            offset += size;
            if (offset<length) {
                goto start_over;
            }

            proto_item_set_len(p_rohc_info->last_created_item, offset-feedback_start);
            return tvb_captured_length(tvb);
        }
    }/*feedback */

    /* 5) If the first remaining octet starts with 1111111, this is a segment:
     *
     */
    if ((oct&0xfe) == 0xfe) {
        col_append_str(pinfo->cinfo, COL_INFO, "Segment");
        if (!p_rohc_info->large_cid_present && !is_add_cid) {
            item = proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
            proto_item_set_generated(item);
        }
        /* Segmentation not supported! */
        proto_tree_add_expert(rohc_tree, pinfo, &ei_rohc_desegmentation_not_implemented, tvb, offset, -1);
        return tvb_captured_length(tvb);
    }

    /* 6) Here, it is known that the rest is forward information (unless the
     *    header is damaged).
     */
    if ((oct&0xfe) == 0xfc) {
        col_append_str(pinfo->cinfo, COL_INFO, "IR");
        offset = dissect_rohc_ir_packet(tvb, rohc_tree, pinfo, offset, cid, is_add_cid, p_rohc_info);
        if (offset == -1) {
            /* Could not parse header */
            return tvb_captured_length(tvb);
        }

        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(payload_tvb, pinfo, rohc_tree);
        return tvb_captured_length(tvb);
    }
    if ((oct&0xff) == 0xf8) {
        col_append_str(pinfo->cinfo, COL_INFO, "IR-DYN packet");
        offset = dissect_rohc_ir_dyn_packet(tvb, rohc_tree, pinfo, offset, cid, is_add_cid, p_rohc_info);
        if (offset == -1) {
            /* Could not parse header */
            return tvb_captured_length(tvb);
        }

        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(payload_tvb, pinfo, rohc_tree);
        return tvb_captured_length(tvb);
    }

    /* First pass - look up or create CID context */
    if (!PINFO_FD_VISITED(pinfo)) {
        int key = cid;
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, GUINT_TO_POINTER(key));
        if (!rohc_cid_context) {
            /* Not found, so initialize new context based upon p_rohc_info */
            rohc_cid_context = wmem_new(wmem_file_scope(), rohc_cid_context_t);
            /*rohc_cid_context->d_mode;*/
            rohc_cid_context->rnd = p_rohc_info->rnd;
            rohc_cid_context->udp_checksum_present = p_rohc_info->udp_checksum_present;
            rohc_cid_context->profile = p_rohc_info->profile;
            rohc_cid_context->mode = p_rohc_info->mode;
            rohc_cid_context->rohc_ip_version = p_rohc_info->rohc_ip_version;
            rohc_cid_context->large_cid_present = p_rohc_info->large_cid_present;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = -1;
            /*ws_warning("Store dummy data %u",cid);*/
        }
        /* Store in pinfo */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0, rohc_cid_context);
    } else {
        /* Later passes - get from pinfo */
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_rohc, 0);
    }
    DISSECTOR_ASSERT(rohc_cid_context);

    /* Call IP for uncompressed profile */
    if (rohc_cid_context->profile==ROHC_PROFILE_UNCOMPRESSED) {
        if (rohc_cid_context->large_cid_present) {
            /* How long does packet say it is? */
            get_self_describing_var_len_val(tvb, rohc_tree, offset+1, hf_rohc_large_cid, &val_len);
            /* How many bytes do we actually have? */
            int len = tvb_captured_length_remaining(tvb, offset);
            if (len >= val_len) {
                len -= val_len;
                uint8_t *payload_data = (uint8_t *)wmem_alloc(pinfo->pool, len);
                tvb_memcpy(tvb, payload_data, offset, 1);
                tvb_memcpy(tvb, &payload_data[1], offset+1+val_len, len-1);
                next_tvb = tvb_new_child_real_data(tvb, payload_data, len, len);
                add_new_data_source(pinfo, next_tvb, "Payload");
            }
        }
        else {
            next_tvb = tvb_new_subset_remaining(tvb, offset);
        }

        /* Call appropriate IP dissector.
           TODO: could just call "ip" dissector instead? */
        if ((oct&0xf0)==0x40) {
            call_dissector(ip_handle, next_tvb, pinfo, tree);
        }
        else if ((oct&0xf0)==0x60) {
            call_dissector(ipv6_handle, next_tvb, pinfo, tree);
        }
        else {
            call_data_dissector(next_tvb, pinfo, tree);
        }

        col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "ROHC/");
        return tvb_captured_length(tvb);
    }
    else if (((oct&0x80)==0x00) &&
             ((rohc_cid_context->profile==ROHC_PROFILE_RTP) || (rohc_cid_context->profile==ROHC_PROFILE_UDP))) {
        /* 5.7.1. Packet type 0: UO-0, R-0, R-0-CRC */
        offset = dissect_rohc_pkt_type_0(tvb, pinfo, rohc_tree, offset, oct, rohc_cid_context);
    } else if ((oct&0xc0)==0x80) {
        if (rohc_cid_context->mode == RELIABLE_BIDIRECTIONAL) {
            /* 5.7.2. Packet type 1 (R-mode): R-1, R-1-TS, R-1-ID */
            offset = dissect_rohc_pkt_type_1_r_mode(tvb, pinfo, rohc_tree, offset, rohc_cid_context);
        }
        else {
            /* 5.7.3. Packet type 1 (U/O-mode): UO-1, UO-1-ID, UO-1-TS */
            offset = dissect_rohc_pkt_type_1_u_o_mode(tvb, pinfo, rohc_tree, offset, rohc_cid_context);
        }
    } else if ((oct&0xe0)==0xc0) {
        /* 5.7.4. Packet type 2: UOR-2 */
        offset = dissect_rohc_pkt_type_2(tvb, pinfo, rohc_tree, offset, rohc_cid_context);
    }

    /* IP-ID */
    if (rohc_cid_context->rnd) {
        proto_tree_add_item(rohc_tree, hf_rohc_ip_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* UDP Checksum */
    if (rohc_cid_context->udp_checksum_present) {
        proto_tree_add_checksum(rohc_tree, tvb, offset, hf_rohc_udp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        offset += 2;
    }

    /* Any remainder is undissected data / payload */
    payload_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(payload_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

/* Set up rohc_cid_hash which holds data for a CID
 * needed to dissect subsequent packages.
 * XXXX ToDo:
 * A better Key than just the CID may have to be devised.
 *
 */


static void
rohc_init_protocol(void)
{
    rohc_cid_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void
rohc_cleanup_protocol(void)
{
    g_hash_table_destroy(rohc_cid_hash);
}

void
proto_register_rohc(void)
{

    static hf_register_info hf[] =
        {
            { &hf_rohc_padding,
              { "Padding","rohc.padding",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_add_cid,
              { "Add-CID","rohc.add_cid",
                FT_UINT8, BASE_HEX, NULL, 0xf0,
                NULL , HFILL
              }
            },
            { &hf_rohc_feedback,
              { "Feedback","rohc.feedback",
                FT_UINT8, BASE_HEX, NULL, 0xf8,
                NULL , HFILL
              }
            },
            { &hf_rohc_code,
              { "Code","rohc.code",
                FT_UINT8, BASE_DEC, NULL, 0x07,
                NULL , HFILL
              }
            },
            { &hf_rohc_size,
              { "Size","rohc.size",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL , HFILL
              }
            },
            { &hf_rohc_ir_packet,
              { "IR packet","rohc.ir_packet",
                FT_UINT8, BASE_HEX, NULL, 0xfe,
                NULL , HFILL
              }
            },
            { &hf_rohc_ir_dyn_packet,
              { "IR-DYN packet","rohc.ir_dyn_packet",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_small_cid,
              { "Small CID","rohc.small_cid",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                NULL , HFILL
              }
            },
            { &hf_rohc_large_cid,
              { "Large CID","rohc.large_cid",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_acktype,
              { "Acktype","rohc.acktype",
                FT_UINT8, BASE_DEC, VALS(rohc_acktype_vals), 0xc0,
                NULL , HFILL
              }
            },
            { &hf_rohc_mode,
              { "Mode","rohc.mode",
                FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x30,
                NULL , HFILL
              }
            },
            { &hf_rohc_sn,
              { "SN LSB","rohc.sn",
                FT_UINT16, BASE_HEX_DEC, NULL, 0x0fff,
                NULL , HFILL
              }
            },
            { &hf_rohc_profile_spec_octet,
              { "Profile-specific octet","rohc.profile_spec_octet",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_fb1_sn,
              { "SN LSB","rohc.sn",
                FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_opt_type,
              { "Option type","rohc.opt_type",
                FT_UINT8, BASE_DEC, VALS(rohc_opt_type_vals), 0xf0,
                NULL , HFILL
              }
            },
            { &hf_rohc_opt_len,
              { "Option length","rohc.opt_length",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                NULL , HFILL
              }
            },
            { &hf_rohc_crc,
              { "CRC","rohc.crc",
                FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_opt_sn,
              { "SN additional bits","rohc.opt.sn_add_bits",
                FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
                "Feedback Option SN", HFILL
              }
            },
            { &hf_rohc_ext,
              { "Extension","rohc.ext",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext_sn,
              { "SN LSB","rohc.sn",
                FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_opt_clock,
              { "Clock", "rohc.opt.clock",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Feedback Option Clock", HFILL
              }
            },
            { &hf_rohc_opt_jitter,
              { "Max Jitter", "rohc.opt.jitter",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Feedback Option Jitter", HFILL
              }
            },
            { &hf_rohc_opt_loss,
              { "Longest loss event (packets)", "rohc.opt.loss",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Feedback Option Loss", HFILL
              }
            },
            { &hf_rohc_profile,
              { "Profile","rohc.profile",
                FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_d_bit,
              { "D - Dynamic chain","rohc.d",
                FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
                NULL , HFILL
              }
            },
            { &hf_rohc_ip_version,
              { "Version","rohc.ip.version",
                FT_UINT8, BASE_DEC, VALS(rohc_ip_version_vals), 0xf0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ip_version_ip_profile,
              { "Version","rohc.ip.version",
                FT_UINT8, BASE_DEC, VALS(rohc_ip_version_ip_profile_vals), 0xf0,
                NULL , HFILL
              }
            },
            { &hf_rohc_static_ipv4,
              { "Static IPv4 chain",
                "rohc.static.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ip_protocol,
              { "Protocol","rohc.ip.protocol",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ipv4_src,
              { "Source address","rohc.ipv4_src",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ipv4_dst,
              { "Destination address","rohc.ipv4_dst",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ipv6_flow,
              { "Flow Label","rohc.ipv6.flow",
                FT_UINT24, BASE_DEC, NULL, 0x0fffff,
                NULL , HFILL
              }
            },
            { &hf_rohc_ipv6_nxt_hdr,
              { "Next Header","rohc.ipv6.nxt_hdr",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ipv6_src,
              { "Source Address","rohc.ipv6.src",
                FT_IPv6, BASE_NONE, NULL, 0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ipv6_dst,
              { "Destination Address","rohc.ipv6.dst",
                FT_IPv6, BASE_NONE, NULL, 0,
                NULL , HFILL
              }
            },
            { &hf_rohc_static_udp,
              { "Static UDP chain", "rohc.static.udp",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_udp_src_port,
              { "Source Port","rohc.udp_src_port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_udp_dst_port,
              { "Destination Port","rohc.udp_dst_port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_static_rtp,
              { "Static RTP chain",
                "rohc.static.rtp", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_rtp_ssrc,
              { "SSRC","rohc.rtp.ssrc",
                FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_dynamic_ipv4,
              { "Dynamic IPv4 chain",
                "rohc.dynamic.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_dynamic_udp,
              { "Dynamic UDP chain",
                "rohc.dynamic.udp", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_rtp_tos,
              { "Type of Service","rohc.rtp.tos",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_ttl,
              { "Time to Live","rohc.rtp.ttl",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_id,
              { "Identification","rohc.rtp.id",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_df,
              { "Don't Fragment(DF)","rohc.rtp.df",
                FT_BOOLEAN, 8, NULL, 0x80,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_rnd,
              { "RND(IP-ID behaves randomly)","rohc.rtp.rnd",
                FT_BOOLEAN, 8, NULL, 0x40,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_nbo,
              { "Network Byte Order (NBO)","rohc.rtp.nbo",
                FT_BOOLEAN, 8, NULL, 0x20,
                "Whether the IP-ID is in Network Byte Order" , HFILL
              }
            },
            { &hf_rohc_dynamic_udp_checksum,
              { "UDP Checksum", "rohc.dynamic.udp.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_dynamic_rtp,
              { "Dynamic RTP chain",
                "rohc.dynamic.rtp", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_rtp_v,
              { "Version","rohc.rtp.v",
                FT_UINT8, BASE_DEC, NULL, 0xc0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_p,
              { "Padding(P)","rohc.rtp.p",
                FT_BOOLEAN, 8, NULL, 0x20,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_rx,
              { "RX","rohc.rtp.rx",
                FT_BOOLEAN, 8, NULL, 0x10,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_cc,
              { "CC","rohc.rtp.cc",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                "CSRC counter from original RTP header" , HFILL
              }
            },
            { &hf_rohc_rtp_m,
              { "Marker Bit (M)","rohc.rtp.m",
                FT_BOOLEAN, BASE_NONE,  TFS(&tfs_set_notset), 0x00,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_pt,
              { "Payload Type(PT)","rohc.rtp.pt",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rtp_payload_type_vals_ext, 0x7f,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_sn,
              { "Sequence Number(SN)","rohc.rtp.sn",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_timestamp,
              { "RTP Timestamp","rohc.rtp.timestamp",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_x,
              { "X","rohc.rtp.x",
                FT_BOOLEAN, 8,  TFS(&tfs_set_notset), 0x10,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_mode,
              { "Mode","rohc.rtp.mode",
                FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0c,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_tis,
              { "TIS","rohc.rtp.tis",
                FT_BOOLEAN, 8,  NULL, 0x02,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_tss,
              { "TSS","rohc.rtp.tss",
                FT_BOOLEAN, 8,  NULL, 0x01,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_ts_stride,
              { "TS_Stride","rohc.rtp.ts_stride",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_time_stride,
              { "Time_Stride","rohc.rtp.time_stride",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_var_len,
              { "Variable length","rohc.var_len",
                FT_UINT8, BASE_DEC, VALS(rohc_var_len_vals), 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ipv6_tc,
              { "Traffic class","rohc.tc",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ipv6_hop_limit,
              { "Hop limit","rohc.hop_limit",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ir_previous_frame,
              { "Previous IR frame","rohc.ir.prev.frame_num",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL , HFILL,
              }
            },
            { &hf_rohc_ir_profile,
              { "Profile","rohc.ir_profile",
                FT_UINT16, BASE_DEC, VALS(rohc_profile_vals), 0x0,
                NULL , HFILL
              }
            },

            { &hf_rohc_ir_ip_version,
              { "IP Version","rohc.ir_ip_version",
                FT_UINT8, BASE_DEC, VALS(rohc_ip_version_vals), 0x0,
                NULL , HFILL
              }
            },

            { &hf_rohc_ir_mode,
              { "Mode","rohc.ir_mode",
                FT_UINT32, BASE_DEC, VALS(rohc_mode_vals), 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ir_pkt_frame,
              { "Setup by IR frame","rohc.ir.frame_num",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_comp_sn,
              { "Compressed Sequence Number","rohc.comp.sn",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_r_0_crc,
              { "CRC","rohc.r_0_crc",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_x,
              { "Extension","rohc.x",
                FT_BOOLEAN, BASE_NONE, TFS(&tfs_present_not_present), 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_ts,
              { "Compressed RTP timestamp","rohc.tp",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_comp_ip_id,
              { "Compressed IP-ID","rohc.comp_ip_id",
                FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_comp_ip_id2,
              { "Compressed IP-ID2","rohc.comp_ip_id2",
                FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_t,
              { "T bit","rohc.t",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_compressed_list,
              { "Compressed List", "rohc.compressed-list",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_compressed_list_et,
              { "Encoding Type", "rohc.compressed-list.et",
                FT_UINT8, BASE_DEC, VALS(compressed_list_encoding_type_vals), 0xc0,
                NULL , HFILL
              }
            },
            { &hf_rohc_compressed_list_gp,
              { "Gen-id Present", "rohc.compressed-list.gp",
                FT_UINT8, BASE_DEC, NULL, 0x20,
                NULL , HFILL
              }
            },
            { &hf_rohc_compressed_list_ps,
              { "PS", "rohc.compressed-list.ps",
                FT_UINT8, BASE_DEC, VALS(compressed_list_ps_vals), 0x10,
                "Size of xi fields", HFILL
              }
            },
            { &hf_rohc_compressed_list_res,
              { "Reserved", "rohc.compressed-list.res",
                FT_UINT8, BASE_DEC, NULL, 0x10,
                NULL, HFILL
              }
            },
            { &hf_rohc_compressed_list_count,
              { "Count", "rohc.compressed-list.count",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                NULL, HFILL
              }
            },
            { &hf_rohc_compressed_list_cc,
              { "CSRC Counter", "rohc.compressed-list.cc",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                "CSRC Counter from original RTP header", HFILL
              }
            },
            { &hf_rohc_compressed_list_xi_1,
              { "XI 1", "rohc.compressed-list.xi_1",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                NULL, HFILL
              }
            },
            { &hf_rohc_compressed_list_gen_id,
              { "gen_id", "rohc.compressed-list.gen-id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_compressed_list_ref_id,
              { "ref_id", "rohc.compressed-list.ref-id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_compressed_list_mask_size,
              { "Mask size","rohc.compressed-list.mask_size",
                FT_BOOLEAN, 8, TFS(&rohc_cmp_lst_mask_size_vals), 0x80,
                NULL , HFILL
              }
            },
            { &hf_rohc_compressed_list_ins_bit_mask,
              { "Insertion bit mask","rohc.compressed-list.ins_bit_mask",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_compressed_list_rem_bit_mask,
              { "Removal bit mask","rohc.compressed-list.rem_bit_mask",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_spare_bits,
              { "Spare bits(0)", "rohc.spare_bits",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ip_id,
              { "IP-ID", "rohc.ip-id",
                FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_udp_checksum,
              { "UDP checksum", "rohc.udp_checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_flags,
              { "Extension 3 flags","rohc.ext3_flags",
                FT_UINT8, BASE_HEX, NULL, ROHC_RTP_EXT3_FLAGS_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_s,
              { "S","rohc.ext3.s",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_S_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_r_ts,
              { "R-TS","rohc.ext3.r-ts",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_R_TS_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_tsc,
              { "Tsc","rohc.ext3.tsc",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_TSC_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_udp_mode,
              { "Mode","rohc.ext3.mode",
                FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), ROHC_UDP_EXT3_UDP_MODE_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_i,
              { "I","rohc.ext3.i",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_I_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_ip,
              { "ip","rohc.ext3.ip",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_IP_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_ip2,
              { "ip2","rohc.ext3.ip2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_UDP_EXT3_IP2_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_rtp,
              { "rtp","rohc.ext3.rtp",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_RTP_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_ip_flags,
              { "Inner IP header flags","rohc.ext3.inner_ip_flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_tos,
              { "TOS","rohc.ext3.tos",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_TOS_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_ttl,
              { "TTL","rohc.ext3.ttl",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_TTL_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_df,
              { "DF","rohc.ext3.df",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_DF_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_pr,
              { "PR","rohc.ext3.pr",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_PR_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_ipx,
              { "IPX","rohc.ext3.ipx",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_IPX_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_nbo,
              { "NBO","rohc.ext3.nbo",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_NBO_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_rnd,
              { "RND","rohc.ext3.rnd",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_RND_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_inner_ip2,
              { "ip2","rohc.ext3.ip2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_INNER_IP2_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_ip_flags,
              { "Outer IP header flags","rohc.ext3.outer_ip_flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_tos,
              { "TOS2","rohc.ext3.tos2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_TOS_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_ttl,
              { "TTL2","rohc.ext3.ttl2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_TTL_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_df,
              { "DF2","rohc.ext3.df2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_DF_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_pr,
              { "PR2","rohc.ext3.pr2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_PR_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_ipx,
              { "IPX2","rohc.ext3.ipx2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_IPX_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_nbo,
              { "NBO2","rohc.ext3.nbo2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_NBO_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_rnd,
              { "RND2","rohc.ext3.rnd2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_RND_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_outer_i2,
              { "I2","rohc.ext3.i2",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_OUTER_I2_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_rtp_flags,
              { "RTP header flags","rohc.ext3.rtp_flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_rtp_mode,
              { "Mode","rohc.ext3.mode",
                FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), ROHC_RTP_EXT3_RTP_MODE_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_r_pt,
              { "R-PT","rohc.ext3.r_pt",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_R_PT_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_m,
              { "M","rohc.ext3.m",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_M_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_r_x,
              { "R-X","rohc.ext3.r_x",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_R_X_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_csrc,
              { "CSRC","rohc.ext3.csrc",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_CSRC_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_tss,
              { "TSS","rohc.ext3.tss",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_TSS_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_tis,
              { "TIS","rohc.ext3.tis",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_TIS_MASK,
                NULL, HFILL
              }
            },
            { &hf_rohc_ext3_r_p,
              { "R-P","rohc.ext3.r_p",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), ROHC_RTP_EXT3_R_P_MASK,
                NULL, HFILL
              }
            },
          /* Generated from convert_proto_tree_add_text.pl */
          { &hf_rohc_unknown_option_data, { "Unknown Option data", "rohc.unknown_option_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
          { &hf_rohc_configured_by_ir_packet, { "Configured by IR packet", "rohc.configured_by_ir_packet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
          { &hf_rohc_no_configuration_info, { "No configuration info", "rohc.no_configuration_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
          { &hf_rohc_error_packet, { "Error packet", "rohc.error_packet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_rohc,
        &ett_rohc_conf,
        &ett_rohc_fb,
        &ett_rohc_feedback,
        &ett_rohc_ir,
        &ett_rohc_ir_dyn,
        &ett_rohc_static_ipv4,
        &ett_rohc_static_udp,
        &ett_rohc_static_rtp,
        &ett_rohc_rtp_static,
        &ett_rohc_rtp_dynamic,
        &ett_rohc_dynamic_ipv4,
        &ett_rohc_dynamic_udp,
        &ett_rohc_dynamic_rtp,
        &ett_rohc_compressed_list,
        &ett_rohc_packet,
        &ett_rohc_ext,
        &ett_rohc_ext3_flags,
        &ett_rohc_ext3_inner_ip_flags,
        &ett_rohc_ext3_outer_ip_flags,
        &ett_rohc_ext3_rtp_flags
    };

    static ei_register_info ei[] = {
        { &ei_rohc_profile_spec_octet, { "rohc.profile_spec_octet.bad", PI_PROTOCOL, PI_WARN, "Invalid profile-specific octet value", EXPFILL }},
        { &ei_rohc_feedback_type_2_is_not_applicable_for_uncompressed_profile, { "rohc.feedback.type_2_is_not_applicable_for_uncompressed_profile", PI_PROTOCOL, PI_WARN, "Feedback type 2 is not applicable for uncompressed profile", EXPFILL }},
        { &ei_rohc_rohc_opt_clock, { "rohc.opt.clock.udp", PI_MALFORMED, PI_ERROR, "CLOCK option should not be used for UDP", EXPFILL }},
        { &ei_rohc_opt_jitter, { "rohc.opt.jitter.udp", PI_MALFORMED, PI_ERROR, "JITTER option should not be used for UDP", EXPFILL }},
        { &ei_rohc_not_dissected_yet, { "rohc.not_dissected_yet", PI_UNDECODED, PI_WARN, "Not dissected yet", EXPFILL }},
        { &ei_rohc_profile_specific, { "rohc.profile_specific", PI_UNDECODED, PI_WARN, "profile-specific information [Not dissected yet]", EXPFILL }},
        { &ei_rohc_profile_not_supported, { "rohc.profile_not_supported", PI_PROTOCOL, PI_WARN, "Profile not supported", EXPFILL }},
        { &ei_rohc_ip_version, { "rohc.ip.version.unknown", PI_PROTOCOL, PI_WARN, "Error unknown version, only 4 or 6 allowed", EXPFILL }},
        { &ei_rohc_desegmentation_not_implemented, { "rohc.desegmentation_not_implemented", PI_UNDECODED, PI_WARN, "Segment [Desegmentation not implemented yet]", EXPFILL }},
    };

    expert_module_t* expert_rohc;

    /* Register the protocol name and description */
    proto_rohc = proto_register_protocol("RObust Header Compression (ROHC)", "ROHC", "rohc");

    rohc_handle = register_dissector("rohc", dissect_rohc, proto_rohc);

    register_init_routine(&rohc_init_protocol);
    register_cleanup_routine(&rohc_cleanup_protocol);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_rohc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rohc = expert_register_protocol(proto_rohc);
    expert_register_field_array(expert_rohc, ei, array_length(ei));
}

void
proto_reg_handoff_rohc(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_ROHC, rohc_handle);

    ip_handle   = find_dissector_add_dependency("ip", proto_rohc);
    ipv6_handle = find_dissector_add_dependency("ipv6", proto_rohc);
}

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
