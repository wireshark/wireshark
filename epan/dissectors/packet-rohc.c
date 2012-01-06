/* packet-rohc.c
 * Routines for RObust Header Compression (ROHC) dissection.
 *
 * Copyright 2011, Anders Broman <anders.broman[at]ericsson.com>
 *                 Per Liedberg  <per.liedberg [at]ericsson.com>
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
 *
 * Ref:
 * http://www.ietf.org/rfc/rfc3095.txt         RObust Header Compression (ROHC): Framework and four profiles: RTP, UDP, ESP, and uncompressed
 * http://datatracker.ietf.org/doc/rfc4815/    RObust Header Compression (ROHC): Corrections and Clarifications to RFC 3095
 * http://datatracker.ietf.org/doc/rfc5225/    RObust Header Compression Version 2 (ROHCv2): Profiles for RTP, UDP, IP, ESP and UDP-Lite
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/rtp_pt.h>
#include <epan/expert.h>
#include <epan/emem.h>

#include "packet-rohc.h"


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

static GHashTable *rohc_cid_hash = NULL; 

/* Initialize the protocol and registered fields */
static int proto_rohc           = -1;


static int hf_rohc_padding = -1;
static int hf_rohc_add_cid = -1;
static int hf_rohc_feedback = -1;
static int hf_rohc_code = -1;
static int hf_rohc_size = -1;
static int hf_rohc_ir_packet = -1;
static int hf_rohc_ir_dyn_packet = -1;
static int hf_rohc_small_cid = -1;
static int hf_rohc_large_cid = -1;
static int hf_rohc_acktype = -1;
static int hf_rohc_mode = -1;
static int hf_rohc_sn = -1;
static int hf_rohc_fb1_sn = -1;
static int hf_rohc_rtp_opt_type = -1;
static int hf_rohc_rtp_opt_len = -1;
static int hf_rohc_rtp_crc = -1;
static int hf_rohc_rtp_opt_sn = -1;
static int hf_rohc_feedback_option_clock = -1;
static int hf_rohc_profile = -1;
static int hf_rohc_d_bit = -1;
static int hf_rohc_ip_version = -1;
static int hf_rohc_ip_protocol = -1;
static int hf_rohc_static_ipv4 = -1;
static int hf_rohc_ipv4_src = -1;
static int hf_rohc_ipv4_dst = -1;
static int hf_rohc_ipv6_flow = -1;
static int hf_rohc_ipv6_nxt_hdr = -1;
static int hf_rohc_ipv6_src = -1;
static int hf_rohc_ipv6_dst = -1;
static int hf_rohc_static_udp = -1;
static int hf_rohc_rtp_udp_src_port = -1;
static int hf_rohc_rtp_udp_dst_port = -1;
static int hf_rohc_static_rtp = -1;
static int hf_rohc_rtp_ssrc = -1;
static int hf_rohc_dynamic_ipv4 = -1;
static int hf_rohc_dynamic_udp = -1;
static int hf_rohc_rtp_tos = -1;
static int hf_rohc_rtp_ttl = -1;
static int hf_rohc_rtp_id = -1;
static int hf_rohc_rtp_df = -1;
static int hf_rohc_rtp_rnd = -1;
static int hf_rohc_rtp_nbo = -1;
static int hf_rohc_rtp_checksum = -1;
static int hf_rohc_dynamic_udp_checksum = -1;
static int hf_rohc_dynamic_rtp =-1;
static int hf_rohc_rtp_v = -1;
static int hf_rohc_rtp_p = -1;
static int hf_rohc_rtp_rx = -1;
static int hf_rohc_rtp_cc = -1;
static int hf_rohc_rtp_m = -1;
static int hf_rohc_rtp_pt = -1;
static int hf_rohc_rtp_sn = -1;
static int hf_rohc_rtp_timestamp = -1;
static int hf_rohc_rtp_x = -1;
static int hf_rohc_rtp_mode = -1;
static int hf_rohc_rtp_tis = -1;
static int hf_rohc_rtp_tss = -1;
static int hf_rohc_rtp_ts_stride = -1;
static int hf_rohc_rtp_time_stride = -1;
static int hf_rohc_var_len = -1;
static int hf_rohc_ipv6_tc = -1;
static int hf_rohc_ipv6_hop_limit = -1;
static int hf_rohc_ir_pkt_frame = -1;
static int hf_rohc_ir_previous_frame = -1;
static int hf_rohc_comp_sn = -1;

static int hf_rohc_compressed_list = -1;
static int hf_rohc_compressed_list_et = -1;
static int hf_rohc_compressed_list_gp = -1;
static int hf_rohc_compressed_list_ps = -1;
static int hf_rohc_compressed_list_cc = -1;
static int hf_rohc_compressed_list_gen_id = -1;


static int ett_rohc = -1;
static int ett_rohc_conf = -1;
static int ett_rohc_fb = -1;
static int ett_rohc_feedback = -1;
static int ett_rohc_ir = -1;
static int ett_rohc_ir_dyn = -1;
static int ett_rohc_static_ipv4 = -1;
static int ett_rohc_static_udp = -1;
static int ett_rohc_static_rtp = -1;
static int ett_rohc_rtp_static = -1;
static int ett_rohc_rtp_dynamic = -1;
static int ett_rohc_dynamic_ipv4 = -1;
static int ett_rohc_dynamic_udp = -1;
static int ett_rohc_dynamic_rtp = -1;
static int ett_rohc_compressed_list = -1;

/* IPv4 hard wired for now */
static guint8 g_profile = 1;
static guint8 g_version = 4;

typedef struct _rohc_cid_context_t
{
    guint16            rohc_ip_version;
    gboolean           large_cid_present;
    enum rohc_mode     mode;
    enum rohc_d_mode   d_mode;
    gboolean           rnd;
    gboolean           udp_checkum_present;
    guint16            profile;
    gint               prev_ir_frame_number;   /* The frame number of the previous IR packet seen */
    gint               ir_frame_number;        /* The frame number of the latest IR packet seen */

} rohc_cid_context_t;

/* ROHC Profiles */
#define ROHC_PROFILE_UNCOMPRESSED   0
#define ROHC_PROFILE_RTP            1
#define ROHC_PROFILE_UDP            2
#define ROHC_PROFILE_UNKNOWN        0xFFFF

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

static const value_string rohc_acktype_vals[] =
{
    { 0,    "ACK" },
    { 1,    "NACK" },
    { 2,    "STATIC-NACK" },
    { 3,    "reserved (MUST NOT be used.  Otherwise unparsable)" },
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

static const value_string rohc_rtp_opt_type_vals[] =
{
    { 1,    "CRC" },
    { 2,    "Reject" },
    { 3,    "SN-NOT-VALID" },
    { 4,    "SN" },
    { 5,    "Clock" },
    { 6,    "Jitter" },
    { 7,    "LOSS" },
    { 0, NULL },
};



static const value_string rohc_ip_version_vals[] =
{
    { 4,    "IPv4" },
    { 6,    "IPv6" },
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


/* 4.5.6.  Self-describing variable-length values */
static guint32
get_self_describing_var_len_val(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, guint8 *val_len){
    guint8 oct;
    guint32 val = 0;
    int num_bits = 0, bit_offset = offset <<3;

    oct = tvb_get_guint8(tvb, offset);
    if((oct&0x80)==0){
        /* One octet */
        *val_len = 1;
        val = (oct&0x7f);
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        num_bits = 7;
        bit_offset++;
    }else if((oct&0xc0)==0x80){
        /* Two octets */
        *val_len = 2;
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset+=2;
        num_bits = 14;
        val =  tvb_get_ntohs(tvb, offset)&0x3fff;
    }else if((oct&0xe0)==0xc0){
        /* Three octets */
        *val_len = 3;
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset+=3;
        num_bits = 21;
        val = tvb_get_ntoh24(tvb, offset)&0x1fffff;
    }else if ((oct&0xe0)==0xe0){
        /* Four octets */
        *val_len = 4;
        proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset+=3;
        num_bits = 29;
        val = tvb_get_ntohl(tvb, offset)&0x1fffffff;
    }
    proto_tree_add_bits_item(tree, hf_index, tvb, bit_offset, num_bits, ENC_BIG_ENDIAN);

    return val;

}

static void
dissect_rohc_feedback_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, gint16 feedback_data_len, rohc_info *p_rohc_info, guint16 cid){

    proto_item *ti;
    proto_tree *rohc_feedback_tree;
    guint8 opt, opt_len, oct;
    rohc_cid_context_t *rohc_cid_context=NULL;


    if (!pinfo->fd->flags.visited){
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, &cid);
        if(rohc_cid_context){
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
        }
    }else{
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(pinfo->fd, proto_rohc);
    }

    if(!rohc_cid_context){
        /* No cotext info, not much we can do */
        if(feedback_data_len==1){
            /* FEEDBACK-1 */
            proto_item_append_text(p_rohc_info->last_created_item, " (type 1)");
            proto_tree_add_text(tree, tvb, offset, feedback_data_len, "profile-specific information[Profile not known]");
        }else{
            proto_item_append_text(p_rohc_info->last_created_item, " (type 2)");
        }
        proto_tree_add_text(tree, tvb, offset, feedback_data_len, "profile-specific information[Profile not known]");
        return;
    }

    if(feedback_data_len==1){
        /* FEEDBACK-1 */
        proto_item_append_text(p_rohc_info->last_created_item, " (type 1)");
        switch(rohc_cid_context->profile){
            case ROHC_PROFILE_RTP: /* 1 */
                /*
                 *     0   1   2   3   4   5   6   7
                 *   +---+---+---+---+---+---+---+---+
                 *   |              SN               |
                 *   +---+---+---+---+---+---+---+---+
                 *
                 */

                oct = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_rohc_fb1_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", oct);
                break;
            default:
                proto_tree_add_text(tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
                break;
        }
        return;
    }
    /*  FEEDBACK-2 */
    proto_item_append_text(p_rohc_info->last_created_item, " (type 2)");
    switch(rohc_cid_context->profile){
        case ROHC_PROFILE_RTP: /* 1 */
            ti = proto_tree_add_text(tree, tvb, offset, feedback_data_len, "RTP profile-specific information");
            rohc_feedback_tree = proto_item_add_subtree(ti, ett_rohc_feedback);
            /* Set mode at first pass? Do we need a new context for the following frames?
             *
             */
            rohc_cid_context->mode = (tvb_get_guint8(tvb,offset) & 0x30)>>4;
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_acktype, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            feedback_data_len-=2;

            while(feedback_data_len>0){
                opt = opt_len = tvb_get_guint8(tvb,offset);
                opt = opt >> 4;
                opt_len = opt_len &0x0f;
                proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_opt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                feedback_data_len--;
                switch(opt){
                    case 1:
                        /* CRC */
                        proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
                        oct = tvb_get_guint8(tvb, offset);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "CRC=%u ", oct);
                        break;
                    case 2:
                        /* REJECT: TODO */
                        proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
                        break;
                    case 3:
                        /* SN-Not-Valid: TODO */
                        proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
                        break;
                    case 4:
                        /* SN */
                        proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_opt_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
                        oct = tvb_get_guint8(tvb, offset);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " SN=%u ", oct);
                        break;
                    case 5:
                        /* Clock */
                        proto_tree_add_item(tree, hf_rohc_feedback_option_clock, tvb, offset, 1, ENC_BIG_ENDIAN);
                        oct = tvb_get_guint8(tvb, offset);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Clock=%u ", oct);
                        break;
                    case 6:
                        /* Jitter: TODO */
                        proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
                        break;
                    case 7:
                        /* Loss: TODO */
                        proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
                        break;
                    default:
                        proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Unknown Option data");
                        break;
                }
                feedback_data_len = feedback_data_len - opt_len;
                offset = offset + opt_len;

            }
            break;
        default:
            ti = proto_tree_add_text(tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
            rohc_feedback_tree = proto_item_add_subtree(ti, ett_rohc_feedback);
            proto_tree_add_item(rohc_feedback_tree, hf_rohc_acktype, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
    }
}


static int
dissect_compressed_list(int expected_encoding_type, packet_info *pinfo,
                        proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *list_ti, *et_ti;
    proto_item *list_tree;
    guint8 first_byte = tvb_get_guint8(tvb, offset);
    guint8 ET, GP /* , PS , CC */;
    int start_offset = offset;

    /* Compressed list root */
    list_ti = proto_tree_add_item(tree, hf_rohc_compressed_list, tvb, offset, -1, ENC_NA);
    list_tree = proto_item_add_subtree(list_ti, ett_rohc_compressed_list);

    /* Fixed fields from first byte */
    ET = (first_byte & 0xc0) >> 6;
    et_ti = proto_tree_add_item(list_tree, hf_rohc_compressed_list_et, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(list_ti, " (type=%d - %s)",
                           ET, val_to_str_const(ET, compressed_list_encoding_type_vals, "Unknown"));
    if (ET != expected_encoding_type) {
        expert_add_info_format(pinfo, et_ti, PI_MALFORMED, PI_ERROR,
                               "Wrong compressed list encoding type (expected %d, got %d)",
                               expected_encoding_type, ET);
        return offset+1;
    }

    GP = (first_byte & 0x20) >> 5;
    proto_tree_add_item(list_tree, hf_rohc_compressed_list_gp, tvb, offset, 1, ENC_BIG_ENDIAN);

    switch (ET) {
        case 0:
            /* 5.8.6.1 */
            /* PS = (first_byte & 0x20) >> 4; */
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_ps, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* CC = first_byte & 0x0f; */
            proto_tree_add_item(list_tree, hf_rohc_compressed_list_cc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            if (GP) {
                proto_tree_add_item(list_tree, hf_rohc_compressed_list_cc, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }

            /* TODO: calculate how many bytes to skip for items */
            break;

        case 1:
            /* 5.8.6.2 */
            /* TODO: */
            offset++;
            break;
        case 2:
            /* 5.8.6.3 */
            /* TODO: */
            offset++;
            break;
        case 3:
            /* 5.8.6.4 */
            /* TODO: */
            offset++;
            break;
    }

    proto_item_set_len(list_ti, offset-start_offset);

    return offset;
}

static int
dissect_rohc_ir_rtp_profile_dynamic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                    int offset, guint8 profile, rohc_cid_context_t *rohc_cid_context){

    proto_item *item, *root_ti;
    proto_tree *sub_tree=NULL, *dynamic_ipv4_tree, *dynamic_udp_tree, *dynamic_rtp_tree;
    guint8 oct, rx, cc, val_len = 0;
    int i, start_offset, tree_start_offset;
    guint8 tos, ttl, rnd, nbo;
    guint16 id;
    /*guint8     contributing_csrcs;*/
    guint16    sequence_number;
    guint32    timestamp;
#if 0
    guint8     tis=0, tss=0;
    guint64    ts_stride=0;
#endif
    start_offset = offset;
    switch(profile){

        case ROHC_PROFILE_UNCOMPRESSED:
            item = proto_tree_add_text(tree, tvb, offset, 0, "Profile 0x0000 Uncompressed");
            break;

        case ROHC_PROFILE_RTP:
            item = proto_tree_add_text(tree, tvb, offset, 0, "Profile 0x0001 RTP Dynamic Chain");
            break;

        case ROHC_PROFILE_UDP:
            item = proto_tree_add_text(tree, tvb, offset, 0, "Profile 0x0002 UDP Dynamic Chain");
            break;

        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Profile not supported");
            return -1;
    }

    /* IP dynamic*/
    /* for all profiles except uncompressed */
    if ( (profile != ROHC_PROFILE_UNCOMPRESSED) ) {
        sub_tree = proto_item_add_subtree(item, ett_rohc_rtp_dynamic);
        switch(rohc_cid_context->rohc_ip_version){
            case 4:
                /* 5.7.7.4.  Initialization of IPv4 Header [IPv4, section 3.1].
                 * Dynamic part:
                 */
                /* Create dynamic IPv4 subtree */
                tree_start_offset = offset;
                root_ti = proto_tree_add_item(sub_tree, hf_rohc_dynamic_ipv4, tvb, offset, -1, ENC_NA);
                dynamic_ipv4_tree = proto_item_add_subtree(root_ti, ett_rohc_dynamic_ipv4);

                /* Type of Service */
                tos = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_tos, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Time to Live */
                ttl = tvb_get_guint8(tvb, offset);
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
                rnd = (tvb_get_guint8(tvb, offset) & 0x40) >> 6;
                nbo = (tvb_get_guint8(tvb, offset) & 0x20) >> 5;
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_df, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_rnd, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(dynamic_ipv4_tree, hf_rohc_rtp_nbo, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Set proper length for subtree */
                proto_item_set_len(root_ti, offset-tree_start_offset);

                /*   +---+---+---+---+---+---+---+---+
                 *   / Generic extension header list /  variable length
                 *   +---+---+---+---+---+---+---+---+
                 */
                offset = dissect_compressed_list(0, pinfo, dynamic_ipv4_tree, tvb, offset);

                /* Add summary to ipv4 root item */
                proto_item_append_text(root_ti, " (ToS=%u, TTL=%u, ID=%u, RND=%u, NBO=%u)",
                                       tos, ttl, id, rnd, nbo);

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
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_tc, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* XXX TODO: use the IPv6 dissector to dissect Generic extension header list ?*/
                proto_tree_add_text(sub_tree, tvb, offset, -1, "Not dissected yet");
                return -1;
            default:
                break;
        }
    }

    /* UDP dynamic*/
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
        proto_tree_add_item(dynamic_udp_tree, hf_rohc_dynamic_udp_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset +=2;
        proto_item_set_len(item, offset - start_offset);
    }

    /* RTP  dynamic*/
    if ( (profile == ROHC_PROFILE_RTP)      ) {
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
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_v, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_p, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_cc, tvb, offset, 1, ENC_BIG_ENDIAN);
        oct = tvb_get_guint8(tvb,offset);
        cc = oct & 0x0f;
        rx = (oct >> 4)& 0x01;
        offset++;
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_m, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_pt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        sequence_number = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        timestamp = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        if(cc > 0){
            /* Dissect Generic CSRC list here */
            for (i = 0; i < cc; i++ ) {
                proto_tree_add_text(dynamic_rtp_tree, tvb, offset, 4, "CSRC item %u",i+1);
                offset+=4;
            }
        }
        /* : Reserved  | X |  Mode |TIS|TSS:  if RX = 1 */
        if(rx==0){
            return offset;
        }
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_x, tvb, offset, 1, ENC_BIG_ENDIAN);
        rohc_cid_context->mode = (tvb_get_guint8(tvb,offset) &  0x0c)>>2;
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_tis, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(dynamic_rtp_tree, hf_rohc_rtp_tss, tvb, offset, 1, ENC_BIG_ENDIAN);
        oct = tvb_get_guint8(tvb,offset);
        offset++;
        /* TS_Stride             :  1-4 octets, if TSS = 1 */
        if((oct&0x01)== 1){
            /* TS_Stride encoded as
             * 4.5.6.  Self-describing variable-length values
             */
            get_self_describing_var_len_val(tvb, dynamic_rtp_tree, offset, hf_rohc_rtp_ts_stride, &val_len);
            offset = offset + val_len;
        }

        /* Time_Stride           :  1-4 octets, if TIS = 1 */
        if((oct&0x02)== 2){
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
dissect_rohc_ir_rtp_udp_profile_static(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, int offset, gboolean d, guint8 profile, rohc_cid_context_t *rohc_cid_context){

    proto_item *item, *ipv4_item, *udp_item, *rtp_item;
    proto_tree *sub_tree=NULL, *static_ipv4_tree, *static_udp_tree, *static_rtp_tree;
    guint8 version;
    int start_offset, tree_start_offset;

    start_offset = offset;
    switch(profile){

        case ROHC_PROFILE_UNCOMPRESSED:
            item = proto_tree_add_text(tree, tvb, offset, 0, "Profile 0x0000 Uncompressed");
            break;

        case ROHC_PROFILE_RTP:
            item = proto_tree_add_text(tree, tvb, offset, 0, "Profile 0x0001 RTP Static Chain");
            break;

        case ROHC_PROFILE_UDP:
            item = proto_tree_add_text(tree, tvb, offset, 0, "Profile 0x0002 UDP Static Chain");
            break;

        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Profile not supported");
            return -1;
    }

    /* IP static*/
    /* for all profiles except uncompressed */
    if ( (profile != ROHC_PROFILE_UNCOMPRESSED) ) {
        sub_tree = proto_item_add_subtree(item, ett_rohc_rtp_static);
        version = tvb_get_guint8(tvb,offset)>>4;
        proto_tree_add_item(sub_tree, hf_rohc_ip_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        if(rohc_cid_context){
            rohc_cid_context->rohc_ip_version = version;
        }
        switch(version){
            case 4:
            {
                /* 5.7.7.4.  Initialization of IPv4 Header [IPv4, section 3.1].
                 * Static part:
                 */
                guint8  protocol;
                guint32 source, dest;

                offset++;
                tree_start_offset = offset;
                /* Create static IPv4 subtree */
                ipv4_item = proto_tree_add_item(sub_tree, hf_rohc_static_ipv4, tvb, offset, -1, ENC_NA);
                static_ipv4_tree = proto_item_add_subtree(ipv4_item, ett_rohc_static_ipv4);
                /* Protocol */
                protocol = tvb_get_guint8(tvb, offset);
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
                                       (char*)get_hostname(source),
                                       (char*)get_hostname(dest));
            }
            break;
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
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_nxt_hdr, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                /* Source Address */
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_src, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset+=16;

                /*  Destination Address */
                proto_tree_add_item(sub_tree, hf_rohc_ipv6_dst, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset+=16;

                return offset;
            default:
                proto_tree_add_text(sub_tree, tvb, offset, -1, "Error unknown version, only 4 or 6 allowed");
                return -1;
        }
    }

    /* UDP static */
    if ((profile == ROHC_PROFILE_RTP) ||
        (profile == ROHC_PROFILE_UDP)) {
        /* 5.7.7.5.  Initialization of UDP Header [RFC-768].
         * Static part
         */
        guint16 source_port, dest_port, ssrc;

        /* Create static UDP subtree */
        tree_start_offset = offset;
        udp_item = proto_tree_add_item(sub_tree, hf_rohc_static_udp, tvb, offset, -1, ENC_NA);
        static_udp_tree = proto_item_add_subtree(udp_item, ett_rohc_static_udp);
        /* Source Port */
        source_port = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(static_udp_tree, hf_rohc_rtp_udp_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* Destination Port */
        dest_port = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(static_udp_tree, hf_rohc_rtp_udp_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* Set proper length for subtree */
        proto_item_set_len(udp_item, offset-tree_start_offset);
        /* Add summary to root item */
        proto_item_append_text(udp_item, " (%u -> %u)", source_port, dest_port);

        if(profile == ROHC_PROFILE_UDP){
            if(d==TRUE){
                offset = dissect_rohc_ir_rtp_profile_dynamic(tvb, pinfo, tree, offset, profile, rohc_cid_context);
            }
            proto_item_set_len(item, offset - start_offset);
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
        proto_item_append_text(rtp_item, " (SSRC=%u)", ssrc);

        proto_item_set_len(item, offset - start_offset);

        /* D:   D = 1 indicates that the dynamic chain is present. */
        if(d==TRUE){
            offset = dissect_rohc_ir_rtp_profile_dynamic(tvb, pinfo, tree, offset, profile, rohc_cid_context);
        }
    }
    return offset;
}

static int
dissect_rohc_ir_packet(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, guint16 cid, gboolean is_add_cid, rohc_info *p_rohc_info)
{
    proto_item *ir_item, *item;
    proto_tree *ir_tree;
    int x_bit_offset;
    gboolean d = FALSE;
    guint8 oct, profile, val_len;
    gint16 feedback_data_len = 0;
    tvbuff_t *next_tvb;
    rohc_cid_context_t *rohc_cid_context = NULL;
    /* This function is potentially called from both dissect_rohc and dissect_pdcp_lte
     * The cid value must have been dissected and valid
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
    oct = tvb_get_guint8(tvb,offset);

    if((p_rohc_info->large_cid_present == FALSE) && (is_add_cid == FALSE)){
        item = proto_tree_add_uint(tree, hf_rohc_small_cid, tvb, 0, 0, cid);
        PROTO_ITEM_SET_GENERATED(item);
    }
    ir_item = proto_tree_add_item(tree, hf_rohc_ir_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
    ir_tree = proto_item_add_subtree(ir_item, ett_rohc_ir);
    d = oct & 0x01;
    x_bit_offset = offset;
    offset++;
    if(p_rohc_info->large_cid_present == TRUE){
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, ir_tree, offset, hf_rohc_large_cid, &val_len);
        offset = offset + val_len;
    }

    profile = tvb_get_guint8(tvb,offset);
    if(profile==ROHC_PROFILE_RTP){
        proto_tree_add_item(ir_tree, hf_rohc_d_bit, tvb, x_bit_offset, 1, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(ir_tree, hf_rohc_profile, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ir_tree, hf_rohc_rtp_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* See if we have an entry for this CID 
     * Update it if we do otherwise create it
     * and fill in the info.
     */
    if (!pinfo->fd->flags.visited){
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, &cid);
        if(rohc_cid_context){
            /* This is not the first IR packet seen*/
            gint *key;
            gint tmp_prev_ir_frame_number = rohc_cid_context->ir_frame_number;

            /*g_warning("IR pkt found CID %u",cid);*/

            rohc_cid_context = se_new(rohc_cid_context_t);
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = tmp_prev_ir_frame_number;
            rohc_cid_context->ir_frame_number = pinfo->fd->num;

            key = g_malloc(sizeof(gint));
            *key = cid;
            g_hash_table_replace(rohc_cid_hash, key, rohc_cid_context);
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
        }else{
            gint *key;
            rohc_cid_context = se_new(rohc_cid_context_t);
            /*rohc_cid_context->rohc_ip_version;*/
            /*rohc_cid_context->large_cid_present;*/
            /*rohc_cid_context->mode     mode;*/
            /*rohc_cid_context->d_mode;*/
            /*rohc_cid_context->rnd;*/
            /*rohc_cid_context->udp_checkum_present;*/
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = pinfo->fd->num;
            key = g_malloc(sizeof(gint));
            *key = cid;

            /*g_warning("IR pkt New CID %u",cid);*/

            g_hash_table_insert(rohc_cid_hash, key, rohc_cid_context);
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
        }
    }else{
        /* get the stored data */
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(pinfo->fd, proto_rohc);
    }

    switch(profile){
        case ROHC_PROFILE_UNCOMPRESSED:
            /*
            offset = dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, cid, profile, rohc_cid_context);
            */
               next_tvb = tvb_new_subset_remaining(tvb, offset);
            if ( (oct&0xf0) == 0x60 ) {
                call_dissector(ipv6_handle, next_tvb, pinfo, tree);
            }
            else {
                call_dissector(ip_handle, next_tvb, pinfo, tree);
            }
            col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "ROHC <");
              col_append_str(pinfo->cinfo, COL_PROTOCOL, ">");
            break;
        case ROHC_PROFILE_RTP:
            offset = dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, profile, rohc_cid_context);
            break;
        case ROHC_PROFILE_UDP:
            offset = dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, profile, rohc_cid_context);
            break;
        default:
            proto_tree_add_text(ir_tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
            offset = -1;
            break;
    }


    return offset;

}

static int
dissect_rohc_ir_dyn_packet(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                           int offset, guint16 cid, gboolean is_add_cid, rohc_info *p_rohc_info)
{
    proto_item *ir_item, *item;
    proto_tree *ir_tree;
    guint8 profile, val_len;
    gint16 feedback_data_len = 0;
    rohc_cid_context_t *rohc_cid_context;

    if((p_rohc_info->large_cid_present == FALSE) && (is_add_cid == FALSE)){
        item = proto_tree_add_uint(tree, hf_rohc_small_cid, tvb, 0, 0, cid);
        PROTO_ITEM_SET_GENERATED(item);
    }
    ir_item = proto_tree_add_item(tree, hf_rohc_ir_dyn_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
    ir_tree = proto_item_add_subtree(ir_item, ett_rohc_ir_dyn);
    if(p_rohc_info->large_cid_present == TRUE){
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, ir_tree, offset, hf_rohc_large_cid, &val_len);
        offset = offset + val_len;
    }
    profile = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(ir_tree, hf_rohc_profile, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* See if we have an entry for this CID
     * Update it if we do otherwise create it
     * and fill in the info.
     */
    if (!pinfo->fd->flags.visited){
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, &cid);
        if(rohc_cid_context){
            /* This is not the first IR packet seen*/
            gint *key;
            gint tmp_prev_ir_frame_number = rohc_cid_context->ir_frame_number;

            /*g_warning("IR pkt found CID %u",cid);*/

            rohc_cid_context = se_new(rohc_cid_context_t);
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = tmp_prev_ir_frame_number;
            rohc_cid_context->ir_frame_number = pinfo->fd->num;

            key = g_malloc(sizeof(gint));
            *key = cid;
            g_hash_table_replace(rohc_cid_hash, key, rohc_cid_context);
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
        }else{
			gint *key;
            rohc_cid_context = se_new(rohc_cid_context_t);
            /*rohc_cid_context->rohc_ip_version;*/
            /*rohc_cid_context->large_cid_present;*/
            /*rohc_cid_context->mode     mode;*/
            /*rohc_cid_context->d_mode;*/
            /*rohc_cid_context->rnd;*/
            /*rohc_cid_context->udp_checkum_present;*/
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = pinfo->fd->num;
            key = g_malloc(sizeof(gint));
            *key = cid;

            /*g_warning("IR pkt New CID %u",cid);*/

            g_hash_table_insert(rohc_cid_hash, key, rohc_cid_context);
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
        }
    }else{
        /* get the stored data */
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(pinfo->fd, proto_rohc);
    }

    proto_tree_add_item(ir_tree, hf_rohc_rtp_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    switch(profile){
        case ROHC_PROFILE_RTP:
            dissect_rohc_ir_rtp_profile_dynamic(tvb, pinfo, ir_tree, offset, profile, rohc_cid_context);
            break;
        default:
            proto_tree_add_text(ir_tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
            break;
    }
    return offset;

}
static void
dissect_rohc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *item, *conf_item;
    proto_tree *rohc_tree, *sub_tree = NULL, *conf_tree;
    int offset = 0, length;
    guint8 oct, code, size, val_len;
    gint16 feedback_data_len = 0, cid = 0;
    gboolean is_add_cid = FALSE;
    rohc_info *p_rohc_info = NULL;
    rohc_info g_rohc_info;
    void *save_private_data = pinfo->private_data;
    tvbuff_t *next_tvb;
    rohc_cid_context_t *rohc_cid_context = NULL;

    if(pinfo->private_data == NULL){
        g_rohc_info.rohc_compression    = FALSE;
        g_rohc_info.rohc_ip_version     = g_version;
        g_rohc_info.cid_inclusion_info  = FALSE;
        g_rohc_info.large_cid_present   = FALSE;
        g_rohc_info.mode                = RELIABLE_BIDIRECTIONAL;
        g_rohc_info.rnd                 = FALSE;
        g_rohc_info.udp_checkum_present = FALSE;
        g_rohc_info.profile             = g_profile;
        g_rohc_info.last_created_item   = NULL;
        p_rohc_info = &g_rohc_info;
    }else{
        p_rohc_info = pinfo->private_data;
        memset(&g_rohc_info, 0, sizeof(rohc_info));
    }

    length = tvb_length(tvb);

    /* If this is ROHC ethertype clear col */
    if ( pinfo->src.type == AT_ETHER ){
        col_set_str(pinfo->cinfo, COL_INFO, "ROHC");
        col_clear(pinfo->cinfo, COL_INFO);
    }else{
        col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC");
        /* Append a space if we add stuff to existing col info */
        col_append_str(pinfo->cinfo, COL_INFO, " ");
    }
    ti = proto_tree_add_item(tree, proto_rohc, tvb, 0, -1, ENC_NA);
    rohc_tree = proto_item_add_subtree(ti, ett_rohc);
    /*    1) If the first octet is a Padding Octet (11100000),
     *       strip away all initial Padding Octets and goto next step.
     */

    /* Put configuration data into the tree */
    item = proto_tree_add_text(rohc_tree, tvb, offset, 0, "Global Configuration: (%s)", p_rohc_info->large_cid_present ? "Large CID" : "Small CID");
    conf_tree = proto_item_add_subtree(item, ett_rohc_conf);
    PROTO_ITEM_SET_GENERATED(item);
    rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(pinfo->fd, proto_rohc);
    if(rohc_cid_context){
		/* Do we have info from an IR frame? */
		if(rohc_cid_context->ir_frame_number>0){
			conf_item = proto_tree_add_text(conf_tree, tvb, offset, 0, "Configured by IR packet");
			PROTO_ITEM_SET_GENERATED(conf_item);
			conf_item = proto_tree_add_uint(conf_tree, hf_rohc_ir_pkt_frame, tvb, 0, 0, rohc_cid_context->ir_frame_number);
			PROTO_ITEM_SET_GENERATED(conf_item);
			if(rohc_cid_context->prev_ir_frame_number>0){
				conf_item = proto_tree_add_uint(conf_tree, hf_rohc_ir_previous_frame, tvb, 0, 0, rohc_cid_context->prev_ir_frame_number);
				PROTO_ITEM_SET_GENERATED(conf_item);
			}
			conf_item = proto_tree_add_text(conf_tree, tvb, offset, 0, "Profile:(%s)", val_to_str(rohc_cid_context->profile, rohc_profile_vals, "Unknown"));
			PROTO_ITEM_SET_GENERATED(conf_item);
			conf_item = proto_tree_add_text(conf_tree, tvb, offset, 0, "IP version:(%s)", val_to_str(rohc_cid_context->rohc_ip_version, rohc_ip_version_vals, "Unknown"));
			PROTO_ITEM_SET_GENERATED(conf_item);
			if(rohc_cid_context->mode == 0){
				conf_item = proto_tree_add_text(conf_tree, tvb, offset, 0, "Mode not known");
				PROTO_ITEM_SET_GENERATED(conf_item);
			}else{
				conf_item = proto_tree_add_text(conf_tree, tvb, offset, 0, "Mode:(%s)", val_to_str(rohc_cid_context->mode, rohc_mode_vals, "Unknown"));
				PROTO_ITEM_SET_GENERATED(conf_item);
			}

		}else{
			conf_item = proto_tree_add_text(conf_tree, tvb, offset, 0, "No configuration info");
			PROTO_ITEM_SET_GENERATED(conf_item);
		}
    }


#if 0
            /*rohc_cid_context->rohc_ip_version;*/
            /*rohc_cid_context->large_cid_present;*/
            /*rohc_cid_context->mode     mode;*/
            /*rohc_cid_context->d_mode;*/
            /*rohc_cid_context->rnd;*/
            /*rohc_cid_context->udp_checkum_present;*/
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = pinfo->fd->num;
#endif
#if 0
    "Profile:(%s)", val_to_str(p_rohc_info->profile, rohc_profile_vals, "Unknown"));
    if(p_rohc_info->large_cid_present == FALSE){
        item = proto_tree_add_text(rohc_tree, tvb, offset, -1, "Small CID configured");
        PROTO_ITEM_SET_GENERATED(item);
    }else{
        item = proto_tree_add_text(rohc_tree, tvb, offset, -1, "Large CID configured");
        PROTO_ITEM_SET_GENERATED(item);
    }
#endif
start_over:
    cid = 0;
    oct = tvb_get_guint8(tvb,offset);
    if(oct== 0xe0){
        while(oct == 0xe0){
            offset++;
            oct = tvb_get_guint8(tvb,offset);
        }
        proto_tree_add_item(rohc_tree, hf_rohc_padding, tvb, 0, offset, ENC_NA);
    }
    /* 2) If the first remaining octet starts with 1110, it is an Add-CID octet:
     *    remember the Add-CID octet; remove the octet.
     */
    if((oct&0xf0) == 0xe0){
        is_add_cid = TRUE;
        cid = oct & 0x0f;
        proto_tree_add_item(rohc_tree, hf_rohc_add_cid, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, offset, 1, cid);
        offset++;

        oct = tvb_get_guint8(tvb,offset);
    }
    /* feedback ?
     * Feedback (begins with 11110)
     */
    if((oct&0xf8) == 0xf0){
        /* 3) If the first remaining octet starts with 11110, and an Add-CID
         *    octet was found in step 2), an error has occurred;
         *    the header MUST be discarded without further action.
         */

        if(is_add_cid){
            proto_tree_add_item(rohc_tree, hf_rohc_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, "Error packet");
            proto_tree_add_text(rohc_tree, tvb, offset, -1, "Error packet");
            pinfo->private_data = save_private_data;
            return;
        }else{
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
            p_rohc_info->last_created_item = proto_tree_add_item(rohc_tree, hf_rohc_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
            sub_tree = proto_item_add_subtree(p_rohc_info->last_created_item, ett_rohc_fb);
            proto_tree_add_item(sub_tree, hf_rohc_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            code = oct&0x7;
            offset++;
            if(code==0){
                size = tvb_get_guint8(tvb,offset);
                proto_tree_add_item(sub_tree, hf_rohc_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }else{
                size = code;
            }
            feedback_data_len = size;
            if(p_rohc_info->large_cid_present == FALSE){
                /* Check for Add-CID octet */
                oct = tvb_get_guint8(tvb,offset);
                if((oct&0xf0) == 0xe0){
                    cid = oct & 0x0f;
                    proto_tree_add_item(sub_tree, hf_rohc_add_cid, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(sub_tree, hf_rohc_small_cid, tvb, offset, 1, cid);
                    offset++;
                    feedback_data_len--;
                }else{
                    item = proto_tree_add_uint(sub_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
                    PROTO_ITEM_SET_GENERATED(item);
                }
            }else{
                /* Read Large CID here */
                get_self_describing_var_len_val(tvb, sub_tree, offset, hf_rohc_large_cid, &val_len);
                /* feedback_data_len - "lenght of large CID" */
                feedback_data_len = feedback_data_len - val_len;
            }

            /* Dissect feedback */
            dissect_rohc_feedback_data(tvb, sub_tree, pinfo, offset, feedback_data_len, p_rohc_info, cid);
            offset = offset + size;
            if(offset<length)
                goto start_over;
            pinfo->private_data = save_private_data;
            return;
        }
    }/*feedback */
    /* 5) If the first remaining octet starts with 1111111, this is a segment:
     *
     */
    if((oct&0xfe) == 0xfe){
        col_append_str(pinfo->cinfo, COL_INFO, "Segment");
        if((p_rohc_info->large_cid_present == FALSE) && (is_add_cid == FALSE)){
            item = proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
            PROTO_ITEM_SET_GENERATED(item);
        }
        proto_tree_add_text(rohc_tree, tvb, offset, -1, "Segment [Desegmentation not implemented yet]");

        pinfo->private_data = save_private_data;
        return;
    }
    /* 6) Here, it is known that the rest is forward information (unless the
     *    header is damaged).
     */
    if((oct&0xfe) == 0xfc){
        col_append_str(pinfo->cinfo, COL_INFO, "IR packet");
        offset = dissect_rohc_ir_packet(tvb, rohc_tree, pinfo, offset, cid, is_add_cid, p_rohc_info);
        if(offset == -1){
            /* Could not pare header */
            return;
        }
        proto_tree_add_text(rohc_tree, tvb, offset, -1, "Data");
        return;
    }
    if((oct&0xff) == 0xf8){
        col_append_str(pinfo->cinfo, COL_INFO, "IR-DYN packet");
        offset = dissect_rohc_ir_dyn_packet(tvb, rohc_tree, pinfo, offset, cid, is_add_cid, p_rohc_info);
        if(offset == -1){
            /* Could not pare header */
            return;
        }
        proto_tree_add_text(rohc_tree, tvb, offset, -1, "Data");
        return;
    }

    if (!pinfo->fd->flags.visited){
        gint key;

        /*g_warning("Lookup CID %u",cid);*/
        key = cid;
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, &key);
        if(rohc_cid_context){		
            /*g_warning("Found CID %u",cid);*/
        }else{
            rohc_cid_context = se_new(rohc_cid_context_t);
            /*rohc_cid_context->rohc_ip_version;*/
            /*rohc_cid_context->large_cid_present;*/
            /*rohc_cid_context->mode     mode;*/
            /*rohc_cid_context->d_mode;*/
            /*rohc_cid_context->rnd;*/
            /*rohc_cid_context->udp_checkum_present;*/
            rohc_cid_context->profile = ROHC_PROFILE_UNKNOWN;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = -1;
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
            /*g_warning("Store dummy data %u",cid);*/
        }
        p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
    }

    /* Call IP for uncompressed*/
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if      (((oct&0xf0)==0x40) && (rohc_cid_context->profile==ROHC_PROFILE_UNCOMPRESSED)) {
       call_dissector(ip_handle, next_tvb, pinfo, tree);
    }
    else if (((oct&0xf0)==0x60) && (rohc_cid_context->profile==0)) {
       call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    }
    else if((oct&0x80)==0x00){
        /* 5.7.1. Packet type 0: UO-0, R-0, R-0-CRC */
        switch(rohc_cid_context->mode){
            case RELIABLE_BIDIRECTIONAL: /* R-mode */
                if((oct&0xc0)==0x00){

                /*   R-0
                 *
                 *     0   1   2   3   4   5   6   7
                 *   +---+---+---+---+---+---+---+---+
                 *   | 0   0 |          SN           |
                 *   +===+===+===+===+===+===+===+===+
                 */
                    col_set_str(pinfo->cinfo, COL_INFO, "R-0");
                    proto_tree_add_bits_item(rohc_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 6, ENC_BIG_ENDIAN);
                }else if((oct&0xc0)==0x40){
                    col_set_str(pinfo->cinfo, COL_INFO, "R-0-CRC");
                /*   R-0-CRC
                 *
                 *     0   1   2   3   4   5   6   7
                 *   +---+---+---+---+---+---+---+---+
                 *   | 0   1 |          SN           |
                 *   +===+===+===+===+===+===+===+===+
                 *   |SN |            CRC            |
                 *   +---+---+---+---+---+---+---+---+
                 */
                    proto_tree_add_bits_item(rohc_tree, hf_rohc_comp_sn, tvb, (offset<<3)+2, 7, ENC_BIG_ENDIAN);
                }
                break;
            case UNIDIRECTIONAL: /* U-mode */
                /* Fall trough */
            case OPTIMISTIC_BIDIRECTIONAL: /* O-mode */
                col_set_str(pinfo->cinfo, COL_INFO, "U0-0");
                /*   UO-0
                 *
                 *     0   1   2   3   4   5   6   7
                 *   +---+---+---+---+---+---+---+---+
                 *   | 0 |      SN       |    CRC    |
                 *   +===+===+===+===+===+===+===+===+
                 */
                 proto_tree_add_bits_item(rohc_tree, hf_rohc_comp_sn, tvb, (offset<<3)+1, 4, ENC_BIG_ENDIAN);

                break;
            default:
                col_set_str(pinfo->cinfo, COL_INFO, "Packet type 0");
                break;
        }
    }else if ((oct&0xc0)==0x80){
        col_set_str(pinfo->cinfo, COL_INFO, "Paket type 1");
    }else if ((oct&0xe0)==0xc0){
        col_set_str(pinfo->cinfo, COL_INFO, "Paket type 2");
    }

    pinfo->private_data = save_private_data;
}

/* Set up rohc_cid_hash which holds data for a CID
 * needed to dissect subsequent packages.
 * XXXX ToDo:
 * A better Key than just the CID may have to be deviced.
 * 
 */
static void
rohc_init_protocol(void)
{

    /* Destroy any existing hashes. */
    if (rohc_cid_hash)
        g_hash_table_destroy(rohc_cid_hash);

    /* Now create them again */
    rohc_cid_hash = g_hash_table_new_full(g_int_hash, g_int_equal, /* key_destroy_func */ g_free, NULL);

}

void
proto_register_rohc(void)
{

    static hf_register_info hf[] =
        {
            { &hf_rohc_padding,
              { "Padding","rohc.pading",
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
                FT_UINT8, BASE_DEC, NULL, 0xfe,
                NULL , HFILL
              }
            },
            { &hf_rohc_ir_dyn_packet,
              { "IR-DYN packet","rohc.ir_dyn_packet",
                FT_UINT8, BASE_DEC, NULL, 0xff,
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
              { "SN(lsb)","rohc.sn",
                FT_UINT16, BASE_HEX, NULL, 0x0fff,
                NULL , HFILL
              }
            },
            { &hf_rohc_fb1_sn,
              { "SN","rohc.fb1_sn",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_opt_type,
              { "Option type","rohc.rtp.opt_type",
                FT_UINT8, BASE_DEC, VALS(rohc_rtp_opt_type_vals), 0xf0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_opt_len,
              { "Option length","rohc.rtp.opt_length",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_crc,
              { "CRC","rohc.crc",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_opt_sn,
              { "SN","rohc.opt.sn",
                FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_feedback_option_clock,
              { "Clock", "rohc.feedback-option-clock",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Feedback Option Clock", HFILL
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
            { &hf_rohc_static_ipv4,
              { "Static IPv4 chain",
                "pdcp-lte.rohc.static.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
              }
            },
            { &hf_rohc_ip_protocol,
              { "Protocol","rohc.ip.protocol",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&ipproto_val_ext), 0x0,
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
              { "Destination Address","rohc.ipv6.src",
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
            { &hf_rohc_rtp_udp_src_port,
              { "Source Port","rohc.rtp.udp_src_port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_udp_dst_port,
              { "Destination Port","rohc.rtp.udp_dst_port",
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
                FT_UINT32, BASE_HEX, NULL, 0x0,
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
              { "Identification","rohc.rtp.rtp.id",
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
            { &hf_rohc_rtp_checksum,
              { "Checksum","rohc.rtp.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL , HFILL
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
              { "version","rohc.rtp.v",
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
                FT_BOOLEAN, 8,  TFS(&tfs_set_notset), 0x80,
                NULL , HFILL
              }
            },
            { &hf_rohc_rtp_pt,
              { "Payload Type(PT)","rohc.rtp.pt",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&rtp_payload_type_vals_ext), 0x7f,
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
                FT_BOOLEAN, 8,  TFS(&tfs_set_notset), 0x80,
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
              { "Compressed RTP Sequence Number","rohc.comp.sn",
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
            { &hf_rohc_compressed_list_cc,
              { "CSRC Counter", "rohc.compressed-list.cc",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                "CSRC Counter from original RTP header", HFILL
              }
            },
            { &hf_rohc_compressed_list_gen_id,
              { "gen_id", "rohc.compressed-list.gen-id",
                FT_UINT8, BASE_DEC, NULL, 0x0f,
                NULL, HFILL
              }
            },

        };

    /* Setup protocol subtree array */
    static gint *ett[] = {
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
        &ett_rohc_compressed_list
    };

    /* Register the protocol name and description */
    proto_rohc = proto_register_protocol("RObust Header Compression (ROHC)", "ROHC", "rohc");

    register_dissector("rohc", dissect_rohc, proto_rohc);

    register_init_routine(&rohc_init_protocol);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_rohc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rohc(void)
{
    static gboolean Initialized = FALSE;

    dissector_handle_t rohc_handle;

    rohc_handle = create_dissector_handle(dissect_rohc, proto_rohc);
    dissector_add_uint("ethertype", ETHERTYPE_ROHC, rohc_handle);

    if (!Initialized) {

        ip_handle = find_dissector("ip");
        ipv6_handle = find_dissector("ipv6");

        Initialized = TRUE;
    }


}
