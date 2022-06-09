/* packet-ancp.c
 *
 * Dissector for ANCP - Access Node Control Protocol
 *
 * More info on the protocol can be found on IETF:
 * https://tools.ietf.org/wg/ancp/
 * https://tools.ietf.org/html/draft-ietf-ancp-protocol-09
 * https://tools.ietf.org/html/rfc6320
 * https://www.iana.org/assignments/ancp/ancp.xhtml
 *
 * Copyright 2010, Aniruddha.A (anira@cisco.com)
 * Uli Heilmeier, 2017; Update to RFC6320; current IANA registry types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/stats_tree.h>
#include "packet-tcp.h"

#define ANCP_PORT 6068 /* The ANCP TCP port:draft-ietf-ancp-protocol-09.txt */

#define ANCP_MIN_HDR  4
#define ANCP_GSMP_ETHER_TYPE  0x880C
#define TECH_TYPE_DSL         0x5
#define TECH_TYPE_PON         0x1

#define ANCP_RESULT_MASK     0xF0
#define ANCP_CODE_MASK       0x0FFF
#define ANCP_I_FLAG_MASK     0x80
#define ANCP_SUBMSG_MASK     0x7FFF
#define ADJ_CODE_MASK        0x7F /* excluding MSB M-Flag */

#define ANCP_MTYPE_ADJ       10
#define ANCP_MTYPE_PORT_MGMT 32
#define ANCP_MTYPE_PORT_UP   80
#define ANCP_MTYPE_PORT_DN   81
#define ANCP_MTYPE_ADJ_UPD   85
#define ANCP_MTYPE_GEN_RSP   91
#define ANCP_MTYPE_PROV      93

/* Topology Discovery Extensions */
#define TLV_DSL_LINE_ATTRIBUTES         0x04
#define TLV_DSL_LINE_STATE              0x8F
#define TLV_DSL_TYPE                    0x91

/* Port Management Extensions */
#define TLV_PING_PARAMS                 0x07
#define TLV_PING_OPAQUE_DATA            0x08
#define TLV_PING_RES_STR                0x09

#define SKIPPADDING(_ofst, _len)         \
    do {                                 \
        if ((_len) % 4)                  \
            _ofst += (4 - ((_len) % 4)); \
    } while(0)

void proto_register_ancp(void);
void proto_reg_handoff_ancp(void);

static int hf_ancp_len = -1;
static int hf_ancp_len2 = -1;
static int hf_ancp_ver = -1;
static int hf_ancp_mtype = -1;
static int hf_ancp_timer = -1;
static int hf_ancp_adj_code = -1;
static int hf_ancp_sender_name = -1;
static int hf_ancp_receiver_name = -1;
static int hf_ancp_sender_port = -1;
static int hf_ancp_receiver_port = -1;
static int hf_ancp_p_info = -1;
static int hf_ancp_sender_instance = -1;
static int hf_ancp_p_id = -1;
static int hf_ancp_receiver_instance = -1;
static int hf_ancp_tech_type = -1;
static int hf_ancp_num_tlvs = -1;
static int hf_ancp_tot_len = -1;
static int hf_ancp_cap = -1;
static int hf_ancp_result = -1;
static int hf_ancp_code = -1;
static int hf_ancp_trans_id = -1;
static int hf_ancp_i_flag = -1;
static int hf_ancp_submsg_num = -1;
static int hf_ancp_pudm_unused = -1;
static int hf_ancp_function = -1;
static int hf_ancp_x_function = -1;
static int hf_ancp_ext_flags_res = -1;
static int hf_ancp_reserved = -1;
static int hf_ancp_blk_len = -1;
static int hf_ancp_num_ext_tlvs = -1;
static int hf_ancp_ext_tlv_type = -1;
static int hf_ancp_ext_tlv_len = -1;
static int hf_ancp_dsl_line_stlv_type = -1;
static int hf_ancp_dsl_line_stlv_len = -1;
static int hf_ancp_dsl_line_stlv_value = -1;
static int hf_ancp_ext_tlv_value_str = -1;
static int hf_ancp_oam_opaque = -1;
static int hf_ancp_oam_loopb_cnt = -1;
static int hf_ancp_oam_timeout = -1;

static gint ett_ancp_len = -1;
static gint ett_ancp_ver = -1;
static gint ett_ancp_mtype = -1;
static gint ett_ancp_timer = -1;
static gint ett_ancp_adj_code = -1;
static gint ett_ancp_sender_name = -1;
static gint ett_ancp_receiver_name = -1;
static gint ett_ancp_sender_port = -1;
static gint ett_ancp_receiver_port = -1;
static gint ett_ancp_p_info = -1;
static gint ett_ancp_sender_instance = -1;
static gint ett_ancp_p_id = -1;
static gint ett_ancp_receiver_instance = -1;
static gint ett_ancp_tech_type = -1;
static gint ett_ancp_num_tlvs = -1;
static gint ett_ancp_tot_len = -1;
static gint ett_ancp_cap = -1;
static gint ett_ancp_result = -1;
static gint ett_ancp_code = -1;
static gint ett_ancp_trans_id = -1;
static gint ett_ancp_i_flag = -1;
static gint ett_ancp_submsg_num = -1;
static gint ett_ancp_port = -1;
static gint ett_ancp_port_sess_num= -1;
static gint ett_ancp_evt_seq_num = -1;
static gint ett_ancp_label = -1;
static gint ett_ancp_reserved = -1;
static gint ett_ancp_blk_len = -1;
static gint ett_ancp_num_ext_tlvs = -1;
static gint ett_ancp_ext_tlv_type = -1;
static gint ett_ancp_dsl_line_stlv_type = -1;
static gint ett_ancp_dsl_line_stlv_val = -1;
static gint ett_ancp_ext_tlv_value_str = -1;
static gint ett_ancp_oam_opaque = -1;
static gint ett_ancp_oam_loopb_cnt = -1;
static gint ett_ancp_oam_timeout = -1;

static int proto_ancp = -1;

/* ANCP stats - Tap interface */
static const guint8 *st_str_packets        = "Total Packets";
static const guint8 *st_str_packet_types   = "ANCP Packet Types";
static const guint8 *st_str_adj_pack_types = "ANCP Adjacency Packet Types";

static int st_node_packets = -1;
static int st_node_packet_types = -1;
static int st_node_adj_pack_types = -1;
static int ancp_tap = -1;

struct ancp_tap_t {
    gint ancp_mtype;
    gint ancp_adjcode; /* valid for ancp adjacency message only */
};

/* Value Strings */
static const value_string mtype_names[] = {
    { 10, "Adjacency" },
    { 32, "Port-Management" },
    { 80, "Port-Up" },
    { 81, "Port-Down" },
    { 85, "Adjacency Update" },
    { 91, "Generic Response" },
    { 93, "Provisioning" },
    {  0,  NULL }
};

static const value_string adj_code_names[] = {
    { 1, "Syn" },
    { 2, "SynAck" },
    { 3, "Ack" },
    { 4, "Rstack" },
    { 0,  NULL }
};

static const value_string captype_names[] = {
    { 1, "Dynamic-Topology-Discovery" },
    { 2, "Line-Configuration" },
    { 3, "Transactional-Multicast" },
    { 4, "OAM" },
    { 0,  NULL }
};

static const value_string resulttype_names[] = {
    { 0, "Ignore" },
    { 1, "NAck" },
    { 2, "AckAll" },
    { 3, "Success" },
    { 4, "Failure" },
    { 0,  NULL }
};

static const value_string codetype_names[] = {
    { 0x000, "No result" },
    { 0x002, "Invalid request message" },
    { 0x006, "One or more of the specified ports are down" },
    { 0x013, "Out of resources" },
    { 0x051, "Request message type not implemented" },
    { 0x053, "Malformed message" },
    { 0x054, "Mandatory TLV missing" },
    { 0x055, "Invalid TLV contents" },
    { 0x500, "One or more of the specified ports do not exist" },
    { 0x501, "Loopback test timed out" },
    { 0x502, "Reserved" },
    { 0x503, "DSL access line status showtime" },
    { 0x504, "DSL access line status idle" },
    { 0x505, "DSL access line status silent" },
    { 0x506, "DSL access line status training" },
    { 0x507, "DSL access line integrity error" },
    { 0x508, "DSLAM resource not available" },
    { 0x509, "Invalid test parameter" },
    { 0,  NULL }
};

static const value_string techtype_str[] = {
    { 0x00,  "Not technology dependent" },
    { 0x01,  "PON" },
    { 0x05,  "DSL" },
    { 0xFF,  "Reserved" },
    { 0,  NULL }
};

static const value_string dsl_line_attrs[] = {
    { 0x91,  "DSL-Type" },
    { 0x81,  "Actual-Net-Data-Rate-Upstream" },
    { 0x82,  "Actual-Net-Data-Rate-Downstream" },
    { 0x83,  "Minimum-Net-Data-Rate-Upstream" },
    { 0x84,  "Minimum-Net-Data-Rate-Downstream" },
    { 0x85,  "Attainable-Net-Data-Rate-Upstream" },
    { 0x86,  "Attainable-Net-Data-Rate-Downstream" },
    { 0x87,  "Maximum-Net-Data-Rate-Upstream" },
    { 0x88,  "Maximum-Net-Data-Rate-Downstream" },
    { 0x89,  "Minimum-Net-Low-Power-Data-Rate-Upstream" },
    { 0x8A,  "Minimum-Net-Low-Power-Data-Rate-Downstream" },
    { 0x8B,  "Maximum-Interleaving-Delay-Upstream" },
    { 0x8C,  "Actual-Interleaving-Delay-Upstream" },
    { 0x8D,  "Maximum-Interleaving-Delay-Downstream" },
    { 0x8E,  "Actual-Interleaving-Delay-Downstream" },
    { 0x8F,  "DSL line state" },
    { 0x90,  "Access Loop Encapsulation" },
    { 0,  NULL }
};

static const value_string dsl_line_attr_units[] = {
    { 0x91,  "" },
    { 0x81,  "Kb/sec" },
    { 0x82,  "Kb/sec" },
    { 0x83,  "Kb/sec" },
    { 0x84,  "Kb/sec" },
    { 0x85,  "Kb/sec" },
    { 0x86,  "Kb/sec" },
    { 0x87,  "Kb/sec" },
    { 0x88,  "Kb/sec" },
    { 0x89,  "Kb/sec" },
    { 0x8A,  "Kb/sec" },
    { 0x8B,  "msec" },
    { 0x8C,  "msec" },
    { 0x8D,  "msec" },
    { 0x8E,  "msec" },
    { 0x8F,  "" },
    { 0x90,  "" },
    { 0,  NULL }
};

static const value_string dsl_line_type_names[] = {
    { 1,  "ADSL1" },
    { 2,  "ADSL2" },
    { 3,  "ADSL2+" },
    { 4,  "VDSL1" },
    { 5,  "VDSL2" },
    { 6,  "SDSL" },
    { 0,  NULL }
};

static const value_string dsl_line_state_names[] = {
    { 1,  "Showtime" },
    { 2,  "Idle" },
    { 3,  "Silent" },
    { 0,  NULL }
};

static const value_string function_names[] = {
    { 0,  "Reserved" },
    { 8,  "Configure Connection Service Data" },
    { 9,  "Remote Loopback" },
    { 0,  NULL }
};

static const value_string ext_tlv_types[] = {
    { 0x0001, "Access-Loop-Circuit-ID" },
    { 0x0002, "Access-Loop-Remote-ID" },
    { 0x0003, "Access-Aggregation-Circuit-ID-ASCII" },
    { 0x0004, "DSL Line Attributes" },
    { 0x0005, "Service-Profile-Name" },
    { 0x0006, "Access-Aggregation-Circuit-ID-Binary" },
    { 0x0007, "OAM-Loopback-Test-Parameters" },
    { 0x0008, "Opaque-Data" },
    { 0x0009, "OAM-Loopback-Test-Response-String" },
    { 0x0011, "Command" },
    { 0x0013, "Multicast-Service-Profile" },
    { 0x0015, "Bandwidth-Allocation" },
    { 0x0016, "Bandwidth-Request" },
    { 0x0018, "Multicast-Service-Profile-Name" },
    { 0x0019, "Multicast-Flow" },
    { 0x0021, "List-Action" },
    { 0x0022, "Sequence-Number" },
    { 0x0024, "White-List-CAC" },
    { 0x0025, "MRepCtl-CAC" },
    { 0x0081, "Actual-Net-Data-Rate-Upstream" },
    { 0x0082, "Actual-Net-Data-Rate-Downstream" },
    { 0x0083, "Minimum-Net-Data-Rate-Upstream" },
    { 0x0084, "Minimum-Net-Data-Rate-Downstream" },
    { 0x0085, "Attainable-Net-Data-Rate-Upstream" },
    { 0x0086, "Attainable-Net-Data-Rate-Downstream" },
    { 0x0087, "Maximum-Net-Data-Rate-Upstream" },
    { 0x0088, "Maximum-Net-Data-Rate-Downstream" },
    { 0x0089, "Minimum-Net-Low-Power-Data-Rate-Upstream" },
    { 0x008A, "Minimum-Net-Low-Power-Data-Rate-Downstream" },
    { 0x008B, "Maximum-Interleaving-Delay-Upstream" },
    { 0x008C, "Actual-Interleaving-Delay-Upstream" },
    { 0x008D, "Maximum-Interleaving-Delay-Downstream" },
    { 0x008E, "Actual-Interleaving-Delay-Downstream" },
    { 0x008F, "DSL-Line-State" },
    { 0x0090, "Access-Loop-Encapsulation" },
    { 0x0091, "DSL-Type" },
    { 0x0092, "Request-Source-IP" },
    { 0x0093, "Request-Source-MAC" },
    { 0x0094, "Report-Buffering-Time" },
    { 0x0095, "Committed-Bandwidth" },
    { 0x0096, "Request-Source-Device-Id" },
    { 0x0106, "Status-Info" },
    { 0x1000, "Target (single access line variant)" },
    { 0,  NULL }
};
static value_string_ext ext_tlv_types_ext = VALUE_STRING_EXT_INIT(ext_tlv_types);

static gint
dissect_ancp_tlv(tvbuff_t *tvb, proto_tree *tlv_tree, gint offset)
{
        guint16     tlen, ttype;
        gint16      num_stlvs;
        proto_item *tti;

            proto_tree_add_item(tlv_tree, hf_ancp_ext_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            ttype = tvb_get_ntohs(tvb, offset);
            offset += 2;

            tti = proto_tree_add_item(tlv_tree, hf_ancp_ext_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            tlen = tvb_get_ntohs(tvb, offset);
            offset += 2;

            /*
             * Extension Block is common for event message and port
             * management message, but the TLVs that can appear
             * are different
             */
            switch (ttype) {
                case TLV_DSL_LINE_ATTRIBUTES:
                {
                    proto_tree *dsl_tree;
                    guint16     stlvtype, stlvlen;
                    gint        val;

                    /* Create a DSL Attribute SubTree */
                    dsl_tree = proto_item_add_subtree(tti, ett_ancp_ext_tlv_type);
                    num_stlvs = tlen / 8; /* TODO - better way? */
                    for ( ;num_stlvs; num_stlvs--) {
                        proto_tree_add_item(dsl_tree,
                                hf_ancp_dsl_line_stlv_type, tvb, offset,
                                2, ENC_BIG_ENDIAN);
                        stlvtype = tvb_get_ntohs(tvb, offset);
                        offset += 2;
                        proto_tree_add_item(dsl_tree,
                                hf_ancp_dsl_line_stlv_len, tvb, offset,
                                2, ENC_BIG_ENDIAN);
                        stlvlen = tvb_get_ntohs(tvb, offset);
                        offset += 2; /* Sub TLV Length */

                        tti = proto_tree_add_item(dsl_tree,
                                hf_ancp_dsl_line_stlv_value, tvb, offset,
                                stlvlen, ENC_BIG_ENDIAN);
                        val = tvb_get_ntohl(tvb, offset);
                        offset += stlvlen; /* Except loop-encap, rest are 4B */

                        switch (stlvtype) {
                            case TLV_DSL_LINE_STATE:
                                proto_item_append_text(tti, " (%s)",
                                        val_to_str(val, dsl_line_state_names,
                                            "Unknown (0x%02x)"));
                                break;
                            case TLV_DSL_TYPE:
                                proto_item_append_text(tti, " (%s)",
                                        val_to_str(val, dsl_line_type_names,
                                            "Unknown (0x%02x)"));
                                break;

                            default:
                                /* Add Unit */
                                proto_item_append_text(tti, " %s",
                                        val_to_str(stlvtype,
                                            dsl_line_attr_units,
                                            "Unknown (0x%02x)"));
                                break;
                        }
                        SKIPPADDING(offset, stlvlen);
                    }
                    break;
                }
                case TLV_PING_OPAQUE_DATA:
                    /* 2 32b values*/
                    proto_tree_add_item(tlv_tree, hf_ancp_oam_opaque,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(tlv_tree, hf_ancp_oam_opaque,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;
                case TLV_PING_PARAMS:
                    /* Count (1B) Timeout (1B), 2B empty */
                    proto_tree_add_item(tlv_tree,
                            hf_ancp_oam_loopb_cnt, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(tlv_tree,
                            hf_ancp_oam_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    /* Lets not bother about 2B until IETF WG figures out */
                    offset += 2;
                    break;
                default:
                    /* Assume TLV value is string - covers ALCID, OAM resp */
                    proto_tree_add_item(tlv_tree, hf_ancp_ext_tlv_value_str,
                            tvb, offset, tlen, ENC_ASCII);
                    offset += tlen;
                    SKIPPADDING(offset, tlen);
                    break;
            } /* end switch {ttype} */
            return offset;
}

static void
dissect_ancp_port_up_dn_mgmt(tvbuff_t *tvb, proto_tree *ancp_tree, gint offset, guint8 mtype)
{
    guint8 tech_type;
    gint16 num_tlvs;
    proto_item *sti;

    if (mtype == ANCP_MTYPE_PORT_MGMT) {
        proto_tree_add_item(ancp_tree, hf_ancp_pudm_unused,    tvb, offset, 14, ENC_NA);
        offset += 14;

        proto_tree_add_item(ancp_tree, hf_ancp_function,       tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(ancp_tree, hf_ancp_x_function,     tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(ancp_tree, hf_ancp_pudm_unused,    tvb, offset, 4, ENC_NA);
        offset += 4;
    } else {
        proto_tree_add_item(ancp_tree, hf_ancp_pudm_unused,    tvb, offset, 20, ENC_NA);
        offset += 20;
    }

    proto_tree_add_item(ancp_tree, hf_ancp_ext_flags_res, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(ancp_tree, hf_ancp_mtype,         tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (mtype == ANCP_MTYPE_PORT_MGMT) {
        proto_tree_add_item(ancp_tree, hf_ancp_reserved,      tvb, offset, 2, ENC_NA);
        offset += 2;
        tech_type = 0;
    } else {
        proto_tree_add_item(ancp_tree, hf_ancp_tech_type,     tvb, offset, 1, ENC_BIG_ENDIAN);
        tech_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ancp_tree, hf_ancp_reserved,      tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    proto_tree_add_item(ancp_tree, hf_ancp_num_ext_tlvs, tvb, offset, 2, ENC_BIG_ENDIAN);
    num_tlvs = tvb_get_ntohs(tvb, offset);
    offset += 2;

    sti = proto_tree_add_item(ancp_tree, hf_ancp_blk_len,       tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (tech_type == TECH_TYPE_DSL || tech_type == TECH_TYPE_PON) {
        proto_tree *tlv_tree;

        /* Create a TLV sub tree */
        tlv_tree = proto_item_add_subtree(sti, ett_ancp_len);

        for( ;num_tlvs; num_tlvs--) {
            offset = dissect_ancp_tlv(tvb, tlv_tree, offset);
        } /* end for {numtlvs} */
    } /* end if {DSL} */
}

static void
dissect_ancp_adj_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ancp_tree,
                     gint offset, struct ancp_tap_t *ancp_info
)
{
    proto_item *sti;
    proto_tree *ancp_cap_tree;
    guint8      byte, numcaps, adjcode;
    guint16     tlv_len;

    sti = proto_tree_add_item(ancp_tree, hf_ancp_timer, tvb, offset, 1,
            ENC_BIG_ENDIAN);
    offset += 1;
    proto_item_append_text(sti, " msec");

    sti = proto_tree_add_item(ancp_tree, hf_ancp_adj_code, tvb, offset, 1,
            ENC_BIG_ENDIAN);
    byte = tvb_get_guint8(tvb, offset);
    offset += 1;
    adjcode = byte & ADJ_CODE_MASK;
    ancp_info->ancp_adjcode = adjcode; /* stats */
    proto_item_append_text(sti, " (%s, M Flag %s)",
            val_to_str(adjcode, adj_code_names, "Unknown (0x%02x)"),
            (byte >> 7) ? "Set" : "Unset");
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
            val_to_str(adjcode, adj_code_names, "Unknown (0x%02x)"));

    proto_tree_add_item(ancp_tree, hf_ancp_sender_name, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(ancp_tree, hf_ancp_receiver_name, tvb,offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(ancp_tree, hf_ancp_sender_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(ancp_tree, hf_ancp_receiver_port, tvb,offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    sti = proto_tree_add_item(ancp_tree, hf_ancp_p_info, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    byte = tvb_get_guint8(tvb, offset);
    offset += 1;
    proto_item_append_text(sti, " (Type = %d, Flag = %d)",
            byte >> 4, byte & 0x0F);

    proto_tree_add_item(ancp_tree, hf_ancp_sender_instance, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(ancp_tree, hf_ancp_p_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(ancp_tree, hf_ancp_receiver_instance, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(ancp_tree, hf_ancp_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    sti = proto_tree_add_item(ancp_tree, hf_ancp_num_tlvs, tvb, offset, 1, ENC_BIG_ENDIAN);
    numcaps = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* Start the capability subtree */
    ancp_cap_tree = proto_item_add_subtree(sti, ett_ancp_tot_len);

    proto_tree_add_item(ancp_cap_tree, hf_ancp_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for ( ;numcaps; numcaps--) {
        sti = proto_tree_add_item(ancp_cap_tree, hf_ancp_cap, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        tlv_len = tvb_get_ntohs(tvb, offset);
        offset += 2;
        proto_item_append_text(sti, " (%d bytes)", tlv_len);
        /* TODO - if there are non boolean caps, validate before use */
    }
}

static void
ancp_stats_tree_init(stats_tree *st)
{
    st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, TRUE);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types,
            st_node_packets);
    st_node_adj_pack_types = stats_tree_create_node(st, st_str_adj_pack_types,
            st_node_packets, STAT_DT_INT, TRUE);
}

static tap_packet_status
ancp_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
                       epan_dissect_t* edt _U_ , const void* p, tap_flags_t flags _U_)
{
    const struct ancp_tap_t *pi = (const struct ancp_tap_t *) p;

    tick_stat_node(st, st_str_packets, 0, FALSE);
    stats_tree_tick_pivot(st, st_node_packet_types,
            val_to_str(pi->ancp_mtype, mtype_names,
                "Unknown packet type (%d)"));
    if (pi->ancp_mtype == ANCP_MTYPE_ADJ)
        stats_tree_tick_pivot(st, st_node_adj_pack_types,
                val_to_str(pi->ancp_adjcode, adj_code_names,
                    "Unknown Adjacency packet (%d)"));
    return TAP_PACKET_REDRAW;
}

static int
dissect_ancp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint               offset;
    guint8             mtype;
    struct ancp_tap_t *ancp_info;
    proto_item        *ti;
    proto_item        *sti;
    proto_item        *tti = NULL;
    proto_tree        *ancp_tree;
    proto_tree        *tlv_tree;
    guint8             byte;
    guint16            len;

    offset = 0;
    if (tvb_get_ntohs(tvb, offset) != ANCP_GSMP_ETHER_TYPE)
        return 0; /* XXX: this dissector is not a heuristic dissector */
                /* Should do "expert" & dissect rest as "data"      */
                /*  (after setting COL_PROTOCOL & etc) ?            */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANCP");
    col_clear(pinfo->cinfo, COL_INFO);

    ancp_info = wmem_new(pinfo->pool, struct ancp_tap_t);
    ancp_info->ancp_mtype   = 0;
    ancp_info->ancp_adjcode = 0;

    ti = proto_tree_add_item(tree, proto_ancp, tvb, 0, -1, ENC_NA);

    ancp_tree = proto_item_add_subtree(ti, ett_ancp_len);

    offset = 2; /* skip ether type */

    proto_tree_add_item(ancp_tree, hf_ancp_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    len = tvb_get_ntohs(tvb, offset);
    offset += 2;

    sti  = proto_tree_add_item(ancp_tree, hf_ancp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
    byte = tvb_get_guint8(tvb, offset);
    offset += 1;
    proto_item_append_text(sti, " (%d.%d)", byte >> 4, byte & 0x0F);

    sti = proto_tree_add_item(ancp_tree, hf_ancp_mtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    mtype = tvb_get_guint8(tvb, offset); /* ANCP message type */
    ancp_info->ancp_mtype = mtype; /* stats */
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Message",
                 val_to_str(mtype, mtype_names, "Unknown (0x%02x)"));

    if (mtype != ANCP_MTYPE_ADJ) {
        /* Dissect common header */
        proto_tree_add_item(ancp_tree, hf_ancp_result, tvb, offset, 1,
                            ENC_BIG_ENDIAN); /* treat as 1B, but don't change offset */

        proto_tree_add_item(ancp_tree, hf_ancp_code, tvb, offset, 2,
                            ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(ancp_tree, hf_ancp_p_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(ancp_tree, hf_ancp_trans_id, tvb,
                            offset, 3, ENC_BIG_ENDIAN);
        offset += 3;

        proto_tree_add_item(ancp_tree, hf_ancp_i_flag, tvb, offset, 1,
                            ENC_BIG_ENDIAN); /* treat as 1B, but don't change offset */

        proto_tree_add_item(ancp_tree, hf_ancp_submsg_num, tvb,
                                  offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        tti = proto_tree_add_item(ancp_tree, hf_ancp_len2, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset += 2; /* Length */
    }

    switch(mtype) {
    case ANCP_MTYPE_ADJ:
        dissect_ancp_adj_msg(tvb, pinfo, ancp_tree, offset, ancp_info);
        break;
    case ANCP_MTYPE_PORT_DN:
        /* FALL THRU */
    case ANCP_MTYPE_PORT_MGMT:
        /* FALL THRU */
    case ANCP_MTYPE_PORT_UP:
        dissect_ancp_port_up_dn_mgmt(tvb, ancp_tree, offset, mtype);
        break;
    case ANCP_MTYPE_PROV:
        /* FALL THRU */
    case ANCP_MTYPE_GEN_RSP:
        tlv_tree = proto_item_add_subtree(tti, ett_ancp_len);

        while( offset < len + 4) {
            offset = dissect_ancp_tlv(tvb, tlv_tree, offset);
        }
        break;
    case ANCP_MTYPE_ADJ_UPD:
        break;
    default:
        proto_item_append_text(sti, " (Unknown Message %d)", mtype);
        break;
    }
    tap_queue_packet(ancp_tap, pinfo, ancp_info);

    return tvb_reported_length(tvb);
}

static guint
get_ancp_msg_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint)tvb_get_ntohs(tvb, offset + 2) + 4; /* 2B len + 4B hdr */
}

static int
dissect_ancp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, ANCP_MIN_HDR,
            get_ancp_msg_len, dissect_ancp_message, data);

    return tvb_reported_length(tvb);
}

void
proto_register_ancp(void)
{
    static hf_register_info hf[] = {
        { &hf_ancp_len,
            { "Length", "ancp.len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_len2,
            { "Length", "ancp.len2",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_ver,
            { "Version", "ancp.ver",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_mtype,
            { "Message Type", "ancp.mtype",
                FT_UINT8, BASE_DEC,
                VALS(mtype_names), 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_timer,
            { "Timer", "ancp.timer",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
                &units_milliseconds, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_adj_code,
            { "Code", "ancp.adjcode", /* this is diff from code */
                FT_UINT8, BASE_DEC,   /* for Adjacency msg only */
                NULL, ADJ_CODE_MASK,
                NULL, HFILL }
        },
        { &hf_ancp_sender_name,
            { "Sender Name", "ancp.sender_name",
                FT_ETHER, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_receiver_name,
            { "Receiver Name", "ancp.receiver_name",
                FT_ETHER, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_sender_port,
            { "Sender Port", "ancp.sender_port",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_receiver_port,
            { "Receiver Port", "ancp.receiver_port",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_p_info,
            { "Partition Info", "ancp.partition_info",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_sender_instance,
            { "Sender Instance", "ancp.sender_instance",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_p_id,
            { "Partition ID", "ancp.partition_id",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_receiver_instance,
            { "Receiver Instance", "ancp.receiver_instance",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_tech_type,
            { "Tech Type", "ancp.tech_type",
                FT_UINT8, BASE_DEC,
                VALS(techtype_str), 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_num_tlvs,
            { "Num TLVs", "ancp.num_tlvs",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_tot_len,
            { "Length", "ancp.tot_len", /* name just Len to reuse*/
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_cap,
            { "Capability", "ancp.capability",
                FT_UINT16, BASE_DEC,
                VALS(captype_names), 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_result,
            { "Result", "ancp.result",
                FT_UINT8, BASE_DEC,
                VALS(resulttype_names), ANCP_RESULT_MASK,
                NULL, HFILL }
        },
        { &hf_ancp_code,
            { "Code", "ancp.code",
                FT_UINT16, BASE_HEX,
                VALS(codetype_names), ANCP_CODE_MASK,
                NULL, HFILL }
        },
        { &hf_ancp_trans_id,
            { "Transaction ID", "ancp.transaction_id",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_i_flag,
            { "I Flag", "ancp.i_flag",
                FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), ANCP_I_FLAG_MASK,
                NULL, HFILL }
        },
        { &hf_ancp_submsg_num,
            { "SubMessage Number", "ancp.submessage_number",
                FT_UINT16, BASE_DEC,
                NULL, ANCP_SUBMSG_MASK,
                NULL, HFILL }
        },
        { &hf_ancp_pudm_unused,
            { "Unused Bytes", "ancp.unused",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_function,
            { "Function", "ancp.function",
                FT_UINT8, BASE_DEC,
                VALS(function_names), 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_x_function,
            { "X-Function", "ancp.x_function",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_ext_flags_res,
            { "Extension Flags Reserved", "ancp.ext_flags",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_reserved,
            { "Reserved", "ancp.reserved",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_blk_len,
            { "Block Length", "ancp.blk_len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_num_ext_tlvs,
            { "Num TLVs", "ancp.ext_tlvs.count",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_ext_tlv_type,
            { "TLV Type", "ancp.ext_tlv.type",
                FT_UINT16, BASE_DEC|BASE_EXT_STRING,
                &ext_tlv_types_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_ext_tlv_len,
            { "TLV Length", "ancp.ext_tlv.len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_dsl_line_stlv_type,
            { "Sub-TLV", "ancp.sub_tlv_type",
                FT_UINT16, BASE_HEX,
                VALS(dsl_line_attrs), 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_dsl_line_stlv_len,
            { "Sub-TLV Length", "ancp.sub_tlv_len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_dsl_line_stlv_value,
            { "Value", "ancp.dsl_line_param",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_ext_tlv_value_str,
            { "Value", "ancp.ext_tlv.value",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_oam_opaque,
            { "Opaque", "ancp.oam.opaque", /* There will be 2 such 32b vals */
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_oam_loopb_cnt,
            { "OAM Loopback Count", "ancp.oam.loopback_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_oam_timeout,
            { "OAM Timeout", "ancp.oam.timeout",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ancp_len,
        &ett_ancp_ver,
        &ett_ancp_mtype,
        &ett_ancp_timer,
        &ett_ancp_adj_code,
        &ett_ancp_sender_name,
        &ett_ancp_receiver_name,
        &ett_ancp_sender_port,
        &ett_ancp_receiver_port,
        &ett_ancp_p_info,
        &ett_ancp_sender_instance,
        &ett_ancp_p_id,
        &ett_ancp_receiver_instance,
        &ett_ancp_tech_type,
        &ett_ancp_num_tlvs,
        &ett_ancp_tot_len,
        &ett_ancp_cap,
        &ett_ancp_result,
        &ett_ancp_code,
        &ett_ancp_trans_id,
        &ett_ancp_i_flag,
        &ett_ancp_submsg_num,
        &ett_ancp_port,
        &ett_ancp_port_sess_num,
        &ett_ancp_evt_seq_num,
        &ett_ancp_label,
        &ett_ancp_reserved,
        &ett_ancp_blk_len,
        &ett_ancp_num_ext_tlvs,
        &ett_ancp_ext_tlv_type,
        &ett_ancp_dsl_line_stlv_type,
        &ett_ancp_dsl_line_stlv_val,
        &ett_ancp_ext_tlv_value_str,
        &ett_ancp_oam_opaque,
        &ett_ancp_oam_loopb_cnt,
        &ett_ancp_oam_timeout,
    };

    proto_ancp = proto_register_protocol (
            "Access Node Control Protocol",
            "ANCP",
            "ancp"
            );

    proto_register_field_array(proto_ancp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    ancp_tap = register_tap("ancp");
}

void
proto_reg_handoff_ancp(void)
{
    dissector_handle_t ancp_handle;

    ancp_handle = create_dissector_handle(dissect_ancp, proto_ancp);
    dissector_add_uint_with_preference("tcp.port", ANCP_PORT, ancp_handle);
    stats_tree_register("ancp", "ancp", "ANCP", 0,
            ancp_stats_tree_packet, ancp_stats_tree_init, NULL);
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
