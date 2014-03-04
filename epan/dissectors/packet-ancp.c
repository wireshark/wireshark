/* packet-ancp.c
 *
 * Dissector for ANCP - Access Node Control Protocol
 *
 * More info on the protocol can be found on IETF:
 * http://tools.ietf.org/wg/ancp/
 * http://tools.ietf.org/html/draft-ietf-ancp-protocol-09
 *
 * Copyright 2010, Aniruddha.A (anira@cisco.com)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>

#define ANCP_PORT 6068 /* The ANCP TCP port:draft-ietf-ancp-protocol-09.txt */

#define ANCP_MIN_HDR  4
#define ANCP_GSMP_ETHER_TYPE  0x880C
#define TECH_TYPE_DSL         0x5

#define ANCP_RESULT_MASK     0xF0
#define ANCP_CODE_MASK       0x0FFF
#define ANCP_I_FLAG_MASK     0x80
#define ANCP_SUBMSG_MASK     0x7FFF
#define ADJ_CODE_MASK        0x7F /* excluding MSB M-Flag */

#define ANCP_MTYPE_ADJ       10
#define ANCP_MTYPE_PORT_MGMT 32
#define ANCP_MTYPE_PORT_UP   80
#define ANCP_MTYPE_PORT_DN   81

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
static int hf_ancp_port = -1;
static int hf_ancp_port_sess_num = -1;
static int hf_ancp_evt_seq_num = -1;
static int hf_ancp_label = -1;
static int hf_ancp_reserved = -1;
static int hf_ancp_blk_len = -1;
static int hf_ancp_num_ext_tlvs = -1;
static int hf_ancp_ext_tlv_type = -1;
static int hf_ancp_dsl_line_stlv_type = -1;
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

static const value_string codetype_names[] = { /* For now, these are OAM codes*/
    { 0x500, "Access-line-doesn't-exist" },
    { 0x501, "Loopback-Test-Timeout" },
    { 0x502, "Reserved" },
    { 0x503, "DSL-line-status-showtime" },
    { 0x504, "DSL-line-status-idle" },
    { 0x505, "DSL-line-status-silent" },
    { 0x506, "DSL-line-status-training" },
    { 0x507, "DSL-line-integrity-error" },
    { 0x508, "DSLAM resource-unavailable" },
    { 0x509, "Invalid Test Parameter" },
    { 0,  NULL }
};

static const value_string techtype_str[] = {
    { 0x01,  "PON" },
    { 0x05,  "DSL" },
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

static const value_string ext_tlv_types[] = {
    { 0x01, "Access-Loop-Circuit-ID" },
    { 0x02, "Access-Loop-Remote-ID" },
    { 0x03, "Access-Aggregation-Circuit-ID-ASCII" },
    { 0x04, "DSL Line Attributes" },
    { 0x06, "Access-Aggregation-Circuit-ID-Binary" },
    { 0x07, "OAM-Loopback-Test-Parameters" },
    { 0x08, "Opaque-Data" },
    { 0x09, "OAM-Loopback-Test-Response-String" },
    { 0,  NULL }
};

static void
dissect_ancp_port_up_dn_mgmt(tvbuff_t *tvb, proto_tree *ancp_tree, gint offset)
{
    guint8 tech_type;

    proto_tree_add_item(ancp_tree, hf_ancp_port,          tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(ancp_tree, hf_ancp_port_sess_num, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(ancp_tree, hf_ancp_evt_seq_num,   tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(ancp_tree, hf_ancp_label,         tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Start of the Extension Block */
    proto_tree_add_item(ancp_tree, hf_ancp_reserved,      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /*
     * We have already displayed the message type in the common header dissect
     * so need not display this again here - skip it
     */
    offset += 1; /* Message type in Ext Blk */

    proto_tree_add_item(ancp_tree, hf_ancp_tech_type,     tvb, offset, 1, ENC_BIG_ENDIAN);
    tech_type = tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(ancp_tree, hf_ancp_blk_len,       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (tech_type == TECH_TYPE_DSL) {
        proto_item *sti;
        proto_tree *tlv_tree;
        guint16     tlen, ttype;
        gint16      num_tlvs, num_stlvs;

        proto_tree_add_item(ancp_tree, hf_ancp_num_ext_tlvs, tvb, offset, 2, ENC_BIG_ENDIAN);
        num_tlvs = tvb_get_ntohs(tvb, offset);
        offset += 2;

        sti = proto_tree_add_item(ancp_tree, hf_ancp_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(sti, " (Extension Block)");
        offset += 2;

        /* Create a TLV sub tree */
        tlv_tree = proto_item_add_subtree(sti, ett_ancp_len);

        for( ;num_tlvs; num_tlvs--) {
            proto_tree_add_item(tlv_tree, hf_ancp_ext_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            ttype = tvb_get_ntohs(tvb, offset);
            offset += 2;

            sti = proto_tree_add_item(tlv_tree, hf_ancp_len, tvb, offset, 2, ENC_BIG_ENDIAN);
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
                    dsl_tree = proto_item_add_subtree(sti, ett_ancp_ext_tlv_type);
                    num_stlvs = tlen / 8; /* TODO - better way? */
                    for ( ;num_stlvs; num_stlvs--) {
                        proto_tree_add_item(dsl_tree,
                                hf_ancp_dsl_line_stlv_type, tvb, offset,
                                2, ENC_BIG_ENDIAN);
                        stlvtype = tvb_get_ntohs(tvb, offset);
                        offset += 2;
                        /* Skip sub-tlv-len display for now */
                        stlvlen = tvb_get_ntohs(tvb, offset);
                        offset += 2; /* Sub TLV Length */

                        sti = proto_tree_add_item(dsl_tree,
                                hf_ancp_dsl_line_stlv_value, tvb, offset,
                                stlvlen, ENC_BIG_ENDIAN);
                        val = tvb_get_ntohl(tvb, offset);
                        offset += stlvlen; /* Except loop-encap, rest are 4B */

                        switch (stlvtype) {
                            case TLV_DSL_LINE_STATE:
                                proto_item_append_text(sti, " (%s)",
                                        val_to_str(val, dsl_line_state_names,
                                            "Unknown (0x%02x)"));
                                break;
                            case TLV_DSL_TYPE:
                                proto_item_append_text(sti, " (%s)",
                                        val_to_str(val, dsl_line_type_names,
                                            "Unknown (0x%02x)"));
                                break;

                            default:
                                /* Add Unit */
                                proto_item_append_text(sti, " %s",
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
                            tvb, offset, tlen, ENC_ASCII|ENC_NA);
                    offset += tlen;
                    SKIPPADDING(offset, tlen);
                    break;
            } /* end switch {ttype} */
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

    proto_tree_add_item(ancp_tree, hf_ancp_tech_type, tvb, offset, 1, ENC_BIG_ENDIAN);
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
    st_node_packets = stats_tree_create_node(st, st_str_packets, 0, TRUE);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types,
            st_node_packets);
    st_node_adj_pack_types = stats_tree_create_node(st, st_str_adj_pack_types,
            st_node_packets, TRUE);
}

static int
ancp_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
                       epan_dissect_t* edt _U_ , const void* p)
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
    return 1;
}

static int
dissect_ancp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint               offset;
    guint8             mtype;
    struct ancp_tap_t *ancp_info;
    proto_item        *ti;
    proto_item        *sti;
    proto_tree        *ancp_tree;
    guint8             byte;

    offset = 0;
    if (tvb_get_ntohs(tvb, offset) != ANCP_GSMP_ETHER_TYPE)
        return 0; /* XXX: this dissector is not a heuristic dissector */
                /* Should do "expert" & dissect rest as "data"      */
                /*  (after setting COL_PROTOCOL & etc) ?            */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANCP");
    col_clear(pinfo->cinfo, COL_INFO);

    ancp_info = wmem_new(wmem_packet_scope(), struct ancp_tap_t);
    ancp_info->ancp_mtype   = 0;
    ancp_info->ancp_adjcode = 0;

    ti = proto_tree_add_item(tree, proto_ancp, tvb, 0, -1, ENC_NA);

    ancp_tree = proto_item_add_subtree(ti, ett_ancp_len);

    offset = 2; /* skip ether type */

    proto_tree_add_item(ancp_tree, hf_ancp_len, tvb, offset, 2, ENC_BIG_ENDIAN);
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
                            ENC_BIG_ENDIAN); /* treat as 1B, but dont change offset */

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
                            ENC_BIG_ENDIAN); /* treat as 1B, but dont change offset */

        sti = proto_tree_add_item(ancp_tree, hf_ancp_submsg_num, tvb,
                                  offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /*
         * Lets not display the 'Length' field now, it is anyway same
         * as GSMP Length
         * which we have already displayed at the start of the dissect
         */
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
        dissect_ancp_port_up_dn_mgmt(tvb, ancp_tree, offset);
        break;
    default:
        proto_item_append_text(sti, " (Unknown Message %d)", mtype);
        break;
    }
    tap_queue_packet(ancp_tap, pinfo, ancp_info);

    return tvb_length(tvb);
}

static guint
get_ancp_msg_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return (guint)tvb_get_ntohs(tvb, offset + 2) + 4; /* 2B len + 4B hdr */
}

static int
dissect_ancp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, ANCP_MIN_HDR,
            get_ancp_msg_len, dissect_ancp_message, data);

    return tvb_length(tvb);
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
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
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
        { &hf_ancp_port,
            { "Port", "ancp.port",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_port_sess_num,
            { "Port Session Number", "ancp.port_sess_num",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_evt_seq_num,
            { "Event Sequence Number", "ancp.evt_seq_num",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_label,
            { "Label", "ancp.label", /* Not used in proto */
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_reserved,
            { "Reserved", "ancp.reserved",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_blk_len,
            { "Block Length", "ancp.blk_len",
                FT_UINT8, BASE_DEC,
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
            { "TLV", "ancp.ext_tlv.type",
                FT_UINT16, BASE_DEC,
                VALS(ext_tlv_types), 0x0,
                NULL, HFILL }
        },
        { &hf_ancp_dsl_line_stlv_type,
            { "Sub-TLV", "ancp.sub_tlv_type",
                FT_UINT16, BASE_HEX,
                VALS(dsl_line_attrs), 0x0,
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

    ancp_handle = new_create_dissector_handle(dissect_ancp, proto_ancp);
    dissector_add_uint("tcp.port", ANCP_PORT, ancp_handle);
    stats_tree_register("ancp", "ancp", "ANCP", 0,
            ancp_stats_tree_packet, ancp_stats_tree_init, NULL);
}

