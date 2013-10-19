/* packet-openflow.c
 * Routines for OpenFlow dissection
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 *
 * Ref https://www.opennetworking.org/sdn-resources/onf-specifications/openflow
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>

void proto_reg_handoff_openflow_v4(void);
static int proto_openflow_v4 = -1;
static int hf_openflow_v4_version = -1;
static int hf_openflow_v4_type = -1;
static int hf_openflow_v4_length = -1;
static int hf_openflow_v4_xid = -1;
static int hf_openflow_v4_oxm_class = -1;
static int hf_openflow_v4_oxm_field = -1;
static int hf_openflow_v4_oxm_field_basic = -1;
static int hf_openflow_v4_oxm_hm = -1;
static int hf_openflow_v4_oxm_length = -1;
static int hf_openflow_v4_oxm_value = -1;
static int hf_openflow_v4_oxm_mask = -1;
static int hf_openflow_v4_match_type = -1;
static int hf_openflow_v4_match_length = -1;
static int hf_openflow_v4_match_pad = -1;
static int hf_openflow_v4_instruction_type = -1;
static int hf_openflow_v4_instruction_length = -1;
static int hf_openflow_v4_instruction_goto_table_table_id = -1;
static int hf_openflow_v4_instruction_goto_table_pad = -1;
static int hf_openflow_v4_instruction_write_metadata_pad = -1;
static int hf_openflow_v4_instruction_write_metadata_value = -1;
static int hf_openflow_v4_instruction_write_metadata_mask = -1;
static int hf_openflow_v4_instruction_actions_pad = -1;
static int hf_openflow_v4_instruction_meter_meter_id = -1;
static int hf_openflow_v4_instruction_meter_meter_id_reserved = -1;
static int hf_openflow_v4_datapath_id = -1;
static int hf_openflow_datapath_v4_mac = -1;
static int hf_openflow_v4_datapath_impl = -1;
static int hf_openflow_v4_n_buffers = -1;
static int hf_openflow_v4_n_tables = -1;
static int hf_openflow_v4_auxiliary_id = -1;
static int hf_openflow_v4_padd16 = -1;
static int hf_openflow_v4_padd32 = -1;
static int hf_openflow_v4_capabilities = -1;
static int hf_openflow_v4_cap_flow_stats = -1;
static int hf_openflow_v4_table_stats = -1;
static int hf_openflow_v4_port_stats = -1;
static int hf_openflow_v4_group_stats = -1;
static int hf_openflow__v4_ip_reasm = -1;
static int hf_openflow_v4_queue_stats = -1;
static int hf_openflow_v4_port_blocked = -1;
static int hf_openflow_v4_flowmod_cookie = -1;
static int hf_openflow_v4_flowmod_cookie_mask = -1;
static int hf_openflow_v4_flowmod_table_id = -1;
static int hf_openflow_v4_flowmod_table_id_reserved = -1;
static int hf_openflow_v4_flowmod_command = -1;
static int hf_openflow_v4_flowmod_idle_timeout = -1;
static int hf_openflow_v4_flowmod_hard_timeout = -1;
static int hf_openflow_v4_flowmod_priority = -1;
static int hf_openflow_v4_flowmod_buffer_id = -1;
static int hf_openflow_v4_flowmod_buffer_id_reserved = -1;
static int hf_openflow_v4_flowmod_out_port = -1;
static int hf_openflow_v4_flowmod_out_port_reserved = -1;
static int hf_openflow_v4_flowmod_out_group = -1;
static int hf_openflow_v4_flowmod_out_group_reserved = -1;
static int hf_openflow_v4_flowmod_flags = -1;
static int hf_openflow_v4_flowmod_flags_send_flow_rem = -1;
static int hf_openflow_v4_flowmod_flags_check_overlap = -1;
static int hf_openflow_v4_flowmod_flags_reset_counts = -1;
static int hf_openflow_v4_flowmod_flags_no_packet_counts = -1;
static int hf_openflow_v4_flowmod_flags_no_byte_counts = -1;
static int hf_openflow_v4_flowmod_pad = -1;
static int hf_openflow_v4_multipart_type = -1;
static int hf_openflow_v4_multipart_request_flags = -1;
static int hf_openflow_v4_multipart_reply_flags = -1;

static gint ett_openflow_v4 = -1;
static gint ett_openflow_v4_path_id = -1;
static gint ett_openflow_v4_cap = -1;
static gint ett_openflow_v4_flowmod_flags = -1;
static gint ett_openflow_v4_flowmod_instructions = -1;
static gint ett_openflow_v4_oxm = -1;
static gint ett_openflow_v4_match = -1;
static gint ett_openflow_v4_match_oxm_fields = -1;
static gint ett_openflow_v4_instruction = -1;
static gint ett_openflow_v4_instruction_actions_actions = -1;

static expert_field ei_openflow_v4_match_undecoded = EI_INIT;
static expert_field ei_openflow_v4_instruction_undecoded = EI_INIT;

static const value_string openflow_v4_version_values[] = {
    { 0x01, "1.0" },
    { 0x02, "1.1" },
    { 0x03, "1.2" },
    { 0x04, "1.3.1" },
    { 0, NULL }
};

/* Immutable messages. */
#define OFPT_V4_HELLO                     0 /* Symmetric message */
#define OFPT_V4_ERROR                     1 /* Symmetric message */
#define OFPT_V4_ECHO_REQUEST              2 /* Symmetric message */
#define OFPT_V4_ECHO_REPLY                3 /* Symmetric message */
#define OFPT_V4_EXPERIMENTER              4 /* Symmetric message */
/* Switch configuration messages. */
#define OFPT_V4_FEATURES_REQUEST          5 /* Controller/switch message */
#define OFPT_V4_FEATURES_REPLY            6 /* Controller/switch message */
#define OFPT_V4_GET_CONFIG_REQUEST        7 /* Controller/switch message */
#define OFPT_V4_GET_CONFIG_REPLY          8 /* Controller/switch message */
#define OFPT_V4_SET_CONFIG                9 /* Controller/switch message */
/* Asynchronous messages. */
#define OFPT_V4_PACKET_IN                10 /* Async message */
#define OFPT_V4_FLOW_REMOVED             11 /* Async message */
#define OFPT_V4_PORT_STATUS              12 /* Async message */
/* Controller command messages. */
#define OFPT_V4_PACKET_OUT               13 /* Controller/switch message */
#define OFPT_V4_FLOW_MOD                 14 /* Controller/switch message */
#define OFPT_V4_GROUP_MOD                15 /* Controller/switch message */
#define OFPT_V4_PORT_MOD                 16 /* Controller/switch message */
#define OFPT_V4_TABLE_MOD                17 /* Controller/switch message */
/* Multipart messages. */
#define OFPT_V4_MULTIPART_REQUEST        18 /* Controller/switch message */
#define OFPT_V4_MULTIPART_REPLY          19 /* Controller/switch message */
/* Barrier messages. */
#define OFPT_V4_BARRIER_REQUEST          20 /* Controller/switch message */
#define OFPT_V4_BARRIER_REPLY            21 /* Controller/switch message */
/* Queue Configuration messages. */
#define OFPT_V4_QUEUE_GET_CONFIG_REQUEST 22 /* Controller/switch message */
#define OFPT_V4_QUEUE_GET_CONFIG_REPLY   23 /* Controller/switch message */
/* Controller role change request messages. */
#define OFPT_V4_ROLE_REQUEST             24 /* Controller/switch message */
#define OFPT_V4_ROLE_REPLY               25 /* Controller/switch message */
/* Asynchronous message configuration. */
#define OFPT_V4_GET_ASYNC_REQUEST        26 /* Controller/switch message */
#define OFPT_V4_GET_ASYNC_REPLY          27 /* Controller/switch message */
#define OFPT_V4_SET_ASYNC                28 /* Controller/switch message */
/* Meters and rate limiters configuration messages. */
#define OFPT_V4_METER_MOD                29 /* Controller/switch message */

static const value_string openflow_v4_type_values[] = {
/* Immutable messages. */
    { 0, "OFPT_HELLO" },              /* Symmetric message */
    { 1, "OFPT_ERROR" },              /* Symmetric message */
    { 2, "OFPT_ECHO_REQUEST" },       /* Symmetric message */
    { 3, "OFPT_ECHO_REPLY" },         /* Symmetric message */
    { 4, "OFPT_EXPERIMENTER" },       /* Symmetric message */
/* Switch configuration messages. */
    { 5, "OFPT_FEATURES_REQUEST" },   /* Controller/switch message */
    { 6, "OFPT_FEATURES_REPLY" },     /* Controller/switch message */
    { 7, "OFPT_GET_CONFIG_REQUEST" }, /* Controller/switch message */
    { 8, "OFPT_GET_CONFIG_REPLY" },   /* Controller/switch message */
    { 9, "OFPT_SET_CONFIG" },         /* Controller/switch message */
/* Asynchronous messages. */
    { 10, "OFPT_PACKET_IN" },                /* Async message */
    { 11, "OFPT_FLOW_REMOVED" },             /* Async message */
    { 12, "OFPT_PORT_STATUS" },              /* Async message */
/* Controller command messages. */
    { 13, "OFPT_PACKET_OUT" },               /* Controller/switch message */
    { 14, "OFPT_FLOW_MOD" },                 /* Controller/switch message */
    { 15, "OFPT_GROUP_MOD" },                /* Controller/switch message */
    { 16, "OFPT_PORT_MOD" },                 /* Controller/switch message */
    { 17, "OFPT_TABLE_MOD" },                /* Controller/switch message */
/* Multipart messages. */
    { 18, "OFPT_MULTIPART_REQUEST" },        /* Controller/switch message */
    { 19, "OFPT_MULTIPART_REPLY" },          /* Controller/switch message */
/* Barrier messages. */
    { 20, "OFPT_BARRIER_REQUEST" },          /* Controller/switch message */
    { 21, "OFPT_BARRIER_REPLY" },            /* Controller/switch message */
/* Queue Configuration messages. */
    { 22, "OFPT_QUEUE_GET_CONFIG_REQUEST" }, /* Controller/switch message */
    { 23, "OFPT_QUEUE_GET_CONFIG_REPLY" },   /* Controller/switch message */
/* Controller role change request messages. */
    { 24, "OFPT_ROLE_REQUEST" },             /* Controller/switch message */
    { 25, "OFPT_ROLE_REPLY" },               /* Controller/switch message */
/* Asynchronous message configuration. */
    { 26, "OFPT_GET_ASYNC_REQUEST" },        /* Controller/switch message */
    { 27, "OFPT_GET_ASYNC_REPLY" },          /* Controller/switch message */
    { 28, "OFPT_SET_ASYNC" },                /* Controller/switch message */
/* Meters and rate limiters configuration messages. */
    { 29, "OFPT_METER_MOD" },                /* Controller/switch message */
    { 0, NULL }
};

#define OFPP_MAX   0xffffff00  /* Last usable port number. */
static const value_string openflow_v4_port_reserved_values[] = {
    { 0xfffffff8, "OFPP_IN_PORT" },
    { 0xfffffff9, "OFPP_TABLE" },
    { 0xfffffffa, "OFPP_NORMAL" },
    { 0xfffffffb, "OFPP_FLOOD" },
    { 0xfffffffc, "OFPP_ALL" },
    { 0xfffffffd, "OFPP_CONTROLLER" },
    { 0xfffffffe, "OFPP_LOCAL" },
    { 0xffffffff, "OFPP_ANY" },
    { 0,          NULL }
};

#define OFPG_MAX   0xffffff00  /* Last usable group number. */
static const value_string openflow_v4_group_reserved_values[] = {
    { 0xfffffffc, "OFPG_ALL" },
    { 0xffffffff, "OFPG_ANY" },
    { 0,          NULL }
};

#define OFPTT_MAX  254    /* Last usable table number. */
static const value_string openflow_v4_table_reserved_values[] = {
    { 255, "OFPTT_ALL"},
    { 0,   NULL}
};


#define OFP_NO_BUFFER  0xffffffff    /* No buffering. */
static const value_string openflow_v4_buffer_reserved_values[] = {
    { 0xffffffff, "OFP_NO_BUFFER" },
    { 0,          NULL}
};

#define OFPXMC_NXM_0           0x0000  /* Backward compatibility with NXM */
#define OFPXMC_NXM_1           0x0001  /* Backward compatibility with NXM */
#define OFPXMC_OPENFLOW_BASIC  0x8000  /* Basic class for OpenFlow */
#define OFPXMC_EXPERIMENTER    0xFFFF  /* Experimenter class */
static const value_string openflow_v4_oxm_class_values[] = {
    { 0x0000, "OFPXMC_NMX_0" },
    { 0x0001, "OFPXMC_NXM_1" },
    { 0x8000, "OFPXMC_OPENFLOW_BASIC" },
    { 0xFFFF, "OFPXMC_EXPERIMENTER" },
    { 0,      NULL}
};

static const value_string openflow_v4_oxm_basic_field_values[] = {
    {  0, "OFPXMT_OFB_IN_PORT" },
    {  1, "OFPXMT_OFB_IN_PHY_PORT" },
    {  2, "OFPXMT_OFB_METADATA" },
    {  3, "OFPXMT_OFB_ETH_DST" },
    {  4, "OFPXMT_OFB_ETH_SRC" },
    {  5, "OFPXMT_OFB_ETH_TYPE" },
    {  6, "OFPXMT_OFB_VLAN_VID" },
    {  7, "OFPXMT_OFB_VLAN_PCP" },
    {  8, "OFPXMT_OFB_IP_DSCP" },
    {  9, "OFPXMT_OFB_IP_ECN" },
    { 10, "OFPXMT_OFB_IP_PROTO" },
    { 11, "OFPXMT_OFB_IPV4_SRC" },
    { 12, "OFPXMT_OFB_IPV4_DST" },
    { 13, "OFPXMT_OFB_TCP_SRC" },
    { 14, "OFPXMT_OFB_TCP_DST" },
    { 15, "OFPXMT_OFB_UDP_SRC" },
    { 16, "OFPXMT_OFB_UDP_DST" },
    { 17, "OFPXMT_OFB_SCTP_SRC" },
    { 18, "OFPXMT_OFB_SCTP_DST" },
    { 19, "OFPXMT_OFB_ICMPV4_TYPE" },
    { 20, "OFPXMT_OFB_ICMPV4_CODE" },
    { 21, "OFPXMT_OFB_ARP_OP" },
    { 22, "OFPXMT_OFB_ARP_SPA" },
    { 23, "OFPXMT_OFB_ARP_TPA" },
    { 24, "OFPXMT_OFB_ARP_SHA" },
    { 25, "OFPXMT_OFB_ARP_THA" },
    { 26, "OFPXMT_OFB_IPV6_SRC" },
    { 27, "OFPXMT_OFB_IPV6_DST" },
    { 28, "OFPXMT_OFB_IPV6_FLABEL" },
    { 29, "OFPXMT_OFB_ICMPV6_TYPE" },
    { 30, "OFPXMT_OFB_ICMPV6_CODE" },
    { 31, "OFPXMT_OFB_IPV6_ND_TARGET" },
    { 32, "OFPXMT_OFB_IPV6_ND_SLL" },
    { 33, "OFPXMT_OFB_IPV6_ND_TLL" },
    { 34, "OFPXMT_OFB_MPLS_LABEL" },
    { 35, "OFPXMT_OFB_MPLS_TC" },
    { 36, "OFPXMT_OFP_MPLS_BOS" },
    { 37, "OFPXMT_OFB_PBB_ISID" },
    { 38, "OFPXMT_OFB_TUNNEL_ID" },
    { 39, "OFPXMT_OFB_IPV6_EXTHDR" },
    {  0, NULL }
};

#define OXM_FIELD_MASK   0xfe
#define OXM_FIELD_OFFSET 1
#define OXM_HM_MASK      0x01
static int
dissect_openflow_oxm_header_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 oxm_class;

    /* oxm_class */
    oxm_class = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_oxm_class, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* oxm_field */
    if (oxm_class == OFPXMC_OPENFLOW_BASIC) {
        proto_tree_add_bits_item(tree, hf_openflow_v4_oxm_field_basic, tvb, (offset * 8), 7, ENC_NA);
    } else {
        proto_tree_add_bits_item(tree, hf_openflow_v4_oxm_field, tvb, (offset * 8), 7, ENC_NA);
    }

    /* oxm_hm */
    proto_tree_add_bits_item(tree, hf_openflow_v4_oxm_hm, tvb, (offset * 8) + 7, 1, ENC_NA);
    offset+=1;

    /* oxm_length */
    proto_tree_add_item(tree, hf_openflow_v4_oxm_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    return offset;
}

static int
dissect_openflow_oxm_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *oxm_tree;
    guint8  oxm_field_hm;
    guint8  oxm_hm;
    guint8  oxm_length;

    oxm_field_hm = tvb_get_guint8(tvb, offset + 2);
    oxm_length = tvb_get_guint8(tvb, offset + 3);

    ti = proto_tree_add_text(tree, tvb, offset, oxm_length + 4, "OXM");
    oxm_tree = proto_item_add_subtree(ti, ett_openflow_v4_oxm);

    offset = dissect_openflow_oxm_header_v4(tvb, pinfo, oxm_tree, offset, length);

    oxm_hm = oxm_field_hm & OXM_HM_MASK;
    if (oxm_hm != 0) {
        oxm_length /= 2;
    }

    /* value */
    if (oxm_length > 0) {
        proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value, tvb, offset, oxm_length, ENC_BIG_ENDIAN);
        offset += oxm_length;
    }

    /* mask */
    if (oxm_length > 0 && oxm_hm != 0) {
        proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask, tvb, offset, oxm_length, ENC_BIG_ENDIAN);
        offset += oxm_length;
    }

    return offset;
}

#define OFPMT_STANDARD  0  /* Standard Match. Deprecated. */
#define OFPMT_OXM       1  /* OpenFlow Extensible Match */
static const value_string openflow_v4_match_type_values[] = {
    { 0, "OFPMT_STANDARD" },
    { 1, "OFPMT_OXM" },
    { 0, NULL }
};

static int
dissect_openflow_match_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *match_tree, *fields_tree;
    guint16 match_type;
    guint16 match_length;
    guint16 fields_end;
    guint16 pad_length;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Match");
    match_tree = proto_item_add_subtree(ti, ett_openflow_v4_match);

    /* uint16_t type; */
    match_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(match_tree, hf_openflow_v4_match_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; (excluding padding) */
    match_length = tvb_get_ntohs(tvb, offset);
    pad_length = (match_length + 7)/8*8 - match_length;
    proto_item_set_len(ti, match_length + pad_length);
    proto_tree_add_item(match_tree, hf_openflow_v4_match_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* body */
    switch (match_type) {
    case OFPMT_STANDARD:
        proto_tree_add_expert_format(match_tree, pinfo, &ei_openflow_v4_match_undecoded,
                                     tvb, offset, match_length - 4, "Standard match (deprecated).");
        offset+=match_length-4;
        break;
    case OFPMT_OXM:
        ti = proto_tree_add_text(match_tree, tvb, offset, match_length - 4, "Fields");
        fields_tree = proto_item_add_subtree(ti, ett_openflow_v4_match_oxm_fields);

        fields_end = offset + match_length - 4;
        while(offset < fields_end) {
            offset = dissect_openflow_oxm_v4(tvb, pinfo, fields_tree, offset, length);
        }
        break;
    default:
        proto_tree_add_expert_format(match_tree, pinfo, &ei_openflow_v4_match_undecoded,
                                     tvb, offset, match_length - 4, "Unknown match.");
        offset+=match_length-4;
        break;
    }

    /* pad; Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of all-zero bytes. */
    if (pad_length > 0) {
        proto_tree_add_item(match_tree, hf_openflow_v4_match_pad, tvb, offset, pad_length, ENC_BIG_ENDIAN);
        offset+=pad_length;
    }

    return offset;
}


#define OFPC_V4_FLOW_STATS   1<<0  /* Flow statistics. */
#define OFPC_V4_TABLE_STATS  1<<1  /* Table statistics. */
#define OFPC_V4_PORT_STATS   1<<2  /* Port statistics. */
#define OFPC_V4_GROUP_STATS  1<<3  /* Group statistics. */
#define OFPC_V4_IP_REASM     1<<5  /* Can reassemble IP fragments. */
#define OFPC_V4_QUEUE_STATS  1<<6  /* Queue statistics. */
#define OFPC_V4_PORT_BLOCKED 1<<8  /* Switch will block looping ports. */

/* Switch features. /
struct ofp_switch_features {
    struct ofp_header header;
    uint64_t datapath_id; / Datapath unique ID. The lower 48-bits are for
    a MAC address, while the upper 16-bits are
    implementer-defined. /
    uint32_t n_buffers; / Max packets buffered at once. /
    uint8_t n_tables; / Number of tables supported by datapath. /
    uint8_t auxiliary_id; / Identify auxiliary connections /
    uint8_t pad[2]; / Align to 64-bits. /
    / Features. /
    uint32_t capabilities; / Bitmap of support "ofp_capabilities". /
    uint32_t reserved;
};
OFP_ASSERT(sizeof(struct ofp_switch_features) == 32);
*/


static void
dissect_openflow_features_reply_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *path_id_tree, *cap_tree;

    ti = proto_tree_add_item(tree, hf_openflow_v4_datapath_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    path_id_tree = proto_item_add_subtree(ti, ett_openflow_v4_path_id);
    proto_tree_add_item(path_id_tree, hf_openflow_datapath_v4_mac, tvb, offset, 6, ENC_NA);
    offset+=6;
    proto_tree_add_item(path_id_tree, hf_openflow_v4_datapath_impl, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_v4_n_buffers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Number of tables supported by datapath. */
    proto_tree_add_item(tree, hf_openflow_v4_n_tables, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Identify auxiliary connections */
    proto_tree_add_item(tree, hf_openflow_v4_auxiliary_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Align to 64-bits. */
    proto_tree_add_item(tree, hf_openflow_v4_padd16, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    ti = proto_tree_add_item(tree, hf_openflow_v4_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    cap_tree = proto_item_add_subtree(ti, ett_openflow_v4_cap);

    /* Dissect flags */
    proto_tree_add_item(cap_tree, hf_openflow_v4_cap_flow_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_table_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_port_stats,     tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_group_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow__v4_ip_reasm,       tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_queue_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_port_blocked,   tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    proto_tree_add_item(tree, hf_openflow_v4_padd32, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset+=4;*/

}

#define OFPIT_GOTO_TABLE      1       /* Setup the next table in the lookup */
#define OFPIT_WRITE_METADATA  2       /* Setup the metadata field for use later in */
#define OFPIT_WRITE_ACTIONS   3       /* Write the action(s) onto the datapath action */
#define OFPIT_APPLY_ACTIONS   4       /* Applies the action(s) immediately */
#define OFPIT_CLEAR_ACTIONS   5       /* Clears all actions from the datapath */
#define OFPIT_METER           6       /* Apply meter (rate limiter) */
#define OFPIT_EXPERIMENTER    0xFFFF  /* Experimenter instruction */
static const value_string openflow_v4_instruction_type_values[] = {
    { 0x0001, "OFPIT_GOTO_TABLE" },
    { 0x0002, "OFPIT_WRITE_METADATA" },
    { 0x0003, "OFPIT_WRITE_ACTIONS" },
    { 0x0004, "OFPIT_APPLY_ACTIONS" },
    { 0x0005, "OFPIT_CLEAR_ACTIONS" },
    { 0x0006, "OFPIT_METER" },
    { 0xffff, "OFPIT_EXPERIMENTER = 0xFFFF" },
    { 0,      NULL }
};

#define OFPM_MAX   0xffffff00  /* Last usable meter number. */
static const value_string openflow_v4_meter_id_reserved_values[] = {
    { 0xfffffffd, "OFPM_SLOWPATH" },
    { 0xfffffffe, "OFPM_CONTROLLER" },
    { 0xffffffff, "OFPM_ALL" },
    { 0,          NULL }
};

static int
dissect_openflow_instruction_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *inst_tree, *actions_tree;
    guint16 inst_type;
    guint16 inst_length;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Instruction");
    inst_tree = proto_item_add_subtree(ti, ett_openflow_v4_instruction);

    /* uint16_t type; */
    inst_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; */
    inst_length = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, inst_length);
    proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    switch (inst_type) {
    case OFPIT_GOTO_TABLE:
        /* uint8_t table_id; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_goto_table_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* uint8_t pad[3]; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_goto_table_pad, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
        break;

    case OFPIT_WRITE_METADATA:
        /* uint8_t pad[4]; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_write_metadata_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint64_t metadata; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_write_metadata_value, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset+=8;

        /* uint64_t metadata_mask; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_write_metadata_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset+=8;
        break;

    case OFPIT_WRITE_ACTIONS:
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_actions_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        ti = proto_tree_add_text(inst_tree, tvb, offset, inst_length - 8, "Actions");
        actions_tree = proto_item_add_subtree(ti, ett_openflow_v4_instruction_actions_actions);

        proto_tree_add_text(actions_tree, tvb, offset, 0, "Actions not dissected yet");
        offset += inst_length - 8;
        break;

    case OFPIT_APPLY_ACTIONS:
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_actions_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        ti = proto_tree_add_text(inst_tree, tvb, offset, inst_length - 8, "Actions");
        actions_tree = proto_item_add_subtree(ti, ett_openflow_v4_instruction_actions_actions);

        proto_tree_add_text(actions_tree, tvb, offset, 0, "Actions not dissected yet");
        offset += inst_length - 8;
        break;

    case OFPIT_CLEAR_ACTIONS:
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_actions_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPIT_METER:
        /* uint32_t meter_id; */
        if (tvb_get_ntohl(tvb, offset) <= OFPM_MAX) {
            proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_meter_meter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_meter_meter_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset+=4;
        break;

    case OFPIT_EXPERIMENTER:
        proto_tree_add_expert_format(inst_tree, pinfo, &ei_openflow_v4_instruction_undecoded,
                                     tvb, offset, inst_length - 4, "Experimenter instruction.");
        offset += inst_length - 4;
        break;

    default:
        proto_tree_add_expert_format(inst_tree, pinfo, &ei_openflow_v4_instruction_undecoded,
                                     tvb, offset, inst_length - 4, "Unknown instruction.");
        offset += inst_length - 4;
        break;
    }

    return offset;
}


static const value_string openflow_v4_flowmod_command_values[] = {
    { 0, "OFPFC_ADD" },
    { 1, "OFPFC_MODIFY" },
    { 2, "OFPFC_MODIFY_STRICT" },
    { 3, "OFPFC_DELETE" },
    { 4, "OFPFC_DELETE_STRICT" },
    { 0, NULL }
};

#define OFPFF_SEND_FLOW_REM  1 << 0  /* Send flow removed message when flow expires or is deleted. */
#define OFPFF_CHECK_OVERLAP  1 << 1  /* Check for overlapping entries first. */
#define OFPFF_RESET_COUNTS   1 << 2  /* Reset flow packet and byte counts. */
#define OFPFF_NO_PKT_COUNTS  1 << 3  /* Don't keep track of packet count. */
#define OFPFF_NO_BYT_COUNTS  1 << 4  /* Don't keep track of byte count. */

static void
dissect_openflow_flowmod_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *flags_tree, *instructions_tree;

    /* uint64_t cookie; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t cookie_mask; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_cookie_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint8_t table_id; */
    if (tvb_get_guint8(tvb, offset) <= OFPTT_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_table_id_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset+=1;

    /* uint8_t command; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_command, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint16_t idle_timeout; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_idle_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t hard_timeout; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_hard_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t priority; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t buffer_id; */
    if (tvb_get_ntohl(tvb, offset) != OFP_NO_BUFFER) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_buffer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_buffer_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t out_port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t out_group; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_group_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint16_t flags; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_flowmod_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_flowmod_flags);

    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_send_flow_rem, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_check_overlap, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_reset_counts,  tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_no_packet_counts, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_no_byte_counts, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[2]; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_pad, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* struct ofp_match match; */
    offset = dissect_openflow_match_v4(tvb, pinfo, tree, offset, length);

    /* struct ofp_instruction instructions[0]; */
    if (offset < length) {
        ti = proto_tree_add_text(tree, tvb, offset, length - offset, "Instructions");
        instructions_tree = proto_item_add_subtree(ti, ett_openflow_v4_flowmod_instructions);

        while (offset < length) {
            offset = dissect_openflow_instruction_v4(tvb, pinfo, instructions_tree, offset, length);
        }
    }
}

/* enum ofp_multipart_types { */
/* Description of this OpenFlow switch.
* The request body is empty.
* The reply body is struct ofp_desc. */
#define OFPMP_DESC  0
/* Individual flow statistics.
* The request body is struct ofp_flow_stats_request.
* The reply body is an array of struct ofp_flow_stats. */
#define OFPMP_FLOW  1
/* Aggregate flow statistics.
* The request body is struct ofp_aggregate_stats_request.
* The reply body is struct ofp_aggregate_stats_reply. */
#define OFPMP_AGGREGATE  2
/* Flow table statistics.
* The request body is empty.
* The reply body is an array of struct ofp_table_stats. */
#define OFPMP_TABLE  3
/* Port statistics.
* The request body is struct ofp_port_stats_request.
* The reply body is an array of struct ofp_port_stats. */
#define OFPMP_PORT_STATS  4
/* Queue statistics for a port
* The request body is struct ofp_queue_stats_request.
* The reply body is an array of struct ofp_queue_stats */
#define OFPMP_QUEUE  5
/* Group counter statistics.
* The request body is struct ofp_group_stats_request.
* The reply is an array of struct ofp_group_stats. */
#define OFPMP_GROUP  6
/* Group description.
* The request body is empty.
* The reply body is an array of struct ofp_group_desc_stats. */
#define OFPMP_GROUP_DESC  7
/* Group features.
* The request body is empty.
* The reply body is struct ofp_group_features. */
#define OFPMP_GROUP_FEATURES  8
/* Meter statistics.
* The request body is struct ofp_meter_multipart_requests.
* The reply body is an array of struct ofp_meter_stats. */
#define OFPMP_METER  9
/* Meter configuration.
* The request body is struct ofp_meter_multipart_requests.
* The reply body is an array of struct ofp_meter_config. */
#define OFPMP_METER_CONFIG  10
/* Meter features.
* The request body is empty.
* The reply body is struct ofp_meter_features. */
#define OFPMP_METER_FEATURES  11
/* Table features.
* The request body is either empty or contains an array of
* struct ofp_table_features containing the controller's
* desired view of the switch. If the switch is unable to
* set the specified view an error is returned.
* The reply body is an array of struct ofp_table_features. */
#define OFPMP_TABLE_FEATURES  12
/* Port description.
* The request body is empty.
* The reply body is an array of struct ofp_port. */
#define OFPMP_PORT_DESC  13
/* Experimenter extension.
* The request and reply bodies begin with
* struct ofp_experimenter_multipart_header.
* The request and reply bodies are otherwise experimenter-defined. */
#define OFPMP_EXPERIMENTER  0xffff

static const value_string openflow_v4_multipart_type_values[] = {
    { OFPMP_DESC,           "OFPMP_DESC" },
    { OFPMP_FLOW,           "OFPMP_FLOW" },
    { OFPMP_TABLE,          "OFPMP_TABLE" },
    { OFPMP_PORT_STATS,     "OFPMP_PORT_STATS" },
    { OFPMP_QUEUE,          "OFPMP_QUEUE" },
    { OFPMP_GROUP,          "OFPMP_GROUP" },
    { OFPMP_GROUP_DESC,     "OFPMP_GROUP_DESC" },
    { OFPMP_GROUP_FEATURES, "OFPMP_GROUP_FEATURES" },
    { OFPMP_METER,          "OFPMP_METER" },
    { OFPMP_METER_CONFIG,   "OFPMP_METER_CONFIG" },
    { OFPMP_METER_FEATURES, "OFPMP_METER_FEATURES" },
    { OFPMP_TABLE_FEATURES, "OFPMP_TABLE_FEATURES" },
    { OFPMP_PORT_DESC,      "OFPMP_PORT_DESC" },
    { OFPMP_EXPERIMENTER,   "OFPMP_EXPERIMENTER" },
    { 0, NULL }
};

/*
struct ofp_multipart_request {
struct ofp_header header;
uint16_t type; / One of the OFPMP_* constants. /
uint16_t flags; / OFPMPF_REQ_* flags. /
uint8_t pad[4];
uint8_t body[0]; / Body of the request. /
};
*/
static void
dissect_openflow_multipart_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 type;

    /* type */
    type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_multipart_type , tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t flags OFPMPF_REQ_* flags. */
    proto_tree_add_item(tree, hf_openflow_v4_multipart_request_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_v4_padd32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPMP_DESC: /* 0 */
        /* The request body is empty. */
        break;
    case OFPMP_FLOW:
        /* The request body is struct ofp_flow_stats_request. */
        proto_tree_add_text(tree, tvb, offset, -1, "struct ofp_flow_stats_request - not dissected yet");
        break;
    default:
        if(length>16)
            proto_tree_add_text(tree, tvb, offset, -1, "Type - not dissected yet");
        break;
    }

}

static void
dissect_openflow_multipart_reply_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 type;

    /* type */
    type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_multipart_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t flags OFPMPF_REPLY_* flags. */
    proto_tree_add_item(tree, hf_openflow_v4_multipart_reply_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_v4_padd32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPMP_DESC: /* 0 */
        /* The reply body is struct ofp_desc. */
        proto_tree_add_text(tree, tvb, offset, -1, "struct ofp_desc - not dissected yet");
        break;
    case OFPMP_FLOW:
        /* The reply body is an array of struct ofp_flow_stats */
        proto_tree_add_text(tree, tvb, offset, -1, "struct ofp_flow_stats - not dissected yet");
        break;
    default:
        if(length>16)
            proto_tree_add_text(tree, tvb, offset, -1, "Type - not dissected yet");
        break;
    }

}

static int
dissect_openflow_v4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *openflow_tree;
    guint offset = 0;
    guint8 type;
    guint16 length;

    type    = tvb_get_guint8(tvb, 1);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
                  val_to_str_const(type, openflow_v4_type_values, "Unknown Messagetype"));

    /* Stop the Ethernet frame from overwriting the columns */
    if((type == OFPT_V4_PACKET_IN) || (type == OFPT_V4_PACKET_OUT)){
        col_set_writable(pinfo->cinfo, FALSE);
    }

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_openflow_v4, tvb, 0, -1, ENC_NA);
    openflow_tree = proto_item_add_subtree(ti, ett_openflow_v4);

    /* A.1 OpenFlow Header. */
    /* OFP_VERSION. */
    proto_tree_add_item(openflow_tree, hf_openflow_v4_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* One of the OFPT_ constants. */
    proto_tree_add_item(openflow_tree, hf_openflow_v4_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Length including this ofp_header. */
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(openflow_tree, hf_openflow_v4_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* Transaction id associated with this packet. Replies use the same id as was in the request
     * to facilitate pairing.
     */
    proto_tree_add_item(openflow_tree, hf_openflow_v4_xid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPT_V4_HELLO: /* 0 */
        /* 5.5.1 Hello
         * The OFPT_HELLO message has no body;
         */
        break;
    case OFPT_V4_FEATURES_REQUEST: /* 5 */
        /* 5.3.1 Handshake
         * Upon TLS session establishment, the controller sends an OFPT_FEATURES_REQUEST
         * message. This message does not contain a body beyond the OpenFlow header.
         */
        break;
    case OFPT_V4_FEATURES_REPLY: /* 6 */
        dissect_openflow_features_reply_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    case OFPT_V4_FLOW_MOD: /* 14 */
        dissect_openflow_flowmod_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    case OFPT_V4_MULTIPART_REQUEST: /* 18 */
        dissect_openflow_multipart_request_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    case OFPT_V4_MULTIPART_REPLY: /* 19 */
        dissect_openflow_multipart_reply_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    default:
        if(length>8){
            proto_tree_add_text(tree, tvb, offset, -1, "Message data not dissected yet");
        }
        break;
    }

    return tvb_length(tvb);

}

/* 
 * Register the protocol with Wireshark.
 */
void
proto_register_openflow_v4(void)
{

    static hf_register_info hf[] = {
        { &hf_openflow_v4_version,
            { "Version", "openflow_v4.version",
               FT_UINT8, BASE_HEX, VALS(openflow_v4_version_values), 0x7f,
               NULL, HFILL }
        },
        { &hf_openflow_v4_type,
            { "Type", "openflow_v4.type",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_xid,
            { "Transaction ID", "openflow_v4.xid",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_length,
            { "Length", "openflow_v4.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_class,
            { "Class", "openflow_v4.oxm.class",
               FT_UINT16, BASE_HEX, VALS(openflow_v4_oxm_class_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_field,
            { "Field", "openflow_v4.oxm.field",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_field_basic,
            { "Field", "openflow_v4.oxm.field",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_oxm_basic_field_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_hm,
            { "Has mask", "openflow_v4.oxm.hm",
               FT_BOOLEAN, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_length,
            { "Length", "openflow_v4.oxm.length",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value,
            { "Value", "openflow_v4.oxm.value",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask,
            { "Mask", "openflow_v4.oxm.mask",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_match_type,
            { "Type", "openflow_v4.match.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_match_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_match_length,
            { "Length", "openflow_v4.match.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_match_pad,
            { "Padding", "openflow_v4.match.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_type,
            { "Type", "openflow_v4.instruction.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_instruction_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_length,
            { "Length", "openflow_v4.instruction.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_goto_table_table_id,
            { "Table ID", "openflow_v4.instruction.goto_table.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_goto_table_pad,
            { "Padding", "openflow_v4.instruction.goto_table.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_write_metadata_pad,
            { "Padding", "openflow_v4.instruction.write_metadata.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_write_metadata_value,
            { "Value", "openflow_v4.instruction.write_metadata.value",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_write_metadata_mask,
            { "Mask", "openflow_v4.instruction.write_metadata.mask",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_actions_pad,
            { "Padding", "openflow_v4.instruction.actions.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_meter_meter_id,
            { "Meter ID", "openflow_v4.instruction.meter.meter_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_meter_meter_id_reserved,
            { "Meter ID", "openflow_v4.instruction.meter.meter_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_meter_id_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_datapath_id,
            { "Datapath unique ID", "openflow_v4.datapath_id",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_v4_mac,
            { "MAC addr", "openflow_v4.datapath_mac",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_datapath_impl,
            { "Implementers part", "openflow_v4.datapath_imp",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_n_buffers,
            { "n_buffers", "openflow_v4.n_buffers",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_n_tables,
            { "n_tables", "openflow_v4.n_tables",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_auxiliary_id,
            { "auxiliary_id", "openflow_v4.auxiliary_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_padd16,
            { "Padding", "openflow_v4.padding16",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_padd32,
            { "Padding", "openflow_v4.padding32",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_capabilities,
            { "capabilities", "openflow_v4.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_cap_flow_stats,
            { "Flow statistics", "openflow_v4.flow_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_FLOW_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats,
            { "Table statistics", "openflow_v4.table_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_TABLE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats,
            { "Port statistics", "openflow_v4.port_stats",
               FT_BOOLEAN, 32, NULL,  OFPC_V4_PORT_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats,
            { "Group statistics", "openflow_v4.group_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_GROUP_STATS,
               NULL, HFILL }
        },
        { &hf_openflow__v4_ip_reasm,
            { "Can reassemble IP fragments", "openflow_v4.ip_reasm",
               FT_BOOLEAN, 32, NULL, OFPC_V4_IP_REASM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats,
            { "Queue statistics", "openflow_v4.queue_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_QUEUE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_blocked,
            { "Switch will block looping ports", "openflow_v4.port_blocked",
               FT_BOOLEAN, 32, NULL, OFPC_V4_PORT_BLOCKED,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_cookie,
            { "Cookie", "openflow_v4.flowmod.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_cookie_mask,
            { "Cookie mask", "openflow_v4.flowmod.cookie_mask",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_table_id,
            { "Table ID", "openflow_v4.flowmod.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_table_id_reserved,
            { "Table ID", "openflow_v4.flowmod.table_id",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_table_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_command,
            { "Command", "openflow_v4.flowmod.command",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_flowmod_command_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_idle_timeout,
            { "Idle timeout", "openflow_v4.flowmod.idle_timeout",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_hard_timeout,
            { "Hard timeout", "openflow_v4.flowmod.hard_timeout",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_priority,
            { "Priority", "openflow_v4.flowmod.priority",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_buffer_id,
            { "Buffer ID", "openflow_v4.flowmod.buffer_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_buffer_id_reserved,
            { "Buffer ID", "openflow_v4.flowmod.buffer_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_buffer_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_port,
            { "Out port", "openflow_v4.flowmod.out_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_port_reserved,
            { "Out port", "openflow_v4.flowmod.out_port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_group,
            { "Out group", "openflow_v4.flowmod.out_group",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_group_reserved,
            { "Out group", "openflow_v4.flowmod.out_group",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags,
            { "Flags", "openflow_v4.flowmod.flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_send_flow_rem,
            { "Send flow removed", "openflow_v4.flowmod.flags.send_flow_rem",
               FT_BOOLEAN, 16, NULL, OFPFF_SEND_FLOW_REM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_check_overlap,
            { "Check overlap", "openflow_v4.flowmod.flags.check_overlap",
               FT_BOOLEAN, 16, NULL, OFPFF_CHECK_OVERLAP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_reset_counts,
            { "Reset counts", "openflow_v4.flowmod.flags.reset_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_RESET_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_no_packet_counts,
            { "Don't count packets", "openflow_v4.flowmod.flags.no_packet_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_NO_PKT_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_no_byte_counts,
            { "Don't count bytes", "openflow_v4.flowmod.flags.no_byte_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_NO_BYT_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_pad,
            { "Padding", "openflow_v4.flowmod.pad",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_type,
            { "Type", "openflow_v4.multipart_type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_multipart_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_flags,
            { "Flags", "openflow_v4.multipart_request_flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_flags,
            { "Flags", "openflow_v4.multipart_request_flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_openflow_v4,
        &ett_openflow_v4_path_id,
        &ett_openflow_v4_cap,
        &ett_openflow_v4_flowmod_flags,
        &ett_openflow_v4_flowmod_instructions,
        &ett_openflow_v4_oxm,
        &ett_openflow_v4_match,
        &ett_openflow_v4_match_oxm_fields,
        &ett_openflow_v4_instruction,
        &ett_openflow_v4_instruction_actions_actions
    };

    static ei_register_info ei[] = {
        { &ei_openflow_v4_match_undecoded,
            { "openflow_v4.match.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown match.", EXPFILL }
        },
        { &ei_openflow_v4_instruction_undecoded,
            { "openflow_v4.instruction.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown instruction.", EXPFILL }
        }
    };

    expert_module_t *expert_openflow_v4;

    /* Register the protocol name and description */
    proto_openflow_v4 = proto_register_protocol("OpenFlow_V4",
            "openflow_v4", "openflow_v4");

    new_register_dissector("openflow_v4", dissect_openflow_v4, proto_openflow_v4);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_openflow_v4, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_openflow_v4 = expert_register_protocol(proto_openflow_v4);
    expert_register_field_array(expert_openflow_v4, ei, array_length(ei));
}
