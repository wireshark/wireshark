/* packet-openflow_v1.c
 * Routines for OpenFlow dissection
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2013, Zoltan Lajos Kis <zoltan.lajos.kis@ericsson.com>
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

#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_openflow_v1(void);
void proto_reg_handoff_openflow_v1(void);

static dissector_handle_t eth_withoutfcs_handle;

/* Initialize the protocol and registered fields */
static int proto_openflow_v1 = -1;
static int hf_openflow_version = -1;
static int hf_openflow_1_0_type = -1;
static int hf_openflow_length = -1;
static int hf_openflow_xid = -1;

static int hf_openflow_datapath_id = -1;
static int hf_openflow_datapath_mac = -1;
static int hf_openflow_datapath_impl = -1;
static int hf_openflow_n_buffers = -1;
static int hf_openflow_n_tables = -1;
/* static int hf_openflow_auxiliary_id = -1; */
static int hf_openflow_capabilities = -1;
static int hf_openflow_actions = -1;
/* static int hf_openflow_reserved32 = -1; */
static int hf_openflow_cap_flow_stats = -1;
static int hf_openflow_table_stats = -1;
static int hf_openflow_port_stats = -1;
static int hf_openflow_group_stats = -1;
static int hf_openflow_ip_reasm = -1;
static int hf_openflow_queue_stats = -1;
static int hf_openflow_port_blocked = -1;

static int hf_openflow_output = -1; /* Output to switch port. */
static int hf_openflow_set_vlan_vid = -1; /* Set the 802.1q VLAN id. */
static int hf_openflow_set_vlan_pcp = -1; /* Set the 802.1q priority. */
static int hf_openflow_strip_vlan = -1; /* Strip the 802.1q header. */
static int hf_openflow_set_dl_src = -1; /* Ethernet source address. */
static int hf_openflow_set_dl_dst = -1; /* Ethernet destination address. */
static int hf_openflow_set_nw_src = -1; /* IP source address. */
static int hf_openflow_set_nw_dst = -1; /* IP destination address. */
static int hf_openflow_set_nw_tos = -1; /* IP ToS (DSCP field, 6 bits). */
static int hf_openflow_set_tp_src = -1; /* TCP/UDP source port. */
static int hf_openflow_set_tp_dst = -1; /* TCP/UDP destination port. */
static int hf_openflow_enqueue = -1; /* Output to queue. */

static int hf_openflow_port_no = -1;
static int hf_openflow_hw_addr = -1;
static int hf_openflow_port_name = -1;


static int hf_openflow_port_config = -1;
static int hf_openflow_port_state = -1;
static int hf_openflow_port_curr = -1;
static int hf_openflow_port_advertised = -1;
static int hf_openflow_port_supported = -1;
static int hf_openflow_port_peer = -1;

static int hf_openflow_port_down = -1;    /* Port is administratively down. */
static int hf_openflow_no_stp = -1;       /* Disable 802.1D spanning tree on port. */
static int hf_openflow_no_recv = -1;      /* Drop all packets except 802.1D spanning tree packets. */
static int hf_openflow_no_recv_stp = -1;  /* Drop received 802.1D STP packets. */
static int hf_openflow_no_flood = -1;     /* Do not include this port when flooding. */
static int hf_openflow_no_fwd = -1;       /* Drop packets forwarded to port. */
static int hf_openflow_no_packet_in = -1; /* Do not send packet-in msgs for port. */

static int hf_openflow_link_down = -1;    /* No physical link present. */

static int hf_openflow_10mb_hd = -1;      /* 10 Mb half-duplex rate support. */
static int hf_openflow_10mb_fd = -1;      /* 10 Mb full-duplex rate support. */
static int hf_openflow_100mb_hd = -1;     /* 100 Mb half-duplex rate support. */
static int hf_openflow_100mb_fd = -1;     /* 100 Mb full-duplex rate support. */
static int hf_openflow_1gb_hd = -1;       /* 1 Gb half-duplex rate support. */
static int hf_openflow_1gb_fd = -1;       /* 1 Gb full-duplex rate support. */
static int hf_openflow_10gb_fd = -1;      /* 10 Gb full-duplex rate support. */
static int hf_openflow_copper = -1;       /* Copper medium. */
static int hf_openflow_fiber = -1;        /* Fiber medium. */
static int hf_openflow_autoneg = -1;      /* Auto-negotiation. */
static int hf_openflow_pause = -1;        /* Pause. */
static int hf_openflow_pause_asym = -1;   /* Asymmetric pause. */

static int hf_openflow_config_flags = -1;
static int hf_openflow_miss_send_len = -1;

static int hf_openflow_buffer_id = -1;
static int hf_openflow_total_len = -1;
static int hf_openflow_in_port = -1;
static int hf_openflow_reason = -1;
static int hf_openflow_pkt_in_pad = -1;
static int hf_openflow_table_id = -1;
static int hf_openflow_cookie = -1;
/* static int hf_openflow_cookie_mask = -1; */
static int hf_openflow_features_reply_pad = -1;
static int hf_openflow_actions_len = -1;
static int hf_openflow_action_type = -1;
static int hf_openflow_action_len = -1;
static int hf_openflow_output_port = -1;
static int hf_openflow_max_len = -1;
static int hf_openflow_wildcards = -1;
static int hf_openflow_command = -1;
static int hf_openflow_eth_src = -1;
static int hf_openflow_eth_dst = -1;
static int hf_openflow_dl_vlan = -1;
static int hf_openflow_dl_vlan_pcp = -1;
static int hf_openflow_ofp_match_pad = -1;
static int hf_openflow_match_dl_type = -1;
static int hf_openflow_ofp_match_tos = -1;
static int hf_openflow_ofp_match_nw_proto = -1;
static int hf_openflow_ofp_source_addr = -1;
static int hf_openflow_ofp_dest_addr = -1;
static int hf_openflow_ofp_source_port = -1;
static int hf_openflow_ofp_dest_port = -1;
static int hf_openflow_idle_timeout = -1;
static int hf_openflow_hard_timeout = -1;
static int hf_openflow_priority = -1;
static int hf_openflow_out_port = -1;
/* static int hf_openflow_out_group = -1; */
static int hf_openflow_flags = -1;
static int hf_openflow_v1_stats_type = -1;
static int hf_openflow_v1_flow_stats_request_pad = -1;

/* Initialize the subtree pointers */
static gint ett_openflow = -1;
static gint ett_openflow_path_id = -1;
static gint ett_openflow_cap = -1;
static gint ett_openflow_act = -1;
static gint ett_openflow_port = -1;
static gint ett_openflow_port_cnf = -1;
static gint ett_openflow_port_state = -1;
static gint ett_openflow_port_cf = -1;

/* static expert_field ei_openflow_undecoded_data = EI_INIT; */
static expert_field ei_openflow_action_type = EI_INIT;
static expert_field ei_openflow_1_0_type = EI_INIT;

static const value_string openflow_version_values[] = {
    { 0x01, "1.0" },
    { 0, NULL }
};


/* Immutable messages. */
#define OFPT_1_0_HELLO                     0 /* Symmetric message */
#define OFPT_1_0_ERROR                     1 /* Symmetric message */
#define OFPT_1_0_ECHO_REQUEST              2 /* Symmetric message */
#define OFPT_1_0_ECHO_REPLY                3 /* Symmetric message */
#define OFPT_1_0_VENDOR                    4 /* Symmetric message */
/* Switch configuration messages. */
#define OFPT_1_0_FEATURES_REQUEST          5 /* Controller/switch message */
#define OFPT_1_0_FEATURES_REPLY            6 /* Controller/switch message */
#define OFPT_1_0_GET_CONFIG_REQUEST        7 /* Controller/switch message */
#define OFPT_1_0_GET_CONFIG_REPLY          8 /* Controller/switch message */
#define OFPT_1_0_SET_CONFIG                9 /* Controller/switch message */
/* Asynchronous messages. */
#define OFPT_1_0_PACKET_IN                10 /* Async message */
#define OFPT_1_0_FLOW_REMOVED             11 /* Async message */
#define OFPT_1_0_PORT_STATUS              12 /* Async message */
/* Controller command messages. */
#define OFPT_1_0_PACKET_OUT               13 /* Controller/switch message */
#define OFPT_1_0_FLOW_MOD                 14 /* Controller/switch message */
#define OFPT_1_0_PORT_MOD                 15 /* Controller/switch message */
/* Statistics messages. */
#define OFPT_1_0_STATS_REQUEST            16 /* Controller/switch message */
#define OFPT_1_0_STATS_REPLY              17 /* Controller/switch message */
/* Barrier messages. */
#define OFPT_1_0_BARRIER_REQUEST          18 /* Controller/switch message */
#define OFPT_1_0_BARRIER_REPLY            19 /* Controller/switch message */
/* Queue Configuration messages. */
#define OFPT_1_0_QUEUE_GET_CONFIG_REQUEST 20 /* Controller/switch message */
#define OFPT_1_0_QUEUE_GET_CONFIG_REPLY   21 /* Controller/switch message */


static const value_string openflow_1_0_type_values[] = {
/* Immutable messages. */
    { 0, "OFPT_HELLO" },                     /* Symmetric message */
    { 1, "OFPT_ERROR" },                     /* Symmetric message */
    { 2, "OFPT_ECHO_REQUEST" },              /* Symmetric message */
    { 3, "OFPT_ECHO_REPLY" },                /* Symmetric message */
    { 4, "OFPT_VENDOR" },                    /* Symmetric message */
/* Switch configuration messages. */
    { 5, "OFPT_FEATURES_REQUEST" },          /* Controller/switch message */
    { 6, "OFPT_FEATURES_REPLY" },            /* Controller/switch message */
    { 7, "OFPT_GET_CONFIG_REQUEST" },        /* Controller/switch message */
    { 8, "OFPT_GET_CONFIG_REPLY" },          /* Controller/switch message */
    { 9, "OFPT_SET_CONFIG" },                /* Controller/switch message */
/* Asynchronous messages. */
    { 10, "OFPT_PACKET_IN" },                /* Async message */
    { 11, "OFPT_FLOW_REMOVED" },             /* Async message */
    { 12, "OFPT_PORT_STATUS" },              /* Async message */
/* Controller command messages. */
    { 13, "OFPT_PACKET_OUT" },               /* Controller/switch message */
    { 14, "OFPT_FLOW_MOD" },                 /* Controller/switch message */
    { 15, "OFPT_PORT_MOD" },                 /* Controller/switch message */
/* Statistics messages. */
    { 16, "OFPT_STATS_REQUEST" },            /* Controller/switch message */
    { 17, "OFPT_STATS_REPLY" },              /* Controller/switch message */
/* Barrier messages. */
    { 18, "OFPT_BARRIER_REQUEST" },          /* Controller/switch message */
    { 19, "OFPT_BARRIER_REPLY" },            /* Controller/switch message */
/* Queue Configuration messages. */
    { 20, "OFPT_QUEUE_GET_CONFIG_REQUEST" }, /* Controller/switch message */
    { 21, "OFPT_QUEUE_GET_CONFIG_REPLY" },   /* Controller/switch message */
    { 0, NULL }
};
static value_string_ext openflow_1_0_type_values_ext = VALUE_STRING_EXT_INIT(openflow_1_0_type_values);

#define OFPC_FLOW_STATS   1<<0  /* Flow statistics. */
#define OFPC_TABLE_STATS  1<<1  /* Table statistics. */
#define OFPC_PORT_STATS   1<<2  /* Port statistics. */
#define OFPC_GROUP_STATS  1<<3  /* Group statistics. */
#define OFPC_IP_REASM     1<<5  /* Can reassemble IP fragments. */
#define OFPC_QUEUE_STATS  1<<6  /* Queue statistics. */
#define OFPC_PORT_BLOCKED 1<<8  /* Switch will block looping ports. */

#define OFPAT_OUTPUT_MASK       1<<0  /* Output to switch port. */
#define OFPAT_SET_VLAN_VID_MASK 1<<1  /* Set the 802.1q VLAN id. */
#define OFPAT_SET_VLAN_PCP_MASK 1<<2  /* Set the 802.1q priority. */
#define OFPAT_STRIP_VLAN_MASK   1<<3  /* Strip the 802.1q header. */
#define OFPAT_SET_DL_SRC_MASK   1<<4  /* Ethernet source address. */
#define OFPAT_SET_DL_DST_MASK   1<<5  /* Ethernet destination address. */
#define OFPAT_SET_NW_SRC_MASK   1<<6  /* IP source address. */
#define OFPAT_SET_NW_DST_MASK   1<<7  /* IP destination address. */
#define OFPAT_SET_NW_TOS_MASK   1<<8  /* IP ToS (DSCP field, 6 bits). */
#define OFPAT_SET_TP_SRC_MASK   1<<9  /* TCP/UDP source port. */
#define OFPAT_SET_TP_DST_MASK   1<<10 /* TCP/UDP destination port. */
#define OFPAT_ENQUEUE_MASK      1<<11 /* Output to queue. */

#define OFPPC_PORT_DOWN    1<<0 /* Port is administratively down. */
#define OFPPC_NO_STP       1<<1 /* Disable 802.1D spanning tree on port. */
#define OFPPC_NO_RECV      1<<2 /* Drop all packets except 802.1D spanning tree packets. */
#define OFPPC_NO_RECV_STP  1<<3 /* Drop received 802.1D STP packets. */
#define OFPPC_NO_FLOOD     1<<4 /* Do not include this port when flooding. */
#define OFPPC_NO_FWD       1<<5 /* Drop packets forwarded to port. */
#define OFPPC_NO_PACKET_IN 1<<6 /* Do not send packet-in msgs for port. */

#define OFP_MAX_PORT_NAME_LEN 16

#define OFPPS_LINK_DOWN    1<<0 /* No physical link present. */
#define OFPPS_STP_LISTEN   0<<8 /* Not learning or relaying frames. */
#define OFPPS_STP_LEARN    1<<8 /* Learning but not relaying frames. */
#define OFPPS_STP_FORWARD  2<<8 /* Learning and relaying frames. */
#define OFPPS_STP_BLOCK    3<<8 /* Not part of spanning tree. */
#define OFPPS_STP_MASK     3<<8 /* Bit mask for OFPPS_STP_* values. */


#define OFPPF_10MB_HD      1<<0  /* 10 Mb half-duplex rate support. */
#define OFPPF_10MB_FD      1<<1  /* 10 Mb full-duplex rate support. */
#define OFPPF_100MB_HD     1<<2  /* 100 Mb half-duplex rate support. */
#define OFPPF_100MB_FD     1<<3  /* 100 Mb full-duplex rate support. */
#define OFPPF_1GB_HD       1<<4  /* 1 Gb half-duplex rate support. */
#define OFPPF_1GB_FD       1<<5  /* 1 Gb full-duplex rate support. */
#define OFPPF_10GB_FD      1<<6  /* 10 Gb full-duplex rate support. */
#define OFPPF_COPPER       1<<7  /* Copper medium. */
#define OFPPF_FIBER        1<<8  /* Fiber medium. */
#define OFPPF_AUTONEG      1<<9  /* Auto-negotiation. */
#define OFPPF_PAUSE        1<<10 /* Pause. */
#define OFPPF_PAUSE_ASYM   1<<11 /* Asymmetric pause. */


#define OFPAT_OUTPUT         0 /* Output to switch port. */
#define OFPAT_SET_VLAN_VID   1 /* Set the 802.1q VLAN id. */
#define OFPAT_SET_VLAN_PCP   2 /* Set the 802.1q priority. */
#define OFPAT_STRIP_VLAN     3 /* Strip the 802.1q header. */
#define OFPAT_SET_DL_SRC     4 /* Ethernet source address. */
#define OFPAT_SET_DL_DST     5 /* Ethernet destination address. */
#define OFPAT_SET_NW_SRC     6 /* IP source address. */
#define OFPAT_SET_NW_DST     7 /* IP destination address. */
#define OFPAT_SET_TP_SRC     8 /* TCP/UDP source port. */
#define OFPAT_SET_TP_DST     9 /* TCP/UDP destination port. */
#define OFPAT_VENDOR         0xffff

static int
dissect_openflow_ofp_match_v1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{

    /* uint32_t wildcards; Wildcard fields. */
    proto_tree_add_item(tree, hf_openflow_wildcards, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    /* uint16_t in_port; Input switch port. */
    proto_tree_add_item(tree, hf_openflow_in_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t dl_src[OFP_ETH_ALEN];  Ethernet source address. */
    proto_tree_add_item(tree, hf_openflow_eth_src, tvb, offset, 6, ENC_NA);
    offset+=6;
    /* uint8_t dl_dst[OFP_ETH_ALEN]; Ethernet destination address. */
    proto_tree_add_item(tree, hf_openflow_eth_dst, tvb, offset, 6, ENC_NA);
    offset+=6;
    /* uint16_t dl_vlan; Input VLAN id. */
    proto_tree_add_item(tree, hf_openflow_dl_vlan, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    /* uint8_t dl_vlan_pcp; Input VLAN priority. */
    proto_tree_add_item(tree, hf_openflow_dl_vlan_pcp, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* uint8_t pad1[1]; Align to 64-bits */
    proto_tree_add_item(tree, hf_openflow_ofp_match_pad, tvb, offset, 1, ENC_NA);
    offset++;
    /* uint16_t dl_type; Ethernet frame type. */
    proto_tree_add_item(tree, hf_openflow_match_dl_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* uint8_t nw_tos; IP ToS (actually DSCP field, 6 bits). */
    proto_tree_add_item(tree, hf_openflow_ofp_match_tos, tvb, offset, 1, ENC_NA);
    offset++;
    /* uint8_t nw_proto; IP protocol or lower 8 bits of
     * ARP opcode.
     */
    proto_tree_add_item(tree, hf_openflow_ofp_match_nw_proto, tvb, offset, 1, ENC_NA);
    offset++;
    /* uint8_t pad2[2]; Align to 64-bits */
    proto_tree_add_item(tree, hf_openflow_ofp_match_pad, tvb, offset, 2, ENC_NA);
    offset += 2;
    /* uint32_t nw_src; IP source address. */
    proto_tree_add_item(tree, hf_openflow_ofp_source_addr, tvb, offset, 4, ENC_NA);
    offset += 4;
    /* uint32_t nw_dst; IP destination address. */
    proto_tree_add_item(tree, hf_openflow_ofp_dest_addr, tvb, offset, 4, ENC_NA);
    offset += 4;
    /* uint16_t tp_src; TCP/UDP source port. */
    proto_tree_add_item(tree, hf_openflow_ofp_source_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* uint16_t tp_dst; TCP/UDP destination port. */
    proto_tree_add_item(tree, hf_openflow_ofp_dest_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    return offset;
}

static int
dissect_openflow_flow_stats_request_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    /* struct ofp_match match;  Fields to match */
    offset = dissect_openflow_ofp_match_v1(tvb, pinfo, tree, offset);

    /* uint8_t table_id; ID of table to read (from ofp_table_stats),
     * 0xff for all tables or 0xfe for emergency.
     */
    proto_tree_add_item(tree, hf_openflow_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* uint8_t pad;  Align to 32 bits. */
    proto_tree_add_item(tree, hf_openflow_v1_flow_stats_request_pad, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* uint16_t out_port; */
    proto_tree_add_item(tree, hf_openflow_out_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;

}


static const value_string openflow_action_values[] = {
    { OFPAT_OUTPUT,          "Output to switch port" },
    { OFPAT_SET_VLAN_VID,    "Set the 802.1q VLAN id" },
    { OFPAT_SET_VLAN_PCP,    "Set the 802.1q priority" },
    { OFPAT_STRIP_VLAN,      "Strip the 802.1q header" },
    { OFPAT_SET_DL_SRC,      "Ethernet source address" },
    { OFPAT_SET_DL_DST,      "Ethernet destination address" },
    { OFPAT_SET_NW_SRC,      "IP source address" },
    { OFPAT_SET_NW_DST,      "IP destination address" },
    { OFPAT_SET_TP_SRC,      "TCP/UDP source port" },
    { OFPAT_SET_TP_DST,      "TCP/UDP destination port" },
    { OFPAT_VENDOR,          "Vendor specific action"},
    { 0, NULL }
};

static int
dissect_openflow_action_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    guint16 action_type, action_len;
    proto_item* ti;

    /* uint16_t type;  One of OFPAT_*. */
    action_type = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_item(tree, hf_openflow_action_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    /* Length of action, including this
     * header. This is the length of action,
     * including any padding to make it
     * 64-bit aligned.
     */
    action_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_action_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    switch(action_type){
    case OFPAT_OUTPUT:
        /* uint16_t port;  Output port. */
        proto_tree_add_item(tree, hf_openflow_output_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* uint16_t max_len;  Max length to send to controller. */
        proto_tree_add_item(tree, hf_openflow_max_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        break;
    default:
        expert_add_info(pinfo, ti, &ei_openflow_action_type);
        offset+=(action_len-4);
        break;
    }

    return offset;
}
static void
dissect_openflow_phy_port(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *ti;
    proto_tree *port_cnf_tree, *port_state_tree, *port_cf_tree;

    proto_tree_add_item(tree, hf_openflow_port_no, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_openflow_hw_addr, tvb, offset, 6, ENC_NA);
    offset+=6;
    proto_tree_add_item(tree, hf_openflow_port_name, tvb, offset, OFP_MAX_PORT_NAME_LEN, ENC_ASCII|ENC_NA);
    offset+=OFP_MAX_PORT_NAME_LEN;

    /* Bitmap of OFPPC_* flags. */
    ti = proto_tree_add_item(tree, hf_openflow_port_config, tvb, offset, 4, ENC_BIG_ENDIAN);
    port_cnf_tree = proto_item_add_subtree(ti, ett_openflow_port_cnf);

    /* Port is administratively down. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_port_down, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Disable 802.1D spanning tree on port. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_stp, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Drop all packets except 802.1D spanning tree packets. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_recv, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Drop received 802.1D STP packets. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_recv_stp, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Do not include this port when flooding. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_flood, tvb, offset, 4, ENC_BIG_ENDIAN);
     /* Drop packets forwarded to port. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_fwd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Do not send packet-in msgs for port. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_packet_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Bitmap of OFPPS_* flags. */
    ti = proto_tree_add_item(tree, hf_openflow_port_state, tvb, offset, 4, ENC_BIG_ENDIAN);
    port_state_tree = proto_item_add_subtree(ti, ett_openflow_port_state);

    /* No physical link present. */
    proto_tree_add_item(port_state_tree, hf_openflow_link_down, tvb, offset, 4, ENC_BIG_ENDIAN);

    offset+=4;

    /* Current features. */
    ti = proto_tree_add_item(tree, hf_openflow_port_curr, tvb, offset, 4, ENC_BIG_ENDIAN);
    port_cf_tree = proto_item_add_subtree(ti, ett_openflow_port_cf);
    /* 10 Mb half-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_10mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* 10 Mb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_10mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* 100 Mb half-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_100mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* 100 Mb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_100mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* 1 Gb half-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_1gb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* 1 Gb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_1gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* 10 Gb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_10gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Copper medium. */
    proto_tree_add_item(port_cf_tree, hf_openflow_copper, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Fiber medium. */
    proto_tree_add_item(port_cf_tree, hf_openflow_fiber, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Auto-negotiation. */
    proto_tree_add_item(port_cf_tree, hf_openflow_autoneg, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Pause. */
    proto_tree_add_item(port_cf_tree, hf_openflow_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Asymmetric pause. */
    proto_tree_add_item(port_cf_tree, hf_openflow_pause_asym, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Features being advertised by the port. */
    proto_tree_add_item(tree, hf_openflow_port_advertised, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Features supported by the port. */
    proto_tree_add_item(tree, hf_openflow_port_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    /* Features advertised by peer. */
    proto_tree_add_item(tree, hf_openflow_port_peer, tvb, offset, 4, ENC_BIG_ENDIAN);


}

#if 0
/*
 * Switch features.
 */

struct ofp_switch_features {
    struct ofp_header   header;
    uint64_t            datapath_id;  /* Datapath unique ID. The lower 48-bits are for
                                         a MAC address, while the upper 16-bits are
                                         implementer-defined. */
    uint32_t            n_buffers;    /* Max packets buffered at once. */
    uint8_t             n_tables;     /* Number of tables supported by datapath. */
    uint8_t             pad[3];       /* Align to 64-bits. */
    /* Features. */
    uint32_t            capabilities; /* Bitmap of support "ofp_capabilities". */
    uint32_t            actions;      /* Bitmap of supported "ofp_action_type"s. */
    /* Port info.*/
    struct ofp_phy_port ports[0];     /* Port definitions. The number of ports
                                         is inferred from the length field in
                                         the header. */
#endif

static void
dissect_openflow_features_reply_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *path_id_tree, *cap_tree, *act_tree;

    guint16 length_remaining;

    ti = proto_tree_add_item(tree, hf_openflow_datapath_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    path_id_tree = proto_item_add_subtree(ti, ett_openflow_path_id);
    proto_tree_add_item(path_id_tree, hf_openflow_datapath_mac, tvb, offset, 6, ENC_NA);
    offset+=6;
    proto_tree_add_item(path_id_tree, hf_openflow_datapath_impl, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_n_buffers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    proto_tree_add_item(tree, hf_openflow_n_tables, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_openflow_features_reply_pad, tvb, offset, 3, ENC_NA);
    offset+=3;

    ti = proto_tree_add_item(tree, hf_openflow_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    cap_tree = proto_item_add_subtree(ti, ett_openflow_cap);

    /* Dissect flags */
    proto_tree_add_item(cap_tree, hf_openflow_cap_flow_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_table_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_port_stats,     tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_group_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_ip_reasm,       tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_queue_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_port_blocked,   tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    ti = proto_tree_add_item(tree, hf_openflow_actions, tvb, offset, 4, ENC_BIG_ENDIAN);
    act_tree = proto_item_add_subtree(ti, ett_openflow_act);
    /* Dissect flags */
    proto_tree_add_item(act_tree, hf_openflow_output, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_vlan_vid, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_vlan_pcp, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_strip_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_dl_src, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_dl_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_nw_src, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_nw_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_nw_tos, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_tp_src, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_set_tp_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(act_tree, hf_openflow_enqueue, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    length_remaining = length-32;
    if(length_remaining > 0){
        guint16 num_ports = length_remaining/48;
        int i;
        if((length_remaining&0x003f) != 0){
            /* protocol_error */
        }
        for(i=0; i<num_ports ;i++){
            proto_tree *port_tree;

            port_tree = proto_tree_add_subtree_format(tree, tvb, offset, 48, ett_openflow_port, NULL, "Port data %u",i+1);
            dissect_openflow_phy_port(tvb, pinfo, port_tree, offset);
            offset+=48;
        }
    }

}


static void
dissect_openflow_switch_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{

    /* ofp_config_flags */
    proto_tree_add_item(tree, hf_openflow_config_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    /* miss_send_len */
    proto_tree_add_item(tree, hf_openflow_miss_send_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    /*offset+=2;*/

}

#define OFPR_NO_MATCH       0        /* No matching flow (table-miss flow entry). */
#define OFPR_ACTION         1        /* Action explicitly output to controller. */
#define OFPR_INVALID_TTL    2        /* Packet has invalid TTL */

static const value_string openflow_reason_values[] = {
    { OFPR_NO_MATCH,    "No matching flow (table-miss flow entry)" },
    { OFPR_ACTION,      "Action explicitly output to controller" },
    { OFPR_INVALID_TTL, "Packet has invalid TTL" },
    { 0, NULL }
};

static void
dissect_openflow_pkt_in(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    tvbuff_t *next_tvb;

    /* uint32_t buffer_id;  ID assigned by datapath. */
    proto_tree_add_item(tree, hf_openflow_buffer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    /* uint16_t total_len;  Full length of frame. */
    proto_tree_add_item(tree, hf_openflow_total_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t in_port;  Port on which frame was received. */
    proto_tree_add_item(tree, hf_openflow_in_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t reason; Reason packet is being sent (one of OFPR_*) */
    proto_tree_add_item(tree, hf_openflow_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_openflow_pkt_in_pad, tvb, offset, 1, ENC_NA);
    offset+=1;

    next_tvb = tvb_new_subset_length(tvb, offset, length-offset);
    call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);

}

static void
dissect_openflow_pkt_out(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    tvbuff_t *next_tvb;
    gint32 buffer_id;

    /* uint32_t buffer_id;  ID assigned by datapath. */
    buffer_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_buffer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t in_port; Packet's input port or OFPP_CONTROLLER. */
    proto_tree_add_item(tree, hf_openflow_in_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t actions_len;  Size of action array in bytes. */
    proto_tree_add_item(tree, hf_openflow_actions_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* struct ofp_action_header actions[0];  Action list. */
    offset = dissect_openflow_action_header(tvb, pinfo, tree, offset);
    /* Packet data. The length is inferred
       from the length field in the header.
       (Only meaningful if buffer_id == -1.)
     */
    if(buffer_id == -1){
        next_tvb = tvb_new_subset_length(tvb, offset, length-offset);
        call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
    }
}

#define OFPFC_ADD             0 /* New flow. */
#define OFPFC_MODIFY          1 /* Modify all matching flows. */
#define OFPFC_MODIFY_STRICT   2 /* Modify entry strictly matching wildcards */
#define OFPFC_DELETE          3 /* Delete all matching flows. */
#define OFPFC_DELETE_STRICT   4 /* Strictly match wildcards and priority. */

static const value_string openflow_command_values[] = {
    { OFPFC_ADD,            "New flow" },
    { OFPFC_MODIFY,         "Modify all matching flows" },
    { OFPFC_MODIFY_STRICT,  "Modify entry strictly matching wildcards" },
    { OFPFC_DELETE,         "Delete all matching flows" },
    { OFPFC_DELETE_STRICT,  "Strictly match wildcards and priority" },
    { 0, NULL }
};

static void
dissect_openflow_flow_mod(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 length _U_)
{

    /* struct ofp_match match;  Fields to match */
    offset = dissect_openflow_ofp_match_v1(tvb, pinfo, tree, offset);

    /* uint64_t cookie; Opaque controller-issued identifier. */
    proto_tree_add_item(tree, hf_openflow_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* uint16_t command;  One of OFPFC_*. */
    proto_tree_add_item(tree, hf_openflow_command, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* uint16_t idle_timeout;  Idle time before discarding (seconds). */
    proto_tree_add_item(tree, hf_openflow_idle_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* uint16_t hard_timeout; Max time before discarding (seconds). */
    proto_tree_add_item(tree, hf_openflow_hard_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* uint16_t priority; Priority level of flow entry. */
    proto_tree_add_item(tree, hf_openflow_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* uint32_t buffer_id;  Buffered packet to apply to, or OFP_NO_BUFFER.
       Not meaningful for OFPFC_DELETE*.
     */
    proto_tree_add_item(tree, hf_openflow_buffer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* uint32_t out_port; For OFPFC_DELETE* commands, require
       matching entries to include this as an output port. A value of OFPP_ANY
       indicates no restriction.
       */
    proto_tree_add_item(tree, hf_openflow_out_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* uint16_t flags; One of OFPFF_*. */
    proto_tree_add_item(tree, hf_openflow_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    /*offset+=2;*/
}


#define    OFPST_DESC 0
#define    OFPST_FLOW 1
#define    OFPST_AGGREGATE 2
#define    OFPST_TABLE 3
#define    OFPST_PORT 4
#define    OFPST_QUEUE 5
#define    OFPST_VENDOR  0xffff

static const value_string openflow_stats_type_values[] = {
    { OFPST_DESC,         "OFPST_DESC" },
    { OFPST_FLOW,         "OFPST_FLOW" },
    { OFPST_AGGREGATE,    "OFPST_AGGREGATE" },
    { OFPST_TABLE,        "OFPST_TABLE" },
    { OFPST_PORT,         "OFPST_PORT" },
    { OFPST_QUEUE,        "OFPST_QUEUE" },
    { OFPST_VENDOR,       "OFPST_VENDOR" },
    { 0, NULL }
};
static int
dissect_openflow_stats_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *type_item;
    guint32 type;

    /* uint16_t type; */
    type_item = proto_tree_add_item_ret_uint(tree, hf_openflow_v1_stats_type, tvb, offset, 2, ENC_BIG_ENDIAN, &type);
    offset += 2;
    /* uint16_t flags; OFPSF_REQ_* flags (none yet defined). */
    proto_tree_add_item(tree, hf_openflow_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* uint8_t body[0];  Body of the request. */
    switch (type) {
    case OFPST_DESC:
        /* The request body is empty. */
        break;
    case OFPST_FLOW:
        dissect_openflow_flow_stats_request_v1(tvb, pinfo, tree, offset);
        break;
    default:
        expert_add_info(pinfo, type_item, &ei_openflow_1_0_type);
        break;
    }

    return offset;
}

static int
dissect_openflow_stats_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 length)
{

    proto_item *type_item;
    guint32 type;

    /* uint16_t type; */
    type_item = proto_tree_add_item_ret_uint(tree, hf_openflow_v1_stats_type, tvb, offset, 2, ENC_BIG_ENDIAN, &type);
    offset += 2;
    /* uint16_t flags; OFPSF_REQ_ */
    proto_tree_add_item(tree, hf_openflow_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* uint8_t body[0];  Body of the request. */
    if (length == 12 ) {
        /* No body */
        return offset;
    }
    switch (type) {
    case OFPST_DESC:
        /* The request body is empty. */
        break;
    case OFPST_FLOW:
        /* fall trough */
    default:
        expert_add_info(pinfo, type_item, &ei_openflow_1_0_type);
        break;
    }

    return offset;
}

static int
dissect_openflow_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *type_item;
    proto_tree *openflow_tree;
    guint offset = 0;
    guint8 type;
    guint16 length;

    type    = tvb_get_guint8(tvb, 1);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
                  val_to_str_ext_const(type, &openflow_1_0_type_values_ext, "Unknown message type"));

    /* Stop the Ethernet frame from overwriting the columns */
    if((type == OFPT_1_0_PACKET_IN) || (type == OFPT_1_0_PACKET_OUT)){
        col_set_writable(pinfo->cinfo, -1, FALSE);
    }

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_openflow_v1, tvb, 0, -1, ENC_NA);
    openflow_tree = proto_item_add_subtree(ti, ett_openflow);

    /* A.1 OpenFlow Header. */
    /* OFP_VERSION. */
    proto_tree_add_item(openflow_tree, hf_openflow_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* One of the OFPT_ constants. */
    type_item = proto_tree_add_item(openflow_tree, hf_openflow_1_0_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Length including this ofp_header. */
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(openflow_tree, hf_openflow_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* Transaction id associated with this packet. Replies use the same id as was in the request
     * to facilitate pairing.
     */
    proto_tree_add_item(openflow_tree, hf_openflow_xid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPT_1_0_HELLO: /* 0 */
        /* 5.5.1 Hello
         * The OFPT_HELLO message has no body;
         */
        break;
    case OFPT_1_0_FEATURES_REQUEST: /* 5 */
        /* 5.3.1 Handshake
         * Upon TLS session establishment, the controller sends an OFPT_FEATURES_REQUEST
         * message. This message does not contain a body beyond the OpenFlow header.
         */
        break;
    case OFPT_1_0_FEATURES_REPLY: /* 6 */
        dissect_openflow_features_reply_v1(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_1_0_GET_CONFIG_REQUEST: /* 7 */
        /* A.3.2 There is no body for OFPT_GET_CONFIG_REQUEST beyond the OpenFlow header. */
        break;
    case OFPT_1_0_GET_CONFIG_REPLY: /* 8 */
        /* Fall trough */
    case OFPT_1_0_SET_CONFIG: /* 9 */
        dissect_openflow_switch_config(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_1_0_PACKET_IN: /* 10 */
        dissect_openflow_pkt_in(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_1_0_PACKET_OUT: /* 13 */
        dissect_openflow_pkt_out(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_1_0_FLOW_MOD: /* 14 */
        dissect_openflow_flow_mod(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_1_0_STATS_REQUEST: /* 16 */
        dissect_openflow_stats_req(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_1_0_STATS_REPLY: /* 17 */
        dissect_openflow_stats_resp(tvb, pinfo, openflow_tree, offset, length);
        break;
    default:
        if(length>8){
            expert_add_info(pinfo, type_item, &ei_openflow_1_0_type);
        }
        break;
    }

    return tvb_reported_length(tvb);

}


/*
 * Register the protocol with Wireshark.
 */
void
proto_register_openflow_v1(void)
{
    static hf_register_info hf[] = {
        { &hf_openflow_version,
            { "Version", "openflow.version",
               FT_UINT8, BASE_HEX, VALS(openflow_version_values), 0x7f,
               NULL, HFILL }
        },
        { &hf_openflow_1_0_type,
            { "Type", "openflow_1_0.type",
               FT_UINT8, BASE_DEC | BASE_EXT_STRING, &openflow_1_0_type_values_ext, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_xid,
            { "Transaction ID", "openflow.xid",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_length,
            { "Length", "openflow.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_id,
            { "Datapath unique ID", "openflow.datapath_id",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_mac,
            { "MAC addr", "openflow.datapath_mac",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_impl,
            { "Implementers part", "openflow.datapath_imp",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_n_buffers,
            { "n_buffers", "openflow.n_buffers",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_n_tables,
            { "n_tables", "openflow.n_tables",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
#if 0
        { &hf_openflow_auxiliary_id,
            { "auxiliary_id", "openflow.auxiliary_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
#endif
        { &hf_openflow_capabilities,
            { "capabilities", "openflow.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_actions,
            { "actions", "openflow.actions",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
#if 0
        { &hf_openflow_reserved32,
            { "Reserved", "openflow.reserved32",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
#endif
        { &hf_openflow_cap_flow_stats,
            { "Flow statistics", "openflow.flow_stats",
               FT_BOOLEAN, 32, NULL, OFPC_FLOW_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_table_stats,
            { "Table statistics", "openflow.table_stats",
               FT_BOOLEAN, 32, NULL, OFPC_TABLE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_port_stats,
            { "Port statistics", "openflow.port_stats",
               FT_BOOLEAN, 32, NULL,  OFPC_PORT_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_group_stats,
            { "Group statistics", "openflow.group_stats",
               FT_BOOLEAN, 32, NULL, OFPC_GROUP_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_ip_reasm,
            { "Can reassemble IP fragments", "openflow.ip_reasm",
               FT_BOOLEAN, 32, NULL, OFPC_IP_REASM,
               NULL, HFILL }
        },
        { &hf_openflow_queue_stats,
            { "Queue statistics", "openflow.queue_stats",
               FT_BOOLEAN, 32, NULL, OFPC_QUEUE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_port_blocked,
            { "Switch will block looping ports", "openflow.port_blocked",
               FT_BOOLEAN, 32, NULL, OFPC_PORT_BLOCKED,
               NULL, HFILL }
        },
        { &hf_openflow_output,
            { "Output to switch port", "openflow.output",
               FT_BOOLEAN, 32, NULL, OFPAT_OUTPUT_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_vlan_vid,
            { "Set the 802.1q VLAN id", "openflow.set_vlan_vid",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_VLAN_VID_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_vlan_pcp,
            { "Set the 802.1q priority", "openflow.set_vlan_pcp",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_VLAN_PCP_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_strip_vlan,
            { "Strip the 802.1q header", "openflow.strip_vlan",
               FT_BOOLEAN, 32, NULL, OFPAT_STRIP_VLAN_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_dl_src,
            { "Ethernet source address", "openflow.set_dl_src",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_DL_SRC_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_dl_dst,
            { "Ethernet destination address", "openflow.set_dl_ds",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_DL_DST_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_nw_src,
            { "IP source address", "openflow.set_nw_src",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_NW_SRC_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_nw_dst,
            { "IP destination address", "openflow.set_nw_ds",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_NW_DST_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_nw_tos,
            { "IP ToS (DSCP field, 6 bits)", "openflow.set_nw_tos",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_NW_TOS_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_tp_src,
            { "TCP/UDP source port", "openflow.set_tp_src",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_TP_SRC_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_tp_dst,
            { "TCP/UDP destination port", "openflow.set_tp_dst",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_TP_DST_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_enqueue,
            { "Output to queue", "openflow.enqueue",
               FT_BOOLEAN, 32, NULL, OFPAT_ENQUEUE_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_port_no,
            { "Port number", "openflow.port_no",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_hw_addr,
            { "HW Address", "openflow.hw_add",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_name,
            { "Port Name", "openflow.port_name",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_config,
            { "Config flags", "openflow.port_config",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_state,
            { "State flags", "openflow.port_state",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_curr,
            { "Current features", "openflow.port_curr",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_advertised,
            { "Advertised features", "openflow.port_advertised",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_supported,
            { "Features supported", "openflow.port_supported",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_peer,
            { "Features advertised by peer", "openflow.port_peer",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_down,
            { "Port is administratively down", "openflow.port_down",
               FT_BOOLEAN, 32, NULL, OFPPC_PORT_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_no_stp,
            { "Disable 802.1D spanning tree on port", "openflow.no_stp",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_STP,
               NULL, HFILL }
        },
        { &hf_openflow_no_recv,
            { "Drop all packets except 802.1D spanning tree packets", "openflow.no_recv",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_RECV,
               NULL, HFILL }
        },
        { &hf_openflow_no_recv_stp,
            { "Drop received 802.1D STP packets", "openflow.no_recv_stp",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_RECV_STP,
               NULL, HFILL }
        },
        { &hf_openflow_no_flood,
            { "Do not include this port when flooding", "openflow.no_flood",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_FLOOD,
               NULL, HFILL }
        },
        { &hf_openflow_no_fwd,
            { "Drop packets forwarded to port", "openflow.no_fwd",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_FWD,
               NULL, HFILL }
        },
        { &hf_openflow_no_packet_in,
            { "Do not send packet-in msgs for port", "openflow.no_packet_in",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_PACKET_IN,
               NULL, HFILL }
        },
        { &hf_openflow_link_down,
            { "No physical link present", "openflow.link_down",
               FT_BOOLEAN, 32, NULL, OFPPS_LINK_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_10mb_hd,
            { "10 Mb half-duplex rate support", "openflow.10mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_10mb_fd,
            { "10 Mb full-duplex rate support", "openflow.10mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_100mb_hd,
            { "100 Mb half-duplex rate support", "openflow.100mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_100mb_fd,
            { "100 Mb full-duplex rate support", "openflow.100mb_0fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_1gb_hd,
            { "1 Gb half-duplex rate support", "openflow.1gb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_1gb_fd,
            { "1 Gb full-duplex rate support", "openflow.1gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_10gb_fd,
            { "10 Gb full-duplex rate support", "openflow.10gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_copper,
            { "Copper medium", "openflow.copper",
               FT_BOOLEAN, 32, NULL, OFPPF_COPPER,
               NULL, HFILL }
        },
        { &hf_openflow_fiber,
            { "Fiber medium", "openflow.fiber",
               FT_BOOLEAN, 32, NULL, OFPPF_FIBER,
               NULL, HFILL }
        },
        { &hf_openflow_autoneg,
            { "Auto-negotiation", "openflow.autoneg",
               FT_BOOLEAN, 32, NULL, OFPPF_AUTONEG,
               NULL, HFILL }
        },
        { &hf_openflow_pause,
            { "Pause", "openflow.pause",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE,
               NULL, HFILL }
        },
        { &hf_openflow_pause_asym,
            { "Asymmetric pause", "openflow.pause_asym",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE_ASYM,
               NULL, HFILL }
        },
        { &hf_openflow_config_flags,
            { "Config flags", "openflow.config_flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_miss_send_len,
            { "Max bytes of packet", "openflow.miss_send_len",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_buffer_id,
            { "Buffer Id", "openflow.buffer_id",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_total_len,
            { "Total length", "openflow.total_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_in_port,
            { "In port", "openflow.in_port",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_reason,
            { "Reason", "openflow.reason",
               FT_UINT8, BASE_DEC, VALS(openflow_reason_values), 0x0,
               NULL, HFILL }
        },

        { &hf_openflow_pkt_in_pad,
            { "Pad", "openflow.pkt_in.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_table_id,
            { "Table Id", "openflow.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_cookie,
            { "Cookie", "openflow.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
#if 0
        { &hf_openflow_cookie_mask,
            { "Cookie mask", "openflow.cookie_mask",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
#endif
        { &hf_openflow_features_reply_pad,
            { "Pad", "openflow.features_reply.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_actions_len,
            { "Actions length", "openflow.actions_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_action_type,
            { "Actions type", "openflow.action_typ",
               FT_UINT16, BASE_DEC, VALS(openflow_action_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_action_len,
            { "Action length", "openflow.action_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_output_port,
            { "Output port", "openflow.output_port",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_max_len,
            { "Max length", "openflow.max_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_wildcards,
            { "Wildcards", "openflow.wildcards",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_command,
            { "Command", "openflow.command",
               FT_UINT16, BASE_DEC, VALS(openflow_command_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_eth_src,
            { "Ethernet source address", "openflow.eth_src",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_eth_dst,
            { "Ethernet destination address", "openflow.eth_dst",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_dl_vlan,
            { "Input VLAN id", "openflow.dl_vlan",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_dl_vlan_pcp,
            { "Input VLAN priority", "openflow.dl_vlan_pcp",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_ofp_match_pad,
            { "Pad", "openflow.ofp_match.pad",
              FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_match_dl_type,
            { "Dl type", "openflow.ofp_match.dl_type",
              FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_ofp_match_tos,
            { "IP ToS", "openflow.ofp_match.tos",
              FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_ofp_match_nw_proto,
            { "IP protocol", "openflow.ofp_match.nw_proto",
              FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_ofp_source_addr,
            { "Source Address", "openflow.ofp_match.source_addr",
              FT_IPv4, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_ofp_dest_addr,
            { "Destination Address", "openflow.ofp_match.dest_addr",
              FT_IPv4, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_ofp_source_port,
            { "Source Port", "openflow.ofp_match.source_port",
              FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_ofp_dest_port,
            { "Destination Port", "openflow.ofp_match.dest_port",
              FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_idle_timeout,
            { "Idle time-out", "openflow.idle_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_hard_timeout,
            { "hard time-out", "openflow.hard_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_priority,
            { "Priority", "openflow.priority",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_out_port,
            { "Out port", "openflow.out_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
#if 0
        { &hf_openflow_out_group,
            { "Out group", "openflow.out_group",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
#endif
        { &hf_openflow_flags,
            { "Flags", "openflow.flags",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v1_stats_type,
            { "Type", "openflow.stats.type",
              FT_UINT16, BASE_DEC, VALS(openflow_stats_type_values), 0x0,
              NULL, HFILL }
        },
        { &hf_openflow_v1_flow_stats_request_pad,
            { "Pad", "openflow.stats.request_pad",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_openflow,
        &ett_openflow_path_id,
        &ett_openflow_cap,
        &ett_openflow_act,
        &ett_openflow_port,
        &ett_openflow_port_cnf,
        &ett_openflow_port_state,
        &ett_openflow_port_cf
    };

    static ei_register_info ei[] = {
#if 0
        { &ei_openflow_undecoded_data, { "openflow.undecoded_data", PI_UNDECODED, PI_WARN, "Data not dissected yet", EXPFILL }},
#endif
        { &ei_openflow_action_type, { "openflow.action_typ.undecoded", PI_UNDECODED, PI_WARN, "Action not dissected yet", EXPFILL }},
        { &ei_openflow_1_0_type, { "openflow_1_0.type.undecoded", PI_UNDECODED, PI_WARN, "Message data not dissected yet", EXPFILL }},
    };

    expert_module_t* expert_openflow_v1;

    /* Register the protocol name and description */
    proto_openflow_v1 = proto_register_protocol("OpenFlow 1.0",
            "openflow_v1", "openflow_v1");

    register_dissector("openflow_v1", dissect_openflow_v1, proto_openflow_v1);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_openflow_v1, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_openflow_v1 = expert_register_protocol(proto_openflow_v1);
    expert_register_field_array(expert_openflow_v1, ei, array_length(ei));
}

void
proto_reg_handoff_openflow_v1(void)
{
    eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_openflow_v1);
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
