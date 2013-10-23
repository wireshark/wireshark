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
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include <epan/packet.h>

void proto_register_openflow_v4(void);
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
static int hf_openflow_v4_oxm_value_etheraddr = -1;
static int hf_openflow_v4_oxm_value_ethertype = -1;
static int hf_openflow_v4_oxm_value_ipv4addr = -1;
static int hf_openflow_v4_oxm_value_ipv6addr = -1;
static int hf_openflow_v4_oxm_value_ipproto = -1;
static int hf_openflow_v4_oxm_value_uint16 = -1;
static int hf_openflow_v4_oxm_value_uint24 = -1;
static int hf_openflow_v4_oxm_value_uint32 = -1;
static int hf_openflow_v4_oxm_mask = -1;
static int hf_openflow_v4_oxm_mask_etheraddr = -1;
static int hf_openflow_v4_oxm_mask_ipv4addr = -1;
static int hf_openflow_v4_oxm_mask_ipv6addr = -1;
static int hf_openflow_v4_match_type = -1;
static int hf_openflow_v4_match_length = -1;
static int hf_openflow_v4_match_pad = -1;
static int hf_openflow_v4_action_type = -1;
static int hf_openflow_v4_action_length = -1;
static int hf_openflow_v4_action_output_port = -1;
static int hf_openflow_v4_action_output_port_reserved = -1;
static int hf_openflow_v4_action_output_max_len = -1;
static int hf_openflow_v4_action_output_max_len_reserved = -1;
static int hf_openflow_v4_action_output_pad = -1;
static int hf_openflow_v4_action_copy_ttl_out_pad = -1;
static int hf_openflow_v4_action_copy_ttl_in_pad = -1;
static int hf_openflow_v4_action_set_mpls_ttl_ttl = -1;
static int hf_openflow_v4_action_set_mpls_ttl_pad = -1;
static int hf_openflow_v4_action_dec_mpls_ttl_pad = -1;
static int hf_openflow_v4_action_push_vlan_ethertype = -1;
static int hf_openflow_v4_action_push_vlan_pad = -1;
static int hf_openflow_v4_action_pop_vlan_pad = -1;
static int hf_openflow_v4_action_push_mpls_ethertype = -1;
static int hf_openflow_v4_action_push_mpls_pad = -1;
static int hf_openflow_v4_action_pop_mpls_ethertype = -1;
static int hf_openflow_v4_action_pop_mpls_pad = -1;
static int hf_openflow_v4_action_set_queue_queue_id = -1;
static int hf_openflow_v4_action_group_group_id = -1;
static int hf_openflow_v4_action_group_group_id_reserved = -1;
static int hf_openflow_v4_action_set_nw_ttl_ttl = -1;
static int hf_openflow_v4_action_set_nw_ttl_pad = -1;
static int hf_openflow_v4_action_dec_nw_ttl_pad = -1;
static int hf_openflow_v4_action_set_field_pad = -1;
static int hf_openflow_v4_action_push_pbb_ethertype = -1;
static int hf_openflow_v4_action_push_pbb_pad = -1;
static int hf_openflow_v4_action_pop_pbb_pad = -1;
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
static int hf_openflow_v4_hello_element_type = -1;
static int hf_openflow_v4_hello_element_length = -1;
static int hf_openflow_v4_hello_element_version_bitmap = -1;
static int hf_openflow_v4_hello_element_pad = -1;
static int hf_openflow_v4_error_type = -1;
static int hf_openflow_v4_error_hello_failed_code = -1;
static int hf_openflow_v4_error_bad_request_code = -1;
static int hf_openflow_v4_error_bad_action_code = -1;
static int hf_openflow_v4_error_bad_instruction_code = -1;
static int hf_openflow_v4_error_bad_match_code = -1;
static int hf_openflow_v4_error_flow_mod_failed_code = -1;
static int hf_openflow_v4_error_group_mod_failed_code = -1;
static int hf_openflow_v4_error_port_mod_failed_code = -1;
static int hf_openflow_v4_error_table_mod_failed_code = -1;
static int hf_openflow_v4_error_queue_op_failed_code = -1;
static int hf_openflow_v4_error_switch_config_failed_code = -1;
static int hf_openflow_v4_error_role_request_failed_code = -1;
static int hf_openflow_v4_error_meter_mod_failed_code = -1;
static int hf_openflow_v4_error_table_features_failed_code = -1;
static int hf_openflow_v4_error_code = -1;
static int hf_openflow_v4_error_data_text = -1;
static int hf_openflow_v4_error_data_body = -1;
static int hf_openflow_v4_error_experimenter = -1;
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
static int hf_openflow_v4_bucket_length = -1;
static int hf_openflow_v4_bucket_weight = -1;
static int hf_openflow_v4_bucket_watch_port = -1;
static int hf_openflow_v4_bucket_watch_port_reserved = -1;
static int hf_openflow_v4_bucket_watch_group = -1;
static int hf_openflow_v4_bucket_watch_group_reserved = -1;
static int hf_openflow_v4_bucket_pad = -1;
static int hf_openflow_v4_groupmod_command = -1;
static int hf_openflow_v4_groupmod_type = -1;
static int hf_openflow_v4_groupmod_pad = -1;
static int hf_openflow_v4_groupmod_group_id = -1;
static int hf_openflow_v4_groupmod_group_id_reserved = -1;
static int hf_openflow_v4_multipart_type = -1;
static int hf_openflow_v4_multipart_request_flags = -1;
static int hf_openflow_v4_multipart_reply_flags = -1;
static gint ett_openflow_v4 = -1;
static gint ett_openflow_v4_path_id = -1;
static gint ett_openflow_v4_cap = -1;
static gint ett_openflow_v4_flowmod_flags = -1;
static gint ett_openflow_v4_flowmod_instructions = -1;
static gint ett_openflow_v4_bucket = -1;
static gint ett_openflow_v4_bucket_actions = -1;
static gint ett_openflow_v4_groupmod_buckets = -1;
static gint ett_openflow_v4_oxm = -1;
static gint ett_openflow_v4_match = -1;
static gint ett_openflow_v4_match_oxm_fields = -1;
static gint ett_openflow_v4_action = -1;
static gint ett_openflow_v4_instruction = -1;
static gint ett_openflow_v4_instruction_actions_actions = -1;
static gint ett_openflow_v4_hello_element = -1;
static gint ett_openflow_v4_error_data = -1;

static expert_field ei_openflow_v4_match_undecoded = EI_INIT;
static expert_field ei_openflow_v4_oxm_undecoded = EI_INIT;
static expert_field ei_openflow_v4_action_undecoded = EI_INIT;
static expert_field ei_openflow_v4_instruction_undecoded = EI_INIT;
static expert_field ei_openflow_v4_hello_element_undecoded = EI_INIT;
static expert_field ei_openflow_v4_error_undecoded = EI_INIT;

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

static int
dissect_openflow_header_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint8_t version; */
    proto_tree_add_item(tree, hf_openflow_v4_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* uint8_t type; */
    proto_tree_add_item(tree, hf_openflow_v4_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* uint16_t length; */
    proto_tree_add_item(tree, hf_openflow_v4_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t xid; */
    proto_tree_add_item(tree, hf_openflow_v4_xid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    return offset;
}

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

#define OFPXMT_OFB_IN_PORT          0
#define OFPXMT_OFB_IN_PHY_PORT      1
#define OFPXMT_OFB_METADATA         2
#define OFPXMT_OFB_ETH_DST          3
#define OFPXMT_OFB_ETH_SRC          4
#define OFPXMT_OFB_ETH_TYPE         5
#define OFPXMT_OFB_VLAN_VID         6
#define OFPXMT_OFB_VLAN_PCP         7
#define OFPXMT_OFB_IP_DSCP          8
#define OFPXMT_OFB_IP_ECN           9
#define OFPXMT_OFB_IP_PROTO        10
#define OFPXMT_OFB_IPV4_SRC        11
#define OFPXMT_OFB_IPV4_DST        12
#define OFPXMT_OFB_TCP_SRC         13
#define OFPXMT_OFB_TCP_DST         14
#define OFPXMT_OFB_UDP_SRC         15
#define OFPXMT_OFB_UDP_DST         16
#define OFPXMT_OFB_SCTP_SRC        17
#define OFPXMT_OFB_SCTP_DST        18
#define OFPXMT_OFB_ICMPV4_TYPE     19
#define OFPXMT_OFB_ICMPV4_CODE     20
#define OFPXMT_OFB_ARP_OP          21
#define OFPXMT_OFB_ARP_SPA         22
#define OFPXMT_OFB_ARP_TPA         23
#define OFPXMT_OFB_ARP_SHA         24
#define OFPXMT_OFB_ARP_THA         25
#define OFPXMT_OFB_IPV6_SRC        26
#define OFPXMT_OFB_IPV6_DST        27
#define OFPXMT_OFB_IPV6_FLABEL     28
#define OFPXMT_OFB_ICMPV6_TYPE     29
#define OFPXMT_OFB_ICMPV6_CODE     30
#define OFPXMT_OFB_IPV6_ND_TARGET  31
#define OFPXMT_OFB_IPV6_ND_SLL     32
#define OFPXMT_OFB_IPV6_ND_TLL     33
#define OFPXMT_OFB_MPLS_LABEL      34
#define OFPXMT_OFB_MPLS_TC         35
#define OFPXMT_OFP_MPLS_BOS        36
#define OFPXMT_OFB_PBB_ISID        37
#define OFPXMT_OFB_TUNNEL_ID       38
#define OFPXMT_OFB_IPV6_EXTHDR     39
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
    guint16 oxm_class;
    guint8  oxm_field_hm;
    guint8  oxm_hm;
    guint8  oxm_field;
    guint8  oxm_length;
    guint8  field_length;

    oxm_class = tvb_get_ntohs(tvb, offset);
    oxm_field_hm = tvb_get_guint8(tvb, offset + 2);
    oxm_length = tvb_get_guint8(tvb, offset + 3);

    oxm_field = (oxm_field_hm & OXM_FIELD_MASK) >> OXM_FIELD_OFFSET;
    oxm_hm = oxm_field_hm & OXM_HM_MASK;
    field_length = (oxm_hm == 0) ? oxm_length : (oxm_length / 2);

    ti = proto_tree_add_text(tree, tvb, offset, oxm_length + 4, "OXM");
    oxm_tree = proto_item_add_subtree(ti, ett_openflow_v4_oxm);

    offset = dissect_openflow_oxm_header_v4(tvb, pinfo, oxm_tree, offset, length);

    if (oxm_class == OFPXMC_OPENFLOW_BASIC) {
        switch(oxm_field) {
        case OFPXMT_OFB_IN_PORT:
        case OFPXMT_OFB_IN_PHY_PORT:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;

        case OFPXMT_OFB_ETH_DST:
        case OFPXMT_OFB_ETH_SRC:
        case OFPXMT_OFB_ARP_SHA:
        case OFPXMT_OFB_ARP_THA:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_etheraddr, tvb, offset, 6, ENC_BIG_ENDIAN);
            offset+=6;
            if (oxm_hm) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask_etheraddr, tvb, offset, 6, ENC_BIG_ENDIAN);
                offset+=6;
            }
            break;

        case OFPXMT_OFB_ETH_TYPE:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            break;

        case OFPXMT_OFB_IP_PROTO:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ipproto, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            break;

        case OFPXMT_OFB_IPV4_SRC:
        case OFPXMT_OFB_IPV4_DST:
        case OFPXMT_OFB_ARP_SPA:
        case OFPXMT_OFB_ARP_TPA:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ipv4addr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            if (oxm_hm) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask_ipv4addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
            }
            break;

        case OFPXMT_OFB_TCP_SRC:
        case OFPXMT_OFB_TCP_DST:
        case OFPXMT_OFB_UDP_SRC:
        case OFPXMT_OFB_UDP_DST:
        case OFPXMT_OFB_SCTP_SRC:
        case OFPXMT_OFB_SCTP_DST:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            break;

        case OFPXMT_OFB_IPV6_SRC:
        case OFPXMT_OFB_IPV6_DST:
        case OFPXMT_OFB_IPV6_ND_SLL:
        case OFPXMT_OFB_IPV6_ND_TLL:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ipv6addr, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset+=16;
            if (oxm_hm) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask_ipv6addr, tvb, offset, 16, ENC_BIG_ENDIAN);
                offset+=16;
            }
            break;

        case OFPXMT_OFB_MPLS_LABEL:
            /* size differs in specification and header file */
            if (field_length == 3) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint24, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset+=3;
            } else if (field_length == 4) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
            }
            break;

        default:
            /* value */
            if (field_length > 0) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value, tvb, offset, field_length, ENC_BIG_ENDIAN);
                offset += field_length;
            }

            /* mask */
            if (field_length > 0 && oxm_hm != 0) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask, tvb, offset, field_length, ENC_BIG_ENDIAN);
                offset += field_length;
            }
            break;
        }

    } else {
        proto_tree_add_expert_format(oxm_tree, pinfo, &ei_openflow_v4_oxm_undecoded,
                                     tvb, offset, oxm_length, "Unknown OXM body.");
        offset+=oxm_length;
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
                                     tvb, offset, match_length - 4, "Standard match body (deprecated).");
        offset+=match_length-4;
        break;

    case OFPMT_OXM:
        fields_end = offset + match_length - 4;

        if (offset < fields_end) {
            ti = proto_tree_add_text(match_tree, tvb, offset, match_length - 4, "Fields");
            fields_tree = proto_item_add_subtree(ti, ett_openflow_v4_match_oxm_fields);
            while(offset < fields_end) {
                offset = dissect_openflow_oxm_v4(tvb, pinfo, fields_tree, offset, length);
            }
        }
        break;

    default:
        proto_tree_add_expert_format(match_tree, pinfo, &ei_openflow_v4_match_undecoded,
                                     tvb, offset, match_length - 4, "Unknown match body.");
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


#define OFPHET_VERSIONBITMAP  1
static const value_string openflow_v4_hello_element_type_values[] = {
    { 1, "OFPHET_VERSIONBITMAP" },
    { 0, NULL }
};

static int
dissect_openflow_hello_element_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *elem_tree;
    guint16 elem_type;
    guint16 elem_length;
    guint16 pad_length;

    ti = proto_tree_add_text(tree, tvb, offset, length - offset, "Element");
    elem_tree = proto_item_add_subtree(ti, ett_openflow_v4_hello_element);

    /* uint16_t type; */
    elem_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(elem_tree, hf_openflow_v4_hello_element_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; */
    elem_length = tvb_get_ntohs(tvb, offset);
    pad_length = (elem_length + 7)/8*8 - elem_length;
    proto_tree_add_item(elem_tree, hf_openflow_v4_hello_element_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    switch (elem_type) {
    case OFPHET_VERSIONBITMAP:
        /* bitmap */
        proto_tree_add_item(elem_tree, hf_openflow_v4_hello_element_version_bitmap, tvb, offset, elem_length - 4, ENC_NA);
        offset += elem_length - 4;
        break;

    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_hello_element_undecoded,
                                     tvb, offset, elem_length - 4, "Unknown hello element body.");
        offset += elem_length - 4;
        break;
    }

    if (pad_length > 0) {
        proto_tree_add_item(tree, hf_openflow_v4_hello_element_pad, tvb, offset, pad_length, ENC_NA);
        offset+=pad_length;
    }

    return offset;
}

static void
dissect_openflow_hello_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{

    while (offset < length) {
        offset = dissect_openflow_hello_element_v4(tvb, pinfo, tree, offset, length);
    }
}


#define OFPET_HELLO_FAILED            0
#define OFPET_BAD_REQUEST             1
#define OFPET_BAD_ACTION              2
#define OFPET_BAD_INSTRUCTION         3
#define OFPET_BAD_MATCH               4
#define OFPET_FLOW_MOD_FAILED         5
#define OFPET_GROUP_MOD_FAILED        6
#define OFPET_PORT_MOD_FAILED         7
#define OFPET_TABLE_MOD_FAILED        8
#define OFPET_QUEUE_OP_FAILED         9
#define OFPET_SWITCH_CONFIG_FAILED   10
#define OFPET_ROLE_REQUEST_FAILED    11
#define OFPET_METER_MOD_FAILED       12
#define OFPET_TABLE_FEATURES_FAILED  13
#define OFPET_EXPERIMENTER           0xffff
static const value_string openflow_v4_error_type_values[] = {
    {      0, "OFPET_HELLO_FAILED" },
    {      1, "OFPET_BAD_REQUEST" },
    {      2, "OFPET_BAD_ACTION" },
    {      3, "OFPET_BAD_INSTRUCTION" },
    {      4, "OFPET_BAD_MATCH" },
    {      5, "OFPET_FLOW_MOD_FAILED" },
    {      6, "OFPET_GROUP_MOD_FAILED" },
    {      7, "OFPET_PORT_MOD_FAILED" },
    {      8, "OFPET_TABLE_MOD_FAILED" },
    {      9, "OFPET_QUEUE_OP_FAILED" },
    {     10, "OFPET_SWITCH_CONFIG_FAILED" },
    {     11, "OFPET_ROLE_REQUEST_FAILED" },
    {     12, "OFPET_METER_MOD_FAILED" },
    {     13, "OFPET_TABLE_FEATURES_FAILED" },
    { 0xffff, "OFPET_EXPERIMENTER" },
    {      0, NULL}
};

static const value_string openflow_v4_error_hello_failed_code_values[] = {
    { 0, "OFPHFC_INCOMPATIBLE" },
    { 1, "OFPHFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_bad_request_code_values[] =  {
    {  0, "OFPBRC_BAD_VERSION" },
    {  1, "OFPBRC_BAD_TYPE" },
    {  2, "OFPBRC_BAD_MULTIPART" },
    {  3, "OFPBRC_BAD_EXPERIMENTER" },
    {  4, "OFPBRC_BAD_EXP_TYPE" },
    {  5, "OFPBRC_EPERM" },
    {  6, "OFPBRC_BAD_LEN" },
    {  7, "OFPBRC_BUFFER_EMPTY" },
    {  8, "OFPBRC_BUFFER_UNKNOWN" },
    {  9, "OFPBRC_BAD_TABLE_ID" },
    { 10, "OFPBRC_IS_SLAVE" },
    { 11, "OFPBRC_BAD_PORT" },
    { 12, "OFPBRC_BAD_PACKET" },
    { 13, "OFPBRC_MULTIPART_BUFFER_OVERFLOW" },
    {  0, NULL }
};

static const value_string openflow_v4_error_bad_action_code_values[] =  {
    {  0, "OFPBAC_BAD_TYPE" },
    {  1, "OFPBAC_BAD_LEN" },
    {  2, "OFPBAC_BAD_EXPERIMENTER" },
    {  3, "OFPBAC_BAD_EXP_TYPE" },
    {  4, "OFPBAC_BAD_OUT_PORT" },
    {  5, "OFPBAC_BAD_ARGUMENT" },
    {  6, "OFPBAC_EPERM" },
    {  7, "OFPBAC_TOO_MANY" },
    {  8, "OFPBAC_BAD_QUEUE" },
    {  9, "OFPBAC_BAD_OUT_GROUP" },
    { 10, "OFPBAC_MATCH_INCONSISTENT" },
    { 11, "OFPBAC_UNSUPPORTED_ORDER" },
    { 12, "OFPBAC_BAD_TAG" },
    { 13, "OFPBAC_BAD_SET_TYPE" },
    { 14, "OFPBAC_BAD_SET_LEN" },
    { 15, "OFPBAC_BAD_SET_ARGUMENT" },
    {  0, NULL }
};

static const value_string openflow_v4_error_bad_instruction_code_values[] =  {
    { 0, "OFPBIC_UNKNOWN_INST" },
    { 1, "OFPBIC_UNSUP_INST" },
    { 2, "OFPBIC_BAD_TABLE_ID" },
    { 3, "OFPBIC_UNSUP_METADATA" },
    { 4, "OFPBIC_UNSUP_METADATA_MASK" },
    { 5, "OFPBIC_BAD_EXPERIMENTER" },
    { 6, "OFPBIC_BAD_EXP_TYPE" },
    { 7, "OFPBIC_BAD_LEN" },
    { 8, "OFPBIC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_bad_match_code_values[] =  {
    {  0, "OFPBMC_BAD_TYPE" },
    {  1, "OFPBMC_BAD_LEN" },
    {  2, "OFPBMC_BAD_TAG" },
    {  3, "OFPBMC_BAD_DL_ADDR_MASK" },
    {  4, "OFPBMC_BAD_NW_ADDR_MASK" },
    {  5, "OFPBMC_BAD_WILDCARDS" },
    {  6, "OFPBMC_BAD_FIELD" },
    {  7, "OFPBMC_BAD_VALUE" },
    {  8, "OFPBMC_BAD_MASK" },
    {  9, "OFPBMC_BAD_PREREQ" },
    { 10, "OFPBMC_DUP_FIELD" },
    { 11, "OFPBMC_EPERM" },
    {  0, NULL }
};

static const value_string openflow_v4_error_flow_mod_failed_code_values[] =  {
    { 0, "OFPFMFC_UNKNOWN" },
    { 1, "OFPFMFC_TABLE_FULL" },
    { 2, "OFPFMFC_BAD_TABLE_ID" },
    { 3, "OFPFMFC_OVERLAP" },
    { 4, "OFPFMFC_EPERM" },
    { 5, "OFPFMFC_BAD_TIMEOUT" },
    { 6, "OFPFMFC_BAD_COMMAND" },
    { 7, "OFPFMFC_BAD_FLAGS" },
    { 0, NULL }
};

static const value_string openflow_v4_error_group_mod_failed_code_values[] =  {
    {  0, "OFPGMFC_GROUP_EXISTS" },
    {  1, "OFPGMFC_INVALID_GROUP" },
    {  2, "OFPGMFC_WEIGHT_UNSUPPORTED" },
    {  3, "OFPGMFC_OUT_OF_GROUPS" },
    {  4, "OFPGMFC_OUT_OF_BUCKETS" },
    {  5, "OFPGMFC_CHAINING_UNSUPPORTED" },
    {  6, "OFPGMFC_WATCH_UNSUPPORTED" },
    {  7, "OFPGMFC_LOOP" },
    {  8, "OFPGMFC_UNKNOWN_GROUP" },
    {  9, "OFPGMFC_CHAINED_GROUP" },
    { 10, "OFPGMFC_BAD_TYPE" },
    { 11, "OFPGMFC_BAD_COMMAND" },
    { 12, "OFPGMFC_BAD_BUCKET" },
    { 13, "OFPGMFC_BAD_WATCH" },
    { 14, "OFPGMFC_EPERM" },
    {  0, NULL }
};

static const value_string openflow_v4_error_port_mod_failed_code_values[] =  {
    { 0, "OFPPMFC_BAD_PORT" },
    { 1, "OFPPMFC_BAD_HW_ADDR" },
    { 2, "OFPPMFC_BAD_CONFIG" },
    { 3, "OFPPMFC_BAD_ADVERTISE" },
    { 4, "OFPPMFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_table_mod_failed_code_values[] =  {
    { 0, "OFPTMFC_BAD_TABLE" },
    { 1, "OFPTMFC_BAD_CONFIG" },
    { 2, "OFPTMFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_queue_op_failed_code_values[] =  {
    { 0, "OFPQOFC_BAD_PORT" },
    { 1, "OFPQOFC_BAD_QUEUE" },
    { 2, "OFPQOFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_switch_config_failed_code_values[] =  {
    { 0, "OFPSCFC_BAD_FLAGS" },
    { 1, "OFPSCFC_BAD_LEN" },
    { 2, "OFPQCFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_role_request_failed_code_values[] =  {
    { 0, "OFPRRFC_STALE" },
    { 1, "OFPRRFC_UNSUP" },
    { 2, "OFPRRFC_BAD_ROLE" },
    { 0, NULL }
};

static const value_string openflow_v4_error_meter_mod_failed_code_values[] =  {
    {   0, "OFPMMFC_UNKNOWN" },
    {   1, "OFPMMFC_METER_EXISTS" },
    {   2, "OFPMMFC_INVALID_METER" },
    {   3, "OFPMMFC_UNKNOWN_METER" },
    {   4, "OFPMMFC_BAD_COMMAND" },
    {   5, "OFPMMFC_BAD_FLAGS" },
    {   6, "OFPMMFC_BAD_RATE" },
    {   7, "OFPMMFC_BAD_BURST" },
    {   8, "OFPMMFC_BAD_BAND" },
    {   9, "OFPMMFC_BAD_BAND_VALUE" },
    {  10, "OFPMMFC_OUT_OF_METERS" },
    {  11, "OFPMMFC_OUT_OF_BANDS" },
    {  0, NULL }
};

static const value_string openflow_v4_error_table_features_failed_code_values[] =  {
    { 0, "OFPTFFC_BAD_TABLE" },
    { 1, "OFPTFFC_BAD_METADATA" },
    { 2, "OFPTFFC_BAD_TYPE" },
    { 3, "OFPTFFC_BAD_LEN" },
    { 4, "OFPTFFC_BAD_ARGUMENT" },
    { 5, "OFPTFFC_EPERM" },
    { 0, NULL }
};

static void
dissect_openflow_error_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *data_tree;
    guint16 error_type;

    /* uint16_t type; */
    error_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_error_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset +=2;

    /* uint16_t code; */
    switch(error_type) {
    case OFPET_HELLO_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_hello_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_REQUEST:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_request_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_ACTION:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_action_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_INSTRUCTION:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_instruction_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_MATCH:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_match_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_FLOW_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_flow_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_GROUP_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_group_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_PORT_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_port_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_TABLE_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_table_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_QUEUE_OP_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_queue_op_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_SWITCH_CONFIG_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_switch_config_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_ROLE_REQUEST_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_role_request_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_METER_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_meter_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_TABLE_FEATURES_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_table_features_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_EXPERIMENTER:
    default:
        proto_tree_add_item(tree, hf_openflow_v4_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    }
    offset +=2;

    switch(error_type) {
    case OFPET_HELLO_FAILED:
        /* uint8_t data[0]; contains an ASCII text string */
        proto_tree_add_item(tree, hf_openflow_v4_error_data_text, tvb, offset, length - 12, ENC_NA|ENC_ASCII);
        /*offset += length - 12;*/
        break;

    case OFPET_BAD_REQUEST:
    case OFPET_BAD_ACTION:
    case OFPET_BAD_INSTRUCTION:
    case OFPET_BAD_MATCH:
    case OFPET_FLOW_MOD_FAILED:
    case OFPET_GROUP_MOD_FAILED:
    case OFPET_PORT_MOD_FAILED:
    case OFPET_TABLE_MOD_FAILED:
    case OFPET_QUEUE_OP_FAILED:
    case OFPET_SWITCH_CONFIG_FAILED:
    case OFPET_ROLE_REQUEST_FAILED:
    case OFPET_METER_MOD_FAILED:
    case OFPET_TABLE_FEATURES_FAILED:
        /* uint8_t data[0]; contains at least the first 64 bytes of the failed request. */
        ti = proto_tree_add_text(tree, tvb, offset, length - offset, "Data");
        data_tree = proto_item_add_subtree(ti, ett_openflow_v4_error_data);

        offset = dissect_openflow_header_v4(tvb, pinfo, data_tree, offset, length);

        proto_tree_add_item(data_tree, hf_openflow_v4_error_data_body, tvb, offset, length - 20, ENC_NA);
        /*offset += length - 12;*/
        break;

    case OFPET_EXPERIMENTER:
        /* uint32_t experimenter */
        proto_tree_add_item(tree, hf_openflow_v4_error_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        /* uint8_t data[0]; */
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_error_undecoded,
                                     tvb, offset, length - 16, "Experimenter error body.");
        /*offset += length - 16;*/
        break;

    default:
        /* uint8_t data[0]; */
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_error_undecoded,
                                     tvb, offset, length - 12, "Unknown error body.");
        /*offset += length - 12;*/
        break;
    }
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

#define OFPAT_OUTPUT         0  /* Output to switch port. */
#define OFPAT_COPY_TTL_OUT  11  /* Copy TTL "outwards" */
#define OFPAT_COPY_TTL_IN   12  /* Copy TTL "inwards" */
#define OFPAT_SET_MPLS_TTL  15  /* MPLS TTL */
#define OFPAT_DEC_MPLS_TTL  16  /* Decrement MPLS TTL */
#define OFPAT_PUSH_VLAN     17  /* Push a new VLAN tag */
#define OFPAT_POP_VLAN      18  /* Pop the outer VLAN tag */
#define OFPAT_PUSH_MPLS     19  /* Push a new MPLS tag */
#define OFPAT_POP_MPLS      20  /* Pop the outer MPLS tag */
#define OFPAT_SET_QUEUE     21  /* Set queue id when outputting to a port */
#define OFPAT_GROUP         22  /* Apply group. */
#define OFPAT_SET_NW_TTL    23  /* IP TTL. */
#define OFPAT_DEC_NW_TTL    24  /* Decrement IP TTL. */
#define OFPAT_SET_FIELD     25  /* Set a header field using OXM TLV format. */
#define OFPAT_PUSH_PBB      26  /* Push a new PBB service tag (I-TAG) */
#define OFPAT_POP_PBB       27  /* Pop the outer PBB service tag (I-TAG) */
#define OFPAT_EXPERIMENTER  0xffff

static const value_string openflow_v4_action_type_values[] = {
    {      0, "OFPAT_OUTPUT" },
    {     11, "OFPAT_COPY_TTL_OUT" },
    {     12, "OFPAT_COPY_TTL_IN" },
    {     15, "OFPAT_SET_MPLS_TTL" },
    {     16, "OFPAT_DEC_MPLS_TTL" },
    {     17, "OFPAT_PUSH_VLAN" },
    {     18, "OFPAT_POP_VLAN" },
    {     19, "OFPAT_PUSH_MPLS" },
    {     20, "OFPAT_POP_MPLS" },
    {     21, "OFPAT_SET_QUEUE" },
    {     22, "OFPAT_GROUP" },
    {     23, "OFPAT_SET_NW_TTL" },
    {     24, "OFPAT_DEC_NW_TTL" },
    {     25, "OFPAT_SET_FIELD" },
    {     26, "OFPAT_PUSH_PBB" },
    {     27, "OFPAT_POP_PBB" },
    { 0xffff, "OFPAT_EXPERIMENTER" },
    { 0,      NULL}
};

#define OFPCML_MAX   0xffe5  /* Maximum max_len value. */
static const value_string openflow_v4_action_output_max_len_reserved_values[] = {
    { 0xffff, "OFPCML_NO_BUFFER" },
    { 0,          NULL }
};

static int
dissect_openflow_action_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *act_tree;
    guint16 act_type;
    guint16 act_length;
    guint16 act_end;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Action");
    act_tree = proto_item_add_subtree(ti, ett_openflow_v4_action);

    /* uint16_t type; */
    act_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(act_tree, hf_openflow_v4_action_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; */
    act_length = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, act_length);
    proto_tree_add_item(act_tree, hf_openflow_v4_action_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    switch (act_type) {
    case OFPAT_OUTPUT:
        /* uint32_t port; */
        if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_port, tvb, offset, 4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset+=4;

        /* uint16_t max_len; */
        if (tvb_get_ntohs(tvb, offset) <= OFPCML_MAX) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_max_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_max_len_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset+=2;

        /* uint8_t pad[6]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_output_pad, tvb, offset, 6, ENC_BIG_ENDIAN);
        offset+=6;

        break;

    case OFPAT_COPY_TTL_OUT:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_copy_ttl_out_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_COPY_TTL_IN:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_copy_ttl_in_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_SET_MPLS_TTL:
        /* uint8_t mpls_ttl; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_mpls_ttl_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* uint8_t pad[3]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_mpls_ttl_pad, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
        break;

    case OFPAT_DEC_MPLS_TTL:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_dec_mpls_ttl_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_PUSH_VLAN:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_vlan_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_vlan_pad, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        break;

    case OFPAT_POP_VLAN:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_vlan_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_PUSH_MPLS:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_mpls_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_mpls_pad, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        break;

    case OFPAT_POP_MPLS:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_mpls_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_mpls_pad, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        break;

    case OFPAT_SET_QUEUE:
        /* uint32_t queue_id; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_queue_queue_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_GROUP:
        /* uint32_t group_id; */
        if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_group_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_group_group_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset+=4;
        break;

    case OFPAT_SET_NW_TTL:
        /* uint8_t nw_ttl; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_nw_ttl_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* uint8_t pad[3]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_nw_ttl_pad, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
        break;

    case OFPAT_DEC_NW_TTL:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_dec_nw_ttl_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_SET_FIELD:
        act_end = offset + act_length - 4;
        offset = dissect_openflow_oxm_v4(tvb, pinfo, act_tree, offset, length);

        /* padded to 64 bits */
        if (offset < act_end) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_set_field_pad, tvb, offset, act_end - offset, ENC_BIG_ENDIAN);
            offset = act_end;
        }
        break;

    case OFPAT_PUSH_PBB:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_pbb_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_pbb_pad, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        break;

    case OFPAT_POP_PBB:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_pbb_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_EXPERIMENTER:
        proto_tree_add_expert_format(act_tree, pinfo, &ei_openflow_v4_action_undecoded,
                                     tvb, offset, act_length - 4, "Experimenter action body.");
        offset += act_length - 4;
        break;

    default:
        proto_tree_add_expert_format(act_tree, pinfo, &ei_openflow_v4_action_undecoded,
                                     tvb, offset, act_length - 4, "Unknown action body.");
        offset += act_length - 4;
        break;
    }

    return offset;
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
    guint16 acts_end;

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
    case OFPIT_APPLY_ACTIONS:
    case OFPIT_CLEAR_ACTIONS:
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_actions_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        acts_end = offset + inst_length - 8;

        if (offset < acts_end) {
            ti = proto_tree_add_text(inst_tree, tvb, offset, inst_length - 8, "Actions");
            actions_tree = proto_item_add_subtree(ti, ett_openflow_v4_instruction_actions_actions);

            while (offset < acts_end) {
                offset = dissect_openflow_action_v4(tvb, pinfo, actions_tree, offset, length);
            }
        }
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
                                     tvb, offset, inst_length - 4, "Experimenter instruction body.");
        offset += inst_length - 4;
        break;

    default:
        proto_tree_add_expert_format(inst_tree, pinfo, &ei_openflow_v4_instruction_undecoded,
                                     tvb, offset, inst_length - 4, "Unknown instruction body.");
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

static int
dissect_openflow_bucket_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *bucket_tree, *actions_tree;
    guint16 bucket_length;
    guint16 acts_end;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Bucket");
    bucket_tree = proto_item_add_subtree(ti, ett_openflow_v4_bucket);

    /* uint16_t len; */
    bucket_length = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, bucket_length);
    proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t weight; */
    proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_weight, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t watch_port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t watch_group; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_group_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /*struct ofp_action_header actions[0]; */
    acts_end = offset + bucket_length - 16;

    if (offset < acts_end) {
        ti = proto_tree_add_text(bucket_tree, tvb, offset, bucket_length - 16, "Actions");
        actions_tree = proto_item_add_subtree(ti, ett_openflow_v4_bucket_actions);

        while (offset < acts_end) {
            offset = dissect_openflow_action_v4(tvb, pinfo, actions_tree, offset, length);
        }
    }

    return offset;
}


static const value_string openflow_v4_groupmod_command_values[] = {
    { 0, "OFPGC_ADD" },
    { 1, "OFPGC_MODIFY" },
    { 2, "OFPGC_DELETE" },
    { 0, NULL }
};

static const value_string openflow_v4_group_type_values[] = {
    { 0, "OFPGT_ALL" },
    { 1, "OFPGT_SELECT" },
    { 2, "OFPGT_INDIRECT" },
    { 3, "OFPGT_FF" },
    { 0, NULL }
};

static void
dissect_openflow_groupmod_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *buckets_tree;

    /* uint16_t command; */
    proto_tree_add_item(tree, hf_openflow_v4_groupmod_command, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t type; */
    proto_tree_add_item(tree, hf_openflow_v4_groupmod_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t pad; */
    proto_tree_add_item(tree, hf_openflow_v4_groupmod_pad, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint32_t group_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_groupmod_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_groupmod_group_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* struct ofp_bucket buckets[0]; */
    if (offset < length) {
        ti = proto_tree_add_text(tree, tvb, offset, length - offset, "Buckets");
        buckets_tree = proto_item_add_subtree(ti, ett_openflow_v4_groupmod_buckets);

        while (offset < length) {
            offset = dissect_openflow_bucket_v4(tvb, pinfo, buckets_tree, offset, length);
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

    type   = tvb_get_guint8(tvb, 1);
    length = tvb_get_ntohs(tvb, 2);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
                  val_to_str_const(type, openflow_v4_type_values, "Unknown Messagetype"));

    /* Stop the Ethernet frame from overwriting the columns */
    if((type == OFPT_V4_PACKET_IN) || (type == OFPT_V4_PACKET_OUT)){
        col_set_writable(pinfo->cinfo, FALSE);
    }

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_openflow_v4, tvb, 0, -1, ENC_NA);
    openflow_tree = proto_item_add_subtree(ti, ett_openflow_v4);

    offset = dissect_openflow_header_v4(tvb, pinfo, openflow_tree, offset, length);

    switch(type){
    case OFPT_V4_HELLO: /* 0 */
        dissect_openflow_hello_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    case OFPT_V4_ERROR: /* 1 */
        dissect_openflow_error_v4(tvb, pinfo, openflow_tree, offset, length);
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

    case OFPT_V4_GROUP_MOD: /* 15 */
        dissect_openflow_groupmod_v4(tvb, pinfo, openflow_tree, offset, length);
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
        { &hf_openflow_v4_oxm_value_etheraddr,
            { "Value", "openflow_v4.oxm.value",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ethertype,
            { "Value", "openflow_v4.oxm.value",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ipv4addr,
            { "Value", "openflow_v4.oxm.value",
               FT_IPv4, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ipv6addr,
            { "Value", "openflow_v4.oxm.value",
               FT_IPv6, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ipproto,
            { "Value", "openflow_v4.oxm.value",
               FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&ipproto_val_ext), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_uint16,
            { "Value", "openflow_v4.oxm.value",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_uint24,
            { "Value", "openflow_v4.oxm.value",
               FT_UINT24, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_uint32,
            { "Value", "openflow_v4.oxm.value",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask,
            { "Mask", "openflow_v4.oxm.mask",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask_etheraddr,
            { "Mask", "openflow_v4.oxm.value",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask_ipv4addr,
            { "Mask", "openflow_v4.oxm.value",
               FT_IPv4, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask_ipv6addr,
            { "Mask", "openflow_v4.oxm.value",
               FT_IPv6, BASE_NONE, NULL, 0x0,
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
        { &hf_openflow_v4_action_type,
            { "Type", "openflow_v4.action.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_action_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_length,
            { "Length", "openflow_v4.action.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_port,
            { "Port", "openflow_v4.action.output.port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_port_reserved,
            { "Port", "openflow_v4.action.output.port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_max_len,
            { "Max length", "openflow_v4.action.output.max_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_max_len_reserved,
            { "Max length", "openflow_v4.action.output.max_len",
               FT_UINT16, BASE_HEX, VALS(openflow_v4_action_output_max_len_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_pad,
            { "Padding", "openflow_v4.action.output.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_copy_ttl_out_pad,
            { "Padding", "openflow_v4.action.copy_ttl_out.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_copy_ttl_in_pad,
            { "Padding", "openflow_v4.action.copy_ttl_in.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_mpls_ttl_ttl,
            { "TTL", "openflow_v4.action.set_mpls_ttl.ttl",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_mpls_ttl_pad,
            { "Padding", "openflow_v4.action.set_mpls_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_dec_mpls_ttl_pad,
            { "Padding", "openflow_v4.action.dec_mpls_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_vlan_ethertype,
            { "Ethertype", "openflow_v4.action.push_vlan.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_vlan_pad,
            { "Padding", "openflow_v4.action.push_vlan.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_vlan_pad,
            { "Padding", "openflow_v4.action.pop_vlan.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_mpls_ethertype,
            { "Ethertype", "openflow_v4.action.push_mpls.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_mpls_pad,
            { "Padding", "openflow_v4.action.push_mpls.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_mpls_ethertype,
            { "Ethertype", "openflow_v4.action.pop_mpls.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_mpls_pad,
            { "Padding", "openflow_v4.action.pop_mpls.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_queue_queue_id,
            { "Queue ID", "openflow_v4.action.set_queue.queue_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_group_group_id,
            { "Group ID", "openflow_v4.action.group.group_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_group_group_id_reserved,
            { "Group ID", "openflow_v4.action.group.group_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_nw_ttl_ttl,
            { "TTL", "openflow_v4.action.set_nw_ttl.ttl",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_nw_ttl_pad,
            { "Padding", "openflow_v4.action.set_nw_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_dec_nw_ttl_pad,
            { "Padding", "openflow_v4.action.dec_nw_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_field_pad,
            { "Padding", "openflow_v4.action.set_field.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_pbb_ethertype,
            { "Ethertype", "openflow_v4.action.push_pbb.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_pbb_pad,
            { "Padding", "openflow_v4.action.push_pbb.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_pbb_pad,
            { "Padding", "openflow_v4.action.pop_pbb.pad",
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
        { &hf_openflow_v4_hello_element_type,
            { "Type", "openflow_v4.hello_element.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_hello_element_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_hello_element_length,
            { "Length", "openflow_v4.hello_element.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_hello_element_version_bitmap,
            { "Bitmap", "openflow_v4.hello_element.version.bitmap",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_hello_element_pad,
            { "Padding", "openflow_v4.hello_element.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_type,
            { "Type", "openflow_v4.error.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_hello_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_hello_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_request_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_request_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_action_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_action_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_instruction_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_instruction_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_match_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_match_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_flow_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_flow_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_group_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_group_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_port_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_port_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_table_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_table_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_queue_op_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_queue_op_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_switch_config_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_switch_config_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_role_request_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_role_request_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_meter_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_meter_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_table_features_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_table_features_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_data_text,
            { "Data", "openflow_v4.error.data",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_data_body,
            { "Body", "openflow_v4.error.data.body",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_experimenter,
            { "Experimenter", "openflow_v4.error.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
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
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_length,
            { "Length", "openflow_v4.bucket.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_weight,
            { "Weight", "openflow_v4.bucket.weight",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_port,
            { "Watch port", "openflow_v4.bucket.watch_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_port_reserved,
            { "Watch port", "openflow_v4.bucket.watch_port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_group,
            { "Watch group", "openflow_v4.bucket.watch_group",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_group_reserved,
            { "Watch group", "openflow_v4.bucket.watch_group",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_pad,
            { "Padding", "openflow_v4.bucket.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_command,
            { "Command", "openflow_v4.groupmod.command",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_groupmod_command_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_type,
            { "Type", "openflow_v4.groupmod.type",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_group_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_pad,
            { "Padding", "openflow_v4.groupmod.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_group_id,
            { "Group ID", "openflow_v4.groupmod.group_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_group_id_reserved,
            { "Group ID", "openflow_v4.groupmod.group_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
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
        &ett_openflow_v4_bucket,
        &ett_openflow_v4_bucket_actions,
        &ett_openflow_v4_groupmod_buckets,
        &ett_openflow_v4_oxm,
        &ett_openflow_v4_match,
        &ett_openflow_v4_match_oxm_fields,
        &ett_openflow_v4_action,
        &ett_openflow_v4_instruction,
        &ett_openflow_v4_instruction_actions_actions,
        &ett_openflow_v4_hello_element,
        &ett_openflow_v4_error_data
    };

    static ei_register_info ei[] = {
        { &ei_openflow_v4_oxm_undecoded,
            { "openflow_v4.oxm.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown OMX body.", EXPFILL }
        },
        { &ei_openflow_v4_match_undecoded,
            { "openflow_v4.match.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown match body.", EXPFILL }
        },
        { &ei_openflow_v4_action_undecoded,
            { "openflow_v4.action.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown action body.", EXPFILL }
        },
        { &ei_openflow_v4_instruction_undecoded,
            { "openflow_v4.instruction.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown instruction body.", EXPFILL }
        },
        { &ei_openflow_v4_hello_element_undecoded,
            { "openflow_v4.hello_element.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown hello element body.", EXPFILL }
        },
        { &ei_openflow_v4_error_undecoded,
            { "openflow_v4.error.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown error data.", EXPFILL }
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
