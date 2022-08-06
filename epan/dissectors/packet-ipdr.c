/* packet-ipdr.c
 *
 * Routines for IP Detail Record (IPDR) dissection.
 *
 * Original dissection based off of a Lua script found at
 * https://bitbucket.org/abn/ipdr-dissector/overview
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/range.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

void proto_register_ipdr(void);
void proto_reg_handoff_ipdr(void);

static int proto_ipdr = -1;
static int proto_ipdr_samis_type_1 = -1;

static dissector_handle_t ipdr_handle;
static dissector_handle_t ipdr_samis_type_1_handle;

static dissector_table_t ipdr_sessions_dissector_table;

static int hf_ipdr_version = -1;
static int hf_ipdr_message_id = -1;
static int hf_ipdr_session_id = -1;
static int hf_ipdr_message_flags = -1;
static int hf_ipdr_message_len = -1;
static int hf_ipdr_initiator_id = -1;
static int hf_ipdr_initiator_port = -1;
static int hf_ipdr_capabilities = -1;
static int hf_ipdr_keepalive_interval = -1;
static int hf_ipdr_vendor_id = -1;
static int hf_ipdr_timestamp = -1;
static int hf_ipdr_error_code = -1;
static int hf_ipdr_description = -1;
static int hf_ipdr_exporter_boot_time = -1;
static int hf_ipdr_first_record_sequence_number = -1;
static int hf_ipdr_dropped_record_count = -1;
static int hf_ipdr_reason_code = -1;
static int hf_ipdr_reason_info = -1;
static int hf_ipdr_request_id = -1;
static int hf_ipdr_config_id = -1;
static int hf_ipdr_flags = -1;
static int hf_ipdr_primary = -1;
static int hf_ipdr_ack_time_interval = -1;
static int hf_ipdr_ack_sequence_interval = -1;
static int hf_ipdr_template_id = -1;
static int hf_ipdr_document_id = -1;
static int hf_ipdr_sequence_num = -1;
static int hf_ipdr_request_number = -1;
static int hf_ipdr_data_record = -1;

/* Header fields for SAMIS-TYPE-1 IPDR DATA Records */
static int hf_ipdr_samis_record_length = -1;
static int hf_ipdr_cmts_host_name_len = -1;
static int hf_ipdr_cmts_host_name = -1;
static int hf_ipdr_cmts_sys_up_time = -1;
static int hf_ipdr_cmts_ipv4_addr = -1;
static int hf_ipdr_cmts_ipv6_addr_len = -1;
static int hf_ipdr_cmts_ipv6_addr = -1;
static int hf_ipdr_cmts_md_if_name_len = -1;
static int hf_ipdr_cmts_md_if_name = -1;
static int hf_ipdr_cmts_md_if_index = -1;
static int hf_ipdr_cm_mac_addr = -1;
static int hf_ipdr_cm_ipv4_addr = -1;
static int hf_ipdr_cm_ipv6_addr = -1;
static int hf_ipdr_cm_ipv6_addr_string_len = -1;
static int hf_ipdr_cm_ipv6_addr_string = -1;
static int hf_ipdr_cm_ipv6_ll_addr = -1;
static int hf_ipdr_cm_ipv6_ll_addr_string_len = -1;
static int hf_ipdr_cm_ipv6_ll_addr_string = -1;
static int hf_ipdr_cm_qos_version = -1;
static int hf_ipdr_cm_reg_status = -1;
static int hf_ipdr_cm_last_reg_time = -1;
static int hf_ipdr_rec_type = -1;
static int hf_ipdr_rec_creation_time = -1;
static int hf_ipdr_sf_ch_set = -1;
static int hf_ipdr_channel_id = -1;
static int hf_ipdr_service_app_id = -1;
static int hf_ipdr_service_ds_multicast = -1;
static int hf_ipdr_service_identifier = -1;
static int hf_ipdr_service_gate_id = -1;
static int hf_ipdr_service_class_name_len = -1;
static int hf_ipdr_service_class_name = -1;
static int hf_ipdr_service_direction = -1;
static int hf_ipdr_service_octets_passed = -1;
static int hf_ipdr_service_pkts_passed = -1;
static int hf_ipdr_service_sla_drop_pkts = -1;
static int hf_ipdr_service_sla_delay_pkts = -1;
static int hf_ipdr_service_time_created = -1;
static int hf_ipdr_service_time_active = -1;

static gint ett_ipdr = -1;
static gint ett_ipdr_samis_type_1 = -1;
static gint ett_ipdr_sf_ch_set = -1;

static expert_field ei_ipdr_message_id = EI_INIT;
static expert_field ei_ipdr_sf_ch_set = EI_INIT;

static range_t *global_sessions_samis_type_1;

#define IPDR_PORT 4737
#define IPDR_HEADER_LEN     8

enum
{
    IPDR_FLOW_START = 0x01,
    IPDR_FLOW_STOP = 0x03,
    IPDR_CONNECT = 0x05,
    IPDR_CONNECT_RESPONSE = 0x06,
    IPDR_DISCONNECT = 0x07,
    IPDR_SESSION_START = 0x08,
    IPDR_SESSION_STOP = 0x09,
    IPDR_TEMPLATE_DATA = 0x10,
    IPDR_FINAL_TEMPLATE_DATA_ACK = 0x13,
    IPDR_GET_SESSIONS = 0x14,
    IPDR_GET_SESSIONS_RESPONSE = 0x15,
    IPDR_GET_TEMPLATES = 0x16,
    IPDR_GET_TEMPLATES_RESPONSE = 0x17,
    IPDR_MODIFY_TEMPLATE = 0x1A,
    IPDR_MODIFY_TEMPLATE_RESPONSE = 0x1B,
    IPDR_START_NEGOTIATION = 0x1D,
    IPDR_START_NEGOTIATION_REJECT = 0x1E,
    IPDR_DATA = 0x20,
    IPDR_DATA_ACK = 0x21,
    IPDR_ERROR = 0x23,
    IPDR_REQUEST = 0x30,
    IPDR_RESPONSE = 0x31,
    IPDR_KEEP_ALIVE = 0x40
};

static const value_string ipdr_message_type_vals[] = {
    { IPDR_FLOW_START,              "FLOW_START" },
    { IPDR_FLOW_STOP,               "FLOW_STOP" },
    { IPDR_CONNECT,                 "CONNECT" },
    { IPDR_CONNECT_RESPONSE,        "CONNECT_RESPONSE" },
    { IPDR_DISCONNECT,              "DISCONNECT" },
    { IPDR_SESSION_START,           "SESSION_START" },
    { IPDR_SESSION_STOP,            "SESSION_STOP" },
    { IPDR_TEMPLATE_DATA,           "TEMPLATE_DATA" },
    { IPDR_FINAL_TEMPLATE_DATA_ACK, "FINAL_TEMPLATE_DATA_ACK" },
    { IPDR_GET_SESSIONS,            "GET_SESSIONS" },
    { IPDR_GET_SESSIONS_RESPONSE,   "GET_SESSIONS_RESPONSE" },
    { IPDR_GET_TEMPLATES,           "GET_TEMPLATES" },
    { IPDR_GET_TEMPLATES_RESPONSE,  "GET_TEMPLATES_RESPONSE" },
    { IPDR_MODIFY_TEMPLATE,         "MODIFY_TEMPLATE" },
    { IPDR_MODIFY_TEMPLATE_RESPONSE,"MODIFY_TEMPLATE_RESPONSE" },
    { IPDR_START_NEGOTIATION,       "START_NEGOTIATION" },
    { IPDR_START_NEGOTIATION_REJECT,"START_NEGOTIATION_REJECT" },
    { IPDR_DATA,                    "DATA" },
    { IPDR_DATA_ACK,                "DATA_ACK" },
    { IPDR_ERROR,                   "ERROR" },
    { IPDR_REQUEST,                 "REQUEST" },
    { IPDR_RESPONSE,                "RESPONSE" },
    { IPDR_KEEP_ALIVE,              "KEEP_ALIVE" },
    { 0, NULL }
};

static const value_string ipdr_cm_qos_type_vals[] = {
    { 1,                             "DOCSIS 1.0 QoS mode" },
    { 2,                             "DOCSIS 1.1 QoS mode" },
    { 0, NULL }
};

static const value_string ipdr_cm_reg_status_vals[] = {
    { 1,                             "Other" },
    { 2,                             "Initial Ranging" },
    { 4,                             "Ranging Auto Adj Complete" },
    { 5,                             "DHCPv4 Complete" },
    { 6,                             "Registration Complete" },
    { 8,                             "Operational" },
    { 9,                             "BPI Init" },
    { 10,                             "Start EAE" },
    { 11,                             "Start DHCPv4" },
    { 12,                             "Start DHCPv6" },
    { 13,                             "DHCPv6 Complete" },
    { 14,                             "Start Configuration File Download" },
    { 15,                             "Configuration File Download Complete" },
    { 16,                             "Start Registration" },
    { 17,                             "Forwarding Disabled" },
    { 18,                             "RF Mute All" },
    { 0, NULL }
};

static const value_string ipdr_record_type_vals[] = {
    { 1,                             "Interim" },
    { 2,                             "Stop" },
    { 3,                             "Start" },
    { 4,                             "Event" },
    { 0, NULL }
};

static const value_string ipdr_service_direction_vals[] = {
    { 1,                             "Downstream" },
    { 2,                             "Upstream" },
    { 0, NULL }
};

static int
dissect_ipdr_samis_type_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *samis_type_1_tree, *sf_ch_set_tree;
    guint len, cmts_sys_up_time, channel_id;

    //col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_ipdr_samis_type_1, tvb, 0, -1, ENC_NA);
    samis_type_1_tree = proto_item_add_subtree(ti, ett_ipdr_samis_type_1);
    col_add_str(pinfo->cinfo, COL_INFO, "SAMIS-TYPE-1");

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_samis_record_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    ti = proto_tree_add_item_ret_uint(samis_type_1_tree, hf_ipdr_cmts_host_name_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    proto_item_append_text(ti, " bytes");
    offset += 4;
    if (len > 0) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_cmts_host_name, tvb, offset, len, ENC_ASCII);
        offset += len;
    }

    ti = proto_tree_add_item_ret_uint(samis_type_1_tree, hf_ipdr_cmts_sys_up_time,
                                      tvb, offset, 4, ENC_BIG_ENDIAN, &cmts_sys_up_time);
    proto_item_append_text(ti, " (%d seconds)", cmts_sys_up_time / 100);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_cmts_ipv4_addr, tvb, offset, 4, ENC_NA);
    offset += 4;

    ti = proto_tree_add_item_ret_uint(samis_type_1_tree, hf_ipdr_cmts_ipv6_addr_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    proto_item_append_text(ti, " bytes");
    offset += 4;
    if (len > 0) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_cmts_ipv6_addr, tvb, offset, len, ENC_NA);
        offset += len;
    }
    ti = proto_tree_add_item_ret_uint(samis_type_1_tree, hf_ipdr_cmts_md_if_name_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    proto_item_append_text(ti, " bytes");
    offset += 4;
    if (len > 0) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_cmts_md_if_name, tvb, offset, len, ENC_ASCII);
        offset += len;
    }

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_cmts_md_if_index, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 6; /* Add another 2 bytes for compatibility with XDR MAC address encoding format */

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_mac_addr, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_ipv4_addr, tvb, offset, 4, ENC_NA);
    offset += 4;

    ti = proto_tree_add_item_ret_uint(samis_type_1_tree, hf_ipdr_cm_ipv6_addr_string_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    proto_item_append_text(ti, " bytes");
    offset += 4;
    if (len == 16) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_ipv6_addr, tvb, offset, len, ENC_ASCII|ENC_BIG_ENDIAN);
    } else if (len > 0) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_ipv6_addr_string, tvb, offset, len, ENC_ASCII);
    }
    offset += len;

    ti = proto_tree_add_item_ret_uint(samis_type_1_tree, hf_ipdr_cm_ipv6_ll_addr_string_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    proto_item_append_text(ti, " bytes");
    offset += 4;
    if (len == 16) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_ipv6_ll_addr, tvb, offset, len, ENC_ASCII|ENC_BIG_ENDIAN);
    } else if (len > 0) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_ipv6_ll_addr_string, tvb, offset, len, ENC_ASCII);
    }
    offset += len;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_qos_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_reg_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_cm_last_reg_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_rec_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_rec_creation_time, tvb, offset, 8, ENC_TIME_MSECS);
    offset += 8;

    len = tvb_get_ntohl(tvb, offset);
    ti = proto_tree_add_item(samis_type_1_tree, hf_ipdr_sf_ch_set, tvb, offset, len + 4, ENC_NA);
    offset += 4;
    if (len > 0 && len <= 255) {
        sf_ch_set_tree = proto_item_add_subtree(ti, ett_ipdr_sf_ch_set);
        proto_item_append_text (ti, ": ");
        while (len) {
            proto_tree_add_item_ret_uint(sf_ch_set_tree, hf_ipdr_channel_id, tvb, offset, 1, ENC_BIG_ENDIAN, &channel_id);
            proto_item_append_text (ti, "%d ", channel_id);
            offset += 1;
            len--;
        }
    } else {
        expert_add_info(pinfo, ti, &ei_ipdr_sf_ch_set);
        offset += len;
    }

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_app_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_ds_multicast, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_identifier, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_gate_id, tvb, offset, 4, ENC_NA);
    offset += 4;

    ti = proto_tree_add_item_ret_uint(samis_type_1_tree, hf_ipdr_service_class_name_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    proto_item_append_text(ti, " bytes");
    offset += 4;
    if (len > 0) {
        proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_class_name, tvb, offset, len, ENC_ASCII);
        offset += len;
    }

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_direction, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_octets_passed, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_pkts_passed, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    ti = proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_sla_drop_pkts, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text (ti, " (Downstream only)");
    offset += 4;

    ti = proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_sla_delay_pkts, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text (ti, " (Downstream only)");
    offset += 4;

    ti = proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_time_created, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, " seconds");
    offset += 4;

    ti = proto_tree_add_item(samis_type_1_tree, hf_ipdr_service_time_active, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, " seconds");
    offset += 4;

    return offset;
}

static int
dissect_ipdr_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti, *type_item;
    proto_tree *ipdr_tree;
    int offset = 0;
    guint32 session_id, message_len, message_type;

    ti = proto_tree_add_item(tree, proto_ipdr, tvb, 0, -1, ENC_NA);
    ipdr_tree = proto_item_add_subtree(ti, ett_ipdr);

    proto_tree_add_item(ipdr_tree, hf_ipdr_version, tvb, offset, 1, ENC_NA);
    offset++;

    type_item = proto_tree_add_item_ret_uint(ipdr_tree, hf_ipdr_message_id, tvb, offset, 1, ENC_NA, &message_type);
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(message_type, ipdr_message_type_vals, "Unknown (0x%02x)"));
    offset++;

    proto_tree_add_item_ret_uint(ipdr_tree, hf_ipdr_session_id, tvb, offset, 1, ENC_BIG_ENDIAN, &session_id);
    offset++;

    proto_tree_add_item(ipdr_tree, hf_ipdr_message_flags, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item_ret_uint(ipdr_tree, hf_ipdr_message_len, tvb, offset, 4, ENC_BIG_ENDIAN, &message_len);
    offset += 4;

    switch(message_type)
    {
    case IPDR_FLOW_START:
    case IPDR_DISCONNECT:
    case IPDR_FINAL_TEMPLATE_DATA_ACK:
    case IPDR_START_NEGOTIATION:
    case IPDR_START_NEGOTIATION_REJECT:
    case IPDR_KEEP_ALIVE:
        /* No additional fields */
        break;
    case IPDR_FLOW_STOP:
        proto_tree_add_item(ipdr_tree, hf_ipdr_reason_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_reason_info, tvb, offset, -1, ENC_ASCII);
        break;
    case IPDR_CONNECT:
        proto_tree_add_item(ipdr_tree, hf_ipdr_initiator_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_initiator_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_keepalive_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_vendor_id, tvb, offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
        break;
    case IPDR_CONNECT_RESPONSE:
        proto_tree_add_item(ipdr_tree, hf_ipdr_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_keepalive_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_vendor_id, tvb, offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
        break;
    case IPDR_SESSION_START:
        proto_tree_add_item(ipdr_tree, hf_ipdr_exporter_boot_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_first_record_sequence_number, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(ipdr_tree, hf_ipdr_dropped_record_count, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(ipdr_tree, hf_ipdr_primary, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(ipdr_tree, hf_ipdr_ack_time_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_ack_sequence_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_document_id, tvb, offset, 16, ENC_NA);
        break;
    case IPDR_SESSION_STOP:
        proto_tree_add_item(ipdr_tree, hf_ipdr_reason_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_reason_info, tvb, offset, -1, ENC_ASCII);
        break;
    case IPDR_TEMPLATE_DATA:
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_flags, tvb, offset, 1, ENC_NA);
        break;
    case IPDR_GET_SESSIONS:
        proto_tree_add_item(ipdr_tree, hf_ipdr_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case IPDR_GET_SESSIONS_RESPONSE:
        proto_tree_add_item(ipdr_tree, hf_ipdr_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case IPDR_GET_TEMPLATES:
        proto_tree_add_item(ipdr_tree, hf_ipdr_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case IPDR_GET_TEMPLATES_RESPONSE:
        proto_tree_add_item(ipdr_tree, hf_ipdr_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case IPDR_MODIFY_TEMPLATE:
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case IPDR_MODIFY_TEMPLATE_RESPONSE:
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_flags, tvb, offset, 1, ENC_NA);
        offset++;
        break;
    case IPDR_DATA:
        proto_tree_add_item(ipdr_tree, hf_ipdr_template_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_flags, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(ipdr_tree, hf_ipdr_sequence_num, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        if (!dissector_try_uint(ipdr_sessions_dissector_table, session_id,
                                tvb_new_subset_remaining(tvb, offset), pinfo, ipdr_tree)) {
            proto_tree_add_item(ipdr_tree, hf_ipdr_data_record, tvb, offset, -1, ENC_NA);
        }
        break;
    case IPDR_DATA_ACK:
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_sequence_num, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;
    case IPDR_ERROR:
        proto_tree_add_item(ipdr_tree, hf_ipdr_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ipdr_tree, hf_ipdr_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_description, tvb, offset, -1, ENC_ASCII);
        break;
    case IPDR_REQUEST:
        proto_tree_add_item(ipdr_tree, hf_ipdr_template_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_flags, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(ipdr_tree, hf_ipdr_request_number, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(ipdr_tree, hf_ipdr_data_record, tvb, offset, -1, ENC_NA);
        break;
    case IPDR_RESPONSE:
        proto_tree_add_item(ipdr_tree, hf_ipdr_template_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_config_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ipdr_tree, hf_ipdr_flags, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(ipdr_tree, hf_ipdr_request_number, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(ipdr_tree, hf_ipdr_data_record, tvb, offset, -1, ENC_NA);
        break;
    default:
        expert_add_info(pinfo, type_item, &ei_ipdr_message_id);
        break;
    }

    return tvb_captured_length(tvb);
}

static guint
get_ipdr_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint)tvb_get_ntohl(tvb, offset+4);
}

static int
dissect_ipdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_reported_length(tvb) < 1)
        return 0;

    if (tvb_get_guint8(tvb, 0) != 2) /* Only version 2 supported */
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPDR/SP");
    col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, IPDR_HEADER_LEN,
                     get_ipdr_message_len, dissect_ipdr_message, data);
    return tvb_captured_length(tvb);
}

void
proto_register_ipdr(void)
{
    static hf_register_info hf[] = {
        { &hf_ipdr_version, { "Version", "ipdr.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_message_id, { "Message id", "ipdr.message_id", FT_UINT8, BASE_DEC, VALS(ipdr_message_type_vals), 0x0, NULL, HFILL } },
        { &hf_ipdr_session_id, { "Session id", "ipdr.session_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_message_flags, { "Message flags", "ipdr.message_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_message_len, { "Message length", "ipdr.message_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_initiator_id, { "Initiator id", "ipdr.initiator_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_initiator_port, { "Initiator port", "ipdr.initiator_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_capabilities, { "Capabilities", "ipdr.capabilities", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_keepalive_interval, { "Keep-alive interval", "ipdr.keepalive_interval", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_vendor_id, { "Vendor id", "ipdr.vendor_id", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_timestamp, { "Timestamp", "ipdr.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_error_code, { "Error code", "ipdr.error_code", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_description, { "Description", "ipdr.description", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_exporter_boot_time, { "Exporter boot time", "ipdr.exporter_boot_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_first_record_sequence_number, { "First record sequence number", "ipdr.first_record_sequence_number", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_dropped_record_count, { "Dropped record count", "ipdr.dropped_record_count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_reason_code, { "Reason code", "ipdr.reason_code", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_reason_info, { "Reason info", "ipdr.reason_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_request_id, { "Request id", "ipdr.request_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_config_id, { "Config id", "ipdr.config_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_flags, { "Flags", "ipdr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_primary, { "Primary", "ipdr.primary", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_ack_time_interval, { "ACK time interval", "ipdr.ack_time_interval", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_ack_sequence_interval, { "ACK sequence interval", "ipdr.ack_sequence_interval", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_template_id, { "Template id", "ipdr.template_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_document_id, { "Document id", "ipdr.document_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_sequence_num, { "Sequence number", "ipdr.sequence_num", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_request_number, { "Request number", "ipdr.request_number", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_data_record, { "Data record", "ipdr.data_record", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* Header fields for SAMIS-TYPE-1 IPDR DATA Records */
        { &hf_ipdr_samis_record_length, { "Record Length", "ipdr.samis_record_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_host_name_len, { "CMTS FQDN Length", "ipdr.cmts_host_name_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_host_name, { "CMTS FQDN", "ipdr.cmts_host_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_sys_up_time, { "CMTS Uptime", "ipdr.cmts_uptime", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_ipv4_addr, { "CMTS IPv4 Address", "ipdr.cmts_ipv4_addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_ipv6_addr_len, { "CMTS IPv6 Address Length", "ipdr.cmts_ipv6_addr_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_ipv6_addr, { "CMTS IPv6 Address", "ipdr.cmts_ipv6_addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_md_if_name_len, { "MD Interface Name Length", "ipdr.cmts_md_if_name_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_md_if_name, { "MD Interface Name", "ipdr.cmts_md_if_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cmts_md_if_index, { "MD Interface Index", "ipdr.cmts_md_if_index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_mac_addr, { "CM MAC", "ipdr.cm_mac_address", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_ipv4_addr, { "CM IPv4 Address", "ipdr.cm_ipv4_addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_ipv6_addr_string_len, { "CM IPv6 Address Length", "ipdr.cm_ipv6_addr_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_ipv6_addr_string, { "CM IPv6 Address", "ipdr.cm_ipv6_addr_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_ipv6_addr, { "CM IPv6 Address", "ipdr.cm_ipv6_addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_ipv6_ll_addr, { "CM IPv6 Link-local Address", "ipdr.cm_ipv6_addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_ipv6_ll_addr_string_len, { "CM IPv6 Link-local Address Length", "ipdr.cm_ipv6_addr_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_ipv6_ll_addr_string, { "CM IPv6 Link-local Address", "ipdr.cm_ipv6_addr_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_qos_version, { "CM QoS Version", "ipdr.cm_qos_version", FT_UINT32, BASE_DEC, VALS(ipdr_cm_qos_type_vals), 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_reg_status, { "CM REG Status", "ipdr.cm_reg_status", FT_UINT32, BASE_DEC, VALS(ipdr_cm_reg_status_vals), 0x0, NULL, HFILL } },
        { &hf_ipdr_cm_last_reg_time, { "CM Last REG Time", "ipdr.cm_last_reg_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_rec_type, { "Record Type", "ipdr.record_type", FT_UINT32, BASE_DEC, VALS(ipdr_record_type_vals), 0x0, NULL, HFILL } },
        { &hf_ipdr_rec_creation_time, { "Record Creation Time", "ipdr.rec_creation_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_sf_ch_set, { "SF Channel Set", "ipdr.sf_ch_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_channel_id, { "Channel ID", "ipdr.channel_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_app_id, { "Service Application ID", "ipdr.svc_app_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_ds_multicast, { "Service Multicast SF", "ipdr.service_ds_multicast", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_identifier, { "Service Identifier", "ipdr.service_identifier", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_gate_id, { "Service Gate ID", "ipdr.service_gate_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_class_name_len, { "Service Class Name Length", "ipdr.service_class_name_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_class_name, { "Service Class Name", "ipdr.service_class_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_direction, { "Service Direction", "ipdr.service_direction", FT_UINT32, BASE_DEC, VALS(ipdr_service_direction_vals), 0x0, NULL, HFILL } },
        { &hf_ipdr_service_octets_passed, { "Octets Passed", "ipdr.octets_passed", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_pkts_passed, { "Packets Passed", "ipdr.packets_passed", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_sla_drop_pkts, { "SLA Packets Dropped", "ipdr.sla_drop_pkts", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_sla_delay_pkts, { "SLA Packets Delayed", "ipdr.sla_delay_pkts", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_time_created, { "SF Creation Time", "ipdr.service_time_created", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ipdr_service_time_active, { "SF Active", "ipdr.service_time_active", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_ipdr,
        &ett_ipdr_samis_type_1,
        &ett_ipdr_sf_ch_set
    };

    static ei_register_info ei[] = {
        { &ei_ipdr_message_id, { "ipdr.message_id.unknown", PI_PROTOCOL, PI_WARN, "Unknown message ID", EXPFILL }},
        { &ei_ipdr_sf_ch_set, { "ipdr.sf_ch_set.too_big", PI_PROTOCOL, PI_WARN, "SF Channel Set Too Big", EXPFILL }},
    };

    expert_module_t* expert_ipdr;
    module_t *ipdr_module;

    proto_ipdr = proto_register_protocol("IPDR", "IPDR/SP", "ipdr");
    proto_ipdr_samis_type_1 = proto_register_protocol_in_name_only("SAMIS-TYPE-1 Record","SAMIS-TYPE-1 Record",
                                                                   "ipdr_samis_type_1", proto_ipdr, FT_PROTOCOL);

    proto_register_field_array(proto_ipdr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ipdr = expert_register_protocol(proto_ipdr);
    expert_register_field_array(expert_ipdr, ei, array_length(ei));

    ipdr_sessions_dissector_table = register_dissector_table("ipdr.session_type", "IPDR Session Type",
                                                             proto_ipdr, FT_UINT8, BASE_DEC);

    ipdr_module = prefs_register_protocol(proto_ipdr, proto_reg_handoff_ipdr);
    prefs_register_range_preference(ipdr_module, "sessions.samis_type_1", "SAMIS-TYPE-1 Sessions",
                                    "Range of session IDs to be decoded as SAMIS-TYPE-1 records",
                                    &global_sessions_samis_type_1, 255);
}

void
proto_reg_handoff_ipdr(void)
{
    static range_t *sessions_samis_type_1;
    static gboolean ipdr_prefs_initialized = FALSE;

    if (!ipdr_prefs_initialized) {
        ipdr_handle = create_dissector_handle(dissect_ipdr, proto_ipdr);
        ipdr_samis_type_1_handle = register_dissector("ipdr-samis-type-1", dissect_ipdr_samis_type_1,
                                                      proto_ipdr_samis_type_1);
        dissector_add_uint_with_preference("tcp.port", IPDR_PORT, ipdr_handle);

        ipdr_prefs_initialized = TRUE;
    } else {
        dissector_delete_uint_range("ipdr.session_type", sessions_samis_type_1, ipdr_samis_type_1_handle);
    }

    sessions_samis_type_1 = range_copy(wmem_epan_scope(), global_sessions_samis_type_1);
    dissector_add_uint_range("ipdr.session_type", sessions_samis_type_1, ipdr_samis_type_1_handle);
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
