/* packet-l2tp.c
 * Routines for Layer Two Tunnelling Protocol (L2TP) packet disassembly
 * John Thomes <john@ensemblecom.com>
 *
 * Minor changes by: (2000-01-10)
 * Laurent Cazalet <laurent.cazalet@mailclub.net>
 * Thomas Parvais <thomas.parvais@advalvas.be>
 *
 * Added RFC 5515 by Uli Heilmeier <uh@heilmeier.eu>, 2016-02-29
 *
 * Ericsson L2TP by Harald Welte <laforge@gnumonks.org>, 2016-07-16
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * RFC 2661 for L2TPv2
 * https://tools.ietf.org/html/rfc2661
 *
 * RFC 3931 for L2TPv3
 * https://tools.ietf.org/html/rfc3931
 *
 * Layer Two Tunneling Protocol "L2TP" number assignments:
 *     http://www.iana.org/assignments/l2tp-parameters
 *
 * Pseudowire types:
 *
 * RFC 4591 for Frame Relay
 * https://tools.ietf.org/html/rfc4591
 *
 * RFC 4454 for ATM
 * https://tools.ietf.org/html/rfc4454
 *
 * RFC 4719 for Ethernet
 * https://tools.ietf.org/html/rfc4719
 *
 * RFC 4349 for HDLC
 * https://tools.ietf.org/html/rfc4349
 *
 * XXX - what about LAPD?
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

#include <wsutil/wsgcrypt.h>

#include "packet-l2tp.h"

void proto_register_l2tp(void);
void proto_reg_handoff_l2tp(void);

static int proto_l2tp = -1;
static int hf_l2tp_flags = -1;
static int hf_l2tp_type = -1;
static int hf_l2tp_length_bit = -1;
static int hf_l2tp_seq_bit = -1;
static int hf_l2tp_offset_bit = -1;
static int hf_l2tp_priority = -1;
static int hf_l2tp_version = -1;
static int hf_l2tp_length = -1;
static int hf_l2tp_tunnel = -1;
static int hf_l2tp_session = -1;
static int hf_l2tp_Ns = -1;
static int hf_l2tp_Nr = -1;
static int hf_l2tp_offset = -1;
static int hf_l2tp_avp_mandatory = -1;
static int hf_l2tp_avp_hidden = -1;
static int hf_l2tp_avp_length = -1;
static int hf_l2tp_avp_vendor_id = -1;
static int hf_l2tp_avp_type = -1;
static int hf_l2tp_tie_breaker = -1;
static int hf_l2tp_sid = -1;
static int hf_l2tp_res = -1;
static int hf_l2tp_ccid = -1;
static int hf_l2tp_cookie = -1;
static int hf_l2tp_l2_spec_def = -1;
static int hf_l2tp_l2_spec_atm = -1;
static int hf_l2tp_l2_spec_docsis_dmpt = -1;
static int hf_l2tp_l2_spec_v = -1;
static int hf_l2tp_l2_spec_s = -1;
static int hf_l2tp_l2_spec_h = -1;
static int hf_l2tp_l2_spec_flow_id = -1;
static int hf_l2tp_l2_spec_sequence = -1;
static int hf_l2tp_l2_spec_t = -1;
static int hf_l2tp_l2_spec_g = -1;
static int hf_l2tp_l2_spec_c = -1;
static int hf_l2tp_l2_spec_u = -1;
static int hf_l2tp_cisco_avp_type = -1;
static int hf_l2tp_ericsson_avp_type = -1;
static int hf_l2tp_broadband_avp_type = -1;
static int hf_l2tp_cablelabs_avp_type = -1;
static int hf_l2tp_avp_message_type = -1;
static int hf_l2tp_avp_assigned_tunnel_id = -1;
static int hf_l2tp_avp_assigned_control_conn_id = -1;
static int hf_l2tp_avp_assigned_session_id = -1;
static int hf_l2tp_avp_remote_session_id = -1;
static int hf_l2tp_avp_local_session_id = -1;
static int hf_l2tp_avp_called_number = -1;
static int hf_l2tp_avp_calling_number = -1;
static int hf_l2tp_cisco_tie_breaker = -1;
static int hf_l2tp_cablel_avp_l_bit = -1;
static int hf_l2tp_cablel_avp_tsid_group_id = -1;
static int hf_l2tp_cablel_avp_frequency = -1;
static int hf_l2tp_cablel_avp_modulation = -1;
static int hf_l2tp_cablel_avp_m = -1;
static int hf_l2tp_cablel_avp_n = -1;
static int hf_l2tp_broadband_agent_circuit_id = -1;
static int hf_l2tp_broadband_agent_remote_id = -1;
static int hf_l2tp_broadband_actual_dr_up = -1;
static int hf_l2tp_broadband_actual_dr_down = -1;
static int hf_l2tp_broadband_minimum_dr_up = -1;
static int hf_l2tp_broadband_minimum_dr_down = -1;
static int hf_l2tp_broadband_attainable_dr_up = -1;
static int hf_l2tp_broadband_attainable_dr_down = -1;
static int hf_l2tp_broadband_maximum_dr_up = -1;
static int hf_l2tp_broadband_maximum_dr_down = -1;
static int hf_l2tp_broadband_minimum_dr_up_low_power = -1;
static int hf_l2tp_broadband_minimum_dr_down_low_power = -1;
static int hf_l2tp_broadband_maximum_interleaving_delay_up = -1;
static int hf_l2tp_broadband_actual_interleaving_delay_up = -1;
static int hf_l2tp_broadband_maximum_interleaving_delay_down = -1;
static int hf_l2tp_broadband_actual_interleaving_delay_down = -1;
static int hf_l2tp_broadband_access_loop_encapsulation = -1;
static int hf_l2tp_broadband_access_loop_encapsulation_data_link = -1;
static int hf_l2tp_broadband_access_loop_encapsulation_enc1 = -1;
static int hf_l2tp_broadband_access_loop_encapsulation_enc2 = -1;
static int hf_l2tp_broadband_ancp_access_line_type = -1;
static int hf_l2tp_broadband_iwf_session = -1;
static int hf_l2tp_avp_csu = -1;
static int hf_l2tp_avp_csu_res = -1;
static int hf_l2tp_avp_csu_remote_session_id_v2 = -1;
static int hf_l2tp_avp_csu_current_tx_speed_v2 = -1;
static int hf_l2tp_avp_csu_current_rx_speed_v2 = -1;
static int hf_l2tp_avp_csu_remote_session_id_v3 = -1;
static int hf_l2tp_avp_csu_current_tx_speed_v3 = -1;
static int hf_l2tp_avp_csu_current_rx_speed_v3 = -1;

static int hf_l2tp_ericsson_msg_type = -1;
static int hf_l2tp_ericsson_conn_type = -1;
static int hf_l2tp_ericsson_stn_name = -1;
static int hf_l2tp_ericsson_crc32_enable = -1;
static int hf_l2tp_ericsson_abis_lower_mode = -1;
static int hf_l2tp_ericsson_tc_overl_thresh = -1;
static int hf_l2tp_ericsson_tc_num_groups = -1;
static int hf_l2tp_ericsson_tcg_group_id = -1;
static int hf_l2tp_ericsson_tcg_num_sapis = -1;
static int hf_l2tp_ericsson_tcg_sapi = -1;
static int hf_l2tp_ericsson_tcg_ip = -1;
static int hf_l2tp_ericsson_tcg_dscp = -1;
static int hf_l2tp_ericsson_tcg_crc32_enable = -1;
static int hf_l2tp_ericsson_tcg_bundling_tout = -1;
static int hf_l2tp_ericsson_tcg_bundling_max_pkt = -1;
static int hf_l2tp_ericsson_tc_num_maps = -1;
static int hf_l2tp_ericsson_map_tei_low = -1;
static int hf_l2tp_ericsson_map_tei_high = -1;
static int hf_l2tp_ericsson_map_sc = -1;
static int hf_l2tp_ericsson_ver_pref = -1;
static int hf_l2tp_ericsson_ver_2 = -1;
static int hf_l2tp_ericsson_ver_3 = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_l2tp_cisco_pw_type = -1;
static int hf_l2tp_avp_error_code = -1;
static int hf_l2tp_avp_cause_msg = -1;
static int hf_l2tp_avp_host_name = -1;
static int hf_l2tp_avp_maximum_bps = -1;
static int hf_l2tp_avp_pseudowire_type = -1;
static int hf_l2tp_avp_minimum_bps = -1;
static int hf_l2tp_avp_nonce = -1;
static int hf_l2tp_avp_circuit_status = -1;
static int hf_l2tp_avp_receive_window_size = -1;
static int hf_l2tp_avp_vendor_name = -1;
static int hf_l2tp_avp_layer2_specific_sublayer = -1;
static int hf_l2tp_avp_disconnect_code = -1;
static int hf_l2tp_cisco_circuit_status = -1;
static int hf_l2tp_cisco_remote_session_id = -1;
static int hf_l2tp_avp_router_id = -1;
static int hf_l2tp_avp_send_accm = -1;
static int hf_l2tp_avp_last_sent_lcp_confreq = -1;
static int hf_l2tp_avp_sync_framing_supported = -1;
static int hf_l2tp_cisco_assigned_control_connection_id = -1;
static int hf_l2tp_avp_sync_framing_type = -1;
static int hf_l2tp_avp_assigned_cookie = -1;
static int hf_l2tp_avp_time_out_errors = -1;
static int hf_l2tp_avp_sub_address = -1;
static int hf_l2tp_avp_connect_speed = -1;
static int hf_l2tp_avp_analog_access_supported = -1;
static int hf_l2tp_avp_private_group_id = -1;
static int hf_l2tp_avp_proxy_authen_response = -1;
static int hf_l2tp_avp_chap_challenge = -1;
static int hf_l2tp_avp_call_serial_number = -1;
static int hf_l2tp_avp_digital_access_supported = -1;
static int hf_l2tp_avp_physical_channel = -1;
static int hf_l2tp_avp_advisory_msg = -1;
static int hf_l2tp_avp_data_sequencing = -1;
static int hf_l2tp_avp_control_protocol_number = -1;
static int hf_l2tp_avp_error_message = -1;
static int hf_l2tp_avp_initial_received_lcp_confreq = -1;
static int hf_l2tp_avp_async_framing_supported = -1;
static int hf_l2tp_cisco_message_digest = -1;
static int hf_l2tp_avp_circuit_type = -1;
static int hf_l2tp_cisco_circuit_type = -1;
static int hf_l2tp_avp_proxy_authen_challenge = -1;
static int hf_l2tp_cisco_assigned_cookie = -1;
static int hf_l2tp_avp_receive_accm = -1;
static int hf_l2tp_stop_ccn_result_code = -1;
static int hf_l2tp_avp_proxy_authen_id = -1;
static int hf_l2tp_avp_digital_bearer_type = -1;
static int hf_l2tp_avp_rx_connect_speed = -1;
static int hf_l2tp_cisco_nonce = -1;
static int hf_l2tp_avp_chap_challenge_response = -1;
static int hf_l2tp_avp_cause_code = -1;
static int hf_l2tp_avp_protocol_revision = -1;
static int hf_l2tp_avp_alignment_errors = -1;
static int hf_l2tp_avp_last_received_lcp_confreq = -1;
static int hf_l2tp_avp_crc_errors = -1;
static int hf_l2tp_avp_random_vector = -1;
static int hf_l2tp_avp_preferred_language = -1;
static int hf_l2tp_cisco_interface_mtu = -1;
static int hf_l2tp_avp_async_framing_type = -1;
static int hf_l2tp_avp_pw_type = -1;
static int hf_l2tp_cisco_local_session_id = -1;
static int hf_l2tp_avp_hardware_overruns = -1;
static int hf_l2tp_avp_proxy_authen_type = -1;
static int hf_l2tp_cisco_draft_avp_version = -1;
static int hf_l2tp_avp_protocol_version = -1;
static int hf_l2tp_result_code = -1;
static int hf_l2tp_avp_buffer_overruns = -1;
static int hf_l2tp_avp_remote_end_id = -1;
static int hf_l2tp_cisco_pseudowire_type = -1;
static int hf_l2tp_avp_message_digest = -1;
static int hf_l2tp_avp_proxy_authen_name = -1;
static int hf_l2tp_avp_analog_bearer_type = -1;
static int hf_l2tp_avp_cause_code_direction = -1;
static int hf_l2tp_avp_firmware_revision = -1;
static int hf_l2tp_avp_cause_code_message = -1;
static int hf_l2tp_avp_framing_errors = -1;
static int hf_l2tp_cisco_remote_end_id = -1;
static int hf_l2tp_avp_tx_connect_speed_v3 = -1;
static int hf_l2tp_avp_rx_connect_speed_v3 = -1;
static int hf_l2tp_lapd_info = -1;
static int hf_l2tp_zero_length_body_message = -1;
static int hf_l2tp_offset_padding = -1;

static dissector_table_t l2tp_vendor_avp_dissector_table;
static dissector_table_t pw_type_table;

#define UDP_PORT_L2TP   1701

#define CONTROL_BIT(msg_info)        (msg_info & 0x8000) /* Type bit control = 1 data = 0 */
#define LENGTH_BIT(msg_info)         (msg_info & 0x4000) /* Length bit = 1  */
#define RESERVE_BITS(msg_info)       (msg_info &0x37F8)  /* Reserved bit - unused */
#define SEQUENCE_BIT(msg_info)       (msg_info & 0x0800) /* SEQUENCE bit = 1 Ns and Nr fields */
#define OFFSET_BIT(msg_info)         (msg_info & 0x0200) /* Offset */
#define PRIORITY_BIT(msg_info)       (msg_info & 0x0100) /* Priority */
#define L2TP_VERSION(msg_info)       (msg_info & 0x000f) /* Version of l2tp */
#define MANDATORY_BIT(msg_info)      (msg_info & 0x8000) /* Mandatory = 1 */
#define HIDDEN_BIT(msg_info)         (msg_info & 0x4000) /* Hidden = 1 */
#define AVP_LENGTH(msg_info)         (msg_info & 0x03ff) /* AVP Length */
#define FRAMING_SYNC(msg_info)       (msg_info & 0x0001) /* SYNC Framing Type */
#define FRAMING_ASYNC(msg_info)      (msg_info & 0x0002) /* ASYNC Framing Type */
#define BEARER_DIGITAL(msg_info)     (msg_info & 0x0001) /* Digital Bearer Type */
#define BEARER_ANALOG(msg_info)      (msg_info & 0x0002) /* Analog Bearer Type */
#define CIRCUIT_STATUS_BIT(msg_info) (msg_info & 0x0001) /* Circuit Status */
#define CIRCUIT_TYPE_BIT(msg_info)   (msg_info & 0x0001) /* Circuit Condition */

/* DOCSIS DMPT Sub-Layer Header definitions */
#define FLOW_ID_MASK  0x0E

static gint ett_l2tp = -1;
static gint ett_l2tp_flags = -1;
static gint ett_l2tp_avp = -1;
static gint ett_l2tp_avp_sub = -1;
static gint ett_l2tp_ale_sub = -1;
static gint ett_l2tp_lcp = -1;
static gint ett_l2tp_l2_spec = -1;
static gint ett_l2tp_csu = -1;
static gint ett_l2tp_ericsson_tcg = -1;
static gint ett_l2tp_ericsson_map = -1;

static expert_field ei_l2tp_incorrect_digest = EI_INIT;
/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_l2tp_vendor_specific_avp_data = EI_INIT;
static expert_field ei_l2tp_avp_length = EI_INIT;

static const enum_val_t l2tpv3_cookies[] = {
    {"detect",  "Detect",              -1},
    {"cookie0", "None",                 0},
    {"cookie4", "4 Byte Cookie",        4},
    {"cookie8", "8 Byte Cookie",        8},
    {NULL, NULL, 0}
};

#define L2TPv3_COOKIE_DEFAULT       0

#define L2TPv3_L2_SPECIFIC_NONE         0
#define L2TPv3_L2_SPECIFIC_DEFAULT      1
#define L2TPv3_L2_SPECIFIC_ATM          2
#define L2TPv3_L2_SPECIFIC_LAPD         3
#define L2TPv3_L2_SPECIFIC_DOCSIS_DMPT  4
#define L2TPv3_L2_SPECIFIC_MAX          (L2TPv3_L2_SPECIFIC_DOCSIS_DMPT + 1)

static const enum_val_t l2tpv3_l2_specifics[] = {
    {"detect",  "Detect",               -1},
    {"none",    "None",                 L2TPv3_L2_SPECIFIC_NONE},
    {"default", "Default L2-Specific",  L2TPv3_L2_SPECIFIC_DEFAULT},
    {"atm",     "ATM-Specific",         L2TPv3_L2_SPECIFIC_ATM},
    {"lapd",    "LAPD-Specific",        L2TPv3_L2_SPECIFIC_LAPD},
    {"dmpt",    "DOCSIS DMPT-Specific", L2TPv3_L2_SPECIFIC_DOCSIS_DMPT},
    {NULL, NULL, 0}
};

static gint l2tpv3_cookie = -1;
static gint l2tpv3_l2_specific = -1;

#define MESSAGE_TYPE_SCCRQ         1
#define MESSAGE_TYPE_SCCRP         2
#define MESSAGE_TYPE_SCCCN         3
#define MESSAGE_TYPE_StopCCN       4
#define MESSAGE_TYPE_Reserved_5    5
#define MESSAGE_TYPE_HELLO         6
#define MESSAGE_TYPE_OCRQ          7
#define MESSAGE_TYPE_OCRP          8
#define MESSAGE_TYPE_OCCN          9
#define MESSAGE_TYPE_ICRQ         10
#define MESSAGE_TYPE_ICRP         11
#define MESSAGE_TYPE_ICCN         12
#define MESSAGE_TYPE_Reserved_13  13
#define MESSAGE_TYPE_CDN          14
#define MESSAGE_TYPE_WEN          15
#define MESSAGE_TYPE_SLI          16
#define MESSAGE_TYPE_MDMST        17
#define MESSAGE_TYPE_SRRQ         18
#define MESSAGE_TYPE_SRRP         19
#define MESSAGE_TYPE_ACK          20
#define MESSAGE_TYPE_FSQ          21
#define MESSAGE_TYPE_FSR          22
#define MESSAGE_TYPE_MSRQ         23
#define MESSAGE_TYPE_MSRP         24
#define MESSAGE_TYPE_MSE          25
#define MESSAGE_TYPE_MSI          26
#define MESSAGE_TYPE_MSEN         27
#define MESSAGE_TYPE_CSUN         28
#define MESSAGE_TYPE_CSURQ        29

static const value_string message_type_vals[] = {
    { MESSAGE_TYPE_SCCRQ,       "Start_Control_Request" },
    { MESSAGE_TYPE_SCCRP,       "Start_Control_Reply" },
    { MESSAGE_TYPE_SCCCN,       "Start_Control_Connected" },
    { MESSAGE_TYPE_StopCCN,     "Stop_Control_Notification" },
    { MESSAGE_TYPE_Reserved_5,  "Reserved" },
    { MESSAGE_TYPE_HELLO,       "Hello" },
    { MESSAGE_TYPE_OCRQ,        "Outgoing_Call_Request" },
    { MESSAGE_TYPE_OCRP,        "Outgoing_Call_Reply" },
    { MESSAGE_TYPE_OCCN,        "Outgoing_Call_Connected" },
    { MESSAGE_TYPE_ICRQ,        "Incoming_Call_Request" },
    { MESSAGE_TYPE_ICRP,        "Incoming_Call_Reply" },
    { MESSAGE_TYPE_ICCN,        "Incoming_Call_Connected" },
    { MESSAGE_TYPE_Reserved_13, "Reserved" },
    { MESSAGE_TYPE_CDN,         "Call_Disconnect_Notification" },
    { MESSAGE_TYPE_WEN,         "WAN_Error_Notify" },
    { MESSAGE_TYPE_SLI,         "Set_Link_Info" },
    { MESSAGE_TYPE_MDMST,       "Modem_Status" },
    { MESSAGE_TYPE_SRRQ,        "Service_Relay_Request_Msg" },
    { MESSAGE_TYPE_SRRP,        "Service_Relay_Reply_Message" },
    { MESSAGE_TYPE_ACK,         "Explicit_Acknowledgement" },
    /* Fail Over Extensions - RFC4951 */
    { MESSAGE_TYPE_FSQ,         "Failover_Session_Query_Message" },
    { MESSAGE_TYPE_FSR,         "Failover_Session_Response_Message" },
    /* Multicast Management - RFC4045 */
    { MESSAGE_TYPE_MSRQ,        "Multicast-Session-Request" },
    { MESSAGE_TYPE_MSRP,        "Multicast-Session-Response" },
    { MESSAGE_TYPE_MSE,         "Multicast-Session-Establishment" },
    { MESSAGE_TYPE_MSI,         "Multicast-Session-Information" },
    { MESSAGE_TYPE_MSEN,        "Multicast-Session-End-Notify" },
    { MESSAGE_TYPE_CSUN,        "Connect-Speed-Update-Notification" },
    { MESSAGE_TYPE_CSURQ,       "Connect-Speed-Update-Request" },
    { 0,                        NULL },
};
static value_string_ext message_type_vals_ext = VALUE_STRING_EXT_INIT(message_type_vals);

static const value_string l2tp_message_type_short_str_vals[] = {
    { MESSAGE_TYPE_SCCRQ,       "SCCRQ" },
    { MESSAGE_TYPE_SCCRP,       "SCCRP" },
    { MESSAGE_TYPE_SCCCN,       "SCCCN" },
    { MESSAGE_TYPE_StopCCN,     "StopCCN" },
    { 5,                        "Reserved"},
    { MESSAGE_TYPE_HELLO,       "Hello" },
    { MESSAGE_TYPE_OCRQ,        "OCRQ" },
    { MESSAGE_TYPE_OCRP,        "OCRP" },
    { MESSAGE_TYPE_OCCN,        "OCCN" },
    { MESSAGE_TYPE_ICRQ,        "ICRQ" },
    { MESSAGE_TYPE_ICRP,        "ICRP" },
    { MESSAGE_TYPE_ICCN,        "ICCN" },
    { 13,                       "Reserved"},
    { MESSAGE_TYPE_CDN,         "CDN" },
    { MESSAGE_TYPE_WEN,         "WEN" },
    { MESSAGE_TYPE_SLI,         "SLI" },
    { MESSAGE_TYPE_MDMST,       "MDMST" },
    { MESSAGE_TYPE_SRRQ,        "SRRQ" },
    { MESSAGE_TYPE_SRRP,        "SRRP" },
    { MESSAGE_TYPE_ACK,         "ACK" },
    /* Fail Over Extensions - RFC4951 */
    { MESSAGE_TYPE_FSQ,         "FSQ" },
    { MESSAGE_TYPE_FSR,         "FSR" },
    /* Multicast Management - RFC4045 */
    { MESSAGE_TYPE_MSRQ,        "MSRQ" },
    { MESSAGE_TYPE_MSRP,        "MSRP" },
    { MESSAGE_TYPE_MSE,         "MSE" },
    { MESSAGE_TYPE_MSI,         "MSI" },
    { MESSAGE_TYPE_MSEN,        "MSEN" },
    { MESSAGE_TYPE_CSUN,        "CSUN" },
    { MESSAGE_TYPE_CSURQ,       "CSURQ" },
    { 0,                        NULL },
};
static value_string_ext l2tp_message_type_short_str_vals_ext = VALUE_STRING_EXT_INIT(l2tp_message_type_short_str_vals);


static const char *control_msg = "Control Message";
static const char *data_msg    = "Data    Message";
static const value_string l2tp_type_vals[] = {
    { 0, "Data Message" },
    { 1, "Control Message" },
    { 0, NULL },
};

static const value_string cause_code_direction_vals[] = {
    { 0, "global error" },
    { 1, "at peer" },
    { 2, "at local" },
    { 0, NULL },
};

static const true_false_string l2tp_length_bit_truth =
    { "Length field is present", "Length field is not present" };

static const true_false_string l2tp_seq_bit_truth =
    { "Ns and Nr fields are present", "Ns and Nr fields are not present" };

static const true_false_string l2tp_offset_bit_truth =
    { "Offset Size field is present", "Offset size field is not present" };

static const true_false_string l2tp_priority_truth =
    { "This data message has priority", "No priority" };

static const value_string authen_type_vals[] = {
    { 0, "Reserved" },
    { 1, "Textual username/password exchange" },
    { 2, "PPP CHAP" },
    { 3, "PPP PAP" },
    { 4, "No Authentication" },
    { 5, "Microsoft CHAP Version 1" },
    { 6, "Reserved" },
    { 7, "EAP" },
    { 0, NULL }
};

static const value_string data_sequencing_vals[] = {
    { 0, "No incoming data packets require sequencing" },
    { 1, "Only non-IP data packets require sequencing" },
    { 2, "All incoming data packets require sequencing" },
    { 0, NULL }
};

static const value_string l2_sublayer_vals[] = {
    { 0, "No L2-Specific Sublayer" },
    { 1, "Default L2-Specific Sublayer present" },
    { 2, "ATM-Specific Sublayer present" },
    { 3, "MPT-Specific Sublayer" },
    { 4, "PSP-Specific Sublayer" },
    { 0, NULL }
};

/* Result Code values for the StopCCN message */
static const value_string result_code_stopccn_vals[] = {
    { 0, "Reserved", },
    { 1, "General request to clear control connection", },
    { 2, "General error, Error Code indicates the problem", },
    { 3, "Control connection already exists", },
    { 4, "Requester is not authorized to establish a control connection", },
    { 5, "The protocol version of the requester is not supported", },
    { 6, "Requester is being shut down", },
    { 7, "Finite state machine error or timeout", },
    { 8, "Control connection due to mismatching CCDS value", }, /* [RFC3308] */
    { 0, NULL }
};

/* Result Code values for the CDN message */
static const value_string result_code_cdn_vals[] = {
    {  0, "Reserved", },
    {  1, "Session disconnected due to loss of carrier or circuit disconnect", },
    {  2, "Session disconnected for the reason indicated in Error Code", },
    {  3, "Session disconnected for administrative reasons", },
    {  4, "Appropriate facilities unavailable (temporary condition)", },
    {  5, "Appropriate facilities unavailable (permanent condition)", },
    {  6, "Invalid destination", },
    {  7, "Call failed due to no carrier detected", },
    {  8, "Call failed due to detection of a busy signal", },
    {  9, "Call failed due to lack of a dial tone", },
    { 10, "Call was not established within time allotted by LAC", },
    { 11, "Call was connected but no appropriate framing was detected", },
    { 12, "Disconnecting call due to mismatching SDS value", },
    { 13, "Session not established due to losing tie breaker", },
    { 14, "Session not established due to unsupported PW type", },
    { 15, "Session not established, sequencing required without valid L2-Specific Sublayer", },
    { 16, "Finite state machine error or timeout", },
    { 17, "FR PVC was deleted permanently (no longer provisioned) ", },         /* [RFC4591] */
    { 18, "FR PVC has been INACTIVE for an extended period of time", },         /* [RFC4591] */
    { 19, "Mismatched FR Header Length", },                                     /* [RFC4591] */
    { 20, "HDLC Link was deleted permanently (no longer provisioned)", },       /* [RFC4349] */
    { 21, "HDLC Link has been INACTIVE for an extended period of time", },      /* [RFC4349] */
    { 22, "Session not established due to other LCCE can not support the OAM Cell Emulation", },    /* [RFC4454] */
    { 23, "Mismatching interface MTU", },                                       /* [RFC4667] */
    { 24, "Attempt to connect to non-existent forwarder", },                    /* [RFC4667] */
    { 25, "Attempt to connect to unauthorized forwarder", },                    /* [RFC4667] */
    { 26, "Loop Detected", },                                                   /* [draft-ietf-l2tpext-tunnel-switching-06.txt] */
    { 27, "Attachment Circuit bound to different PE", },                        /* [RFC6074]  */
    { 28, "Attachment Circuit bound to different remote Attachment Circuit", }, /* [RFC6074]  */
    { 29, "Unassigned", },
    { 30, "Return code to indicate connection was refused because of TDM PW parameters. The error code indicates the problem.", }, /* [RFC5611]  */
    { 31, "Sequencing not supported", },                                        /* [RFC6073]  */
    { 0, NULL }
};
static value_string_ext result_code_cdn_vals_ext = VALUE_STRING_EXT_INIT(result_code_cdn_vals);


static const value_string error_code_vals[] = {
    { 0, "No General Error", },
    { 1, "No control connection exists yet for this pair of LCCEs", },
    { 2, "Length is wrong", },
    { 3, "One of the field values was out of range", },
    { 4, "Insufficient resources to handle this operation now", },
    { 5, "Invalid Session ID", },
    { 6, "A generic vendor-specific error occurred", },
    { 7, "Try another", },
    { 8, "Receipt of an unknown AVP with the M bit set", },
    { 9, "Try another directed", },
    { 10, "Next hop unreachable", },
    { 11, "Next hop busy", },
    { 12, "TSA busy", },
    { 0, NULL }
};

#define  CONTROL_MESSAGE               0
#define  RESULT_ERROR_CODE             1
#define  PROTOCOL_VERSION              2
#define  FRAMING_CAPABILITIES          3
#define  BEARER_CAPABILITIES           4
#define  TIE_BREAKER                   5
#define  FIRMWARE_REVISION             6
#define  HOST_NAME                     7
#define  VENDOR_NAME                   8
#define  ASSIGNED_TUNNEL_ID            9
#define  RECEIVE_WINDOW_SIZE          10
#define  CHALLENGE                    11
#define  CAUSE_CODE                   12
#define  CHALLENGE_RESPONSE           13
#define  ASSIGNED_SESSION             14
#define  CALL_SERIAL_NUMBER           15
#define  MINIMUM_BPS                  16
#define  MAXIMUM_BPS                  17
#define  BEARER_TYPE                  18
#define  FRAMING_TYPE                 19
#define  CALLED_NUMBER                21
#define  CALLING_NUMBER               22
#define  SUB_ADDRESS                  23
#define  TX_CONNECT_SPEED             24
#define  PHYSICAL_CHANNEL             25
#define  INITIAL_RECEIVED_LCP_CONFREQ 26
#define  LAST_SENT_LCP_CONFREQ        27
#define  LAST_RECEIVED_LCP_CONFREQ    28
#define  PROXY_AUTHEN_TYPE            29
#define  PROXY_AUTHEN_NAME            30
#define  PROXY_AUTHEN_CHALLENGE       31
#define  PROXY_AUTHEN_ID              32
#define  PROXY_AUTHEN_RESPONSE        33
#define  CALL_STATUS_AVPS             34
#define  ACCM                         35
#define  RANDOM_VECTOR                36
#define  PRIVATE_GROUP_ID             37
#define  RX_CONNECT_SPEED             38
#define  SEQUENCING_REQUIRED          39
#define  PPP_DISCONNECT_CAUSE_CODE    46    /* RFC 3145 */
#define  EXTENDED_VENDOR_ID           58
#define  MESSAGE_DIGEST               59
#define  ROUTER_ID                    60
#define  ASSIGNED_CONTROL_CONN_ID     61
#define  PW_CAPABILITY_LIST           62
#define  LOCAL_SESSION_ID             63
#define  REMOTE_SESSION_ID            64
#define  ASSIGNED_COOKIE              65
#define  REMOTE_END_ID                66
#define  PW_TYPE                      68
#define  L2_SPECIFIC_SUBLAYER         69
#define  DATA_SEQUENCING              70
#define  CIRCUIT_STATUS               71
#define  PREFERRED_LANGUAGE           72
#define  CTL_MSG_AUTH_NONCE           73
#define  TX_CONNECT_SPEED_V3          74
#define  RX_CONNECT_SPEED_V3          75
#define  CONNECT_SPEED_UPDATE         97

/* http://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml */
#define NUM_AVP_TYPES                 102
static const value_string avp_type_vals[] = {
    { CONTROL_MESSAGE,              "Control Message" },
    { RESULT_ERROR_CODE,            "Result-Error Code" },
    { PROTOCOL_VERSION,             "Protocol Version" },
    { FRAMING_CAPABILITIES,         "Framing Capabilities" },
    { BEARER_CAPABILITIES,          "Bearer Capabilities" },
    { TIE_BREAKER,                  "Tie Breaker" },
    { FIRMWARE_REVISION,            "Firmware Revision" },
    { HOST_NAME,                    "Host Name" },
    { VENDOR_NAME,                  "Vendor Name" },
    { ASSIGNED_TUNNEL_ID,           "Assigned Tunnel ID" },
    { RECEIVE_WINDOW_SIZE,          "Receive Window Size" },
    { CHALLENGE,                    "Challenge" },
    { CAUSE_CODE,                   "Cause Code" },
    { CHALLENGE_RESPONSE,           "Challenge Response" },
    { ASSIGNED_SESSION,             "Assigned Session" },
    { CALL_SERIAL_NUMBER,           "Call Serial Number" },
    { MINIMUM_BPS,                  "Minimum BPS" },
    { MAXIMUM_BPS,                  "Maximum BPS" },
    { BEARER_TYPE,                  "Bearer Type" },
    { FRAMING_TYPE,                 "Framing Type" },
    { 20,                           "Reserved" },
    { CALLED_NUMBER,                "Called Number" },
    { CALLING_NUMBER,               "Calling Number" },
    { SUB_ADDRESS,                  "Sub-Address" },
    { TX_CONNECT_SPEED,             "Connect Speed" },
    { PHYSICAL_CHANNEL,             "Physical Channel" },
    { INITIAL_RECEIVED_LCP_CONFREQ, "Initial Received LCP CONFREQ" },
    { LAST_SENT_LCP_CONFREQ,        "Last Sent LCP CONFREQ" },
    { LAST_RECEIVED_LCP_CONFREQ,    "Last Received LCP CONFREQ" },
    { PROXY_AUTHEN_TYPE,            "Proxy Authen Type" },
    { PROXY_AUTHEN_NAME,            "Proxy Authen Name" },
    { PROXY_AUTHEN_CHALLENGE,       "Proxy Authen Challenge" },
    { PROXY_AUTHEN_ID,              "Proxy Authen ID" },
    { PROXY_AUTHEN_RESPONSE,        "Proxy Authen Response" },
    { CALL_STATUS_AVPS,             "Call status AVPs" },
    { ACCM,                         "ACCM" },
    { RANDOM_VECTOR,                "Random Vector" },
    { PRIVATE_GROUP_ID,             "Private group ID" },
    { RX_CONNECT_SPEED,             "RxConnect Speed" },
    { SEQUENCING_REQUIRED,          "Sequencing Required" },
    { PPP_DISCONNECT_CAUSE_CODE,    "PPP Disconnect Cause Code" },
    { EXTENDED_VENDOR_ID,           "Extended Vendor ID" },
    { MESSAGE_DIGEST,               "Message Digest" },
    { ROUTER_ID,                    "Router ID" },
    { ASSIGNED_CONTROL_CONN_ID,     "Assigned Control Connection ID" },
    { PW_CAPABILITY_LIST,           "Pseudowire Capability List" },
    { LOCAL_SESSION_ID,             "Local Session ID" },
    { REMOTE_SESSION_ID,            "Remote Session ID" },
    { ASSIGNED_COOKIE,              "Assigned Cookie" },
    { REMOTE_END_ID,                "Remote End ID" },
    { PW_TYPE,                      "Pseudowire Type" },
    { L2_SPECIFIC_SUBLAYER,         "Layer2 Specific Sublayer" },
    { DATA_SEQUENCING,              "Data Sequencing" },
    { CIRCUIT_STATUS,               "Circuit Status" },
    { PREFERRED_LANGUAGE,           "Preferred Language" },
    { CTL_MSG_AUTH_NONCE,           "Control Message Authentication Nonce" },
    { TX_CONNECT_SPEED_V3,          "Tx Connect Speed Version 3" },
    { RX_CONNECT_SPEED_V3,          "Rx Connect Speed Version 3" },
    { 76,                           "Failover Capability" },                            /*[RFC4951] */
    { 77,                           "Tunnel Recovery" },                                /*[RFC4951] */
    { 78,                           "Suggested Control Sequence" },                     /*[RFC4951] */
    { 79,                           "Failover Session State" },                         /*[RFC4951] */
    { 80,                           "Multicast Capability" },                           /*[RFC4045] */
    { 81,                           "New Outgoing Sessions" },                          /*[RFC4045] */
    { 82,                           "New Outgoing Sessions Acknowledgement" },          /*[RFC4045] */
    { 83,                           "Withdraw Outgoing Sessions" },                     /*[RFC4045] */
    { 84,                           "Multicast Packets Priority" },                     /*[RFC4045] */
    { 85,                           "Frame-Relay Header Length" },                      /*[RFC4591] */
    { 86,                           "ATM Maximum Concatenated Cells" },                 /*[RFC4454] */
    { 87,                           "OAM Emulation Required" },                         /*[RFC4454] */
    { 88,                           "ATM Alarm Status" },                               /*[RFC4454] */
    /*        Also, see ATM Alarm Status AVP Values below */
    { 89,                           "Attachment Group Identifier" },                    /*[RFC4667] */
    { 90,                           "Local End Identifier" },                           /*[RFC4667] */
    { 91,                           "Interface Maximum Transmission Unit" },            /*[RFC4667] */
    { 92,                           "FCS Retention" },                                  /*[RFC4720] */
    { 93,                           "Tunnel Switching Aggregator ID" },                 /*[draft-ietf-l2tpext-tunnel-switching-06.txt] */
    { 94,                           "Maximum Receive Unit (MRU)" },                     /*[RFC4623] */
    { 95,                           "Maximum Reassembled Receive Unit (MRRU)" },        /*[RFC4623] */
    { 96,                           "VCCV Capability" },                                /*[RFC5085] */
    { CONNECT_SPEED_UPDATE,         "Connect Speed Update" },                           /*[RFC5515] */
    { 98,                           "Connect Speed Update Enable" },                    /*[RFC5515] */
    { 99,                           "TDM Pseudowire" },                                 /*[RFC5611] */
    { 100,                          "RTP AVP" },                                        /*[RFC5611] */
    { 101,                          "PW Switching Point" },                             /*[RFC6073] */
    { 0,                         NULL }
};

static value_string_ext avp_type_vals_ext = VALUE_STRING_EXT_INIT(avp_type_vals);

#define CISCO_ACK                        0
#define CISCO_ASSIGNED_CONNECTION_ID     1
#define CISCO_PW_CAPABILITY_LIST         2
#define CISCO_LOCAL_SESSION_ID           3
#define CISCO_REMOTE_SESSION_ID          4
#define CISCO_ASSIGNED_COOKIE            5
#define CISCO_REMOTE_END_ID              6
#define CISCO_PW_TYPE                    7
#define CISCO_CIRCUIT_STATUS             8
#define CISCO_SESSION_TIE_BREAKER        9
#define CISCO_DRAFT_AVP_VERSION         10
#define CISCO_MESSAGE_DIGEST            12
#define CISCO_AUTH_NONCE                13
#define CISCO_INTERFACE_MTU             14

static const value_string cisco_avp_type_vals[] = {
    { CISCO_ACK,                      "Cisco ACK" },
    { CISCO_ASSIGNED_CONNECTION_ID,   "Assigned Connection ID" },
    { CISCO_PW_CAPABILITY_LIST,       "Pseudowire Capabilities List" },
    { CISCO_LOCAL_SESSION_ID,         "Local Session ID" },
    { CISCO_REMOTE_SESSION_ID,        "Remote Session ID" },
    { CISCO_ASSIGNED_COOKIE,          "Assigned Cookie" },
    { CISCO_REMOTE_END_ID,            "Remote End ID" },
    { CISCO_PW_TYPE,                  "Pseudowire Type" },
    { CISCO_CIRCUIT_STATUS,           "Circuit Status" },
    { CISCO_SESSION_TIE_BREAKER,      "Session Tie Breaker" },
    { CISCO_DRAFT_AVP_VERSION,        "Draft AVP Version" },
    { CISCO_MESSAGE_DIGEST,           "Message Digest" },
    { CISCO_AUTH_NONCE,               "Control Message Authentication Nonce" },
    { CISCO_INTERFACE_MTU,            "Interface MTU" },
    { 0,                              NULL }
};

#define ERICSSON_MSG_TYPE               0
#define ERICSSON_TRANSPORT_CONFIG       1
#define ERICSSON_PACKET_LOSS            2
#define ERICSSON_PROTO_VERSION          3
#define ERICSSON_CONN_TYPE              4
#define ERICSSON_CRC_ENABLED            5
#define ERICSSON_STN_NAME               6
#define ERICSSON_ABIS_LOWER_MODE        7
#define ERICSSON_TEI_TO_SC_MAP          8
#define ERICSSON_CHAN_STATUS_LIST       9
#define ERICSSON_EXT_PROTO_VERSION      10
#define ERICSSON_CHAN_STATUS_LIST2      11

static const value_string ericsson_avp_type_vals[] = {
    { ERICSSON_MSG_TYPE,              "Message Type" },
    { ERICSSON_TRANSPORT_CONFIG,      "Transport Configuration" },
    { ERICSSON_PACKET_LOSS,           "Packet Loss" },
    { ERICSSON_PROTO_VERSION,         "Protocol Version" },
    { ERICSSON_CONN_TYPE,             "Connection Type" },
    { ERICSSON_STN_NAME,              "STN Name" },
    { ERICSSON_CRC_ENABLED,           "CRC32 Enabled" },
    { ERICSSON_ABIS_LOWER_MODE,       "Abis Lower Mode" },
    { ERICSSON_TEI_TO_SC_MAP,         "TEI to SC Map" },
    { ERICSSON_CHAN_STATUS_LIST,      "Channel Status List" },
    { ERICSSON_EXT_PROTO_VERSION,     "Extended Protocol Version" },
    { ERICSSON_CHAN_STATUS_LIST2,     "Channel Status List 2" },
    { 0,                              NULL }
};

static const value_string ericsson_msg_type_vals[] = {
    { 0,   "Transport Configuration Notification" },
    { 1,   "Performance Notification" },
    { 2,   "Transport Configuration Request" },
    { 3,   "Transport Configuration Response" },
    { 4,   "Abis Lower Transport Config Request" },
    { 5,   "Abis Lower Transport Config Response" },
    { 6,   "Local Connect Channel Status Notification" },
    { 0,   NULL }
};

static const value_string ericsson_short_msg_type_vals[] = {
    { 0,   "TCN" },
    { 1,   "PN" },
    { 2,   "TCRQ" },
    { 3,   "TCRP" },
    { 4,   "ALTCRQ" },
    { 5,   "ALTCRP" },
    { 6,   "LCCSN" },
    { 0,   NULL }
};

static const value_string ericsson_conn_type_vals[] = {
    { 0,   "Primary" },
    { 1,   "Secondary" },
    { 0,   NULL }
};

static const value_string ericsson_abis_lower_mode_vals[] = {
    { 0,   "Single Timeslot" },
    { 1,   "Super Channel" },
    { 0,   NULL }
};

#define BROADBAND_AGENT_CIRCUIT_ID                    1
#define BROADBAND_AGENT_REMOTE_ID                     2
#define BROADBAND_ACTUAL_DR_UP                      129
#define BROADBAND_ACTUAL_DR_DOWN                    130
#define BROADBAND_MINIMUM_DR_UP                     131
#define BROADBAND_MINIMUM_DR_DOWN                   132
#define BROADBAND_ATTAINABLE_DR_UP                  133
#define BROADBAND_ATTAINABLE_DR_DOWN                134
#define BROADBAND_MAXIMUM_DR_UP                     135
#define BROADBAND_MAXIMUM_DR_DOWN                   136
#define BROADBAND_MINIMUM_DR_UP_LOW_POWER           137
#define BROADBAND_MINIMUM_DR_DOWN_LOW_POWER         138
#define BROADBAND_MAXIMUM_INTERLEAVING_DELAY_UP     139
#define BROADBAND_ACTUAL_INTERLEAVING_DELAY_UP      140
#define BROADBAND_MAXIMUM_INTERLEAVING_DELAY_DOWN   141
#define BROADBAND_ACTUAL_INTERLEAVING_DELAY_DOWN    142
#define BROADBAND_ACCESS_LOOP_ENCAPSULATION         144
#define BROADBAND_ANCP_ACCESS_LINE_TYPE             145
#define BROADBAND_IWF_SESSION                       254

static const value_string broadband_avp_type_vals[] = {
    { BROADBAND_AGENT_CIRCUIT_ID,                 "Agent-Circuit-Id" },
    { BROADBAND_AGENT_REMOTE_ID,                  "Agent-Remote-Id" },
    { BROADBAND_ACTUAL_DR_UP,                     "Actual-Data-Rate-Upstream" },
    { BROADBAND_ACTUAL_DR_DOWN,                   "Actual-Data-Rate-Downstream" },
    { BROADBAND_MINIMUM_DR_UP,                    "Minimum-Data-Rate-Upstream" },
    { BROADBAND_MINIMUM_DR_DOWN,                  "Minimum-Data-Rate-Downstream" },
    { BROADBAND_ATTAINABLE_DR_UP,                 "Attainable-Data-Rate-Upstream" },
    { BROADBAND_ATTAINABLE_DR_DOWN,               "Attainable-Data-Rate-Downstream" },
    { BROADBAND_MAXIMUM_DR_UP,                    "Maximum-Data-Rate-Upstream" },
    { BROADBAND_MAXIMUM_DR_DOWN,                  "Maximum-Data-Rate-Downstream" },
    { BROADBAND_MINIMUM_DR_UP_LOW_POWER,          "Minimum-Data-Rate-Upstream-Low-Power" },
    { BROADBAND_MINIMUM_DR_DOWN_LOW_POWER,        "Minimum-Data-Rate-Downstream-Low-Power" },
    { BROADBAND_MAXIMUM_INTERLEAVING_DELAY_UP,    "Maximum-Interleaving-Delay-Upstream" },
    { BROADBAND_ACTUAL_INTERLEAVING_DELAY_UP,     "Actual-Interleaving-Delay-Upstream" },
    { BROADBAND_MAXIMUM_INTERLEAVING_DELAY_DOWN,  "Maximum-Interleaving-Delay-Downstream" },
    { BROADBAND_ACTUAL_INTERLEAVING_DELAY_DOWN,   "Actual-Interleaving-Delay-Downstream" },
    { BROADBAND_ACCESS_LOOP_ENCAPSULATION,        "Access-Loop-Encapsulation" },
    { BROADBAND_ANCP_ACCESS_LINE_TYPE,            "ANCP Access Line Type" },
    { BROADBAND_IWF_SESSION,                      "IWF-Session" },
    { 0,                                          NULL }
};

static const value_string cablelabs_avp_type_vals[] = {
    /* 7.5.2 DEPI Specific AVPs */
    { 0,   "Reserved" },
    { 1,   "DEPI Result Code" },
    { 2,   "DEPI Resource Allocation Request" },
    { 3,   "DEPI Resource Allocation Reply" },
    { 4,   "DEPI Local MTU" },
    { 5,   "DOCSIS SYNC Control" },
    { 6,   "EQAM Capability Bits" },
    { 7,   "DEPI Remote MTU" },
    { 8,   "DEPI Local UDP Port" },
    { 9,   "DPR Session Type" },
    { 10,  "DPR Session Status" },
    /* 7.5.3 QAM Channel PHY AVPs */
    { 100, "Downstream QAM Channel TSID Group" },
    { 101, "Downstream QAM Channel Frequency" },
    { 102, "Downstream QAM Channel Power" },
    { 103, "Downstream QAM Channel Modulation" },
    { 104, "Downstream QAM Channel J.83 Annex" },
    { 105, "Downstream QAM Channel Symbol Rate" },
    { 106, "Downstream QAM Channel Interleave Depth" },
    { 107, "Downstream QAM Channel RF Block Muting53" },
    /* 7.5.4 DEPI Redundancy Capabilities AVPs */
    { 200, "DEPI Redundancy Capabilities" },
    { 0,                              NULL }
};

static const value_string l2tp_cablel_modulation_vals[] = {
    { 0,   "64-QAM" },
    { 1,   "128-QAM" },
    { 0,        NULL }
};

static const value_string pw_types_vals[] = {
    { L2TPv3_PW_FR,          "Frame Relay DLCI" },
    { L2TPv3_PW_AAL5,        "ATM AAL5 SDU VCC transport" },
    { L2TPv3_PW_ATM_PORT,    "ATM Cell transparent Port Mode" },
    { L2TPv3_PW_ETH_VLAN,    "Ethernet VLAN" },
    { L2TPv3_PW_ETH,         "Ethernet" },
    { L2TPv3_PW_CHDLC,       "HDLC" },
    { L2TPv3_PW_PPP,         "PPP" }, /* Currently unassigned */
    { L2TPv3_PW_ATM_VCC,     "ATM Cell transport VCC Mode" },
    { L2TPv3_PW_ATM_VPC,     "ATM Cell transport VPC Mode" },
    { L2TPv3_PW_IP,          "IP Transport" }, /* Currently unassigned */
    { L2TPv3_PW_DOCSIS_DMPT, "MPEG-TS Payload Type (MPTPW)" },
    { L2TPv3_PW_DOCSIS_PSP,  "Packet Streaming Protocol (PSPPW)" },
    /* 0x000E-0x0010 Unassigned */
    { L2TPv3_PW_E1,          "Structure-agnostic E1 circuit" },       /* [RFC5611]  */
    { L2TPv3_PW_T1,          "Structure-agnostic T1 (DS1) circuit" }, /* [RFC5611]  */
    { L2TPv3_PW_E3,          "Structure-agnostic E3 circuit" },       /* [RFC5611]  */
    { L2TPv3_PW_T3,          "Structure-agnostic T3 (DS3) circuit" }, /* [RFC5611]  */
    { L2TPv3_PW_CESOPSN,     "CESoPSN basic mode" },                  /* [RFC5611]  */
    { 0x0016,                "Unassigned" },
    { L2TPv3_PW_CESOPSN_CAS, "CESoPSN TDM with CAS" },                /* [RFC5611]  */

    { 0,  NULL },
};

static const value_string ale_datalink_types_vals[] = {
    { 0x00,  "ATM AAL5" },
    { 0x01,  "Ethernet" },
    { 0,     NULL },
};

static const value_string ale_enc1_types_vals[] = {
    { 0x00,  "NA - Not Available" },
    { 0x01,  "Untagged Ethernet" },
    { 0x02,  "Single-Tagged Ethernet" },
    { 0,     NULL },
};

static const value_string ale_enc2_types_vals[] = {
    { 0x00,  "NA - Not Available" },
    { 0x01,  "PPPoA LLC" },
    { 0x02,  "PPPoA Null" },
    { 0x03,  "IP over ATM (IPoA) LLC" },
    { 0x04,  "IPoA Null" },
    { 0x05,  "Ethernet over AAL5 LLC with Frame Check Sequence (FCS)" },
    { 0x06,  "Ethernet over AAL5 LLC without FCS" },
    { 0x07,  "Ethernet over AAL5 Null with FCS" },
    { 0x08,  "Ethernet over AAL5 Null without FCS" },
    { 0,     NULL },
};

static const value_string ancp_types_vals[] = {
    { 0x01,  "ADSL1" },
    { 0x02,  "ADSL2" },
    { 0x03,  "ADSL2+" },
    { 0x04,  "VDSL1" },
    { 0x05,  "VDSL2" },
    { 0x06,  "SDSL" },
    { 0x07,  "UNKNOWN" },
    { 0,     NULL },
};

static const value_string iwf_types_vals[] = {
    { 0x00,  "IWF not performed" },
    { 0x01,  "IWF performed" },
    { 0,     NULL },
};

static const val64_string unique_indeterminable_or_no_link[] = {
    { 0, "indeterminable or no physical p2p link" },
    { 0, NULL },
};

static const true_false_string tfs_new_existing = { "New", "Existing" };

static dissector_handle_t ppp_hdlc_handle;
static dissector_handle_t ppp_lcp_options_handle;

static dissector_handle_t atm_oam_handle;
static dissector_handle_t llc_handle;

static dissector_handle_t l2tp_udp_handle;
static dissector_handle_t l2tp_ip_handle;

#define L2TP_HMAC_MD5  0
#define L2TP_HMAC_SHA1 1

typedef struct l2tpv3_conversation {
    address               lcce1;
    guint16               lcce1_port;
    address               lcce2;
    guint16               lcce2_port;
    port_type             pt;
    struct l2tpv3_tunnel *tunnel;
} l2tpv3_conversation_t;

typedef struct l2tpv3_tunnel {
    l2tpv3_conversation_t *conv;

    address  lcce1;
    guint32  lcce1_id;
    guint8  *lcce1_nonce;
    gint     lcce1_nonce_len;

    address  lcce2;
    guint32  lcce2_id;
    guint8  *lcce2_nonce;
    gint     lcce2_nonce_len;

    gchar   *shared_key_secret;
    guint8   shared_key[HASH_MD5_LENGTH];

    GSList  *sessions;
} l2tpv3_tunnel_t;

typedef struct lcce_settings {
    guint32 id;
    gint    cookie_len;
    gint    l2_specific;
} lcce_settings_t;

typedef struct l2tpv3_session {
    lcce_settings_t lcce1;
    lcce_settings_t lcce2;

    guint    pw_type;
} l2tpv3_session_t;

static const gchar* shared_secret = "";

static GSList *list_heads = NULL;

static void update_shared_key(l2tpv3_tunnel_t *tunnel)
{
    const gchar *secret = "";

    /* There is at least one nonce in the packet, so we can do authentication,
       otherwise it's just a plain digest without nonces. */
    if (tunnel->lcce1_nonce != NULL || tunnel->lcce2_nonce != NULL) {
        secret = shared_secret;
    }

    /* If there's no shared key in the conversation context, or the secret has been changed */
    if (tunnel->shared_key_secret == NULL || strcmp(secret, tunnel->shared_key_secret) != 0) {
        /* For secret specification, see RFC 3931 pg 37 */
        guint8 data = 2;
        if (ws_hmac_buffer(GCRY_MD_MD5, tunnel->shared_key, &data, 1, secret, strlen(secret))) {
            return;
        }
        tunnel->shared_key_secret = wmem_strdup(wmem_file_scope(), secret);
    }
}

static void md5_hmac_digest(l2tpv3_tunnel_t *tunnel,
                            tvbuff_t *tvb,
                            int length,
                            int idx,
                            int avp_len,
                            int msg_type,
                            packet_info *pinfo,
                            guint8 digest[20])
{
    guint8 zero[HASH_MD5_LENGTH] = { 0 };
    gcry_md_hd_t hmac_handle;
    int remainder;
    int offset = 0;

    if (tunnel->conv->pt == PT_NONE) /* IP encapsulated L2TPv3 */
        offset = 4;

    if (gcry_md_open(&hmac_handle, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC)) {
        return;
    }
    if (gcry_md_setkey(hmac_handle, tunnel->shared_key, HASH_MD5_LENGTH)) {
        gcry_md_close(hmac_handle);
        return;
    }

    if (msg_type != MESSAGE_TYPE_SCCRQ) {
        if (tunnel->lcce1_nonce != NULL && tunnel->lcce2_nonce != NULL) {
            if (addresses_equal(&tunnel->lcce1, &pinfo->src)) {
                gcry_md_write(hmac_handle, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
                gcry_md_write(hmac_handle, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
            } else {
                gcry_md_write(hmac_handle, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
                gcry_md_write(hmac_handle, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
            }
        }
    }

    gcry_md_write(hmac_handle, tvb_get_ptr(tvb, offset, idx + 1 - offset), idx + 1 - offset);
    /* Message digest is calculated with an empty message digest field */
    gcry_md_write(hmac_handle, zero, avp_len - 1);
    remainder = length - (idx + avp_len);
    gcry_md_write(hmac_handle, tvb_get_ptr(tvb, idx + avp_len, remainder), remainder);
    memcpy(digest, gcry_md_read(hmac_handle, 0), HASH_MD5_LENGTH);
    gcry_md_close(hmac_handle);
}

static void sha1_hmac_digest(l2tpv3_tunnel_t *tunnel,
                             tvbuff_t *tvb,
                             int length,
                             int idx,
                             int avp_len,
                             int msg_type,
                             packet_info *pinfo,
                             guint8 digest[20])
{
    guint8 zero[HASH_SHA1_LENGTH] = { 0 };
    gcry_md_hd_t hmac_handle;
    int remainder;
    int offset = 0;

    if (tunnel->conv->pt == PT_NONE) /* IP encapsulated L2TPv3 */
        offset = 4;

    if (gcry_md_open(&hmac_handle, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC)) {
        return;
    }
    if (gcry_md_setkey(hmac_handle, tunnel->shared_key, HASH_MD5_LENGTH)) {
        gcry_md_close(hmac_handle);
        return;
    }

    if (msg_type != MESSAGE_TYPE_SCCRQ) {
        if (tunnel->lcce1_nonce != NULL && tunnel->lcce2_nonce != NULL) {
            if (addresses_equal(&tunnel->lcce1, &pinfo->src)) {
                gcry_md_write(hmac_handle, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
                gcry_md_write(hmac_handle, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
            } else {
                gcry_md_write(hmac_handle, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
                gcry_md_write(hmac_handle, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
            }
        }
    }

    gcry_md_write(hmac_handle, tvb_get_ptr(tvb, offset, idx + 1 - offset), idx + 1 - offset);
    /* Message digest is calculated with an empty message digest field */
    gcry_md_write(hmac_handle, zero, avp_len - 1);
    remainder = length - (idx + avp_len);
    gcry_md_write(hmac_handle, tvb_get_ptr(tvb, idx + avp_len, remainder), remainder);
    memcpy(digest, gcry_md_read(hmac_handle, 0), HASH_SHA1_LENGTH);
    gcry_md_close(hmac_handle);
}

static int check_control_digest(l2tpv3_tunnel_t *tunnel,
                                tvbuff_t *tvb,
                                int length,
                                int idx,
                                int avp_len,
                                int msg_type,
                                packet_info *pinfo)
{
    guint8 digest[HASH_SHA1_LENGTH];

    if (!tunnel)
        return 1;

    update_shared_key(tunnel);

    switch (tvb_get_guint8(tvb, idx)) {
        case L2TP_HMAC_MD5:
            if ((avp_len - 1) != HASH_MD5_LENGTH)
                return -1;
            md5_hmac_digest(tunnel, tvb, length, idx, avp_len, msg_type, pinfo, digest);
            break;
        case L2TP_HMAC_SHA1:
            if ((avp_len - 1) != HASH_SHA1_LENGTH)
                return -1;
            sha1_hmac_digest(tunnel, tvb, length, idx, avp_len, msg_type, pinfo, digest);
            break;
        default:
            return 1;
            break;
    }

    return tvb_memeql(tvb, idx + 1, digest, avp_len - 1);
}

static void store_cma_nonce(l2tpv3_tunnel_t *tunnel,
                            tvbuff_t *tvb,
                            int offset,
                            int length,
                            int msg_type)
{
    guint8 *nonce = NULL;

    if (!tunnel)
        return;

    switch (msg_type) {
        case MESSAGE_TYPE_SCCRQ:
            if (!tunnel->lcce1_nonce) {
                tunnel->lcce1_nonce = (guint8 *)wmem_alloc(wmem_file_scope(), length);
                tunnel->lcce1_nonce_len = length;
                nonce = tunnel->lcce1_nonce;
            }
            break;
        case MESSAGE_TYPE_SCCRP:
            if (!tunnel->lcce2_nonce) {
                tunnel->lcce2_nonce = (guint8 *)wmem_alloc(wmem_file_scope(), length);
                tunnel->lcce2_nonce_len = length;
                nonce = tunnel->lcce2_nonce;
            }
            break;
        default:
            break;
    }

    if (nonce)
        tvb_memcpy(tvb, (void *)nonce, offset, length);

    return;
}

static void store_ccid(l2tpv3_tunnel_t *tunnel,
                       tvbuff_t *tvb,
                       int offset,
                       int msg_type)
{
    if (!tunnel)
        return;

    switch (msg_type) {
        case MESSAGE_TYPE_SCCRQ:
            tunnel->lcce1_id = tvb_get_ntohl(tvb, offset);
            break;
        case MESSAGE_TYPE_SCCRP:
            tunnel->lcce2_id = tvb_get_ntohl(tvb, offset);
            break;
        default:
            break;
    }

    return;
}

static l2tpv3_session_t *find_session(l2tpv3_tunnel_t *tunnel,
                                      guint32 lcce1_id,
                                      guint32 lcce2_id)
{
    l2tpv3_session_t *session = NULL;
    GSList *iterator;

    iterator = tunnel->sessions;
    while (iterator) {
        session = (l2tpv3_session_t *)iterator->data;

        if ((session->lcce1.id == lcce1_id) ||
            (session->lcce2.id == lcce2_id)) {
                return session;
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

static void init_session(l2tpv3_session_t *session)
{
    session->lcce1.cookie_len = session->lcce2.cookie_len = -1;
    session->lcce1.l2_specific = session->lcce2.l2_specific = -1;
    session->pw_type = L2TPv3_PW_DEFAULT;
}

static l2tpv3_session_t *alloc_session(void)
{
    l2tpv3_session_t *session = wmem_new0(wmem_packet_scope(), l2tpv3_session_t);
    init_session(session);

    return session;
}

static l2tpv3_session_t *store_lsession_id(l2tpv3_session_t *_session,
                                         tvbuff_t *tvb,
                                         int offset,
                                         int msg_type)
{
    l2tpv3_session_t *session = _session;

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
        case MESSAGE_TYPE_ICRP:
        case MESSAGE_TYPE_OCRP:
            break;
        default:
            return session;
    }

    if (session == NULL)
        session = alloc_session();

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
            session->lcce1.id = tvb_get_ntohl(tvb, offset);
            break;
        case MESSAGE_TYPE_ICRP:
        case MESSAGE_TYPE_OCRP:
            session->lcce2.id = tvb_get_ntohl(tvb, offset);
            break;
    }

    return session;
}

static l2tpv3_session_t *store_rsession_id(l2tpv3_session_t *_session,
                                         tvbuff_t *tvb,
                                         int offset,
                                         int msg_type)
{
    l2tpv3_session_t *session = _session;

    switch (msg_type) {
        case MESSAGE_TYPE_ICRP:
        case MESSAGE_TYPE_OCRP:
            break;
        default:
            return session;
    }

    if (session == NULL)
        session = alloc_session();

    session->lcce1.id = tvb_get_ntohl(tvb, offset);

    return session;
}

static l2tpv3_session_t *store_cookie_len(l2tpv3_session_t *_session,
                                        int len,
                                        int msg_type)
{
    l2tpv3_session_t *session = _session;

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
        case MESSAGE_TYPE_ICRP:
        case MESSAGE_TYPE_OCRP:
            break;
        default:
            return session;
    }

    if (session == NULL)
        session = alloc_session();

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
            session->lcce1.cookie_len = len;
            break;
        case MESSAGE_TYPE_ICRP:
        case MESSAGE_TYPE_OCRP:
            session->lcce2.cookie_len = len;
            break;
    }

    return session;
}

static l2tpv3_session_t *store_pw_type(l2tpv3_session_t *_session,
                                     tvbuff_t *tvb,
                                     int offset,
                                     int msg_type)
{
    l2tpv3_session_t *session = _session;

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
            break;
        default:
            return session;
    }

    if (session == NULL)
        session = alloc_session();

    session->pw_type = tvb_get_ntohs(tvb, offset);

    return session;
}

static l2tpv3_session_t *store_l2_sublayer(l2tpv3_session_t *_session,
                                           tvbuff_t *tvb,
                                           int offset,
                                           int msg_type)
{
    l2tpv3_session_t *session = _session;
    gint result = l2tpv3_l2_specific;
    guint16 l2_sublayer;

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
        case MESSAGE_TYPE_ICCN:
        case MESSAGE_TYPE_OCCN:
        case MESSAGE_TYPE_ICRP:
        case MESSAGE_TYPE_OCRP:
            break;
        default:
            return session;
    }

    if (session == NULL)
        session = alloc_session();

    l2_sublayer = tvb_get_ntohs(tvb, offset);
    switch (l2_sublayer) {
       case 0x0000:
           result = L2TPv3_L2_SPECIFIC_NONE; break;
       case 0x0001:
           result = L2TPv3_L2_SPECIFIC_DEFAULT; break;
       case 0x0002:
           result = L2TPv3_L2_SPECIFIC_ATM; break;
       case 0x0003:
           result = L2TPv3_L2_SPECIFIC_DOCSIS_DMPT; break;
       default:
           break;
    }

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
        case MESSAGE_TYPE_ICCN:
        case MESSAGE_TYPE_OCCN:
            session->lcce1.l2_specific = result;
        /* FALL THROUGH */
        case MESSAGE_TYPE_ICRP:
        case MESSAGE_TYPE_OCRP:
            session->lcce2.l2_specific = result;
            break;
    }

    return session;
}

static void update_session(l2tpv3_tunnel_t *tunnel, l2tpv3_session_t *session)
{
    l2tpv3_session_t *existing = NULL;

    if (tunnel == NULL || session == NULL)
        return;

    if (session->lcce1.id == 0 && session->lcce2.id == 0)
        return;

    existing = find_session(tunnel, session->lcce1.id, session->lcce2.id);
    if (!existing) {
        existing = wmem_new0(wmem_file_scope(), l2tpv3_session_t);
        init_session(existing);
    }

    if (session->lcce1.id != 0)
        existing->lcce1.id = session->lcce1.id;

    if (session->lcce2.id != 0)
        existing->lcce2.id = session->lcce2.id;

    if (session->lcce1.cookie_len != -1)
        existing->lcce1.cookie_len = session->lcce1.cookie_len;

    if (session->lcce2.cookie_len != -1)
        existing->lcce2.cookie_len = session->lcce2.cookie_len;

    if (session->lcce1.l2_specific != -1)
        existing->lcce1.l2_specific = session->lcce1.l2_specific;

    if (session->lcce2.l2_specific != -1)
        existing->lcce2.l2_specific = session->lcce2.l2_specific;

    if (session->pw_type != L2TPv3_PW_DEFAULT)
        existing->pw_type = session->pw_type;

    if (tunnel->sessions == NULL) {
        tunnel->sessions = g_slist_append(tunnel->sessions, existing);
        list_heads = g_slist_append(list_heads, tunnel->sessions);
    } else {
        tunnel->sessions = g_slist_append(tunnel->sessions, existing);
    }
}

static void l2tp_prompt(packet_info *pinfo _U_, gchar* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Decode L2TPv3 pseudowire type 0x%04x as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_l2tp, 0)));
}

static gpointer l2tp_value(packet_info *pinfo _U_)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_l2tp, 0);
}

/*
 * Dissect CISCO AVP:s
 */
static int dissect_l2tp_cisco_avps(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, l2tp_cntrl_data_t *l2tp_cntrl_data, l2tpv3_session_t **session) {

    int offset = 0;
    int         avp_type;
    guint32     avp_vendor_id;
    guint16     avp_len;
    guint16     ver_len_hidden;
    proto_tree *l2tp_avp_tree, *l2tp_avp_tree_sub;

    ver_len_hidden  = tvb_get_ntohs(tvb, offset);
    avp_len         = AVP_LENGTH(ver_len_hidden);
    avp_vendor_id   = tvb_get_ntohs(tvb, offset + 2);
    avp_type        = tvb_get_ntohs(tvb, offset + 4);

    l2tp_avp_tree =  proto_tree_add_subtree_format(tree, tvb, offset,
                              avp_len, ett_l2tp_avp, NULL, "Vendor %s (%u): %s AVP",
                              enterprises_lookup(avp_vendor_id, "Unknown"), avp_vendor_id,
                              val_to_str(avp_type, cisco_avp_type_vals, "Unknown (%u)"));

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_mandatory, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hidden, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_length, tvb, offset, 2, ENC_BIG_ENDIAN);

    if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
        offset += avp_len;
        return offset;
    }

    offset += 2;
    avp_len -= 2;

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    avp_len -= 2;

    proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_cisco_avp_type, tvb, offset, 2, avp_type);
    offset += 2;
    avp_len -= 2;

    switch (avp_type) {
    case CISCO_ACK:
        /* process_l2tpv3_control does not set COL_INFO for vendor messages */
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Cisco ACK (ccid=%u)", control_msg, l2tp_cntrl_data->ccid);
        break;

    case CISCO_ASSIGNED_CONNECTION_ID:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_assigned_control_connection_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;

    case CISCO_PW_CAPABILITY_LIST:
        l2tp_avp_tree_sub = proto_tree_add_subtree(l2tp_avp_tree, tvb, offset, avp_len,
                                    ett_l2tp_avp_sub, NULL, "Pseudowire Capabilities List");
        while (avp_len >= 2) {
            proto_tree_add_item(l2tp_avp_tree_sub, hf_l2tp_cisco_pw_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            avp_len -= 2;
        }
        break;

    case CISCO_LOCAL_SESSION_ID:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_local_session_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        *session = store_lsession_id(*session, tvb, offset, l2tp_cntrl_data->msg_type);
        break;
    case CISCO_REMOTE_SESSION_ID:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_remote_session_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        *session = store_rsession_id(*session, tvb, offset, l2tp_cntrl_data->msg_type);
        break;
    case CISCO_ASSIGNED_COOKIE:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_assigned_cookie, tvb, offset, avp_len, ENC_NA);
        *session = store_cookie_len(*session, avp_len, l2tp_cntrl_data->msg_type);
        break;
    case CISCO_REMOTE_END_ID:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_remote_end_id, tvb, offset, avp_len, ENC_NA|ENC_ASCII);
        break;
    case CISCO_PW_TYPE:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_pseudowire_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        *session = store_pw_type(*session, tvb, offset, l2tp_cntrl_data->msg_type);
        break;
    case CISCO_CIRCUIT_STATUS:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_circuit_status, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_circuit_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case CISCO_SESSION_TIE_BREAKER:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_tie_breaker,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        break;
    case CISCO_DRAFT_AVP_VERSION:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_draft_avp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case CISCO_MESSAGE_DIGEST:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_message_digest, tvb, offset, avp_len, ENC_NA);
        break;
    case CISCO_AUTH_NONCE:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_nonce, tvb, offset, avp_len, ENC_NA);
        break;
    case CISCO_INTERFACE_MTU:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cisco_interface_mtu, tvb, offset, avp_len, ENC_BIG_ENDIAN);
        break;

    default:
        proto_tree_add_expert(l2tp_avp_tree, pinfo, &ei_l2tp_vendor_specific_avp_data, tvb, offset, avp_len);
        break;
    }
    offset += avp_len;

    return offset;
}

/*
 * Dissect Broadband Forums AVP:s
 */
static int dissect_l2tp_broadband_avps(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree) {

    int offset = 0;
    int         avp_type;
    guint32     avp_vendor_id;
    guint16     avp_len;
    guint16     ver_len_hidden;
    proto_tree *l2tp_avp_tree, *l2tp_avp_ale_tree;
    proto_item *ta;

    ver_len_hidden  = tvb_get_ntohs(tvb, offset);
    avp_len         = AVP_LENGTH(ver_len_hidden);
    avp_vendor_id   = tvb_get_ntohs(tvb, offset + 2);
    avp_type        = tvb_get_ntohs(tvb, offset + 4);

    l2tp_avp_tree =  proto_tree_add_subtree_format(tree, tvb, offset,
                              avp_len, ett_l2tp_avp, NULL, "Vendor %s (%u): %s AVP",
                              enterprises_lookup(avp_vendor_id, "Unknown"), avp_vendor_id,
                              val_to_str(avp_type, broadband_avp_type_vals, "Unknown (%u)"));

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_mandatory, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hidden, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_length, tvb, offset, 2, ENC_BIG_ENDIAN);

    if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
        offset += avp_len;
        return offset;
    }

    offset += 2;
    avp_len -= 2;

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    avp_len -= 2;

    proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_broadband_avp_type, tvb, offset, 2, avp_type);
    offset += 2;
    avp_len -= 2;

    switch (avp_type) {

    case BROADBAND_AGENT_CIRCUIT_ID:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_agent_circuit_id, tvb, offset, avp_len, ENC_UTF_8);
        break;

    case BROADBAND_AGENT_REMOTE_ID:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_agent_remote_id, tvb, offset, avp_len, ENC_UTF_8);
        break;

    case BROADBAND_ACTUAL_DR_UP:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_actual_dr_up, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_ACTUAL_DR_DOWN:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_actual_dr_down, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MINIMUM_DR_UP:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_minimum_dr_up, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MINIMUM_DR_DOWN:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_minimum_dr_down, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_ATTAINABLE_DR_UP:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_attainable_dr_up, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_ATTAINABLE_DR_DOWN:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_attainable_dr_down, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MAXIMUM_DR_UP:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_maximum_dr_up, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MAXIMUM_DR_DOWN:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_maximum_dr_down, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MINIMUM_DR_UP_LOW_POWER:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_minimum_dr_up_low_power, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MINIMUM_DR_DOWN_LOW_POWER:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_minimum_dr_down_low_power, tvb, offset, 8, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MAXIMUM_INTERLEAVING_DELAY_UP:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_maximum_interleaving_delay_up, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_ACTUAL_INTERLEAVING_DELAY_UP:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_actual_interleaving_delay_up, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_MAXIMUM_INTERLEAVING_DELAY_DOWN:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_maximum_interleaving_delay_down, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_ACTUAL_INTERLEAVING_DELAY_DOWN:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_actual_interleaving_delay_down, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_ACCESS_LOOP_ENCAPSULATION:
        {
        ta = proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_access_loop_encapsulation, tvb, offset, avp_len, ENC_NA);
        l2tp_avp_ale_tree = proto_item_add_subtree(ta, ett_l2tp_ale_sub);
        proto_tree_add_item(l2tp_avp_ale_tree, hf_l2tp_broadband_access_loop_encapsulation_data_link, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_ale_tree, hf_l2tp_broadband_access_loop_encapsulation_enc1, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_ale_tree, hf_l2tp_broadband_access_loop_encapsulation_enc2, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        }
        break;

    case BROADBAND_ANCP_ACCESS_LINE_TYPE:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_ancp_access_line_type, tvb, offset, avp_len, ENC_BIG_ENDIAN);
        break;

    case BROADBAND_IWF_SESSION:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_broadband_iwf_session, tvb, offset, avp_len, ENC_BIG_ENDIAN);
        break;

    default:
        proto_tree_add_expert(l2tp_avp_tree, pinfo, &ei_l2tp_vendor_specific_avp_data, tvb, offset, avp_len);
        break;
    }
    offset += avp_len;

    return offset;
}

/*
 * Dissect Ericsson AVP:s
 */

/* Dissect a single variable-length Ericsson Transport Configuration Group */
static int dissect_l2tp_ericsson_transp_cfg(tvbuff_t *tvb, proto_tree *parent_tree)
{
    int offset = 0;
    guint32 i, num_sapis;
    proto_tree *tree;

    while (tvb_reported_length_remaining(tvb, offset) >= 8) {
        tree = proto_tree_add_subtree_format(parent_tree, tvb, 0, -1, ett_l2tp_ericsson_tcg,
                                             NULL, "Transport Config Bundling Group");
        proto_tree_add_item(tree, hf_l2tp_ericsson_tcg_group_id, tvb, offset++, 1, ENC_NA);
        proto_tree_add_item_ret_uint(tree, hf_l2tp_ericsson_tcg_num_sapis, tvb, offset++, 1, ENC_NA, &num_sapis);
        for (i = 0; i < num_sapis; i++) {
            proto_tree_add_item(tree, hf_l2tp_ericsson_tcg_sapi, tvb, offset++, 1, ENC_NA);
        }
        proto_tree_add_item(tree, hf_l2tp_ericsson_tcg_ip, tvb, offset, 4, ENC_NA);
        offset += 4;
        proto_tree_add_item(tree, hf_l2tp_ericsson_tcg_dscp, tvb, offset++, 1, ENC_NA);
        proto_tree_add_item(tree, hf_l2tp_ericsson_tcg_crc32_enable, tvb, offset++, 1, ENC_NA);
        proto_tree_add_item(tree, hf_l2tp_ericsson_tcg_bundling_tout, tvb, offset++, 1, ENC_NA);
        proto_tree_add_item(tree, hf_l2tp_ericsson_tcg_bundling_max_pkt, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    return offset;
}

/* Dissect a single 3-byte Ericsson TEI-to-SC Map */
static int dissect_l2tp_ericsson_tei_sc_map(tvbuff_t *tvb, proto_tree *parent_tree)
{
    int i = 0, offset = 0;
    proto_tree *tree;

    while (tvb_reported_length_remaining(tvb, offset) >= 3) {
        tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, 3, ett_l2tp_ericsson_map,
                                             NULL, "Transport Config Bundling Group %u", i);
        proto_tree_add_item(tree, hf_l2tp_ericsson_map_tei_low, tvb, offset++, 1, ENC_NA);
        proto_tree_add_item(tree, hf_l2tp_ericsson_map_tei_high, tvb, offset++, 1, ENC_NA);
        proto_tree_add_item(tree, hf_l2tp_ericsson_map_sc, tvb, offset++, 1, ENC_NA);
        i++;
    }
    return offset;
}

static int dissect_l2tp_ericsson_avps(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 ccid)
{
    int offset = 0;
    int         avp_type;
    guint32     avp_vendor_id;
    guint16     avp_len;
    guint16     ver_len_hidden;
    guint32     msg_type;
    proto_tree *l2tp_avp_tree;
    tvbuff_t   *tcg_tvb;

    ver_len_hidden  = tvb_get_ntohs(tvb, offset);
    avp_len         = AVP_LENGTH(ver_len_hidden);
    avp_vendor_id   = tvb_get_ntohs(tvb, offset + 2);
    avp_type        = tvb_get_ntohs(tvb, offset + 4);

    l2tp_avp_tree =  proto_tree_add_subtree_format(tree, tvb, offset,
                              avp_len, ett_l2tp_avp, NULL, "Vendor %s (%u): %s AVP",
                              enterprises_lookup(avp_vendor_id, "Unknown"), avp_vendor_id,
                              val_to_str(avp_type, ericsson_avp_type_vals, "Unknown (%u)"));

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_mandatory, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hidden, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_length, tvb, offset, 2, ENC_BIG_ENDIAN);

    if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
        offset += avp_len;
        return offset;
    }

    offset += 2;
    avp_len -= 2;

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    avp_len -= 2;

    proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_ericsson_avp_type, tvb, offset, 2, avp_type);
    offset += 2;
    avp_len -= 2;

    ccid++;

    switch (avp_type) {
    case ERICSSON_MSG_TYPE:
        proto_tree_add_item_ret_uint(l2tp_avp_tree, hf_l2tp_ericsson_msg_type, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_type);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s - %s", control_msg, val_to_str(msg_type, ericsson_short_msg_type_vals, "Unknown (0x%x)"));
        break;
    case ERICSSON_PROTO_VERSION:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_ver_pref, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_ver_2, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_ver_3, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        break;
    case ERICSSON_CONN_TYPE:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_conn_type, tvb, offset, 1, ENC_NA);
        break;
    case ERICSSON_STN_NAME:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_stn_name, tvb, offset, avp_len, ENC_ASCII);
        break;
    case ERICSSON_CRC_ENABLED:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_crc32_enable, tvb, offset, avp_len, ENC_NA);
        break;
    case ERICSSON_ABIS_LOWER_MODE:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_abis_lower_mode, tvb, offset, 1, ENC_NA);
        break;
    case ERICSSON_TRANSPORT_CONFIG:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_tc_overl_thresh, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_tc_num_groups, tvb, offset+2, 1, ENC_NA);
        /* FIXME: iterate over multiple groups */
        tcg_tvb = tvb_new_subset_length(tvb, offset+3, avp_len-3);
        dissect_l2tp_ericsson_transp_cfg(tcg_tvb, l2tp_avp_tree);
        break;
    case ERICSSON_TEI_TO_SC_MAP:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_ericsson_tc_num_maps, tvb, offset++, 1, ENC_NA);
        tcg_tvb = tvb_new_subset_length(tvb, offset, avp_len);
        offset += dissect_l2tp_ericsson_tei_sc_map(tcg_tvb, l2tp_avp_tree);
        break;

    default:
        proto_tree_add_expert(l2tp_avp_tree, pinfo, &ei_l2tp_vendor_specific_avp_data, tvb, offset, avp_len);
        break;
    }
    offset += avp_len;

    return offset;
}

/*
 * Ref: http://www.cablelabs.com/specifications/CM-SP-DEPI-I08-100611.pdf
 */
static int
dissect_l2tp_vnd_cablelabs_avps(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    int         avp_type;
    guint32     avp_vendor_id;
    guint32     avp_len;
    guint16     ver_len_hidden;
    proto_tree *l2tp_avp_tree;

    ver_len_hidden  = tvb_get_ntohs(tvb, offset);
    avp_len         = AVP_LENGTH(ver_len_hidden);
    avp_vendor_id   = tvb_get_ntohs(tvb, offset + 2);
    avp_type        = tvb_get_ntohs(tvb, offset + 4);

    l2tp_avp_tree =  proto_tree_add_subtree_format(tree, tvb, offset,
                              avp_len, ett_l2tp_avp, NULL, "Vendor %s (%u): %s AVP",
                              enterprises_lookup(avp_vendor_id, "Unknown"), avp_vendor_id,
                              val_to_str(avp_type, cablelabs_avp_type_vals, "Unknown (%u)"));

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_mandatory, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hidden, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_length, tvb, offset, 2, ENC_BIG_ENDIAN);

    if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
        offset += avp_len;
        return offset;
    }

    offset += 2;
    avp_len -= 2;

    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    avp_len -= 2;

    proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_cablelabs_avp_type, tvb, offset, 2, avp_type);
    offset += 2;
    avp_len -= 2;

    switch (avp_type) {
    case 101:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_l_bit, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_tsid_group_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        avp_len-=2;
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
        avp_len -= 4;
        offset+=4;
        break;
    case 103:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_l_bit, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_tsid_group_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_modulation, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        avp_len-=2;
        break;
    case 105:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_l_bit, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_tsid_group_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        avp_len-=2;
        while(avp_len > 0){
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_m, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            avp_len-=2;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_cablel_avp_n, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            avp_len-=2;
        }
        break;
    default:
        proto_tree_add_expert(l2tp_avp_tree, pinfo, &ei_l2tp_vendor_specific_avp_data, tvb, offset, avp_len);
        break;
    }
    offset += avp_len;

    return offset;
}


/*
 * Processes AVPs for Control Messages all versions and transports
 */
static void process_control_avps(tvbuff_t *tvb,
                                 packet_info *pinfo,
                                 proto_tree *l2tp_tree,
                                 int idx,
                                 int length,
                                 guint32 ccid,
                                 l2tpv3_tunnel_t *tunnel)
{
    proto_tree *l2tp_lcp_avp_tree, *l2tp_avp_tree = NULL, *l2tp_avp_tree_sub, *l2tp_avp_csu_tree;
    proto_item *te, *tc;

    int                msg_type  = 0;
    gboolean           isStopCcn = FALSE;
    int                avp_type;
    guint32            avp_vendor_id;
    guint16            avp_len;
    guint16            ver_len_hidden;
    tvbuff_t          *next_tvb, *avp_tvb;
    int                digest_idx = 0;
    guint16            digest_avp_len = 0;
    proto_item        *digest_item = NULL;
    l2tp_cntrl_data_t *l2tp_cntrl_data = wmem_new0(wmem_packet_scope(), l2tp_cntrl_data_t);

    l2tpv3_session_t *session = NULL;

    l2tp_cntrl_data->ccid = ccid;

    while (idx < length) {    /* Process AVP's */
        ver_len_hidden  = tvb_get_ntohs(tvb, idx);
        avp_len         = AVP_LENGTH(ver_len_hidden);
        avp_vendor_id   = tvb_get_ntohs(tvb, idx + 2);
        avp_type        = tvb_get_ntohs(tvb, idx + 4);

        if (avp_len < 6) {
            proto_tree_add_expert_format(l2tp_avp_tree ? l2tp_avp_tree : l2tp_tree, pinfo, &ei_l2tp_avp_length, tvb, idx, 2, "AVP length must be >= 6, got %u", avp_len);
            return;
        }

        if (avp_vendor_id != VENDOR_IETF) {

            avp_tvb = tvb_new_subset_length(tvb, idx, avp_len);

            if (avp_vendor_id == VENDOR_CISCO) {      /* Vendor-Specific AVP */

                dissect_l2tp_cisco_avps(avp_tvb, pinfo, l2tp_tree, l2tp_cntrl_data, &session);
                idx += avp_len;
                continue;

            } else if (avp_vendor_id == VENDOR_BROADBAND_FORUM) {      /* Vendor-Specific AVP */

                dissect_l2tp_broadband_avps(avp_tvb, pinfo, l2tp_tree);
                idx += avp_len;
                continue;

            } else if (avp_vendor_id == VENDOR_ERICSSON) {      /* Vendor-Specific AVP */

                dissect_l2tp_ericsson_avps(avp_tvb, pinfo, l2tp_tree, ccid);
                idx += avp_len;
                continue;

            } else {
                /* Vendor-Specific AVP */
                if (!dissector_try_uint_new(l2tp_vendor_avp_dissector_table, avp_vendor_id, avp_tvb, pinfo, l2tp_tree, FALSE, l2tp_cntrl_data)){
                    l2tp_avp_tree =  proto_tree_add_subtree_format(l2tp_tree, tvb, idx,
                                          avp_len, ett_l2tp_avp, NULL, "Vendor %s (%u) AVP Type %u",
                                          enterprises_lookup(avp_vendor_id, "Unknown"), avp_vendor_id,
                                          avp_type);

                    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_mandatory, tvb, idx, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hidden, tvb, idx, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_length, tvb, idx, 2, ENC_BIG_ENDIAN);

                    if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
                        idx += avp_len;
                        continue;
                    }
                    idx += 2;
                    proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id, tvb, idx, 2, ENC_BIG_ENDIAN);
                    idx += 2;

                    proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_avp_type, tvb, idx, 2, avp_type);
                    idx += 2;
                    proto_tree_add_expert(l2tp_avp_tree, pinfo, &ei_l2tp_vendor_specific_avp_data, tvb, idx, avp_len-6);
                    avp_len-=6;
                }
                idx += avp_len;
                continue;
            }
        }

        /* IETF AVP:s */
        l2tp_avp_tree =  proto_tree_add_subtree_format(l2tp_tree, tvb, idx,
                                  avp_len, ett_l2tp_avp, NULL, "%s AVP",
                                  val_to_str_ext(avp_type, &avp_type_vals_ext, "Unknown (%u)"));

        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_mandatory, tvb, idx, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hidden, tvb, idx, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_length, tvb, idx, 2, ENC_BIG_ENDIAN);

        if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
            idx += avp_len;
            continue;
        }

        idx += 2;
        avp_len -= 2;

        /* Special Case for handling Extended Vendor Id */
        if (avp_type == EXTENDED_VENDOR_ID) {
            idx += 2;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id,
                                tvb, idx, 4, ENC_BIG_ENDIAN);


            idx += 4;
            continue;
        }
        else {
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id,
                                tvb, idx, 2, ENC_BIG_ENDIAN);
            idx += 2;
            avp_len -= 2;
        }

        proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_avp_type,
                            tvb, idx, 2, avp_type);
        idx += 2;
        avp_len -= 2;

        switch (avp_type) {

        case CONTROL_MESSAGE:
            msg_type = tvb_get_ntohs(tvb, idx);
            l2tp_cntrl_data->msg_type = msg_type;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_message_type,
                                tvb, idx, 2, ENC_BIG_ENDIAN);

            if (msg_type == MESSAGE_TYPE_StopCCN) {
                isStopCcn = TRUE;
            }
            break;

        case RESULT_ERROR_CODE:
            if (avp_len < 2)
                break;
            if (isStopCcn) {
                proto_tree_add_item(l2tp_avp_tree, hf_l2tp_stop_ccn_result_code, tvb, idx, 2, ENC_BIG_ENDIAN);
            }
            else {
                proto_tree_add_item(l2tp_avp_tree, hf_l2tp_result_code, tvb, idx, 2, ENC_BIG_ENDIAN);
            }
            idx += 2;
            avp_len -= 2;

            if (avp_len < 2)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_error_code, tvb, idx, 2, ENC_BIG_ENDIAN);
            idx += 2;
            avp_len -= 2;

            if (avp_len == 0)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_error_message, tvb, idx, avp_len, ENC_ASCII);
            break;

        case PROTOCOL_VERSION:
            if (avp_len < 1)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_protocol_version, tvb, idx, 1, ENC_BIG_ENDIAN);
            idx += 1;
            avp_len -= 1;

            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_protocol_revision, tvb, idx, 1, ENC_BIG_ENDIAN);
            break;

        case FRAMING_CAPABILITIES:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_async_framing_supported, tvb, idx, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_sync_framing_supported, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case BEARER_CAPABILITIES:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_analog_access_supported, tvb, idx, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_digital_access_supported, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case TIE_BREAKER:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_tie_breaker, tvb, idx, 8, ENC_BIG_ENDIAN);
            break;

        case FIRMWARE_REVISION:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_firmware_revision, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;

        case HOST_NAME:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_host_name, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;

        case VENDOR_NAME:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_name, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;

        case ASSIGNED_TUNNEL_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_assigned_tunnel_id, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;

        case RECEIVE_WINDOW_SIZE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_receive_window_size, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;

        case CHALLENGE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_chap_challenge, tvb, idx, avp_len, ENC_NA);
            break;

        case CAUSE_CODE:
            /*
             * XXX - export stuff from the Q.931 dissector
             * to dissect the cause code and cause message,
             * and use it.
             */
            if (avp_len < 2)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_cause_code, tvb, idx, 2, ENC_BIG_ENDIAN);
            idx += 2;
            avp_len -= 2;

            if (avp_len < 1)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_cause_msg, tvb, idx, 1, ENC_BIG_ENDIAN);
            idx += 1;
            avp_len -= 1;

            if (avp_len == 0)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_advisory_msg, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;

        case CHALLENGE_RESPONSE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_chap_challenge_response, tvb, idx, 16, ENC_NA);
            break;

        case ASSIGNED_SESSION:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_assigned_session_id, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;

        case CALL_SERIAL_NUMBER:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_call_serial_number, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case MINIMUM_BPS:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_minimum_bps, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case MAXIMUM_BPS:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_maximum_bps, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case BEARER_TYPE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_analog_bearer_type, tvb, idx, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_digital_bearer_type, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case FRAMING_TYPE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_async_framing_type, tvb, idx, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_sync_framing_type, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case CALLED_NUMBER:
            if (avp_len == 0)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_called_number,
                                tvb, idx, avp_len, ENC_ASCII);
            break;

        case CALLING_NUMBER:
            if (avp_len == 0)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_calling_number,
                                tvb, idx, avp_len, ENC_ASCII);
            break;

        case SUB_ADDRESS:
            if (avp_len == 0)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_sub_address, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;

        case TX_CONNECT_SPEED:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_connect_speed, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case PHYSICAL_CHANNEL:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_physical_channel, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case INITIAL_RECEIVED_LCP_CONFREQ:
            te = proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_initial_received_lcp_confreq, tvb, idx, avp_len, ENC_NA);
            l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
            next_tvb = tvb_new_subset_length(tvb, idx, avp_len);
            call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
            break;

        case LAST_SENT_LCP_CONFREQ:
            te = proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_last_sent_lcp_confreq, tvb, idx, avp_len, ENC_NA);
            l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
            next_tvb = tvb_new_subset_length(tvb, idx, avp_len);
            call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
            break;

        case LAST_RECEIVED_LCP_CONFREQ:
            te = proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_last_received_lcp_confreq, tvb, idx, avp_len, ENC_NA);
            l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
            next_tvb = tvb_new_subset_length(tvb, idx, avp_len);
            call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
            break;

        case PROXY_AUTHEN_TYPE:
            msg_type = tvb_get_ntohs(tvb, idx);
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_proxy_authen_type, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;

        case PROXY_AUTHEN_NAME:
            if (avp_len == 0)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_proxy_authen_name, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;

        case PROXY_AUTHEN_CHALLENGE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_proxy_authen_challenge, tvb, idx, avp_len, ENC_NA);
            break;

        case PROXY_AUTHEN_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_proxy_authen_id, tvb, idx + 1, 1, ENC_BIG_ENDIAN);
            break;

        case PROXY_AUTHEN_RESPONSE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_proxy_authen_response, tvb, idx, avp_len, ENC_NA);
            break;

        case CALL_STATUS_AVPS:
            if (avp_len < 2)
                break;
            idx += 2;
            avp_len -= 2;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_crc_errors, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_framing_errors, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hardware_overruns, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_buffer_overruns, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_time_out_errors, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_alignment_errors, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;
            break;

        case ACCM:
            if (avp_len < 2)
                break;
            idx += 2;
            avp_len -= 2;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_send_accm, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_receive_accm, tvb, idx, 4, ENC_BIG_ENDIAN);
            idx += 4;
            avp_len -= 4;
            break;

        case RANDOM_VECTOR:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_random_vector, tvb, idx, avp_len, ENC_NA);
            break;

        case PRIVATE_GROUP_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_private_group_id, tvb, idx, avp_len, ENC_NA);
            break;

        case RX_CONNECT_SPEED:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_rx_connect_speed, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;

        case PPP_DISCONNECT_CAUSE_CODE:
            if (avp_len < 2)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_disconnect_code, tvb, idx, 2, ENC_BIG_ENDIAN);
            idx += 2;
            avp_len -= 2;

            if (avp_len < 2)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_control_protocol_number, tvb, idx, 2, ENC_BIG_ENDIAN);
            idx += 2;
            avp_len -= 2;

            if (avp_len < 1)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_cause_code_direction, tvb, idx, 1, ENC_BIG_ENDIAN);
            idx += 1;
            avp_len -= 1;

            if (avp_len == 0)
                break;
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_cause_code_message, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;

        case MESSAGE_DIGEST:
        {
            digest_idx = idx;
            digest_avp_len = avp_len;
            digest_item = proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_message_digest, tvb, idx, avp_len, ENC_NA);
            break;
        }
        case ROUTER_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_router_id, tvb, idx, 4, ENC_BIG_ENDIAN);
            break;
        case ASSIGNED_CONTROL_CONN_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_assigned_control_conn_id,
                                tvb, idx, 4, ENC_BIG_ENDIAN);
            store_ccid(tunnel, tvb, idx, msg_type);
            break;
        case PW_CAPABILITY_LIST:
            l2tp_avp_tree_sub = proto_tree_add_subtree(l2tp_avp_tree, tvb, idx, avp_len,
                                     ett_l2tp_avp_sub, NULL, "Pseudowire Capabilities List");

            while (avp_len >= 2) {
                proto_tree_add_item(l2tp_avp_tree_sub, hf_l2tp_avp_pw_type, tvb, idx, 2, ENC_BIG_ENDIAN);
                idx += 2;
                avp_len -= 2;
            }
            break;
        case LOCAL_SESSION_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_local_session_id,
                                tvb, idx, 4, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo,COL_INFO, ", LSID: %2u",
                          tvb_get_ntohl(tvb, idx));
            session = store_lsession_id(session, tvb, idx, msg_type);
            break;
        case REMOTE_SESSION_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_remote_session_id,
                                tvb, idx, 4, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo,COL_INFO, ", RSID: %2u",
                            tvb_get_ntohl(tvb, idx));
            session = store_rsession_id(session, tvb, idx, msg_type);
            break;
        case ASSIGNED_COOKIE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_assigned_cookie, tvb, idx, avp_len, ENC_NA);
            session = store_cookie_len(session, avp_len, msg_type);
            break;
        case REMOTE_END_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_remote_end_id, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;
        case PW_TYPE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_pseudowire_type, tvb, idx, 2, ENC_BIG_ENDIAN);
            session = store_pw_type(session, tvb, idx, msg_type);
            break;
        case L2_SPECIFIC_SUBLAYER:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_layer2_specific_sublayer, tvb, idx, 2, ENC_BIG_ENDIAN);
            session = store_l2_sublayer(session, tvb, idx, msg_type);
            break;
        case DATA_SEQUENCING:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_data_sequencing, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;
        case CIRCUIT_STATUS:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_circuit_status, tvb, idx, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_circuit_type, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;
        case PREFERRED_LANGUAGE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_preferred_language, tvb, idx, avp_len, ENC_NA|ENC_ASCII);
            break;
        case CTL_MSG_AUTH_NONCE:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_nonce, tvb, idx, avp_len, ENC_NA);
            store_cma_nonce(tunnel, tvb, idx, avp_len, msg_type);
            break;
        case TX_CONNECT_SPEED_V3:
            if (avp_len < 8)
                break;

            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_tx_connect_speed_v3, tvb, idx, 8, ENC_BIG_ENDIAN);
            break;
        case RX_CONNECT_SPEED_V3:
            if (avp_len < 8)
                break;

            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_rx_connect_speed_v3, tvb, idx, 8, ENC_BIG_ENDIAN);
            break;
        case CONNECT_SPEED_UPDATE:
        {
            tc = proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_csu, tvb, idx, avp_len, ENC_NA);
            l2tp_avp_csu_tree = proto_item_add_subtree(tc, ett_l2tp_csu);
            if (avp_len == 12) {
                /* L2TPv2 */
                proto_tree_add_item(l2tp_avp_csu_tree, hf_l2tp_avp_csu_res, tvb, idx, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(l2tp_avp_csu_tree, hf_l2tp_avp_csu_remote_session_id_v2, tvb, idx+2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(l2tp_avp_csu_tree, hf_l2tp_avp_csu_current_tx_speed_v2, tvb, idx+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(l2tp_avp_csu_tree, hf_l2tp_avp_csu_current_rx_speed_v2, tvb, idx+8, 4, ENC_BIG_ENDIAN);
            }
            else if (avp_len == 20) {
                /* L2TPv3 */
                proto_tree_add_item(l2tp_avp_csu_tree, hf_l2tp_avp_csu_remote_session_id_v3, tvb, idx, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(l2tp_avp_csu_tree, hf_l2tp_avp_csu_current_tx_speed_v3, tvb, idx+4, 8, ENC_BIG_ENDIAN);
                proto_tree_add_item(l2tp_avp_csu_tree, hf_l2tp_avp_csu_current_rx_speed_v3, tvb, idx+12, 8, ENC_BIG_ENDIAN);
            }
            break;
        }

        default:
            if(avp_len>0)
                proto_tree_add_expert(l2tp_avp_tree, pinfo, &ei_l2tp_vendor_specific_avp_data, tvb, idx, avp_len);
            break;
        }

        idx += avp_len;
    }

    /* SCCRQ digest can only be calculated once we know whether nonces are being used */
    if (digest_avp_len) {
        if (check_control_digest(tunnel, tvb, length, digest_idx, digest_avp_len, msg_type, pinfo) < 0)
            expert_add_info(pinfo, digest_item, &ei_l2tp_incorrect_digest);
    }

    update_session(tunnel, session);
}

/*
 * Processes Data Messages for v3 IP and UDP, starting from the  Session ID
 * (common to IP and UDP). Dissects the L2TPv3 Session header, the (optional)
 * L2-Specific sublayer and calls the appropriate dissector for the payload.
 */
static void
process_l2tpv3_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    proto_tree *l2tp_tree, proto_item *l2tp_item, int *pIdx,
                    l2tpv3_tunnel_t *tunnel)
{
    int         idx         = *pIdx;
    int         sid;
    guint32     oam_cell    = 0;
    proto_tree *l2_specific = NULL;
    proto_item *ti          = NULL;
    tvbuff_t   *next_tvb;
    gint        cookie_len  = l2tpv3_cookie;
    gint        l2_spec     = l2tpv3_l2_specific;
    guint       pw_type     = L2TPv3_PW_DEFAULT;

    lcce_settings_t  *lcce      = NULL;
    l2tpv3_session_t *session   = NULL;

    /* Get Session ID */
    sid = tvb_get_ntohl(tvb, idx);
    idx += 4;

    if (tunnel) {
        if (addresses_equal(&tunnel->lcce1, &pinfo->dst)) {
            session = find_session(tunnel, sid, 0);
            if (session)
                lcce = &session->lcce1;
        } else {
            session = find_session(tunnel, 0, sid);
            if (session)
                lcce = &session->lcce2;
        }
    }

    if (lcce) {
        if (l2_spec == -1)
            l2_spec = lcce->l2_specific;
        if (cookie_len == -1)
            cookie_len = lcce->cookie_len;
        if (pw_type == L2TPv3_PW_DEFAULT)
            pw_type = session->pw_type;
    }

    if (l2_spec == -1)
        l2_spec = L2TPv3_L2_SPECIFIC_NONE;

    if (cookie_len == -1)
        cookie_len = L2TPv3_COOKIE_DEFAULT;

    col_append_fstr(pinfo->cinfo, COL_INFO, "D[S:0x%08X]", sid);
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(l2tp_tree, hf_l2tp_sid, tvb, idx-4, 4, ENC_BIG_ENDIAN);
    ti = proto_tree_add_uint(l2tp_tree, hf_l2tp_avp_pseudowire_type, tvb, 0, 0, pw_type);
    proto_item_set_generated(ti);
    if (!(tvb_offset_exists(tvb, idx))) {
        return;
    }
    if (cookie_len != 0) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_cookie, tvb, idx, cookie_len, ENC_NA);
        idx += cookie_len;
        proto_item_set_len(l2tp_item, idx);
    }

    switch(l2_spec){
    case L2TPv3_L2_SPECIFIC_DEFAULT:
        if (tree) {
            ti = proto_tree_add_item(l2tp_tree, hf_l2tp_l2_spec_def,
                                     tvb, idx, 4, ENC_NA);
            l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb, idx,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                idx + 1, 3, ENC_BIG_ENDIAN);
        }
        idx += 4;
        break;
    case L2TPv3_L2_SPECIFIC_DOCSIS_DMPT:
        if (tree) {
            ti = proto_tree_add_item(l2tp_tree, hf_l2tp_l2_spec_docsis_dmpt,
                                     tvb, idx, 4, ENC_NA);
            l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_v, tvb,
                                idx, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb,
                                idx, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_h, tvb,
                                idx, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_flow_id, tvb,
                                idx, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                idx + 2, 2, ENC_BIG_ENDIAN);
        }
        idx += 4;
        break;
    case L2TPv3_L2_SPECIFIC_ATM:
        if (tree) {
            ti = proto_tree_add_item(l2tp_tree, hf_l2tp_l2_spec_atm,
                                     tvb, idx, 4, ENC_NA);
            l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb, idx,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_t, tvb, idx,
                                1, ENC_BIG_ENDIAN);
            /*
             * As per RFC 4454, the T bit specifies whether
             * we're transporting an OAM cell or an AAL5 frame.
             */
            oam_cell = tvb_get_guint8(tvb, idx) & 0x08;
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_g, tvb, idx,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_c, tvb, idx,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_u, tvb, idx,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                idx + 1, 3, ENC_BIG_ENDIAN);
        }
        idx += 4;
        break;
    case L2TPv3_L2_SPECIFIC_LAPD:
        if (tree)
            proto_tree_add_item(l2tp_tree, hf_l2tp_lapd_info, tvb, idx + 4, 3, ENC_NA);
        idx += 4 + 3;
        break;
    case L2TPv3_L2_SPECIFIC_NONE:
    default:
        break;
    }

    next_tvb = tvb_new_subset_remaining(tvb, idx);
    proto_item_set_len(l2tp_item, idx);
    p_add_proto_data(pinfo->pool, pinfo, proto_l2tp, 0, GUINT_TO_POINTER(pw_type));

    if (!dissector_try_uint_new(pw_type_table, pw_type, next_tvb, pinfo, tree, FALSE, GUINT_TO_POINTER(oam_cell)))
    {
        call_data_dissector(next_tvb, pinfo, tree);
    }
}

static int * const l2tp_control_fields[] = {
    &hf_l2tp_type,
    &hf_l2tp_length_bit,
    &hf_l2tp_seq_bit,
    &hf_l2tp_version,
    NULL
};

/*
 * Processes v3 data message over UDP, to then call process_l2tpv3_data
 * from the common part (Session ID)
 */
static void
process_l2tpv3_data_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        l2tpv3_conversation_t *l2tp_conv)
{
    proto_tree *l2tp_tree;
    proto_item *l2tp_item;
    int idx = 4;  /* skip to sid */

    l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, 8, ENC_NA);
    l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);

    if (tree) {
        proto_item_append_text(l2tp_item, " version 3");

        proto_tree_add_bitmask(l2tp_tree, tvb, 0, hf_l2tp_flags, ett_l2tp_flags, l2tp_control_fields, ENC_BIG_ENDIAN);

        /* Data in v3 over UDP has this reserved */
        proto_tree_add_item(l2tp_tree, hf_l2tp_res, tvb, 2, 2, ENC_BIG_ENDIAN);
    }

    /* Call process_l2tpv3_data from Session ID (offset in idx of 4) */
    process_l2tpv3_data(tvb, pinfo, tree, l2tp_tree, l2tp_item, &idx, l2tp_conv->tunnel);
}

/*
 * Processes v3 data message over IP, to then call process_l2tpv3_data
 * from the common part (Session ID)
 */
static void
process_l2tpv3_data_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       l2tpv3_conversation_t *l2tp_conv)
{
    proto_tree *l2tp_tree;
    proto_item *l2tp_item;

    int idx = 0;

    l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, 4, ENC_NA);
    l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);
    proto_item_append_text(l2tp_item, " version 3");

    /* Call process_l2tpv3_data from Session ID (offset in idx of 0) */
    process_l2tpv3_data(tvb, pinfo, tree, l2tp_tree, l2tp_item, &idx, l2tp_conv->tunnel);
}

/*
 * Processes v3 Control Message over IP, that carries NULL Session ID
 * to then call process_control_avps after dissecting the control.
 */
static void
process_l2tpv3_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int baseIdx,
                       l2tpv3_conversation_t *l2tp_conv)
{
    proto_tree *l2tp_tree = NULL;
    proto_item *l2tp_item = NULL;

    int     idx     = baseIdx;
    int     tmp_idx;
    guint16 length  = 0;        /* Length field */
    guint32 ccid    = 0;        /* Control Connection ID */
    guint16 vendor_id = 0;
    guint16 avp_type;
    guint16 msg_type;
    guint16 control = 0;

    l2tpv3_tunnel_t *tunnel = NULL;
    l2tpv3_tunnel_t tmp_tunnel;

    control = tvb_get_ntohs(tvb, idx);
    idx += 2;                       /* skip ahead */
    if (LENGTH_BIT(control)) {      /* length field included ? */
        length = tvb_get_ntohs(tvb, idx);
        idx += 2;
    }

    /* Get Control Channel ID */
    ccid = tvb_get_ntohl(tvb, idx);
    idx += 4;

    tmp_idx = idx;

    if ((LENGTH_BIT(control))&&(length==12))                /* ZLB Message */
        col_add_fstr(pinfo->cinfo, COL_INFO,
                        "%s - ZLB (ccid=0x%08X)",
                        control_msg , ccid);
    else
    {
        if (SEQUENCE_BIT(control)) {
            tmp_idx += 4;
        }

        tmp_idx+=2;

        vendor_id = tvb_get_ntohs(tvb, tmp_idx);
        tmp_idx+=2;

        avp_type = tvb_get_ntohs(tvb, tmp_idx);
        tmp_idx += 2;

        /* If it's a vendor AVP let the vendor AVP dissector fill in the info column */
        if ( vendor_id == VENDOR_IETF ) {
            if (avp_type == CONTROL_MESSAGE) {
                /* We print message type */
                msg_type = tvb_get_ntohs(tvb, tmp_idx);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                                "%s - %s (ccid=0x%08X)",
                                control_msg ,
                                val_to_str_ext(msg_type, &l2tp_message_type_short_str_vals_ext, "Unknown (%u)"),
                                ccid);
            }
            else {
                /*
                    * This is not a control message.
                    * We never pass here except in case of bad l2tp packet!
                    */
                col_add_fstr(pinfo->cinfo, COL_INFO,
                                "%s (ccid=0x%08X)",
                                control_msg,  ccid);
            }
        }
    }

    if (LENGTH_BIT(control)) {
        /*
         * Set the length of this tvbuff to be no longer than the length
         * in the header.
         *
         * XXX - complain if that length is longer than the length of
         * the tvbuff?  Have "set_actual_length()" return a Boolean
         * and have its callers check the result?
         */
        set_actual_length(tvb, length+baseIdx);
    }

    if (tree) {
        l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, -1, ENC_NA);
        l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);
        proto_item_append_text(l2tp_item, " version 3");

        if (baseIdx) {
            proto_tree_add_item(l2tp_tree, hf_l2tp_sid, tvb, 0, 4, ENC_BIG_ENDIAN);
        }
        proto_tree_add_bitmask(l2tp_tree, tvb, baseIdx, hf_l2tp_flags, ett_l2tp_flags, l2tp_control_fields, ENC_BIG_ENDIAN);
    }
    idx = baseIdx + 2;
    if (LENGTH_BIT(control)) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_length, tvb, idx, 2, ENC_BIG_ENDIAN);
        idx += 2;
    }

    proto_tree_add_item(l2tp_tree, hf_l2tp_ccid, tvb, idx, 4, ENC_BIG_ENDIAN);
    idx += 4;

    if (SEQUENCE_BIT(control)) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_Ns, tvb, idx, 2, ENC_BIG_ENDIAN);
        idx += 2;
        proto_tree_add_item(l2tp_tree, hf_l2tp_Nr, tvb, idx, 2, ENC_BIG_ENDIAN);
        idx += 2;

    }

    if ((LENGTH_BIT(control))&&(length==12)) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_zero_length_body_message, tvb, 0, 0, ENC_NA);
    } else {
        avp_type = tvb_get_ntohs(tvb, idx + 4);
        if (avp_type == CONTROL_MESSAGE) {

            msg_type = tvb_get_ntohs(tvb, idx + 6);
            if (msg_type == MESSAGE_TYPE_SCCRQ) {
                tunnel = &tmp_tunnel;
                memset(tunnel, 0, sizeof(l2tpv3_tunnel_t));
                tunnel->conv = l2tp_conv;
                copy_address_wmem(wmem_file_scope(), &tunnel->lcce1, &pinfo->src);
                copy_address_wmem(wmem_file_scope(), &tunnel->lcce2, &pinfo->dst);
            }
        }
    }

    if (!LENGTH_BIT(control)) {
        return;
    }

    if (tunnel == NULL) {
        tunnel = l2tp_conv->tunnel;
    }

    process_control_avps(tvb, pinfo, l2tp_tree, idx, length+baseIdx, ccid, tunnel);

    if (tunnel == &tmp_tunnel && l2tp_conv->tunnel == NULL) {
        l2tp_conv->tunnel = wmem_new0(wmem_file_scope(), l2tpv3_tunnel_t);
        memcpy(l2tp_conv->tunnel, &tmp_tunnel, sizeof(l2tpv3_tunnel_t));
    }
}

/*
 * Dissector for L2TP over UDP. For v2, calls process_control_avps for
 * control messages, or the ppp dissector based on the control bit.
 * For v3, calls either process_l2tpv3_control or process_l2tpv3_data_udp
 * based on the control bit.
 */
static int
dissect_l2tp_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *l2tp_tree;
    proto_item *l2tp_item;
    int         idx       = 0;
    int         tmp_idx;
    guint16     length    = 0;  /* Length field */
    guint16     tid;            /* Tunnel ID */
    guint16     cid;            /* Call ID */
    guint16     offset_size;    /* Offset size */
    guint16     avp_type;
    guint16     msg_type;
    guint16     control;
    tvbuff_t   *next_tvb;
    conversation_t *conv = NULL;
    l2tpv3_conversation_t *l2tp_conv = NULL;

    /*
     * Don't accept packets that aren't for an L2TP version we know,
     * as they might not be L2TP packets even though they happen
     * to be coming from or going to the L2TP port.
     */
    if (tvb_captured_length(tvb) < 2)
        return 0;       /* not enough information to check */
    control = tvb_get_ntohs(tvb, 0);
    switch (L2TP_VERSION(control)) {

    case 2:
    case 3:
        break;

    default:
        return 0;
    }

    /* RFCs 2661 and 3931 say that L2TPv2 and v3 use a TFTP-like method
     * of each side choosing their own port and only using the L2TP port
     * to establish the connection. In common practice, both parties use
     * the assigned L2TP port the entire time, due to NAT, firewalls, etc.
     * We support both methods by using conversations with no second port.
     */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                         pinfo->srcport, pinfo->destport, NO_PORT_B);

    if (conv == NULL || (conversation_get_dissector(conv, pinfo->num) != l2tp_udp_handle)) {
        conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->src, ENDPOINT_UDP,
                             pinfo->destport, pinfo->srcport, NO_PORT_B);
    }

    if ((conv == NULL) || (conversation_get_dissector(conv, pinfo->num) != l2tp_udp_handle)) {
        conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                        pinfo->srcport, 0, NO_PORT2);
        conversation_set_dissector(conv, l2tp_udp_handle);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2TP");
    col_clear(pinfo->cinfo, COL_INFO);

    switch (L2TP_VERSION(control)) {

    case 2:
        break;

    case 3:
        l2tp_conv = (l2tpv3_conversation_t *)conversation_get_proto_data(conv, proto_l2tp);
        if (!l2tp_conv) {
            l2tp_conv = wmem_new0(wmem_file_scope(), l2tpv3_conversation_t);
            l2tp_conv->pt = PT_UDP;
            conversation_add_proto_data(conv, proto_l2tp, (void *)l2tp_conv);
        }

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2TPv3");
        if (CONTROL_BIT(control)) {
            /* Call to process l2tp v3 control message */
            process_l2tpv3_control(tvb, pinfo, tree, 0, l2tp_conv);
        }
        else {
            /* Call to process l2tp v3 data message */
            process_l2tpv3_data_udp(tvb, pinfo, tree, l2tp_conv);
        }
        return tvb_reported_length(tvb);
    }

    if (LENGTH_BIT(control)) {              /* length field included ? */
        idx += 2;                       /* skip ahead */
        length = tvb_get_ntohs(tvb, idx);
    }

    /* collect the tunnel id & call id */
    idx += 2;
    tid = tvb_get_ntohs(tvb, idx);
    idx += 2;
    cid = tvb_get_ntohs(tvb, idx);

    if (CONTROL_BIT(control)) {
        /* CONTROL MESSAGE */
        tmp_idx = idx;

        if ((LENGTH_BIT(control))&&(length==12))        /* ZLB Message */
            col_add_fstr(pinfo->cinfo, COL_INFO,
                            "%s - ZLB      (tunnel id=%d, session id=%u)",
                            control_msg, tid, cid);
        else
        {
            if (SEQUENCE_BIT(control)) {
                tmp_idx += 4;
            }

            tmp_idx+=4;

            avp_type = tvb_get_ntohs(tvb, (tmp_idx+=2));

            if (avp_type == CONTROL_MESSAGE) {
                /* We print message type */
                msg_type = tvb_get_ntohs(tvb, tmp_idx+2);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                                "%s - %s (tunnel id=%u, session id=%u)",
                                control_msg,
                                val_to_str_ext(msg_type, &l2tp_message_type_short_str_vals_ext, "Unknown (%u)"),
                                tid, cid);
            }
            else
            {
                /*
                    * This is not a control message.
                    * We never pass here except in case of bad l2tp packet!
                    */
                col_add_fstr(pinfo->cinfo, COL_INFO,
                                "%s (tunnel id=%u, session id=%u)",
                                control_msg, tid, cid);

            }
        }
    }
    else {
        /* DATA Message */
        col_add_fstr(pinfo->cinfo, COL_INFO,
                        "%s            (tunnel id=%u, session id=%u)",
                        data_msg, tid, cid);
    }

    if (LENGTH_BIT(control)) {
        /*
         * Set the length of this tvbuff to be no longer than the length
         * in the header.
         *
         * XXX - complain if that length is longer than the length of
         * the tvbuff?  Have "set_actual_length()" return a Boolean
         * and have its callers check the result?
         */
        set_actual_length(tvb, length);
    }

    l2tp_item = proto_tree_add_item(tree,proto_l2tp, tvb, 0, -1, ENC_NA);
    l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);

    if (tree) {
        static int * const control_fields[] = {
            &hf_l2tp_type,
            &hf_l2tp_length_bit,
            &hf_l2tp_seq_bit,
            &hf_l2tp_offset_bit,
            &hf_l2tp_priority,
            &hf_l2tp_version,
            NULL
        };

        proto_tree_add_bitmask(l2tp_tree, tvb, 0, hf_l2tp_flags, ett_l2tp_flags, control_fields, ENC_BIG_ENDIAN);
    }
    idx = 2;
    if (LENGTH_BIT(control)) {
        if (tree) {
            proto_tree_add_item(l2tp_tree, hf_l2tp_length, tvb, idx, 2, ENC_BIG_ENDIAN);
        }
        idx += 2;
    }

    if (tree) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_tunnel, tvb, idx, 2, ENC_BIG_ENDIAN);
    }
    idx += 2;
    if (tree) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_session, tvb, idx, 2, ENC_BIG_ENDIAN);
    }
    idx += 2;

    if (SEQUENCE_BIT(control)) {
        if (tree) {
            proto_tree_add_item(l2tp_tree, hf_l2tp_Ns, tvb, idx, 2, ENC_BIG_ENDIAN);
        }
        idx += 2;
        if (tree) {
            proto_tree_add_item(l2tp_tree, hf_l2tp_Nr, tvb, idx, 2, ENC_BIG_ENDIAN);
        }
        idx += 2;
    }
    if (OFFSET_BIT(control)) {
        offset_size = tvb_get_ntohs(tvb, idx);
        if (tree) {
            proto_tree_add_uint(l2tp_tree, hf_l2tp_offset, tvb, idx, 2,
                                offset_size);
        }
        idx += 2;
        if (offset_size != 0) {
            if (tree) {
                proto_tree_add_item(l2tp_tree, hf_l2tp_offset_padding, tvb, idx, offset_size, ENC_NA);
            }
            idx += offset_size;
        }
    }

    if (tree && (LENGTH_BIT(control))&&(length==12)) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_zero_length_body_message, tvb, 0, 0, ENC_NA);
    }

    if (!CONTROL_BIT(control)) {  /* Data Messages so we are done */
        if (tree)
            proto_item_set_len(l2tp_item, idx);
        /* If we have data, signified by having a length bit, dissect it */
        if (tvb_offset_exists(tvb, idx)) {
            next_tvb = tvb_new_subset_remaining(tvb, idx);
            call_dissector(ppp_hdlc_handle, next_tvb, pinfo, tree);
        }
        return tvb_reported_length(tvb);
    }

    if (LENGTH_BIT(control))
        process_control_avps(tvb, pinfo, l2tp_tree, idx, length, -1, NULL);

    return tvb_reported_length(tvb);
}


/*
 * Only L2TPv3 runs directly over IP, and dissect_l2tp_ip starts dissecting
 * those packets to call either process_l2tpv3_control for Control Messages
 * or process_l2tpv3_data_ip for Data Messages over IP, based on the
 * Session ID
 */
static int
dissect_l2tp_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int     idx = 0;
    guint32 sid;                /* Session ID */

    conversation_t *conv = NULL;
    l2tpv3_conversation_t *l2tp_conv = NULL;

    conv = find_or_create_conversation(pinfo);

    l2tp_conv = (l2tpv3_conversation_t *)conversation_get_proto_data(conv, proto_l2tp);
    if (!l2tp_conv) {
        l2tp_conv = wmem_new0(wmem_file_scope(), l2tpv3_conversation_t);
        l2tp_conv->pt = PT_NONE;
        conversation_add_proto_data(conv, proto_l2tp, (void *)l2tp_conv);
    }

    /* Only L2TPv3 runs directly over IP */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2TPv3");

    col_clear(pinfo->cinfo, COL_INFO);

    sid = tvb_get_ntohl(tvb, idx);
    if (sid == 0) {
        /* This is control message */
        /* Call to process l2tp v3 control message */
        process_l2tpv3_control(tvb, pinfo, tree, 4, l2tp_conv);
    }
    else {
        /* Call to process l2tp v3 data message */
        process_l2tpv3_data_ip(tvb, pinfo, tree, l2tp_conv);
    }

    return tvb_captured_length(tvb);
}

static int dissect_atm_oam_llc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint32      oam_cell   = GPOINTER_TO_UINT(data);

    if (oam_cell) {
        call_dissector(atm_oam_handle, tvb, pinfo, tree);
    } else {
        call_dissector(llc_handle, tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

static void l2tp_cleanup(void)
{
    GSList *iterator = list_heads;

    while (iterator) {
        g_slist_free((GSList *)iterator->data);
        iterator = g_slist_next(iterator);
    }

    if (list_heads != NULL) {
        g_slist_free(list_heads);
        list_heads = NULL;
    }
}

/* registration with the filtering engine */
void
proto_register_l2tp(void)
{
    static hf_register_info hf[] = {
        { &hf_l2tp_flags,
          { "Flags", "l2tp.flags", FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_type,
          { "Type", "l2tp.type", FT_UINT16, BASE_DEC, VALS(l2tp_type_vals), 0x8000,
            "Type bit", HFILL }},

        { &hf_l2tp_length_bit,
          { "Length Bit", "l2tp.length_bit", FT_BOOLEAN, 16, TFS(&l2tp_length_bit_truth), 0x4000,
            NULL, HFILL }},

        { &hf_l2tp_seq_bit,
          { "Sequence Bit", "l2tp.seq_bit", FT_BOOLEAN, 16, TFS(&l2tp_seq_bit_truth), 0x0800,
            NULL, HFILL }},

        { &hf_l2tp_offset_bit,
          { "Offset bit", "l2tp.offset_bit", FT_BOOLEAN, 16, TFS(&l2tp_offset_bit_truth), 0x0200,
            NULL, HFILL }},

        { &hf_l2tp_priority,
          { "Priority", "l2tp.priority", FT_BOOLEAN, 16, TFS(&l2tp_priority_truth), 0x0100,
            "Priority bit", HFILL }},

        { &hf_l2tp_version,
          { "Version", "l2tp.version", FT_UINT16, BASE_DEC, NULL, 0x000f,
            NULL, HFILL }},

        { &hf_l2tp_length,
          { "Length","l2tp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_tunnel,
          { "Tunnel ID","l2tp.tunnel", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
            NULL, HFILL }},

        { &hf_l2tp_session,
          { "Session ID","l2tp.session", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
            NULL, HFILL }},

        { &hf_l2tp_Ns,
          { "Ns","l2tp.Ns", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_Nr,
          { "Nr","l2tp.Nr", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_offset,
          { "Offset","l2tp.offset", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of octets past the L2TP header at which the payload data starts.", HFILL }},

        { &hf_l2tp_avp_mandatory,
          { "Mandatory", "l2tp.avp.mandatory", FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }},

        { &hf_l2tp_avp_hidden,
          { "Hidden", "l2tp.avp.hidden", FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }},

        { &hf_l2tp_avp_length,
          { "Length", "l2tp.avp.length", FT_UINT16, BASE_DEC, NULL, 0x03ff,
            NULL, HFILL }},

        { &hf_l2tp_avp_vendor_id,
          { "Vendor ID", "l2tp.avp.vendor_id", FT_UINT16, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0,
            "AVP Vendor ID", HFILL }},

        { &hf_l2tp_avp_type,
          { "AVP Type", "l2tp.avp.type", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &avp_type_vals_ext, 0,
            NULL, HFILL }},

        { &hf_l2tp_tie_breaker,
          { "Tie Breaker", "l2tp.tie_breaker", FT_UINT64, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_sid,
          { "Session ID","l2tp.sid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ccid,
          { "Control Connection ID","l2tp.ccid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_res,
          { "Reserved","l2tp.res", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_cookie,
          { "Cookie","l2tp.cookie", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_l2_spec_def,
          { "Default L2-Specific Sublayer","l2tp.l2_spec_def", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_l2_spec_atm,
          { "ATM-Specific Sublayer","l2tp.l2_spec_atm", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_l2_spec_docsis_dmpt,
          { "DOCSIS DMPT - Specific Sublayer","l2tp.l2_spec_docsis_dmpt", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_l2_spec_v,
          { "V-bit","l2tp.l2_spec_v", FT_BOOLEAN, 8, NULL, 0x80,
            "VCCV Bit", HFILL }},

        { &hf_l2tp_l2_spec_s,
          { "S-bit","l2tp.l2_spec_s", FT_BOOLEAN, 8, NULL, 0x40,
            "Sequence Bit", HFILL }},

        { &hf_l2tp_l2_spec_h,
          { "H-bits","l2tp.l2_spec_h", FT_UINT8, BASE_HEX, NULL, 0x30,
            "Extended Header Bits", HFILL }},

        { &hf_l2tp_l2_spec_t,
          { "T-bit","l2tp.l2_spec_t", FT_BOOLEAN, 8, NULL, 0x08,
            "Transport Type Bit", HFILL }},

        { &hf_l2tp_l2_spec_g,
          { "G-bit","l2tp.l2_spec_g", FT_BOOLEAN, 8, NULL, 0x04,
            "EFCI Bit", HFILL }},

        { &hf_l2tp_l2_spec_c,
          { "C-bit","l2tp.l2_spec_c", FT_BOOLEAN, 8, NULL, 0x02,
            "CLP Bit", HFILL }},

        { &hf_l2tp_l2_spec_u,
          { "U-bit","l2tp.l2_spec_u", FT_BOOLEAN, 8, NULL, 0x01,
            "C/R Bit", HFILL }},

        { &hf_l2tp_l2_spec_flow_id,
          { "Flow ID","l2tp.l2_spec_flow_id", FT_UINT8, BASE_HEX, NULL, FLOW_ID_MASK,
            NULL, HFILL }},

        { &hf_l2tp_l2_spec_sequence,
          { "Sequence Number","l2tp.l2_spec_sequence", FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_cisco_avp_type,
          { "Type", "l2tp.avp.ciscotype", FT_UINT16, BASE_DEC, VALS(cisco_avp_type_vals), 0,
            "AVP Type", HFILL }},

        { &hf_l2tp_ericsson_avp_type,
          { "Type", "l2tp.avp.ericssontype", FT_UINT16, BASE_DEC, VALS(ericsson_avp_type_vals), 0,
            "AVP Type", HFILL }},

        { &hf_l2tp_broadband_avp_type,
          { "Type", "l2tp.avp.broadbandtype", FT_UINT16, BASE_DEC, VALS(broadband_avp_type_vals), 0,
            "AVP Type", HFILL }},

        { &hf_l2tp_cablelabs_avp_type,
          { "Type", "l2tp.avp.cablelabstype", FT_UINT16, BASE_DEC, VALS(cablelabs_avp_type_vals), 0,
            "AVP Type", HFILL }},

        { &hf_l2tp_avp_message_type,
          { "Message Type", "l2tp.avp.message_type", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &message_type_vals_ext, 0,
            NULL, HFILL }},

        { &hf_l2tp_avp_assigned_tunnel_id,
          { "Assigned Tunnel ID", "l2tp.avp.assigned_tunnel_id", FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_avp_assigned_control_conn_id,
          { "Assigned Control Connection ID", "l2tp.avp.assigned_control_conn_id", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_avp_assigned_session_id,
          { "Assigned Session ID", "l2tp.avp.assigned_session_id", FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_avp_remote_session_id,
          { "Remote Session ID", "l2tp.avp.remote_session_id", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_avp_local_session_id,
          { "Local Session ID", "l2tp.avp.local_session_id", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_avp_called_number,
          { "Called Number", "l2tp.avp.called_number", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_avp_calling_number,
          { "Calling Number", "l2tp.avp.calling_number", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_cisco_tie_breaker,
          { "Tie Breaker", "l2tp.cisco.tie_breaker", FT_UINT64, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_cablel_avp_l_bit,
          { "L(lock bit)", "l2tp.cablel.l_bit", FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }},

        { &hf_l2tp_cablel_avp_tsid_group_id,
          { "TSID Group ID", "l2tp.cablel.tsid_group_id", FT_UINT16, BASE_DEC, NULL, 0x7f00,
            NULL, HFILL }},

        { &hf_l2tp_cablel_avp_frequency,
          { "Frequency", "l2tp.cablel.frequency", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_cablel_avp_modulation,
          { "Modulation", "l2tp.cablel.modulation", FT_UINT16, BASE_DEC, VALS(l2tp_cablel_modulation_vals), 0x000f,
            NULL, HFILL }},

        { &hf_l2tp_cablel_avp_m,
          { "M", "l2tp.cablel.m", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_cablel_avp_n,
          { "N", "l2tp.cablel.n", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_agent_circuit_id,
          { "Agent Circuit ID", "l2tp.broadband.agent_circuit_id", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_agent_remote_id,
          { "Agent Remote ID", "l2tp.broadband.agent_remote_id", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_actual_dr_up,
          { "Actual Data Rate Upstream", "l2tp.broadband.actual_dr_up", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Actual Data Rate Upstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_actual_dr_down,
          { "Actual Data Rate Downstream", "l2tp.broadband.actual_dr_down", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Actual Data Rate Downstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_minimum_dr_up,
          { "Minimum Data Rate Upstream", "l2tp.broadband.minimum_dr_up", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Minimum Data Rate Upstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_minimum_dr_down,
          { "Minimum Data Rate Downstream", "l2tp.broadband.minimum_dr_down", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Minimum Data Rate Downstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_attainable_dr_up,
          { "Attainable Data Rate Upstream", "l2tp.broadband.attainable_dr_up", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Attainable Data Rate Upstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_attainable_dr_down,
          { "Attainable Data Rate Downstream", "l2tp.broadband.attainable_dr_down", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Attainable Data Rate Downstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_maximum_dr_up,
          { "Maximum Data Rate Upstream", "l2tp.broadband.maximum_dr_up", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Maximum Data Rate Upstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_maximum_dr_down,
          { "Maximum Data Rate Downstream", "l2tp.broadband.maximum_dr_down", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Maximum Data Rate Downstream in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_minimum_dr_up_low_power,
          { "Minimum Data Rate Upstream Low-Power", "l2tp.broadband.minimum_dr_up_low_power", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Minimum Data Rate Upstream Low-Power in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_minimum_dr_down_low_power,
          { "Minimum Data Rate Downstream Low-Power", "l2tp.broadband.minimum_dr_down_low_power", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Minimum Data Rate Downstream Low-Power in bits per seconds", HFILL }},

        { &hf_l2tp_broadband_maximum_interleaving_delay_up,
          { "Maximum Interleaving Delay Upstream", "l2tp.broadband.maximum_interleaving_delay_up", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Maximum Interleaving Delay Upstream in ms", HFILL }},

        { &hf_l2tp_broadband_actual_interleaving_delay_up,
          { "Actual Interleaving Delay Upstream", "l2tp.broadband.actual_interleaving_delay_up", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Actual Interleaving Delay Upstream in ms", HFILL }},

        { &hf_l2tp_broadband_maximum_interleaving_delay_down,
          { "Maximum Interleaving Delay Downstream", "l2tp.broadband.maximum_interleaving_delay_down", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Maximum Interleaving Delay Downstream in ms", HFILL }},

        { &hf_l2tp_broadband_actual_interleaving_delay_down,
          { "Actual Interleaving Delay Downstream", "l2tp.broadband.actual_interleaving_delay_down", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Actual Interleaving Delay Downstream in ms", HFILL }},

        { &hf_l2tp_broadband_access_loop_encapsulation,
          { "Access Loop Encapsulation", "l2tp.broadband.access_loop_encapsulation", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_access_loop_encapsulation_data_link,
          { "Data Link", "l2tp.broadband.access_loop_encapsulation.data_link", FT_UINT8, BASE_HEX, VALS(ale_datalink_types_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_access_loop_encapsulation_enc1,
          { "Encaps 1", "l2tp.broadband.access_loop_encapsulation.enc1", FT_UINT8, BASE_HEX, VALS(ale_enc1_types_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_access_loop_encapsulation_enc2,
          { "Encaps 2", "l2tp.broadband.access_loop_encapsulation.enc2", FT_UINT8, BASE_HEX, VALS(ale_enc2_types_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_ancp_access_line_type,
          { "ANCP Access Line Type", "l2tp.broadband.ancp_access_line_type", FT_UINT32, BASE_HEX, VALS(ancp_types_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_broadband_iwf_session,
          { "IWF Session", "l2tp.broadband.iwf_session", FT_UINT32, BASE_HEX, VALS(iwf_types_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_avp_csu,
          { "Connect Speed Update","l2tp.avp.csu", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},

        { &hf_l2tp_avp_csu_res,
          { "Reserved", "l2tp.avp.csu.res", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_avp_csu_remote_session_id_v2,
          { "Remote Session ID", "l2tp.avp.csu.remote_session_id", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_avp_csu_current_tx_speed_v2,
          { "Current TX Connect Speed", "l2tp.avp.csu.current_tx_speed", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Current TX Connect Speed in bps", HFILL }},

        { &hf_l2tp_avp_csu_current_rx_speed_v2,
          { "Current RX Connect Speed", "l2tp.avp.csu.current_rx_speed", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Current RX Connect Speed in bps", HFILL }},

        { &hf_l2tp_avp_csu_remote_session_id_v3,
          { "Remote Session ID", "l2tp.avp.csu.res", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_avp_csu_current_tx_speed_v3,
          { "Current TX Connect Speed", "l2tp.avp.csu.current_tx_speed64", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Current TX Connect Speed in bps", HFILL }},

        { &hf_l2tp_avp_csu_current_rx_speed_v3,
          { "Current RX Connect Speed", "l2tp.avp.csu.current_rx_speed64", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Current RX Connect Speed in bps", HFILL }},

        { &hf_l2tp_ericsson_msg_type,
          { "Ericsson Message Type", "l2tp.ericsson.msg_type", FT_UINT16, BASE_DEC, VALS(ericsson_msg_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_conn_type,
          { "Connection Type", "l2tp.ericsson.conn_type", FT_UINT8, BASE_DEC, VALS(ericsson_conn_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_stn_name,
          { "STN Name", "l2tp.ericsson.stn_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_crc32_enable,
          { "CRC32 Enabled", "l2tp.ericsson.crc32_enable", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_abis_lower_mode,
          { "Abis Lower Type", "l2tp.ericsson.abis_lower_mode", FT_UINT8, BASE_DEC, VALS(ericsson_abis_lower_mode_vals), 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tc_overl_thresh,
          { "Overload Threshold in 0.1%", "l2tp.ericsson.overload_thresh", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tc_num_groups,
          { "Number of Transport Config Groups", "l2tp.ericsson.tc_num_groups", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_group_id,
          { "Transport Config Group ID", "l2tp.ericsson.tc_group_id", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_num_sapis,
          { "Number of SAPIs in Transport Group", "l2tp.ericsson.tc_num_sapi", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_sapi,
          { "TCG SAPI", "l2tp.ericsson.tcg_sapi", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_ip,
          { "TCG IP Address", "l2tp.ericsson.tcg_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_dscp,
          { "TCG DSCP", "l2tp.ericsson.tcg_dscp", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_crc32_enable,
          { "CRC32 Enabled", "l2tp.ericsson.crc32_en", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_bundling_tout,
          { "TCG Bundling Timeout (ms)", "l2tp.ericsson.gcg.bundle_tout", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tcg_bundling_max_pkt,
          { "TCG Bundling Max Packet Size", "l2tp.ericsson.tcg.bundle_max_pkt", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_tc_num_maps,
          { "Number of TEI-SC Maps", "l2tp.ericsson.num_maps", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_map_tei_low,
          { "TEI Range Lowest Value", "l2tp.ericsson.map_tei_low", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_map_tei_high,
          { "TEI Range Highest Value", "l2tp.ericsson.map_tei_high", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_map_sc,
          { "Super Channel", "l2tp.ericsson.map_ssc", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_ver_pref,
          { "Preferred/Chosen Version", "l2tp.ericsson.ver_pref", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_ver_2,
          { "Version (2)", "l2tp.ericsson.ver_2", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ericsson_ver_3,
          { "Version (3)", "l2tp.ericsson.ver_3", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_l2tp_cisco_assigned_control_connection_id, { "Assigned Control Connection ID", "l2tp.cisco.assigned_control_connection_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_pw_type, { "PW Type", "l2tp.cisco.pw_type", FT_UINT16, BASE_DEC, VALS(pw_types_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_local_session_id, { "Local Session ID", "l2tp.cisco.local_session_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_remote_session_id, { "Remote Session ID", "l2tp.cisco.remote_session_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_assigned_cookie, { "Assigned Cookie", "l2tp.cisco.assigned_cookie", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_remote_end_id, { "Remote End ID", "l2tp.cisco.remote_end_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_pseudowire_type, { "Pseudowire Type", "l2tp.cisco.pseudowire_type", FT_UINT16, BASE_DEC, VALS(pw_types_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_circuit_status, { "Circuit Status", "l2tp.cisco.circuit_status", FT_BOOLEAN, 16, TFS(&tfs_up_down), 0x0001, NULL, HFILL }},
      { &hf_l2tp_cisco_circuit_type, { "Circuit Type", "l2tp.cisco.circuit_type", FT_BOOLEAN, 16, TFS(&tfs_new_existing), 0x0001, NULL, HFILL }},
      { &hf_l2tp_cisco_draft_avp_version, { "Draft AVP Version", "l2tp.cisco.draft_avp_version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_message_digest, { "Message Digest", "l2tp.cisco.message_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_nonce, { "Nonce", "l2tp.cisco.nonce", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_cisco_interface_mtu, { "Interface MTU", "l2tp.cisco.interface_mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_stop_ccn_result_code, { "Result code", "l2tp.result_code", FT_UINT16, BASE_DEC, VALS(result_code_stopccn_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_result_code, { "Result code", "l2tp.result_code", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &result_code_cdn_vals_ext, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_error_code, { "Error code", "l2tp.avp.error_code", FT_UINT16, BASE_DEC, VALS(error_code_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_error_message, { "Error Message", "l2tp.avp.error_message", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_protocol_version, { "Version", "l2tp.avp.protocol_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_protocol_revision, { "Revision", "l2tp.avp.protocol_revision", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_async_framing_supported, { "Async Framing Supported", "l2tp.avp.async_framing_supported", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0002, NULL, HFILL }},
      { &hf_l2tp_avp_sync_framing_supported, { "Sync Framing Supported", "l2tp.avp.sync_framing_supported", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0001, NULL, HFILL }},
      { &hf_l2tp_avp_analog_access_supported, { "Analog Access Supported", "l2tp.avp.analog_access_supported", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0002, NULL, HFILL }},
      { &hf_l2tp_avp_digital_access_supported, { "Digital Access Supported", "l2tp.avp.digital_access_supported", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0001, NULL, HFILL }},
      { &hf_l2tp_avp_firmware_revision, { "Firmware Revision", "l2tp.avp.firmware_revision", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_host_name, { "Host Name", "l2tp.avp.host_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_vendor_name, { "Vendor Name", "l2tp.avp.vendor_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_receive_window_size, { "Receive Window Size", "l2tp.avp.receive_window_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_chap_challenge, { "CHAP Challenge", "l2tp.avp.chap_challenge", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_cause_code, { "Cause Code", "l2tp.avp.cause_code", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_cause_msg, { "Cause Msg", "l2tp.avp.cause_msg", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_advisory_msg, { "Advisory Msg", "l2tp.avp.advisory_msg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_chap_challenge_response, { "CHAP Challenge Response", "l2tp.avp.chap_challenge_response", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_call_serial_number, { "Call Serial Number", "l2tp.avp.call_serial_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_minimum_bps, { "Minimum BPS", "l2tp.avp.minimum_bps", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_maximum_bps, { "Maximum BPS", "l2tp.avp.maximum_bps", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_analog_bearer_type, { "Analog Bearer Type", "l2tp.avp.analog_bearer_type", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0002, NULL, HFILL }},
      { &hf_l2tp_avp_digital_bearer_type, { "Digital Bearer Type", "l2tp.avp.digital_bearer_type", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0001, NULL, HFILL }},
      { &hf_l2tp_avp_async_framing_type, { "Async Framing Type", "l2tp.avp.async_framing_type", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0002, NULL, HFILL }},
      { &hf_l2tp_avp_sync_framing_type, { "Sync Framing Type", "l2tp.avp.sync_framing_type", FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0001, NULL, HFILL }},
      { &hf_l2tp_avp_sub_address, { "Sub-Address", "l2tp.avp.sub_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_connect_speed, { "Connect Speed", "l2tp.avp.connect_speed", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_physical_channel, { "Physical Channel", "l2tp.avp.physical_channel", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_initial_received_lcp_confreq, { "Initial Received LCP CONFREQ", "l2tp.avp.initial_received_lcp_confreq", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_last_sent_lcp_confreq, { "Last Sent LCP CONFREQ", "l2tp.avp.last_sent_lcp_confreq", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_last_received_lcp_confreq, { "Last Received LCP CONFREQ", "l2tp.avp.last_received_lcp_confreq", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_proxy_authen_type, { "Proxy Authen Type", "l2tp.avp.proxy_authen_type", FT_UINT16, BASE_DEC, VALS(authen_type_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_proxy_authen_name, { "Proxy Authen Name", "l2tp.avp.proxy_authen_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_proxy_authen_challenge, { "Proxy Authen Challenge", "l2tp.avp.proxy_authen_challenge", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_proxy_authen_id, { "Proxy Authen ID", "l2tp.avp.proxy_authen_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_proxy_authen_response, { "Proxy Authen Response", "l2tp.avp.proxy_authen_response", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_crc_errors, { "CRC Errors", "l2tp.avp.crc_errors", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_framing_errors, { "Framing Errors", "l2tp.avp.framing_errors", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_hardware_overruns, { "Hardware Overruns", "l2tp.avp.hardware_overruns", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_buffer_overruns, { "Buffer Overruns", "l2tp.avp.buffer_overruns", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_time_out_errors, { "Time-out Errors", "l2tp.avp.time_out_errors", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_alignment_errors, { "Alignment Errors", "l2tp.avp.alignment_errors", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_send_accm, { "Send ACCM", "l2tp.avp.send_accm", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_receive_accm, { "Receive ACCM", "l2tp.avp.receive_accm", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_random_vector, { "Random Vector", "l2tp.avp.random_vector", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_private_group_id, { "Private Group ID", "l2tp.avp.private_group_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_rx_connect_speed, { "Rx Connect Speed", "l2tp.avp.rx_connect_speed", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_disconnect_code, { "Disconnect Code", "l2tp.avp.disconnect_code", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_control_protocol_number, { "Control Protocol Number", "l2tp.avp.control_protocol_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_cause_code_direction, { "Direction", "l2tp.avp.cause_code_direction", FT_UINT8, BASE_DEC, VALS(cause_code_direction_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_cause_code_message, { "Message", "l2tp.avp.cause_code_message", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_message_digest, { "Message Digest", "l2tp.avp.message_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_router_id, { "Router ID", "l2tp.avp.router_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_pw_type, { "PW Type", "l2tp.avp.pw_type", FT_UINT16, BASE_DEC, VALS(pw_types_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_assigned_cookie, { "Assigned Cookie", "l2tp.avp.assigned_cookie", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_remote_end_id, { "Remote End ID", "l2tp.avp.remote_end_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_pseudowire_type, { "Pseudowire Type", "l2tp.avp.pseudowire_type", FT_UINT16, BASE_DEC, VALS(pw_types_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_layer2_specific_sublayer, { "Layer2 Specific Sublayer", "l2tp.avp.layer2_specific_sublayer", FT_UINT16, BASE_DEC, VALS(l2_sublayer_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_data_sequencing, { "Data Sequencing", "l2tp.avp.data_sequencing", FT_UINT16, BASE_DEC, VALS(data_sequencing_vals), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_circuit_status, { "Circuit Status", "l2tp.avp.circuit_status", FT_BOOLEAN, 16, TFS(&tfs_up_down), 0x0001, NULL, HFILL }},
      { &hf_l2tp_avp_circuit_type, { "Circuit Type", "l2tp.avp.circuit_type", FT_BOOLEAN, 16, TFS(&tfs_new_existing), 0x0002, NULL, HFILL }},
      { &hf_l2tp_avp_preferred_language, { "Preferred Language", "l2tp.avp.preferred_language", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_nonce, { "Nonce", "l2tp.avp.nonce", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_tx_connect_speed_v3, { "Tx Connect Speed v3", "l2tp.avp.tx_connect_speed_v3", FT_UINT64, BASE_HEX|BASE_VAL64_STRING|BASE_SPECIAL_VALS, VALS64(unique_indeterminable_or_no_link), 0x0, NULL, HFILL }},
      { &hf_l2tp_avp_rx_connect_speed_v3, { "Rx Connect Speed v3", "l2tp.avp.rx_connect_speed_v3", FT_UINT64, BASE_HEX|BASE_VAL64_STRING|BASE_SPECIAL_VALS, VALS64(unique_indeterminable_or_no_link), 0x0, NULL, HFILL }},
      { &hf_l2tp_lapd_info, { "LAPD info", "l2tp.lapd_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_zero_length_body_message, { "Zero Length Body message", "l2tp.zero_length_body_message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_l2tp_offset_padding, { "Offset Padding", "l2tp.offset_padding", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_l2tp,
        &ett_l2tp_flags,
        &ett_l2tp_avp,
        &ett_l2tp_avp_sub,
        &ett_l2tp_ale_sub,
        &ett_l2tp_l2_spec,
        &ett_l2tp_lcp,
        &ett_l2tp_csu,
        &ett_l2tp_ericsson_tcg,
        &ett_l2tp_ericsson_map,
    };

    static ei_register_info ei[] = {
        { &ei_l2tp_incorrect_digest, { "l2tp.incorrect_digest", PI_CHECKSUM, PI_WARN, "Incorrect Digest", EXPFILL }},
        /* Generated from convert_proto_tree_add_text.pl */
        { &ei_l2tp_vendor_specific_avp_data, { "l2tp.vendor_specific_avp_data", PI_UNDECODED, PI_WARN, "Vendor-Specific AVP data", EXPFILL }},
        { &ei_l2tp_avp_length, { "l2tp.avp_length.bad", PI_MALFORMED, PI_ERROR, "Bad AVP length", EXPFILL }},
    };

    module_t *l2tp_module;
    expert_module_t* expert_l2tp;

    /* Decode As handling */
    static build_valid_func l2tp_da_build_value[1] = {l2tp_value};
    static decode_as_value_t l2tp_da_values = {l2tp_prompt, 1, l2tp_da_build_value};
    static decode_as_t l2tp_da = {"l2tp", "l2tp.pw_type", 1, 0, &l2tp_da_values, NULL, NULL,
                                    decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    proto_l2tp = proto_register_protocol(
        "Layer 2 Tunneling Protocol", "L2TP", "l2tp");
    proto_register_field_array(proto_l2tp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_l2tp = expert_register_protocol(proto_l2tp);
    expert_register_field_array(expert_l2tp, ei, array_length(ei));

    l2tp_vendor_avp_dissector_table = register_dissector_table("l2tp.vendor_avp", "L2TP vendor AVP dissector table", proto_l2tp, FT_UINT32, BASE_DEC);
    pw_type_table = register_dissector_table("l2tp.pw_type", "L2TPv3 pseudowire type", proto_l2tp, FT_UINT32, BASE_DEC);

    l2tp_module = prefs_register_protocol(proto_l2tp, NULL);

    prefs_register_enum_preference(l2tp_module,
                                   "cookie_size",
                                   "L2TPv3 Cookie Size",
                                   "L2TPv3 Cookie Size",
                                   &l2tpv3_cookie,
                                   l2tpv3_cookies,
                                   FALSE);

    prefs_register_enum_preference(l2tp_module,
                                   "l2_specific",
                                   "L2TPv3 L2-Specific Sublayer",
                                   "L2TPv3 L2-Specific Sublayer",
                                   &l2tpv3_l2_specific,
                                   l2tpv3_l2_specifics,
                                   FALSE);

    prefs_register_static_text_preference(l2tp_module, "protocol",
        "Dissection of pseudowire types is configured through \"Decode As\". "
        "Type 0 is used for sessions with unknown pseudowire type.",
        "Pseudowire Type \"Decode As\" instuctions");

    prefs_register_string_preference(l2tp_module,"shared_secret","Shared Secret",
                                   "Shared secret used for control message digest authentication",
                                   &shared_secret);

    register_cleanup_routine(l2tp_cleanup);
    register_decode_as(&l2tp_da);
}

void
proto_reg_handoff_l2tp(void)
{
    dissector_handle_t atm_oam_llc_handle;

    l2tp_udp_handle = create_dissector_handle(dissect_l2tp_udp, proto_l2tp);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_L2TP, l2tp_udp_handle);

    l2tp_ip_handle = create_dissector_handle(dissect_l2tp_ip, proto_l2tp);
    dissector_add_uint("ip.proto", IP_PROTO_L2TP, l2tp_ip_handle);

    /*
     * Get a handle for the PPP-in-HDLC-like-framing dissector.
     */
    ppp_hdlc_handle = find_dissector_add_dependency("ppp_hdlc", proto_l2tp);
    ppp_lcp_options_handle = find_dissector_add_dependency("ppp_lcp_options", proto_l2tp);

    /* Register vendor AVP dissector(s)*/
    dissector_add_uint("l2tp.vendor_avp", VENDOR_CABLELABS, create_dissector_handle(dissect_l2tp_vnd_cablelabs_avps, proto_l2tp));


    /*
     * Get a handle for the dissectors used in v3.
     */
    atm_oam_handle        = find_dissector_add_dependency("atm_oam_cell", proto_l2tp);
    llc_handle            = find_dissector_add_dependency("llc", proto_l2tp);

    atm_oam_llc_handle = create_dissector_handle( dissect_atm_oam_llc, proto_l2tp );
    dissector_add_uint("l2tp.pw_type", L2TPv3_PW_AAL5, atm_oam_llc_handle);

    /*
     * XXX: Should we register something (Ethernet?) to L2TPv3_PW_DEFAULT?
     * The user could always change it with Decode As.
     */
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
