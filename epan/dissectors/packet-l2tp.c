/* packet-l2tp.c
 * Routines for Layer Two Tunnelling Protocol (L2TP) packet disassembly
 * John Thomes <john@ensemblecom.com>
 *
 * Minor changes by: (2000-01-10)
 * Laurent Cazalet <laurent.cazalet@mailclub.net>
 * Thomas Parvais <thomas.parvais@advalvas.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * RFC 2661 for L2TPv2
 * http://tools.ietf.org/html/rfc2661
 *
 * RFC 3931 for L2TPv3
 * http://tools.ietf.org/html/rfc3931
 *
 * Layer Two Tunneling Protocol "L2TP" number assignments:
 *     http://www.iana.org/assignments/l2tp-parameters
 *
 * Pseudowire types:
 *
 * RFC 4591 for Frame Relay
 * http://tools.ietf.org/html/rfc4591
 *
 * RFC 4454 for ATM
 * http://tools.ietf.org/html/rfc4454
 *
 * RFC 4719 for Ethernet
 * http://tools.ietf.org/html/rfc4719
 *
 * RFC 4349 for HDLC
 * http://tools.ietf.org/html/rfc4349
 *
 * XXX - what about LAPD?
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/sminmpec.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/crypt/md5.h>
#include <epan/crypt/sha1.h>
#include <epan/expert.h>
#include <epan/proto.h>

static int proto_l2tp = -1;
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
static int hf_l2tp_l2_spec_flow_id = -1;
static int hf_l2tp_l2_spec_sequence = -1;
static int hf_l2tp_l2_spec_t = -1;
static int hf_l2tp_l2_spec_g = -1;
static int hf_l2tp_l2_spec_c = -1;
static int hf_l2tp_l2_spec_u = -1;
static int hf_l2tp_cisco_avp_type = -1;
static int hf_l2tp_avp_message_type = -1;
static int hf_l2tp_avp_assigned_tunnel_id = -1;
static int hf_l2tp_avp_assigned_control_conn_id = -1;
static int hf_l2tp_avp_assigned_session_id = -1;
static int hf_l2tp_avp_remote_session_id = -1;
static int hf_l2tp_avp_local_session_id = -1;
static int hf_l2tp_avp_called_number = -1;
static int hf_l2tp_avp_calling_number = -1;

#define UDP_PORT_L2TP   1701

#define CONTROL_BIT(msg_info)        (msg_info & 0x8000) /* Type bit control = 1 data = 0 */
#define LENGTH_BIT(msg_info)         (msg_info & 0x4000) /* Length bit = 1  */
#define RESERVE_BITS(msg_info)       (msg_info &0x37F8)  /* Reserved bit - usused */
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
static gint ett_l2tp_ctrl = -1;
static gint ett_l2tp_avp = -1;
static gint ett_l2tp_avp_sub = -1;
static gint ett_l2tp_lcp = -1;
static gint ett_l2tp_l2_spec = -1;

static const enum_val_t l2tpv3_cookies[] = {
    {"detect",  "Detect",              -1},
    {"cookie0", "None",                 0},
    {"cookie4", "4 Byte Cookie",        4},
    {"cookie8", "8 Byte Cookie",        8},
    {NULL, NULL, 0}
};

#define L2TPv3_COOKIE_DEFAULT       0

#define L2TPv3_PROTOCOL_ETH         0
#define L2TPv3_PROTOCOL_CHDLC       1
#define L2TPv3_PROTOCOL_FR          2
#define L2TPv3_PROTOCOL_PPP         3
#define L2TPv3_PROTOCOL_IP          4
#define L2TPv3_PROTOCOL_MPLS        5
#define L2TPv3_PROTOCOL_AAL5        6
#define L2TPv3_PROTOCOL_LAPD        7
#define L2TPv3_PROTOCOL_DOCSIS_DMPT 8
#define L2TPv3_PROTOCOL_ERICSSON    9
#define L2TPv3_PROTOCOL_MAX         (L2TPv3_PROTOCOL_ERICSSON + 1)

#define L2TPv3_PROTOCOL_DEFAULT     L2TPv3_PROTOCOL_CHDLC

static const enum_val_t l2tpv3_protocols[] = {
    {"detect",      "Detect",        -1},
    {"eth",         "Ethernet",      L2TPv3_PROTOCOL_ETH},
    {"chdlc",       "Cisco HDLC",    L2TPv3_PROTOCOL_CHDLC},
    {"fr",          "Frame Relay",   L2TPv3_PROTOCOL_FR},
    {"ppp",         "PPP",           L2TPv3_PROTOCOL_PPP},
    {"ip",          "IP",            L2TPv3_PROTOCOL_IP},
    {"mpls",        "MPLS",          L2TPv3_PROTOCOL_MPLS},
    {"aal5",        "AAL5",          L2TPv3_PROTOCOL_AAL5},
    {"lapd",        "LAPD",          L2TPv3_PROTOCOL_LAPD},
    {"docsis-dmpt", "DOCSIS-DMPT",   L2TPv3_PROTOCOL_DOCSIS_DMPT},
    {"ehdlc",       "Ericsson HDLC", L2TPv3_PROTOCOL_ERICSSON},
    {NULL, NULL, 0}
};

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
static gint l2tpv3_protocol = -1;
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

static const value_string message_type_vals[] = {
    { MESSAGE_TYPE_SCCRQ,       "Start_Control_Request" },
    { MESSAGE_TYPE_SCCRP,       "Start_Control_Reply" },
    { MESSAGE_TYPE_SCCCN,       "Start_Control_Connected" },
    { MESSAGE_TYPE_StopCCN,     "Stop_Control_Notification" },
    { MESSAGE_TYPE_HELLO,       "Hello" },
    { MESSAGE_TYPE_OCRQ,        "Outgoing_Call_Request" },
    { MESSAGE_TYPE_OCRP,        "Outgoing_Call_Reply" },
    { MESSAGE_TYPE_OCCN,        "Outgoing_Call_Connected" },
    { MESSAGE_TYPE_ICRQ,        "Incoming_Call_Request" },
    { MESSAGE_TYPE_ICRP,        "Incoming_Call_Reply" },
    { MESSAGE_TYPE_ICCN,        "Incoming_Call_Connected" },
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
    { 0,                        NULL },
};

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
    { 0,                        NULL },
};


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
    { 86,                           "ATM Maximum Concatenated Cells AVP" },             /*[RFC4454] */
    { 87,                           "OAM Emulation Required AVP" },                     /*[RFC4454] */
    { 88,                           "ATM Alarm Status AVP" },                           /*[RFC4454] */
    /*        Also, see ATM Alarm Status AVP Values below */
    { 89,                           "Attachment Group Identifier" },                    /*[RFC4667] */
    { 90,                           "Local End Identifier" },                           /*[RFC4667] */
    { 91,                           "Interface Maximum Transmission Unit" },            /*[RFC4667] */
    { 92,                           "FCS Retention" },                                  /*[RFC4720] */
    { 93,                           "Tunnel Switching Aggregator ID AVP" },             /*[draft-ietf-l2tpext-tunnel-switching-06.txt] */
    { 94,                           "Maximum Receive Unit (MRU) AVP" },                 /*[RFC4623] */
    { 95,                           "Maximum Reassembled Receive Unit (MRRU) AVP" },    /*[RFC4623] */
    { 96,                           "VCCV Capability AVP" },                            /*[RFC5085] */
    { 97,                           "Connect Speed Update AVP" },                       /*[RFC5515] */
    { 98,                           "Connect Speed Update Enable AVP" },                /*[RFC5515] */
    { 99,                           "TDM Pseudowire AVP" },                             /*[RFC5611] */
    { 100,                          "RTP AVP" },                                        /*[RFC5611] */
    { 101,                          "PW Switching Point AVP" },                         /*[RFC6073] */
    { 0,                         NULL }
};

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

static const value_string pw_types_vals[] = {
    { 0x0001,  "Frame Relay DLCI" },
    { 0x0002,  "ATM AAL5 SDU VCC transport" },
    { 0x0003,  "ATM Cell transparent Port Mode" },
    { 0x0004,  "Ethernet VLAN" },
    { 0x0005,  "Ethernet" },
    { 0x0006,  "HDLC" },
    { 0x0007,  "PPP" },
    { 0x0009,  "ATM Cell transport VCC Mode" },
    { 0x000A,  "ATM Cell transport VPC Mode" },
    { 0x000B,  "IP Transport" },
    { 0x000C,  "MPEG-TS Payload Type (MPTPW)" },
    { 0x000D,  "Packet Streaming Protocol (PSPPW)" },
	/* 0x000E-0x0010 Unassigned */
    { 0x0011,  "Structure-agnostic E1 circuit" },       /* [RFC5611] */
    { 0x0012,  "Structure-agnostic T1 (DS1) circuit" }, /* [RFC5611]   */
    { 0x0013,  "Structure-agnostic E3 circuit" },       /* [RFC5611]   */
    { 0x0014,  "Structure-agnostic T3 (DS3) circuit" }, /* [RFC5611]   */
    { 0x0015,  "CESoPSN basic mode" },                  /* [RFC5611]   */
    { 0x0016,  "Unassigned" },
    { 0x0017,  "CESoPSN TDM with CAS" },                /* [RFC5611]  */

    { 0,  NULL },
};

static dissector_handle_t ppp_hdlc_handle;
static dissector_handle_t ppp_lcp_options_handle;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t chdlc_handle;
static dissector_handle_t fr_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t mpls_handle;
static dissector_handle_t atm_oam_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t lapd_handle;
static dissector_handle_t mp2t_handle;
static dissector_handle_t ehdlc_handle;
static dissector_handle_t data_handle;

static dissector_handle_t l2tp_udp_handle;
static dissector_handle_t l2tp_ip_handle;

#define L2TP_HMAC_MD5  0
#define L2TP_HMAC_SHA1 1
#define L2TP_HMAC_MD5_KEY_LEN 16
#define L2TP_HMAC_MD5_DIGEST_LEN 16
#define L2TP_HMAC_SHA1_DIGEST_LEN 20

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
    guint8   shared_key[L2TP_HMAC_MD5_KEY_LEN];

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

    gint    pw_type;
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
        md5_hmac(&data, 1, secret, strlen(secret), tunnel->shared_key);
        tunnel->shared_key_secret = se_strdup(secret);
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
    guint8 zero[L2TP_HMAC_MD5_DIGEST_LEN];
    md5_hmac_state_t ms;
    int remainder;
    int offset = 0;

    if (tunnel->conv->pt == PT_NONE) /* IP encapsulated L2TPv3 */
        offset = 4;

    md5_hmac_init(&ms, tunnel->shared_key, L2TP_HMAC_MD5_KEY_LEN);

    if (msg_type != MESSAGE_TYPE_SCCRQ) {
        if (tunnel->lcce1_nonce != NULL && tunnel->lcce2_nonce != NULL) {
            if (ADDRESSES_EQUAL(&tunnel->lcce1, &pinfo->src)) {
                md5_hmac_append(&ms, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
                md5_hmac_append(&ms, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
            } else {
                md5_hmac_append(&ms, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
                md5_hmac_append(&ms, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
            }
        }
    }

    md5_hmac_append(&ms, tvb_get_ptr(tvb, offset, idx + 1 - offset), idx + 1 - offset);
    /* Message digest is calculated with an empty message digest field */
    memset(zero, 0, L2TP_HMAC_MD5_DIGEST_LEN);
    md5_hmac_append(&ms, zero, avp_len - 1);
    remainder = length - (idx + avp_len);
    md5_hmac_append(&ms, tvb_get_ptr(tvb, idx + avp_len, remainder), remainder);
    md5_hmac_finish(&ms, digest);
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
    guint8 zero[L2TP_HMAC_SHA1_DIGEST_LEN];
    sha1_hmac_context ms;
    int remainder;
    int offset = 0;

    if (tunnel->conv->pt == PT_NONE) /* IP encapsulated L2TPv3 */
        offset = 4;

    sha1_hmac_starts(&ms, tunnel->shared_key, L2TP_HMAC_MD5_KEY_LEN);

    if (msg_type != MESSAGE_TYPE_SCCRQ) {
        if (tunnel->lcce1_nonce != NULL && tunnel->lcce2_nonce != NULL) {
            if (ADDRESSES_EQUAL(&tunnel->lcce1, &pinfo->src)) {
                sha1_hmac_update(&ms, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
                sha1_hmac_update(&ms, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
            } else {
                sha1_hmac_update(&ms, tunnel->lcce2_nonce, tunnel->lcce2_nonce_len);
                sha1_hmac_update(&ms, tunnel->lcce1_nonce, tunnel->lcce1_nonce_len);
            }
        }
    }

    sha1_hmac_update(&ms, tvb_get_ptr(tvb, 0, idx + 1 - offset), idx + 1 - offset);
    /* Message digest is calculated with an empty message digest field */
    memset(zero, 0, L2TP_HMAC_SHA1_DIGEST_LEN);
    sha1_hmac_update(&ms, zero, avp_len - 1);
    remainder = length - (idx + avp_len);
    sha1_hmac_update(&ms, tvb_get_ptr(tvb, idx + avp_len, remainder), remainder);
    sha1_hmac_finish(&ms, digest);
}

static int check_control_digest(l2tpv3_tunnel_t *tunnel,
                                tvbuff_t *tvb,
                                int length,
                                int idx,
                                int avp_len,
                                int msg_type,
                                packet_info *pinfo)
{
    guint8 digest[L2TP_HMAC_SHA1_DIGEST_LEN];

    if (!tunnel)
        return 1;

    update_shared_key(tunnel);

    switch (tvb_get_guint8(tvb, idx)) {
        case L2TP_HMAC_MD5:
            md5_hmac_digest(tunnel, tvb, length, idx, avp_len, msg_type, pinfo, digest);
            break;
        case L2TP_HMAC_SHA1:
            sha1_hmac_digest(tunnel, tvb, length, idx, avp_len, msg_type, pinfo, digest);
            break;
        default:
            return 1;
            break;
    }

    if (memcmp(digest, tvb_get_ptr(tvb, idx + 1, avp_len - 1), avp_len - 1) != 0)
        return -1;

    return 0;
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
                tunnel->lcce1_nonce = se_alloc(length);
                tunnel->lcce1_nonce_len = length;
                nonce = tunnel->lcce1_nonce;
            }
            break;
        case MESSAGE_TYPE_SCCRP:
            if (!tunnel->lcce2_nonce) {
                tunnel->lcce2_nonce = se_alloc(length);
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
        session = iterator->data;

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
    session->pw_type = -1;
}

static l2tpv3_session_t *alloc_session(void)
{
    l2tpv3_session_t *session = ep_alloc0(sizeof(l2tpv3_session_t));
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
    gint result = l2tpv3_protocol;
    guint16 pw_type;

    switch (msg_type) {
        case MESSAGE_TYPE_ICRQ:
        case MESSAGE_TYPE_OCRQ:
            break;
        default:
            return session;
    }

    if (session == NULL)
        session = alloc_session();

    pw_type = tvb_get_ntohs(tvb, offset);
    switch (pw_type) {
        case 0x0007:
            result = L2TPv3_PROTOCOL_PPP; break;
        case 0x0005:
            result = L2TPv3_PROTOCOL_ETH; break;
        case 0x0006:
            result = L2TPv3_PROTOCOL_CHDLC; break;
        case 0x0002:
            result = L2TPv3_PROTOCOL_AAL5; break;
        case 0x0001:
            result = L2TPv3_PROTOCOL_FR; break;
        default:
            break;
    }

    session->pw_type = result;

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
        existing = se_alloc0(sizeof(l2tpv3_session_t));
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

    if (session->pw_type != -1)
        existing->pw_type = session->pw_type;

    if (tunnel->sessions == NULL) {
        tunnel->sessions = g_slist_append(tunnel->sessions, existing);
        list_heads = g_slist_append(list_heads, tunnel->sessions);
    } else {
        tunnel->sessions = g_slist_append(tunnel->sessions, existing);
    }
}


/*
 * Dissect CISCO AVP:s
 */
static int dissect_l2tp_cisco_avps(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree) {

    int offset = 0;
    int         avp_type;
    guint32     avp_vendor_id;
    guint16     avp_len;
    guint16     ver_len_hidden;
	proto_item *tf, *te;
	proto_tree *l2tp_avp_tree, *l2tp_avp_tree_sub;
    guint32     bits;

    ver_len_hidden  = tvb_get_ntohs(tvb, offset);
    avp_len         = AVP_LENGTH(ver_len_hidden);
    avp_vendor_id   = tvb_get_ntohs(tvb, offset + 2);
    avp_type        = tvb_get_ntohs(tvb, offset + 4);

    tf =  proto_tree_add_text(tree, tvb, offset,
                              avp_len, "Vendor %s: %s AVP",
                              val_to_str_ext(avp_vendor_id, &sminmpec_values_ext, "Unknown (%u)"),
                              val_to_str(avp_type, cisco_avp_type_vals, "Unknown (%u)"));


    l2tp_avp_tree = proto_item_add_subtree(tf,  ett_l2tp_avp);

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
    case CISCO_ASSIGNED_CONNECTION_ID:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, 4,
                            "Assigned Control Connection ID: %u",
                            tvb_get_ntohl(tvb, offset));
        break;

    case CISCO_PW_CAPABILITY_LIST:
        te = proto_tree_add_text(l2tp_avp_tree, tvb, offset, avp_len,
                                    "Pseudowire Capabilities List");
        l2tp_avp_tree_sub = proto_item_add_subtree(te, ett_l2tp_avp_sub);
        while (avp_len >= 2) {
            int pw_type = tvb_get_ntohs(tvb, offset);

            proto_tree_add_text(l2tp_avp_tree_sub, tvb, offset,
                                2, "PW Type: (%u) %s",
                                pw_type,
                                val_to_str(pw_type, pw_types_vals,
                                            "Unknown (0x%04x)"));
            offset += 2;
            avp_len -= 2;
        }
        break;

    case CISCO_LOCAL_SESSION_ID:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, 4,
                            "Local Session ID: %u",
                            tvb_get_ntohl(tvb, offset));
        break;
    case CISCO_REMOTE_SESSION_ID:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, 4,
                            "Remote Session ID: %u",
                            tvb_get_ntohl(tvb, offset));
        break;
    case CISCO_ASSIGNED_COOKIE:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, avp_len,
                            "Assigned Cookie: %s",
                            tvb_bytes_to_str(tvb, offset, avp_len));
        break;
    case CISCO_REMOTE_END_ID:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, avp_len,
                            "Remote End ID: %s",
                            tvb_format_text(tvb, offset, avp_len));
        break;
    case CISCO_PW_TYPE:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, 2,
                            "Pseudowire Type: %u - %s",
                            tvb_get_ntohs(tvb, offset),
                            val_to_str(tvb_get_ntohs(tvb, offset),
                                        pw_types_vals, "Unknown (0x%04x)"));
        break;
    case CISCO_CIRCUIT_STATUS:
        bits = tvb_get_ntohs(tvb, offset);
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, 2,
                            "Circuit Status: %s",
                            (CIRCUIT_STATUS_BIT(bits)) ? "Up" : "Down");
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, 2,
                            "Circuit Type: %s",
                            (CIRCUIT_TYPE_BIT(bits)) ? "New" : "Existing");
        break;
    case CISCO_SESSION_TIE_BREAKER:
        proto_tree_add_item(l2tp_avp_tree, hf_l2tp_tie_breaker,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        break;
    case CISCO_DRAFT_AVP_VERSION:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, 2,
                            "Draft AVP Version: %u",
                            tvb_get_ntohs(tvb, offset));
        break;
    case CISCO_MESSAGE_DIGEST:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, avp_len,
                            "Message Digest: %s",
                            tvb_bytes_to_str(tvb, offset, avp_len));
        break;
    case CISCO_AUTH_NONCE:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, avp_len,
                            "Nonce: %s",
                            tvb_bytes_to_str(tvb, offset, avp_len));
        break;
    case CISCO_INTERFACE_MTU:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset, avp_len,
                            "Interface MTU: %u",
                            tvb_get_ntohs(tvb, offset));
        break;

    default:
        proto_tree_add_text(l2tp_avp_tree, tvb, offset,
                            avp_len, "Vendor-Specific AVP");
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
                                 l2tpv3_tunnel_t *tunnel)
{
    proto_tree *l2tp_lcp_avp_tree, *l2tp_avp_tree = NULL, *l2tp_avp_tree_sub;
    proto_item *tf, *te;

    int         msg_type  = 0;
    gboolean    isStopCcn = FALSE;
    int         avp_type;
    guint32     avp_vendor_id;
    guint16     avp_len;
    guint16     ver_len_hidden;
    tvbuff_t   *next_tvb, *avp_tvb;
    guint16     result_code;
    guint16     error_code;
    guint32     bits;
    guint16     firmware_rev;
    int         digest_idx = 0;
    guint16     digest_avp_len = 0;
    proto_item *digest_item = NULL;

    l2tpv3_session_t *session = NULL;

    while (idx < length) {    /* Process AVP's */
        ver_len_hidden  = tvb_get_ntohs(tvb, idx);
        avp_len         = AVP_LENGTH(ver_len_hidden);
        avp_vendor_id   = tvb_get_ntohs(tvb, idx + 2);
        avp_type        = tvb_get_ntohs(tvb, idx + 4);

        if (avp_len < 6) {
            proto_tree_add_text(l2tp_avp_tree ? l2tp_avp_tree : l2tp_tree, tvb, idx, 2,
                                "AVP length must be >= 6, got %u", avp_len);
            return;
        }

        if (avp_vendor_id != VENDOR_IETF) {
            if (avp_vendor_id == VENDOR_CISCO) {      /* Vendor-Specific AVP */

                avp_tvb = tvb_new_subset(tvb, idx, avp_len, avp_len);
                dissect_l2tp_cisco_avps(avp_tvb, pinfo, l2tp_tree);
                idx += avp_len;
                continue;

            } else {
                /* Vendor-Specific AVP */
                tf =  proto_tree_add_text(l2tp_tree, tvb, idx,
                                      avp_len, "Vendor %s AVP Type %u",
                                      val_to_str_ext(avp_vendor_id, &sminmpec_values_ext, "Unknown (%u)"),
                                      avp_type);

                l2tp_avp_tree = proto_item_add_subtree(tf,  ett_l2tp_avp);

                proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_mandatory, tvb, idx, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_hidden, tvb, idx, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_length, tvb, idx, 2, ENC_BIG_ENDIAN);

                if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
                    idx += avp_len;
                    continue;
                }
                idx += 2;
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2, "Type: %u", avp_type);
                idx += 2;
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len, "Vendor-Specific AVP");
                idx += avp_len;
                continue;
            }
        }

        /* IETF AVP:s */
        tf =  proto_tree_add_text(l2tp_tree, tvb, idx,
                                  avp_len, "%s AVP",
                                  val_to_str(avp_type, avp_type_vals, "Unknown (%u)"));

        l2tp_avp_tree = proto_item_add_subtree(tf,  ett_l2tp_avp);

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
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_message_type,
                                tvb, idx, 2, ENC_BIG_ENDIAN);

            if (msg_type == MESSAGE_TYPE_StopCCN) {
                isStopCcn = TRUE;
            }
            break;

        case RESULT_ERROR_CODE:
            if (avp_len < 2)
                break;
            result_code = tvb_get_ntohs(tvb, idx);
            if (isStopCcn) {
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                    "Result code: %u - %s", result_code,
                                    val_to_str(result_code, result_code_stopccn_vals, "Unknown (%u)"));
            }
            else {
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                    "Result code: %u - %s", result_code,
                                    val_to_str(result_code, result_code_cdn_vals, "Unknown (%u)"));
            }
            idx += 2;
            avp_len -= 2;

            if (avp_len < 2)
                break;
            error_code = tvb_get_ntohs(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Error code: %u - %s", error_code,
                                val_to_str(error_code, error_code_vals, "Unknown (%u)"));
            idx += 2;
            avp_len -= 2;

            if (avp_len == 0)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Error Message: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;

        case PROTOCOL_VERSION:
            if (avp_len < 1)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 1,
                                "Version: %u", tvb_get_guint8(tvb, idx));
            idx += 1;
            avp_len -= 1;

            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 1,
                                "Revision: %u", tvb_get_guint8(tvb, idx));
            break;

        case FRAMING_CAPABILITIES:
            bits = tvb_get_ntohl(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Async Framing Supported: %s",
                                (FRAMING_ASYNC(bits)) ? "True" : "False");
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Sync Framing Supported: %s",
                                (FRAMING_SYNC(bits)) ? "True" : "False");
            break;

        case BEARER_CAPABILITIES:
            bits = tvb_get_ntohl(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Analog Access Supported: %s",
                                (BEARER_ANALOG(bits)) ? "True" : "False");
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Digital Access Supported: %s",
                                (BEARER_DIGITAL(bits)) ? "True" : "False");
            break;

        case TIE_BREAKER:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_tie_breaker, tvb, idx, 8, ENC_BIG_ENDIAN);
            break;

        case FIRMWARE_REVISION:
            firmware_rev = tvb_get_ntohs(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Firmware Revision: %d 0x%x", firmware_rev,firmware_rev );
            break;

        case HOST_NAME:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Host Name: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;

        case VENDOR_NAME:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Vendor Name: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;

        case ASSIGNED_TUNNEL_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_assigned_tunnel_id, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;

        case RECEIVE_WINDOW_SIZE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Receive Window Size: %u",
                                tvb_get_ntohs(tvb, idx));
            break;

        case CHALLENGE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "CHAP Challenge: %s",
                                tvb_bytes_to_str(tvb, idx, avp_len));
            break;

        case CAUSE_CODE:
            /*
             * XXX - export stuff from the Q.931 dissector
             * to dissect the cause code and cause message,
             * and use it.
             */
            if (avp_len < 2)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Cause Code: %u",
                                tvb_get_ntohs(tvb, idx));
            idx += 2;
            avp_len -= 2;

            if (avp_len < 1)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 1,
                                "Cause Msg: %u",
                                tvb_get_guint8(tvb, idx));
            idx += 1;
            avp_len -= 1;

            if (avp_len == 0)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Advisory Msg: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;

        case CHALLENGE_RESPONSE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 16,
                                "CHAP Challenge Response: %s",
                                tvb_bytes_to_str(tvb, idx, 16));
            break;

        case ASSIGNED_SESSION:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_assigned_session_id, tvb, idx, 2, ENC_BIG_ENDIAN);
            break;

        case CALL_SERIAL_NUMBER:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Call Serial Number: %u",
                                tvb_get_ntohl(tvb, idx));
            break;

        case MINIMUM_BPS:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Minimum BPS: %u",
                                tvb_get_ntohl(tvb, idx));
            break;

        case MAXIMUM_BPS:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Maximum BPS: %u",
                                tvb_get_ntohl(tvb, idx));
            break;

        case BEARER_TYPE:
            bits = tvb_get_ntohl(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Analog Bearer Type: %s",
                                (BEARER_ANALOG(bits)) ? "True" : "False");
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Digital Bearer Type: %s",
                                (BEARER_DIGITAL(bits)) ? "True" : "False");
            break;

        case FRAMING_TYPE:
            bits = tvb_get_ntohl(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Async Framing Type: %s",
                                (FRAMING_ASYNC(bits)) ? "True" : "False");
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Sync Framing Type: %s",
                                (FRAMING_SYNC(bits)) ? "True" : "False");
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
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Sub-Address: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;

        case TX_CONNECT_SPEED:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Connect Speed: %u",
                                tvb_get_ntohl(tvb, idx));
            break;

        case PHYSICAL_CHANNEL:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Physical Channel: %u",
                                tvb_get_ntohl(tvb, idx));
            break;

        case INITIAL_RECEIVED_LCP_CONFREQ:
            te = proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                     "Initial Received LCP CONFREQ: %s",
                                     tvb_bytes_to_str(tvb, idx, avp_len));
            l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
            next_tvb = tvb_new_subset(tvb, idx, avp_len, avp_len);
            call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
            break;

        case LAST_SENT_LCP_CONFREQ:
            te = proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                     "Last Sent LCP CONFREQ: %s",
                                     tvb_bytes_to_str(tvb, idx, avp_len));
            l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
            next_tvb = tvb_new_subset(tvb, idx, avp_len, avp_len);
            call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
            break;

        case LAST_RECEIVED_LCP_CONFREQ:
            te = proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                     "Last Received LCP CONFREQ: %s",
                                     tvb_bytes_to_str(tvb, idx, avp_len));
            l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
            next_tvb = tvb_new_subset(tvb, idx, avp_len, avp_len);
            call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
            break;

        case PROXY_AUTHEN_TYPE:
            msg_type = tvb_get_ntohs(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Proxy Authen Type: %s",
                                val_to_str(msg_type, authen_type_vals, "Unknown (%u)"));
            break;

        case PROXY_AUTHEN_NAME:
            if (avp_len == 0)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Proxy Authen Name: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;

        case PROXY_AUTHEN_CHALLENGE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Proxy Authen Challenge: %s",
                                tvb_bytes_to_str(tvb, idx, avp_len));
            break;

        case PROXY_AUTHEN_ID:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx + 1, 1,
                                "Proxy Authen ID: %u",
                                tvb_get_guint8(tvb, idx + 1));
            break;

        case PROXY_AUTHEN_RESPONSE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Proxy Authen Response: %s",
                                tvb_bytes_to_str(tvb, idx, avp_len));
            break;

        case CALL_STATUS_AVPS:
            if (avp_len < 2)
                break;
            idx += 2;
            avp_len -= 2;

            if (avp_len < 4)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "CRC Errors: %u", tvb_get_ntohl(tvb, idx));
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Framing Errors: %u", tvb_get_ntohl(tvb, idx));
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Hardware Overruns: %u", tvb_get_ntohl(tvb, idx));
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Buffer Overruns: %u", tvb_get_ntohl(tvb, idx));
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Time-out Errors: %u", tvb_get_ntohl(tvb, idx));
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Alignment Errors: %u", tvb_get_ntohl(tvb, idx));
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
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Send ACCM: %u", tvb_get_ntohl(tvb, idx));
            idx += 4;
            avp_len -= 4;

            if (avp_len < 4)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Receive ACCM: %u", tvb_get_ntohl(tvb, idx));
            idx += 4;
            avp_len -= 4;
            break;

        case RANDOM_VECTOR:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Random Vector: %s",
                                tvb_bytes_to_str(tvb, idx, avp_len));
            break;

        case PRIVATE_GROUP_ID:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Private Group ID: %s",
                                tvb_bytes_to_str(tvb, idx, avp_len));
            break;

        case RX_CONNECT_SPEED:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Rx Connect Speed: %u",
                                tvb_get_ntohl(tvb, idx));
            break;

        case PPP_DISCONNECT_CAUSE_CODE:
            if (avp_len < 2)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Disconnect Code: %u",
                                tvb_get_ntohs(tvb, idx));
            idx += 2;
            avp_len -= 2;

            if (avp_len < 2)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Control Protocol Number: %u",
                                tvb_get_ntohs(tvb, idx));
            idx += 2;
            avp_len -= 2;

            if (avp_len < 1)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 1,
                                "Direction: %s",
                                val_to_str(tvb_get_guint8(tvb, idx),
                                           cause_code_direction_vals,
                                           "Reserved (%u)"));
            idx += 1;
            avp_len -= 1;

            if (avp_len == 0)
                break;
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Message: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;

        case MESSAGE_DIGEST:
        {
            digest_idx = idx;
            digest_avp_len = avp_len;
            digest_item = proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                              "Message Digest: %s",
                                              tvb_bytes_to_str(tvb, idx, avp_len));
            break;
        }
        case ROUTER_ID:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 4,
                                "Router ID: %u",
                                tvb_get_ntohl(tvb, idx));
            break;
        case ASSIGNED_CONTROL_CONN_ID:
            proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_assigned_control_conn_id,
                                tvb, idx, 4, ENC_BIG_ENDIAN);
            store_ccid(tunnel, tvb, idx, msg_type);
            break;
        case PW_CAPABILITY_LIST:
            te = proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                     "Pseudowire Capabilities List");
            l2tp_avp_tree_sub = proto_item_add_subtree(te, ett_l2tp_avp_sub);

            while (avp_len >= 2) {
                int pw_type = tvb_get_ntohs(tvb, idx);
                proto_tree_add_text(l2tp_avp_tree_sub, tvb, idx,
                                    2, "PW Type: (%u) %s",
                                    pw_type,
                                    val_to_str(pw_type, pw_types_vals,
                                               "Unknown (0x%04x)"));
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
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Assigned Cookie: %s",
                                tvb_bytes_to_str(tvb, idx, avp_len));
            session = store_cookie_len(session, avp_len, msg_type);
            break;
        case REMOTE_END_ID:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Remote End ID: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;
        case PW_TYPE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Pseudowire Type: %u - %s",
                                tvb_get_ntohs(tvb, idx),
                                val_to_str(tvb_get_ntohs(tvb, idx),
                                           pw_types_vals, "Unknown (0x%04x)"));
            session = store_pw_type(session, tvb, idx, msg_type);
            break;
        case L2_SPECIFIC_SUBLAYER:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Layer2 Specific Sublayer: %s",
                                val_to_str(tvb_get_ntohs(tvb, idx),
                                           l2_sublayer_vals, "Invalid (%u)"));
            session = store_l2_sublayer(session, tvb, idx, msg_type);
            break;
        case DATA_SEQUENCING:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Data Sequencing: %s",
                                val_to_str(tvb_get_ntohs(tvb, idx),
                                           data_sequencing_vals, "Invalid (%u)"));
            break;
        case CIRCUIT_STATUS:
            bits = tvb_get_ntohs(tvb, idx);
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Circuit Status: %s",
                                (CIRCUIT_STATUS_BIT(bits)) ? "Up" : "Down");
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, 2,
                                "Circuit Type: %s",
                                (CIRCUIT_TYPE_BIT(bits)) ? "New" : "Existing");
            break;
        case PREFERRED_LANGUAGE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Preferred Language: %s",
                                tvb_format_text(tvb, idx, avp_len));
            break;
        case CTL_MSG_AUTH_NONCE:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Nonce: %s",
                                tvb_bytes_to_str(tvb, idx, avp_len));
            store_cma_nonce(tunnel, tvb, idx, avp_len, msg_type);
            break;
        case TX_CONNECT_SPEED_V3:
        {
            guint32 l_int, h_int;
            if (avp_len < 8)
                break;

            h_int = tvb_get_ntohl(tvb, idx);
            l_int = tvb_get_ntohl(tvb, idx+4);
            if (!h_int && !l_int) {
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, 8,
                                    "Tx Connect Speed v3: indeterminable or no physical p2p link");
            }
            else {
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, 8,
                                    "Tx Connect Speed v3: %#x%04x",
                                    h_int, l_int);
            }
            break;
        }
        case RX_CONNECT_SPEED_V3:
        {
            guint32 l_int, h_int;
            if (avp_len < 8)
                break;

            h_int = tvb_get_ntohl(tvb, idx);
            l_int = tvb_get_ntohl(tvb, idx+4);
            if (!h_int && !l_int) {
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, 8,
                                    "Rx Connect Speed v3: indeterminable or no physical p2p link");
            }
            else {
                proto_tree_add_text(l2tp_avp_tree, tvb, idx, 8,
                                    "Rx Connect Speed v3: %#x%04x",
                                    h_int, l_int);
            }
            break;
        }
        default:
            proto_tree_add_text(l2tp_avp_tree, tvb, idx, avp_len,
                                "Unknown AVP");
            break;
        }

        idx += avp_len;
    }

    /* SCCRQ digest can only be calculated once we know whether nonces are being used */
    if (digest_avp_len) {
        if (check_control_digest(tunnel, tvb, length, digest_idx, digest_avp_len, msg_type, pinfo) < 0)
            expert_add_info_format(pinfo, digest_item, PI_CHECKSUM, PI_WARN, "Incorrect Digest");
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
    guint8      oam_cell    = 0;
    proto_tree *l2_specific = NULL;
    proto_item *ti          = NULL;
    tvbuff_t   *next_tvb;
    gint        cookie_len  = l2tpv3_cookie;
    gint        l2_spec     = l2tpv3_l2_specific;
    gint        pw_type     = l2tpv3_protocol;

    lcce_settings_t  *lcce      = NULL;
    l2tpv3_session_t *session   = NULL;

    /* Get Session ID */
    sid = tvb_get_ntohl(tvb, idx);
    idx += 4;

    if (tunnel) {
        if (ADDRESSES_EQUAL(&tunnel->lcce1, &pinfo->dst)) {
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
        if (pw_type == -1)
            pw_type = session->pw_type;
    }

    if (l2_spec == -1)
        l2_spec = L2TPv3_L2_SPECIFIC_NONE;

    if (pw_type == -1)
        pw_type = L2TPv3_PROTOCOL_DEFAULT;

    if (cookie_len == -1)
        cookie_len = L2TPv3_COOKIE_DEFAULT;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo,COL_INFO,
                     "%s            (session id=%u)",
                     data_msg, sid);
    }

    if (tree) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_sid, tvb, idx-4, 4, ENC_BIG_ENDIAN);
        proto_item_set_len(l2tp_item, idx);
        if (!(tvb_offset_exists(tvb, idx)))
            return;
        if (cookie_len != 0)
            proto_tree_add_item(l2tp_tree, hf_l2tp_cookie, tvb, idx, cookie_len, ENC_NA);
    }

    switch(l2_spec){
    case L2TPv3_L2_SPECIFIC_DEFAULT:
        if (tree) {
            ti = proto_tree_add_item(tree, hf_l2tp_l2_spec_def,
                                     tvb, idx + cookie_len, 4, ENC_NA);
            l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb, idx + cookie_len,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                idx + cookie_len + 1, 3, ENC_BIG_ENDIAN);
        }
        next_tvb = tvb_new_subset_remaining(tvb, idx + cookie_len + 4);
        break;
    case L2TPv3_L2_SPECIFIC_DOCSIS_DMPT:
        if (tree) {
            ti = proto_tree_add_item(tree, hf_l2tp_l2_spec_docsis_dmpt,
                                     tvb, idx + cookie_len, 4, ENC_NA);
            l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_v, tvb,
                                idx + cookie_len,1, ENC_BIG_ENDIAN);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb,
                                idx + cookie_len,1, ENC_BIG_ENDIAN);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_flow_id, tvb,
                                idx + cookie_len,1, ENC_BIG_ENDIAN);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                idx + cookie_len + 2,2, ENC_BIG_ENDIAN);
        }
        next_tvb = tvb_new_subset_remaining(tvb, idx + cookie_len + 4);
        break;
    case L2TPv3_L2_SPECIFIC_ATM:
        if (tree) {
            ti = proto_tree_add_item(tree, hf_l2tp_l2_spec_atm,
                                     tvb, idx + cookie_len, 4, ENC_NA);
            l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb, idx + cookie_len,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_t, tvb, idx + cookie_len,
                                1, ENC_BIG_ENDIAN);
            /*
             * As per RFC 4454, the T bit specifies whether
             * we're transporting an OAM cell or an AAL5 frame.
             */
            oam_cell = tvb_get_guint8(tvb, idx + cookie_len) & 0x08;
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_g, tvb, idx + cookie_len,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_c, tvb, idx + cookie_len,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_u, tvb, idx + cookie_len,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                idx + cookie_len + 1, 3, ENC_BIG_ENDIAN);
        }
        next_tvb = tvb_new_subset_remaining(tvb, idx + cookie_len + 4);
        break;
    case L2TPv3_L2_SPECIFIC_LAPD:
        if (tree)
            proto_tree_add_text(tree, tvb, idx + cookie_len + 4, 3,"LAPD info");
        next_tvb = tvb_new_subset_remaining(tvb, idx + cookie_len+4+3);
        break;
    case L2TPv3_L2_SPECIFIC_NONE:
    default:
        next_tvb = tvb_new_subset_remaining(tvb, idx + cookie_len);
        break;
    }

    switch(pw_type){
    case L2TPv3_PROTOCOL_ETH:
        call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_CHDLC:
        call_dissector(chdlc_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_FR:
        call_dissector(fr_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_PPP:
        /*
         * PPP is transported without Address and Control
         * fields, ppp_hdlc_handle can handle that as if if
         * was ACFC (NULL Address and Control)
         */
        call_dissector(ppp_hdlc_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_IP:
        call_dissector(ip_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_MPLS:
        call_dissector(mpls_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_DOCSIS_DMPT:
        call_dissector(mp2t_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_AAL5:
        if (oam_cell) {
            call_dissector(atm_oam_handle, next_tvb, pinfo, tree);
        } else {
            call_dissector(llc_handle, next_tvb, pinfo, tree);
        }
        break;
    case L2TPv3_PROTOCOL_LAPD:
        call_dissector(lapd_handle, next_tvb, pinfo, tree);
        break;
    case L2TPv3_PROTOCOL_ERICSSON:
        call_dissector(ehdlc_handle, next_tvb, pinfo, tree);
        break;
    default:
        call_dissector(data_handle, next_tvb, pinfo, tree);
        break;
    }
}

/*
 * Processes v3 data message over UDP, to then call process_l2tpv3_data
 * from the common part (Session ID)
 */
static void
process_l2tpv3_data_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        l2tpv3_conversation_t *l2tp_conv)
{
    proto_tree *l2tp_tree = NULL, *ctrl_tree;
    proto_item *l2tp_item = NULL, *ti;

    int idx = 0;
    int control;
    int sid;

    control = tvb_get_ntohs(tvb, idx);
    idx += 2;                       /* skip ahead */
    idx += 2;                       /* Skip the reserved */
    sid = tvb_get_ntohl(tvb, idx);

    if (tree) {
        l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, -1, ENC_NA);
        l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);
        proto_item_append_text(l2tp_item, " version 3");

        ti = proto_tree_add_text(l2tp_tree, tvb, 0, 2,
                                 "Packet Type: %s Session Id=%u",
                                 data_msg, sid);

        ctrl_tree = proto_item_add_subtree(ti, ett_l2tp_ctrl);
        proto_tree_add_uint(ctrl_tree, hf_l2tp_type, tvb, 0, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_length_bit, tvb, 0, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_seq_bit, tvb, 0, 2, control);
        proto_tree_add_uint(ctrl_tree, hf_l2tp_version, tvb, 0, 2, control);
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
    proto_tree *l2tp_tree = NULL;
    proto_item *l2tp_item = NULL;

    int idx = 0;
    int sid;

    sid = tvb_get_ntohl(tvb, idx);

    if (tree) {
        l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, -1, ENC_NA);
        l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);
        proto_item_append_text(l2tp_item, " version 3");

        proto_tree_add_text(l2tp_tree, tvb, 0, 4,
                            "Packet Type: %s Session Id=%u",
                            data_msg, sid);
    }

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
    proto_tree *l2tp_tree = NULL, *ctrl_tree;
    proto_item *l2tp_item = NULL, *ti;

    int     idx     = baseIdx;
    int     tmp_idx;
    guint16 length  = 0;        /* Length field */
    guint32 ccid    = 0;        /* Control Connection ID */
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

    if (check_col(pinfo->cinfo, COL_INFO)) {
        tmp_idx = idx;

        if ((LENGTH_BIT(control))&&(length==12))                /* ZLB Message */
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "%s - ZLB      (tunnel id=%u)",
                         control_msg , ccid);
        else
        {
            if (SEQUENCE_BIT(control)) {
                tmp_idx += 4;
            }

            tmp_idx+=4;

            avp_type = tvb_get_ntohs(tvb, tmp_idx);
            tmp_idx += 2;

            if (avp_type == CONTROL_MESSAGE) {
                /* We print message type */
                msg_type = tvb_get_ntohs(tvb, tmp_idx);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                             "%s - %s (tunnel id=%u)",
                             control_msg ,
                             val_to_str(msg_type, l2tp_message_type_short_str_vals, "Unknown (%u)"),
                             ccid);
            }
            else {
                /*
                 * This is not a control message.
                 * We never pass here except in case of bad l2tp packet!
                 */
                col_add_fstr(pinfo->cinfo, COL_INFO,
                             "%s (tunnel id=%u)",
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
        ti = proto_tree_add_text(l2tp_tree, tvb, baseIdx, 2,
                                 "Packet Type: %s Control Connection Id=%d",
                                 (CONTROL_BIT(control) ? control_msg : data_msg), ccid);

        ctrl_tree = proto_item_add_subtree(ti, ett_l2tp_ctrl);
        proto_tree_add_uint(ctrl_tree, hf_l2tp_type, tvb, baseIdx, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_length_bit, tvb, baseIdx, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_seq_bit, tvb, baseIdx, 2, control);
        proto_tree_add_uint(ctrl_tree, hf_l2tp_version, tvb, baseIdx, 2, control);
    }
    idx = baseIdx + 2;
    if (LENGTH_BIT(control)) {
        if (tree) {
            proto_tree_add_item(l2tp_tree, hf_l2tp_length, tvb, idx, 2, ENC_BIG_ENDIAN);
        }
        idx += 2;
    }

    if (tree) {
        proto_tree_add_item(l2tp_tree, hf_l2tp_ccid, tvb, idx, 4, ENC_BIG_ENDIAN);
    }
    idx += 4;

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

    if (tree && (LENGTH_BIT(control))&&(length==12)) {
        proto_tree_add_text(l2tp_tree, tvb, 0, 0, "Zero Length Bit message");
    } else {
        avp_type = tvb_get_ntohs(tvb, idx + 4);
        if (avp_type == CONTROL_MESSAGE) {

            msg_type = tvb_get_ntohs(tvb, idx + 6);
            if (msg_type == MESSAGE_TYPE_SCCRQ) {
                tunnel = &tmp_tunnel;
                memset(tunnel, 0, sizeof(l2tpv3_tunnel_t));
                tunnel->conv = l2tp_conv;
                SE_COPY_ADDRESS(&tunnel->lcce1, &pinfo->src)
                SE_COPY_ADDRESS(&tunnel->lcce2, &pinfo->dst)
            }
        }
    }

    if (!LENGTH_BIT(control)) {
        return;
    }

    if (tunnel == NULL) {
        tunnel = l2tp_conv->tunnel;
    }

    process_control_avps(tvb, pinfo, l2tp_tree, idx, length+baseIdx, tunnel);

    if (tunnel == &tmp_tunnel && l2tp_conv->tunnel == NULL) {
        l2tp_conv->tunnel = se_alloc0(sizeof(l2tpv3_tunnel_t));
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
    proto_tree *l2tp_tree = NULL, *ctrl_tree;
    proto_item *l2tp_item = NULL, *ti;
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
    if (tvb_length(tvb) < 2)
        return 0;       /* not enough information to check */
    control = tvb_get_ntohs(tvb, 0);
    switch (L2TP_VERSION(control)) {

    case 2:
    case 3:
        break;

    default:
        return 0;
    }

    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
                         pinfo->srcport, pinfo->destport, NO_PORT_B);

    if (conv == NULL) {
        conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
                             pinfo->srcport, pinfo->destport, 0);
    }

    if ((conv == NULL) || (conv->dissector_handle != l2tp_udp_handle)) {
        conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
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
            l2tp_conv = se_alloc0(sizeof(l2tpv3_conversation_t));
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
        return tvb_length(tvb);
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

    if (check_col(pinfo->cinfo, COL_INFO)) {
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
                                 val_to_str(msg_type, l2tp_message_type_short_str_vals, "Unknown (%u)"),
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

    if (tree) {
        l2tp_item = proto_tree_add_item(tree,proto_l2tp, tvb, 0, -1, ENC_NA);
        l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);

        ti = proto_tree_add_text(l2tp_tree, tvb, 0, 2,
                                 "Packet Type: %s Tunnel Id=%d Session Id=%d",
                                 (CONTROL_BIT(control) ? control_msg : data_msg), tid, cid);

        ctrl_tree = proto_item_add_subtree(ti, ett_l2tp_ctrl);
        proto_tree_add_uint(ctrl_tree, hf_l2tp_type, tvb, 0, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_length_bit, tvb, 0, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_seq_bit, tvb, 0, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_offset_bit, tvb, 0, 2, control);
        proto_tree_add_boolean(ctrl_tree, hf_l2tp_priority, tvb, 0, 2, control);
        proto_tree_add_uint(ctrl_tree, hf_l2tp_version, tvb, 0, 2, control);
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
                proto_tree_add_text(l2tp_tree, tvb, idx, offset_size, "Offset Padding");
            }
            idx += offset_size;
        }
    }

    if (tree && (LENGTH_BIT(control))&&(length==12)) {
        proto_tree_add_text(l2tp_tree, tvb, 0, 0, "Zero Length Bit message");
    }

    if (!CONTROL_BIT(control)) {  /* Data Messages so we are done */
        if (tree)
            proto_item_set_len(l2tp_item, idx);
        /* If we have data, signified by having a length bit, dissect it */
        if (tvb_offset_exists(tvb, idx)) {
            next_tvb = tvb_new_subset_remaining(tvb, idx);
            call_dissector(ppp_hdlc_handle, next_tvb, pinfo, tree);
        }
        return tvb_length(tvb);
    }

    if (LENGTH_BIT(control))
        process_control_avps(tvb, pinfo, l2tp_tree, idx, length, NULL);

    return tvb_length(tvb);
}


/*
 * Only L2TPv3 runs directly over IP, and dissect_l2tp_ip starts dissecting
 * those packets to call either process_l2tpv3_control for Control Messages
 * or process_l2tpv3_data_ip for Data Messages over IP, based on the
 * Session ID
 */
static void
dissect_l2tp_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int     idx = 0;
    guint32 sid;                /* Session ID */

    conversation_t *conv = NULL;
    l2tpv3_conversation_t *l2tp_conv = NULL;

    conv = find_or_create_conversation(pinfo);

    l2tp_conv = (l2tpv3_conversation_t *)conversation_get_proto_data(conv, proto_l2tp);
    if (!l2tp_conv) {
        l2tp_conv = se_alloc0(sizeof(l2tpv3_conversation_t));
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

    return;
}

void init_l2tp_dissection(void)
{
    GSList *iterator = list_heads;

    while (iterator) {
        if (iterator->data != NULL)
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
            "Number of octest past the L2TP header at which the payload data starts.", HFILL }},

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
          { "Vendor ID", "l2tp.avp.vendor_id", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0,
            "AVP Vendor ID", HFILL }},

        { &hf_l2tp_avp_type,
          { "Type", "l2tp.avp.type", FT_UINT16, BASE_DEC, VALS(avp_type_vals), 0,
            "AVP Type", HFILL }},

        { &hf_l2tp_tie_breaker,
          { "Tie Breaker", "l2tp.tie_breaker", FT_UINT64, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_l2tp_sid,
          { "Session ID","l2tp.sid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_l2tp_ccid,
          { "Control Connection ID","l2tp.ccid", FT_UINT32, BASE_DEC, NULL, 0x0,
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

        { &hf_l2tp_avp_message_type,
          { "Message Type", "l2tp.avp.message_type", FT_UINT16, BASE_DEC, VALS(message_type_vals), 0,
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
    };

    static gint *ett[] = {
        &ett_l2tp,
        &ett_l2tp_ctrl,
        &ett_l2tp_avp,
        &ett_l2tp_avp_sub,
        &ett_l2tp_l2_spec,
        &ett_l2tp_lcp,
    };

    module_t *l2tp_module;

    proto_l2tp = proto_register_protocol(
        "Layer 2 Tunneling Protocol", "L2TP", "l2tp");
    proto_register_field_array(proto_l2tp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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

    prefs_register_enum_preference(l2tp_module,
                                   "protocol",
                                   "Decode L2TPv3 packet contents as this protocol",
                                   "Decode L2TPv3 packet contents as this protocol",
                                   &l2tpv3_protocol,
                                   l2tpv3_protocols,
                                   FALSE);

    prefs_register_string_preference(l2tp_module,"shared_secret","Shared Secret",
                                   "Shared secret used for control message digest authentication",
                                   &shared_secret);

    register_init_routine(init_l2tp_dissection);
}

void
proto_reg_handoff_l2tp(void)
{
    l2tp_udp_handle = new_create_dissector_handle(dissect_l2tp_udp, proto_l2tp);
    dissector_add_uint("udp.port", UDP_PORT_L2TP, l2tp_udp_handle);

    l2tp_ip_handle = create_dissector_handle(dissect_l2tp_ip, proto_l2tp);
    dissector_add_uint("ip.proto", IP_PROTO_L2TP, l2tp_ip_handle);

    /*
     * Get a handle for the PPP-in-HDLC-like-framing dissector.
     */
    ppp_hdlc_handle = find_dissector("ppp_hdlc");
    ppp_lcp_options_handle = find_dissector("ppp_lcp_options");

    /*
     * Get a handle for the dissectors used in v3.
     */
    eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
    chdlc_handle          = find_dissector("chdlc");
    fr_handle             = find_dissector("fr");
    ip_handle             = find_dissector("ip");
    mpls_handle           = find_dissector("mpls");
    atm_oam_handle        = find_dissector("atm_oam_cell");
    llc_handle            = find_dissector("llc");
    lapd_handle           = find_dissector("lapd");
    mp2t_handle           = find_dissector("mp2t");
    ehdlc_handle          = find_dissector("ehdlc");
    data_handle           = find_dissector("data");
}
