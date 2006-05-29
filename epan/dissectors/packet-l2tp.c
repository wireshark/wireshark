/* packet-l2tp.c
 * Routines for Layer Two Tunnelling Protocol (L2TP) (RFC 2661) packet
 * disassembly
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * RFC 2661 for L2TPv2
 * I-D draft-ietf-l2tpext-l2tp-base for L2TPv3
 */

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
static int hf_l2tp_l2_spec_s = -1;
static int hf_l2tp_l2_spec_sequence = -1;
static int hf_l2tp_l2_spec_t = -1;
static int hf_l2tp_l2_spec_g = -1;
static int hf_l2tp_l2_spec_c = -1;
static int hf_l2tp_l2_spec_u = -1;
static int hf_l2tp_cisco_avp_type = -1;

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/sminmpec.h>
#include <epan/prefs.h>

#define UDP_PORT_L2TP   1701

#define CONTROL_BIT(msg_info) (msg_info & 0x8000)   /* Type bit control = 1 data = 0 */
#define LENGTH_BIT(msg_info) (msg_info & 0x4000)    /* Length bit = 1  */
#define RESERVE_BITS(msg_info) (msg_info &0x37F8)   /* Reserved bit - usused */
#define SEQUENCE_BIT(msg_info) (msg_info & 0x0800)  /* SEQUENCE bit = 1 Ns and Nr fields */
#define OFFSET_BIT(msg_info) (msg_info & 0x0200)    /* Offset */
#define PRIORITY_BIT(msg_info) (msg_info & 0x0100)  /* Priority */
#define L2TP_VERSION(msg_info) (msg_info & 0x000f)  /* Version of l2tp */
#define MANDATORY_BIT(msg_info) (msg_info & 0x8000) /* Mandatory = 1 */
#define HIDDEN_BIT(msg_info) (msg_info & 0x4000)    /* Hidden = 1 */
#define AVP_LENGTH(msg_info) (msg_info & 0x03ff)    /* AVP Length */
#define FRAMING_SYNC(msg_info)  (msg_info & 0x0001) /* SYNC Framing Type */
#define FRAMING_ASYNC(msg_info) (msg_info & 0x0002) /* ASYNC Framing Type */
#define BEARER_DIGITAL(msg_info) (msg_info & 0x0001) /* Digital Bearer Type */
#define BEARER_ANALOG(msg_info) (msg_info & 0x0002) /* Analog Bearer Type */
#define CIRCUIT_STATUS_BIT(msg_info) (msg_info & 0x0001)	/* Circuit Status */
#define CIRCUIT_TYPE_BIT(msg_info) (msg_info & 0x0001)		/* Circuit Condition */

static gint ett_l2tp = -1;
static gint ett_l2tp_ctrl = -1;
static gint ett_l2tp_avp = -1;
static gint ett_l2tp_avp_sub = -1;
static gint ett_l2tp_lcp = -1;
static gint ett_l2tp_l2_spec = -1;

static enum_val_t l2tpv3_cookies[] = {
    {"cookie0", "None",                 0},
    {"cookie4", "4 Byte Cookie",        4},
    {"cookie8", "8 Byte Cookie",        8},
    {NULL, NULL, 0}
};

#define L2TPv3_PROTOCOL_ETH     0
#define L2TPv3_PROTOCOL_CHDLC   1
#define L2TPv3_PROTOCOL_FR      2
#define L2TPv3_PROTOCOL_PPP     3
#define L2TPv3_PROTOCOL_IP      4
#define L2TPv3_PROTOCOL_MPLS    5
#define L2TPv3_PROTOCOL_AAL5    6

static enum_val_t l2tpv3_protocols[] = {
    {"eth",     "Ethernet",     L2TPv3_PROTOCOL_ETH},
    {"chdlc",   "Cisco HDLC",   L2TPv3_PROTOCOL_CHDLC},
    {"fr",      "Frame Relay",  L2TPv3_PROTOCOL_FR},
    {"ppp",     "PPP",          L2TPv3_PROTOCOL_PPP},
    {"ip",      "IP",           L2TPv3_PROTOCOL_IP},
    {"mpls",    "MPLS",         L2TPv3_PROTOCOL_MPLS},
    {"aal5",    "AAL5",         L2TPv3_PROTOCOL_AAL5},
    {NULL, NULL, 0}
};

#define L2TPv3_L2_SPECIFIC_NONE         0
#define L2TPv3_L2_SPECIFIC_DEFAULT      1
#define L2TPv3_L2_SPECIFIC_ATM          2

static enum_val_t l2tpv3_l2_specifics[] = {
    {"none",    "None",                 L2TPv3_L2_SPECIFIC_NONE},
    {"default", "Default L2-Specific",  L2TPv3_L2_SPECIFIC_DEFAULT},
    {"atm",     "ATM-Specific",         L2TPv3_L2_SPECIFIC_ATM},
    {NULL, NULL, 0}
};

static gint l2tpv3_cookie = 4;
static gint l2tpv3_protocol = L2TPv3_PROTOCOL_CHDLC;
static gint l2tpv3_l2_specific = L2TPv3_L2_SPECIFIC_DEFAULT;

#define AVP_SCCRQ      1
#define AVP_SCCRP      2
#define AVP_SCCCN      3
#define AVP_StopCCN    4
#define AVP_Reserved   5
#define AVP_HELLO      6
#define AVP_OCRQ       7
#define AVP_OCRP       8
#define AVP_ORCRP      9
#define AVP_ICRQ      10
#define AVP_ICRP      11
#define AVP_ICCN      12
#define AVP_Reserved1 13
#define AVP_CDN       14

#define NUM_CONTROL_CALL_TYPES  20
static const char *calltypestr[NUM_CONTROL_CALL_TYPES+1] = {
  "Unknown Call Type           ",
  "Start_Control_Request       ",
  "Start_Control_Reply         ",
  "Start_Control_Connected     ",
  "Stop_Control_Notification   ",
  "Reserved                    ",
  "Hello                       ",
  "Outgoing_Call_Request       ",
  "Outgoing_Call_Reply         ",
  "Outgoing_Call_Connected     ",
  "Incoming_Call_Request       ",
  "Incoming_Call_Reply         ",
  "Incoming_Call_Connected     ",
  "Reserved                    ",
  "Call_Disconnect_Notification",
  "WAN_Error_Notify            ",
  "Set_Link_Info               ",
  "Modem_Status                ",
  "Service_Relay_Request_Msg   ",
  "Service_Relay_Reply_Message ",
  "Explicit_Acknowledgement    ",
};

static const char *calltype_short_str[NUM_CONTROL_CALL_TYPES+1] = {
  "Unknown ",
  "SCCRQ   ",
  "SCCRP   ",
  "SCCCN   ",
  "StopCCN ",
  "Reserved",
  "Hello   ",
  "OCRQ    ",
  "OCRP    ",
  "OCCN    ",
  "ICRQ    ",
  "ICRP    ",
  "ICCN    ",
  "Reserved",
  "CDN     ",
  "WEN     ",
  "SLI     ",
  "MDMST   ",
  "SRRQ    ",
  "SRRP    ",
  "ACK     ",
};


static const char *control_msg	= "Control Message";
static const char *data_msg	= "Data    Message";
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
  { 1, "Textual username and password" },
  { 2, "PPP CHAP" },
  { 3, "PPP PAP" },
  { 4, "No Authentication" },
  { 5, "Microsoft CHAP Version 1" },
  { 0, NULL }
};

static const value_string data_sequencing_vals[] = {
  { 0, "No incoming data packets require sequencing" },
  { 1, "Only non-IP data packets require sequencing" },
  { 2, "All incoming data packets require sequencing" },
  { 0, NULL }
};

static const value_string l2_sublayer_vals[] = {
  { 0, "No L2-Specific Sublayer Present" },
  { 1, "Default L2-Specific is used" },
  { 0, NULL }
};

static const value_string result_code_stopccn_vals[] = {
  { 0, "Reserved", },
  { 1, "General request to clear control connection", },
  { 2, "General error, Error Code indicates the problem", },
  { 3, "Control connection already exists", },
  { 4, "Requester is not authorized to establish a control connection", },
  { 5, "The protocol version of the requester is not supported", },
  { 6, "Requester is being shut down", },
  { 7, "Finite state machine error or timeout", },
  { 8, "Control connection due to mismatching CCDS value", },
  { 0, NULL }
};

static const value_string result_code_cdn_vals[] = {
  { 0, "Reserved", },
  { 1, "Session disconnected due to loss of carrier or circuit disconnect", },
  { 2, "Session disconnected for the reason indicated in Error Code", },
  { 3, "Session disconnected for administrative reasons", },
  { 4, "Appropriate facilities unavailable (temporary condition)", },
  { 5, "Appropriate facilities unavailable (permanent condition)", },
  { 6, "Invalid destination", },
  { 7, "Call failed due to no carrier detected", },
  { 8, "Call failed due to detection of a busy signal", },
  { 9, "Call failed due to lack of a dial tone", },
  { 10, "Call was not established within time allotted by LAC", },
  { 11, "Call was connected but no appropriate framing was detected", },
  { 12, "Disconnecting call due to mismatching SDS value", },
  { 13, "Session not established due to losing tie breaker", },
  { 14, "Session not established due to unsupported PW type", },
  { 15, "Session not established, sequencing required without valid L2-Specific Sublayer", },
  { 16, "Finite state machine error or timeout", },
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
  { 0, NULL }
};

#define  CONTROL_MESSAGE  0
#define  RESULT_ERROR_CODE 1
#define  PROTOCOL_VERSION  2
#define  FRAMING_CAPABILITIES 3
#define  BEARER_CAPABILITIES 4
#define  TIE_BREAKER 5
#define  FIRMWARE_REVISION 6
#define  HOST_NAME 7
#define  VENDOR_NAME 8
#define  ASSIGNED_TUNNEL_ID 9
#define  RECEIVE_WINDOW_SIZE 10
#define  CHALLENGE 11
#define  CAUSE_CODE 12
#define  CHALLENGE_RESPONSE 13
#define  ASSIGNED_SESSION 14
#define  CALL_SERIAL_NUMBER 15
#define  MINIMUM_BPS 16
#define  MAXIMUM_BPS 17
#define  BEARER_TYPE 18
#define  FRAMING_TYPE 19
#define  CALLED_NUMBER 21
#define  CALLING_NUMBER 22
#define  SUB_ADDRESS 23
#define  TX_CONNECT_SPEED 24
#define  PHYSICAL_CHANNEL 25
#define  INITIAL_RECEIVED_LCP_CONFREQ 26
#define  LAST_SENT_LCP_CONFREQ 27
#define  LAST_RECEIVED_LCP_CONFREQ 28
#define  PROXY_AUTHEN_TYPE 29
#define  PROXY_AUTHEN_NAME 30
#define  PROXY_AUTHEN_CHALLENGE 31
#define  PROXY_AUTHEN_ID 32
#define  PROXY_AUTHEN_RESPONSE 33
#define  CALL_STATUS_AVPS 34
#define  ACCM 35
#define  RANDOM_VECTOR 36
#define  PRIVATE_GROUP_ID 37
#define  RX_CONNECT_SPEED 38
#define  SEQUENCING_REQUIRED 39
#define  PPP_DISCONNECT_CAUSE_CODE 46	/* RFC 3145 */
#define  EXTENDED_VENDOR_ID			58
#define  MESSAGE_DIGEST				59
#define  ROUTER_ID					60
#define  ASSIGNED_CONTROL_CONN_ID	61
#define  PW_CAPABILITY_LIST			62
#define  LOCAL_SESSION_ID			63
#define  REMOTE_SESSION_ID			64
#define  ASSIGNED_COOKIE			65
#define  REMOTE_END_ID				66
#define  PW_TYPE					68
#define  L2_SPECIFIC_SUBLAYER		69
#define  DATA_SEQUENCING			70
#define  CIRCUIT_STATUS				71
#define  PREFERRED_LANGUAGE			72
#define  CTL_MSG_AUTH_NONCE			73
#define  TX_CONNECT_SPEED_V3		74
#define  RX_CONNECT_SPEED_V3		75

#define NUM_AVP_TYPES  76
static const value_string avp_type_vals[] = {
  { CONTROL_MESSAGE,           "Control Message" },
  { RESULT_ERROR_CODE,         "Result-Error Code" },
  { PROTOCOL_VERSION,          "Protocol Version" },
  { FRAMING_CAPABILITIES,      "Framing Capabilities" },
  { BEARER_CAPABILITIES,       "Bearer Capabilities" },
  { TIE_BREAKER,               "Tie Breaker" },
  { FIRMWARE_REVISION,         "Firmware Revision" },
  { HOST_NAME,                 "Host Name" },
  { VENDOR_NAME,               "Vendor Name" },
  { ASSIGNED_TUNNEL_ID,        "Assigned Tunnel ID" },
  { RECEIVE_WINDOW_SIZE,       "Receive Window Size" },
  { CHALLENGE,                 "Challenge" },
  { CAUSE_CODE,                "Cause Code" },
  { CHALLENGE_RESPONSE,        "Challenge Response" },
  { ASSIGNED_SESSION,          "Assigned Session" },
  { CALL_SERIAL_NUMBER,        "Call Serial Number" },
  { MINIMUM_BPS,               "Minimum BPS" },
  { MAXIMUM_BPS,               "Maximum BPS" },
  { BEARER_TYPE,               "Bearer Type" },
  { FRAMING_TYPE,              "Framing Type" },
  { CALLED_NUMBER,             "Called Number" },
  { CALLING_NUMBER,            "Calling Number" },
  { SUB_ADDRESS,               "Sub-Address" },
  { TX_CONNECT_SPEED,          "Connect Speed" },
  { PHYSICAL_CHANNEL,          "Physical Channel" },
  { INITIAL_RECEIVED_LCP_CONFREQ, "Initial Received LCP CONFREQ" },
  { LAST_SENT_LCP_CONFREQ,     "Last Sent LCP CONFREQ" },
  { LAST_RECEIVED_LCP_CONFREQ, "Last Received LCP CONFREQ" },
  { PROXY_AUTHEN_TYPE,         "Proxy Authen Type" },
  { PROXY_AUTHEN_NAME,         "Proxy Authen Name" },
  { PROXY_AUTHEN_CHALLENGE,    "Proxy Authen Challenge" },
  { PROXY_AUTHEN_ID,           "Proxy Authen ID" },
  { PROXY_AUTHEN_RESPONSE,     "Proxy Authen Response" },
  { CALL_STATUS_AVPS,          "Call status AVPs" },
  { ACCM,                      "ACCM" },
  { RANDOM_VECTOR,             "Random Vector" },
  { PRIVATE_GROUP_ID,          "Private group ID" },
  { RX_CONNECT_SPEED,          "RxConnect Speed" },
  { SEQUENCING_REQUIRED,       "Sequencing Required" },
  { PPP_DISCONNECT_CAUSE_CODE, "PPP Disconnect Cause Code" },
  { EXTENDED_VENDOR_ID,        "Extended Vendor ID" },
  { MESSAGE_DIGEST,            "Message Digest" },
  { ROUTER_ID,                 "Router ID" },
  { ASSIGNED_CONTROL_CONN_ID,  "Assigned Control Connection ID" },
  { PW_CAPABILITY_LIST,        "Pseudowire Capability List" },
  { LOCAL_SESSION_ID,          "Local Session ID" },
  { REMOTE_SESSION_ID,         "Remote Session ID" },
  { ASSIGNED_COOKIE,           "Assigned Cookie" },
  { REMOTE_END_ID,             "Remote End ID" },
  { PW_TYPE,                   "Pseudowire Type" },
  { L2_SPECIFIC_SUBLAYER,      "Layer2 Specific Sublayer" },
  { DATA_SEQUENCING,           "Data Sequencing" },
  { CIRCUIT_STATUS,            "Circuit Status" },
  { PREFERRED_LANGUAGE,        "Preferred Language" },
  { CTL_MSG_AUTH_NONCE,        "Control Message Authentication Nonce" },
  { TX_CONNECT_SPEED_V3,       "Tx Connect Speed Version 3" },
  { RX_CONNECT_SPEED_V3,       "Rx Connect Speed Version 3" },
  { 0,                         NULL }
};

#define CISCO_ASSIGNED_CONNECTION_ID	1
#define CISCO_PW_CAPABILITY_LIST	2
#define CISCO_LOCAL_SESSION_ID		3
#define CISCO_REMOTE_SESSION_ID		4
#define CISCO_ASSIGNED_COOKIE		5
#define CISCO_REMOTE_END_ID		6
#define CISCO_PW_TYPE			7
#define CISCO_CIRCUIT_STATUS		8
#define CISCO_SESSION_TIE_BREAKER	9
#define CISCO_DRAFT_AVP_VERSION		10
#define CISCO_MESSAGE_DIGEST		12
#define CISCO_AUTH_NONCE		13
#define CISCO_INTERFACE_MTU		14

static const value_string cisco_avp_type_vals[] = {
  { CISCO_ASSIGNED_CONNECTION_ID,	"Assigned Connection ID" },
  { CISCO_PW_CAPABILITY_LIST,		"Pseudowire Capabilities List" },
  { CISCO_LOCAL_SESSION_ID,		"Local Session ID" },
  { CISCO_REMOTE_SESSION_ID,		"Remote Session ID" },
  { CISCO_ASSIGNED_COOKIE,		"Assigned Cookie" },
  { CISCO_REMOTE_END_ID,		"Remote End ID" },
  { CISCO_PW_TYPE,			"Pseudowire Type" },
  { CISCO_CIRCUIT_STATUS,		"Circuit Status" },
  { CISCO_SESSION_TIE_BREAKER,		"Session Tie Breaker" },
  { CISCO_DRAFT_AVP_VERSION,		"Draft AVP Version" },
  { CISCO_MESSAGE_DIGEST,       	"Message Digest" },
  { CISCO_AUTH_NONCE,        		"Control Message Authentication Nonce" },
  { CISCO_INTERFACE_MTU,		"Interface MTU" },
  { 0,                         		NULL }
};

#define NUM_PW_TYPES  0x1A
static const value_string pw_types_vals[NUM_PW_TYPES+1] = {
	{ 0,  "End of PW Capability List" },
	{ 1,  "Frame Relay DLCI (Martini Mode)" },
	{ 2,  "ATM AAL5 SDU VCC transport" },
	{ 3,  "ATM transparent cell transport" },
	{ 4,  "Ethernet Tagged Mode" },
	{ 5,  "Ethernet" },
	{ 6,  "HDLC" },
	{ 7,  "PPP" },
	{ 8,  "SONET/SDH Circuit Emulation Service Over MPLS (CEM) [Note1]" },
	{ 9,  "ATM n-to-one VCC cell transport" },
	{ 10, "ATM n-to-one VPC cell transport" },
	{ 11, "IP Layer2 Transport" },
	{ 12, "ATM one-to-one VCC Cell Mode" },
	{ 13, "ATM one-to-one VPC Cell Mode" },
	{ 14, "ATM AAL5 PDU VCC transport" },
	{ 15, "Frame-Relay Port mode" },
	{ 16, "SONET/SDH Circuit Emulation over Packet (CEP)" },
	{ 17, "Structure-agnostic E1 over Packet (SAToP)" },
	{ 18, "Structure-agnostic T1 (DS1) over Packet (SAToP)" },
	{ 19, "Structure-agnostic E3 over Packet (SAToP)" },
	{ 20, "Structure-agnostic T3 (DS3) over Packet (SAToP)" },
	{ 21, "CESoPSN basic mode" },
	{ 22, "TDMoIP basic mode" },
	{ 23, "CESoPSN TDM with CAS" },
	{ 24, "TDMoIP TDM with CAS" },
	{ 25, "Frame Relay DLCI" },
	{ 0,  "NULL" },
};

static dissector_handle_t ppp_hdlc_handle;
static dissector_handle_t ppp_lcp_options_handle;

static dissector_handle_t eth_withoutfcs_handle; 
static dissector_handle_t chdlc_handle; 
static dissector_handle_t fr_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t mpls_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t data_handle;

/*
 * Processes AVPs for Control Messages all versions and transports
 */
static void process_control_avps(tvbuff_t *tvb,
				 packet_info *pinfo,
				 proto_tree *l2tp_tree,
				 int index,
				 int length)
{
	proto_tree *l2tp_lcp_avp_tree, *l2tp_avp_tree, *l2tp_avp_tree_sub;
	proto_item *tf, *te;

	int		msg_type;
	gboolean	isStopCcn = FALSE;
	int		avp_type;
	guint32 	avp_vendor_id;
	guint16		avp_len;
	guint16 	ver_len_hidden;
	int		rhcode = 10;
	tvbuff_t	*next_tvb;
	guint16 	result_code;
	guint16 	error_code;
	guint32 	bits;
	guint16 	firmware_rev;
	
	if (l2tp_tree) {
		while (index < length) {    /* Process AVP's */
			ver_len_hidden	= tvb_get_ntohs(tvb, index);
			avp_len		= AVP_LENGTH(ver_len_hidden);
			avp_vendor_id	= tvb_get_ntohs(tvb, index + 2);
			avp_type	= tvb_get_ntohs(tvb, index + 4);

			if (avp_len < 1) {
				proto_tree_add_text(l2tp_tree, tvb, index, 0,
						    "AVP length must be >= 1");
				return;
			}

			if (avp_vendor_id == VENDOR_IETF) {
				tf =  proto_tree_add_text(l2tp_tree, tvb, index,
							  avp_len, "%s AVP",
							  val_to_str(avp_type, avp_type_vals, "Unknown (%u)"));
			} else if (avp_vendor_id == VENDOR_CISCO) {	 /* Vendor-Specific AVP */
				tf =  proto_tree_add_text(l2tp_tree, tvb, index,
							  avp_len, "Vendor %s: %s AVP",
							  val_to_str(avp_vendor_id, sminmpec_values, "Unknown (%u)"),
							  val_to_str(avp_type, cisco_avp_type_vals, "Unknown (%u)"));
			} else {	/* Vendor-Specific AVP */
				tf =  proto_tree_add_text(l2tp_tree, tvb, index,
							  avp_len, "Vendor %s AVP Type %u",
							  val_to_str(avp_vendor_id, sminmpec_values, "Unknown (%u)"),
							  avp_type);
			}
										

			l2tp_avp_tree = proto_item_add_subtree(tf,  ett_l2tp_avp);

			proto_tree_add_boolean_format(l2tp_avp_tree,hf_l2tp_avp_mandatory, tvb, index, 1,
						      rhcode, "Mandatory: %s",
						      (MANDATORY_BIT(ver_len_hidden)) ? "True" : "False" );
			proto_tree_add_boolean_format(l2tp_avp_tree,hf_l2tp_avp_hidden, tvb, index, 1,
						      rhcode, "Hidden: %s",
						      (HIDDEN_BIT(ver_len_hidden)) ? "True" : "False" );
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_avp_length, tvb, index, 2,
						   rhcode, "Length: %u", avp_len);
			if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
				index += avp_len;
				continue;
			}

			if (avp_len < 6) {
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 0,
						    "AVP length must be >= 6");
				return;
			}
			index += 2;
			avp_len -= 2;

			/* Special Case for handling Extended Vendor Id */
			if (avp_type == EXTENDED_VENDOR_ID) {
				index += 2;
				avp_len -= 2;
				proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id,
									tvb, index, 4, FALSE);

				avp_vendor_id  = tvb_get_ntohl(tvb, index);
				
				index += 4;
				avp_len -= 4;
				continue;
			}
			else {
				proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id,
						    tvb, index, 2, FALSE);
				index += 2;
				avp_len -= 2;
			}

			if (avp_vendor_id == VENDOR_CISCO) {
				proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_cisco_avp_type,
						    tvb, index, 2, avp_type);
				index += 2;
				avp_len -= 2;

				/* For the time being, we don't decode any Vendor-
				   specific AVP. */
				switch (avp_type) {
				case CISCO_ASSIGNED_CONNECTION_ID:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
							    "Assigned Control Connection ID: %u",
							    tvb_get_ntohl(tvb, index));
					break;

				case CISCO_PW_CAPABILITY_LIST:
					te = proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						"Pseudowire Capabilities List");
					l2tp_avp_tree_sub = proto_item_add_subtree(te, ett_l2tp_avp_sub);
					while (avp_len >= 2) {
						int pw_type = tvb_get_ntohs(tvb, index);

						proto_tree_add_text(l2tp_avp_tree_sub, tvb, index,
								    2, "PW Type: (%u) %s",
								    pw_type,
								    (pw_type < NUM_PW_TYPES) ? 
								    pw_types_vals[pw_type].strptr : "Unknown");
						index += 2;
						avp_len -= 2;
					}
					break;
					
				case CISCO_LOCAL_SESSION_ID:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
							    "Local Session ID: %u",
							    tvb_get_ntohl(tvb, index));
					break;
				case CISCO_REMOTE_SESSION_ID:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
							    "Remote Session ID: %u",
							    tvb_get_ntohl(tvb, index));
					break;
				case CISCO_ASSIGNED_COOKIE:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							    "Assigned Cookie: %s",
							    tvb_bytes_to_str(tvb, index, avp_len));
					break;
				case CISCO_REMOTE_END_ID:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							    "Remote End ID: %s",
							    tvb_format_text(tvb, index, avp_len));
					break;
				case CISCO_PW_TYPE:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
							    "Pseudowire Type: %u - %s",
							    tvb_get_ntohs(tvb, index),
							    val_to_str(tvb_get_ntohs(tvb, index),
								       pw_types_vals, "Unknown (%u)"));
					break;
				case CISCO_CIRCUIT_STATUS:
					bits = tvb_get_ntohs(tvb, index);
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
							    "Circuit Status: %s",
							    (CIRCUIT_STATUS_BIT(bits)) ? "Up" : "Down");
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
							    "Circuit Type: %s",
							    (CIRCUIT_TYPE_BIT(bits)) ? "New" : "Existing");
					break;
				case CISCO_SESSION_TIE_BREAKER:
					proto_tree_add_item(l2tp_avp_tree, hf_l2tp_tie_breaker,
							    tvb, index, 8, FALSE);
					break;
				case CISCO_DRAFT_AVP_VERSION:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
							    "Draft AVP Version: %u",
							    tvb_get_ntohs(tvb, index));
					break;
				case CISCO_MESSAGE_DIGEST:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							    "Message Digest: %s",
							    tvb_bytes_to_str(tvb, index, avp_len));
					break;
				case CISCO_AUTH_NONCE:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							    "Nonce: %s",
							    tvb_bytes_to_str(tvb, index, avp_len));
					break;
				case CISCO_INTERFACE_MTU:
					proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							    "Interface MTU: %u",
							    tvb_get_ntohs(tvb, index));
					break;
					
				default:
					proto_tree_add_text(l2tp_avp_tree, tvb, index,
							    avp_len, "Vendor-Specific AVP");
					break;
				}
				index += avp_len;
				continue;
			} else if (avp_vendor_id != VENDOR_IETF) {
				if (avp_len >= 2) {
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						"Type: %u", avp_type);
					index += 2;
					avp_len -= 2;
					if (avp_len > 0) {
						proto_tree_add_text(l2tp_avp_tree, tvb, index,
							avp_len, "Vendor-Specific AVP");
					}
				}
				index += avp_len;
				continue;
			}

			proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_avp_type,
					    tvb, index, 2, avp_type);
			index += 2;
			avp_len -= 2;

			switch (avp_type) {

			case CONTROL_MESSAGE:
				msg_type = tvb_get_ntohs(tvb, index);
				proto_tree_add_text(l2tp_avp_tree,tvb, index, 2,
						    "Control Message Type: (%u) %s", msg_type,
						    ((NUM_CONTROL_CALL_TYPES + 1 ) > msg_type) ?
						    calltypestr[msg_type] : "Unknown");

				if (msg_type == AVP_StopCCN) {
					isStopCcn = TRUE;
				}
				break;

			case RESULT_ERROR_CODE:
				if (avp_len < 2)
					break;
				result_code = tvb_get_ntohs(tvb, index);
				if (isStopCcn) {
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
							    "Result code: %u - %s", result_code,
							    val_to_str(result_code, result_code_stopccn_vals, "Unknown (%u)"));
				}
				else {
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
							    "Result code: %u - %s", result_code,
							    val_to_str(result_code, result_code_cdn_vals, "Unknown (%u)"));
				}
				index += 2;
				avp_len -= 2;

				if (avp_len < 2)
					break;
				error_code = tvb_get_ntohs(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Error code: %u - %s", error_code, 
						    val_to_str(error_code, error_code_vals, "Unknown (%u)"));
				index += 2;
				avp_len -= 2;

				if (avp_len == 0)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Error Message: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case PROTOCOL_VERSION:
				if (avp_len < 1)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
						    "Version: %u", tvb_get_guint8(tvb, index));
				index += 1;
				avp_len -= 1;

				proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
						    "Revision: %u", tvb_get_guint8(tvb, index));
				break;

			case FRAMING_CAPABILITIES:
				bits = tvb_get_ntohl(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Async Framing Supported: %s",
						    (FRAMING_ASYNC(bits)) ? "True" : "False");
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Sync Framing Supported: %s",
						    (FRAMING_SYNC(bits)) ? "True" : "False");
				break;

			case BEARER_CAPABILITIES:
				bits = tvb_get_ntohl(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Analog Access Supported: %s",
						    (BEARER_ANALOG(bits)) ? "True" : "False");
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Digital Access Supported: %s",
						    (BEARER_DIGITAL(bits)) ? "True" : "False");
				break;

			case TIE_BREAKER:
				proto_tree_add_item(l2tp_avp_tree, hf_l2tp_tie_breaker, tvb, index, 8, FALSE);
				break;

			case FIRMWARE_REVISION:
				firmware_rev = tvb_get_ntohs(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Firmware Revision: %d 0x%x", firmware_rev,firmware_rev );
				break;

			case HOST_NAME:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Host Name: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case VENDOR_NAME:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Vendor Name: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case ASSIGNED_TUNNEL_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Tunnel ID: %u", tvb_get_ntohs(tvb, index));
				break;

			case RECEIVE_WINDOW_SIZE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Receive Window Size: %u",
						    tvb_get_ntohs(tvb, index));
				break;

			case CHALLENGE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "CHAP Challenge: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;

			case CAUSE_CODE:
				/*
				 * XXX - export stuff from the Q.931 dissector
				 * to dissect the cause code and cause message,
				 * and use it.
				 */
				if (avp_len < 2)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Cause Code: %u",
						    tvb_get_ntohs(tvb, index));
				index += 2;
				avp_len -= 2;

				if (avp_len < 1)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
						    "Cause Msg: %u",
						    tvb_get_guint8(tvb, index));
				index += 1;
				avp_len -= 1;

				if (avp_len == 0)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Advisory Msg: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case CHALLENGE_RESPONSE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 16,
						    "CHAP Challenge Response: %s",
						    tvb_bytes_to_str(tvb, index, 16));
				break;

			case ASSIGNED_SESSION:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Assigned Session: %u",
						    tvb_get_ntohs(tvb, index));
				break;

			case CALL_SERIAL_NUMBER:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Call Serial Number: %u",
						    tvb_get_ntohl(tvb, index));
				break;

			case MINIMUM_BPS:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Minimum BPS: %u",
						    tvb_get_ntohl(tvb, index));
				break;

			case MAXIMUM_BPS:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Maximum BPS: %u",
						    tvb_get_ntohl(tvb, index));
				break;

			case BEARER_TYPE:
				bits = tvb_get_ntohl(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Analog Bearer Type: %s",
						    (BEARER_ANALOG(bits)) ? "True" : "False");
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Digital Bearer Type: %s",
						    (BEARER_DIGITAL(bits)) ? "True" : "False");
				break;

			case FRAMING_TYPE:
				bits = tvb_get_ntohl(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Async Framing Type: %s",
						    (FRAMING_ASYNC(bits)) ? "True" : "False");
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Sync Framing Type: %s",
						     (FRAMING_SYNC(bits)) ? "True" : "False");
				break;

			case CALLED_NUMBER:
				if (avp_len == 0)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Called Number: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case CALLING_NUMBER:
				if (avp_len == 0)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Calling Number: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case SUB_ADDRESS:
				if (avp_len == 0)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Sub-Address: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case TX_CONNECT_SPEED:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Connect Speed: %u",
						    tvb_get_ntohl(tvb, index));
				break;

			case PHYSICAL_CHANNEL:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Physical Channel: %u",
						    tvb_get_ntohl(tvb, index));
				break;

			case INITIAL_RECEIVED_LCP_CONFREQ:
				te = proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							 "Initial Received LCP CONFREQ: %s",
							 tvb_bytes_to_str(tvb, index, avp_len));
				l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
				next_tvb = tvb_new_subset(tvb, index, avp_len, avp_len);
				call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
				break;

			case LAST_SENT_LCP_CONFREQ:
				te = proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							 "Last Sent LCP CONFREQ: %s",
							 tvb_bytes_to_str(tvb, index, avp_len));
				l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
				next_tvb = tvb_new_subset(tvb, index, avp_len, avp_len);
				call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
				break;

			case LAST_RECEIVED_LCP_CONFREQ:
				te = proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
							 "Last Received LCP CONFREQ: %s",
							 tvb_bytes_to_str(tvb, index, avp_len));
				l2tp_lcp_avp_tree = proto_item_add_subtree(te, ett_l2tp_lcp);
				next_tvb = tvb_new_subset(tvb, index, avp_len, avp_len);
				call_dissector(ppp_lcp_options_handle, next_tvb, pinfo, l2tp_lcp_avp_tree );
				break;

			case PROXY_AUTHEN_TYPE:
				msg_type = tvb_get_ntohs(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Proxy Authen Type: %s",
						    val_to_str(msg_type, authen_type_vals, "Unknown (%u)"));
				break;

			case PROXY_AUTHEN_NAME:
				if (avp_len == 0)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Proxy Authen Name: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case PROXY_AUTHEN_CHALLENGE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Proxy Authen Challenge: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;

			case PROXY_AUTHEN_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index + 1, 1,
						    "Proxy Authen ID: %u",
						    tvb_get_guint8(tvb, index + 1));
				break;

			case PROXY_AUTHEN_RESPONSE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Proxy Authen Response: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;

			case CALL_STATUS_AVPS:
				if (avp_len < 2)
					break;
				index += 2;
				avp_len -= 2;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "CRC Errors: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Framing Errors: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Hardware Overruns: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Buffer Overruns: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Time-out Errors: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Alignment Errors: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;
				break;

			case ACCM:
				if (avp_len < 2)
					break;
				index += 2;
				avp_len -= 2;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Send ACCM: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;

				if (avp_len < 4)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Receive ACCM: %u", tvb_get_ntohl(tvb, index));
				index += 4;
				avp_len -= 4;
				break;

			case RANDOM_VECTOR:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Random Vector: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;

			case PRIVATE_GROUP_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Private Group ID: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;

			case RX_CONNECT_SPEED:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Rx Connect Speed: %u",
						    tvb_get_ntohl(tvb, index));
				break;

			case PPP_DISCONNECT_CAUSE_CODE:
				if (avp_len < 2)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Disconnect Code: %u",
						    tvb_get_ntohs(tvb, index));
				index += 2;
				avp_len -= 2;

				if (avp_len < 2)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Control Protocol Number: %u",
						    tvb_get_ntohs(tvb, index));
				index += 2;
				avp_len -= 2;

				if (avp_len < 1)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
						    "Direction: %s",
						    val_to_str(tvb_get_guint8(tvb, index),
						    cause_code_direction_vals,
						    "Reserved (%u)"));
				index += 1;
				avp_len -= 1;

				if (avp_len == 0)
					break;
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Message: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;

			case MESSAGE_DIGEST:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Message Digest: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;
			case ROUTER_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Router ID: %u",
						    tvb_get_ntohl(tvb, index));
				break;
			case ASSIGNED_CONTROL_CONN_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Assigned Control Connection ID: %u",
						    tvb_get_ntohl(tvb, index));
				break;
			case PW_CAPABILITY_LIST:
				te = proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
					"Pseudowire Capabilities List");
				l2tp_avp_tree_sub = proto_item_add_subtree(te, ett_l2tp_avp_sub);

				while (avp_len >= 2) {
					int pw_type = tvb_get_ntohs(tvb, index);
					proto_tree_add_text(l2tp_avp_tree_sub, tvb, index,
							    2, "PW Type: (%u) %s",
							    pw_type,
							    (pw_type < NUM_PW_TYPES) ?
							    pw_types_vals[pw_type].strptr : "Unknown");
					index += 2;
					avp_len -= 2;
				}
				break;
			case LOCAL_SESSION_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Local Session ID: %u",
						    tvb_get_ntohl(tvb, index));
				break;
			case REMOTE_SESSION_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
						    "Remote Session ID: %u",
						    tvb_get_ntohl(tvb, index));
				break;
			case ASSIGNED_COOKIE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Assigned Cookie: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;
			case REMOTE_END_ID:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Remote End ID: %s",
						    tvb_format_text(tvb, index, avp_len));
				break;
			case PW_TYPE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Pseudowire Type: %u - %s",
						    tvb_get_ntohs(tvb, index),
						    val_to_str(tvb_get_ntohs(tvb, index),
							       pw_types_vals, "Unknown"));
				break;
			case L2_SPECIFIC_SUBLAYER:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Layer2 Specific Sublayer: %s",
						    val_to_str(tvb_get_ntohs(tvb, index),
							       l2_sublayer_vals, "Invalid (%u)"));
				break;
			case DATA_SEQUENCING:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Data Sequencing: %s",
						    val_to_str(tvb_get_ntohs(tvb, index),
							       data_sequencing_vals, "Invalid (%u)"));
				break;
			case CIRCUIT_STATUS:
				bits = tvb_get_ntohs(tvb, index);
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Circuit Status: %s",
						    (CIRCUIT_STATUS_BIT(bits)) ? "Up" : "Down");
				proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
						    "Circuit Type: %s",
						    (CIRCUIT_TYPE_BIT(bits)) ? "New" : "Existing");
				break;
			case PREFERRED_LANGUAGE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						   "Preferred Language: %s",
						   tvb_format_text(tvb, index, avp_len));
				break;
			case CTL_MSG_AUTH_NONCE:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Nonce: %s",
						    tvb_bytes_to_str(tvb, index, avp_len));
				break;
			case TX_CONNECT_SPEED_V3:
			{
				guint32 l_int, h_int;
				if (avp_len < 8)
					break;
				
				h_int = tvb_get_ntohl(tvb, index);
				l_int = tvb_get_ntohl(tvb, index+4);
				if (!h_int && !l_int) {
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 8,
							    "Tx Connect Speed v3: indeterminable or no physical p2p link");
				}
				else {
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 8,
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
				
				h_int = tvb_get_ntohl(tvb, index);
				l_int = tvb_get_ntohl(tvb, index+4);
				if (!h_int && !l_int) {
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 8,
							    "Rx Connect Speed v3: indeterminable or no physical p2p link");
				}
				else {
					proto_tree_add_text(l2tp_avp_tree, tvb, index, 8,
							    "Rx Connect Speed v3: %#x%04x",
							    h_int, l_int);
				}
				break;
			}
			default:
				proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
						    "Unknown AVP");
				break;
			}

			index += avp_len;
		}

	}
	return;
}

/*
 * Processes Data Messages for v3 IP and UDP, starting from the  Session ID
 * (common to IP and UDP). Dissects the L2TPv3 Session header, the (optional)
 * L2-Specific sublayer and calls the appropriate dissector for the payload.
 */
static void
process_l2tpv3_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		    proto_tree *l2tp_tree, proto_item *l2tp_item, int *pIndex)
{
	int 		index = *pIndex;
	int 		sid, oam_cell = 0;
	proto_tree	*l2_specific = NULL;
	proto_item	*ti = NULL;
	tvbuff_t	*next_tvb;
	
	/* Get Session ID */
	sid = tvb_get_ntohl(tvb, index);
	index += 4;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo,COL_INFO,
			     "%s            (session id=%u)",
			     data_msg, sid);
	}

	if (tree) {
		proto_tree_add_item(l2tp_tree, hf_l2tp_sid, tvb, index-4, 4, FALSE);
		proto_item_set_len(l2tp_item, index);
		if (!(tvb_offset_exists(tvb, index)))
			return;
		if (l2tpv3_cookie != 0)
			proto_tree_add_item(l2tp_tree, hf_l2tp_cookie, tvb, index, l2tpv3_cookie, FALSE);

                switch(l2tpv3_l2_specific){

                case L2TPv3_L2_SPECIFIC_DEFAULT:
                        ti = proto_tree_add_item(tree, hf_l2tp_l2_spec_def,
                                        tvb, index + l2tpv3_cookie, 4, FALSE);
                        l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb, index + l2tpv3_cookie,
                                                1, FALSE);
                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                                index + l2tpv3_cookie + 1, 3, FALSE);
                        break;
                case L2TPv3_L2_SPECIFIC_ATM:
                        ti = proto_tree_add_item(tree, hf_l2tp_l2_spec_atm,
                                        tvb, index + l2tpv3_cookie, 4, FALSE);
                        l2_specific = proto_item_add_subtree(ti, ett_l2tp_l2_spec);

                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_s, tvb, index + l2tpv3_cookie,
                                                1, FALSE);
                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_t, tvb, index + l2tpv3_cookie,
                                                1, FALSE);
                        oam_cell = tvb_get_ntohl(tvb, 4 + l2tpv3_cookie) & 0x08000000;
                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_g, tvb, index + l2tpv3_cookie,
                                                1, FALSE);
                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_c, tvb, index + l2tpv3_cookie,
                                                1, FALSE);
                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_u, tvb, index + l2tpv3_cookie,
                                                1, FALSE);
                        proto_tree_add_item(l2_specific, hf_l2tp_l2_spec_sequence, tvb,
                                                index + l2tpv3_cookie + 1, 3, FALSE);
                        break;
                case L2TPv3_L2_SPECIFIC_NONE:
                default:
                        break;
                }
          }

          switch(l2tpv3_l2_specific){
          case L2TPv3_L2_SPECIFIC_DEFAULT:
          case L2TPv3_L2_SPECIFIC_ATM:
                next_tvb = tvb_new_subset(tvb, index + l2tpv3_cookie + 4, -1, -1);
                break;
          case L2TPv3_L2_SPECIFIC_NONE:
          default:
                next_tvb = tvb_new_subset(tvb, index + l2tpv3_cookie, -1, -1);
                break;
          }

          switch(l2tpv3_protocol){
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
          case L2TPv3_PROTOCOL_AAL5:
                if (oam_cell) {
                	/* XXX - the ATM dissector should offer an OAM cell dissector */
                        call_dissector(data_handle, next_tvb, pinfo, tree);
                } else {
                        call_dissector(llc_handle, next_tvb, pinfo, tree);
                }
                break;
          default:
                call_dissector(data_handle, next_tvb, pinfo, tree);
                break;
          }

	return;
}

/*
 * Processes v3 data message over UDP, to then call process_l2tpv3_data
 * from the common part (Session ID)
 */
static void
process_l2tpv3_data_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *l2tp_tree = NULL, *ctrl_tree;
	proto_item *l2tp_item = NULL, *ti;
	
	int index = 0;
	int control;
	int sid;
	
	control = tvb_get_ntohs(tvb, index);
	index += 2; 			/* skip ahead */
	index += 2;			/* Skip the reserved */
	sid = tvb_get_ntohl(tvb, index);

	if (tree) {
        	l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, -1, FALSE);
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
		proto_tree_add_item(l2tp_tree, hf_l2tp_res, tvb, 2, 2, FALSE);
	}

	/* Call process_l2tpv3_data from Session ID (offset in index of 4) */
	process_l2tpv3_data(tvb, pinfo, tree, l2tp_tree, l2tp_item, &index);

	return;
}

/*
 * Processes v3 data message over IP, to then call process_l2tpv3_data
 * from the common part (Session ID)
 */
static void
process_l2tpv3_data_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *l2tp_tree = NULL;
	proto_item *l2tp_item = NULL, *ti;
	
	int index = 0;
	int sid;

	sid = tvb_get_ntohl(tvb, index);
	
	if (tree) {
        	l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, -1, FALSE);
		l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);
		proto_item_append_text(l2tp_item, " version 3");

		ti = proto_tree_add_text(l2tp_tree, tvb, 0, 4,
					 "Packet Type: %s Session Id=%u",
					 data_msg, sid);
	}

	/* Call process_l2tpv3_data from Session ID (offset in index of 0) */
	process_l2tpv3_data(tvb, pinfo, tree, l2tp_tree, l2tp_item, &index);

	return;
}

/*
 * Processes v3 Control Message over IP, that carries NULL Session ID
 * to then call process_control_avps after dissecting the control.
 */
static void
process_l2tpv3_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int baseIndex)
{
	proto_tree *l2tp_tree=NULL, *ctrl_tree;
	proto_item *l2tp_item = NULL, *ti;
	
	int index = baseIndex;
	int tmp_index;
	guint16 length = 0;		/* Length field */
	guint32 ccid = 0;		/* Control Connection ID */
	guint16 avp_type;
	guint16 msg_type;
	guint16	control = 0;
	
	control = tvb_get_ntohs(tvb, index);
	index += 2; 			/* skip ahead */
	if (LENGTH_BIT(control)) { 	/* length field included ? */
		length = tvb_get_ntohs(tvb, index);
		index += 2;
	}

	/* Get Control Channel ID */
	ccid = tvb_get_ntohl(tvb, index);
	index += 4;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		tmp_index = index;

		if ((LENGTH_BIT(control))&&(length==12))  		/* ZLB Message */
			col_add_fstr(pinfo->cinfo, COL_INFO,
				     "%s - ZLB      (tunnel id=%u)",
				     control_msg , ccid);
		else
		{
			if (SEQUENCE_BIT(control)) {
				tmp_index += 4;
			}

			tmp_index+=4;

			avp_type = tvb_get_ntohs(tvb, tmp_index);
			tmp_index += 2;
				
			if (avp_type == CONTROL_MESSAGE) {
				/* We print message type */
				msg_type = tvb_get_ntohs(tvb, tmp_index);
				tmp_index += 2;
				col_add_fstr(pinfo->cinfo, COL_INFO,
					     "%s - %s (tunnel id=%u)",
					     control_msg ,
					     ((NUM_CONTROL_CALL_TYPES + 1 ) > msg_type) ?
					     calltype_short_str[msg_type] : "Unknown",
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
		set_actual_length(tvb, length+baseIndex);
	}

	if (tree) {
        	l2tp_item = proto_tree_add_item(tree, proto_l2tp, tvb, 0, -1, FALSE);
		l2tp_tree = proto_item_add_subtree(l2tp_item, ett_l2tp);
		proto_item_append_text(l2tp_item, " version 3");

		if (baseIndex) {
			proto_tree_add_item(l2tp_tree, hf_l2tp_sid, tvb, 0, 4, FALSE);
		}
		ti = proto_tree_add_text(l2tp_tree, tvb, baseIndex, 2,
								 "Packet Type: %s Control Connection Id=%d",
								 (CONTROL_BIT(control) ? control_msg : data_msg), ccid);

		ctrl_tree = proto_item_add_subtree(ti, ett_l2tp_ctrl);
		proto_tree_add_uint(ctrl_tree, hf_l2tp_type, tvb, baseIndex, 2, control);
		proto_tree_add_boolean(ctrl_tree, hf_l2tp_length_bit, tvb, baseIndex, 2, control);
		proto_tree_add_boolean(ctrl_tree, hf_l2tp_seq_bit, tvb, baseIndex, 2, control);
		proto_tree_add_uint(ctrl_tree, hf_l2tp_version, tvb, baseIndex, 2, control);
	}
	index = baseIndex + 2;
	if (LENGTH_BIT(control)) {
		if (tree) {
			proto_tree_add_item(l2tp_tree, hf_l2tp_length, tvb, index, 2, FALSE);
		}
		index += 2;
	}

	if (tree) {
		proto_tree_add_item(l2tp_tree, hf_l2tp_ccid, tvb, index, 4, FALSE);
	}
	index += 4;

	if (SEQUENCE_BIT(control)) {
		if (tree) {
			proto_tree_add_item(l2tp_tree, hf_l2tp_Ns, tvb, index, 2, FALSE);
		}
		index += 2;
		if (tree) {
			proto_tree_add_item(l2tp_tree, hf_l2tp_Nr, tvb, index, 2, FALSE);
		}
		index += 2;
	}
	
	if (tree && (LENGTH_BIT(control))&&(length==12)) {
		proto_tree_add_text(l2tp_tree, tvb, 0, 0, "Zero Length Bit message");
	}

	if (!LENGTH_BIT(control)) {
		return;
	}

	process_control_avps(tvb, pinfo, l2tp_tree, index, length+baseIndex);

	return;
}

/*
 * Dissector for L2TP over UDP. For v2, calls process_control_avps for
 * control messages, or the ppp dissector based on the control bit.
 * For v3, calls either process_l2tpv3_control or process_l2tpv3_data_udp
 * based on the control bit.
 */
static int
dissect_l2tp_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *l2tp_tree=NULL, *ctrl_tree;
	proto_item *l2tp_item = NULL, *ti;
	int index = 0;
	int tmp_index;
	guint16 length = 0;		/* Length field */
	guint16 tid;			/* Tunnel ID */
	guint16 cid;			/* Call ID */
	guint16 offset_size;		/* Offset size */
	guint16 avp_type;
	guint16 msg_type;
	guint16	control;
	tvbuff_t	*next_tvb;

	/*
	 * Don't accept packets that aren't for an L2TP version we know,
	 * as they might not be L2TP packets even though they happen
	 * to be coming from or going to the L2TP port.
	 */
	if (!tvb_bytes_exist(tvb, 0, 2))
		return 0;	/* not enough information to check */
	control = tvb_get_ntohs(tvb, 0);
	switch (L2TP_VERSION(control)) {

	case 2:
	case 3:
		break;

	default:
		return 0;
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))	/* build output for closed L2tp frame displayed  */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2TP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	switch (L2TP_VERSION(control)) {

	case 2:
		break;

	case 3:
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2TPv3");
		if (CONTROL_BIT(control)) {
			/* Call to process l2tp v3 control message */
			process_l2tpv3_control(tvb, pinfo, tree, 0);
		}
		else {
			/* Call to process l2tp v3 data message */
			process_l2tpv3_data_udp(tvb, pinfo, tree);
		}
		return tvb_length(tvb);
	}

	if (LENGTH_BIT(control)) { 		/* length field included ? */
		index += 2; 			/* skip ahead */
		length = tvb_get_ntohs(tvb, index);
	}

	/* collect the tunnel id & call id */
	index += 2;
	tid = tvb_get_ntohs(tvb, index);
	index += 2;
	cid = tvb_get_ntohs(tvb, index);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (CONTROL_BIT(control)) {
			/* CONTROL MESSAGE */
			tmp_index = index;

			if ((LENGTH_BIT(control))&&(length==12))	/* ZLB Message */
				col_add_fstr(pinfo->cinfo, COL_INFO,
					     "%s - ZLB      (tunnel id=%d, session id=%u)",
					     control_msg, tid, cid);
			else
			{
				if (SEQUENCE_BIT(control)) {
					tmp_index += 4;
				}

				tmp_index+=4;

				avp_type = tvb_get_ntohs(tvb, (tmp_index+=2));

				if (avp_type == CONTROL_MESSAGE) {
					/* We print message type */
					msg_type = tvb_get_ntohs(tvb, (tmp_index+=2));
					col_add_fstr(pinfo->cinfo, COL_INFO,
						     "%s - %s (tunnel id=%u, session id=%u)",
						     control_msg,
						     ((NUM_CONTROL_CALL_TYPES + 1 ) > msg_type) ?
						     calltype_short_str[msg_type] : "Unknown",
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
		l2tp_item = proto_tree_add_item(tree,proto_l2tp, tvb, 0, -1, FALSE);
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
	index = 2;
	if (LENGTH_BIT(control)) {
		if (tree) {
			proto_tree_add_item(l2tp_tree, hf_l2tp_length, tvb, index, 2, FALSE);
		}
		index += 2;
	}

	if (tree) {
		proto_tree_add_item(l2tp_tree, hf_l2tp_tunnel, tvb, index, 2, FALSE);
	}
	index += 2;
	if (tree) {
		proto_tree_add_item(l2tp_tree, hf_l2tp_session, tvb, index, 2, FALSE);
	}
	index += 2;

	if (SEQUENCE_BIT(control)) {
		if (tree) {
			proto_tree_add_item(l2tp_tree, hf_l2tp_Ns, tvb, index, 2, FALSE);
		}
		index += 2;
		if (tree) {
			proto_tree_add_item(l2tp_tree, hf_l2tp_Nr, tvb, index, 2, FALSE);
		}
		index += 2;
	}
	if (OFFSET_BIT(control)) {
		offset_size = tvb_get_ntohs(tvb, index);
		if (tree) {
			proto_tree_add_uint(l2tp_tree, hf_l2tp_offset, tvb, index, 2,
								offset_size);
		}
		index += 2;
		if (offset_size != 0) {
			if (tree) {
				proto_tree_add_text(l2tp_tree, tvb, index, offset_size, "Offset Padding");
			}
			index += offset_size;
		}
	}
	
	if (tree && (LENGTH_BIT(control))&&(length==12)) {
		proto_tree_add_text(l2tp_tree, tvb, 0, 0, "Zero Length Bit message");
	}

	if (!CONTROL_BIT(control)) {  /* Data Messages so we are done */
		if (tree)
			proto_item_set_len(l2tp_item, index);
		/* If we have data, signified by having a length bit, dissect it */
		if (tvb_offset_exists(tvb, index)) {
			next_tvb = tvb_new_subset(tvb, index, -1, -1);
			call_dissector(ppp_hdlc_handle, next_tvb, pinfo, tree);
		}
		return tvb_length(tvb);
	}

	if (LENGTH_BIT(control))
		process_control_avps(tvb, pinfo, l2tp_tree, index, length);

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
	int index = 0;
	guint32 sid;			/* Session ID */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))	/* Only L2TPv3 runs directly over IP */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2TPv3");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	sid = tvb_get_ntohl(tvb, index);
	if (sid == 0) {
		/* This is control message */
		/* Call to process l2tp v3 control message */
		process_l2tpv3_control(tvb, pinfo, tree, 4);
	}
	else {
		/* Call to process l2tp v3 data message */
		process_l2tpv3_data_ip(tvb, pinfo, tree);
	}
	
	return;	
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
			"Length bit", HFILL }},

		{ &hf_l2tp_seq_bit,
		{ "Sequence Bit", "l2tp.seq_bit", FT_BOOLEAN, 16, TFS(&l2tp_seq_bit_truth), 0x0800,
			"Sequence bit", HFILL }},

		{ &hf_l2tp_offset_bit,
		{ "Offset bit", "l2tp.offset_bit", FT_BOOLEAN, 16, TFS(&l2tp_offset_bit_truth), 0x0200,
			"Offset bit", HFILL }},

		{ &hf_l2tp_priority,
		{ "Priority", "l2tp.priority", FT_BOOLEAN, 16, TFS(&l2tp_priority_truth), 0x0100,
			"Priority bit", HFILL }},

		{ &hf_l2tp_version,
		{ "Version", "l2tp.version", FT_UINT16, BASE_DEC, NULL, 0x000f,
			"Version", HFILL }},

		{ &hf_l2tp_length,
		{ "Length","l2tp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_l2tp_tunnel,
		{ "Tunnel ID","l2tp.tunnel", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
			"Tunnel ID", HFILL }},

		{ &hf_l2tp_session,
		{ "Session ID","l2tp.session", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
			"Session ID", HFILL }},

		{ &hf_l2tp_Ns,
		{ "Ns","l2tp.Ns", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_l2tp_Nr,
		{ "Nr","l2tp.Nr", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_l2tp_offset,
		{ "Offset","l2tp.offset", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of octest past the L2TP header at which the"
				"payload data starts.", HFILL }},

		{ &hf_l2tp_avp_mandatory,
		{ "Mandatory", "l2tp.avp.mandatory", FT_BOOLEAN, BASE_NONE, NULL, 0,
			"Mandatory AVP", HFILL }},

		{ &hf_l2tp_avp_hidden,
		{ "Hidden", "l2tp.avp.hidden", FT_BOOLEAN, BASE_NONE, NULL, 0,
			"Hidden AVP", HFILL }},

		{ &hf_l2tp_avp_length,
		{ "Length", "l2tp.avp.length", FT_UINT16, BASE_DEC, NULL, 0,
			"AVP Length", HFILL }},

		{ &hf_l2tp_avp_vendor_id,
		{ "Vendor ID", "l2tp.avp.vendor_id", FT_UINT16, BASE_DEC, VALS(sminmpec_values), 0,
			"AVP Vendor ID", HFILL }},

		{ &hf_l2tp_avp_type,
		{ "Type", "l2tp.avp.type", FT_UINT16, BASE_DEC, VALS(avp_type_vals), 0,
			"AVP Type", HFILL }},

		{ &hf_l2tp_tie_breaker,
		{ "Tie Breaker", "l2tp.tie_breaker", FT_UINT64, BASE_HEX, NULL, 0,
			"Tie Breaker", HFILL }},

		{ &hf_l2tp_sid,
		{ "Session ID","l2tp.sid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Session ID", HFILL }},

		{ &hf_l2tp_ccid,
		{ "Control Connection ID","l2tp.ccid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Control Connection ID", HFILL }},

		{ &hf_l2tp_res,
		{ "Reserved","l2tp.res", FT_UINT16, BASE_HEX, NULL, 0x0,
			"Reserved", HFILL }},

		{ &hf_l2tp_cookie,
		{ "Cookie","lt2p.cookie", FT_BYTES, BASE_HEX, NULL, 0x0,
			"Cookie", HFILL }},

		{ &hf_l2tp_l2_spec_def,
		{ "Default L2-Specific Sublayer","lt2p.l2_spec_def", FT_NONE, BASE_NONE, NULL, 0x0,
			"Default L2-Specific Sublayer", HFILL }},

		{ &hf_l2tp_l2_spec_atm,
		{ "ATM-Specific Sublayer","lt2p.l2_spec_atm", FT_NONE, BASE_NONE, NULL, 0x0,
			"ATM-Specific Sublayer", HFILL }},

		{ &hf_l2tp_l2_spec_s,
		{ "S-bit","lt2p.l2_spec_s", FT_BOOLEAN, 8, NULL, 0x40,
			"Sequence Bit", HFILL }},

		{ &hf_l2tp_l2_spec_t,
		{ "T-bit","lt2p.l2_spec_t", FT_BOOLEAN, 8, NULL, 0x08,
			"Transport Type Bit", HFILL }},

		{ &hf_l2tp_l2_spec_g, 
		{ "G-bit","lt2p.l2_spec_g", FT_BOOLEAN, 8, NULL, 0x04,
			"EFCI Bit", HFILL }},

		{ &hf_l2tp_l2_spec_c,
		{ "C-bit","lt2p.l2_spec_c", FT_BOOLEAN, 8, NULL, 0x02,
			"CLP Bit", HFILL }},

		{ &hf_l2tp_l2_spec_u,
		{ "U-bit","lt2p.l2_spec_u", FT_BOOLEAN, 8, NULL, 0x01,
			"C/R Bit", HFILL }},

		{ &hf_l2tp_l2_spec_sequence,
		{ "Sequence Number","lt2p.l2_spec_sequence", FT_UINT24, BASE_DEC, NULL, 0x0,
			"Sequence Number", HFILL }},

		{ &hf_l2tp_cisco_avp_type,
		{ "Type", "l2tp.avp.ciscotype", FT_UINT16, BASE_DEC, VALS(cisco_avp_type_vals), 0,
			"AVP Type", HFILL }},

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

}

void
proto_reg_handoff_l2tp(void)
{
	dissector_handle_t l2tp_udp_handle;
	dissector_handle_t l2tp_ip_handle;

	l2tp_udp_handle = new_create_dissector_handle(dissect_l2tp_udp, proto_l2tp);
	dissector_add("udp.port", UDP_PORT_L2TP, l2tp_udp_handle);

	l2tp_ip_handle = create_dissector_handle(dissect_l2tp_ip, proto_l2tp);
	dissector_add("ip.proto", IP_PROTO_L2TP, l2tp_ip_handle);

	/*
	 * Get a handle for the PPP-in-HDLC-like-framing dissector.
	 */
	ppp_hdlc_handle = find_dissector("ppp_hdlc");
	ppp_lcp_options_handle = find_dissector("ppp_lcp_options");

	/*
	 * Get a handle for the dissectors used in v3.
	 */
	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
	chdlc_handle = find_dissector("chdlc");
	fr_handle = find_dissector("fr");
	ip_handle = find_dissector("ip");
	mpls_handle = find_dissector("mpls");
	llc_handle = find_dissector("llc");

	data_handle = find_dissector("data");
}
