/* packet-aim-messaging.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Messaging
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 * Copyright 2004, Devin Heitmueller <dheitmueller@netilla.com>
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

#include "config.h"



#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

void proto_register_aim_messaging(void);
void proto_reg_handoff_aim_messaging(void);


#define FAMILY_MESSAGING  0x0004


#define INCOMING_CH1_MESSAGE_BLOCK     0x0002
#define INCOMING_CH1_SERVER_ACK_REQ    0x0003
#define INCOMING_CH1_MESSAGE_AUTH_RESP 0x0004
#define INCOMING_CH1_MESSAGE_OFFLINE   0x0006
#define INCOMING_CH1_ICON_PRESENT      0x0008
#define INCOMING_CH1_BUDDY_REQ         0x0009
#define INCOMING_CH1_TYPING            0x000b

static const aim_tlv aim_messaging_incoming_ch1_tlvs[] = {
	{ INCOMING_CH1_MESSAGE_BLOCK,	  "Message Block", dissect_aim_tlv_value_messageblock },
	{ INCOMING_CH1_SERVER_ACK_REQ,	  "Server Ack Requested", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_MESSAGE_AUTH_RESP, "Message is Auto Response", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_MESSAGE_OFFLINE,	  "Message was received offline", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_ICON_PRESENT,	  "Icon present", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_BUDDY_REQ,	  "Buddy Req", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH1_TYPING,		  "Non-direct connect typing notification", dissect_aim_tlv_value_bytes },
	{ 0, NULL, NULL },
};

static int dissect_aim_tlv_value_rendezvous(proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo);

#define ICBM_CHANNEL_IM		0x0001
#define ICBM_CHANNEL_RENDEZVOUS	0x0002

static const value_string icbm_channel_types[] = {
	{ ICBM_CHANNEL_IM,	   "IM" },
	{ ICBM_CHANNEL_RENDEZVOUS, "Rendezvous" },
	{ 0, NULL },
};

#define INCOMING_CH2_SERVER_ACK_REQ    	   0x0003
#define INCOMING_CH2_RENDEZVOUS_DATA       0x0005

static const aim_tlv aim_messaging_incoming_ch2_tlvs[] = {
	{ INCOMING_CH2_SERVER_ACK_REQ, "Server Ack Requested", dissect_aim_tlv_value_bytes },
	{ INCOMING_CH2_RENDEZVOUS_DATA, "Rendez Vous Data", dissect_aim_tlv_value_rendezvous },
	{ 0, NULL, NULL },
};

#define RENDEZVOUS_TLV_CHANNEL				0x0001
#define RENDEZVOUS_TLV_IP_ADDR				0x0002
#define RENDEZVOUS_TLV_INT_IP				0x0003
#define RENDEZVOUS_TLV_EXT_IP				0x0004
#define RENDEZVOUS_TLV_EXT_PORT				0x0005
#define RENDEZVOUS_TLV_DOWNLOAD_URL			0x0006
#define RENDEZVOUS_TLV_VERIFIED_DOWNLOAD_URL		0x0008
#define RENDEZVOUS_TLV_SEQ_NUM				0x000A
#define RENDEZVOUS_TLV_CANCEL_REASON			0x000B
#define RENDEZVOUS_TLV_INVITATION			0x000C
#define RENDEZVOUS_TLV_INVITE_MIME_CHARSET		0x000D
#define RENDEZVOUS_TLV_INVITE_MIME_LANG			0x000E
#define RENDEZVOUS_TLV_REQ_HOST_CHECK			0x000F
#define RENDEZVOUS_TLV_REQ_USE_ARS			0x0010
#define RENDEZVOUS_TLV_REQ_SECURE			0x0011
#define RENDEZVOUS_TLV_MAX_PROTOCOL_VER			0x0012
#define RENDEZVOUS_TLV_MIN_PROTOCOL_VER			0x0013
#define RENDEZVOUS_TLV_COUNTER_REASON			0x0014
#define RENDEZVOUS_TLV_INVITE_MIME_TYPE			0x0015
#define RENDEZVOUS_TLV_IP_ADDR_XOR			0x0016
#define RENDEZVOUS_TLV_PORT_XOR				0x0017
#define RENDEZVOUS_TLV_ADDR_LIST			0x0018
#define RENDEZVOUS_TLV_SESSION_ID			0x0019
#define RENDEZVOUS_TLV_ROLLOVER_ID			0x001A
#define RENDEZVOUS_TLV_EXTENDED_DATA			0x2711
#define RENDEZVOUS_TLV_ICHAT_INVITEES_DATA		0x277E

static const aim_tlv aim_rendezvous_tlvs[] = {
	{ RENDEZVOUS_TLV_CHANNEL,		"Rendezvous ICBM Channel", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_IP_ADDR,		"Rendezvous IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_INT_IP,		"Internal IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_EXT_IP,		"External IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_EXT_PORT,		"External Port", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_DOWNLOAD_URL,		"Service Support Download URL", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_VERIFIED_DOWNLOAD_URL, "Verified Service Support Download URL", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_SEQ_NUM,		"Sequence Number", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_CANCEL_REASON,		"Cancel Reason", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_INVITATION,		"Invitation Text", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_INVITE_MIME_CHARSET,	"Data MIME Type", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_INVITE_MIME_LANG,	"Data Language", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_REQ_HOST_CHECK,	"Request Host Check", NULL },
	{ RENDEZVOUS_TLV_REQ_USE_ARS,		"Request Data via Rendezvous Server", NULL },
	{ RENDEZVOUS_TLV_REQ_SECURE,		"Request SSL Connection", NULL },
	{ RENDEZVOUS_TLV_MAX_PROTOCOL_VER,	"Maximum Protocol Version", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_MIN_PROTOCOL_VER,	"Minimum Protocol Version", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_COUNTER_REASON,	"Counter Proposal Reason", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_INVITE_MIME_TYPE,	"Data MIME Type", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_IP_ADDR_XOR,		"XORed Rendezvous IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_PORT_XOR,		"XORed Port", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_ADDR_LIST,		"Address/Port List", dissect_aim_tlv_value_string08_array },
	{ RENDEZVOUS_TLV_SESSION_ID,		"Session ID", dissect_aim_tlv_value_string },
	{ RENDEZVOUS_TLV_ROLLOVER_ID,		"Rollover ID", dissect_aim_tlv_value_string },
/*
	The dissect_aim_tlv_value_extended_data function does not work for iChat generated rendezvous data
	{ RENDEZVOUS_TLV_EXTENDED_DATA,		"Extended Data", dissect_aim_tlv_value_extended_data },
*/
	{ RENDEZVOUS_TLV_EXTENDED_DATA,		"Extended Data", NULL },
	{ RENDEZVOUS_TLV_ICHAT_INVITEES_DATA,	"iChat Invitees Data", NULL },
	{ 0, NULL, NULL },
};

#define MINITYPING_FINISHED_SIGN			0x0000
#define MINITYPING_TEXT_TYPED_SIGN			0x0001
#define MINITYPING_BEGUN_SIGN				0x0002

static const value_string minityping_type[] _U_ = {
	{MINITYPING_FINISHED_SIGN,   "Typing finished sign" },
	{MINITYPING_TEXT_TYPED_SIGN, "Text typed sign" },
	{MINITYPING_BEGUN_SIGN,	     "Typing begun sign" },
	{0, NULL }
};

#define RENDEZVOUS_MSG_REQUEST 		0
#define RENDEZVOUS_MSG_CANCEL		1
#define RENDEZVOUS_MSG_ACCEPT 		2

static const value_string rendezvous_msg_types[] = {
	{ RENDEZVOUS_MSG_REQUEST, "Request" },
	{ RENDEZVOUS_MSG_CANCEL,  "Cancel" },
	{ RENDEZVOUS_MSG_ACCEPT,  "Accept" },
	{ 0, NULL },
};

#define CLIENT_ERR__REASON_UNSUPPORTED_CHANNEL	1
#define CLIENT_ERR__REASON_BUSTED_PAYLOAD	2
#define CLIENT_ERR__REASON_CHANNEL_SPECIFIC	3

static const value_string client_err_reason_types[] = {
	{ CLIENT_ERR__REASON_UNSUPPORTED_CHANNEL, "Unsupported Channel" },
	{ CLIENT_ERR__REASON_BUSTED_PAYLOAD,	  "Busted Payload" },
	{ CLIENT_ERR__REASON_CHANNEL_SPECIFIC,	  "Channel Specific Error" },
	{ 0, NULL },
};

#define RENDEZVOUS_NAK_PROPOSAL_UNSUPPORTED 0
#define RENDEZVOUS_NAK_PROPOSAL_DENIED 1
#define RENDEZVOUS_NAK_PROPOSAL_IGNORED 2
#define RENDEZVOUS_NAK_BUSTED_PARAMETERS 3
#define RENDEZVOUS_NAK_PROPOSAL_TIMED_OUT 4
#define RENDEZVOUS_NAK_ONLINE_BUT_NOT_AVAILABLE 5
#define RENDEZVOUS_NAK_INSUFFICIENT_RESOURCES 6
#define RENDEZVOUS_NAK_RATE_LIMITED 7
#define RENDEZVOUS_NAK_NO_DATA 8
#define RENDEZVOUS_NAK_VERSION_MISMATCH 9
#define RENDEZVOUS_NAK_SECURITY_MISMATCH 10
#define RENDEZVOUS_NAK_SERVICE_SPECIFIC_REASON 15

static const value_string rendezvous_nak_reason_types[] = {
	{ RENDEZVOUS_NAK_PROPOSAL_UNSUPPORTED,	   "Proposal UUID not supported" },
	{ RENDEZVOUS_NAK_PROPOSAL_DENIED,	   "Not authorized, or user declined" },
	{ RENDEZVOUS_NAK_PROPOSAL_IGNORED,	   "Proposal ignored" },
	{ RENDEZVOUS_NAK_BUSTED_PARAMETERS,	   "Proposal malformed" },
	{ RENDEZVOUS_NAK_PROPOSAL_TIMED_OUT,	   "Attempt to act on proposal (e.g. connect) timed out" },
	{ RENDEZVOUS_NAK_ONLINE_BUT_NOT_AVAILABLE, "Recipient away or busy" },
	{ RENDEZVOUS_NAK_INSUFFICIENT_RESOURCES,   "Recipient had internal error" },
	{ RENDEZVOUS_NAK_RATE_LIMITED,		   "Recipient was ratelimited" },
	{ RENDEZVOUS_NAK_NO_DATA,		   "Recipient had nothing to send" },
	{ RENDEZVOUS_NAK_VERSION_MISMATCH,	   "Incompatible versions" },
	{ RENDEZVOUS_NAK_SECURITY_MISMATCH,	   "Incompatible security settings" },
	{ RENDEZVOUS_NAK_SERVICE_SPECIFIC_REASON,  "Service-specific reject defined by client" },
	{ 0, NULL },
};

#define EXTENDED_DATA_MTYPE_PLAIN 0x01
#define EXTENDED_DATA_MTYPE_CHAT 0x02
#define EXTENDED_DATA_MTYPE_FILEREQ 0x03
#define EXTENDED_DATA_MTYPE_URL 0x04
#define EXTENDED_DATA_MTYPE_AUTHREQ 0x06
#define EXTENDED_DATA_MTYPE_AUTHDENY 0x07
#define EXTENDED_DATA_MTYPE_AUTHOK 0x08
#define EXTENDED_DATA_MTYPE_SERVER 0x09
#define EXTENDED_DATA_MTYPE_ADDED 0x0C
#define EXTENDED_DATA_MTYPE_WWP 0x0D
#define EXTENDED_DATA_MTYPE_EEXPRESS 0x0E
#define EXTENDED_DATA_MTYPE_CONTACTS 0x13
#define EXTENDED_DATA_MTYPE_PLUGIN 0x1A
#define EXTENDED_DATA_MTYPE_AUTOAWAY 0xE8
#define EXTENDED_DATA_MTYPE_AUTOBUSY 0xE9
#define EXTENDED_DATA_MTYPE_AUTONA 0xEA
#define EXTENDED_DATA_MTYPE_AUTODND 0xEB
#define EXTENDED_DATA_MTYPE_AUTOFFC 0xEC

static const value_string extended_data_message_types[] = {
	{EXTENDED_DATA_MTYPE_PLAIN,    "Plain text (simple) message"},
	{EXTENDED_DATA_MTYPE_CHAT,     "Chat request message"},
	{EXTENDED_DATA_MTYPE_FILEREQ,  "File request / file ok message"},
	{EXTENDED_DATA_MTYPE_URL,      "URL message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHREQ,  "Authorization request message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHDENY, "Authorization denied message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHOK,   "Authorization given message (empty)"},
	{EXTENDED_DATA_MTYPE_SERVER,   "Message from OSCAR server (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_ADDED,    "\"You-were-added\" message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_WWP,      "Web pager message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_EEXPRESS, "Email express message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_CONTACTS, "Contact list message"},
	{EXTENDED_DATA_MTYPE_PLUGIN,   "Plugin message described by text string"},
	{EXTENDED_DATA_MTYPE_AUTOAWAY, "Auto away message"},
	{EXTENDED_DATA_MTYPE_AUTOBUSY, "Auto occupied message"},
	{EXTENDED_DATA_MTYPE_AUTONA,   "Auto not available message"},
	{EXTENDED_DATA_MTYPE_AUTODND,  "Auto do not disturb message"},
	{EXTENDED_DATA_MTYPE_AUTOFFC,  "Auto free for chat message"},
	{ 0, NULL },
};

#define EXTENDED_DATA_MFLAG_NORMAL 0x01
#define EXTENDED_DATA_MFLAG_AUTO 0x03
#define EXTENDED_DATA_MFLAG_MULTI 0x80

#define EVIL_ORIGIN_ANONYMOUS		1
#define EVIL_ORIGIN_NONANONYMOUS 	2

static const value_string evil_origins[] = {
	{EVIL_ORIGIN_ANONYMOUS,	   "Anonymous"},
	{EVIL_ORIGIN_NONANONYMOUS, "Non-Anonymous"},
	{0, NULL },
};

/* Initialize the protocol and registered fields */
static int proto_aim_messaging = -1;
static int hf_aim_icbm_channel = -1;
static int hf_aim_icbm_cookie = -1;
static int hf_aim_icbm_msg_flags = -1;
static int hf_aim_icbm_max_sender_warnlevel = -1;
static int hf_aim_icbm_max_receiver_warnlevel = -1;
static int hf_aim_icbm_max_snac_size = -1;
static int hf_aim_icbm_min_msg_interval = -1;
static int hf_aim_icbm_notification_cookie = -1;
static int hf_aim_icbm_notification_channel = -1;
static int hf_aim_icbm_notification_type = -1;
static int hf_aim_icbm_rendezvous_nak = -1;
static int hf_aim_icbm_rendezvous_nak_length = -1;
static int hf_aim_message_channel_id = -1;
static int hf_aim_icbm_evil = -1;
static int hf_aim_evil_warn_level = -1;
static int hf_aim_evil_new_warn_level = -1;
static int hf_aim_rendezvous_msg_type = -1;
static int hf_aim_icbm_client_err_reason = -1;
static int hf_aim_icbm_client_err_protocol_version = -1;
static int hf_aim_icbm_client_err_client_caps_flags = -1;
static int hf_aim_rendezvous_extended_data_message_type = -1;
static int hf_aim_rendezvous_extended_data_message_flags = -1;
static int hf_aim_rendezvous_extended_data_message_flags_normal = -1;
static int hf_aim_rendezvous_extended_data_message_flags_auto = -1;
static int hf_aim_rendezvous_extended_data_message_flags_multi = -1;
static int hf_aim_rendezvous_extended_data_message_status_code = -1;
static int hf_aim_rendezvous_extended_data_message_priority_code = -1;
static int hf_aim_rendezvous_extended_data_message_text_length = -1;
static int hf_aim_rendezvous_extended_data_message_text = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_aim_messaging_plugin = -1;
static int hf_aim_icbm_client_err_length = -1;
static int hf_aim_messaging_unknown = -1;
static int hf_aim_icbm_client_err_downcounter = -1;
static int hf_aim_messaging_unknown_data = -1;
static int hf_aim_messaging_plugin_specific_data = -1;

/* Initialize the subtree pointers */
static gint ett_aim_messaging = -1;
static gint ett_aim_rendezvous_data = -1;
static gint ett_aim_extended_data = -1;
static gint ett_aim_extended_data_message_flags = -1;

static int
dissect_aim_tlv_value_rendezvous(proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo)
{
	int offset = 0;
	proto_tree *entry = proto_item_add_subtree(ti, ett_aim_rendezvous_data);
	proto_tree_add_item(entry, hf_aim_rendezvous_msg_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(entry, hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA);
	offset += 8;

	offset = dissect_aim_capability(entry, tvb, offset);

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, entry,
					aim_rendezvous_tlvs);
}

static int
dissect_aim_msg_outgoing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	const aim_tlv *aim_ch_tlvs = NULL;
	guint16 channel_id;
	guint8 *buddyname;
	int buddyname_length;

	/* ICBM Cookie */
	proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA);
	offset += 8;

	/* Message Channel ID */
	channel_id = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;

	/* Add the outgoing username to the info column */
	buddyname_length = aim_get_buddyname(&buddyname, tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " to: %s",
			format_text(buddyname, buddyname_length));

	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);

	switch(channel_id) {
	case ICBM_CHANNEL_IM: aim_ch_tlvs = aim_messaging_incoming_ch1_tlvs; break;
	case ICBM_CHANNEL_RENDEZVOUS: aim_ch_tlvs = aim_messaging_incoming_ch2_tlvs; break;
	default: return offset;
	}

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, msg_tree, aim_ch_tlvs);
}


static int
dissect_aim_msg_incoming(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	const aim_tlv *aim_ch_tlvs;
	guint16 channel_id;

	/* ICBM Cookie */
	proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA);
	offset += 8;

	/* Message Channel ID */
	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	channel_id = tvb_get_ntohs(tvb, offset);
	offset += 2;

	offset = dissect_aim_userinfo(tvb, pinfo, offset, msg_tree);

	switch(channel_id) {
	case ICBM_CHANNEL_IM: aim_ch_tlvs = aim_messaging_incoming_ch1_tlvs; break;
	case ICBM_CHANNEL_RENDEZVOUS: aim_ch_tlvs = aim_messaging_incoming_ch2_tlvs; break;
	default: return offset;
	}

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, msg_tree, aim_ch_tlvs);
}

static int
dissect_aim_msg_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_icbm_channel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_msg_flags, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_snac_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_sender_warnlevel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_receiver_warnlevel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_min_msg_interval, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	return offset;
}

static int
dissect_aim_msg_evil_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_icbm_evil, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	return dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
}


static int
dissect_aim_msg_evil_repl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_evil_warn_level, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_evil_new_warn_level, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	return offset;
}

static int
dissect_aim_msg_minityping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_cookie, tvb, offset, 8, ENC_NA); offset+=8;
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_channel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_type, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	return offset;
}

typedef struct _aim_client_plugin
{
	const char *name;
	e_guid_t uuid;
} aim_client_plugin;

static const aim_client_plugin known_client_plugins[] = {
	{ "None",
	 {0x0, 0x0, 0x0,
	 {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}},

	{ "Status Manager",
	 {0xD140CF10, 0xE94F, 0x11D3,
	 {0xBC, 0xD2, 0x00, 0x04, 0xAC, 0x96, 0xDD, 0x96}}},

	{ NULL, {0x0, 0x0, 0x0, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } } }
};

static const
aim_client_plugin *aim_find_plugin ( e_guid_t uuid)
{
	int i;

	for(i = 0; known_client_plugins[i].name; i++)
	{
		const aim_client_plugin *plugin = &(known_client_plugins[i]);

		if(memcmp(&(plugin->uuid), &uuid, sizeof(e_guid_t)) == 0)
			return plugin;
	}

	return NULL;
}

static int
dissect_aim_plugin(proto_tree *entry, tvbuff_t *tvb, int offset, e_guid_t* out_plugin_uuid)
{
	const aim_client_plugin *plugin = NULL;
	e_guid_t uuid;
	proto_item* ti;

	uuid.data1 = tvb_get_ntohl(tvb, offset);
	uuid.data2 = tvb_get_ntohs(tvb, offset+4);
	uuid.data3 = tvb_get_ntohs(tvb, offset+6);
	tvb_memcpy(tvb, uuid.data4, offset+8, 8);
	if (out_plugin_uuid)
		*out_plugin_uuid = uuid;

	plugin = aim_find_plugin(uuid);

	ti = proto_tree_add_item(entry, hf_aim_messaging_plugin, tvb, offset, 16, ENC_NA);
	proto_item_append_text(ti, " (%s)", plugin ? plugin->name:"Unknown");

	return offset+16;
}

static int
dissect_aim_rendezvous_extended_message(tvbuff_t *tvb, proto_tree *msg_tree)
{
	int offset = 0;
	guint32 text_length;
	static const int * flags[] = {
		&hf_aim_rendezvous_extended_data_message_flags_normal,
		&hf_aim_rendezvous_extended_data_message_flags_auto,
		&hf_aim_rendezvous_extended_data_message_flags_multi,
		NULL
	};

	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
	proto_tree_add_bitmask(msg_tree, tvb, offset, hf_aim_rendezvous_extended_data_message_flags,
			       ett_aim_extended_data_message_flags, flags, ENC_NA);
	offset+=1;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_status_code, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_priority_code, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	text_length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item_ret_uint(msg_tree, hf_aim_rendezvous_extended_data_message_text_length, tvb, offset, 2, ENC_BIG_ENDIAN, &text_length); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_text, tvb, offset, text_length, ENC_ASCII|ENC_NA); /* offset+=text_length; */

	offset = tvb_reported_length(tvb);

	return offset;
}

static int
is_uuid_null(e_guid_t uuid)
{
	return (uuid.data1 == 0) &&
	       (uuid.data2 == 0) &&
	       (uuid.data3 == 0) &&
	       (uuid.data4[0] == 0) &&
	       (uuid.data4[1] == 0) &&
	       (uuid.data4[2] == 0) &&
	       (uuid.data4[3] == 0) &&
	       (uuid.data4[4] == 0) &&
	       (uuid.data4[5] == 0) &&
	       (uuid.data4[6] == 0) &&
	       (uuid.data4[7] == 0);
}

static int
dissect_aim_tlv_value_extended_data(proto_tree *entry, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	guint16 length/*, protocol_version*/;
	int start_offset;
	e_guid_t plugin_uuid;

	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(entry, hf_aim_icbm_client_err_length, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset+=2;
	start_offset = offset;

	proto_tree_add_item(entry, hf_aim_icbm_client_err_protocol_version, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

	offset = dissect_aim_plugin(entry, tvb, offset, &plugin_uuid);
	proto_tree_add_item(entry, hf_aim_messaging_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(entry, hf_aim_icbm_client_err_client_caps_flags, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
	proto_tree_add_item(entry, hf_aim_messaging_unknown, tvb, offset, 1, ENC_NA);	offset += 1;
	proto_tree_add_item(entry, hf_aim_icbm_client_err_downcounter, tvb, offset, 2, ENC_LITTLE_ENDIAN); /* offset += 2;*/

	offset = start_offset + length;

	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(entry, hf_aim_icbm_client_err_length, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset+=2;
	start_offset = offset;
	proto_tree_add_item(entry, hf_aim_icbm_client_err_downcounter, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(entry, hf_aim_messaging_unknown_data, tvb, offset, length-2, ENC_NA);
	offset = start_offset + length;

	if (is_uuid_null(plugin_uuid))
	{
		/* a message follows */
		tvbuff_t *subtvb = tvb_new_subset_remaining(tvb, offset);
		/* offset += */ dissect_aim_rendezvous_extended_message(subtvb, entry);
	}
	else
	{
		/* plugin-specific data follows */
		proto_tree_add_item(entry, hf_aim_messaging_plugin_specific_data, tvb, offset, -1, ENC_NA);
	}
	offset = tvb_reported_length(tvb);

	return offset;
}

static int
dissect_aim_msg_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;

	proto_tree_add_item(msg_tree,hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA); offset+=8;

	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			    ENC_BIG_ENDIAN); offset += 2;

	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);

	return offset;
}

static int
dissect_aim_msg_client_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	guint16 channel, reason;

	proto_tree_add_item(msg_tree,hf_aim_icbm_cookie, tvb, offset, 8, ENC_NA); offset+=8;
	channel = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree,hf_aim_icbm_channel, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
	reason = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_icbm_client_err_reason, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

	if (reason == CLIENT_ERR__REASON_CHANNEL_SPECIFIC && tvb_reported_length_remaining(tvb, offset) > 0)
	{
		switch (channel)
		{
		case ICBM_CHANNEL_RENDEZVOUS:
			proto_tree_add_item(msg_tree, hf_aim_icbm_rendezvous_nak_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
			proto_tree_add_item(msg_tree, hf_aim_icbm_rendezvous_nak, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
			break;

		default:
		    {
			tvbuff_t *subtvb = tvb_new_subset_remaining(tvb, offset);
			proto_tree *extended_tree = proto_tree_add_subtree(msg_tree, tvb, offset, -1, ett_aim_extended_data, NULL, "Extended Data");
			dissect_aim_tlv_value_extended_data(extended_tree, 0, subtvb, pinfo);
			break;
		    }
		}
	}

	return offset;
}

static const aim_subtype aim_fnac_family_messaging[] = {
	{ 0x0001, "Error",			     dissect_aim_snac_error },
	{ 0x0002, "Set ICBM Parameter",		     dissect_aim_msg_params },
	{ 0x0003, "Reset ICBM Parameter",	     NULL },
	{ 0x0004, "Request Parameter Info",	     NULL},
	{ 0x0005, "Parameter Info",		     dissect_aim_msg_params },
	{ 0x0006, "Outgoing",			     dissect_aim_msg_outgoing },
	{ 0x0007, "Incoming",			     dissect_aim_msg_incoming },
	{ 0x0008, "Evil Request",		     dissect_aim_msg_evil_req },
	{ 0x0009, "Evil Response",		     dissect_aim_msg_evil_repl  },
	{ 0x000a, "Missed Call", 		     NULL },
	{ 0x000b, "Client Error",		     dissect_aim_msg_client_err },
	{ 0x000c, "Acknowledge",		     dissect_aim_msg_ack },
	{ 0x0014, "Mini Typing Notifications (MTN)", dissect_aim_msg_minityping },
	{ 0, NULL, NULL }
};



/* Register the protocol with Wireshark */
void
proto_register_aim_messaging(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_icbm_channel,
		  { "Channel", "aim_messaging.icbm.channel",
		    FT_UINT16, BASE_HEX, VALS(icbm_channel_types), 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_msg_flags,
		  { "Message Flags", "aim_messaging.icbm.flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_max_snac_size,
		  { "Max SNAC Size", "aim_messaging.icbm.max_snac",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_max_sender_warnlevel,
		  { "Max sender warn level", "aim_messaging.icbm.max_sender_warn-level",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_max_receiver_warnlevel,
		  { "max receiver warn level", "aim_messaging.icbm.max_receiver_warnlevel",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_min_msg_interval,
		  { "Minimum message interval (milliseconds)", "aim_messaging.icbm.min_msg_interval",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_cookie,
		  { "ICBM Cookie", "aim_messaging.icbmcookie",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_message_channel_id,
		  { "Message Channel ID", "aim_messaging.channelid",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_evil,
		  { "Send Evil Bit As", "aim_messaging.evilreq.origin",
		    FT_UINT16, BASE_DEC, VALS(evil_origins), 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_evil_warn_level,
		  { "Old warning level", "aim_messaging.evil.warn_level",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_evil_new_warn_level,
		  { "New warning level", "aim_messaging.evil.new_warn_level",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_notification_cookie,
		  { "Notification Cookie", "aim_messaging.notification.cookie",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_notification_channel,
		  { "Notification Channel", "aim_messaging.notification.channel",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_notification_type,
		  { "Notification Type", "aim_messaging.notification.type",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_rendezvous_nak,
		  { "Rendezvous NAK reason", "aim_messaging.rendezvous_nak",
		    FT_UINT16, BASE_HEX, VALS(rendezvous_nak_reason_types), 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_rendezvous_nak_length,
		  { "Rendezvous NAK reason length", "aim_messaging.rendezvous_nak_length",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_msg_type,
		  { "Message Type", "aim_messaging.rendezvous.msg_type",
		    FT_UINT16, BASE_HEX, VALS(rendezvous_msg_types), 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_client_err_reason,
		  { "Reason", "aim_messaging.clienterr.reason",
		    FT_UINT16, BASE_DEC, VALS(client_err_reason_types), 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_client_err_protocol_version,
		  { "Version", "aim_messaging.clienterr.protocol_version",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_icbm_client_err_client_caps_flags,
		  { "Client Capabilities Flags", "aim_messaging.clienterr.client_caps_flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_type,
		  { "Message Type", "aim_messaging.icbm.extended_data.message.type",
		    FT_UINT8, BASE_HEX, VALS(extended_data_message_types), 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags,
		  { "Message Flags", "aim_messaging.icbm.extended_data.message.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_normal,
		  { "Normal Message", "aim_messaging.icbm.extended_data.message.flags.normal",
		    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EXTENDED_DATA_MFLAG_NORMAL,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_auto,
		  { "Auto Message", "aim_messaging.icbm.extended_data.message.flags.auto",
		    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EXTENDED_DATA_MFLAG_AUTO,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_multi,
		  { "Multiple Recipients Message", "aim_messaging.icbm.rendezvous.extended_data.message.flags.multi",
		    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EXTENDED_DATA_MFLAG_MULTI,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_status_code,
		  { "Status Code", "aim_messaging.icbm.extended_data.message.status_code",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_priority_code,
		  { "Priority Code", "aim_messaging.icbm.extended_data.message.priority_code",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_text_length,
		  { "Text Length", "aim_messaging.icbm.extended_data.message.text_length",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_aim_rendezvous_extended_data_message_text,
		  { "Text", "aim_messaging.icbm.extended_data.message.text",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		/* Generated from convert_proto_tree_add_text.pl */
		{ &hf_aim_messaging_plugin, { "Plugin", "aim_messaging.plugin", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_icbm_client_err_length, { "Length", "aim_messaging.clienterr.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_messaging_unknown, { "Unknown", "aim_messaging.unknown", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_icbm_client_err_downcounter, { "Downcounter?", "aim_messaging.clienterr.downcounter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_messaging_unknown_data, { "Unknown", "aim_messaging.unknown_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_aim_messaging_plugin_specific_data, { "Plugin-specific data", "aim_messaging.plugin_specific_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_messaging,
		&ett_aim_rendezvous_data,
		&ett_aim_extended_data,
		&ett_aim_extended_data_message_flags
	};

	/* Register the protocol name and description */
	proto_aim_messaging = proto_register_protocol("AIM Messaging", "AIM Messaging", "aim_messaging");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_messaging, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_messaging(void)
{
	aim_init_family(proto_aim_messaging, ett_aim_messaging, FAMILY_MESSAGING, aim_fnac_family_messaging);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
