/* packet-aim-messaging.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Messaging
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 * Copyright 2004, Devin Heitmueller <dheitmueller@netilla.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_MESSAGING  0x0004


#define INCOMING_CH1_MESSAGE_BLOCK     0x0002
#define INCOMING_CH1_SERVER_ACK_REQ    0x0003
#define INCOMING_CH1_MESSAGE_AUTH_RESP 0x0004
#define INCOMING_CH1_MESSAGE_OFFLINE   0x0006
#define INCOMING_CH1_ICON_PRESENT      0x0008
#define INCOMING_CH1_BUDDY_REQ         0x0009
#define INCOMING_CH1_TYPING            0x000b

static const aim_tlv messaging_incoming_ch1_tlvs[] = {
  { INCOMING_CH1_MESSAGE_BLOCK, "Message Block", dissect_aim_tlv_value_messageblock },
  { INCOMING_CH1_SERVER_ACK_REQ, "Server Ack Requested", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_MESSAGE_AUTH_RESP, "Message is Auto Response", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_MESSAGE_OFFLINE, "Message was received offline", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_ICON_PRESENT, "Icon present", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_BUDDY_REQ, "Buddy Req", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_TYPING, "Non-direct connect typing notification", dissect_aim_tlv_value_bytes },
  { 0, NULL, NULL },
};

int dissect_aim_tlv_value_rendezvous ( proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_);
int dissect_aim_tlv_value_extended_data ( proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_);


#define INCOMING_CH2_SERVER_ACK_REQ    	   0x0003
#define INCOMING_CH2_RENDEZVOUS_DATA       0x0005

static const aim_tlv messaging_incoming_ch2_tlvs[] = {
  { INCOMING_CH2_SERVER_ACK_REQ, "Server Ack Requested", dissect_aim_tlv_value_bytes },
  { INCOMING_CH2_RENDEZVOUS_DATA, "Rendez Vous Data", dissect_aim_tlv_value_rendezvous },
  { 0, NULL, NULL },
};

#define RENDEZVOUS_TLV_INT_IP				0x0003
#define RENDEZVOUS_TLV_EXT_IP				0x0004
#define RENDEZVOUS_TLV_EXT_PORT				0x0005
#define RENDEZVOUS_TLV_EXTENDED_DATA			0x2711

static const aim_tlv rendezvous_tlvs[] = {
	{ RENDEZVOUS_TLV_INT_IP, "Internal IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_EXT_IP, "External IP", dissect_aim_tlv_value_ipv4 },
	{ RENDEZVOUS_TLV_EXT_PORT, "External Port", dissect_aim_tlv_value_uint16 },
	{ RENDEZVOUS_TLV_EXTENDED_DATA, "Extended Data", dissect_aim_tlv_value_extended_data },
	{ 0, NULL, NULL },
};

#define MINITYPING_FINISHED_SIGN			0x0000
#define MINITYPING_TEXT_TYPED_SIGN			0x0001
#define MINITYPING_BEGUN_SIGN				0x0002

static const value_string minityping_type[] = {
	{MINITYPING_FINISHED_SIGN, "Typing finished sign" },
	{MINITYPING_TEXT_TYPED_SIGN, "Text typed sign" },
	{MINITYPING_BEGUN_SIGN, "Typing begun sign" },
	{0, NULL }
};

#define RENDEZVOUS_MSG_REQUEST 		0
#define RENDEZVOUS_MSG_CANCEL		1
#define RENDEZVOUS_MSG_ACCEPT 		2

static const value_string rendezvous_msg_types[] = {
	{ RENDEZVOUS_MSG_REQUEST, "Request" },
	{ RENDEZVOUS_MSG_CANCEL, "Cancel" },
	{ RENDEZVOUS_MSG_ACCEPT, "Accept" },
	{ 0, NULL },
};

#define CLIENTAUTORESP_REASON_BUSTED_PAYLOAD	2
#define CLIENTAUTORESP_REASON_CHANNEL_SPECIFIC	3

static const value_string clientautoresp_reason_types[] = {
	{ CLIENTAUTORESP_REASON_BUSTED_PAYLOAD, "Busted Payload" },
	{ CLIENTAUTORESP_REASON_CHANNEL_SPECIFIC, "Channel-specific" },
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
	{EXTENDED_DATA_MTYPE_PLAIN, "Plain text (simple) message"},
	{EXTENDED_DATA_MTYPE_CHAT, "Chat request message"},
	{EXTENDED_DATA_MTYPE_FILEREQ, "File request / file ok message"},
	{EXTENDED_DATA_MTYPE_URL, "URL message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHREQ, "Authorization request message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHDENY, "Authorization denied message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_AUTHOK, "Authorization given message (empty)"},
	{EXTENDED_DATA_MTYPE_SERVER, "Message from OSCAR server (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_ADDED, "\"You-were-added\" message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_WWP, "Web pager message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_EEXPRESS, "Email express message (0xFE formatted)"},
	{EXTENDED_DATA_MTYPE_CONTACTS, "Contact list message"},
	{EXTENDED_DATA_MTYPE_PLUGIN, "Plugin message described by text string"},
	{EXTENDED_DATA_MTYPE_AUTOAWAY, "Auto away message"},
	{EXTENDED_DATA_MTYPE_AUTOBUSY, "Auto occupied message"},
	{EXTENDED_DATA_MTYPE_AUTONA, "Auto not available message"},
	{EXTENDED_DATA_MTYPE_AUTODND, "Auto do not disturb message"},
	{EXTENDED_DATA_MTYPE_AUTOFFC, "Auto free for chat message"},
	{ 0, NULL },
};

#define EXTENDED_DATA_MFLAG_NORMAL 0x01
#define EXTENDED_DATA_MFLAG_AUTO 0x03
#define EXTENDED_DATA_MFLAG_MULTI 0x80

#define EVIL_ORIGIN_ANONYMOUS		1
#define EVIL_ORIGIN_NONANONYMOUS 	2

static const value_string evil_origins[] = {
	{EVIL_ORIGIN_ANONYMOUS, "Anonymous"},
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
static int hf_aim_icbm_unknown = -1;
static int hf_aim_icbm_notification_cookie = -1;
static int hf_aim_icbm_notification_channel = -1;
static int hf_aim_icbm_notification_type = -1;
static int hf_aim_message_channel_id = -1;
static int hf_aim_icbm_evil = -1;
static int hf_aim_evil_warn_level = -1;
static int hf_aim_evil_new_warn_level = -1;
static int hf_aim_rendezvous_msg_type = -1;
static int hf_aim_icbm_clientautoresp_reason = -1;
static int hf_aim_icbm_clientautoresp_protocol_version = -1;
static int hf_aim_icbm_clientautoresp_client_caps_flags = -1;
static int hf_aim_rendezvous_extended_data_message_type = -1;
static int hf_aim_rendezvous_extended_data_message_flags = -1;
static int hf_aim_rendezvous_extended_data_message_flags_normal = -1;
static int hf_aim_rendezvous_extended_data_message_flags_auto = -1;
static int hf_aim_rendezvous_extended_data_message_flags_multi = -1;
static int hf_aim_rendezvous_extended_data_message_status_code = -1;
static int hf_aim_rendezvous_extended_data_message_priority_code = -1;
static int hf_aim_rendezvous_extended_data_message_text_length = -1;
static int hf_aim_rendezvous_extended_data_message_text = -1;

/* Initialize the subtree pointers */
static gint ett_aim_messaging = -1;
static gint ett_aim_rendezvous_data = -1;
static gint ett_aim_extended_data = -1;
static gint ett_aim_extended_data_message_flags = -1;

int dissect_aim_tlv_value_rendezvous ( proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	proto_tree *entry = proto_item_add_subtree(ti, ett_aim_rendezvous_data);
	proto_tree_add_item(entry, hf_aim_rendezvous_msg_type, tvb, offset, 2, FALSE);
	offset+=2;
	
	proto_tree_add_item(entry, hf_aim_icbm_cookie, tvb, offset, 8, FALSE);
	offset += 8;

	offset = dissect_aim_capability(entry, tvb, offset);

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, entry, rendezvous_tlvs);
}

static int dissect_aim_msg_outgoing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	const aim_tlv *ch_tlvs = NULL;
	guint16 channel_id;
	
	/* ICBM Cookie */
	proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, FALSE);
	offset += 8;

	/* Message Channel ID */
	channel_id = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
						FALSE);
	offset += 2;

	/* Add the outgoing username to the info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		char buddyname[MAX_BUDDYNAME_LENGTH+1];
		int buddyname_length = aim_get_buddyname(buddyname, tvb, offset, 
											 offset + 1);
		col_append_fstr(pinfo->cinfo, COL_INFO, " to: %s",
						format_text(buddyname, buddyname_length));
	}

	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);

	switch(channel_id) {
	case 1: ch_tlvs = messaging_incoming_ch1_tlvs; break;
	case 2: ch_tlvs = messaging_incoming_ch2_tlvs; break;
	default: return offset;
	}
			
	return dissect_aim_tlv_sequence(tvb, pinfo, offset, msg_tree, ch_tlvs);
}


static int dissect_aim_msg_incoming(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	const aim_tlv *ch_tlvs;
	guint16 channel_id; 
	
	/* ICBM Cookie */
	proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, FALSE);
	offset += 8;

	/* Message Channel ID */
	proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
						FALSE);
	channel_id = tvb_get_ntohs(tvb, offset);
	offset += 2;

	offset = dissect_aim_userinfo(tvb, pinfo, offset, msg_tree);
				
	switch(channel_id) {
	case 1: ch_tlvs = messaging_incoming_ch1_tlvs; break;
	case 2: ch_tlvs = messaging_incoming_ch2_tlvs; break;
	default: return offset;
	}

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, msg_tree, 
								 ch_tlvs);
}

static int dissect_aim_msg_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_icbm_channel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_msg_flags, tvb, offset, 4, tvb_get_ntoh24(tvb, offset)); offset+=4;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_snac_size, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_sender_warnlevel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_max_receiver_warnlevel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_min_msg_interval, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_icbm_unknown, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	return offset;
}

static int dissect_aim_msg_evil_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_icbm_evil, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	return dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
}


static int dissect_aim_msg_evil_repl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree, hf_aim_evil_warn_level, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_evil_new_warn_level, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	return offset;
}

static int dissect_aim_msg_minityping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_cookie, tvb, offset, 8, FALSE); offset+=8;
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_channel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
	proto_tree_add_item(msg_tree,hf_aim_icbm_notification_type, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	return offset;
}

typedef struct _aim_client_plugin
{
	const char *name;
	e_uuid_t uuid;
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

static const aim_client_plugin *aim_find_plugin ( e_uuid_t uuid)
{
	int i;

	for(i = 0; known_client_plugins[i].name; i++) 
	{
		const aim_client_plugin *plugin = &(known_client_plugins[i]);

		if(memcmp(&(plugin->uuid), &uuid, sizeof(e_uuid_t)) == 0)
			return plugin;
	}

	return NULL;
}

static int dissect_aim_plugin(proto_tree *entry, tvbuff_t *tvb, int offset, e_uuid_t* out_plugin_uuid)
{
	const aim_client_plugin *plugin = NULL;
	e_uuid_t uuid;

	uuid.Data1 = tvb_get_ntohl(tvb, offset);
	uuid.Data2 = tvb_get_ntohs(tvb, offset+4);
	uuid.Data3 = tvb_get_ntohs(tvb, offset+6);
	tvb_memcpy(tvb, uuid.Data4, offset+8, 8);
	if (out_plugin_uuid)
		*out_plugin_uuid = uuid;

	plugin = aim_find_plugin(uuid);

	proto_tree_add_text(entry, tvb, offset, 16, 
		"Plugin: %s {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", 
		plugin ? plugin->name:"Unknown", uuid.Data1, uuid.Data2, 
		uuid.Data3, uuid.Data4[0], uuid.Data4[1], uuid.Data4[2], 
		uuid.Data4[3], uuid.Data4[4],	uuid.Data4[5], uuid.Data4[6], 
			uuid.Data4[7]
	);
	
	return offset+16;
}

static int dissect_aim_rendezvous_extended_message(tvbuff_t *tvb, proto_tree *msg_tree)
{
	guint8 message_type, message_flags;
	int offset = 0;
	proto_item *ti_flags;
	proto_tree *flags_entry;
	guint16 text_length;
	guint8* text;
	
	message_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_type, tvb, offset, 1, FALSE); offset+=1;
	message_flags = tvb_get_guint8(tvb, offset);
	ti_flags = proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_flags, tvb, offset, 1, message_flags);
	flags_entry = proto_item_add_subtree(ti_flags, ett_aim_extended_data_message_flags);
	proto_tree_add_boolean(flags_entry, hf_aim_rendezvous_extended_data_message_flags_normal, tvb, offset, 1, message_flags);
	proto_tree_add_boolean(flags_entry, hf_aim_rendezvous_extended_data_message_flags_auto, tvb, offset, 1, message_flags);
	proto_tree_add_boolean(flags_entry, hf_aim_rendezvous_extended_data_message_flags_multi, tvb, offset, 1, message_flags);
	offset+=1;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_status_code, tvb, offset, 2, TRUE); offset+=2;
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_priority_code, tvb, offset, 2, TRUE); offset+=2;
	text_length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_rendezvous_extended_data_message_text_length, tvb, offset, 2, TRUE); offset+=2;
	text = tvb_get_ephemeral_string(tvb, offset, text_length);
	proto_tree_add_text(msg_tree, tvb, offset, text_length, "Text: %s", text); offset+=text_length;
	offset = tvb->length;
	
	return offset;
}

static int is_uuid_null(e_uuid_t uuid)
{
	return (uuid.Data1 == 0) &&
	       (uuid.Data2 == 0) &&
	       (uuid.Data3 == 0) &&
	       (uuid.Data4[0] == 0) &&
	       (uuid.Data4[1] == 0) &&
	       (uuid.Data4[2] == 0) &&
	       (uuid.Data4[3] == 0) &&
	       (uuid.Data4[4] == 0) &&
	       (uuid.Data4[5] == 0) &&
	       (uuid.Data4[6] == 0) &&
	       (uuid.Data4[7] == 0);
}

int dissect_aim_tlv_value_extended_data ( proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int offset = 0;
	guint16 length, protocol_version;
	int start_offset;
	proto_tree *entry;
	e_uuid_t plugin_uuid;

	entry = proto_item_add_subtree(ti, ett_aim_extended_data);
	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_text(entry, tvb, offset, 2, "Length: %d", length); offset+=2;
	start_offset = offset;
	protocol_version = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(entry, hf_aim_icbm_clientautoresp_protocol_version, tvb, offset, 2, TRUE); offset+=2;
	
	offset = dissect_aim_plugin(entry, tvb, offset, &plugin_uuid);
	proto_tree_add_text(entry, tvb, offset, 2, "Unknown"); offset += 2;
	proto_tree_add_item(entry, hf_aim_icbm_clientautoresp_client_caps_flags, tvb, offset, 4, TRUE); offset+=4;
	proto_tree_add_text(entry, tvb, offset, 1, "Unknown");	offset += 1;
	proto_tree_add_text(entry, tvb, offset, 2, "Downcounter?"); offset += 2;

	offset = start_offset + length;

	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_text(entry, tvb, offset, 2, "Length: %d", length); offset+=2;
	start_offset = offset;
	proto_tree_add_text(entry, tvb, offset, 2, "Downcounter?"); offset += 2;
	proto_tree_add_text(entry, tvb, offset, length-2, "Unknown");
	offset = start_offset + length;

	if (is_uuid_null(plugin_uuid))
	{
	        /* a message follows */
	        tvbuff_t *subtvb = tvb_new_subset(tvb, offset, -1, -1);
	        offset += dissect_aim_rendezvous_extended_message(subtvb, entry);
	}
	else
	{
	        /* plugin-specific data follows */
	        proto_tree_add_text(entry, tvb, offset, -1, "Plugin-specific data");
	}
	offset = tvb->length;
	
	return offset;
}

static int dissect_aim_msg_clientautoresp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *msg_tree)
{
	int offset = 0;
	guint16 reason;

	proto_tree_add_item(msg_tree,hf_aim_icbm_cookie, tvb, offset, 8, FALSE); offset+=8;
	proto_tree_add_item(msg_tree,hf_aim_icbm_channel, tvb, offset, 2, FALSE); offset+=2;
	offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
	reason = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(msg_tree, hf_aim_icbm_clientautoresp_reason, tvb, offset, 2, FALSE); offset+=2;
	switch (reason)
	{
	case 0x0003:
		{
		    proto_item *ti_extended_data = proto_tree_add_text(msg_tree, tvb, offset, -1, "Extended Data");
		    tvbuff_t *subtvb = tvb_new_subset(tvb, offset, -1, -1);
		    dissect_aim_tlv_value_extended_data(ti_extended_data, 0, subtvb, pinfo);			
		}
		break;
	}
	
	return offset;
}

static const aim_subtype aim_fnac_family_messaging[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Set ICBM Parameter", dissect_aim_msg_params },
	{ 0x0003, "Reset ICBM Parameter", NULL },
	{ 0x0004, "Request Parameter Info", NULL},
	{ 0x0005, "Parameter Info", dissect_aim_msg_params },
	{ 0x0006, "Outgoing", dissect_aim_msg_outgoing },
	{ 0x0007, "Incoming", dissect_aim_msg_incoming },
	{ 0x0008, "Evil Request", dissect_aim_msg_evil_req },
	{ 0x0009, "Evil Response", dissect_aim_msg_evil_repl  },
	{ 0x000a, "Missed Call", NULL },
	{ 0x000b, "Client Auto Response", dissect_aim_msg_clientautoresp },
	{ 0x000c, "Acknowledge", NULL },
	{ 0x0014, "Mini Typing Notifications (MTN)", dissect_aim_msg_minityping },
	{ 0, NULL, NULL }
};



/* Register the protocol with Ethereal */
void
proto_register_aim_messaging(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_icbm_channel,
			{ "Channel to setup", "aim.icbm.channel", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_msg_flags, 
			{ "Message Flags", "aim.icbm.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_max_snac_size,
			{ "Max SNAC Size", "aim.icbm.max_snac", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_max_sender_warnlevel,
			{ "Max sender warn level", "aim.icbm.max_sender_warn-level", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_max_receiver_warnlevel,
			{ "max receiver warn level", "aim.icbm.max_receiver_warnlevel", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_min_msg_interval,
			{ "Minimum message interval (seconds)", "aim.icbm.min_msg_interval", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_unknown,
			{ "Unknown parameter", "aim.icbm.unknown", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_cookie,
			{ "ICBM Cookie", "aim.messaging.icbmcookie", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }
		},
		{ &hf_aim_message_channel_id,
			{ "Message Channel ID", "aim.messaging.channelid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
		},
		{ &hf_aim_icbm_evil,
			{ "Send Evil Bit As", "aim.evilreq.origin", FT_UINT16, BASE_DEC, VALS(evil_origins), 0x0, "", HFILL },
		},
		{ &hf_aim_evil_warn_level,
			{ "Old warning level", "aim.evil.warn_level", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_evil_new_warn_level,
			{ "New warning level", "aim.evil.new_warn_level", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_notification_cookie,
			{ "Notification Cookie", "aim.notification.cookie", FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_notification_channel,
			{ "Notification Channel", "aim.notification.channel", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_notification_type,
			{ "Notification Type", "aim.notification.type", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_rendezvous_msg_type,
			{ "Message Type", "aim.rendezvous.msg_type", FT_UINT16, BASE_HEX, VALS(rendezvous_msg_types), 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_clientautoresp_reason,
			{ "Reason", "aim.clientautoresp.reason", FT_UINT16, BASE_DEC, VALS(clientautoresp_reason_types), 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_clientautoresp_protocol_version,
			{ "Version", "aim.clientautoresp.protocol_version", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_icbm_clientautoresp_client_caps_flags,
			{ "Client Capabilities Flags", "aim.clientautoresp.client_caps_flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_type,
			{ "Message Type", "aim.icbm.extended_data.message.type", FT_UINT8, BASE_HEX, VALS(extended_data_message_types), 0x0, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_flags,
			{ "Message Flags", "aim.icbm.extended_data.message.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_normal,
			{ "Normal Message", "aim.icbm.extended_data.message.flags.normal", FT_BOOLEAN, 16, TFS(&flags_set_truth), EXTENDED_DATA_MFLAG_NORMAL, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_auto,
			{ "Auto Message", "aim.icbm.extended_data.message.flags.auto", FT_BOOLEAN, 16, TFS(&flags_set_truth), EXTENDED_DATA_MFLAG_AUTO, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_flags_multi,
			{ "Multiple Recipients Message", "aim.icbm.rendezvous.extended_data.message.flags.multi", FT_BOOLEAN, 16, TFS(&flags_set_truth), EXTENDED_DATA_MFLAG_MULTI, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_status_code,
			{ "Status Code", "aim.icbm.extended_data.message.status_code", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_priority_code,
			{ "Priority Code", "aim.icbm.extended_data.message.priority_code", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_text_length,
			{ "Text Length", "aim.icbm.extended_data.message.text_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
		{ &hf_aim_rendezvous_extended_data_message_text,
			{ "Text", "aim.icbm.extended_data.message.text", FT_STRING, BASE_HEX, NULL, 0x0, "", HFILL },
		}
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
