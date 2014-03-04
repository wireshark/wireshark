/* packet-yhoo.c
 * Routines for yahoo messenger packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <glib.h>

#include <epan/packet.h>

void proto_register_yhoo(void);
void proto_reg_handoff_yhoo(void);

static int proto_yhoo = -1;
static int hf_yhoo_version = -1;
static int hf_yhoo_len = -1;
static int hf_yhoo_service = -1;
static int hf_yhoo_connection_id = -1;
static int hf_yhoo_magic_id = -1;
static int hf_yhoo_unknown1 = -1;
static int hf_yhoo_msgtype = -1;
static int hf_yhoo_nick1 = -1;
static int hf_yhoo_nick2 = -1;
static int hf_yhoo_content = -1;

static gint ett_yhoo = -1;

#define TCP_PORT_YHOO	5050

/* This is from yahoolib.h from gtkyahoo */

/* Service constants */
#define YAHOO_SERVICE_LOGON                   1
#define YAHOO_SERVICE_LOGOFF                  2
#define YAHOO_SERVICE_ISAWAY                  3
#define YAHOO_SERVICE_ISBACK                  4
#define YAHOO_SERVICE_IDLE                    5
#define YAHOO_SERVICE_MESSAGE                 6
#define YAHOO_SERVICE_IDACT                   7
#define YAHOO_SERVICE_IDDEACT                 8
#define YAHOO_SERVICE_MAILSTAT                9
#define YAHOO_SERVICE_USERSTAT               10
#define YAHOO_SERVICE_NEWMAIL                11
#define YAHOO_SERVICE_CHATINVITE             12
#define YAHOO_SERVICE_CALENDAR               13
#define YAHOO_SERVICE_NEWPERSONALMAIL        14
#define YAHOO_SERVICE_NEWCONTACT             15
#define YAHOO_SERVICE_ADDIDENT               16
#define YAHOO_SERVICE_ADDIGNORE              17
#define YAHOO_SERVICE_PING                   18
#define YAHOO_SERVICE_GROUPRENAME            19
#define YAHOO_SERVICE_SYSMESSAGE             20
#define YAHOO_SERVICE_PASSTHROUGH2           22
#define YAHOO_SERVICE_CONFINVITE             24
#define YAHOO_SERVICE_CONFLOGON              25
#define YAHOO_SERVICE_CONFDECLINE            26
#define YAHOO_SERVICE_CONFLOGOFF             27
#define YAHOO_SERVICE_CONFADDINVITE          28
#define YAHOO_SERVICE_CONFMSG                29
#define YAHOO_SERVICE_CHATLOGON              30
#define YAHOO_SERVICE_CHATLOGOFF             31
#define YAHOO_SERVICE_CHATMSG                32
#define YAHOO_SERVICE_FILETRANSFER           70
#define YAHOO_SERVICE_CHATADDINVITE         157
#define YAHOO_SERVICE_AVATAR                188
#define YAHOO_SERVICE_PICTURE_CHECKSUM      189
#define YAHOO_SERVICE_PICTURE               190
#define YAHOO_SERVICE_PICTURE_UPDATE        193
#define YAHOO_SERVICE_PICTURE_UPLOAD        194
#define YAHOO_SERVICE_YAHOO6_STATUS_UPDATE  198
#define YAHOO_SERVICE_AVATAR_UPDATE         199
#define YAHOO_SERVICE_AUDIBLE               208
#define YAHOO_SERVICE_WEBLOGIN              550
#define YAHOO_SERVICE_SMS_MSG               746


/* Message flags */
#define YAHOO_MSGTYPE_NONE	0
#define YAHOO_MSGTYPE_NORMAL	1
#define YAHOO_MSGTYPE_BOUNCE	2
#define YAHOO_MSGTYPE_STATUS	4
#define YAHOO_MSGTYPE_OFFLINE	1515563606	/* yuck! */

#define YAHOO_RAWPACKET_LEN 105

#if 0
struct yahoo_rawpacket
{
	char          version[8];       /* 7 chars and trailing null */
	unsigned char len[4];           /* length - little endian */
	unsigned char service[4];       /* service - little endian */
	unsigned char connection_id[4]; /* connection number - little endian */
	unsigned char magic_id[4];      /* magic number used for http session */
	unsigned char unknown1[4];
	unsigned char msgtype[4];
	char          nick1[36];
	char          nick2[36];
	char          content[1];       /* was zero, had problems with aix xlc */
};
#endif

static const value_string yhoo_service_vals[] = {
	{YAHOO_SERVICE_LOGON,                "Pager Logon"},
	{YAHOO_SERVICE_LOGOFF,               "Pager Logoff"},
	{YAHOO_SERVICE_ISAWAY,               "Is Away"},
	{YAHOO_SERVICE_ISBACK,               "Is Back"},
	{YAHOO_SERVICE_IDLE,                 "Idle"},
	{YAHOO_SERVICE_MESSAGE,              "Message"},
	{YAHOO_SERVICE_IDACT,                "Activate Identity"},
	{YAHOO_SERVICE_IDDEACT,              "Deactivate Identity"},
	{YAHOO_SERVICE_MAILSTAT,             "Mail Status"},
	{YAHOO_SERVICE_USERSTAT,             "User Status"},
	{YAHOO_SERVICE_NEWMAIL,              "New Mail"},
	{YAHOO_SERVICE_CHATINVITE,           "Chat Invitation"},
	{YAHOO_SERVICE_CALENDAR,             "Calendar Reminder"},
	{YAHOO_SERVICE_NEWPERSONALMAIL,      "New Personals Mail"},
	{YAHOO_SERVICE_NEWCONTACT,           "New Friend"},
	{YAHOO_SERVICE_GROUPRENAME,          "Group Renamed"},
	{YAHOO_SERVICE_ADDIDENT,             "Add Identity"},
	{YAHOO_SERVICE_ADDIGNORE,            "Add Ignore"},
	{YAHOO_SERVICE_PING,                 "Ping"},
	{YAHOO_SERVICE_SYSMESSAGE,           "System Message"},
	{YAHOO_SERVICE_CONFINVITE,           "Conference Invitation"},
	{YAHOO_SERVICE_CONFLOGON,            "Conference Logon"},
	{YAHOO_SERVICE_CONFDECLINE,          "Conference Decline"},
	{YAHOO_SERVICE_CONFLOGOFF,           "Conference Logoff"},
	{YAHOO_SERVICE_CONFMSG,              "Conference Message"},
	{YAHOO_SERVICE_CONFADDINVITE,        "Conference Additional Invitation"},
	{YAHOO_SERVICE_CHATLOGON,            "Chat Logon"},
	{YAHOO_SERVICE_CHATLOGOFF,           "Chat Logoff"},
	{YAHOO_SERVICE_CHATMSG,              "Chat Message"},
	{YAHOO_SERVICE_FILETRANSFER,         "File Transfer"},
	{YAHOO_SERVICE_PASSTHROUGH2,         "Passthrough 2"},
	{YAHOO_SERVICE_CHATADDINVITE,        "Chat add Invite"},
	{YAHOO_SERVICE_AVATAR,               "Avatar"},
	{YAHOO_SERVICE_PICTURE_CHECKSUM,     "Picture Checksum"},
	{YAHOO_SERVICE_PICTURE,              "Picture"},
	{YAHOO_SERVICE_PICTURE_UPDATE,       "Picture Update"},
	{YAHOO_SERVICE_PICTURE_UPLOAD,       "Picture Upload"},
	{YAHOO_SERVICE_YAHOO6_STATUS_UPDATE, "Status update"},
	{YAHOO_SERVICE_AUDIBLE,              "Audible"},
	{YAHOO_SERVICE_WEBLOGIN,             "Weblogin"},
	{YAHOO_SERVICE_SMS_MSG,              "SMS Message"},
	{0, NULL}
};

static const value_string yhoo_msgtype_vals[] = {
	{YAHOO_MSGTYPE_NONE,                 "None"},
	{YAHOO_MSGTYPE_NORMAL,               "Normal"},
	{YAHOO_MSGTYPE_BOUNCE,               "Bounce"},
	{YAHOO_MSGTYPE_STATUS,               "Status Update"},
	{YAHOO_MSGTYPE_OFFLINE,              "Request Offline"},
	{0, NULL}
};

static gboolean
dissect_yhoo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree      *yhoo_tree, *ti;
	int		 offset = 0;

	if (pinfo->srcport != TCP_PORT_YHOO && pinfo->destport != TCP_PORT_YHOO) {
		/* Not the Yahoo port - not a Yahoo Messenger packet. */
		return FALSE;
	}

	/* get at least a full packet structure */
	if ( tvb_length(tvb) < YAHOO_RAWPACKET_LEN ) {
		/* Not enough data captured; maybe it is a Yahoo
		   Messenger packet, but it contains too little data to
		   tell. */
		return FALSE;
	}

	if (tvb_memeql(tvb, offset, "YPNS", 4) != 0 &&
	    tvb_memeql(tvb, offset, "YHOO", 4) != 0) {
		/* Not a Yahoo Messenger packet. */
		return FALSE;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "YHOO");

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
			     ( tvb_memeql(tvb, offset + 0, "YPNS", 4) == 0 ) ? "Request" : "Response",
			     val_to_str(tvb_get_letohl(tvb, offset + 12),
					yhoo_service_vals, "Unknown Service: %u"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_yhoo, tvb,
			offset, -1, ENC_NA);
		yhoo_tree = proto_item_add_subtree(ti, ett_yhoo);

		proto_tree_add_item(yhoo_tree, hf_yhoo_version, tvb,
			offset, 8, ENC_ASCII|ENC_NA);
		offset += 8;

		proto_tree_add_item(yhoo_tree, hf_yhoo_len, tvb,
			offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(yhoo_tree, hf_yhoo_service, tvb,
			offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(yhoo_tree, hf_yhoo_connection_id, tvb,
			offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(yhoo_tree, hf_yhoo_magic_id, tvb,
			offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(yhoo_tree, hf_yhoo_unknown1, tvb,
			offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(yhoo_tree, hf_yhoo_msgtype, tvb,
			offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(yhoo_tree, hf_yhoo_nick1, tvb,
			offset, 36, ENC_ASCII|ENC_NA);
		offset += 36;

		proto_tree_add_item(yhoo_tree, hf_yhoo_nick2, tvb,
			offset, 36, ENC_ASCII|ENC_NA);
		offset += 36;

		proto_tree_add_item(yhoo_tree, hf_yhoo_content, tvb, -1,
			offset, ENC_ASCII|ENC_NA);
	}

	return TRUE;
}

void
proto_register_yhoo(void)
{
	static hf_register_info hf[] = {
		{ &hf_yhoo_service, {
				"Service Type", "yhoo.service", FT_UINT32, BASE_DEC,
				VALS(yhoo_service_vals), 0, NULL, HFILL }},
		{ &hf_yhoo_msgtype, {
				"Message Type", "yhoo.msgtype", FT_UINT32, BASE_DEC,
				VALS(yhoo_msgtype_vals), 0, "Message Type Flags", HFILL }},
		{ &hf_yhoo_connection_id, {
				"Connection ID", "yhoo.connection_id", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }},
		{ &hf_yhoo_magic_id, {
				"Magic ID", "yhoo.magic_id", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }},
		{ &hf_yhoo_unknown1, {
				"Unknown 1", "yhoo.unknown1", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }},
		{ &hf_yhoo_len, {
				"Packet Length", "yhoo.len", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},
		{ &hf_yhoo_nick1, {
				"Real Nick (nick1)", "yhoo.nick1", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},
		{ &hf_yhoo_nick2, {
				"Active Nick (nick2)", "yhoo.nick2", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},
		{ &hf_yhoo_content, {
				"Content", "yhoo.content", FT_STRING, BASE_NONE,
				NULL, 0, "Data portion of the packet", HFILL }},
		{ &hf_yhoo_version, {
				"Version", "yhoo.version", FT_STRING, BASE_NONE,
				NULL, 0, "Packet version identifier", HFILL }},
        };
	static gint *ett[] = {
		&ett_yhoo,
	};

	proto_yhoo = proto_register_protocol("Yahoo Messenger Protocol",
	    "YHOO", "yhoo");

	proto_register_field_array(proto_yhoo, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_yhoo(void)
{
	/*
	 * DO NOT register for port 5050, as that's used by the
	 * old and new Yahoo messenger protocols.
	 *
	 * Just register as a heuristic TCP dissector, and reject stuff
	 * not to or from that port.
	 */
	heur_dissector_add("tcp", dissect_yhoo, proto_yhoo);
}
