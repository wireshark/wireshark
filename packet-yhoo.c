/* packet-yhoo.c
 * Routines for yahoo messenger packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id: packet-yhoo.c,v 1.15 2001/04/23 04:29:54 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-yhoo.h"

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

static const value_string yhoo_service_vals[] = {
	{YAHOO_SERVICE_LOGON, "Pager Logon"},
	{YAHOO_SERVICE_LOGOFF, "Pager Logoff"},
	{YAHOO_SERVICE_ISAWAY, "Is Away"},
	{YAHOO_SERVICE_ISBACK, "Is Back"},
	{YAHOO_SERVICE_IDLE, "Idle"},
	{YAHOO_SERVICE_MESSAGE, "Message"},
	{YAHOO_SERVICE_IDACT, "Activate Identity"},
	{YAHOO_SERVICE_IDDEACT, "Deactivate Identity"},
	{YAHOO_SERVICE_MAILSTAT, "Mail Status"},
	{YAHOO_SERVICE_USERSTAT, "User Status"},
	{YAHOO_SERVICE_NEWMAIL, "New Mail"},
	{YAHOO_SERVICE_CHATINVITE, "Chat Invitation"},
	{YAHOO_SERVICE_CALENDAR, "Calendar Reminder"},
	{YAHOO_SERVICE_NEWPERSONALMAIL, "New Personals Mail"},
	{YAHOO_SERVICE_NEWCONTACT, "New Friend"},
	{YAHOO_SERVICE_GROUPRENAME, "Group Renamed"},
	{YAHOO_SERVICE_ADDIDENT, "Add Identity"},
	{YAHOO_SERVICE_ADDIGNORE, "Add Ignore"},
	{YAHOO_SERVICE_PING, "Ping"},
	{YAHOO_SERVICE_SYSMESSAGE, "System Message"},
	{YAHOO_SERVICE_CONFINVITE, "Conference Invitation"},
	{YAHOO_SERVICE_CONFLOGON, "Conference Logon"},
	{YAHOO_SERVICE_CONFDECLINE, "Conference Decline"},
	{YAHOO_SERVICE_CONFLOGOFF, "Conference Logoff"},
	{YAHOO_SERVICE_CONFMSG, "Conference Message"},
	{YAHOO_SERVICE_CONFADDINVITE, "Conference Additional Invitation"},
	{YAHOO_SERVICE_CHATLOGON, "Chat Logon"},
	{YAHOO_SERVICE_CHATLOGOFF, "Chat Logoff"},
	{YAHOO_SERVICE_CHATMSG, "Chat Message"},
	{YAHOO_SERVICE_FILETRANSFER, "File Transfer"},
	{YAHOO_SERVICE_PASSTHROUGH2, "Passthrough 2"},
	{0, NULL}
};

static const value_string yhoo_msgtype_vals[] = {
	{YAHOO_MSGTYPE_NONE, "None"},
	{YAHOO_MSGTYPE_NORMAL, "Normal"},
	{YAHOO_MSGTYPE_BOUNCE, "Bounce"},
	{YAHOO_MSGTYPE_STATUS, "Status Update"},
	{YAHOO_MSGTYPE_OFFLINE, "Request Offline"},
	{0, NULL}
};

static gboolean
dissect_yhoo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *yhoo_tree, *ti;
	int offset = 0;
	int length = 0;

	if (!proto_is_protocol_enabled(proto_yhoo)) {
		return FALSE;
	}
  
	if (pi.srcport != TCP_PORT_YHOO && pi.destport != TCP_PORT_YHOO) {
		/* Not the Yahoo port - not a Yahoo Messenger packet. */
		return FALSE;
	}

	/* get at least a full packet structure */
	if ( !tvb_bytes_exist(tvb, 0, sizeof(struct yahoo_rawpacket)) ) {
		/* Not enough data captured; maybe it is a Yahoo
		   Messenger packet, but it contains too little data to
		   tell. */
		return FALSE;
	}

	length = tvb_length(tvb);

	if (memcmp(tvb_get_ptr(tvb, offset, 4), "YPNS", 4) != 0 &&
	    memcmp(tvb_get_ptr(tvb, offset, 4), "YHOO", 4) != 0) {
		/* Not a Yahoo Messenger packet. */
		return FALSE;
	}

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "YHOO");

	offset = 0;
	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO, 
			"%s: %s", 
			( strncmp(tvb_get_ptr(tvb, offset + 0, 4), "YPNS", 4) == 0 ) ? "Request" : "Response",
			val_to_str(tvb_get_letohl(tvb, offset + 12),
				 yhoo_service_vals, "Unknown Service: %u")
		);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_yhoo, tvb, offset, 
			tvb_length_remaining(tvb, offset), FALSE);
		yhoo_tree = proto_item_add_subtree(ti, ett_yhoo);

		proto_tree_add_string(yhoo_tree, hf_yhoo_version, tvb, 
			offset, 8, tvb_get_ptr(tvb, offset, 8));
		offset += 8;

		proto_tree_add_uint(yhoo_tree, hf_yhoo_len, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		proto_tree_add_uint(yhoo_tree, hf_yhoo_service, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		proto_tree_add_uint(yhoo_tree, hf_yhoo_connection_id, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		proto_tree_add_uint(yhoo_tree, hf_yhoo_magic_id, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		proto_tree_add_uint(yhoo_tree, hf_yhoo_unknown1, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		proto_tree_add_uint(yhoo_tree, hf_yhoo_msgtype, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		proto_tree_add_string(yhoo_tree, hf_yhoo_nick1, tvb, 
			offset, 36, tvb_get_ptr(tvb, offset, 36));
		offset += 36;

		proto_tree_add_string(yhoo_tree, hf_yhoo_nick2, tvb, 
			offset, 36, tvb_get_ptr(tvb, offset, 36));
		offset += 36;

		proto_tree_add_string(yhoo_tree, hf_yhoo_content, tvb, 
			offset, length, tvb_get_ptr(tvb, offset, length-offset));
	}

	return TRUE;
}

void
proto_register_yhoo(void)
{
	static hf_register_info hf[] = {
			{ &hf_yhoo_service, {	
				"Service Type", "yhoo.service", FT_UINT32, BASE_DEC,
				VALS(yhoo_service_vals), 0, "Service Type" }},
			{ &hf_yhoo_msgtype, {	
				"Message Type", "yhoo.msgtype", FT_UINT32, BASE_DEC,
				VALS(yhoo_msgtype_vals), 0, "Message Type Flags" }},
			{ &hf_yhoo_connection_id, {	
				"Connection ID", "yhoo.connection_id", FT_UINT32, BASE_HEX,
				NULL, 0, "Connection ID" }},
			{ &hf_yhoo_magic_id, {	
				"Magic ID", "yhoo.magic_id", FT_UINT32, BASE_HEX,
				NULL, 0, "Magic ID" }},
			{ &hf_yhoo_unknown1, {	
				"Unknown 1", "yhoo.unknown1", FT_UINT32, BASE_HEX,
				NULL, 0, "Unknown 1" }},
			{ &hf_yhoo_len, {	
				"Packet Length", "yhoo.len", FT_UINT32, BASE_DEC,
				NULL, 0, "Packet Length" }},
			{ &hf_yhoo_nick1, {	
				"Real Nick (nick1)", "yhoo.nick1", FT_STRING, 0,
				NULL, 0, "Real Nick (nick1)" }},
			{ &hf_yhoo_nick2, {	
				"Active Nick (nick2)", "yhoo.nick2", FT_STRING, 0,
				NULL, 0, "Active Nick (nick2)" }},
			{ &hf_yhoo_content, {	
				"Content", "yhoo.content", FT_STRING, 0,
				NULL, 0, "Data portion of the packet" }},
			{ &hf_yhoo_version, {	
				"Version", "yhoo.version", FT_STRING, 0,
				NULL, 0, "Packet version identifier" }},
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
	heur_dissector_add("tcp", dissect_yhoo, proto_yhoo);
}
