/* packet-yhoo.c
 * Routines for yahoo messenger packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id: packet-yhoo.c,v 1.4 1999/11/16 11:43:03 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

void
dissect_yhoo(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *yhoo_tree, *ti;
	struct yahoo_rawpacket *pkt;

	/* get at least a full packet structure */
	if ( !BYTES_ARE_IN_FRAME(offset, sizeof(struct yahoo_rawpacket)) )
		return;

	pkt = (struct yahoo_rawpacket *) &pd[offset];
	
	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "YHOO");

	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, 
			"%s: %s", 
			( strncmp(pkt->version, "YPNS", 4) == 0 ) ? "Request" : "Response",
			val_to_str(pletohl(pkt->service),
				 yhoo_service_vals, "Unknown Service: %u")
		);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_yhoo, offset, END_OF_FRAME, NULL);
		yhoo_tree = proto_item_add_subtree(ti, ett_yhoo);

		proto_tree_add_item(yhoo_tree, hf_yhoo_version, 
			offset, 8, pkt->version);
		proto_tree_add_item(yhoo_tree, hf_yhoo_len, 
			offset+8, 4, pletohl(pkt->len));
		proto_tree_add_item(yhoo_tree, hf_yhoo_service, 
			offset+12, 4, pletohl(pkt->service));
		proto_tree_add_item(yhoo_tree, hf_yhoo_connection_id, 
			offset+16, 4, pletohl(pkt->connection_id));
		proto_tree_add_item(yhoo_tree, hf_yhoo_magic_id, 
			offset+20, 4, pletohl(pkt->magic_id));
		proto_tree_add_item(yhoo_tree, hf_yhoo_unknown1, 
			offset+24, 4, pletohl(pkt->unknown1));
		proto_tree_add_item(yhoo_tree, hf_yhoo_msgtype, 
			offset+28, 4, pletohl(pkt->msgtype));
		proto_tree_add_item(yhoo_tree, hf_yhoo_nick1, 
			offset+32, 36, pkt->nick1);
		proto_tree_add_item(yhoo_tree, hf_yhoo_nick2, 
			offset+68, 36, pkt->nick2);
		proto_tree_add_item(yhoo_tree, hf_yhoo_content, 
			offset+104, END_OF_FRAME, pkt->content);
	}
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

	proto_yhoo = proto_register_protocol("Yahoo Messenger Protocol", "yhoo");

	proto_register_field_array(proto_yhoo, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}
