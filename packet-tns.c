/* packet-tns.c
 * Routines for MSX tns packet dissection
 *
 * $Id: packet-tns.c,v 1.10 2000/11/19 08:54:10 guy Exp $
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
#include "packet-tns.h"

static int proto_tns = -1;
static int hf_tns_request = -1;
static int hf_tns_response = -1;
static int hf_tns_length = -1;
static int hf_tns_packet_checksum = -1;
static int hf_tns_header_checksum = -1;
static int hf_tns_packet_type = -1;
static int hf_tns_reserved_byte = -1;
static int hf_tns_data_flag = -1;
static int hf_tns_sns = -1;
static int hf_tns_connect = -1;
static int hf_tns_version = -1;
static int hf_tns_compat_version = -1;
static int hf_tns_service_options = -1;

static gint ett_tns = -1;
static gint ett_tns_sns = -1;
static gint ett_tns_connect = -1;
static gint ett_sql = -1;

#define TCP_PORT_TNS			1521

static const value_string tns_type_vals[] = {
		{TNS_TYPE_CONNECT, "Connect" },
		{TNS_TYPE_ACCEPT, "Accept" },
		{TNS_TYPE_DATA, "Data" },
		{TNS_TYPE_RESEND, "Resend"},
	        {0, NULL}
};


/* Handy macro for checking for truncated packet */
#define TRUNC(length) if ( ! BYTES_ARE_IN_FRAME(offset, length)) { \
			old_dissect_data(pd,offset,fd,tree); return; }

static void dissect_tns_sns(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, proto_tree *tns_tree)
{
	proto_tree *sns_tree = NULL, *ti;

	if ( tree )
	{
		ti = proto_tree_add_text(tns_tree, NullTVB, offset, END_OF_FRAME, "Secure Network Services");
		sns_tree = proto_item_add_subtree(ti, ett_tns_sns);

		proto_tree_add_boolean_hidden(tns_tree, hf_tns_sns, NullTVB, 0, 0, TRUE);
	}
		
	if ( check_col(fd, COL_INFO) )
	{
		col_append_fstr(fd, COL_INFO, ", SNS");
	}

	if ( sns_tree )
	{
		old_dissect_data(pd,offset,fd,sns_tree);
	}
}

static void dissect_tns_data(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, proto_tree *tns_tree)
{

	TRUNC(2);
	if ( tree )
	{
		proto_tree_add_uint(tns_tree, hf_tns_data_flag, NullTVB,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;

	if ( BYTES_ARE_IN_FRAME(offset, 4) )
	{
		if ( pd[offset] == 0xDE && pd[offset+1] == 0xAD &&
			pd[offset+2] == 0xBE && pd[offset+3] == 0xEF )
		{
			dissect_tns_sns(pd,offset,fd,tree,tns_tree);
			return;
		}
	}
	
	old_dissect_data(pd,offset,fd,tree);
	return;
}

static void dissect_tns_connect(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, proto_tree *tns_tree)
{
	proto_tree *connect_tree = NULL, *ti;

	if ( tree )
	{
		ti = proto_tree_add_text(tns_tree, NullTVB, offset, END_OF_FRAME, "Connect");
		connect_tree = proto_item_add_subtree(ti, ett_tns_connect);

		proto_tree_add_boolean_hidden(tns_tree, hf_tns_connect, NullTVB, 0, 0, TRUE);
	}
		
	if ( check_col(fd, COL_INFO) )
	{
		col_append_fstr(fd, COL_INFO, ", Connect");
	}

	TRUNC(2);
	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_version, NullTVB,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;
	
	TRUNC(2);
	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_compat_version, NullTVB,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;

	TRUNC(2);
	if ( connect_tree )
	{
		/* need to break down w/ bitfield */
		proto_tree_add_uint(connect_tree, hf_tns_service_options, NullTVB,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;

	if ( connect_tree )
	{
		old_dissect_data(pd,offset,fd,connect_tree);
	}
	return;
}

static void dissect_tns_accept(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, proto_tree *tns_tree)
{
	old_dissect_data(pd,offset,fd,tns_tree);
	return;
}


static void
dissect_tns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *tns_tree = NULL, *ti;
	guint16 length;
	guint16 type;

	OLD_CHECK_DISPLAY_AS_DATA(proto_tns, pd, offset, fd, tree);

	if (check_col(fd, COL_PROTOCOL))
		col_set_str(fd, COL_PROTOCOL, "TNS");

	if (check_col(fd, COL_INFO))
	{
		col_add_fstr(fd, COL_INFO, "%s", 
			(pi.match_port == pi.destport) ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_tns, NullTVB, offset, END_OF_FRAME, FALSE);
		tns_tree = proto_item_add_subtree(ti, ett_tns);

		if (pi.match_port == pi.destport)
		{
			proto_tree_add_boolean_hidden(tns_tree, hf_tns_request, NullTVB,
			   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tns_tree, NullTVB, offset, 
				END_OF_FRAME, "Request: <opaque data>" );
		}
		else
		{
			proto_tree_add_boolean_hidden(tns_tree, hf_tns_response, NullTVB,
				offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tns_tree, NullTVB, offset, 
				END_OF_FRAME, "Response: <opaque data>");
		}
	}

		/* check to make sure length is present */
	if ( ! BYTES_ARE_IN_FRAME(offset, 2)) return;

	length = pntohs(&pd[offset]);
	if (tree)
	{
		proto_tree_add_uint(tns_tree, hf_tns_length, NullTVB,
			offset, 2, length);
	}
	TRUNC(length);
	offset += 2;

	TRUNC(2);
	if ( tree )
	{
		proto_tree_add_uint(tns_tree, hf_tns_packet_checksum, NullTVB,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;

	TRUNC(2);
	type = pd[offset];
	if ( tree )
	{
		proto_tree_add_uint(tns_tree, hf_tns_packet_type, NullTVB,
			offset, 1, type);
	}
	offset += 1;

	if ( check_col(fd, COL_INFO))
	{
		col_append_fstr(fd, COL_INFO, ", %s (%d)",
			val_to_str(type, tns_type_vals, "Unknown"), type);
	}

	TRUNC(1);
	if ( tree )
	{
		proto_tree_add_bytes(tns_tree, hf_tns_reserved_byte, NullTVB,
			offset, 1, &pd[offset]);
	}
	offset += 1;

	TRUNC(2);
	if ( tree )
	{
		proto_tree_add_uint(tns_tree, hf_tns_header_checksum, NullTVB,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;

	switch (type)
	{
		case TNS_TYPE_CONNECT:
			dissect_tns_connect(pd,offset,fd,tree,tns_tree);
			break;
		case TNS_TYPE_ACCEPT:
			dissect_tns_accept(pd,offset,fd,tree,tns_tree);
			break;
		case TNS_TYPE_DATA:
			dissect_tns_data(pd,offset,fd,tree,tns_tree);
			break;
		default:
			old_dissect_data(pd,offset,fd,tns_tree);
	}
}

void proto_register_tns(void)
{
	static hf_register_info hf[] = {
		{ &hf_tns_sns, { 
			"Secure Network Services", "tns.sns", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "Secure Network Services" }},
		{ &hf_tns_connect, { 
			"Connect", "tns.connect", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "Connect" }},
		{ &hf_tns_response, { 
			"Response", "tns.response", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "TRUE if TNS response" }},
		{ &hf_tns_request, { 
			"Request", "tns.request", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "TRUE if TNS request" }},
		{ &hf_tns_length, { 	
			"Packet Length", "tns.length", FT_UINT32, BASE_NONE, 
			NULL, 0x0, "Length of TNS packet" }},
		{ &hf_tns_packet_checksum, { 	
			"Packet Checksum", "tns.packet_checksum", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Checksum of Packet Data" }},
		{ &hf_tns_header_checksum, { 	
			"Header Checksum", "tns.header_checksum", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Checksum of Header Data" }},
		{ &hf_tns_data_flag, { 	
			"Data Flag", "tns.data_flag", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Data Flag" }},
		{ &hf_tns_version, { 	
			"Version", "tns.version", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Version" }},
		{ &hf_tns_compat_version, { 	
			"Version (Compatible)", "tns.compat_version", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Version (Compatible)" }},
		{ &hf_tns_service_options, { 	
			"Service Options", "tns.service_options", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Service Options" }},
		{ &hf_tns_reserved_byte, { 	
			"Reserved Byte", "tns.reserved_byte", FT_BYTES, BASE_HEX, 
			NULL, 0x0, "Reserved Byte" }},
		{ &hf_tns_packet_type, { 	
			"Packet Type", "tns.type", FT_UINT8, BASE_NONE, 
			VALS(tns_type_vals), 0x0, "Type of TNS packet" }}	
	};

	static gint *ett[] = {
		&ett_tns,
		&ett_tns_sns,
		&ett_tns_connect,
		&ett_sql
	};
	proto_tns = proto_register_protocol(
		"Transparent Network Substrate Protocol", "tns");
	proto_register_field_array(proto_tns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tns(void)
{
	old_dissector_add("tcp.port", TCP_PORT_TNS, dissect_tns);
}
