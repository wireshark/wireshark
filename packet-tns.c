/* packet-tns.c
 * Routines for MSX tns packet dissection
 *
 * $Id: packet-tns.c,v 1.1 1999/11/29 19:43:26 nneul Exp $
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
#include "packet-tns.h"

static int proto_tns = -1;
static int hf_tns_request = -1;
static int hf_tns_response = -1;
static int hf_tns_length = -1;
static int hf_tns_packet_checksum = -1;
static int hf_tns_header_checksum = -1;
static int hf_tns_packet_type = -1;
static int hf_tns_reserved_byte = -1;

static gint ett_tns = -1;

static const value_string tns_type_vals[] = {
		{TNS_TYPE_CONNECT, "Connect" },
		{TNS_TYPE_ACCEPT, "Accept" },
		{TNS_TYPE_DATA, "Data" },
		{TNS_TYPE_RESEND, "Resend"},
        {0, NULL}
};


/* Handy macro for checking for truncated packet */
#define TRUNC(length) if ( ! BYTES_ARE_IN_FRAME(offset, length)) { \
			dissect_data(pd,offset,fd,tree); return; }

void dissect_tns_data(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree)
{
	dissect_data(pd,offset,fd,tree);
	return;
}

void dissect_tns_connect(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree)
{
	dissect_data(pd,offset,fd,tree);
	return;
}

void dissect_tns_accept(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree)
{
	dissect_data(pd,offset,fd,tree);
	return;
}


void
dissect_tns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *tns_tree, *ti;
	guint16 length;
	guint16 type;

	if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "TNS");

	if (check_col(fd, COL_INFO))
	{
		col_add_fstr(fd, COL_INFO, "%s", 
			(pi.match_port == pi.destport) ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_tns, offset, END_OF_FRAME, NULL);
		tns_tree = proto_item_add_subtree(ti, ett_tns);

		if (pi.match_port == pi.destport)
		{
			proto_tree_add_item_hidden(tns_tree, hf_tns_request,
			   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tns_tree, offset, 
				END_OF_FRAME, "Request: <opaque data>" );
		}
		else
		{
			proto_tree_add_item_hidden(tns_tree, hf_tns_response,
				offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tns_tree, offset, 
				END_OF_FRAME, "Response: <opaque data>");
		}
	}

		/* check to make sure length is present */
	if ( ! BYTES_ARE_IN_FRAME(offset, 2)) return;

	length = pntohs(&pd[offset]);
	if (tree)
	{
		proto_tree_add_item(tns_tree, hf_tns_length,
			offset, 2, length);
	}
	TRUNC(length);
	offset += 2;

	TRUNC(2);
	if ( tree )
	{
		proto_tree_add_item(tns_tree, hf_tns_packet_checksum,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;

	TRUNC(2);
	type = pd[offset];
	if ( tree )
	{
		proto_tree_add_item(tns_tree, hf_tns_packet_type,
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
		proto_tree_add_item(tns_tree, hf_tns_reserved_byte,
			offset, 1, &pd[offset]);
	}
	offset += 1;

	TRUNC(2);
	if ( tree )
	{
		proto_tree_add_item(tns_tree, hf_tns_header_checksum,
			offset, 2, pntohs(&pd[offset]));
	}
	offset += 2;

	switch (type)
	{
		case TNS_TYPE_CONNECT:
			dissect_tns_connect(pd,offset,fd,tree);
			break;
		case TNS_TYPE_ACCEPT:
			dissect_tns_accept(pd,offset,fd,tree);
			break;
		case TNS_TYPE_DATA:
			dissect_tns_data(pd,offset,fd,tree);
			break;
		default:
			dissect_data(pd,offset,fd,tree);
	}
}

void proto_register_tns(void)
{
	static hf_register_info hf[] = {
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
		{ &hf_tns_reserved_byte, { 	
			"Reserved Byte", "tns.reserved_byte", FT_BYTES, BASE_HEX, 
			NULL, 0x0, "Reserved Byte" }},
		{ &hf_tns_packet_type, { 	
			"Packet Type", "tns.type", FT_UINT8, BASE_NONE, 
			VALS(tns_type_vals), 0x0, "Type of TNS packet" }}	
	};

	static gint *ett[] = {
		&ett_tns,
	};
	proto_tns = proto_register_protocol(
		"Transparent Network Substrate Protocol", "tns");
	proto_register_field_array(proto_tns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
