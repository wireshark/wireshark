/* packet-tns.c
 * Routines for Oracle TNS packet dissection
 *
 * $Id: packet-tns.c,v 1.18 2001/10/06 15:45:38 nneul Exp $
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
static int hf_tns_sdu_size = -1;
static int hf_tns_max_tdu_size = -1;
static int hf_tns_nt_proto_characteristics = -1;
static int hf_tns_line_turnaround = -1;
static int hf_tns_value_of_one = -1;
static int hf_tns_connect_data_length = -1;
static int hf_tns_connect_data_offset = -1;
static int hf_tns_connect_data_max = -1;
static int hf_tns_connect_flags0 = -1;
static int hf_tns_connect_flags1 = -1;
static int hf_tns_connect_data = -1;
static int hf_tns_trace_cf1 = -1;
static int hf_tns_trace_cf2 = -1;
static int hf_tns_trace_cid = -1;

static gint ett_tns = -1;
static gint ett_tns_sns = -1;
static gint ett_tns_connect = -1;
static gint ett_tns_accept = -1;
static gint ett_sql = -1;

#define TCP_PORT_TNS			1521

static const value_string tns_type_vals[] = {
		{TNS_TYPE_CONNECT,   "Connect" },
		{TNS_TYPE_ACCEPT,    "Accept" },
		{TNS_TYPE_ACK,       "Acknowledge" },
		{TNS_TYPE_REFUSE,    "Refuse" },
		{TNS_TYPE_REDIRECT,  "Redirect" },
		{TNS_TYPE_DATA,      "Data" },
		{TNS_TYPE_NULL,      "Null" },
		{TNS_TYPE_ABORT,     "Abort" },
		{TNS_TYPE_RESEND,    "Resend"},
		{TNS_TYPE_MARKER,    "Marker"},
		{TNS_TYPE_ATTENTION, "Attention"},
		{TNS_TYPE_CONTROL,   "Control"},
		{0, NULL}
};


static void dissect_tns_sns(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, proto_tree *tns_tree)
{
	proto_tree *sns_tree = NULL, *ti;

	if ( tree )
	{
		ti = proto_tree_add_text(tns_tree, tvb, offset,
		    tvb_length_remaining(tvb, offset), "Secure Network Services");
		sns_tree = proto_item_add_subtree(ti, ett_tns_sns);

		proto_tree_add_boolean_hidden(tns_tree, hf_tns_sns, tvb, 0, 0,
		    TRUE);
	}

	if ( check_col(pinfo->fd, COL_INFO) )
	{
		col_append_fstr(pinfo->fd, COL_INFO, ", SNS");
	}

	if ( sns_tree )
	{
		dissect_data(tvb,offset,pinfo,sns_tree);
	}
}

static void dissect_tns_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, proto_tree *tns_tree)
{

	if ( tree )
	{
		proto_tree_add_uint(tns_tree, hf_tns_data_flag, tvb,
			offset, 2, FALSE);
	}
	offset += 2;

	if ( tvb_bytes_exist(tvb, offset, 4) )
	{
		if ( tvb_get_guint8(tvb, offset) == 0xDE &&
		     tvb_get_guint8(tvb, offset+1) == 0xAD &&
		     tvb_get_guint8(tvb, offset+2) == 0xBE &&
		     tvb_get_guint8(tvb, offset+3) == 0xEF )
		{
			dissect_tns_sns(tvb,offset,pinfo,tree,tns_tree);
			return;
		}
	}
	
	dissect_data(tvb,offset,pinfo,tree);
	return;
}

static void dissect_tns_connect(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, proto_tree *tns_tree)
{
	proto_tree *connect_tree = NULL, *ti;
	int cd_offset;
	int cd_len;
	int tns_offset = offset-8;

	if ( tree )
	{
		ti = proto_tree_add_text(tns_tree, tvb, offset,
		    tvb_length_remaining(tvb, offset), "Connect");
		connect_tree = proto_item_add_subtree(ti, ett_tns_connect);

		proto_tree_add_boolean_hidden(tns_tree, hf_tns_connect, tvb,
		    0, 0, TRUE);
	}
		
	if ( check_col(pinfo->fd, COL_INFO) )
	{
		col_append_str(pinfo->fd, COL_INFO, ", Connect");
	}

	if ( connect_tree )
	{
		proto_tree_add_item(connect_tree, hf_tns_version, tvb,
			offset, 2, FALSE);
	}
	offset += 2;
	
	if ( connect_tree )
	{
		proto_tree_add_item(connect_tree, hf_tns_compat_version, tvb,
			offset, 2, FALSE);
	}
	offset += 2;

	if ( connect_tree )
	{
		/* need to break down w/ bitfield */
		proto_tree_add_uint(connect_tree, hf_tns_service_options, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_sdu_size, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_max_tdu_size, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_nt_proto_characteristics, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_line_turnaround, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_bytes(connect_tree, hf_tns_value_of_one, tvb,
			offset, 2, tvb_get_ptr(tvb, offset, 2));
	}
	offset += 2;

	cd_len = tvb_get_ntohs(tvb, offset);
	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_data_length, tvb,
			offset, 2, cd_len);
	}
	offset += 2;

	cd_offset = tvb_get_ntohs(tvb, offset);
	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_data_offset, tvb,
			offset, 2, cd_offset);
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_data_max, tvb,
			offset, 4, tvb_get_ntohl(tvb, offset));
	}
	offset += 4;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_flags0, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_flags1, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_trace_cf1, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_trace_cf2, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_trace_cid, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree && cd_len > 0)
	{
		proto_tree_add_string(connect_tree, hf_tns_connect_data, tvb,
			tns_offset+cd_offset, tvb_length(tvb)-(tns_offset+cd_offset), 
			tvb_get_ptr(tvb, tns_offset+cd_offset,
			tvb_length(tvb)-(tns_offset+cd_offset)));
	}
	return;
}

static void dissect_tns_accept(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, proto_tree *tns_tree)
{
	proto_tree *connect_tree = NULL, *ti;
	int cd_offset;
	int cd_len;
	int tns_offset = offset-8;

	if ( tree )
	{
		ti = proto_tree_add_text(tns_tree, tvb, offset,
		    tvb_length_remaining(tvb, offset), "Accept");
		connect_tree = proto_item_add_subtree(ti, ett_tns_accept);

		proto_tree_add_boolean_hidden(tns_tree, hf_tns_connect, tvb,
		    0, 0, TRUE);
	}
		
	if ( check_col(pinfo->fd, COL_INFO) )
	{
		col_append_str(pinfo->fd, COL_INFO, ", Accept");
	}

	if ( connect_tree )
	{
		proto_tree_add_item(connect_tree, hf_tns_version, tvb,
			offset, 2, FALSE);
	}
	offset += 2;
	
	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_service_options, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_sdu_size, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_max_tdu_size, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_bytes(connect_tree, hf_tns_value_of_one, tvb,
			offset, 2, tvb_get_ptr(tvb, offset, 2));
	}
	offset += 2;

	cd_len = tvb_get_ntohs(tvb, offset);
	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_data_length, tvb,
			offset, 2, cd_len);
	}
	offset += 2;

	cd_offset = tvb_get_ntohs(tvb, offset);
	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_data_offset, tvb,
			offset, 2, cd_offset);
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_flags0, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree )
	{
		proto_tree_add_uint(connect_tree, hf_tns_connect_flags1, tvb,
			offset, 2, tvb_get_ntohs(tvb, offset));
	}
	offset += 2;

	if ( connect_tree && cd_len > 0)
	{
		proto_tree_add_string(connect_tree, hf_tns_connect_data, tvb,
			tns_offset+cd_offset, tvb_length(tvb)-(tns_offset+cd_offset), 
			tvb_get_ptr(tvb, tns_offset+cd_offset,
			tvb_length(tvb)-(tns_offset+cd_offset)));
	}
	return;
}


static void
dissect_tns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *tns_tree = NULL, *ti;
	int offset = 0;
	guint16 length;
	guint16 type;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "TNS");

	if (check_col(pinfo->fd, COL_INFO))
	{
		col_add_str(pinfo->fd, COL_INFO,
			(pinfo->match_port == pinfo->destport) ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_tns, tvb, 0,
		    tvb_length(tvb), FALSE);
		tns_tree = proto_item_add_subtree(ti, ett_tns);

		if (pinfo->match_port == pinfo->destport)
		{
			proto_tree_add_boolean_hidden(tns_tree, hf_tns_request,
			   tvb, offset, tvb_length(tvb), TRUE);
			proto_tree_add_text(tns_tree, tvb, offset, 
			    tvb_length(tvb), "Request: <opaque data>");
		}
		else
		{
			proto_tree_add_boolean_hidden(tns_tree, hf_tns_response,
			    tvb, offset, tvb_length(tvb), TRUE);
			proto_tree_add_text(tns_tree, tvb, offset,
			    tvb_length(tvb), "Response: <opaque data>");
		}
	}

	length = tvb_get_ntohs(tvb, offset);
	if (tree)
	{
		proto_tree_add_uint(tns_tree, hf_tns_length, tvb,
			offset, 2, length);
	}
	offset += 2;

	if ( tree )
	{
		proto_tree_add_item(tns_tree, hf_tns_packet_checksum, tvb,
			offset, 2, FALSE);
	}
	offset += 2;

	type = tvb_get_guint8(tvb, offset);
	if ( tree )
	{
		proto_tree_add_uint(tns_tree, hf_tns_packet_type, tvb,
			offset, 1, type);
	}
	offset += 1;

	if ( check_col(pinfo->fd, COL_INFO))
	{
		col_append_fstr(pinfo->fd, COL_INFO, ", %s (%u)",
			val_to_str(type, tns_type_vals, "Unknown"), type);
	}

	if ( tree )
	{
		proto_tree_add_item(tns_tree, hf_tns_reserved_byte, tvb,
			offset, 1, FALSE);
	}
	offset += 1;

	if ( tree )
	{
		proto_tree_add_item(tns_tree, hf_tns_header_checksum, tvb,
			offset, 2, FALSE);
	}
	offset += 2;

	switch (type)
	{
		case TNS_TYPE_CONNECT:
			dissect_tns_connect(tvb,offset,pinfo,tree,tns_tree);
			break;
		case TNS_TYPE_ACCEPT:
			dissect_tns_accept(tvb,offset,pinfo,tree,tns_tree);
			break;
		case TNS_TYPE_DATA:
			dissect_tns_data(tvb,offset,pinfo,tree,tns_tree);
			break;
		default:
			dissect_data(tvb,offset,pinfo,tns_tree);
	}
}

void proto_register_tns(void)
{
	static hf_register_info hf[] = {
		{ &hf_tns_sns, { 
			"Secure Network Services", "tns.sns", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "Secure Network Services", HFILL }},
		{ &hf_tns_connect, { 
			"Connect", "tns.connect", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "Connect", HFILL }},
		{ &hf_tns_response, { 
			"Response", "tns.response", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "TRUE if TNS response", HFILL }},
		{ &hf_tns_request, { 
			"Request", "tns.request", FT_BOOLEAN, BASE_NONE, 
			NULL, 0x0, "TRUE if TNS request", HFILL }},
		{ &hf_tns_length, { 	
			"Packet Length", "tns.length", FT_UINT32, BASE_DEC, 
			NULL, 0x0, "Length of TNS packet", HFILL }},
		{ &hf_tns_packet_checksum, { 	
			"Packet Checksum", "tns.packet_checksum", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Checksum of Packet Data", HFILL }},
		{ &hf_tns_header_checksum, { 	
			"Header Checksum", "tns.header_checksum", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Checksum of Header Data", HFILL }},
		{ &hf_tns_data_flag, { 	
			"Data Flag", "tns.data_flag", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Data Flag", HFILL }},
		{ &hf_tns_version, { 	
			"Version", "tns.version", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Version", HFILL }},
		{ &hf_tns_compat_version, { 	
			"Version (Compatible)", "tns.compat_version", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Version (Compatible)", HFILL }},
		{ &hf_tns_service_options, { 	
			"Service Options", "tns.service_options", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Service Options", HFILL }},
		{ &hf_tns_sdu_size, { 	
			"Session Data Unit Size", "tns.sdu_size", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Session Data Unit Size", HFILL }},
		{ &hf_tns_max_tdu_size, { 	
			"Maximum Transmission Data Unit Size", "tns.max_tdu_size", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Maximum Transmission Data Unit Size", HFILL }},
		{ &hf_tns_nt_proto_characteristics, { 	
			"NT Protocol Characteristics", "tns.nt_proto_characteristics", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "NT Protocol Characteristics", HFILL }},
		{ &hf_tns_line_turnaround, { 	
			"Line Turnaround Value", "tns.line_turnaround", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Line Turnaround Value", HFILL }},
		{ &hf_tns_value_of_one, { 	
			"Value of 1 in Hardware", "tns.value_of_one", FT_BYTES, BASE_NONE, 
			NULL, 0x0, "Value of 1 in Hardware", HFILL }},		
		{ &hf_tns_connect_data_length, { 	
			"Length of Connect Data", "tns.connect_data_length", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Length of Connect Data", HFILL }},
		{ &hf_tns_connect_data_offset, { 	
			"Offset to Connect Data", "tns.connect_data_offset", FT_UINT16, BASE_DEC, 
			NULL, 0x0, "Offset to Connect Data", HFILL }},
		{ &hf_tns_connect_data_max, { 	
			"Maximum Receivable Connect Data", "tns.connect_data_max", FT_UINT32, BASE_DEC, 
			NULL, 0x0, "Maximum Receivable Connect Data", HFILL }},
		{ &hf_tns_connect_flags0, { 	
			"Connect Flags 0", "tns.connect_flags0", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Connect Flags 0", HFILL }},
		{ &hf_tns_connect_flags1, { 	
			"Connect Flags 1", "tns.connect_flags1", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Connect Flags 1", HFILL }},
		{ &hf_tns_trace_cf1, { 	
			"Trace Cross Facility Item 1", "tns.trace_cf1", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Trace Cross Facility Item 1", HFILL }},
		{ &hf_tns_trace_cf2, { 	
			"Trace Cross Facility Item 2", "tns.trace_cf2", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Trace Cross Facility Item 2", HFILL }},
		{ &hf_tns_trace_cid, { 	
			"Trace Unique Connection ID", "tns.trace_cid", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "Trace Unique Connection ID", HFILL }},
		{ &hf_tns_connect_data, { 	
			"Connect Data", "tns.connect_data", FT_STRING, BASE_NONE, 
			NULL, 0x0, "Connect Data", HFILL }},
		{ &hf_tns_reserved_byte, { 	
			"Reserved Byte", "tns.reserved_byte", FT_BYTES, BASE_HEX, 
			NULL, 0x0, "Reserved Byte", HFILL }},
		{ &hf_tns_packet_type, { 	
			"Packet Type", "tns.type", FT_UINT8, BASE_DEC, 
			VALS(tns_type_vals), 0x0, "Type of TNS packet", HFILL }}	
	};

	static gint *ett[] = {
		&ett_tns,
		&ett_tns_sns,
		&ett_tns_connect,
		&ett_tns_accept,
		&ett_sql
	};
	proto_tns = proto_register_protocol(
		"Transparent Network Substrate Protocol", "TNS", "tns");
	proto_register_field_array(proto_tns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tns(void)
{
	dissector_add("tcp.port", TCP_PORT_TNS, dissect_tns, proto_tns);
}
