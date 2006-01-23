/* packet-stun.c
 * Routines for Simple Traversal of UDP Through NAT dissection
 * Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
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
 *
 * Please refer to RFC 3489 for protocol detail.
 * (supports extra message attributes described in draft-ietf-behave-rfc3489bis-00)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_stun = -1;

static int hf_stun_type = -1;		/* STUN message header */
static int hf_stun_length = -1;
static int hf_stun_id = -1;
static int hf_stun_att = -1;

static int stun_att_type = -1;		/* STUN attribute fields */
static int stun_att_length = -1;
static int stun_att_value = -1;
static int stun_att_family = -1;
static int stun_att_ipv4 = -1;
static int stun_att_ipv6 = -1;
static int stun_att_port = -1;
static int stun_att_change_ip = -1;
static int stun_att_change_port = -1;
static int stun_att_unknown = -1;
static int stun_att_error_class = -1;
static int stun_att_error_number = -1;
static int stun_att_error_reason = -1;
static int stun_att_server_string = -1;
static int stun_att_xor_ipv4 = -1;
static int stun_att_xor_ipv6 = -1;
static int stun_att_xor_port = -1;
static int stun_att_lifetime = -1;
static int stun_att_magic_cookie = -1;
static int stun_att_bandwidth = -1;
static int stun_att_data = -1;



/* Message Types */
#define BINDING_REQUEST			0x0001
#define BINDING_RESPONSE		0x0101
#define BINDING_ERROR_RESPONSE		0x0111
#define SHARED_SECRET_REQUEST		0x0002
#define SHARED_SECRET_RESPONSE		0x0102
#define SHARED_SECRET_ERROR_RESPONSE	0x1112
#define ALLOCATE_REQUEST		0x0003
#define ALLOCATE_RESPONSE		0x0103
#define ALLOCATE_ERROR_RESPONSE		0x0113
#define SEND_REQUEST			0x0004
#define SEND_RESPONSE			0x0104
#define SEND_ERROR_RESPONSE		0x0114
#define DATA_INDICATION			0x0115
#define SET_ACTIVE_DESTINATION_REQUEST	0x0006
#define SET_ACTIVE_DESTINATION_RESPONSE	0x0106
#define SET_ACTIVE_DESTINATION_ERROR_RESPONSE	0x0116

/* Attribute Types */
#define MAPPED_ADDRESS		0x0001
#define RESPONSE_ADDRESS	0x0002
#define CHANGE_REQUEST		0x0003
#define SOURCE_ADDRESS		0x0004
#define CHANGED_ADDRESS		0x0005
#define USERNAME		0x0006
#define PASSWORD		0x0007
#define MESSAGE_INTEGRITY	0x0008
#define ERROR_CODE		0x0009
#define UNKNOWN_ATTRIBUTES	0x000a
#define REFLECTED_FROM		0x000b
#define LIFETIME		0x000d
#define ALTERNATE_SERVER	0x000e
#define MAGIC_COOKIE		0x000f
#define BANDWIDTH		0x0010
#define DESTINATION_ADDRESS	0x0011
#define REMOTE_ADDRESS		0x0012
#define DATA			0x0013
#define NONCE			0x0014
#define REALM			0x0015
#define REQUESTED_ADDRESS_TYPE	0x0016
#define XOR_MAPPED_ADDRESS	0x8020
#define XOR_ONLY		0x0021
#define SERVER			0x8022



/* Initialize the subtree pointers */
static gint ett_stun = -1;
static gint ett_stun_att_type = -1;
static gint ett_stun_att = -1;


#define UDP_PORT_STUN 	3478
#define TCP_PORT_STUN	3478


#define STUN_HDR_LEN	20	/* STUN message header length */
#define ATTR_HDR_LEN	4	/* STUN attribute header length */


static const true_false_string set_flag = {
	"SET",
	"NOT SET"
};

static const value_string messages[] = {
	{BINDING_REQUEST, "Binding Request"},
	{BINDING_RESPONSE, "Binding Response"},
	{BINDING_ERROR_RESPONSE, "Binding Error Response"},
	{SHARED_SECRET_REQUEST, "Shared Secret Request"},
	{SHARED_SECRET_RESPONSE, "Shared Secret Response"},
	{SHARED_SECRET_ERROR_RESPONSE, "Shared Secret Error Response"},
	{ALLOCATE_REQUEST, "Allocate Request"},
	{ALLOCATE_RESPONSE, "Allocate Response"},
	{ALLOCATE_ERROR_RESPONSE, "Allocate Error Response"},
	{SEND_REQUEST, "Send Request"},
	{SEND_RESPONSE, "Send Response"},
	{SEND_ERROR_RESPONSE, "Send Error Response"},
	{DATA_INDICATION, "Data Indication"},
	{SET_ACTIVE_DESTINATION_REQUEST, "Set Active Destination Request"},
	{SET_ACTIVE_DESTINATION_RESPONSE, "Set Active Destination Response"},
	{SET_ACTIVE_DESTINATION_ERROR_RESPONSE, "Set Active Destination Error Response"},
	{0x00, NULL}
};

static const value_string attributes[] = {
	{MAPPED_ADDRESS, "MAPPED-ADDRESS"},
	{RESPONSE_ADDRESS, "RESPONSE-ADDRESS"},
	{CHANGE_REQUEST, "CHANGE-REQUEST"},
	{SOURCE_ADDRESS, "SOURCE-ADDRESS"},
	{CHANGED_ADDRESS, "CHANGED-ADDRESS"},
	{USERNAME, "USERNAME"},
	{PASSWORD, "PASSWORD"},
	{MESSAGE_INTEGRITY, "MESSAGE-INTEGRITY"},
	{ERROR_CODE, "ERROR-CODE"},
	{REFLECTED_FROM, "REFLECTED-FROM"},
	{LIFETIME, "LIFETIME"},
	{ALTERNATE_SERVER, "ALTERNATE_SERVER"},
	{MAGIC_COOKIE, "MAGIC_COOKIE"},
	{BANDWIDTH, "BANDWIDTH"},
	{DESTINATION_ADDRESS, "DESTINATION_ADDRESS"},
	{REMOTE_ADDRESS, "REMOTE_ADDRESS"},
	{DATA, "DATA"},
	{NONCE, "NONCE"},
	{REALM, "REALM"},
	{REQUESTED_ADDRESS_TYPE, "REQUESTED_ADDRESS_TYPE"},
	{XOR_MAPPED_ADDRESS, "XOR_MAPPED_ADDRESS"},
	{XOR_ONLY, "XOR_ONLY"},
	{SERVER, "SERVER"},
	{0x00, NULL}
};

static const value_string attributes_family[] = {
	{0x0001, "IPv4"},
	{0x0002, "IPv6"},
	{0x00, NULL}
};

static int
dissect_stun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_item *ti;
	proto_item *ta;
	proto_tree *stun_tree;
	proto_tree *att_type_tree;
	proto_tree *att_tree;
	guint16 msg_type;
	guint16 msg_length;
	const char *msg_type_str;
	guint16 att_type;
	guint16 att_length;
	guint16 offset;
	guint i;

	/*
	 * First check if the frame is really meant for us.
	 */

	/* First, make sure we have enough data to do the check. */
	if (!tvb_bytes_exist(tvb, 0, STUN_HDR_LEN))
		return 0;
	
	msg_type = tvb_get_ntohs(tvb, 0);
	
	/* check if message type is correct */
	msg_type_str = match_strval(msg_type, messages);
	if (msg_type_str == NULL)
		return 0;
	
	msg_length = tvb_get_ntohs(tvb, 2);
	
	/* check if payload enough */
	if (!tvb_bytes_exist(tvb, 0, STUN_HDR_LEN+msg_length))
		return 0;

	/* Check if too much payload */
	if (tvb_bytes_exist(tvb, 0, STUN_HDR_LEN+msg_length+1))
		return 0;

	/* The message seems to be a valid STUN message! */

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "STUN");
    
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Message: %s",
		    msg_type_str);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_stun, tvb, 0, -1, FALSE);
			    
		stun_tree = proto_item_add_subtree(ti, ett_stun);

		proto_tree_add_uint(stun_tree, hf_stun_type, tvb, 0, 2, msg_type);
		proto_tree_add_uint(stun_tree, hf_stun_length, tvb, 2, 2, msg_length);
		proto_tree_add_item(stun_tree, hf_stun_id, tvb, 4, 16, FALSE);

		if (msg_length > 0) {
		    ta = proto_tree_add_item(stun_tree, hf_stun_att, tvb, STUN_HDR_LEN, msg_length, FALSE);
		    att_type_tree = proto_item_add_subtree(ta, ett_stun_att_type);

		    offset = STUN_HDR_LEN;

		    while( msg_length > 0) {
			att_type = tvb_get_ntohs(tvb, offset); /* Type field in attribute header */
			att_length = tvb_get_ntohs(tvb, offset+2); /* Length field in attribute header */
			
			ta = proto_tree_add_text(att_type_tree, tvb, offset,
			    ATTR_HDR_LEN+att_length,
			    "Attribute: %s",
			    val_to_str(att_type, attributes, "Unknown (0x%04x)"));
			att_tree = proto_item_add_subtree(ta, ett_stun_att);
			
			proto_tree_add_uint(att_tree, stun_att_type, tvb,
			    offset, 2, att_type);
			offset += 2;
			if (ATTR_HDR_LEN+att_length > msg_length) {
				proto_tree_add_uint_format(att_tree,
				    stun_att_length, tvb, offset, 2,
				    att_length,
				    "Attribute Length: %u (bogus, goes past the end of the message)",
				    att_length);
				break;
			}
			proto_tree_add_uint(att_tree, stun_att_length, tvb,
			    offset, 2, att_length);
			offset += 2;
			switch( att_type ){
				case MAPPED_ADDRESS:
				case RESPONSE_ADDRESS:
				case SOURCE_ADDRESS:
				case CHANGED_ADDRESS:
				case REFLECTED_FROM:
				case ALTERNATE_SERVER:
				case DESTINATION_ADDRESS:
				case REMOTE_ADDRESS:
					if (att_length < 2)
						break;
					proto_tree_add_item(att_tree, stun_att_family, tvb, offset+1, 1, FALSE);
					if (att_length < 4)
						break;
					proto_tree_add_item(att_tree, stun_att_port, tvb, offset+2, 2, FALSE);
					switch( tvb_get_guint8(tvb, offset+1) ){
						case 1:
							if (att_length < 8)
								break;
							proto_tree_add_item(att_tree, stun_att_ipv4, tvb, offset+4, 4, FALSE);
							break;

						case 2:
							if (att_length < 20)
								break;
							proto_tree_add_item(att_tree, stun_att_ipv6, tvb, offset+4, 16, FALSE);
							break;
						}
					break;
					
				case CHANGE_REQUEST:
					if (att_length < 4)
						break;
					proto_tree_add_item(att_tree, stun_att_change_ip, tvb, offset, 4, FALSE);
					proto_tree_add_item(att_tree, stun_att_change_port, tvb, offset, 4, FALSE);
					break;					
					
				case USERNAME:
				case PASSWORD:
				case MESSAGE_INTEGRITY:
				case NONCE:
				case REALM:
					if (att_length < 1)
						break;
					proto_tree_add_item(att_tree, stun_att_value, tvb, offset, att_length, FALSE);
					break;
					
				case ERROR_CODE:
					if (att_length < 3)
						break;
					proto_tree_add_item(att_tree, stun_att_error_class, tvb, offset+2, 1, FALSE);
					if (att_length < 4)
						break;
					proto_tree_add_item(att_tree, stun_att_error_number, tvb, offset+3, 1, FALSE);
					if (att_length < 5)
						break;
					proto_tree_add_item(att_tree, stun_att_error_reason, tvb, offset+4, (att_length-4), FALSE);
					break;
				
				case LIFETIME:
					if (att_length < 4)
						break;
					proto_tree_add_item(att_tree, stun_att_lifetime, tvb, offset, 4, FALSE);
					break;

				case MAGIC_COOKIE:
					if (att_length < 4)
						break;
					proto_tree_add_item(att_tree, stun_att_magic_cookie, tvb, offset, 4, FALSE);
					break;

				case BANDWIDTH:
					if (att_length < 4)
						break;
					proto_tree_add_item(att_tree, stun_att_bandwidth, tvb, offset, 4, FALSE);
					break;

				case DATA:
					proto_tree_add_item(att_tree, stun_att_data, tvb, offset, att_length, FALSE);
					break;

				case UNKNOWN_ATTRIBUTES:
					for (i = 0; i < att_length; i += 4) {
						proto_tree_add_item(att_tree, stun_att_unknown, tvb, offset+i, 2, FALSE);
						proto_tree_add_item(att_tree, stun_att_unknown, tvb, offset+i+2, 2, FALSE);
					}
					break;
					
				case SERVER:
					proto_tree_add_item(att_tree, stun_att_server_string, tvb, offset, att_length, FALSE);
					break;

				case XOR_MAPPED_ADDRESS:
					if (att_length < 2)
						break;
					proto_tree_add_item(att_tree, stun_att_family, tvb, offset+1, 1, FALSE);
					if (att_length < 4)
						break;
					proto_tree_add_item(att_tree, stun_att_xor_port, tvb, offset+2, 2, FALSE);
					if (att_length < 8)
						break;
					switch( tvb_get_guint8(tvb, offset+1) ){
						case 1:
							if (att_length < 8)
								break;
							proto_tree_add_item(att_tree, stun_att_xor_ipv4, tvb, offset+4, 4, FALSE);
							break;

						case 2:
							if (att_length < 20)
								break;
							proto_tree_add_item(att_tree, stun_att_xor_ipv6, tvb, offset+4, 16, FALSE);
							break;
						}
					break;

				case REQUESTED_ADDRESS_TYPE:
					if (att_length < 2)
						break;
					proto_tree_add_item(att_tree, stun_att_family, tvb, offset+1, 1, FALSE);
					break;

				default:
					break;
			}
			offset += att_length;
			msg_length -= ATTR_HDR_LEN+att_length;
		    }
		}
	}
	return tvb_length(tvb);
}


static gboolean
dissect_stun_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (dissect_stun(tvb, pinfo, tree) == 0)
		return FALSE;

	return TRUE;
}




void
proto_register_stun(void)
{
	static hf_register_info hf[] = {
		{ &hf_stun_type,
			{ "Message Type",	"stun.type", 	FT_UINT16, 
			BASE_HEX, 	VALS(messages),	0x0, 	"", 	HFILL }
		},
		{ &hf_stun_length,
			{ "Message Length",	"stun.length",	FT_UINT16, 
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun_id,
			{ "Message Transaction ID",	"stun.id",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun_att,
			{ "Attributes",		"stun.att",	FT_NONE,
			0, 		NULL, 	0x0, 	"",	HFILL }
		},
		/* ////////////////////////////////////// */
		{ &stun_att_type,
			{ "Attribute Type",	"stun.att.type",	FT_UINT16,
			BASE_HEX,	VALS(attributes),	0x0, 	"",	HFILL }
		},
		{ &stun_att_length,
			{ "Attribute Length",	"stun.att.length",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_value,
			{ "Value",	"stun.att.value",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_family,
			{ "Protocol Family",	"stun.att.family",	FT_UINT16,
			BASE_HEX,	VALS(attributes_family),	0x0, 	"",	HFILL }
		},
		{ &stun_att_ipv4,
			{ "IP",		"stun.att.ipv4",	FT_IPv4,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_ipv6,
			{ "IP",		"stun.att.ipv6",	FT_IPv6,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_port,
			{ "Port",	"stun.att.port",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_change_ip,
			{ "Change IP","stun.att.change.ip",	FT_BOOLEAN,
			16, 	TFS(&set_flag),	0x0004,	"",	HFILL}
		},
		{ &stun_att_change_port,
			{ "Change Port","stun.att.change.port",	FT_BOOLEAN,
			16, 	TFS(&set_flag),	0x0002,	"",	HFILL}
		},		
		{ &stun_att_unknown,
			{ "Unknown Attribute","stun.att.unknown",	FT_UINT16,
			BASE_HEX, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun_att_error_class,
			{ "Error Class","stun.att.error.class",	FT_UINT8,
			BASE_DEC, 	NULL,	0x07,	"",	HFILL}
		},
		{ &stun_att_error_number,
			{ "Error Code","stun.att.error",	FT_UINT8,
			BASE_DEC, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun_att_error_reason,
			{ "Error Reason Phase","stun.att.error.reason",	FT_STRING,
			BASE_NONE, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun_att_xor_ipv4,
			{ "IP (XOR-d)",		"stun.att.ipv4-xord",	FT_IPv4,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_xor_ipv6,
			{ "IP (XOR-d)",		"stun.att.ipv6-xord",	FT_IPv6,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_xor_port,
			{ "Port (XOR-d)",	"stun.att.port-xord",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_server_string,
			{ "Server version","stun.att.server",	FT_STRING,
			BASE_NONE, 	NULL,	0x0,	"",	HFILL}
 		},
		{ &stun_att_lifetime,
			{ "Lifetime",	"stun.att.lifetime",	FT_UINT32,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_magic_cookie,
			{ "Magic Cookie",	"stun.att.magic.cookie",	FT_UINT32,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_bandwidth,
			{ "Bandwidth",	"stun.att.bandwidth",	FT_UINT32,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_data,
			{ "Data",	"stun.att.data",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_stun,
		&ett_stun_att_type,
		&ett_stun_att,
	};

/* Register the protocol name and description */
	proto_stun = proto_register_protocol("Simple Traversal of UDP Through NAT",
	    "STUN", "stun");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_stun, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	new_register_dissector("stun", dissect_stun, proto_stun);
}


void
proto_reg_handoff_stun(void)
{
	dissector_handle_t stun_handle;

	stun_handle = find_dissector("stun");

	dissector_add("tcp.port", TCP_PORT_STUN, stun_handle);
	dissector_add("udp.port", UDP_PORT_STUN, stun_handle);

	heur_dissector_add("udp", dissect_stun_heur, proto_stun);
	heur_dissector_add("tcp", dissect_stun_heur, proto_stun);
}
