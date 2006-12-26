/* packet-stun2.c
 * Routines for Simple Traversal Underneath NAT dissection
 * Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
 * Copyright 2006, Marc Petit-Huguenin <marc@petit-huguenin.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Please refer to draft-ietf-behave-rfc3489bis-05 for protocol detail.
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
static int proto_stun2 = -1;

static int hf_stun2_class = -1;
static int hf_stun2_method = -1;
static int hf_stun2_length = -1;
static int hf_stun2_cookie = -1;
static int hf_stun2_id = -1;
static int hf_stun2_att = -1;

static int stun2_att_type = -1;		/* STUN2 attribute fields */
static int stun2_att_length = -1;
static int stun2_att_family = -1;
static int stun2_att_ipv4 = -1;
static int stun2_att_ipv6 = -1;
static int stun2_att_port = -1;
static int stun2_att_username = -1;
static int stun2_att_padding = -1;
static int stun2_att_password = -1;
static int stun2_att_hmac = -1;
static int stun2_att_crc32 = -1;
static int stun2_att_error_class = -1;
static int stun2_att_error_number = -1;
static int stun2_att_error_reason = -1;
static int stun2_att_realm = -1;
static int stun2_att_nonce = -1;
static int stun2_att_unknown = -1;
static int stun2_att_xor_ipv4 = -1;
static int stun2_att_xor_ipv6 = -1;
static int stun2_att_xor_port = -1;
static int stun2_att_server = -1;
static int stun2_att_refresh_interval = -1;
static int stun2_att_value = -1;

/* Message classes */
#define CLASS_MASK	0xC110
#define REQUEST		0x0000
#define INDICATION	0x0001
#define RESPONSE	0x0010
#define STUN2_ERROR	0x0011  /* use prefix to prevent redefinition from wingdi.h */

/* Message methods */
#define METHOD_MASK	0xCEEF
#define BINDING		0x0001
#define SHARED_SECRET	0x0002

/* Attribute Types */
#define MAPPED_ADDRESS		0x0001
#define USERNAME		0x0006
#define PASSWORD		0x0007
#define MESSAGE_INTEGRITY	0x0008
#define ERROR_CODE		0x0009
#define UNKNOWN_ATTRIBUTES	0x000a
#define REALM			0x0014
#define NONCE			0x0015
#define XOR_MAPPED_ADDRESS	0x0020
#define SERVER			0x8022
#define ALTERNATE_SERVER	0x8023
#define REFRESH_INTERVAL	0x8024
#define FINGERPRINT		0x8025

/* Initialize the subtree pointers */
static gint ett_stun2 = -1;
static gint ett_stun2_att_type = -1;
static gint ett_stun2_att = -1;

#define UDP_PORT_STUN2 	3478
#define TCP_PORT_STUN2	3478

#define STUN2_HDR_LEN	20	/* STUN2 message header length */
#define ATTR_HDR_LEN	4	/* STUN2 attribute header length */


static const value_string classes[] = {
	{REQUEST, "Request"},
	{INDICATION, "Indication"},
	{RESPONSE, "Response"},
	{STUN2_ERROR, "Error Response"},
	{0x00, NULL}
};

static const value_string methods[] = {
	{BINDING, "Binding"},
	{SHARED_SECRET, "Shared Secret"},
	{0x00, NULL}
};

static const value_string attributes[] = {
	{MAPPED_ADDRESS, "MAPPED-ADDRESS"},
	{USERNAME, "USERNAME"},
	{PASSWORD, "PASSWORD"},
	{MESSAGE_INTEGRITY, "MESSAGE-INTEGRITY"},
	{ERROR_CODE, "ERROR-CODE"},
	{UNKNOWN_ATTRIBUTES, "UNKNOWN-ATTRIBUTES"},
	{REALM, "REALM"},
	{NONCE, "NONCE"},
	{XOR_MAPPED_ADDRESS, "XOR-MAPPED-ADDRESS"},
	{SERVER, "SERVER"},
	{ALTERNATE_SERVER, "ALTERNATE-SERVER"},
	{REFRESH_INTERVAL, "REFRESH-INTERVAL"},
	{FINGERPRINT, "FINGERPRINT"},
	{0x00, NULL}
};

static const value_string attributes_family[] = {
	{0x0001, "IPv4"},
	{0x0002, "IPv6"},
	{0x00, NULL}
};

static int
dissect_stun2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_item *ta;
	proto_tree *stun2_tree;
	proto_tree *att_type_tree;
	proto_tree *att_tree;
	guint16 msg_type;
	guint16 msg_length;
	const char *msg_class_str;
	const char *msg_method_str;
	guint16 att_type;
	guint16 att_length;
	guint16 offset;
	guint i;

	/*
	 * First check if the frame is really meant for us.
	 */

	/* First, make sure we have enough data to do the check. */
	if (!tvb_bytes_exist(tvb, 0, STUN2_HDR_LEN))
		return 0;

	msg_type = tvb_get_ntohs(tvb, 0);
	msg_length = tvb_get_ntohs(tvb, 2);

	/* Check if it is really a STUN2 message */
	if (msg_type & 0xC000 || tvb_get_ntohl(tvb, 4) != 0x2112a442)
		return 0;

	/* check if payload enough */
	if (!tvb_bytes_exist(tvb, 0, STUN2_HDR_LEN+msg_length))
		return 0;

	/* Check if too much payload */
	if (tvb_bytes_exist(tvb, 0, STUN2_HDR_LEN+msg_length+1))
		return 0;

	/* The message seems to be a valid STUN2 message! */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "STUN2");

	msg_class_str = match_strval((msg_type & CLASS_MASK) >> 4, classes);
	msg_method_str = match_strval(msg_type & METHOD_MASK, methods);
	if (msg_method_str == NULL)
		msg_method_str = "Unknown";
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		    msg_method_str, msg_class_str);

	if (tree) {
		guint transaction_id_first_word;

		ti = proto_tree_add_item(tree, proto_stun2, tvb, 0, -1, FALSE);

		stun2_tree = proto_item_add_subtree(ti, ett_stun2);

		proto_tree_add_uint(stun2_tree, hf_stun2_class, tvb, 0, 2, msg_type);
		proto_tree_add_uint(stun2_tree, hf_stun2_method, tvb, 0, 2, msg_type);
		proto_tree_add_uint(stun2_tree, hf_stun2_length, tvb, 2, 2, msg_length);
		proto_tree_add_item(stun2_tree, hf_stun2_cookie, tvb, 4, 4, FALSE);
		proto_tree_add_item(stun2_tree, hf_stun2_id, tvb, 8, 12, FALSE);

		/* Remember this (in host order) so we can show clear xor'd addresses */
		/* TODO IPv6 support */
		transaction_id_first_word = tvb_get_ntohl(tvb, 4);

		if (msg_length > 0) {
		    ta = proto_tree_add_item(stun2_tree, hf_stun2_att, tvb, STUN2_HDR_LEN, msg_length, FALSE);
		    att_type_tree = proto_item_add_subtree(ta, ett_stun2_att_type);

		    offset = STUN2_HDR_LEN;

		    while (msg_length > 0) {
				att_type = tvb_get_ntohs(tvb, offset); /* Type field in attribute header */
				att_length = tvb_get_ntohs(tvb, offset+2); /* Length field in attribute header */

				ta = proto_tree_add_text(att_type_tree, tvb, offset,
					ATTR_HDR_LEN+att_length,
					"Attribute: %s",
					val_to_str(att_type, attributes, "Unknown (0x%04x)"));
				att_tree = proto_item_add_subtree(ta, ett_stun2_att);

				proto_tree_add_uint(att_tree, stun2_att_type, tvb,
					offset, 2, att_type);
				offset += 2;
				if (ATTR_HDR_LEN+att_length > msg_length) {
					proto_tree_add_uint_format(att_tree,
						stun2_att_length, tvb, offset, 2,
						att_length,
						"Attribute Length: %u (bogus, goes past the end of the message)",
						att_length);
					break;
				}
				proto_tree_add_uint(att_tree, stun2_att_length, tvb,
					offset, 2, att_length);
				offset += 2;
				switch (att_type) {
					case MAPPED_ADDRESS:
					case ALTERNATE_SERVER:
						if (att_length < 2)
							break;
						proto_tree_add_item(att_tree, stun2_att_family, tvb, offset+1, 1, FALSE);
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, stun2_att_port, tvb, offset+2, 2, FALSE);
						switch (tvb_get_guint8(tvb, offset+1)) {
							case 1:
								if (att_length < 8)
									break;
								proto_tree_add_item(att_tree, stun2_att_ipv4, tvb, offset+4, 4, FALSE);
								break;

							case 2:
								if (att_length < 20)
									break;
								proto_tree_add_item(att_tree, stun2_att_ipv6, tvb, offset+4, 16, FALSE);
								break;
							}
						break;

					case USERNAME:
						proto_tree_add_item(att_tree, stun2_att_username, tvb, offset, att_length, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;

					case PASSWORD:
						proto_tree_add_item(att_tree, stun2_att_password, tvb, offset, att_length, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;

					case NONCE:
						proto_tree_add_item(att_tree, stun2_att_nonce, tvb, offset, att_length, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;

					case REALM:
						proto_tree_add_item(att_tree, stun2_att_realm, tvb, offset, att_length, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;

					case MESSAGE_INTEGRITY:
						if (att_length < 20)
							break;
						proto_tree_add_item(att_tree, stun2_att_hmac, tvb, offset, att_length, FALSE);
						break;

					case FINGERPRINT:
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, stun2_att_crc32, tvb, offset, att_length, FALSE);
						break;

					case ERROR_CODE:
						if (att_length < 3)
							break;
						proto_tree_add_item(att_tree, stun2_att_error_class, tvb, offset+2, 1, FALSE);
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, stun2_att_error_number, tvb, offset+3, 1, FALSE);
						if (att_length < 5)
							break;
						proto_tree_add_item(att_tree, stun2_att_error_reason, tvb, offset+4, att_length-4, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;

					case UNKNOWN_ATTRIBUTES:
						for (i = 0; i < att_length; i += 2)
							proto_tree_add_item(att_tree, stun2_att_unknown, tvb, offset+i, 2, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;

					case SERVER:
						proto_tree_add_item(att_tree, stun2_att_server, tvb, offset, att_length, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;

					case XOR_MAPPED_ADDRESS:
						if (att_length < 2)
							break;
						proto_tree_add_item(att_tree, stun2_att_family, tvb, offset+1, 1, FALSE);
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, stun2_att_xor_port, tvb, offset+2, 2, FALSE);

						/* Show the port 'in the clear'
						   XOR (host order) transid with (host order) xor-port.
						   Add host-order port into tree. */
						ti = proto_tree_add_uint(att_tree, stun2_att_port, tvb, offset+2, 2,
												 tvb_get_ntohs(tvb, offset+2) ^
												 (transaction_id_first_word >> 16));
						PROTO_ITEM_SET_GENERATED(ti);

						if (att_length < 8)
							break;
						switch (tvb_get_guint8(tvb, offset+1) ){
							case 1:
								if (att_length < 8)
									break;
								proto_tree_add_item(att_tree, stun2_att_xor_ipv4, tvb, offset+4, 4, FALSE);

								/* Show the address 'in the clear'.
								   XOR (host order) transid with (host order) xor-address.
								   Add in network order tree. */
								ti = proto_tree_add_ipv4(att_tree, stun2_att_ipv4, tvb, offset+4, 4,
														 g_htonl(tvb_get_ntohl(tvb, offset+4) ^
														 transaction_id_first_word));
								PROTO_ITEM_SET_GENERATED(ti);
								break;

							case 2:
								if (att_length < 20)
									break;
								/* TODO add IPv6 */
								proto_tree_add_item(att_tree, stun2_att_xor_ipv6, tvb, offset+4, 16, FALSE);
								break;
							}
						break;

					case REFRESH_INTERVAL:
						if (att_length < 4)
							break;
						proto_tree_add_item(att_tree, stun2_att_refresh_interval, tvb, offset, 4, FALSE);
						break;

					default:
						if (att_length > 0)
							proto_tree_add_item(att_tree, stun2_att_value, tvb, offset, att_length, FALSE);
						if (att_length % 4 != 0)
							proto_tree_add_uint(att_tree, stun2_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
						break;
				}
				offset += (att_length+3) & -4;
				msg_length -= (ATTR_HDR_LEN+att_length+3) & -4;
		    }
		}
	}
	return tvb_length(tvb);
}


static gboolean
dissect_stun2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (dissect_stun2(tvb, pinfo, tree) == 0)
		return FALSE;

	return TRUE;
}

void
proto_register_stun2(void)
{
	static hf_register_info hf[] = {
		{ &hf_stun2_class,
			{ "Message Class",	"stun2.class", 	FT_UINT16,
			BASE_HEX, 	VALS(classes),	0x0110, 	"", 	HFILL }
		},
		{ &hf_stun2_method,
			{ "Message Method",	"stun2.method", 	FT_UINT16,
			BASE_HEX, 	VALS(methods),	0x3EEF, 	"", 	HFILL }
		},
		{ &hf_stun2_length,
			{ "Message Length",	"stun2.length",	FT_UINT16,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun2_cookie,
			{ "Message Cookie",	"stun2.cookie",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun2_id,
			{ "Message Transaction ID",	"stun2.id",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun2_att,
			{ "Attributes",		"stun2.att",	FT_NONE,
			0, 		NULL, 	0x0, 	"",	HFILL }
		},
		/* ////////////////////////////////////// */
		{ &stun2_att_type,
			{ "Attribute Type",	"stun2.att.type",	FT_UINT16,
			BASE_HEX,	VALS(attributes),	0x0, 	"",	HFILL }
		},
		{ &stun2_att_length,
			{ "Attribute Length",	"stun2.att.length",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_family,
			{ "Protocol Family",	"stun2.att.family",	FT_UINT16,
			BASE_HEX,	VALS(attributes_family),	0x0, 	"",	HFILL }
		},
		{ &stun2_att_ipv4,
			{ "IP",		"stun2.att.ipv4",	FT_IPv4,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_ipv6,
			{ "IP",		"stun2.att.ipv6",	FT_IPv6,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_port,
			{ "Port",	"stun2.att.port",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_username,
			{ "Username",	"stun2.att.username",	FT_STRING,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_padding,
			{ "Padding",	"stun2.att.padding",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_password,
			{ "Password",	"stun2.att.password",	FT_STRING,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_hmac,
			{ "HMAC-SHA1",	"stun2.att.hmac",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_crc32,
			{ "CRC-32",	"stun2.att.crc32",	FT_UINT32,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_error_class,
			{ "Error Class","stun2.att.error.class",	FT_UINT8,
			BASE_DEC, 	NULL,	0x07,	"",	HFILL}
		},
		{ &stun2_att_error_number,
			{ "Error Code","stun2.att.error",	FT_UINT8,
			BASE_DEC, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun2_att_error_reason,
			{ "Error Reason Phase","stun2.att.error.reason",	FT_STRING,
			BASE_NONE, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun2_att_realm,
			{ "Realm",	"stun2.att.realm",	FT_STRING,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_nonce,
			{ "Nonce",	"stun2.att.nonce",	FT_STRING,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_unknown,
			{ "Unknown Attribute","stun2.att.unknown",	FT_UINT16,
			BASE_HEX, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun2_att_xor_ipv4,
			{ "IP (XOR-d)",		"stun2.att.ipv4-xord",	FT_IPv4,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_xor_ipv6,
			{ "IP (XOR-d)",		"stun2.att.ipv6-xord",	FT_IPv6,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_xor_port,
			{ "Port (XOR-d)",	"stun2.att.port-xord",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun2_att_server,
			{ "Server software","stun2.att.server",	FT_STRING,
			BASE_NONE, 	NULL,	0x0,	"",	HFILL}
 		},
		{ &stun2_att_refresh_interval,
			{ "Refresh Interval","stun2.att.refresh-interval",	FT_UINT16,
			BASE_DEC, 	NULL,	0x0,	"",	HFILL}
 		},
		{ &stun2_att_value,
			{ "Value",	"stun2.value",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_stun2,
		&ett_stun2_att_type,
		&ett_stun2_att,
	};

/* Register the protocol name and description */
	proto_stun2 = proto_register_protocol("Simple Traversal Underneath NAT",
	    "STUN2", "stun2");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_stun2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	new_register_dissector("stun2", dissect_stun2, proto_stun2);
}


void
proto_reg_handoff_stun2(void)
{
	dissector_handle_t stun2_handle;

	stun2_handle = find_dissector("stun2");

	dissector_add("tcp.port", TCP_PORT_STUN2, stun2_handle);
	dissector_add("udp.port", UDP_PORT_STUN2, stun2_handle);

	heur_dissector_add("udp", dissect_stun2_heur, proto_stun2);
	heur_dissector_add("tcp", dissect_stun2_heur, proto_stun2);
}

