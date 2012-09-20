/* packet-bfcp.c
 * Routines for Binary Floor Control Protocol(BFCP) dissection
 * Copyright 2012, Nitinkumar Yemul <nitinkumaryemul@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * BFCP Message structure is defined in RFC 4582.
 */
#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* Initialize protocol and registered fields */
static int proto_bfcp = -1;
static gboolean  bfcp_enable_heuristic_dissection = FALSE;


static int hf_bfcp_transaction_initiator = -1;
static int hf_bfcp_primitive = -1;
static int hf_bfcp_payload_length = -1;
static int hf_bfcp_conference_id = -1;
static int hf_bfcp_transaction_id = -1;
static int hf_bfcp_user_id = -1;
static int hf_bfcp_payload = -1;
static int hf_bfcp_attribute_types = -1;
static int hf_bfcp_attribute_length = -1;
static int hf_bfcp_request_status = -1;

/* Initialize subtree pointers */
static gint ett_bfcp = -1;

/* Initialize BFCP primitives */
static const value_string map_bfcp_primitive[] = {
	{ 0,  "<Invalid Primitive>"},
	{ 1,  "FloorRequest"},
	{ 2,  "FloorRelease"},
	{ 3,  "FloorRequestQuery"},
	{ 4,  "FloorRequestStatus"},
	{ 5,  "UserQuery"},
	{ 6,  "UserStatus"},
	{ 7,  "FloorQuery"},
	{ 8,  "FloorStatus"},
	{ 9,  "ChairAction"},
	{ 10, "ChairActionAck"},
	{ 11, "Hello"},
	{ 12, "HelloAck"},
	{ 13, "Error"},
	{ 14, "FloorRequestStatusAck"},
	{ 15, "ErrorAck"},
	{ 16, "FloorStatusAck"},
	{ 17, "Goodbye"},
	{ 18, "GoodbyeAck"},
	{ 0,  NULL},
};

static const value_string map_bfcp_attribute_types[] = {
	{ 0,  "<Invalid Primitive>"},
	{ 1,  "BeneficiaryID"},
	{ 2,  "FloorID"},
	{ 3,  "FloorRequestID"},
	{ 4,  "Priority"},
	{ 5,  "RequestStatus"},
	{ 6,  "ErrorCode"},
	{ 7,  "ErrorInfo"},
	{ 8,  "ParticipantProvidedInfo"},
	{ 9,  "StatusInfo"},
	{ 10, "SupportedAttributes"},
	{ 11, "SupportedPrimitives"},
	{ 12, "UserDisplayName"},
	{ 13, "UserURI"},
	{ 14, "BeneficiaryInformation"},
	{ 15, "FloorRequestInformation"},
	{ 16, "RequestedByInformation"},
	{ 17, "FloorRequestStatus"},
	{ 18, "OverallRequestStatus"},
	{ 0,  NULL},
};

static const value_string map_bfcp_request_status[] = {
	{ 0,  "<Invalid Primitive>"},
	{ 1,  "Pending"},
	{ 2,  "Accepted"},
	{ 3,  "Granted"},
	{ 4,  "Denied"},
	{ 5,  "Cancelled"},
	{ 6,  "Released"},
	{ 7,  "Revoked"},
	{ 0,  NULL},
};

/*Define offset for fields in BFCP packet */
#define BFCP_OFFSET_TRANSACTION_INITIATOR  0
#define BFCP_OFFSET_PRIMITIVE              1
#define BFCP_OFFSET_PAYLOAD_LENGTH         2
#define BFCP_OFFSET_CONFERENCE_ID          4
#define BFCP_OFFSET_TRANSACTION_ID         8
#define BFCP_OFFSET_USER_ID               10
#define BFCP_OFFSET_PAYLOAD               12

/* Code to actually dissect BFCP packets */
static gboolean dissect_bfcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint8       first_byte;
	guint8       primitive;
	const gchar *str;
	gint         bfcp_payload_length;
	gint         read_attr = 0;
	proto_tree  *bfcp_tree = NULL;


	/* Size of smallest BFCP packet: 12 octets */
	if (tvb_length(tvb) < 12)
		return FALSE;

	/* Check version and reserved bits in first byte */
	first_byte = tvb_get_guint8(tvb, 0);

	/* If first_byte of bfcp_packet is a combination of the
	 * version and the I bit. The value must be either 0x20 or 0x30
	 * if the bit is set, otherwise it is not BFCP.
	 */
	if ((first_byte != 0x20) && (first_byte != 0x30))
		return FALSE;

	primitive = tvb_get_guint8(tvb, 1);

	if ((primitive < 1) || (primitive > 18))
		return FALSE;

	str = match_strval(primitive, map_bfcp_primitive);
	if (NULL == str)
		return FALSE;

	/* Make entries in Protocol column and Info column on summary display*/
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BFCP");
	col_add_str(pinfo->cinfo, COL_INFO, str);

	if (tree) {
		proto_item	*ti;
		ti = proto_tree_add_item(tree, proto_bfcp, tvb, 0, -1, ENC_NA);
		bfcp_tree = proto_item_add_subtree(ti, ett_bfcp);

		/* Add items to BFCP tree */
		proto_tree_add_item(bfcp_tree, hf_bfcp_transaction_initiator, tvb,
				    BFCP_OFFSET_TRANSACTION_INITIATOR, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_primitive, tvb,
				    BFCP_OFFSET_PRIMITIVE, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_payload_length, tvb,
				    BFCP_OFFSET_PAYLOAD_LENGTH, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_conference_id, tvb,
				    BFCP_OFFSET_CONFERENCE_ID, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_transaction_id, tvb,
				    BFCP_OFFSET_TRANSACTION_ID, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_user_id, tvb,
				    BFCP_OFFSET_USER_ID, 2, ENC_BIG_ENDIAN);
	}

	bfcp_payload_length = tvb_get_ntohs(tvb,
					    BFCP_OFFSET_PAYLOAD_LENGTH) * 4;

	while ((tvb_reported_length_remaining(tvb, BFCP_OFFSET_PAYLOAD + read_attr) >= 2) &&
	       ((bfcp_payload_length - read_attr) >= 2))
	{
		proto_item *ti;
		gint        read = 0;
		gint        length;
		guint8      attribute_type;

		first_byte = tvb_get_guint8(tvb, BFCP_OFFSET_PAYLOAD + read_attr);

		/* Padding so continue to next attribute */
		if (first_byte == 0)
		{
			read_attr++;
			continue;
		}

		proto_tree_add_item(bfcp_tree, hf_bfcp_attribute_types, tvb,
				    BFCP_OFFSET_PAYLOAD + read_attr,1, ENC_BIG_ENDIAN);
		attribute_type = (first_byte & 0xFE) >> 1;
		read++;

		ti = proto_tree_add_item(bfcp_tree, hf_bfcp_attribute_length, tvb,
					 BFCP_OFFSET_PAYLOAD + read_attr + read,1, ENC_BIG_ENDIAN);
		length = tvb_get_guint8(tvb, BFCP_OFFSET_PAYLOAD  + read_attr + read);
		read++;

		/* If RequestStatus then show what type of status it is... */
		if (attribute_type == 5)
		{
			proto_tree_add_item(bfcp_tree, hf_bfcp_request_status, tvb,
					    BFCP_OFFSET_PAYLOAD + read_attr + read,1, ENC_BIG_ENDIAN);
			read++;
		}
		if (length >= read)
		{
			proto_tree_add_item(bfcp_tree, hf_bfcp_payload, tvb,
					    BFCP_OFFSET_PAYLOAD + read_attr + read, length-read, ENC_NA);
		}
		else
		{
			expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
					       "Attribute length is too small (%d bytes)", length);
			break;
		}
		read_attr = read_attr + length;
	}
	return TRUE;
}

void proto_reg_handoff_bfcp(void);

void proto_register_bfcp(void)
{
	module_t *bfcp_module;

	static hf_register_info hf[] = {
		{
			&hf_bfcp_transaction_initiator,
			{ "Transaction Initiator", "bfcp.transaction_initiator",
			  FT_BOOLEAN, 8,
			  NULL, 0x10,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_primitive,
			{ "Primitive", "bfcp.primitive",
			  FT_UINT8, BASE_DEC,
			  VALS(map_bfcp_primitive), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_payload_length,
			{ "Payload Length", "bfcp.payload_length",
			  FT_UINT16, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_conference_id,
			{ "Conference ID", "bfcp.conference_id",
			  FT_UINT32, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_transaction_id,
			{ "Transaction ID", "bfcp.transaction_id",
			  FT_UINT16, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_id,
			{ "User ID", "bfcp.user_id",
			  FT_UINT16, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_payload,
			{ "Payload", "bfcp.payload",
			  FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL,
			  HFILL }
		},
		{
			&hf_bfcp_attribute_types,
			{ "Attribute Type", "bfcp.attribute_type",
			  FT_UINT8, BASE_DEC,
			  VALS(map_bfcp_attribute_types), 0xFE,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_attribute_length,
			{ "Attribute Length", "bfcp.attribute_length",
			  FT_UINT16, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_request_status,
			{ "Request Status", "bfcp.request_status",
			  FT_UINT8, BASE_DEC,
			  VALS(map_bfcp_request_status), 0x0,
			  NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_bfcp
	};

	/* Register protocol name and description */
	proto_bfcp = proto_register_protocol("Binary Floor Control Protocol",
				"BFCP", "bfcp");

	bfcp_module = prefs_register_protocol(proto_bfcp,
				proto_reg_handoff_bfcp);

	prefs_register_bool_preference(bfcp_module, "enable",
		      "Enable BFCP heuristic dissection",
		      "Enable BFCP heuristic dissection (default is disabled)",
		      &bfcp_enable_heuristic_dissection);

	/* Register field and subtree array */
	proto_register_field_array(proto_bfcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_bfcp(void)
{
	static gboolean prefs_initialized = FALSE;

	/* "Decode As" is always available;
	 *  Heuristic dissection in disabled by default since
	 *  the heuristic is quite weak.
	 */
	if (!prefs_initialized)
	{
		dissector_handle_t bfcp_handle;

		heur_dissector_add("tcp", dissect_bfcp, proto_bfcp);
		heur_dissector_add("udp", dissect_bfcp, proto_bfcp);
		bfcp_handle = new_create_dissector_handle(dissect_bfcp, proto_bfcp);
		dissector_add_handle("tcp.port", bfcp_handle);
		dissector_add_handle("udp.port", bfcp_handle);
		prefs_initialized = TRUE;
	}

	heur_dissector_set_enabled("tcp", dissect_bfcp, proto_bfcp,
				   bfcp_enable_heuristic_dissection);

	heur_dissector_set_enabled("udp", dissect_bfcp, proto_bfcp,
				   bfcp_enable_heuristic_dissection);
}
