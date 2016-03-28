/* packet-bfcp.c
 * Routines for Binary Floor Control Protocol(BFCP) dissection
 * Copyright 2012, Nitinkumar Yemul <nitinkumaryemul@gmail.com>
 *
 * Updated with attribute dissection
 * Copyright 2012, Anders Broman <anders.broman@ericsson.com>
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
 * BFCP Message structure is defined in RFC 4582bis
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

void proto_register_bfcp(void);
void proto_reg_handoff_bfcp(void);

/* Initialize protocol and registered fields */
static int proto_bfcp = -1;

static int hf_bfcp_version = -1;
static int hf_bfcp_hdr_r_bit = -1;
static int hf_bfcp_hdr_f_bit = -1;
static int hf_bfcp_primitive = -1;
static int hf_bfcp_payload_length = -1;
static int hf_bfcp_conference_id = -1;
static int hf_bfcp_transaction_id = -1;
static int hf_bfcp_user_id = -1;
static int hf_bfcp_payload = -1;
static int hf_bfcp_attribute_types = -1;
static int hf_bfcp_attribute_types_m_bit = -1;
static int hf_bfcp_attribute_length = -1;
static int hf_bfcp_beneficiary_id = -1;
static int hf_bfcp_floor_id = -1;
static int hf_bfcp_floor_request_id = -1;
static int hf_bfcp_priority = -1;
static int hf_bfcp_request_status = -1;
static int hf_bfcp_queue_pos = -1;
static int hf_bfcp_error_code = -1;
static int hf_bfcp_error_info_text = -1;
static int hf_bfcp_part_prov_info_text = -1;
static int hf_bfcp_status_info_text = -1;
static int hf_bfcp_supp_attr = -1;
static int hf_bfcp_supp_prim = -1;
static int hf_bfcp_user_disp_name = -1;
static int hf_bfcp_user_uri = -1;
static int hf_bfcp_req_by_id = -1;
static int hf_bfcp_padding = -1;
static int hf_bfcp_error_specific_details = -1;

/* Initialize subtree pointers */
static gint ett_bfcp = -1;
static gint ett_bfcp_attr = -1;

static expert_field ei_bfcp_attribute_length_too_small = EI_INIT;

static dissector_handle_t bfcp_handle;

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

/* 5.2.6.  ERROR-CODE */
static const value_string bfcp_error_code_valuse[] = {
	{ 1,  "Conference does not Exist"},
	{ 2,  "User does not Exist"},
	{ 3,  "Unknown Primitive"},
	{ 4,  "Unknown Mandatory Attribute"},
	{ 5,  "Unauthorized Operation"},
	{ 6,  "Invalid Floor ID"},
	{ 7,  "Floor Request ID Does Not Exist"},
	{ 8,  "You have Already Reached the Maximum Number of Ongoing Floor Requests for this Floor"},
	{ 9,  "Use TLS"},
	{ 10,  "Unable to Parse Message"},
	{ 11,  "Use DTLS"},
	{ 12,  "Unsupported Version"},
	{ 13,  "Incorrect Message Length"},
	{ 14,  "Generic Error"},

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

static int
dissect_bfcp_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int bfcp_payload_length)
{
	proto_item *ti, *item;
	proto_tree  *bfcp_attr_tree = NULL;
	gint        attr_start_offset;
	gint        length;
	guint8      attribute_type;
	gint        read_attr = 0;
	guint8      first_byte, pad_len;

	while ((tvb_reported_length_remaining(tvb, offset) >= 2) &&
			((bfcp_payload_length - read_attr) >= 2))
	{

		attr_start_offset = offset;
		first_byte = tvb_get_guint8(tvb, offset);

		/* Padding so continue to next attribute */
		if (first_byte == 0){
			read_attr++;
			continue;
		}

		ti = proto_tree_add_item(tree, hf_bfcp_attribute_types, tvb, offset, 1, ENC_BIG_ENDIAN);
		bfcp_attr_tree = proto_item_add_subtree(ti, ett_bfcp_attr);
		proto_tree_add_item(bfcp_attr_tree, hf_bfcp_attribute_types_m_bit, tvb, offset, 1, ENC_BIG_ENDIAN);

		attribute_type = (first_byte & 0xFE) >> 1;
		offset++;

	/*   Length: This 8-bit field contains the length of the attribute in
	 *   octets, excluding any padding defined for specific attributes.  The
	 *   length of attributes that are not grouped includes the Type, 'M' bit,
	 *   and Length fields.  The Length in grouped attributes is the length of
	 *   the grouped attribute itself (including Type, 'M' bit, and Length
	 *   fields) plus the total length (including padding) of all the included
	 *   attributes.
	 */

		item = proto_tree_add_item(bfcp_attr_tree, hf_bfcp_attribute_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		length = tvb_get_guint8(tvb, offset);
		offset++;

		pad_len = 0; /* Default to no padding*/

		switch(attribute_type){
		case 1: /* Beneficiary ID */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_beneficiary_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 2: /* FLOOR-ID */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 3: /* FLOOR-REQUEST-ID */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 4: /* PRIORITY */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 5: /* REQUEST-STATUS */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_request_status, tvb, offset,1, ENC_BIG_ENDIAN);
			offset++;
			/* Queue Position */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_queue_pos, tvb, offset,1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 6: /* ERROR-CODE */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_error_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			if(length>3){
				/* We have Error Specific Details */
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_error_specific_details, tvb, offset, length-3, ENC_NA);
			}
			offset = offset + length-3;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 7: /* ERROR-INFO */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_error_info_text, tvb, offset, length-3, ENC_ASCII|ENC_NA);
			offset = offset + length-3;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 8: /* PARTICIPANT-PROVIDED-INFO */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_part_prov_info_text, tvb, offset, length-3, ENC_ASCII|ENC_NA);
			offset = offset + length-3;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 9: /* STATUS-INFO */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_status_info_text, tvb, offset, length-3, ENC_ASCII|ENC_NA);
			offset = offset + length-3;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 10: /* SUPPORTED-ATTRIBUTES */

			while(offset < (attr_start_offset+length)){
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_supp_attr, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset+=1;
			}
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 11: /* SUPPORTED-PRIMITIVES */

			while(offset < (attr_start_offset+length)){
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_supp_prim, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset+=1;
			}
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 12: /* USER-DISPLAY-NAME */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_user_disp_name, tvb, offset, length-3, ENC_ASCII|ENC_NA);
			offset = offset + length-3;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 13: /* USER-URI */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_user_uri, tvb, offset, length-3, ENC_ASCII|ENC_NA);
			offset = offset + length-3;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 14: /* BENEFICIARY-INFORMATION */
			/*    The BENEFICIARY-INFORMATION attribute is a grouped attribute that
			 *   consists of a header, which is referred to as BENEFICIARY-
			 *   INFORMATION-HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_beneficiary_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 15: /* FLOOR-REQUEST-INFORMATION */
			/*    The FLOOR-REQUEST-INFORMATION attribute is a grouped attribute that
			 *   consists of a header, which is referred to as FLOOR-REQUEST-
			 *   INFORMATION-HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 16: /*  REQUESTED-BY-INFORMATION */
			/*    The  REQUESTED-BY-INFORMATION attribute is a grouped attribute that
			 *   consists of a header, which is referred to as FLOOR-REQUEST-STATUS-
			 *   -HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_req_by_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 17: /*  FLOOR-REQUEST-STATUS */
			/*    The  FLOOR-REQUEST-STATUS attribute is a grouped attribute that
			 *   consists of a header, which is referred to as OVERALL-REQUEST-STATUS-
			 *   -HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 18: /* OVERALL-REQUEST-STATUS */
			/*    The OVERALL-REQUEST-STATUS attribute is a grouped attribute that
			 *   consists of a header, which is referred to as FLOOR-REQUEST-
			 *   INFORMATION-HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;

		default:
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_payload, tvb, offset, length-2, ENC_NA);
			offset = offset + length - 2;
			break;
		}
		if ((length+pad_len) < (offset - attr_start_offset)){
			expert_add_info_format(pinfo, item, &ei_bfcp_attribute_length_too_small,
							"Attribute length is too small (%d bytes)", length);
			break;
		}
		read_attr = read_attr + length;
	}

	return offset;
}


static gboolean
dissect_bfcp_heur_check(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	guint8       primitive;
	guint8      first_byte;
	const gchar *str;


	/* Size of smallest BFCP packet: 12 octets */
	if (tvb_captured_length(tvb) < 12)
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

	str = try_val_to_str(primitive, map_bfcp_primitive);
	if (NULL == str)
		return FALSE;

	return TRUE;
}

/* Code to actually dissect BFCP packets */
static int
dissect_bfcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int          offset = 0;
	guint8       primitive;
	const gchar *str;
	gint         bfcp_payload_length;
	proto_tree  *bfcp_tree;
	proto_item	*ti;

	if (!dissect_bfcp_heur_check(tvb, pinfo, tree, data))
		return 0;

	primitive = tvb_get_guint8(tvb, 1);
	str = try_val_to_str(primitive, map_bfcp_primitive);

	/* Make entries in Protocol column and Info column on summary display*/
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BFCP");
	col_add_str(pinfo->cinfo, COL_INFO, str);

	ti = proto_tree_add_item(tree, proto_bfcp, tvb, 0, -1, ENC_NA);
	bfcp_tree = proto_item_add_subtree(ti, ett_bfcp);
/*
  The following is the format of the common header.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Ver |R|F| Res |  Primitive    |        Payload Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Conference ID                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Transaction ID        |            User ID            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Fragment Offset (if F is set) | Fragment Length (if F is set) |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


*/
	/* Add items to BFCP tree */
	proto_tree_add_item(bfcp_tree, hf_bfcp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bfcp_tree, hf_bfcp_hdr_r_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bfcp_tree, hf_bfcp_hdr_f_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(bfcp_tree, hf_bfcp_primitive, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(bfcp_tree, hf_bfcp_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(bfcp_tree, hf_bfcp_conference_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(bfcp_tree, hf_bfcp_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(bfcp_tree, hf_bfcp_user_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	bfcp_payload_length = tvb_get_ntohs(tvb,
						BFCP_OFFSET_PAYLOAD_LENGTH) * 4;

	/*offset = */dissect_bfcp_attributes(tvb, pinfo, bfcp_tree, offset, bfcp_payload_length);

	return tvb_captured_length(tvb);
}

static gboolean
dissect_bfcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (!dissect_bfcp_heur_check(tvb, pinfo, tree, data))
		return FALSE;

	dissect_bfcp(tvb, pinfo, tree, data);
	return TRUE;
}

void proto_register_bfcp(void)
{
	module_t *bfcp_module;
	expert_module_t* expert_bfcp;

	static hf_register_info hf[] = {
		{
			&hf_bfcp_version,
			{ "Version(ver)", "bfcp.ver",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_hdr_r_bit,
			{ "Transaction Responder (R)", "bfcp.hdr_r_bit",
			  FT_BOOLEAN, 8, NULL, 0x10,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_hdr_f_bit,
			{ "Fragmentation (F)", "bfcp.hdr_f_bit",
			  FT_BOOLEAN, 8, NULL, 0x08,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_primitive,
			{ "Primitive", "bfcp.primitive",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_primitive), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_payload_length,
			{ "Payload Length", "bfcp.payload_length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_conference_id,
			{ "Conference ID", "bfcp.conference_id",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_transaction_id,
			{ "Transaction ID", "bfcp.transaction_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_id,
			{ "User ID", "bfcp.user_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_payload,
			{ "Payload", "bfcp.payload",
			  FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
			  HFILL }
		},
		{
			&hf_bfcp_attribute_types,
			{ "Attribute Type", "bfcp.attribute_type",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_attribute_types), 0xFE,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_attribute_types_m_bit,
			{ "Mandatory bit(M)", "bfcp.attribute_types_m_bit",
			  FT_BOOLEAN, 8, NULL, 0x01,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_attribute_length,
			{ "Attribute Length", "bfcp.attribute_length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_beneficiary_id,
			{ "BENEFICIARY-ID", "bfcp.beneficiary_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_floor_id,
			{ "FLOOR-ID", "bfcp.floor_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_floor_request_id,
			{ "FLOOR-REQUEST-ID", "bfcp.floorrequest_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_priority,
			{ "FLOOR-REQUEST-ID", "bfcp.priority",
			  FT_UINT16, BASE_DEC, NULL, 0xe000,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_request_status,
			{ "Request Status", "bfcp.request_status",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_request_status), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_queue_pos,
			{ "Queue Position", "bfcp.queue_pos",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_error_code,
			{ "Error Code", "bfcp.error_code",
			  FT_UINT8, BASE_DEC, VALS(bfcp_error_code_valuse), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_error_info_text,
			{ "Text", "bfcp.error_info_text",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_part_prov_info_text,
			{ "Text", "bfcp.part_prov_info_text",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_status_info_text,
			{ "Text", "bfcp.status_info_text",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_supp_attr,
			{ "Supported Attribute", "bfcp.supp_attr",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_attribute_types), 0xFE,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_supp_prim,
			{ "Supported Primitive", "bfcp.supp_primitive",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_primitive), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_disp_name,
			{ "Name", "bfcp.user_disp_name",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_uri,
			{ "URI", "bfcp.user_uri",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_req_by_id,
			{ "Requested-by ID", "bfcp.req_by_i",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_padding,
			{ "Padding", "bfcp.padding",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_error_specific_details,
			{ "Error Specific Details", "bfcp.error_specific_details",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_bfcp,
		&ett_bfcp_attr,
	};

	static ei_register_info ei[] = {
		{ &ei_bfcp_attribute_length_too_small, { "bfcp.attribute_length.too_small", PI_MALFORMED, PI_ERROR, "Attribute length is too small", EXPFILL }},
	};

	/* Register protocol name and description */
	proto_bfcp = proto_register_protocol("Binary Floor Control Protocol",
				"BFCP", "bfcp");

	bfcp_handle = register_dissector("bfcp", dissect_bfcp, proto_bfcp);

	bfcp_module = prefs_register_protocol(proto_bfcp,
				proto_reg_handoff_bfcp);

	prefs_register_obsolete_preference(bfcp_module, "enable");

	/* Register field and subtree array */
	proto_register_field_array(proto_bfcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_bfcp = expert_register_protocol(proto_bfcp);
	expert_register_field_array(expert_bfcp, ei, array_length(ei));
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
		heur_dissector_add("tcp", dissect_bfcp_heur, "BFCP over TCP", "bfcp_tcp", proto_bfcp, HEURISTIC_DISABLE);
		heur_dissector_add("udp", dissect_bfcp_heur, "BFCP over UDP", "bfcp_udp", proto_bfcp, HEURISTIC_DISABLE);
		dissector_add_for_decode_as("tcp.port", bfcp_handle);
		dissector_add_for_decode_as("udp.port", bfcp_handle);
		prefs_initialized = TRUE;
	}
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
