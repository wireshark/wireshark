/* msg_dsd.c
 * WiMax MAC Management DSD-REQ/RSP Messages decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
#define DEBUG
*/

#include <glib.h>
#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"

extern gint proto_mac_mgmt_msg_dsa_decoder;

gint proto_mac_mgmt_msg_dsd_decoder = -1;
static gint ett_mac_mgmt_msg_dsd_req_decoder = -1;
static gint ett_mac_mgmt_msg_dsd_rsp_decoder = -1;
/* static gint ett_dsd_ul_sfe_decoder = -1; */
/* static gint ett_dsd_dl_sfe_decoder = -1; */
/* static gint ett_dsd_hmac_tuple = -1;     */
/* static gint ett_dsd_cmac_tuple = -1;     */

static const value_string vals_dsd_msgs[] =
{
	{ MAC_MGMT_MSG_DSD_REQ, "Dynamic Service Deletion Request (DSD-REQ)" },
	{ MAC_MGMT_MSG_DSD_RSP, "Dynamic Service Deletion Response (DSD-RSP)" },
	{ 0,                    NULL }
};

/* fix fields */
static gint hf_dsd_req_message_type = -1;
static gint hf_dsd_transaction_id = -1;
static gint hf_dsd_service_flow_id = -1;
static gint hf_dsd_rsp_message_type = -1;
static gint hf_dsd_confirmation_code = -1;
static gint hf_dsd_invalid_tlv = -1;
static gint hf_dsd_unknown_type = -1;


void dissect_mac_mgmt_msg_dsd_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_item *dsd_item = NULL;
	proto_tree *dsd_tree = NULL;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;

	if(tree)
	{	/* we are being asked for details */
		/* get the message type */
		payload_type = tvb_get_guint8(tvb, offset);
		/* ensure the message type is DSD REQ/RSP/ACK */
		if(payload_type != MAC_MGMT_MSG_DSD_REQ)
			return;
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		dsd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tvb_len,
							  "%s (%u bytes)", val_to_str(payload_type, vals_dsd_msgs, "Unknown"), tvb_len);
		/* add MAC DSx subtree */
		dsd_tree = proto_item_add_subtree(dsd_item, ett_mac_mgmt_msg_dsd_req_decoder);
		/* Decode and display the DSD message */
		/* display the Message Type */
		proto_tree_add_item(dsd_tree, hf_dsd_req_message_type, tvb, offset, 1, FALSE);
		/* move to next field */
		offset++;
		/* display the Transaction ID */
		proto_tree_add_item(dsd_tree, hf_dsd_transaction_id, tvb, offset, 2, FALSE);
		/* move to next field */
		offset += 2;
		/* display the Service Flow ID */
		proto_tree_add_item(dsd_tree, hf_dsd_service_flow_id, tvb, offset, 4, FALSE);
		/* move to next field */
		offset += 4;
		/* process DSD REQ message TLV Encode Information */
		while(offset < tvb_len)
		{	/* get the TLV information */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DSD-REQ TLV error");
				proto_tree_add_item(dsd_tree, hf_dsd_invalid_tlv, tvb, offset, (tvb_len - offset), FALSE);
				break;
			}
			/* get the TLV value offset */
			tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
			proto_tree_add_protocol_format(dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len + tlv_value_offset, "DSD-REQ TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, tlv_len + tlv_value_offset, offset, tvb_len);
#endif
			/* update the offset */
			offset += tlv_value_offset;
			/* process TLV */
			switch (tlv_type)
			{
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dsd_req_decoder, dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len, "HMAC Tuple (%u byte(s))", tlv_len);
					wimax_hmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
					break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dsd_req_decoder, dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len, "CMAC Tuple (%u byte(s))", tlv_len);
					wimax_cmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
					break;
				default:
					/* display the unknown tlv in hex */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dsd_req_decoder, dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len, "Unknown TLV (%u byte(s))", tlv_len);
					proto_tree_add_item(tlv_tree, hf_dsd_unknown_type, tvb, (offset - tlv_value_offset), (tlv_len + tlv_value_offset), FALSE);
					break;
			}
			offset += tlv_len;
		}	/* end of while loop */
	}
}

void dissect_mac_mgmt_msg_dsd_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_item *dsd_item = NULL;
	proto_tree *dsd_tree = NULL;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;

	if(tree)
	{	/* we are being asked for details */
		/* get the message type */
		payload_type = tvb_get_guint8(tvb, offset);
		/* ensure the message type is DSD REQ/RSP/ACK */
		if(payload_type != MAC_MGMT_MSG_DSD_RSP)
			return;
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		dsd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tvb_len,
							  "%s (%u bytes)", val_to_str(payload_type, vals_dsd_msgs, "Unknown"), tvb_len);
		/* add MAC DSx subtree */
		dsd_tree = proto_item_add_subtree(dsd_item, ett_mac_mgmt_msg_dsd_rsp_decoder);
		/* Decode and display the DSD message */
		/* display the Message Type */
		proto_tree_add_item(dsd_tree, hf_dsd_rsp_message_type, tvb, offset, 1, ENC_NA);
		/* move to next field */
		offset++;
		/* display the Transaction ID */
		proto_tree_add_item(dsd_tree, hf_dsd_transaction_id, tvb, offset, 2, FALSE);
		/* move to next field */
		offset += 2;
		/* display the Confirmation Code */
		proto_tree_add_item(dsd_tree, hf_dsd_confirmation_code, tvb, offset, 1, FALSE);
		/* move to next field */
		offset++;
		/* display the Service Flow ID */
		proto_tree_add_item(dsd_tree, hf_dsd_service_flow_id, tvb, offset, 4, FALSE);
		/* move to next field */
		offset += 4;
		/* process DSD RSP message TLV Encode Information */
		while(offset < tvb_len)
		{	/* get the TLV information */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DSD RSP TLV error");
				proto_tree_add_item(dsd_tree, hf_dsd_invalid_tlv, tvb, offset, (tvb_len - offset), FALSE);
				break;
			}
			/* get the TLV value offset */
			tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
			proto_tree_add_protocol_format(dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len + tlv_value_offset, "DSD-RSP TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, tlv_len + tlv_value_offset, offset, tvb_len);
#endif
			/* update the offset */
			offset += tlv_value_offset;
			/* process TLV */
			switch (tlv_type)
			{
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dsd_req_decoder, dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len, "HMAC Tuple (%u byte(s))", tlv_len);
					wimax_hmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
					break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dsd_req_decoder, dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len, "CMAC Tuple (%u byte(s))", tlv_len);
					wimax_cmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
					break;
				default:
					/* display the unknown tlv in hex */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dsd_req_decoder, dsd_tree, proto_mac_mgmt_msg_dsd_decoder, tvb, offset, tlv_len, "Unknown TLV (%u byte(s))", tlv_len);
					proto_tree_add_item(tlv_tree, hf_dsd_unknown_type, tvb, (offset - tlv_value_offset), (tlv_len + tlv_value_offset), FALSE);
					break;
			}
			offset += tlv_len;
		}	/* end of while loop */
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dsd(void)
{
	/* DSx display */
	static hf_register_info hf[] =
	{
		{
			&hf_dsd_req_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dsd_req", 
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsd_rsp_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dsd_rsp", 
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_dsd_confirmation_code,
			{
				"Confirmation code", "wmx.dsd.confirmation_code", 
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsd_service_flow_id,
			{
				"Service Flow ID", "wmx.dsd.service_flow_id", 
				FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsd_transaction_id,
			{
				"Transaction ID", "wmx.dsd.transaction_id", 
				FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_dsd_req_decoder,
			&ett_mac_mgmt_msg_dsd_rsp_decoder,
			/* &ett_dsd_ul_sfe_decoder, */
			/* &ett_dsd_dl_sfe_decoder, */
			/* &ett_dsd_hmac_tuple,     */
			/* &ett_dsd_cmac_tuple,     */
		};

	proto_mac_mgmt_msg_dsd_decoder = proto_mac_mgmt_msg_dsa_decoder;

	proto_register_field_array(proto_mac_mgmt_msg_dsd_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
