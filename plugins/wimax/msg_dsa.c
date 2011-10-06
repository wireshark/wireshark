/* msg_dsa.c
 * WiMax MAC Management DSA-REQ/RSP/ACK Messages decoder
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

extern gint proto_wimax;

gint proto_mac_mgmt_msg_dsa_decoder = -1;
static gint ett_mac_mgmt_msg_dsa_req_decoder = -1;
static gint ett_mac_mgmt_msg_dsa_rsp_decoder = -1;
static gint ett_mac_mgmt_msg_dsa_ack_decoder = -1;

static const value_string vals_dsa_msgs[] = {
	{ MAC_MGMT_MSG_DSA_REQ, "Dynamic Service Addition Request (DSA-REQ)" },
	{ MAC_MGMT_MSG_DSA_RSP, "Dynamic Service Addition Response (DSA-RSP)" },
	{ MAC_MGMT_MSG_DSA_ACK, "Dynamic Service Addition Acknowledge (DSA-ACK)" },
	{ 0,                    NULL }
};

/* fix fields */
static gint hf_dsa_req_message_type = -1;
static gint hf_dsa_transaction_id = -1;
static gint hf_dsa_rsp_message_type = -1;
static gint hf_dsa_confirmation_code = -1;
static gint hf_dsa_ack_message_type = -1;


void dissect_mac_mgmt_msg_dsa_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type;
	proto_item *dsa_item = NULL;
	proto_tree *dsa_tree = NULL;

	if(tree)
	{	/* we are being asked for details */
		/* get the message type */
		payload_type = tvb_get_guint8(tvb, offset);
		/* ensure the message type is DSA REQ */
		if(payload_type != MAC_MGMT_MSG_DSA_REQ)
			return;
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		dsa_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsa_decoder, tvb, offset, tvb_len, 
							  "%s (%u bytes)", val_to_str(payload_type, vals_dsa_msgs, "Unknown"), tvb_len);
		/* add MAC DSx subtree */
		dsa_tree = proto_item_add_subtree(dsa_item, ett_mac_mgmt_msg_dsa_req_decoder);
		/* Decode and display the Uplink Channel Descriptor (UCD) */
		/* display the Message Type */
		proto_tree_add_item(dsa_tree, hf_dsa_req_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the Transaction ID */
		proto_tree_add_item(dsa_tree, hf_dsa_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* move to next field */
		offset += 2;
		/* process DSA-REQ message TLV Encode Information */
		wimax_common_tlv_encoding_decoder(tvb_new_subset(tvb, offset, (tvb_len - offset), (tvb_len - offset)), pinfo, dsa_tree);
	}
}

void dissect_mac_mgmt_msg_dsa_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type;
	proto_item *dsa_item = NULL;
	proto_tree *dsa_tree = NULL;

	if(tree)
	{	/* we are being asked for details */
		/* get the message type */
		payload_type = tvb_get_guint8(tvb, offset);
		/* ensure the message type is DSA RSP */
		if(payload_type != MAC_MGMT_MSG_DSA_RSP)
			return;
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		dsa_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsa_decoder, tvb, offset, tvb_len,
							  "%s (%u bytes)", val_to_str(payload_type, vals_dsa_msgs, "Unknown"), tvb_len);
		/* add MAC DSx subtree */
		dsa_tree = proto_item_add_subtree(dsa_item, ett_mac_mgmt_msg_dsa_rsp_decoder);
		/* Decode and display the Uplink Channel Descriptor (UCD) */
		/* display the Message Type */
		proto_tree_add_item(dsa_tree, hf_dsa_rsp_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the Transaction ID */
		proto_tree_add_item(dsa_tree, hf_dsa_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* move to next field */
		offset += 2;
		/* display the Confirmation Code */
		proto_tree_add_item(dsa_tree, hf_dsa_confirmation_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* process DSA RSP message TLV Encode Information */
		wimax_common_tlv_encoding_decoder(tvb_new_subset(tvb, offset, (tvb_len - offset), (tvb_len - offset)), pinfo, dsa_tree);
	}
}

void dissect_mac_mgmt_msg_dsa_ack_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type;
	proto_item *dsa_item = NULL;
	proto_tree *dsa_tree = NULL;

	if(tree)
	{	/* we are being asked for details */
		/* get the message type */
		payload_type = tvb_get_guint8(tvb, offset);
		/* ensure the message type is DSA ACK */
		if(payload_type != MAC_MGMT_MSG_DSA_ACK)
			return;
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		dsa_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsa_decoder, tvb, offset, tvb_len,
							  "%s (%u bytes)", val_to_str(payload_type, vals_dsa_msgs, "Unknown"), tvb_len);
		/* add MAC DSx subtree */
		dsa_tree = proto_item_add_subtree(dsa_item, ett_mac_mgmt_msg_dsa_ack_decoder);
		/* Decode and display the Uplink Channel Descriptor (UCD) */
		/* display the Message Type */
		proto_tree_add_item(dsa_tree, hf_dsa_ack_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the Transaction ID */
		proto_tree_add_item(dsa_tree, hf_dsa_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* move to next field */
		offset += 2;
		/* display the Confirmation Code */
		proto_tree_add_item(dsa_tree, hf_dsa_confirmation_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* process DSA-REQ message TLV Encode Information */
		wimax_common_tlv_encoding_decoder(tvb_new_subset(tvb, offset, (tvb_len - offset), (tvb_len - offset)), pinfo, dsa_tree);
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dsa(void)
{
	/* DSx display */
	static hf_register_info hf[] =
	{
		{
			&hf_dsa_ack_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dsa_ack",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsa_req_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dsa_req",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsa_rsp_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dsa_rsp",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsa_confirmation_code,
			{
				"Confirmation code", "wmx.dsa.confirmation_code",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsa_transaction_id,
			{
				"Transaction ID", "wmx.dsa.transaction_id",
				FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_dsa_req_decoder,
			&ett_mac_mgmt_msg_dsa_rsp_decoder,
			&ett_mac_mgmt_msg_dsa_ack_decoder,
		};

	proto_mac_mgmt_msg_dsa_decoder = proto_register_protocol (
		"WiMax DSA/C/D Messages", /* name       */
		"WiMax DSA/C/D (ds)",     /* short name */
		"wmx.ds"                  /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_dsa_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
