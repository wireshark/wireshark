/* msg_pkm.c
 * WiMax MAC Management PKM-REQ/RSP Messages decoders
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
#define DEBUG	// for debug only
*/

/* Include files */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"

static gint proto_mac_mgmt_msg_pkm_decoder = -1;
static gint ett_mac_mgmt_msg_pkm_req_decoder = -1;
static gint ett_mac_mgmt_msg_pkm_rsp_decoder = -1;

static const value_string vals_pkm_msg_code[] =
{
	{3, "SA ADD"},
	{4, "Auth Request"},
	{5, "Auth Reply"},
	{6, "Auth Reject"},
	{7, "Key Request"},
	{8, "Key Reply"},
	{9, "Key Reject"},
	{10, "Auth Invalid"},
	{11, "TEK Invalid"},
	{12, "Auth Info"},
	{13, "PKMv2 RSA-Request"},
	{14, "PKMv2 RSA-Reply"},
	{15, "PKMv2 RSA-Reject"},
	{16, "PKMv2 RSA-Acknowledgement"},
	{17, "PKMv2 EAP Start"},
	{18, "PKMv2 EAP-Transfer"},
	{19, "PKMv2 Authenticated EAP-Transfer"},
	{20, "PKMv2 SA TEK Challenge"},
  	{21, "PKMv2 SA TEK Request"},
	{22, "PKMv2 SA TEK Response"},
	{23, "PKMv2 Key-Request"},
  	{24, "PKMv2 Key-Reply"},
	{25, "PKMv2 Key-Reject"},
	{26, "PKMv2 SA-Addition"},
	{27, "PKMv2 TEK-Invalid"},
 	{28, "PKMv2 Group-Key-Update-Command"},
	{29, "PKMv2 EAP Complete"},
	{30, "PKMv2 Authenticated EAP Start"},
	{ 0,				NULL}
};

/* fix fields */
static gint hf_pkm_req_message_type = -1;
static gint hf_pkm_rsp_message_type = -1;
static gint hf_pkm_msg_code = -1;
static gint hf_pkm_msg_pkm_id = -1;


/* Wimax Mac PKM-REQ Message Dissector */
void dissect_mac_mgmt_msg_pkm_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type, length;
	proto_item *pkm_item = NULL;
	proto_tree *pkm_tree = NULL;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, offset);
	if(payload_type != MAC_MGMT_MSG_PKM_REQ)
	{
		return;
	}

	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type PKM-REQ */
		pkm_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_pkm_decoder, tvb, offset, tvb_len, "Privacy Key Management Request (PKM-REQ) (%u bytes)", tvb_len);
		/* add MAC PKM subtree */
		pkm_tree = proto_item_add_subtree(pkm_item, ett_mac_mgmt_msg_pkm_req_decoder);
		/* Decode and display the Privacy Key Management Request Message (PKM-REQ) (table 24) */
		/* display the Message Type */
		proto_tree_add_item(pkm_tree, hf_pkm_req_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the PKM Code */
		offset++;
		/* display the PKM Code */
		proto_tree_add_item(pkm_tree, hf_pkm_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the PKM ID */
		offset++;
		/* display the PKM ID */
		proto_tree_add_item(pkm_tree, hf_pkm_msg_pkm_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the TLV Encoded info */
		offset++;
		/* process the PKM TLV Encoded Attributes */
		length = tvb_len - offset;
		wimax_pkm_tlv_encoded_attributes_decoder(tvb_new_subset(tvb, offset, length, length), pinfo, pkm_tree);
	}
}

/* Wimax Mac PKM-RSP Message Dissector */
void dissect_mac_mgmt_msg_pkm_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type, length;
	proto_item *pkm_item = NULL;
	proto_tree *pkm_tree = NULL;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, offset);
	if(payload_type != MAC_MGMT_MSG_PKM_RSP)
	{
		return;
	}

	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type PKM-RSP */
		pkm_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_pkm_decoder, tvb, offset, tvb_len, "Privacy Key Management Response (PKM-RSP) (%u bytes)", tvb_len);
		/* add MAC PKM subtree */
		pkm_tree = proto_item_add_subtree(pkm_item, ett_mac_mgmt_msg_pkm_rsp_decoder);
		/* Decode and display the Privacy Key Management Response (PKM-RSP) (table 25) */
		/* display the Message Type */
		proto_tree_add_item(pkm_tree, hf_pkm_rsp_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the PKM Code */
		offset++;
		/* display the PKM Code */
		proto_tree_add_item(pkm_tree, hf_pkm_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the PKM ID */
		offset++;
		/* display the PKM ID */
		proto_tree_add_item(pkm_tree, hf_pkm_msg_pkm_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the TLV Encoded info */
		offset++;
		/* process the PKM TLV Encoded Attributes */
		length = tvb_len - offset;
		wimax_pkm_tlv_encoded_attributes_decoder(tvb_new_subset(tvb, offset, length, length), pinfo, pkm_tree);
	}
}

/* Register Wimax Mac PKM-REQ/RSP Messages Dissectors */
void proto_register_mac_mgmt_msg_pkm(void)
{
	/* PKM display */
	static hf_register_info hf_pkm[] =
	{
		{
			&hf_pkm_msg_code,
			{"Code", "wmx.pkm.msg_code",FT_UINT8, BASE_DEC, VALS(vals_pkm_msg_code),0x0, NULL, HFILL}
		},
		{
			&hf_pkm_msg_pkm_id,
			{"PKM Identifier", "wmx.pkm.msg_pkm_identifier",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_pkm_req_message_type,
			{"MAC Management Message Type", "wmx.macmgtmsgtype.pkm_req", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_pkm_rsp_message_type,
			{"MAC Management Message Type", "wmx.macmgtmsgtype.pkm_rsp", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett_pkm[] =
		{
			&ett_mac_mgmt_msg_pkm_req_decoder,
			&ett_mac_mgmt_msg_pkm_rsp_decoder,
		};

	proto_mac_mgmt_msg_pkm_decoder = proto_register_protocol (
		"WiMax PKM-REQ/RSP Messages", /* name       */
		"WiMax PKM-REQ/RSP (pkm)",    /* short name */
		"wmx.pkm"                     /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_pkm_decoder, hf_pkm, array_length(hf_pkm));
	proto_register_subtree_array(ett_pkm, array_length(ett_pkm));
}
