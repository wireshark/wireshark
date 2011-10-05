/* msg_res_cmd.c
 * WiMax MAC Management RES-CMD Message decoder
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

/*
#define DEBUG	// for debug only
*/

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"

static gint proto_mac_mgmt_msg_res_cmd_decoder = -1;
static gint ett_mac_mgmt_msg_res_cmd_decoder = -1;

/* fix fields */
static gint hf_res_cmd_message_type = -1;
static gint hf_res_cmd_unknown_type = -1;
static gint hf_res_cmd_invalid_tlv = -1;


/* Wimax Mac RES-CMD Message Dissector */
void dissect_mac_mgmt_msg_res_cmd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type;
	gint  tlv_type, tlv_len, tlv_value_offset;
	proto_item *res_cmd_item = NULL;
	proto_tree *res_cmd_tree = NULL;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, offset);
	if(payload_type != MAC_MGMT_MSG_RES_CMD)
	{
		return;
	}

	if(tree)
	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type RES-CMD */
		res_cmd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_res_cmd_decoder, tvb, offset, tvb_len, "Reset Command (RES-CMD) (%u bytes)", tvb_len);
		/* add MAC RES-CMD subtree */
		res_cmd_tree = proto_item_add_subtree(res_cmd_item, ett_mac_mgmt_msg_res_cmd_decoder);
		/* Decode and display the Reset Command (RES-CMD) */
		/* display the Message Type */
		proto_tree_add_item(res_cmd_tree, hf_res_cmd_message_type, tvb, offset, 1, FALSE);
		/* set the offset for the TLV Encoded info */
		offset++;
		/* process the RES-CMD TLVs */
		while(offset < tvb_len)
		{
			/* get the TLV information */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "RES-CMD TLV error");
				proto_tree_add_item(res_cmd_tree, hf_res_cmd_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
				break;
			}
			/* get the TLV value offset */
			tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
			proto_tree_add_protocol_format(res_cmd_tree, proto_mac_mgmt_msg_res_cmd_decoder, tvb, offset, (tlv_len + tlv_value_offset), "RES-CMD Type: %u (%u bytes, offset=%u, tlv_len=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tlv_len, tvb_len);
#endif
			/* update the offset for the TLV value */
			offset += tlv_value_offset;
			/* process RES-CMD TLV Encoded information */
			switch (tlv_type)
			{
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_res_cmd_decoder, res_cmd_tree, proto_mac_mgmt_msg_res_cmd_decoder, tvb, offset, tlv_len, "HMAC Tuple (%u byte(s))", tlv_len);
					wimax_hmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
				break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_res_cmd_decoder, res_cmd_tree, proto_mac_mgmt_msg_res_cmd_decoder, tvb, offset, tlv_len, "CMAC Tuple (%u byte(s))", tlv_len);
					wimax_cmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
				break;
				default:
					/* display the unknown tlv in hex */
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_res_cmd_decoder, res_cmd_tree, hf_res_cmd_unknown_type, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_res_cmd_unknown_type, tvb, offset, tlv_len, ENC_NA);
				break;
			}
			offset += tlv_len;
		}	/* end of TLV process while loop */
	}
}

/* Register Wimax Mac RES-CMD Message Dissector */
void proto_register_mac_mgmt_msg_res_cmd(void)
{
	/* DSx display */
	static hf_register_info hf_res_cmd[] =
	{
		{
			&hf_res_cmd_message_type,
			{"MAC Management Message Type", "wmx.macmgtmsgtype.res_cmd", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_res_cmd_invalid_tlv,
			{"Invalid TLV", "wmx.res_cmd.invalid_tlv", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{
			&hf_res_cmd_unknown_type,
			{"Unknown TLV type", "wmx.res_cmd.unknown_tlv_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett_res_cmd[] =
		{
			&ett_mac_mgmt_msg_res_cmd_decoder,
		};

	proto_mac_mgmt_msg_res_cmd_decoder = proto_register_protocol (
		"WiMax RES-CMD Message", /* name       */
		"WiMax RES-CMD (res)",   /* short name */
		"wmx.res"                /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_res_cmd_decoder, hf_res_cmd, array_length(hf_res_cmd));
	proto_register_subtree_array(ett_res_cmd, array_length(ett_res_cmd));
}
