/* msg_dsc.c
 * WiMax MAC Management DSC-REQ/RSP/ACK Messages decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
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

/* Include files */

#include "config.h"

/*
#define DEBUG
*/

#include <epan/packet.h>
#include "wimax_mac.h"
#include "wimax_utils.h"

void proto_register_mac_mgmt_msg_dsc(void);
void proto_reg_handoff_mac_mgmt_msg_dsc(void);

static gint proto_mac_mgmt_msg_dsc_decoder = -1;
static gint ett_mac_mgmt_msg_dsc_req_decoder = -1;
static gint ett_mac_mgmt_msg_dsc_rsp_decoder = -1;
static gint ett_mac_mgmt_msg_dsc_ack_decoder = -1;

/* fix fields */
static gint hf_dsc_transaction_id = -1;
static gint hf_dsc_confirmation_code = -1;


static int dissect_mac_mgmt_msg_dsc_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint offset = 0;
	proto_item *dsc_item;
	proto_tree *dsc_tree;

	{	/* we are being asked for details */

		/* display MAC message type */
		dsc_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsc_decoder, tvb, offset, -1,
							  "Dynamic Service Change Request (DSC-REQ)");
		/* add MAC DSx subtree */
		dsc_tree = proto_item_add_subtree(dsc_item, ett_mac_mgmt_msg_dsc_req_decoder);
		/* Decode and display the Uplink Channel Descriptor (UCD) */
		/* display the Transaction ID */
		proto_tree_add_item(dsc_tree, hf_dsc_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* move to next field */
		offset += 2;
		/* process DSC REQ message TLV Encode Information */
		wimax_common_tlv_encoding_decoder(tvb_new_subset_remaining(tvb, offset), pinfo, dsc_tree);
	}
	return tvb_captured_length(tvb);
}

static int dissect_mac_mgmt_msg_dsc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint offset = 0;
	proto_item *dsc_item;
	proto_tree *dsc_tree;

	{	/* we are being asked for details */
		/* display MAC message type */
		dsc_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsc_decoder, tvb, offset, -1,
							"Dynamic Service Change Response (DSC-RSP)");
		/* add MAC DSx subtree */
		dsc_tree = proto_item_add_subtree(dsc_item, ett_mac_mgmt_msg_dsc_rsp_decoder);
		/* Decode and display the Uplink Channel Descriptor (UCD) */
		/* display the Transaction ID */
		proto_tree_add_item(dsc_tree, hf_dsc_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* move to next field */
		offset += 2;
		/* display the Confirmation Code */
		proto_tree_add_item(dsc_tree, hf_dsc_confirmation_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* process DSC RSP message TLV Encode Information */
		wimax_common_tlv_encoding_decoder(tvb_new_subset_remaining(tvb, offset), pinfo, dsc_tree);
	}
	return tvb_captured_length(tvb);
}

static int dissect_mac_mgmt_msg_dsc_ack_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint offset = 0;
	proto_item *dsc_item;
	proto_tree *dsc_tree;

	{	/* we are being asked for details */
		/* display MAC message type */
		dsc_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dsc_decoder, tvb, offset, -1,
							  "Dynamic Service Change Acknowledge (DSC-ACK)");
		/* add MAC DSx subtree */
		dsc_tree = proto_item_add_subtree(dsc_item, ett_mac_mgmt_msg_dsc_ack_decoder);
		/* Decode and display the Uplink Channel Descriptor (UCD) */
		/* display the Transaction ID */
		proto_tree_add_item(dsc_tree, hf_dsc_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* move to next field */
		offset += 2;
		/* display the Confirmation Code */
		proto_tree_add_item(dsc_tree, hf_dsc_confirmation_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* process DSC ACK message TLV Encode Information */
		wimax_common_tlv_encoding_decoder(tvb_new_subset_remaining(tvb, offset), pinfo, dsc_tree);
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dsc(void)
{
	/* DSx display */
	static hf_register_info hf[] =
	{
		{
			&hf_dsc_confirmation_code,
			{
				"Confirmation code", "wmx.dsc.confirmation_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dsc_transaction_id,
			{
				"Transaction ID", "wmx.dsc.transaction_id",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_dsc_req_decoder,
			&ett_mac_mgmt_msg_dsc_rsp_decoder,
			&ett_mac_mgmt_msg_dsc_ack_decoder
		};

	proto_mac_mgmt_msg_dsc_decoder = proto_register_protocol (
		"WiMax DSC Messages", /* name       */
		"WiMax DSC",     /* short name */
		"wmx.dsc"        /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_dsc_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("mac_mgmt_msg_dsc_rsp_handler", dissect_mac_mgmt_msg_dsc_rsp_decoder, -1);
}

void
proto_reg_handoff_mac_mgmt_msg_dsc(void)
{
	dissector_handle_t dsc_handle;

	dsc_handle = create_dissector_handle(dissect_mac_mgmt_msg_dsc_req_decoder, proto_mac_mgmt_msg_dsc_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_DSC_REQ, dsc_handle);

	dsc_handle = create_dissector_handle(dissect_mac_mgmt_msg_dsc_rsp_decoder, proto_mac_mgmt_msg_dsc_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_DSC_RSP, dsc_handle);

	dsc_handle = create_dissector_handle(dissect_mac_mgmt_msg_dsc_ack_decoder, proto_mac_mgmt_msg_dsc_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_DSC_ACK, dsc_handle);
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
