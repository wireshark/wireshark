/* msg_res_cmd.c
 * WiMax MAC Management RES-CMD Message decoder
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

#if 0
#define DEBUG	/* for debug only */
#endif

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"

void proto_register_mac_mgmt_msg_res_cmd(void);
void proto_reg_handoff_mac_mgmt_msg_res_cmd(void);

static gint proto_mac_mgmt_msg_res_cmd_decoder = -1;
static gint ett_mac_mgmt_msg_res_cmd_decoder = -1;

/* fix fields */
static gint hf_res_cmd_unknown_type = -1;
static gint hf_res_cmd_invalid_tlv = -1;


/* Wimax Mac RES-CMD Message Dissector */
static int dissect_mac_mgmt_msg_res_cmd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint offset = 0;
	guint tvb_len;
	gint  tlv_type, tlv_len, tlv_value_offset;
	proto_item *res_cmd_item;
	proto_tree *res_cmd_tree;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;

	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type RES-CMD */
		res_cmd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_res_cmd_decoder, tvb, offset, -1, "Reset Command (RES-CMD)");
		/* add MAC RES-CMD subtree */
		res_cmd_tree = proto_item_add_subtree(res_cmd_item, ett_mac_mgmt_msg_res_cmd_decoder);
		/* Decode and display the Reset Command (RES-CMD) */
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
			/* process RES-CMD TLV Encoded information */
			switch (tlv_type)
			{
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_res_cmd_decoder, res_cmd_tree, proto_mac_mgmt_msg_res_cmd_decoder, tvb, offset, tlv_len, "HMAC Tuple");
					wimax_hmac_tuple_decoder(tlv_tree, tvb, offset+tlv_value_offset, tlv_len);
				break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_res_cmd_decoder, res_cmd_tree, proto_mac_mgmt_msg_res_cmd_decoder, tvb, offset, tlv_len, "CMAC Tuple");
					wimax_cmac_tuple_decoder(tlv_tree, tvb, offset+tlv_value_offset, tlv_len);
				break;
				default:
					/* display the unknown tlv in hex */
					add_tlv_subtree(&tlv_info, res_cmd_tree, hf_res_cmd_unknown_type, tvb, offset, ENC_NA);
				break;
			}
			offset += (tlv_len+tlv_value_offset);
		}	/* end of TLV process while loop */
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax Mac RES-CMD Message Dissector */
void proto_register_mac_mgmt_msg_res_cmd(void)
{
	/* DSx display */
	static hf_register_info hf_res_cmd[] =
	{
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

void
proto_reg_handoff_mac_mgmt_msg_res_cmd(void)
{
	dissector_handle_t handle;

	handle = create_dissector_handle(dissect_mac_mgmt_msg_res_cmd_decoder, proto_mac_mgmt_msg_res_cmd_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_RES_CMD, handle);
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
