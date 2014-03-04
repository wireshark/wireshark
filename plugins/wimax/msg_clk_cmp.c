/* msg_clk_cmp.c
 * WiMax MAC Management CLK_CMP Message decoders
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

#include <glib.h>
#include <epan/packet.h>
#include "wimax_mac.h"

void proto_register_mac_mgmt_msg_clk_cmp(void);
void proto_reg_handoff_mac_mgmt_msg_clk_cmp(void);

static gint proto_mac_mgmt_msg_clk_cmp_decoder = -1;

static gint ett_mac_mgmt_msg_clk_cmp_decoder = -1;

/* CLK_CMP fields */
static gint hf_clk_cmp_clock_count = -1;
static gint hf_clk_cmp_clock_id = -1;
static gint hf_clk_cmp_seq_number = -1;
static gint hf_clk_cmp_comparison_value = -1;
/* static gint hf_clk_cmp_invalid_tlv = -1; */


/* Decode CLK_CMP messages. */
static void dissect_mac_mgmt_msg_clk_cmp_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint offset = 0;
	guint i;
	guint clock_count;
	proto_item *clk_cmp_item;
	proto_tree *clk_cmp_tree;

	{	/* we are being asked for details */
		/* display MAC payload type CLK_CMP */
		clk_cmp_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_clk_cmp_decoder, tvb, offset, -1, "Clock Comparison (CLK-CMP)");
		/* add MAC CLK_CMP subtree */
		clk_cmp_tree = proto_item_add_subtree(clk_cmp_item, ett_mac_mgmt_msg_clk_cmp_decoder);
		/* get the clock count */
		clock_count = tvb_get_guint8(tvb, offset);
		/* display the clock count */
		proto_tree_add_item(clk_cmp_tree, hf_clk_cmp_clock_count, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for clock comparison */
		offset++;
		for (i = 0; i < clock_count; i++ )
		{	/* display the Clock ID */
			proto_tree_add_item(clk_cmp_tree, hf_clk_cmp_clock_id, tvb, offset++, 1, ENC_BIG_ENDIAN);
			/* display the sequence number */
			proto_tree_add_item(clk_cmp_tree, hf_clk_cmp_seq_number, tvb, offset++, 1, ENC_BIG_ENDIAN);
			/* display the comparison value */
			proto_tree_add_item(clk_cmp_tree, hf_clk_cmp_comparison_value, tvb, offset++, 1, ENC_BIG_ENDIAN);
		}
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_clk_cmp(void)
{
	/* CLK_CMP fields display */
	static hf_register_info hf_clk_cmp[] =
	{
		{
			&hf_clk_cmp_clock_count,
			{
				"Clock Count", "wmx.clk_cmp.clock_count",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_clk_cmp_clock_id,
			{
				"Clock ID", "wmx.clk_cmp.clock_id",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_clk_cmp_comparison_value,
			{
				"Comparison Value", "wmx.clk_cmp.comparison_value",
				FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#if 0
		{
			&hf_clk_cmp_invalid_tlv,
			{
				"Invalid TLV", "wmx.clk_cmp.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
#endif
		{
			&hf_clk_cmp_seq_number,
			{
				"Sequence Number", "wmx.clk_cmp.seq_number",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_clk_cmp_decoder,
		};

	proto_mac_mgmt_msg_clk_cmp_decoder = proto_register_protocol (
		"WiMax CLK-CMP Message", /* name       */
		"WiMax CLK-CMP (clk)",   /* short name */
		"wmx.clk"                /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_clk_cmp_decoder, hf_clk_cmp, array_length(hf_clk_cmp));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mac_mgmt_msg_clk_cmp(void)
{
	dissector_handle_t handle;

	handle = create_dissector_handle(dissect_mac_mgmt_msg_clk_cmp_decoder, proto_mac_mgmt_msg_clk_cmp_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_CLK_CMP, handle);
}
