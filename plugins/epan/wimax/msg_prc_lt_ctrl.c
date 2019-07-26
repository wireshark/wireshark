/* msg_prc_lt_ctrl.c
 * WiMax MAC Management PRC-LT-CTRL Message decoders
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: John R. Underwood <junderx@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include "wimax_mac.h"


void proto_register_mac_mgmt_msg_prc_lt_ctrl(void);
void proto_reg_handoff_mac_mgmt_msg_prc_lt_ctrl(void);

static gint proto_mac_mgmt_msg_prc_lt_ctrl_decoder = -1;

static gint ett_mac_mgmt_msg_prc_lt_ctrl_decoder = -1;

/* PRC-LT-CTRL fields */
static gint hf_prc_lt_ctrl_precoding = -1;
static gint hf_prc_lt_ctrl_precoding_delay = -1;
/* static gint hf_prc_lt_ctrl_invalid_tlv = -1; */

static const value_string vals_turn_on[] = {
	{0, "Turn off"},
	{1, "Turn on"},
	{0, NULL}
};


/* Decode PRC-LT-CTRL messages. */
static int dissect_mac_mgmt_msg_prc_lt_ctrl_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	guint offset = 0;
	proto_item *prc_lt_ctrl_item;
	proto_tree *prc_lt_ctrl_tree;

	{	/* we are being asked for details */

		/* display MAC payload type PRC-LT-CTRL */
		prc_lt_ctrl_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_prc_lt_ctrl_decoder, tvb, 0, -1, "MAC Management Message, PRC-LT-CTRL");

		/* add MAC PRC-LT-CTRL subtree */
		prc_lt_ctrl_tree = proto_item_add_subtree(prc_lt_ctrl_item, ett_mac_mgmt_msg_prc_lt_ctrl_decoder);

		/* display whether to Setup or Tear-down the
		 * long-term MIMO precoding delay */
		proto_tree_add_item(prc_lt_ctrl_tree, hf_prc_lt_ctrl_precoding, tvb, offset, 1, ENC_BIG_ENDIAN);

		/* display the Precoding Delay */
		proto_tree_add_item(prc_lt_ctrl_tree, hf_prc_lt_ctrl_precoding_delay, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_prc_lt_ctrl(void)
{
	/* PRC-LT-CTRL fields display */
	static hf_register_info hf[] =
	{
#if 0
		{
			&hf_prc_lt_ctrl_invalid_tlv,
			{
				"Invalid TLV", "wmx.prc_lt_ctrl.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
#endif
		{
			&hf_prc_lt_ctrl_precoding,
			{
				"Setup/Tear-down long-term precoding with feedback",
				"wimax.prc_lt_ctrl.precoding",
				FT_UINT8, BASE_DEC, VALS(vals_turn_on), 0x80, NULL, HFILL
			}
		},
		{
			&hf_prc_lt_ctrl_precoding_delay,
			{
				"BS precoding application delay",
				"wimax.prc_lt_ctrl.precoding_delay",
				FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_prc_lt_ctrl_decoder,
		};

	proto_mac_mgmt_msg_prc_lt_ctrl_decoder = proto_register_protocol (
		"WiMax PRC-LT-CTRL Message", /* name       */
		"WiMax PRC-LT-CTRL (prc)",   /* short name */
		"wmx.prc"                    /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_prc_lt_ctrl_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mac_mgmt_msg_prc_lt_ctrl(void)
{
	dissector_handle_t handle;

	handle = create_dissector_handle(dissect_mac_mgmt_msg_prc_lt_ctrl_decoder, proto_mac_mgmt_msg_prc_lt_ctrl_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_PRC_LT_CTRL, handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
