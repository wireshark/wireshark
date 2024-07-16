/* msg_pmc.c
 * WiMax MAC Management PMC-REQ, PMC-RSP Message decoders
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
#include "wimax_prefs.h"

void proto_register_mac_mgmt_msg_pmc_req(void);
void proto_register_mac_mgmt_msg_pmc_rsp(void);
void proto_reg_handoff_mac_mgmt_msg_pmc(void);
static int dissect_mac_mgmt_msg_pmc_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static int dissect_mac_mgmt_msg_pmc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static dissector_handle_t pmc_req_handle;
static dissector_handle_t pmc_rsp_handle;

static int proto_mac_mgmt_msg_pmc_req_decoder;
static int proto_mac_mgmt_msg_pmc_rsp_decoder;

static int ett_mac_mgmt_msg_pmc_decoder;

/* Setup protocol subtree array */
static int *ett[] =
{
	&ett_mac_mgmt_msg_pmc_decoder,
};

/* PMC fields */
static int hf_pmc_req_pwr_control_mode_change;
static int hf_pmc_req_pwr_control_mode_change_cor2;
static int hf_pmc_req_tx_power_level;
static int hf_pmc_req_confirmation;
static int hf_pmc_req_reserved;
static int hf_pmc_rsp_start_frame;
static int hf_pmc_rsp_power_adjust;
static int hf_pmc_rsp_offset_BS_per_MS;

/* STRING RESOURCES */
static const value_string vals_pmc_req_pwr[] = {
	{0, "Closed loop power control mode"},
	{1, "Reserved"},
	{2, "Open loop power control passive mode"},
	{3, "Open loop power control active mode"},
	{0,				NULL}
};

static const value_string vals_pmc_req_pwr_cor2[] = {
	{0, "Closed loop power control mode"},
	{1, "Open loop power control passive mode with Offset_SSperSS retention"},
	{2, "Open loop power control passive mode with Offset_SSperSS reset"},
	{3, "Open loop power control active mode"},
	{0,				NULL}
};

static const value_string vals_pmc_req_confirmation[] = {
	{0, "MS requests to change the power control mode"},
	{1, "MS confirms the receipt of PMC_RSP from BS"},
	{0,				NULL}
};

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_pmc_req(void)
{
	/* PMC fields display */
	static hf_register_info hf[] =
	{
		{
			&hf_pmc_req_confirmation,
			{
				"Confirmation", "wmx.pmc_req.confirmation",
				FT_UINT16, BASE_DEC, VALS(vals_pmc_req_confirmation), 0x0020, NULL, HFILL
			}
		},
		{
			&hf_pmc_req_pwr_control_mode_change,
			{
				"Power control mode change", "wmx.pmc_req.power_control_mode",
				FT_UINT16, BASE_DEC, VALS(vals_pmc_req_pwr), 0xC000, NULL, HFILL
			}
		},
		{
			&hf_pmc_req_pwr_control_mode_change_cor2,
			{
				"Power control mode change", "wmx.pmc_req.power_control_mode",
				FT_UINT16, BASE_DEC, VALS(vals_pmc_req_pwr_cor2), 0xC000, NULL, HFILL
			}
		},
		{
			&hf_pmc_req_reserved,
			{
				"Reserved", "wmx.pmc_req.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x001F, NULL, HFILL
			}
		},
		{
			&hf_pmc_req_tx_power_level,
			{
				"UL Tx power level for the burst that carries this header", "wmx.pmc_req.ul_tx_power_level",
				FT_UINT16, BASE_DEC, NULL, 0x3FC0, "When the Tx power is different from slot to slot, the maximum value is reported", HFILL
			}
		},
		{
			&hf_pmc_rsp_offset_BS_per_MS,
			{
				"Offset_BS per MS", "wmx.pmc_rsp.offset_BS_per_MS",
				FT_FLOAT, BASE_NONE, NULL, 0x0, "Signed change in power level (incr of 0.25 dB) that the MS shall apply to the open loop power control formula in 8.4.10.3.2", HFILL
			}
		},
		{
			&hf_pmc_rsp_power_adjust,
			{
				"Power adjust", "wmx.pmc_rsp.power_adjust",
				FT_FLOAT, BASE_NONE, NULL, 0x0, "Signed change in power level (incr of 0.25 dB) that the MS shall apply to its current transmission power. When subchannelization is employed, the SS shall interpret as a required change to the Tx power density", HFILL
			}
		},
		{
			&hf_pmc_rsp_start_frame,
			{
				"Start frame", "wmx.pmc_rsp.start_frame",
				FT_UINT16, BASE_HEX, NULL, 0x3F00, "Apply mode change from current frame when 6 LSBs of frame match this", HFILL
			}
		}
	};

	proto_mac_mgmt_msg_pmc_req_decoder = proto_register_protocol (
		"WiMax PMC-REQ Messages", /* name */
		"WiMax PMC-REQ", /* short name */
		"wmx.pmc_req" /* abbrev */
		);

	proto_register_field_array(proto_mac_mgmt_msg_pmc_req_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	pmc_req_handle = register_dissector("mac_mgmt_msg_pmc_req_handler", dissect_mac_mgmt_msg_pmc_req_decoder, proto_mac_mgmt_msg_pmc_req_decoder);
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_pmc_rsp(void)
{
	proto_mac_mgmt_msg_pmc_rsp_decoder = proto_register_protocol (
		"WiMax PMC-RSP Messages", /* name */
		"WiMax PMC-RSP", /* short name */
		"wmx.pmc_rsp" /* abbrev */
		);
	pmc_rsp_handle = register_dissector("mac_mgmt_msg_pmc_rsp_handler", dissect_mac_mgmt_msg_pmc_rsp_decoder, proto_mac_mgmt_msg_pmc_rsp_decoder);
}

/* Decode PMC-REQ messages. */
static int dissect_mac_mgmt_msg_pmc_req_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned offset = 0;
	proto_item *pmc_req_item;
	proto_tree *pmc_req_tree;

	{	/* we are being asked for details */

		/* display MAC payload type PMC-REQ */
		pmc_req_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_pmc_req_decoder, tvb, 0, -1, "MAC Management Message, PMC-REQ");
		/* add MAC PMC REQ subtree */
		pmc_req_tree = proto_item_add_subtree(pmc_req_item, ett_mac_mgmt_msg_pmc_decoder);
		/* display the Power Control Mode Change */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_pwr_control_mode_change, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* show the Transmit Power Level */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_tx_power_level, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the Confirmation/request */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_confirmation, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* show the Reserved bits */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	}
	return tvb_captured_length(tvb);
}

/* Decode PMC-RSP messages. */
static int dissect_mac_mgmt_msg_pmc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned offset = 0;
	proto_item *pmc_rsp_item;
	proto_tree *pmc_rsp_tree;
	uint8_t pwr_control_mode;
	int8_t value;
	float power_change;

	{	/* we are being asked for details */

		/* display MAC payload type PMC-RSP */
		pmc_rsp_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_pmc_rsp_decoder, tvb, 0, -1, "MAC Management Message, PMC-RSP");
		/* add MAC PMC RSP subtree */
		pmc_rsp_tree = proto_item_add_subtree(pmc_rsp_item, ett_mac_mgmt_msg_pmc_decoder);

		/* display the Power Control Mode Change */
		if (include_cor2_changes)
			proto_tree_add_item(pmc_rsp_tree, hf_pmc_req_pwr_control_mode_change_cor2, tvb, offset, 2, ENC_BIG_ENDIAN);
		else
			proto_tree_add_item(pmc_rsp_tree, hf_pmc_req_pwr_control_mode_change, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the Power Adjust start frame */
		proto_tree_add_item(pmc_rsp_tree, hf_pmc_rsp_start_frame, tvb, offset, 2, ENC_BIG_ENDIAN);
		pwr_control_mode = 0xC0 & tvb_get_uint8(tvb, offset);
		offset++;

		value = tvb_get_int8(tvb, offset);
		power_change = (float)0.25 * value;  /* 0.25dB incr */
		/* Check if Power Control Mode is 0 */
		if (pwr_control_mode == 0) {
			/* display the amount of power change requested */
			proto_tree_add_float_format_value(pmc_rsp_tree, hf_pmc_rsp_power_adjust, tvb, offset, 1, power_change, " %.2f dB", power_change);
		} else {
			/* display the amount of MS power change requested */
			proto_tree_add_float_format_value(pmc_rsp_tree, hf_pmc_rsp_offset_BS_per_MS, tvb, offset, 1, power_change, " %.2f dB", power_change);
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_reg_handoff_mac_mgmt_msg_pmc(void)
{
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_PMC_REQ, pmc_req_handle);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_PMC_RSP, pmc_rsp_handle);
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
