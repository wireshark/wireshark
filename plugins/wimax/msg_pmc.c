/* msg_pmc.c
 * WiMax MAC Management PMC-REQ, PMC-RSP Message decoders
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: John R. Underwood <junderx@yahoo.com>
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

/* Include files */

#include "config.h"

#include "moduleinfo.h"

#include <glib.h>
#include <epan/packet.h>
#include "crc.h"
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"

extern gint man_ofdma;
extern	gboolean include_cor2_changes;

/* Forward reference */
void dissect_mac_mgmt_msg_pmc_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_mac_mgmt_msg_pmc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint proto_mac_mgmt_msg_pmc_req_decoder = -1;
static gint proto_mac_mgmt_msg_pmc_rsp_decoder = -1;

static gint ett_mac_mgmt_msg_pmc_decoder = -1;

/* Setup protocol subtree array */
static gint *ett[] =
{
	&ett_mac_mgmt_msg_pmc_decoder,
};

/* PMC fields */
static gint hf_pmc_req_message_type = -1;
static gint hf_pmc_rsp_message_type = -1;
static gint hf_pmc_req_pwr_control_mode_change = -1;
static gint hf_pmc_req_pwr_control_mode_change_cor2 = -1;
static gint hf_pmc_req_tx_power_level = -1;
static gint hf_pmc_req_confirmation = -1;
static gint hf_pmc_req_reserved = -1;
static gint hf_pmc_rsp_start_frame = -1;
static gint hf_pmc_rsp_power_adjust = -1;
static gint hf_pmc_rsp_offset_BS_per_MS = -1;

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
			&hf_pmc_req_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.pmc_req",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
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
			&hf_pmc_rsp_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.pmc_rsp",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
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
		"WiMax PMC-REQ/RSP Messages", /* name */
		"WiMax PMC-REQ/RSP (pmc)", /* short name */
		"wmx.pmc" /* abbrev */
		);

	proto_register_field_array(proto_mac_mgmt_msg_pmc_req_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_pmc_rsp(void)
{
	proto_mac_mgmt_msg_pmc_rsp_decoder = proto_mac_mgmt_msg_pmc_req_decoder;
}

/* Decode PMC-REQ messages. */
void dissect_mac_mgmt_msg_pmc_req_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type;
	proto_item *pmc_req_item = NULL;
	proto_tree *pmc_req_tree = NULL;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, 0);
	if(payload_type != MAC_MGMT_MSG_PMC_REQ)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type PMC-REQ */
		pmc_req_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_pmc_req_decoder, tvb, 0, tvb_len, "MAC Management Message, PMC-REQ (63)");
		/* add MAC PMC REQ subtree */
		pmc_req_tree = proto_item_add_subtree(pmc_req_item, ett_mac_mgmt_msg_pmc_decoder);
		/* display the Message Type */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		/* display the Power Control Mode Change */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_pwr_control_mode_change, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* show the Transmit Power Level */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_tx_power_level, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the Confirmation/request */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_confirmation, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* show the Reserved bits */
		proto_tree_add_item(pmc_req_tree, hf_pmc_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	}
}

/* Decode PMC-RSP messages. */
void dissect_mac_mgmt_msg_pmc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type;
	proto_item *pmc_rsp_item = NULL;
	proto_tree *pmc_rsp_tree = NULL;
	guint8 pwr_control_mode;
	gint8 value;
	gfloat power_change;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, 0);
	if(payload_type != MAC_MGMT_MSG_PMC_RSP)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type PMC-RSP */
		pmc_rsp_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_pmc_rsp_decoder, tvb, 0, tvb_len, "MAC Management Message, PMC-RSP (64)");
		/* add MAC PMC RSP subtree */
		pmc_rsp_tree = proto_item_add_subtree(pmc_rsp_item, ett_mac_mgmt_msg_pmc_decoder);
		/* display the Message Type */
		proto_tree_add_item(pmc_rsp_tree, hf_pmc_rsp_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset ++;

		/* display the Power Control Mode Change */
		if (include_cor2_changes)
			proto_tree_add_item(pmc_rsp_tree, hf_pmc_req_pwr_control_mode_change_cor2, tvb, offset, 2, ENC_BIG_ENDIAN);
		else
			proto_tree_add_item(pmc_rsp_tree, hf_pmc_req_pwr_control_mode_change, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the Power Adjust start frame */
		proto_tree_add_item(pmc_rsp_tree, hf_pmc_rsp_start_frame, tvb, offset, 2, ENC_BIG_ENDIAN);
		pwr_control_mode = 0xC0 & tvb_get_guint8(tvb, offset);
		offset++;

		value = (gint8)tvb_get_guint8(tvb, offset);
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
}

