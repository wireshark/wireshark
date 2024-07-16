/* msg_aas_beam.c
 * WiMax MAC Management AAS-BEAM-SELECT/REQ/RSP Messages decoders
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define OFDM	/* disable it if not supporting OFDM */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include "wimax_mac.h"

extern int proto_mac_mgmt_msg_aas_fbck_decoder;

#define AAS_BEAM_SELECT_AAS_BEAM_INDEX_MASK	0xFC
#define AAS_BEAM_SELECT_RESERVED_MASK		0x03
#define AAS_BEAM_FEEDBACK_REQUEST_NUMBER_MASK	0xE0
#define AAS_BEAM_MEASUREMENT_REPORT_TYPE_MASK	0x18
#define AAS_BEAM_RESOLUTION_PARAMETER_MASK	0x07

#define AAS_BEAM_BEAM_BIT_MASK_MASK		0xF0
#define AAS_BEAM_RESERVED_MASK			0x0F

void proto_register_mac_mgmt_msg_aas_beam(void);
void proto_reg_handoff_mac_mgmt_msg_aas_beam(void);

static dissector_handle_t aas_handle;

static int proto_mac_mgmt_msg_aas_beam_decoder;
static int ett_mac_mgmt_msg_aas_beam_select_decoder;
static int ett_mac_mgmt_msg_aas_beam_req_decoder;
static int ett_mac_mgmt_msg_aas_beam_rsp_decoder;

#ifdef OFDM
static const value_string vals_report_types[] =
{
	{0, "BEAM_REP_IE"},
	{0,  NULL}
};

static const value_string vals_resolution_parameter[] =
{
	{0, "report every 4th subcarrier"},
	{1, "report every 8th subcarrier"},
	{2, "report every 16th subcarrier"},
	{3, "report every 32nd subcarrier"},
	{4, "report every 64th subcarrier"},
	{0,  NULL}
};
#endif

/* fix fields */
/* static int hf_aas_beam_unknown_type; */
static int hf_aas_beam_select_index;
static int hf_aas_beam_select_reserved;
#ifdef OFDM
static int hf_aas_beam_frame_number;
static int hf_aas_beam_feedback_request_number;
static int hf_aas_beam_measurement_report_type;
static int hf_aas_beam_resolution_parameter;
static int hf_aas_beam_beam_bit_mask;
static int hf_aas_beam_freq_value_re;
static int hf_aas_beam_freq_value_im;
static int hf_aas_beam_rssi_value;
static int hf_aas_beam_cinr_value;
#endif


static int dissect_mac_mgmt_msg_aas_beam_select_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned offset = 0;
	proto_item *aas_beam_item;
	proto_tree *aas_beam_tree;

	{	/* we are being asked for details */

		/* display MAC message type */
		aas_beam_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_aas_beam_decoder, tvb, offset, -1, "AAS Beam Select (AAS-BEAM-SELECT)");
		/* add subtree */
		aas_beam_tree = proto_item_add_subtree(aas_beam_item, ett_mac_mgmt_msg_aas_beam_select_decoder);

		/* Decode and display the AAS-BEAM-SELECT message body */
		/* display the AAS Beam Index */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_select_index, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the reserved fields */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_select_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	return tvb_captured_length(tvb);
}

#ifdef OFDM
static int dissect_mac_mgmt_msg_aas_beam_req_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned offset = 0;
	proto_item *aas_beam_item;
	proto_tree *aas_beam_tree;

	{	/* we are being asked for details */

		/* display MAC message type */
		aas_beam_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_aas_beam_decoder, tvb, offset, -1, "AAS Beam Request (AAS-BEAM-REQ)");
		/* add subtree */
		aas_beam_tree = proto_item_add_subtree(aas_beam_item, ett_mac_mgmt_msg_aas_beam_req_decoder);

		/* Decode and display the AAS-BEAM-REQ message body */
		/* display the Frame Number */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_frame_number, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the Feedback Request Number */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_feedback_request_number, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Measurement Report Type */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_measurement_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Resolution Parameter */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_resolution_parameter, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the Beam Bit mask */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_beam_bit_mask, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the reserved fields */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_select_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	return tvb_captured_length(tvb);
}

static int dissect_mac_mgmt_msg_aas_beam_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned offset = 0;
	unsigned tvb_len, report_type;
	unsigned number_of_frequencies, indx;
	proto_item *aas_beam_item;
	proto_tree *aas_beam_tree;

	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		aas_beam_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_aas_beam_decoder, tvb, offset, -1, "AAS Beam Response (AAS-BEAM-RSP)");
		/* add subtree */
		aas_beam_tree = proto_item_add_subtree(aas_beam_item, ett_mac_mgmt_msg_aas_beam_rsp_decoder);

		/* Decode and display the AAS-BEAM-RSP message body */
		/* display the Frame Number */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_frame_number, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* get the Measurement Report Type */
		report_type = tvb_get_uint8(tvb, offset);
		/* display the Feedback Request Number */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_feedback_request_number, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Measurement Report Type */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_measurement_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Resolution Parameter */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_resolution_parameter, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the Beam Bit mask */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_beam_bit_mask, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the reserved fields */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_select_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* check the Measurement Report Type */
		if((report_type & AAS_BEAM_MEASUREMENT_REPORT_TYPE_MASK) == 0)
		{
			/* calculate the total number of frequencies */
			number_of_frequencies = (tvb_len - offset) / 2 - 1;
			/* display the frequency */
			for(indx = 0; indx < number_of_frequencies; indx++)
			{	/* display the Frequency Value (real part) */
				proto_tree_add_item(aas_beam_tree, hf_aas_beam_freq_value_re, tvb, offset, 1, ENC_BIG_ENDIAN);
				/* move to next field */
				offset++;
				/* display the Frequency Value (imaginary part) */
				proto_tree_add_item(aas_beam_tree, hf_aas_beam_freq_value_im, tvb, offset, 1, ENC_BIG_ENDIAN);
				/* move to next field */
				offset++;
			}
		}
		/* display the RSSI Mean Value */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_rssi_value, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the CINR Mean Value */
		proto_tree_add_item(aas_beam_tree, hf_aas_beam_cinr_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	return tvb_captured_length(tvb);
}
#endif

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_aas_beam(void)
{
	/* AAS-BEAM display */
	static hf_register_info hf_aas_beam[] =
	{
		{
			&hf_aas_beam_select_index,
			{
				"AAS Beam Index", "wmx.aas_beam.aas_beam_index",
				FT_UINT8, BASE_DEC, NULL, AAS_BEAM_SELECT_AAS_BEAM_INDEX_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_beam_bit_mask,
			{
				"Beam Bit Mask", "wmx.aas_beam.beam_bit_mask",
				FT_UINT8, BASE_HEX, NULL, AAS_BEAM_BEAM_BIT_MASK_MASK, NULL, HFILL
			}
		},
#ifdef OFDM
		{
			&hf_aas_beam_cinr_value,
			{
				"CINR Mean Value", "wmx.aas_beam.cinr_mean_value",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_feedback_request_number,
			{
				"Feedback Request Number", "wmx.aas_beam.feedback_request_number",
				FT_UINT8, BASE_DEC, NULL, AAS_BEAM_FEEDBACK_REQUEST_NUMBER_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_frame_number,
			{
				"Frame Number", "wmx.aas_beam.frame_number",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_freq_value_im,
			{
				"Frequency Value (imaginary part)", "wmx.aas_beam.freq_value_im",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_freq_value_re,
			{
				"Frequency Value (real part)", "wmx.aas_beam.freq_value_re",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_measurement_report_type,
			{
				"Measurement Report Type", "wmx.aas_beam.measurement_report_type",
				FT_UINT8, BASE_DEC, VALS(vals_report_types), AAS_BEAM_MEASUREMENT_REPORT_TYPE_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_select_reserved,
			{
				"Reserved", "wmx.aas_beam.reserved",
				FT_UINT8, BASE_HEX, NULL, AAS_BEAM_SELECT_RESERVED_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_resolution_parameter,
			{
				"Resolution Parameter", "wmx.aas_beam.resolution_parameter",
				FT_UINT8, BASE_DEC, VALS(vals_resolution_parameter), AAS_BEAM_RESOLUTION_PARAMETER_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_beam_rssi_value,
			{
				"RSSI Mean Value", "wmx.aas_beam.rssi_mean_value",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
#if 0
		{
			&hf_aas_beam_unknown_type,
			{
				"Unknown TLV type", "wmx.aas_beam.unknown_type",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		}
#endif
	};

	/* Setup protocol subtree array */
	static int *ett[] =
		{
			&ett_mac_mgmt_msg_aas_beam_select_decoder,
			&ett_mac_mgmt_msg_aas_beam_req_decoder,
			&ett_mac_mgmt_msg_aas_beam_rsp_decoder,
		};

	proto_mac_mgmt_msg_aas_beam_decoder = proto_register_protocol (
		"WiMax AAS-BEAM Messages", /* name       */
		"WiMax AAS-BEAM",          /* short name */
		"wmx.aas_beam"             /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_aas_beam_decoder, hf_aas_beam, array_length(hf_aas_beam));
	proto_register_subtree_array(ett, array_length(ett));

	aas_handle = register_dissector("mac_mgmt_msg_aas_beam_select_handler", dissect_mac_mgmt_msg_aas_beam_select_decoder, proto_mac_mgmt_msg_aas_beam_decoder);
#ifdef OFDM
	register_dissector("mac_mgmt_msg_aas_beam_req_handler", dissect_mac_mgmt_msg_aas_beam_req_decoder, proto_mac_mgmt_msg_aas_beam_decoder);
	register_dissector("mac_mgmt_msg_aas_beam_rsp_handler", dissect_mac_mgmt_msg_aas_beam_rsp_decoder, proto_mac_mgmt_msg_aas_beam_decoder);
#endif
}

void
proto_reg_handoff_mac_mgmt_msg_aas_beam(void)
{
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_AAS_BEAM_SELECT, aas_handle);
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
