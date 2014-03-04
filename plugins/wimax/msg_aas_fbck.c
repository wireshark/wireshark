/* msg_aas_beam.c
 * WiMax MAC Management AAS-BEAM-SELECT/REQ/RSP Messages decoders
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

#define OFDMA_AAS_FBCK_REQ_NUMBER_OF_FRAME_MASK	0xFE
#define OFDMA_AAS_FBCK_REQ_DATA_TYPE_MASK	0x01
#define OFDMA_AAS_FBCK_REQ_FB_REQ_COUNTER_MASK	0xE0
#define OFDMA_AAS_FBCK_REQ_FB_REQ_RESOLUTION_MASK	0x18
#define OFDMA_AAS_FBCK_REQ_FB_REQ_RESERVED_MASK	0x07

#define OFDMA_AAS_FBCK_REQ_FB_RSP_RESERVED_MASK	0xC0
#define OFDMA_AAS_FBCK_RSP_DATA_TYPE_MASK	0x20
#define OFDMA_AAS_FBCK_REQ_FB_RSP_COUNTER_MASK	0x1C
#define OFDMA_AAS_FBCK_REQ_FB_RSP_RESOLUTION_MASK	0x03

void proto_register_mac_mgmt_msg_aas_fbck(void);
void proto_reg_handoff_mac_mgmt_msg_aas(void);

static gint proto_mac_mgmt_msg_aas_fbck_decoder = -1;
static gint ett_mac_mgmt_msg_aas_fbck_req_decoder = -1;
static gint ett_mac_mgmt_msg_aas_fbck_rsp_decoder = -1;

static const value_string vals_data_types[] =
{
    {0, "measure on downlink preamble only"},
    {1, "measure on downlink data (for this SS) only"},
    {0,  NULL}
};

static const value_string vals_resolutions_0[] =
{
    {0, "32 subcarriers"},
    {1, "64 subcarriers"},
    {2, "128 subcarriers"},
    {3, "256 subcarriers"},
    {0,  NULL}
};

static const value_string vals_resolutions_1[] =
{
    {0, "1 subcarrier"},
    {1, "4 subcarriers"},
    {2, "8 subcarriers"},
    {3, "16 subcarriers"},
    {0,  NULL}
};

/* fix fields */
/* static int hf_aas_fbck_unknown_type = -1; */
static int hf_aas_fbck_frame_number = -1;
static int hf_aas_fbck_number_of_frames = -1;
static int hf_aas_fbck_req_data_type = -1;
static int hf_aas_fbck_rsp_data_type = -1;
static int hf_aas_fbck_req_counter = -1;
static int hf_aas_fbck_rsp_counter = -1;
static int hf_aas_fbck_req_resolution_0 = -1;
static int hf_aas_fbck_rsp_resolution_0 = -1;
static int hf_aas_fbck_req_resolution_1 = -1;
static int hf_aas_fbck_rsp_resolution_1 = -1;
static int hf_aas_fbck_req_reserved = -1;
static int hf_aas_fbck_rsp_reserved = -1;
static int hf_aas_fbck_freq_value_re = -1;
static int hf_aas_fbck_freq_value_im = -1;
static int hf_aas_fbck_rssi_value = -1;
static int hf_aas_fbck_cinr_value = -1;


void dissect_mac_mgmt_msg_aas_fbck_req_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint offset = 0;
	guint data_type;
	proto_item *aas_fbck_item;
	proto_tree *aas_fbck_tree;

	{	/* we are being asked for details */

		/* display MAC message type */
		aas_fbck_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_aas_fbck_decoder, tvb, offset, -1, "AAS Channel Feedback Request (AAS-FBCK-REQ)");
		/* add subtree */
		aas_fbck_tree = proto_item_add_subtree(aas_fbck_item, ett_mac_mgmt_msg_aas_fbck_req_decoder);
		/* Display the AAS-FBCK-REQ message type */

		/* Decode and display the AAS-FBCK-REQ message body */
		/* display the Frame Number */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_frame_number, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* get the data type */
		data_type = tvb_get_guint8(tvb, offset);
		/* display the number of Frames */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_number_of_frames, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Data Type */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_req_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the Feedback Request Counter */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_req_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Frequency Measurement Resolution */
		if(data_type & OFDMA_AAS_FBCK_REQ_DATA_TYPE_MASK)
			proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_req_resolution_1, tvb, offset, 1, ENC_BIG_ENDIAN);
		else
			proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_req_resolution_0, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the reserved fields */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_req_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
}

void dissect_mac_mgmt_msg_aas_fbck_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, data_type;
	proto_item *aas_fbck_item;
	proto_tree *aas_fbck_tree;

	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC message type */
		aas_fbck_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_aas_fbck_decoder, tvb, offset, -1, "AAS Channel Feedback Response (AAS-FBCK-RSP)");
		/* add subtree */
		aas_fbck_tree = proto_item_add_subtree(aas_fbck_item, ett_mac_mgmt_msg_aas_fbck_rsp_decoder);
		/* Display the AAS-FBCK-RSP message type */

		/* get the data type */
		data_type = tvb_get_guint8(tvb, offset);
		/* Decode and display the AAS-FBCK-RSP message body */
		/* display the reserved fields */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_rsp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Data Type */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_rsp_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Feedback Request Counter */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_rsp_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Frequency Measurement Resolution */
		if(data_type & OFDMA_AAS_FBCK_RSP_DATA_TYPE_MASK)
			proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_rsp_resolution_1, tvb, offset, 1, ENC_BIG_ENDIAN);
		else
			proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_rsp_resolution_0, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		for(; offset < (tvb_len - 2); )
		{
			/* display the Frequency Value (real part) */
			proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_freq_value_re, tvb, offset, 1, ENC_BIG_ENDIAN);
			/* move to next field */
			offset++;
			/* display the Frequency Value (imaginary part) */
			proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_freq_value_im, tvb, offset, 1, ENC_BIG_ENDIAN);
			/* move to next field */
			offset++;
		}
		/* display the RSSI Mean Value */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_rssi_value, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* display the CINR Mean Value */
		proto_tree_add_item(aas_fbck_tree, hf_aas_fbck_cinr_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_aas_fbck(void)
{
	/* AAS-FBCK display */
	static hf_register_info hf_aas_fbck[] =
	{
		{
			&hf_aas_fbck_cinr_value,
			{
				"CINR Mean Value", "wmx.aas_fbck.cinr_mean_value",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_req_counter,
			{
				"Feedback Request Counter", "wmx.aas_fbck.counter",
				FT_UINT8, BASE_DEC, NULL, OFDMA_AAS_FBCK_REQ_FB_REQ_COUNTER_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_frame_number,
			{
				"Frame Number", "wmx.aas_fbck.frame_number",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_freq_value_re,
			{
				"Frequency Value (real part)", "wmx.aas_fbck.freq_value_re",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_freq_value_im,
			{
				"Frequency Value (imaginary part)", "wmx.aas_fbck.freq_value_im",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_number_of_frames,
			{
				"Number Of Frames", "wmx.aas_fbck.number_of_frames",
				FT_UINT8, BASE_DEC, NULL, OFDMA_AAS_FBCK_REQ_NUMBER_OF_FRAME_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_req_resolution_0,
			{
				"Frequency Measurement Resolution", "wmx.aas_fbck.resolution",
				FT_UINT8, BASE_DEC, VALS(vals_resolutions_0), OFDMA_AAS_FBCK_REQ_FB_REQ_RESOLUTION_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_req_resolution_1,
			{
				"Frequency Measurement Resolution", "wmx.aas_fbck.resolution",
				FT_UINT8, BASE_DEC, VALS(vals_resolutions_1), OFDMA_AAS_FBCK_REQ_FB_REQ_RESOLUTION_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_rssi_value,
			{
				"RSSI Mean Value", "wmx.aas_fbck.rssi_mean_value",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#if 0
		{
			&hf_aas_fbck_unknown_type,
			{
				"Unknown TLV type", "wmx.aas_fbck.unknown_type",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
#endif
		{
			&hf_aas_fbck_req_data_type,
			{
				"Measurement Data Type", "wmx.aas_fbck_req.data_type",
				FT_UINT8, BASE_DEC, VALS(vals_data_types), OFDMA_AAS_FBCK_REQ_DATA_TYPE_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_req_reserved,
			{
				"Reserved", "wmx.aas_fbck_req.reserved",
				FT_UINT8, BASE_HEX, NULL, OFDMA_AAS_FBCK_REQ_FB_REQ_RESERVED_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_rsp_counter,
			{
				"Feedback Request Counter", "wmx.aas_fbck_rsp.counter",
				FT_UINT8, BASE_DEC, NULL, OFDMA_AAS_FBCK_REQ_FB_RSP_COUNTER_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_rsp_data_type,
			{
				"Measurement Data Type", "wmx.aas_fbck_rsp.data_type",
				FT_UINT8, BASE_DEC, VALS(vals_data_types), OFDMA_AAS_FBCK_RSP_DATA_TYPE_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_rsp_reserved,
			{
				"Reserved", "wmx.aas_fbck_rsp.reserved",
				FT_UINT8, BASE_HEX, NULL, OFDMA_AAS_FBCK_REQ_FB_RSP_RESERVED_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_rsp_resolution_0,
			{
				"Frequency Measurement Resolution", "wmx.aas_fbck_rsp.resolution",
				FT_UINT8, BASE_DEC, VALS(vals_resolutions_0), OFDMA_AAS_FBCK_REQ_FB_RSP_RESOLUTION_MASK, NULL, HFILL
			}
		},
		{
			&hf_aas_fbck_rsp_resolution_1,
			{
				"Frequency Measurement Resolution", "wmx.aas_fbck_rsp.resolution",
				FT_UINT8, BASE_DEC, VALS(vals_resolutions_1), OFDMA_AAS_FBCK_REQ_FB_RSP_RESOLUTION_MASK, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_aas_fbck_req_decoder,
			&ett_mac_mgmt_msg_aas_fbck_rsp_decoder,
		};

	proto_mac_mgmt_msg_aas_fbck_decoder = proto_register_protocol (
		"WiMax AAS-FEEDBACK Messages", /* name       */
		"WiMax AAS-FEEDBACK (aas)",    /* short name */
		"wmx.aas"                           /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_aas_fbck_decoder, hf_aas_fbck, array_length(hf_aas_fbck));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mac_mgmt_msg_aas(void)
{
	dissector_handle_t aas_handle;

	aas_handle = create_dissector_handle(dissect_mac_mgmt_msg_aas_fbck_req_decoder, proto_mac_mgmt_msg_aas_fbck_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_AAS_FBCK_REQ, aas_handle);

	aas_handle = create_dissector_handle(dissect_mac_mgmt_msg_aas_fbck_rsp_decoder, proto_mac_mgmt_msg_aas_fbck_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_AAS_FBCK_RSP, aas_handle);
}
