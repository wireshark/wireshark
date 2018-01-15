/* msg_fpc.c
 * WiMax MAC Management FPC Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: John R. Underwood <junderx@yahoo.com>
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

#include <epan/packet.h>
#include "wimax_mac.h"


void proto_register_mac_mgmt_msg_fpc(void);
void proto_reg_handoff_mac_mgmt_msg_fpc(void);

static gint proto_mac_mgmt_msg_fpc_decoder = -1;

static gint ett_mac_mgmt_msg_fpc_decoder = -1;

/* FPC fields */
static gint hf_fpc_number_of_stations = -1;
static gint hf_fpc_basic_cid = -1;
static gint hf_fpc_power_adjust = -1;
static gint hf_fpc_power_measurement_frame = -1;
/* static gint hf_fpc_invalid_tlv = -1; */


/* Decode FPC messages. */
static int dissect_mac_mgmt_msg_fpc_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	guint offset = 0;
	guint i;
	guint number_stations;
	guint tvb_len;
	proto_item *fpc_item;
	proto_tree *fpc_tree;
	gint8 value;
	gfloat power_change;

	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type FPC */
		fpc_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_fpc_decoder, tvb, 0, -1, "MAC Management Message, FPC");
		/* add MAC FPC subtree */
		fpc_tree = proto_item_add_subtree(fpc_item, ett_mac_mgmt_msg_fpc_decoder);

		/* display the Number of stations */
		proto_tree_add_item(fpc_tree, hf_fpc_number_of_stations, tvb, offset, 1, ENC_BIG_ENDIAN);

		number_stations = tvb_get_guint8(tvb, offset);
		offset++;
		for (i = 0; ((i < number_stations) && (offset >= tvb_len)); i++ ) {
			/* display the Basic CID*/
			proto_tree_add_item(fpc_tree, hf_fpc_basic_cid, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			/* display the Power adjust value */
			value = (gint8)tvb_get_guint8(tvb, offset);
			power_change = (float)0.25 * value;  /* 0.25dB incr */

			/* display the Power adjust value in dB */
			proto_tree_add_float_format_value(fpc_tree, hf_fpc_power_adjust, tvb, offset, 1, power_change, " %.2f dB", power_change);
			offset++;

			/* display the Power measurement frame */
			proto_tree_add_item(fpc_tree, hf_fpc_power_measurement_frame, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_fpc(void)
{
	/* FPC fields display */
	static hf_register_info hf[] =
	{
		{
			&hf_fpc_basic_cid,
			{
				"Basic CID", "wmx.fpc.basic_cid",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#if 0
		{
			&hf_fpc_invalid_tlv,
			{
				"Invalid TLV", "wmx.fpc.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
#endif
		{
			&hf_fpc_number_of_stations,
			{
				"Number of stations", "wmx.fpc.number_stations",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_fpc_power_adjust,
			{
				"Power Adjust", "wmx.fpc.power_adjust",
				FT_FLOAT, BASE_NONE, NULL, 0x0, "Signed change in power level (incr of 0.25dB) that the SS shall apply to its current power setting", HFILL
			}
		},
		{
			&hf_fpc_power_measurement_frame,
			{
				"Power measurement frame", "wmx.fpc.power_measurement_frame",
				FT_INT8, BASE_DEC, NULL, 0x0, "The 8 LSB of the frame number in which the BS measured the power corrections referred to in the message", HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_fpc_decoder,
		};

	proto_mac_mgmt_msg_fpc_decoder = proto_register_protocol (
		"WiMax FPC Message", /* name       */
		"WiMax FPC (fpc)",   /* short name */
		"wmx.fpc"            /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_fpc_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mac_mgmt_msg_fpc(void)
{
	dissector_handle_t fpc_handle;

	fpc_handle = create_dissector_handle(dissect_mac_mgmt_msg_fpc_decoder, proto_mac_mgmt_msg_fpc_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_FPC, fpc_handle);
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
