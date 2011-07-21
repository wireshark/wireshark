/* msg_dreg.c
 * WiMax MAC Management DREG-REQ, DREG-CMD Message decoders
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
static void dissect_dreg_tlv(proto_tree *dreg_tree, gint tlv_type, tvbuff_t *tvb, guint tlv_offset, guint tlv_len);
void dissect_mac_mgmt_msg_dreg_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_mac_mgmt_msg_dreg_cmd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint proto_mac_mgmt_msg_dreg_req_decoder = -1;
static gint proto_mac_mgmt_msg_dreg_cmd_decoder = -1;

static gint ett_mac_mgmt_msg_dreg_decoder = -1;

/* Setup protocol subtree array */
static gint *ett[] =
{
	&ett_mac_mgmt_msg_dreg_decoder,
};

/* DREG fields */
static gint hf_dreg_cmd_message_type = -1;
static gint hf_dreg_req_message_type = -1;
static gint hf_ack_type_reserved = -1;
static gint hf_dreg_cmd_action = -1;
static gint hf_dreg_cmd_action_cor2 = -1;
static gint hf_dreg_cmd_reserved = -1;
static gint hf_dreg_paging_cycle = -1;
static gint hf_dreg_paging_offset = -1;
static gint hf_dreg_paging_group_id = -1;
static gint hf_dreg_req_duration = -1;
static gint hf_paging_controller_id = -1;
static gint hf_mac_hash_skip_threshold = -1;
static gint hf_dreg_paging_cycle_request = -1;
static gint hf_dreg_retain_ms_service_sbc = -1;
static gint hf_dreg_retain_ms_service_pkm = -1;
static gint hf_dreg_retain_ms_service_reg = -1;
static gint hf_dreg_retain_ms_service_network_address = -1;
static gint hf_dreg_retain_ms_service_tod = -1;
static gint hf_dreg_retain_ms_service_tftp = -1;
static gint hf_dreg_retain_ms_service_full_service = -1;
static gint hf_dreg_consider_paging_pref = -1;
static gint hf_tlv_value = -1;
static gint hf_dreg_req_action = -1;
static gint hf_dreg_req_reserved = -1;
static gint hf_dreg_invalid_tlv = -1;

/* STRING RESOURCES */
static const value_string vals_dreg_req_code[] = {
	{0, "SS De-Registration request from BS and network"},
	{1, "MS request for De-Registration from serving BS and initiation of Idle Mode"},
	{2, "MS response for the Unsolicited De-Registration initiated by BS"},
	{3, "Reject for the unsolicited DREG-CMD with action \
code 05 (idle mode request) by the BS.  \
Applicable only when MS has pending UL data to transmit"},
	{4, "Reserved"},
	{0,				NULL}
};

static const value_string vals_dreg_cmd_action[] = {
	{0, "SS shall immediately terminate service with the BS and \
should attempt network entry at another BS"},
	{1, "SS shall listen to the current channel BS but shall not \
transmit until an RES-CMD message or DREG-CMD with \
Action Code 02 or 03 is received"},
	{2, "SS shall listen to the BS but only transmit \
on the Basic, and Primary Management Connections"},
	{3, "SS shall return to normal operation and may transmit on \
any of its active connections"},
	{4, "SS shall terminate current Normal Operations with the BS; \
the BS shall transmit this action code only in response \
to any SS DREG-REQ message"},
	{5, "MS shall immediately begin de-registration from serving \
BS and request initiation of MS Idle Mode"},
	{6, "The MS may retransmit the DREG-REQ message after the \
time duration (REQ-duration) provided in the message"},
	{7, "The MS shall not retransmit the DREG-REQ message and shall \
wait for the DREG-CMD message. BS transmittal of a \
subsequent DREG-CMD with Action Code 03 shall cancel \
this restriction"},
	{0,				NULL}
};

static const value_string vals_dreg_cmd_action_cor2[] = {
	{0, "SS shall immediately terminate service with the BS and \
should attempt network entry at another BS"},
	{1, "SS shall listen to the current channel BS but shall not \
transmit until an RES-CMD message or DREG-CMD with \
Action Code 02 or 03 is received"},
	{2, "SS shall listen to the BS but only transmit \
on the Basic, and Primary Management Connections"},
	{3, "SS shall return to normal operation and may transmit on \
any of its active connections"},
	{4, "Only valid in response to a DREG-REQ message with DREG \
Code = 00.  SS shall terminate current Normal Operations with the BS"},
	{5, "MS shall immediately begin de-registration from serving \
BS and request initiation of MS Idle Mode"},
	{6, "Only valid in response to a DREG-REQ message with DREG \
Code = 01.  The MS may retransmit the DREG-REQ message after the \
REQ-duration provided in the message; \
BS sending a subsequent DREG-CMD message with \
Action Code 03 cancels this restriction"},
	{0,				NULL}
};

/* Decode sub-TLV's of either DREG-REQ or DREG-CMD. */
static void dissect_dreg_tlv(proto_tree *dreg_tree, gint tlv_type, tvbuff_t *tvb, guint tlv_offset, guint tlv_len)
{
	switch (tlv_type) {
		case DREG_PAGING_INFO:
			proto_tree_add_item(dreg_tree, hf_dreg_paging_cycle, tvb, tlv_offset, 2, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_paging_offset, tvb, tlv_offset + 2, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_paging_group_id, tvb, tlv_offset + 3, 2, FALSE);
			break;
		case DREG_REQ_DURATION:
			proto_tree_add_item(dreg_tree, hf_dreg_req_duration, tvb, tlv_offset, 1, FALSE);
			break;
		case DREG_PAGING_CONTROLLER_ID:
			proto_tree_add_item(dreg_tree, hf_paging_controller_id, tvb, tlv_offset, 6, FALSE);
			break;
		case DREG_IDLE_MODE_RETAIN_INFO:
			proto_tree_add_item(dreg_tree, hf_dreg_retain_ms_service_sbc, tvb, tlv_offset, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_retain_ms_service_pkm, tvb, tlv_offset, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_retain_ms_service_reg, tvb, tlv_offset, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_retain_ms_service_network_address, tvb, tlv_offset, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_retain_ms_service_tod, tvb, tlv_offset, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_retain_ms_service_tftp, tvb, tlv_offset, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_retain_ms_service_full_service, tvb, tlv_offset, 1, FALSE);
			proto_tree_add_item(dreg_tree, hf_dreg_consider_paging_pref, tvb, tlv_offset, 1, FALSE);
			break;
		case DREG_MAC_HASH_SKIP_THRESHOLD:
			proto_tree_add_item(dreg_tree, hf_mac_hash_skip_threshold, tvb, tlv_offset, 2, FALSE);
			break;
		case DREG_PAGING_CYCLE_REQUEST:
			proto_tree_add_item(dreg_tree, hf_dreg_paging_cycle_request, tvb, tlv_offset, 2, FALSE);
			break;
		default:
			proto_tree_add_item(dreg_tree, hf_tlv_value, tvb, tlv_offset, tlv_len, FALSE);
			break;
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dreg_req(void)
{
	/* DREG fields display */
	static hf_register_info hf[] =
	{
		{
			&hf_dreg_consider_paging_pref,
			{
				"Consider Paging Preference of each Service Flow in resource retention", "wmx.dreg.consider_paging_preference",
				FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL
			}
		},
		{
			&hf_dreg_invalid_tlv,
			{
				"Invalid TLV", "wmx.dreg.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mac_hash_skip_threshold,
			{
				"MAC Hash Skip Threshold", "wmx.dreg.mac_hash_skip_threshold",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_paging_controller_id,
			{
				"Paging Controller ID", "wmx.dreg.paging_controller_id",
				FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_paging_cycle,
			{
				"PAGING CYCLE", "wmx.dreg.paging_cycle",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_paging_cycle_request,
			{
				"Paging Cycle Request", "wmx.dreg.paging_cycle_request",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_paging_group_id,
			{
				"Paging-group-ID", "wmx.dreg.paging_group_id",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_paging_offset,
			{
				"PAGING OFFSET", "wmx.dreg.paging_offset",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_req_duration,
			{
				"REQ-duration (Waiting value for the DREG-REQ message re-transmission in frames)", "wmx.dreg.req_duration",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_retain_ms_service_full_service,
			{
				"Retain MS service and operation information associated with Full service", "wmx.dreg.retain_ms_full_service",
				FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL
			}
		},
		{
			&hf_dreg_retain_ms_service_network_address,
			{
				"Retain MS service and operational information associated with Network Address", "wmx.dreg.retain_ms_service_network_address",
				FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL
			}
		},
		{
			&hf_dreg_retain_ms_service_pkm,
			{
				"Retain MS service and operational information associated with PKM-REQ/RSP", "wmx.dreg.retain_ms_service_pkm",
				FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL
			}
		},
		{
			&hf_dreg_retain_ms_service_reg,
			{
				"Retain MS service and operational information associated with REG-REQ/RSP", "wmx.dreg.retain_ms_service_reg",
				FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL
			}
		},
		{
			&hf_dreg_retain_ms_service_sbc,
			{
				"Retain MS service and operational information associated with SBC-REQ/RSP", "wmx.dreg.retain_ms_service_sbc",
				FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_dreg_retain_ms_service_tftp,
			{
				"Retain MS service and operational information associated with TFTP messages", "wmx.dreg.retain_ms_service_tftp",
				FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL
			}
		},
		{
			&hf_dreg_retain_ms_service_tod,
			{
				"Retain MS service and operational information associated with Time of Day", "wmx.dreg.retain_ms_service_tod",
				FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL
			}
		},
		{
			&hf_dreg_cmd_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dreg_cmd",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_cmd_action,
			{
				"DREG-CMD Action code", "wmx.dreg_cmd.action",
				FT_UINT8, BASE_DEC, VALS(vals_dreg_cmd_action), 0x07, NULL, HFILL
			}
		},
		{
			&hf_dreg_cmd_action_cor2,
			{
				"DREG-CMD Action code", "wmx.dreg_cmd.action",
				FT_UINT8, BASE_DEC, VALS(vals_dreg_cmd_action_cor2), 0x07, NULL, HFILL
			}
		},
		{
			&hf_dreg_cmd_reserved,
			{
				"Reserved", "wmx.dreg_cmd.action_reserved",
				FT_UINT8, BASE_DEC, NULL, 0xF8, NULL, HFILL
			}
		},
		{
			&hf_dreg_req_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dreg_req",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dreg_req_action,
			{
				"DREG-REQ Action code", "wmx.dreg_req.action",
				FT_UINT8, BASE_DEC, VALS(vals_dreg_req_code), 0x03, NULL, HFILL
			}
		},
		{
			&hf_dreg_req_reserved,
			{
				"Reserved", "wmx.dreg_req.action_reserved",
				FT_UINT8, BASE_DEC, NULL, 0xFC, NULL, HFILL
			}
		},
		{
			&hf_tlv_value,
			{
				"Value", "wmx.dreg.unknown_tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_ack_type_reserved,
			{
				"Reserved", "wmx.ack_type_reserved",
				FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL
			}
		}
	};

	proto_mac_mgmt_msg_dreg_req_decoder = proto_register_protocol (
		"WiMax DREG-REQ/CMD Messages", /* name */
		"WiMax DREG-REQ/CMD (dreg)", /* short name */
		"wmx.dreg" /* abbrev */
		);

	proto_register_field_array(proto_mac_mgmt_msg_dreg_req_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dreg_cmd(void)
{
	proto_mac_mgmt_msg_dreg_cmd_decoder = proto_mac_mgmt_msg_dreg_req_decoder;
}

/* Decode DREG-REQ messages. */
void dissect_mac_mgmt_msg_dreg_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tlv_offset;
	guint tvb_len, payload_type;
	proto_item *dreg_req_item = NULL;
	proto_tree *dreg_req_tree = NULL;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;
	gint tlv_type;
	gint tlv_len;
	gboolean hmac_found = FALSE;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, 0);
	if(payload_type != MAC_MGMT_MSG_DREG_REQ)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type DREG-REQ */
		dreg_req_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dreg_req_decoder, tvb, 0, tvb_len, "MAC Management Message, DREG-REQ (49)");
		/* add MAC DREG REQ subtree */
		dreg_req_tree = proto_item_add_subtree(dreg_req_item, ett_mac_mgmt_msg_dreg_decoder);
		/* display the Message Type */
		proto_tree_add_item(dreg_req_tree, hf_dreg_req_message_type, tvb, offset, 1, FALSE);
		offset++;
		/* display the Action Code */
		proto_tree_add_item(dreg_req_tree, hf_dreg_req_action, tvb, offset, 1, FALSE);
		/* show the Reserved bits */
		proto_tree_add_item(dreg_req_tree, hf_dreg_req_reserved, tvb, offset, 1, FALSE);
		offset++;

		while(offset < tvb_len)
		{
			/* Get the TLV data. */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DREG-REQ TLV error");
				proto_tree_add_item(dreg_req_tree, hf_dreg_invalid_tlv, tvb, offset, (tvb_len - offset), FALSE);
				break;
			}
			/* get the offset to the TLV data */
			tlv_offset = offset + get_tlv_value_offset(&tlv_info);

			switch (tlv_type) {
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dreg_decoder, dreg_req_tree, proto_mac_mgmt_msg_dreg_req_decoder, tvb, tlv_offset, tlv_len, "HMAC Tuple (%u byte(s))", tlv_len);
					wimax_hmac_tuple_decoder(tlv_tree, tvb, tlv_offset, tlv_len);
					hmac_found = TRUE;
					break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dreg_decoder, dreg_req_tree, proto_mac_mgmt_msg_dreg_req_decoder, tvb, tlv_offset, tlv_len, "CMAC Tuple (%u byte(s))", tlv_len);
					wimax_cmac_tuple_decoder(tlv_tree, tvb, tlv_offset, tlv_len);
					break;
				default:
					/* Decode DREG-REQ sub-TLV's */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dreg_decoder, dreg_req_tree, proto_mac_mgmt_msg_dreg_req_decoder, tvb, tlv_offset, tlv_len, "DREG-REQ sub-TLV's (%u byte(s))", tlv_len);
					dissect_dreg_tlv(tlv_tree, tlv_type, tvb, tlv_offset, tlv_len);
					break;
			}


			offset = tlv_len + tlv_offset;
		}	/* end of TLV process while loop */
		if (!hmac_found)
			proto_item_append_text(dreg_req_tree, " (HMAC Tuple is missing !)");
	}
}

/* Decode DREG-CMD messages. */
void dissect_mac_mgmt_msg_dreg_cmd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tlv_offset;
	guint tvb_len, payload_type;
	proto_item *dreg_cmd_item = NULL;
	proto_tree *dreg_cmd_tree = NULL;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;
	gint tlv_type;
	gint tlv_len;
	gboolean hmac_found = FALSE;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, 0);
	if(payload_type != MAC_MGMT_MSG_DREG_CMD)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type DREG-CMD */
		dreg_cmd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dreg_cmd_decoder, tvb, 0, tvb_len, "MAC Management Message, DREG-CMD (29)");
		/* add MAC DREG CMD subtree */
		dreg_cmd_tree = proto_item_add_subtree(dreg_cmd_item, ett_mac_mgmt_msg_dreg_decoder);
		/* display the Message Type */
		proto_tree_add_item(dreg_cmd_tree, hf_dreg_cmd_message_type, tvb, offset, 1, FALSE);
		offset ++;
		/* display the Action Code */
		if (include_cor2_changes)
			proto_tree_add_item(dreg_cmd_tree, hf_dreg_cmd_action_cor2, tvb, offset, 1, FALSE);
		else
			proto_tree_add_item(dreg_cmd_tree, hf_dreg_cmd_action, tvb, offset, 1, FALSE);
		/* show the Reserved bits */
		proto_tree_add_item(dreg_cmd_tree, hf_dreg_cmd_reserved, tvb, offset, 1, FALSE);
		offset ++;

		while(offset < tvb_len)
		{
			/* Get the TLV data. */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DREG-CMD TLV error");
				proto_tree_add_item(dreg_cmd_tree, hf_dreg_invalid_tlv, tvb, offset, (tvb_len - offset), FALSE);
				break;
			}
			/* get the offset to the TLV data */
			tlv_offset = offset + get_tlv_value_offset(&tlv_info);

			switch (tlv_type) {
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dreg_decoder, dreg_cmd_tree, proto_mac_mgmt_msg_dreg_cmd_decoder, tvb, tlv_offset, tlv_len, "HMAC Tuple (%u byte(s))", tlv_len);
					wimax_hmac_tuple_decoder(tlv_tree, tvb, tlv_offset, tlv_len);
					hmac_found = TRUE;
					break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dreg_decoder, dreg_cmd_tree, proto_mac_mgmt_msg_dreg_cmd_decoder, tvb, tlv_offset, tlv_len, "CMAC Tuple (%u byte(s))", tlv_len);
					wimax_cmac_tuple_decoder(tlv_tree, tvb, tlv_offset, tlv_len);
					break;
				default:
					/* Decode DREG-CMD sub-TLV's */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dreg_decoder, dreg_cmd_tree, proto_mac_mgmt_msg_dreg_cmd_decoder, tvb, tlv_offset, tlv_len, "DREG-CMD sub-TLV's (%u byte(s))", tlv_len);
					dissect_dreg_tlv(tlv_tree, tlv_type, tvb, tlv_offset, tlv_len);
					break;
			}

			offset = tlv_len + tlv_offset;
		}	/* end of TLV process while loop */
		if (!hmac_found)
			proto_item_append_text(dreg_cmd_tree, " (HMAC Tuple is missing !)");
	}
}

