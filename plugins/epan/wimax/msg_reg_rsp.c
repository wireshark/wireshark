/* msg_reg_rsp.c
 * WiMax MAC Management REG-RSP Message decoder
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

#define WIMAX_16E_2005

#define         FRAG_LAST                       0x1

#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"
#include "wimax_prefs.h"

void proto_register_mac_mgmt_msg_reg_rsp(void);
void proto_reg_handoff_mac_mgmt_msg_reg_rsp(void);

static dissector_handle_t reg_rsp_handle;

static dissector_handle_t dsc_rsp_handle;

static int proto_mac_mgmt_msg_reg_rsp_decoder;
static int ett_mac_mgmt_msg_reg_rsp_decoder;
static int ett_reg_rsp_message_tree;

/* NCT messages */

/* REG-RSP fields */
static int hf_reg_rsp_status;
static int hf_tlv_type;
/* static int hf_tlv_value; */
static int hf_reg_rsp_secondary_mgmt_cid;
static int hf_reg_invalid_tlv;
static int hf_reg_rsp_new_cid_after_ho;
static int hf_reg_rsp_service_flow_id;
static int hf_reg_rsp_system_resource_retain_time;
static int hf_reg_total_provisioned_sf;

/* STRING RESOURCES */

static const value_string vals_reg_rsp_status [] = {
	{0, "OK"},
	{1, "Message authentication failure"},
	{0, NULL}
};



/* Decode REG-RSP messages. */
static int dissect_mac_mgmt_msg_reg_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	unsigned offset = 0;
	unsigned tlv_offset;
	unsigned tvb_len;
	proto_item *reg_rsp_item;
	proto_tree *reg_rsp_tree;
	proto_item *tlv_item = NULL;
	proto_tree *tlv_tree = NULL;
	proto_tree *sub_tree = NULL;
	bool hmac_found = false;
	tlv_info_t tlv_info;
	int tlv_type;
	unsigned tlv_len;
	unsigned this_offset = 0;
	tlv_info_t sub_tlv_info;
	int sub_tlv_type;
	int sub_tlv_len;
	unsigned sub_tlv_offset;

	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type REG-RSP */
		reg_rsp_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, offset, tvb_len, "MAC Management Message, REG-RSP");
		/* add MAC REG-RSP subtree */
		reg_rsp_tree = proto_item_add_subtree(reg_rsp_item, ett_mac_mgmt_msg_reg_rsp_decoder);
		proto_tree_add_item(reg_rsp_tree, hf_reg_rsp_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		while (offset < tvb_len)
		{
			/* Get the TLV data. */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if (tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "REG-RSP TLV error");
				proto_tree_add_item(reg_rsp_tree, hf_reg_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
				break;
			}
			/* get the offset to the TLV data */
			tlv_offset = offset + get_tlv_value_offset(&tlv_info);

			switch (tlv_type) {
				case REG_ARQ_PARAMETERS:
				case REG_SS_MGMT_SUPPORT:
				case REG_IP_MGMT_MODE:
				case REG_IP_VERSION:
				case REG_UL_TRANSPORT_CIDS_SUPPORTED:
				case REG_IP_PHS_SDU_ENCAP:
				case REG_MAX_CLASSIFIERS_SUPPORTED:
				case REG_PHS_SUPPORT:
				case REG_ARQ_SUPPORT:
				case REG_DSX_FLOW_CONTROL:
				case REG_MCA_FLOW_CONTROL:
				case REG_MCAST_POLLING_CIDS:
				case REG_NUM_DL_TRANS_CID:
				case REG_MAC_ADDRESS:
#ifdef WIMAX_16E_2005
				case REG_TLV_T_20_MAX_MAC_DATA_PER_FRAME_SUPPORT:
				case REG_TLV_T_21_PACKING_SUPPORT:
				case REG_TLV_T_22_MAC_EXTENDED_RTPS_SUPPORT:
				case REG_TLV_T_23_MAX_NUM_BURSTS_TRANSMITTED_CONCURRENTLY_TO_THE_MS:
				case REG_TLV_T_26_METHOD_FOR_ALLOCATING_IP_ADDR_SECONDARY_MGMNT_CONNECTION:
				case REG_TLV_T_27_HANDOVER_SUPPORTED:
				case REG_TLV_T_29_HO_PROCESS_OPTIMIZATION_MS_TIMER:
				case REG_TLV_T_31_MOBILITY_FEATURES_SUPPORTED:
				case REG_TLV_T_40_ARQ_ACK_TYPE:
				case REG_TLV_T_41_MS_HO_CONNECTIONS_PARAM_PROCESSING_TIME:
				case REG_TLV_T_42_MS_HO_TEK_PROCESSING_TIME:
				case REG_TLV_T_43_MAC_HEADER_AND_EXTENDED_SUBHEADER_SUPPORT:
				case REG_POWER_SAVING_CLASS_CAPABILITY:
#endif
					dissect_extended_tlv(reg_rsp_tree, tlv_type, tvb, tlv_offset, tlv_len, pinfo, offset, proto_mac_mgmt_msg_reg_rsp_decoder);
					break;
				case REG_RSP_SECONDARY_MGMT_CID:
					add_tlv_subtree(&tlv_info, reg_rsp_tree, hf_reg_rsp_secondary_mgmt_cid, tvb, offset, ENC_BIG_ENDIAN);
					break;

				case REG_RSP_TLV_T_36_TOTAL_PROVISIONED_SERVICE_FLOW_DSAs:
					add_tlv_subtree(&tlv_info, reg_rsp_tree, hf_reg_total_provisioned_sf, tvb, offset, ENC_BIG_ENDIAN);
					break;

				case REG_RSP_TLV_T_24_CID_UPDATE_ENCODINGS:
					/* Display CID update encodings */
					/* add subtree */
					sub_tree = add_protocol_subtree(&tlv_info, ett_reg_rsp_message_tree, reg_rsp_tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, offset, tlv_len, "CID update encodings");
					/* Use a local copy of tlv_offset */
					this_offset = tlv_offset;
					while(this_offset < tlv_len) {
						/* Get the sub TLV data. */
						init_tlv_info(&sub_tlv_info, tvb, this_offset);
						/* get the sub TLV type */
						sub_tlv_type = get_tlv_type(&sub_tlv_info);
						/* get the TLV length */
						sub_tlv_len = get_tlv_length(&sub_tlv_info);
						if (sub_tlv_type == -1 || sub_tlv_len > MAX_TLV_LEN || sub_tlv_len < 1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "REG-RSP TLV error");
							proto_tree_add_item(reg_rsp_tree, hf_reg_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
							break;
						}
						/* get the offset to the sub TLV data */
						sub_tlv_offset = this_offset + get_tlv_value_offset(&sub_tlv_info);
						switch (sub_tlv_type) {
							case REG_RSP_TLV_T_24_1_CID_UPDATE_ENCODINGS_NEW_CID:
								add_tlv_subtree(&sub_tlv_info, sub_tree, hf_reg_rsp_new_cid_after_ho, tvb, this_offset, ENC_BIG_ENDIAN);
								break;
							case REG_RSP_TLV_T_24_2_CID_UPDATE_ENCODINGS_SFID:
								add_tlv_subtree(&sub_tlv_info, sub_tree, hf_reg_rsp_service_flow_id, tvb, this_offset, ENC_BIG_ENDIAN);
								break;
							case REG_RSP_TLV_T_24_3_CID_UPDATE_ENCODINGS_CONNECTION_INFO:
								tlv_tree = add_protocol_subtree(&sub_tlv_info, ett_reg_rsp_message_tree, sub_tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, this_offset, sub_tlv_len, "CID Update Encodings Connection Info");
								/* Decode the DSC_RSP subTLV's */
								call_dissector(dsc_rsp_handle, tvb_new_subset_length(tvb, sub_tlv_offset, sub_tlv_len), pinfo, tlv_tree);
								break;
							default:
								add_tlv_subtree(&sub_tlv_info, sub_tree, hf_tlv_type, tvb, this_offset, ENC_NA);
								break;
						}
						this_offset = sub_tlv_len + sub_tlv_offset;
					}
					break;
				case REG_RSP_TLV_T_28_HO_SYSTEM_RESOURCE_RETAIN_TIME:
					tlv_item = add_tlv_subtree(&tlv_info, reg_rsp_tree, hf_reg_rsp_system_resource_retain_time, tvb, offset, ENC_BIG_ENDIAN);
					if (include_cor2_changes) {
						proto_item_append_text(tlv_item, " (in units of 100 milliseconds)");
					} else {
						proto_item_append_text(tlv_item, " (multiple of 100 milliseconds)");
					}
					break;
				case DSx_UPLINK_FLOW:
					/* display Uplink Service Flow Encodings info */
					/* add subtree */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_rsp_decoder, reg_rsp_tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, offset, tlv_len, "Uplink Service Flow Encodings");
					/* decode and display the DL Service Flow Encodings */
					wimax_service_flow_encodings_decoder(tvb_new_subset_length(tvb, tlv_offset, tlv_len), pinfo, tlv_tree);
					break;
				case DSx_DOWNLINK_FLOW:
					/* display Downlink Service Flow Encodings info */
					/* add subtree */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_rsp_decoder, reg_rsp_tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, offset, tlv_len, "Downlink Service Flow Encodings");
					/* decode and display the DL Service Flow Encodings */
					wimax_service_flow_encodings_decoder(tvb_new_subset_length(tvb, tlv_offset, tlv_len), pinfo, tlv_tree);
					break;
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_rsp_decoder, reg_rsp_tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, offset, tlv_len, "HMAC Tuple");
					wimax_hmac_tuple_decoder(tlv_tree, tvb, offset+2, tlv_len);
					hmac_found = true;
					break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_rsp_decoder, reg_rsp_tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, offset, tlv_len, "CMAC Tuple");
					wimax_cmac_tuple_decoder(tlv_tree, tvb, offset+2, tlv_len);
					break;
				case SHORT_HMAC_TUPLE:
				case SHORT_HMAC_TUPLE_COR2:
					if ((!include_cor2_changes && (tlv_type == SHORT_HMAC_TUPLE)) ||
						(include_cor2_changes && (tlv_type == SHORT_HMAC_TUPLE_COR2))) {
						/* decode and display the Short HMAC Tuple */
						tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_rsp_decoder, reg_rsp_tree, proto_mac_mgmt_msg_reg_rsp_decoder, tvb, offset, tlv_len, "Short HMAC Tuple");
						wimax_short_hmac_tuple_decoder(tlv_tree, tvb, tlv_offset, tlv_len);
					} else {
						/* Unknown TLV Type */
						add_tlv_subtree(&tlv_info, reg_rsp_tree, hf_tlv_type, tvb, offset, ENC_NA);
					}
					break;
				case VENDOR_SPECIFIC_INFO:
				case VENDOR_ID_ENCODING:
				case MAC_VERSION_ENCODING:
					wimax_common_tlv_encoding_decoder(tvb_new_subset_length(tvb, offset, (tvb_len - offset)), pinfo, reg_rsp_tree);
					break;
				default:
					add_tlv_subtree(&tlv_info, reg_rsp_tree, hf_tlv_type, tvb, offset, ENC_NA);
					break;
			}

			offset = tlv_len + tlv_offset;
		}	/* end of TLV process while loop */
		if (!hmac_found)
			proto_item_append_text(reg_rsp_tree, " (HMAC Tuple is missing !)");
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_reg_rsp(void)
{
	/* REG-RSP fields display */
	static hf_register_info hf[] =
	{
		{
			&hf_reg_invalid_tlv,
			{
				"Invalid TLV", "wmx.reg_rsp.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_reg_rsp_new_cid_after_ho,
			{
				"New CID after handover to new BS", "wmx.reg_rsp.new_cid_after_ho",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_rsp_status,
			{
				"Response", "wmx.reg_rsp.response",
				FT_UINT8, BASE_HEX, VALS(vals_reg_rsp_status), 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_rsp_secondary_mgmt_cid,
			{
				"Secondary Management CID", "wmx.reg_rsp.secondary_mgmt_cid",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_total_provisioned_sf,
			{
				"Total Number of Provisional Service Flow", "wmx.reg_rsp.total_provisional_sf",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_rsp_service_flow_id,
			{
				"Service flow ID", "wmx.reg_rsp.service_flow_id",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_rsp_system_resource_retain_time,
			{
				"System Resource Retain Time", "wmx.reg_rsp.system_resource_retain_time",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_tlv_type,
			{
				"Unknown TLV Type", "wmx.reg_rsp.unknown_tlv_type",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
#if 0
		{
			&hf_tlv_value,
			{
				"Value", "wmx.reg_rsp.tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		}
#endif
	};

	/* Setup protocol subtree array */
	static int *ett[] =
		{
			&ett_mac_mgmt_msg_reg_rsp_decoder,
			&ett_reg_rsp_message_tree
		};

	proto_mac_mgmt_msg_reg_rsp_decoder = proto_register_protocol (
		"WiMax REG-RSP Messages", /* name       */
		"WiMax REG-RSP",    /* short name */
		"wmx.reg_rsp"                     /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_reg_rsp_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	reg_rsp_handle = register_dissector("mac_mgmt_msg_reg_rsp_handler", dissect_mac_mgmt_msg_reg_rsp_decoder, proto_mac_mgmt_msg_reg_rsp_decoder);
}

void proto_reg_handoff_mac_mgmt_msg_reg_rsp(void)
{
	dsc_rsp_handle = find_dissector("mac_mgmt_msg_dsc_rsp_handler");
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_REG_RSP, reg_rsp_handle);
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
