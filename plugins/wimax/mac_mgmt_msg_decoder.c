/* mac_mgmt_msg_decoder.c
 * WiMax MAC Management Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
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

#include <glib.h>
#include <epan/packet.h>
#include "wimax_mac.h"

extern gint proto_wimax;

extern void proto_register_wimax_utility_decoders(void);

extern void proto_register_mac_mgmt_msg_dcd(void);
extern void proto_register_mac_mgmt_msg_ucd(void);
extern void proto_register_mac_mgmt_msg_dlmap(void);
extern void proto_register_mac_mgmt_msg_ulmap(void);
extern void proto_register_mac_mgmt_msg_rng_req(void);
extern void proto_register_mac_mgmt_msg_rng_rsp(void);
extern void proto_register_mac_mgmt_msg_reg_req(void);
extern void proto_register_mac_mgmt_msg_reg_rsp(void);
extern void proto_register_mac_mgmt_msg_dsa(void);
extern void proto_register_mac_mgmt_msg_dsc(void);
extern void proto_register_mac_mgmt_msg_dsd(void);
extern void proto_register_mac_mgmt_msg_arq_feedback(void);
extern void proto_register_mac_mgmt_msg_arq_discard(void);
extern void proto_register_mac_mgmt_msg_arq_reset(void);
extern void proto_register_mac_mgmt_msg_dreg_req(void);
extern void proto_register_mac_mgmt_msg_dreg_cmd(void);
extern void proto_register_mac_mgmt_msg_fpc(void);
extern void proto_register_mac_mgmt_msg_sbc(void);
extern void proto_register_mac_mgmt_msg_pkm(void);
extern void proto_register_mac_mgmt_msg_pmc_req(void);
extern void proto_register_mac_mgmt_msg_pmc_rsp(void);
extern void proto_register_mac_mgmt_msg_prc_lt_ctrl(void);
extern void proto_register_mac_mgmt_msg_aas_fbck(void);
extern void proto_register_mac_mgmt_msg_aas_beam(void);
extern void proto_register_mac_mgmt_msg_res_cmd(void);
extern void proto_register_mac_mgmt_msg_rep(void);
extern void proto_register_mac_mgmt_msg_clk_cmp(void);
extern void proto_register_mac_mgmt_msg_dsx_rvd(void);

extern void dissect_mac_mgmt_msg_ucd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dcd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dlmap_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_ulmap_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_rng_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_rng_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_reg_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_reg_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_pkm_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_pkm_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsa_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsa_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsa_ack_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsc_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsc_ack_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsd_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsd_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_fpc_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_sbc_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_sbc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dreg_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dreg_cmd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_arq_feedback_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_arq_discard_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_arq_reset_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_pmc_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_pmc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_prc_lt_ctrl_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_aas_fbck_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_aas_fbck_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_aas_beam_select_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_res_cmd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_rep_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_rep_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_clk_cmp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_dsx_rvd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint proto_mac_mgmt_msg_decoder = -1;
static gint ett_mac_mgmt_msg_decoder = -1;

/* WIMAX MAC Management message type info */
static const char *mgt_msg_abbrv[MAC_MGMT_MSG_TYPE_MAX] =
{
	"UCD",		/* 0 */
	"DCD",
	"DL-MAP",
	"UL-MAP",
	"RNG-REQ",
	"RNG-RSP",
	"REG-REQ",
	"REG-RSP",
	"Reserved8",
	"PKM-REQ",
	"PKM-RSP",	/* 10 */
	"DSA-REQ",
	"DSA-RSP",
	"DSA-ACK",
	"DSC-REQ",
	"DSC-RSP",
	"DSC-ACK",
	"DSD-REQ",
	"DSD-RSP",
	"Reserved19",
	"Reserved20",		/* 20 */
	"MCA-REQ",
	"MCA-RSP",
	"DBPC-REQ",
	"DBPC-RSP",
	"RES-CMD",
	"SBC-REQ",
	"SBC-RSP",
	"CLK-CMP",
	"DREG-CMD",
	"DSX-RVD",	/* 30 */
	"TFTP-CPLT",
	"TFTP-RSP",
	"ARQ-FEEDBACK",
	"ARQ-DISCARD",
	"ARQ-RESET",
	"REP-REQ",
	"REP-RSP",
	"FPC",
	"MSH-NCFG",
	"MSH-NENT",	/* 40 */
	"MSH-DSCH",
	"MSH-CSCH",
	"MSH-CSCF",
	"AAS-FBCK_REQ",
	"AAS-FBCK_RSP",
	"AAS-BEAM_SELECT",
	"AAS-BEAM_REQ",
	"AAS-BEAM_RSP",
	"DREG-REQ",
	"MOB-SLP-REQ",	/* 50 */
	"MOB-SLP-RSP",
	"MOB-TRF-IND",
	"MOB-NBR-ADV",
	"MOB-SCN-REQ",
	"MOB-SCN-RSP",
	"MOB-BSHO-REQ",
	"MOB-MSHO-REQ",
	"MOB-BSHO-RSP",
	"MOB-HO-IND",
	"MOB-SCN-REP",	/* 60 */
	"MOB-PAG-ADV",
	"MBS-MAP",
	"PMC-REQ",
	"PMC-RSP",
	"PRC-LT-CTRL",
	"MOB-ASC-REP"
};

static gint hf_mac_mgmt_msg_values = -1;
static gint hf_mac_mgmt_msg_unknown_type = -1;


void dissect_mac_mgmt_msg_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, message_type;
	dissector_handle_t mgt_msg_handle;
	proto_item *parent_item = NULL;
	proto_item *message_item = NULL;
	proto_tree *message_tree = NULL;

	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		if(!tvb_len)
		{
			/* display the error message */
			proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "Error: Mac payload tvb is empty ! (%u bytes)", tvb_len);
			return;
		}
		/* Get the payload type */
		message_type = tvb_get_guint8(tvb, offset);
		/* add the payload type into the info column */
		if(message_type < MAC_MGMT_MSG_TYPE_MAX)
		{
			/* Display message type in Info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", mgt_msg_abbrv[message_type]);
		}
		else
		{
			col_append_str(pinfo->cinfo, COL_INFO, "Unknown message type,");
			/* display MAC payload types */
			message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "Unknown message type: %u (%u bytes)", message_type, tvb_len);
			/* add MAC payload subtree */
			message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
			/* display the MAC payload in Hex */
			proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			return;
		}
		/* get the parent */
		parent_item = proto_tree_get_parent(tree);
		/* add the MAC header info */
		proto_item_append_text(parent_item, ", %s", mgt_msg_abbrv[message_type]);
		/* Decode and display the MAC payload */
		switch (message_type)
		{
		case MAC_MGMT_MSG_UCD:
			/* UCD message handler */
			dissect_mac_mgmt_msg_ucd_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DCD:
			/* DCD message handler */
			dissect_mac_mgmt_msg_dcd_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DL_MAP:
			/* DL-MAP message handler */
			dissect_mac_mgmt_msg_dlmap_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_UL_MAP:
			/* UL-MAP message handler */
			dissect_mac_mgmt_msg_ulmap_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_RNG_REQ:
			/* Ranging request message handler */
			dissect_mac_mgmt_msg_rng_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_RNG_RSP:
			/* Ranging response message handler */
			dissect_mac_mgmt_msg_rng_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_REG_REQ:
			/* Registration request message handler */
			dissect_mac_mgmt_msg_reg_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_REG_RSP:
			/* Registration response message handler */
			dissect_mac_mgmt_msg_reg_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_PKM_REQ:
			/* Privacy Key Management request message handler */
			dissect_mac_mgmt_msg_pkm_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_PKM_RSP:
			/* Privacy Key Management response message handler */
			dissect_mac_mgmt_msg_pkm_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSA_REQ:
			/* Dynamic Service Addition request message handler */
			dissect_mac_mgmt_msg_dsa_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSA_RSP:
			/* Dynamic Service Addition response message handler */
			dissect_mac_mgmt_msg_dsa_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSA_ACK:
			/* Dynamic Service Addition acknowledge message handler */
			dissect_mac_mgmt_msg_dsa_ack_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSC_REQ:
			/* Dynamic Service Change request message handler */
			dissect_mac_mgmt_msg_dsc_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSC_RSP:
			/* Dynamic Service Change response message handler */
			dissect_mac_mgmt_msg_dsc_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSC_ACK:
			/* Dynamic Service Change acknowledge message handler */
			dissect_mac_mgmt_msg_dsc_ack_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSD_REQ:
			/* Dynamic Service Deletion request message handler */
			dissect_mac_mgmt_msg_dsd_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSD_RSP:
			/* Dynamic Service Deletion response message handler */
			dissect_mac_mgmt_msg_dsd_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_MCA_REQ:
			/* find the Multicast Assignment request message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mca_req_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MCA_RSP:
			/* find the Multicast Assignment response message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mca_rsp_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_DBPC_REQ:
			/* find the DL Burst Profile Change request message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_dbpc_req_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_DBPC_RSP:
			/* find the DL Burst Profile Change response message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_dbpc_rsp_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_RES_CMD:
			/* Reset Command message handler */
			dissect_mac_mgmt_msg_res_cmd_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_SBC_REQ:
			/* SS Basic Capability request message handler */
			dissect_mac_mgmt_msg_sbc_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_SBC_RSP:
			/* SS Basic Capability response message handler */
			dissect_mac_mgmt_msg_sbc_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_CLK_CMP:
			/* SS Network Clock Comparison message handler */
			dissect_mac_mgmt_msg_clk_cmp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DREG_CMD:
			/* De/Re-register Command message handler */
			dissect_mac_mgmt_msg_dreg_cmd_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_DSX_RVD:
			/* DSx Recieved message handler */
			dissect_mac_mgmt_msg_dsx_rvd_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_TFTP_CPLT:
			/* find the Config File TFTP Complete message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_tftp_cplt_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_TFTP_RSP:
			/* find the Config File TFTP Complete response message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_tftp_rsp_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_ARQ_FEEDBACK:
			/* Standalone ARQ feedback message handler */
			dissect_mac_mgmt_msg_arq_feedback_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_ARQ_DISCARD:
			dissect_mac_mgmt_msg_arq_discard_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_ARQ_RESET:
			/* ARQ Reset message handler */
			dissect_mac_mgmt_msg_arq_reset_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_REP_REQ:
			/* Channel measurement Report request message handler */
			dissect_mac_mgmt_msg_rep_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_REP_RSP:
			/* Channel measurement Report response message handler */
			dissect_mac_mgmt_msg_rep_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_FPC:
			/* Fast Power Control message handler */
			dissect_mac_mgmt_msg_fpc_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_MSH_NCFG:
			/* find the Mesh Network Configuration message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_ncfg_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MSH_NENT:
			/* find the Mesh Network Entry message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_nent_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MSH_DSCH:
			/* find the Mesh Distributed Schedule message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_dsch_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MSH_CSCH:
			/* find the Mesh Centralized Schedule message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_csch_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MSH_CSCF:
			/* find the Mesh Centralized Schedule Configuration message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_cscf_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_AAS_FBCK_REQ:
			/* AAS feedback request message handler */
			dissect_mac_mgmt_msg_aas_fbck_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_AAS_FBCK_RSP:
			/* AAS feedback response message handler */
			dissect_mac_mgmt_msg_aas_fbck_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_AAS_BEAM_SELECT:
			/* AAS Beam Select message handler */
			dissect_mac_mgmt_msg_aas_beam_select_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_AAS_BEAM_REQ:
			/* find the AAS Beam request message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_aas_beam_req_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_AAS_BEAM_RSP:
			/* find the AAS Beam response message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_aas_beam_rsp_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_DREG_REQ:
			/* SS De-registation message handler */
			dissect_mac_mgmt_msg_dreg_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_MOB_SLP_REQ:
			/* find the Sleep Request message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_slp_req_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_SLP_RSP:
			/* find the Sleep Response message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_slp_rsp_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_TRF_IND:
			/* find the Traffic Indication message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_trf_ind_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_NBR_ADV:
			/* find the Neighbor Advertisement message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_nbr_adv_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_SCN_REQ:
			/* find the Scanning Interval Allocation Reqest message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_scn_req_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_SCN_RSP:
			/* find the Scanning Interval Allocation Response message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_scn_rsp_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_BSHO_REQ:
			/* find the BS HO Request message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_bsho_req_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_MSHO_REQ:
			/* find the MS HO Request message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_msho_req_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_BSHO_RSP:
			/* find the BS HO Response message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_bsho_rsp_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_HO_IND:
			/* find the HO Indication message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_ho_ind_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_SCN_REP:
			/* find the Scanning Result Report message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_scn_rep_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MOB_PAG_ADV:
			/* find the BS Broadcast Paging message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_pag_adv_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_MBS_MAP:
			/* find the MBS MAP message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mbs_map_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		case MAC_MGMT_MSG_PMC_REQ:
			/* Power Control Mode Change Reuest message handler */
			dissect_mac_mgmt_msg_pmc_req_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_PMC_RSP:
			/* Power Control Mode Change Response message handler */
			dissect_mac_mgmt_msg_pmc_rsp_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_PRC_LT_CTRL:
			/* Setup/Tear-down of Long-term MIMO Precoding message handler */
			dissect_mac_mgmt_msg_prc_lt_ctrl_decoder(tvb, pinfo, tree);
		break;
		case MAC_MGMT_MSG_MOB_ASC_REP:
			/* find the Association Result Report message handler */
			mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_asc_rep_handler");
			if(mgt_msg_handle)
				call_dissector(mgt_msg_handle, tvb, pinfo, tree);
			else
			{
				/* display MAC payload types */
				message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, tvb_len, "%s (%u bytes)", mgt_msg_abbrv[message_type], tvb_len);
				/* add MAC payload subtree */
				message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);
				/* display the MAC payload in Hex */
				proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, tvb_len, ENC_NA);
			}
		break;
		default:
			/* display the unknown message in hex */
			proto_tree_add_item(tree, hf_mac_mgmt_msg_unknown_type, tvb, offset, (tvb_len - offset), ENC_NA);
		break;
		}
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg(void)
{
	/* Payload display */
	static hf_register_info hf[] =
	{
		{
			&hf_mac_mgmt_msg_values,
			{
				"Values", "wmx.values",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_mgmt_msg_unknown_type,
			{
				"Unknown MAC Message Type", "wmx.unknown_type",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_decoder,
		};

	proto_mac_mgmt_msg_decoder = proto_wimax;
#if 0
	proto_mac_mgmt_msg_decoder = proto_register_protocol (
		"WiMax MAC Management Message", /* name       */
		"MGMT MSG",                     /* short name */
		"wmx.mgmtmsg"                   /* abbrev     */
		);
#endif

	proto_register_field_array(proto_mac_mgmt_msg_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register dissector by name */
	register_dissector("wmx_mac_mgmt_msg_decoder", dissect_mac_mgmt_msg_decoder,
	                   proto_mac_mgmt_msg_decoder);

	proto_register_mac_mgmt_msg_dcd();
	proto_register_mac_mgmt_msg_ucd();
	proto_register_mac_mgmt_msg_dlmap();
	proto_register_mac_mgmt_msg_ulmap();
	proto_register_mac_mgmt_msg_rng_req();
	proto_register_mac_mgmt_msg_rng_rsp();
	proto_register_mac_mgmt_msg_reg_req();
	proto_register_mac_mgmt_msg_reg_rsp();
	proto_register_mac_mgmt_msg_dsa();
	proto_register_mac_mgmt_msg_dsc();
	proto_register_mac_mgmt_msg_dsd();
	proto_register_mac_mgmt_msg_arq_feedback();
	proto_register_mac_mgmt_msg_arq_discard();
	proto_register_mac_mgmt_msg_arq_reset();
	proto_register_mac_mgmt_msg_dreg_req();
	proto_register_mac_mgmt_msg_dreg_cmd();
	proto_register_mac_mgmt_msg_fpc();
	proto_register_mac_mgmt_msg_sbc();
	proto_register_mac_mgmt_msg_pkm();
	proto_register_mac_mgmt_msg_pmc_req();
	proto_register_mac_mgmt_msg_pmc_rsp();
	proto_register_mac_mgmt_msg_prc_lt_ctrl();
	proto_register_mac_mgmt_msg_aas_fbck();
	proto_register_mac_mgmt_msg_aas_beam();
	proto_register_mac_mgmt_msg_res_cmd();
	proto_register_mac_mgmt_msg_rep();
	proto_register_mac_mgmt_msg_clk_cmp();
	proto_register_mac_mgmt_msg_dsx_rvd();

	proto_register_wimax_utility_decoders();
}
