/* mac_mgmt_msg_decoder.c
 * WiMax MAC Management Message decoder
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
#include <epan/expert.h>
#include "wimax_mac.h"

void proto_register_mac_mgmt_msg(void);
void proto_reg_handoff_mac_mgmt_msg(void);

static gint proto_mac_mgmt_msg_decoder = -1;
static gint ett_mac_mgmt_msg_decoder = -1;

static gint hf_mac_mgmt_msg_type = -1;
static gint hf_mac_mgmt_msg_values = -1;

static expert_field ei_empty_payload = EI_INIT;

static dissector_table_t  subdissector_message_table;

/* WIMAX MAC Management message type info */
static const value_string mgt_msg_abbrv_vals[] = {
   {    MAC_MGMT_MSG_UCD,   	"UCD" },
   {    MAC_MGMT_MSG_DCD,   	"DCD" },
   {    MAC_MGMT_MSG_DL_MAP,   	"DL-MAP" },
   {    MAC_MGMT_MSG_UL_MAP,   	"UL-MAP" },
   {    MAC_MGMT_MSG_RNG_REQ,   "RNG-REQ" },
   {    MAC_MGMT_MSG_RNG_RSP,   "RNG-RSP" },
   {    MAC_MGMT_MSG_REG_REQ,   "REG-REQ" },
   {    MAC_MGMT_MSG_REG_RSP,   "REG-RSP" },
   {    8,   	"Reserved8" },
   {    MAC_MGMT_MSG_PKM_REQ,   "PKM-REQ" },
   {    MAC_MGMT_MSG_PKM_RSP,   "PKM-RSP" },
   {    MAC_MGMT_MSG_DSA_REQ,   "DSA-REQ" },
   {    MAC_MGMT_MSG_DSA_RSP,   "DSA-RSP" },
   {    MAC_MGMT_MSG_DSA_ACK,   "DSA-ACK" },
   {    MAC_MGMT_MSG_DSC_REQ,   "DSC-REQ" },
   {    MAC_MGMT_MSG_DSC_RSP,   "DSC-RSP" },
   {    MAC_MGMT_MSG_DSC_ACK, 	"DSC-ACK" },
   {    MAC_MGMT_MSG_DSD_REQ,	"DSD-REQ" },
   {    MAC_MGMT_MSG_DSD_RSP,	"DSD-RSP" },
   {    19,	    "Reserved19" },
   {    20,	    "Reserved20" },
   {    MAC_MGMT_MSG_MCA_REQ,	    "MCA-REQ" },
   {    MAC_MGMT_MSG_MCA_RSP,	    "MCA-RSP" },
   {    MAC_MGMT_MSG_DBPC_REQ,	    "DBPC-REQ" },
   {    MAC_MGMT_MSG_DBPC_RSP,	    "DBPC-RSP" },
   {    MAC_MGMT_MSG_RES_CMD,	    "RES-CMD" },
   {    MAC_MGMT_MSG_SBC_REQ,	    "SBC-REQ" },
   {    MAC_MGMT_MSG_SBC_RSP,	    "SBC-RSP" },
   {    MAC_MGMT_MSG_CLK_CMP,	    "CLK-CMP" },
   {    MAC_MGMT_MSG_DREG_CMD,	    "DREG-CMD" },
   {    MAC_MGMT_MSG_DSX_RVD,	    "DSX-RVD" },
   {    MAC_MGMT_MSG_TFTP_CPLT,	    "TFTP-CPLT" },
   {    MAC_MGMT_MSG_TFTP_RSP,	    "TFTP-RSP" },
   {    MAC_MGMT_MSG_ARQ_FEEDBACK,	    "ARQ-FEEDBACK" },
   {    MAC_MGMT_MSG_ARQ_DISCARD,	    "ARQ-DISCARD" },
   {    MAC_MGMT_MSG_ARQ_RESET,	    "ARQ-RESET" },
   {    MAC_MGMT_MSG_REP_REQ,	    "REP-REQ" },
   {    MAC_MGMT_MSG_REP_RSP,	    "REP-RSP" },
   {    MAC_MGMT_MSG_FPC,	        "FPC" },
   {    MAC_MGMT_MSG_MSH_NCFG,	    "MSH-NCFG" },
   {    MAC_MGMT_MSG_MSH_NENT,	    "MSH-NENT" },
   {    MAC_MGMT_MSG_MSH_DSCH,	    "MSH-DSCH" },
   {    MAC_MGMT_MSG_MSH_CSCH,	    "MSH-CSCH" },
   {    MAC_MGMT_MSG_MSH_CSCF,	    "MSH-CSCF" },
   {    MAC_MGMT_MSG_AAS_FBCK_REQ,	"AAS-FBCK_REQ" },
   {    MAC_MGMT_MSG_AAS_FBCK_RSP,	"AAS-FBCK_RSP" },
   {    MAC_MGMT_MSG_AAS_BEAM_SELECT, "AAS-BEAM_SELECT" },
   {    MAC_MGMT_MSG_AAS_BEAM_REQ,	"AAS-BEAM_REQ" },
   {    MAC_MGMT_MSG_AAS_BEAM_RSP,	"AAS-BEAM_RSP" },
   {    MAC_MGMT_MSG_DREG_REQ,	    "DREG-REQ" },
   {    MAC_MGMT_MSG_MOB_SLP_REQ,	"MOB-SLP-REQ" },
   {    MAC_MGMT_MSG_MOB_SLP_RSP,	"MOB-SLP-RSP" },
   {    MAC_MGMT_MSG_MOB_TRF_IND,	"MOB-TRF-IND" },
   {    MAC_MGMT_MSG_MOB_NBR_ADV,	"MOB-NBR-ADV" },
   {    MAC_MGMT_MSG_MOB_SCN_REQ,	"MOB-SCN-REQ" },
   {    MAC_MGMT_MSG_MOB_SCN_RSP,	"MOB-SCN-RSP" },
   {    MAC_MGMT_MSG_MOB_BSHO_REQ,	"MOB-BSHO-REQ" },
   {    MAC_MGMT_MSG_MOB_MSHO_REQ,	"MOB-MSHO-REQ" },
   {    MAC_MGMT_MSG_MOB_BSHO_RSP,	"MOB-BSHO-RSP" },
   {    MAC_MGMT_MSG_MOB_HO_IND,	"MOB-HO-IND" },
   {    MAC_MGMT_MSG_MOB_SCN_REP,	"MOB-SCN-REP" },
   {    MAC_MGMT_MSG_MOB_PAG_ADV,	"MOB-PAG-ADV" },
   {    MAC_MGMT_MSG_MBS_MAP,	    "MBS-MAP" },
   {    MAC_MGMT_MSG_PMC_REQ,	    "PMC-REQ" },
   {    MAC_MGMT_MSG_PMC_RSP,	    "PMC-RSP" },
   {    MAC_MGMT_MSG_PRC_LT_CTRL,	"PRC-LT-CTRL" },
   {    MAC_MGMT_MSG_MOB_ASC_REP,	"MOB-ASC-REP" },

   { 0, NULL }
};

static value_string_ext mgt_msg_abbrv_vals_ext = VALUE_STRING_EXT_INIT(mgt_msg_abbrv_vals);

static void dissect_mac_mgmt_msg_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint message_type;
	proto_item *message_item;
	proto_tree *message_tree;
	const char* mgt_msg_str;

	message_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_decoder, tvb, offset, -1,
					"MAC Management Message Type (%u bytes)", tvb_reported_length(tvb));
	message_tree = proto_item_add_subtree(message_item, ett_mac_mgmt_msg_decoder);

	if (tvb_reported_length(tvb) == 0)
	{
		expert_add_info(pinfo, message_item, &ei_empty_payload);
		return;
	}

	/* Get the payload type */
	message_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(message_tree, hf_mac_mgmt_msg_type, tvb, offset, 1, ENC_NA);
	mgt_msg_str = val_to_str_ext_const(message_type, &mgt_msg_abbrv_vals_ext, "Unknown");

	/* Display message type in Info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", mgt_msg_str);

	/* add the payload type into the info column */
	if (try_val_to_str_ext(message_type, &mgt_msg_abbrv_vals_ext) == NULL)
	{
		/* display the MAC payload in Hex */
		proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, -1, ENC_NA);
		return;
	}

	/* add the MAC header info to parent*/
	proto_item_append_text(proto_tree_get_parent(tree), ", %s", mgt_msg_str);

	/* Decode and display the MAC payload */
	if (!dissector_try_uint(subdissector_message_table, message_type,
		tvb_new_subset_remaining(tvb, 1), pinfo, tree))
	{
		proto_tree_add_item(message_tree, hf_mac_mgmt_msg_values, tvb, offset, -1, ENC_NA);
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg(void)
{
	/* Payload display */
	static hf_register_info hf[] =
	{
		{
			&hf_mac_mgmt_msg_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype",
				FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mgt_msg_abbrv_vals_ext, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_mgmt_msg_values,
			{
				"Values", "wmx.values",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_decoder,
		};

	static ei_register_info ei[] = {
		{ &ei_empty_payload, { "wmx.empty_payload", PI_PROTOCOL, PI_ERROR, "Error: Mac payload tvb is empty !", EXPFILL }},
	};

	expert_module_t* expert_mac_mgmt;

	proto_mac_mgmt_msg_decoder = proto_register_protocol (
		"WiMax MAC Management Message", /* name       */
		"MGMT MSG",                     /* short name */
		"wmx.mgmt"                   /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mac_mgmt = expert_register_protocol(proto_mac_mgmt_msg_decoder);
	expert_register_field_array(expert_mac_mgmt, ei, array_length(ei));

	subdissector_message_table = register_dissector_table("wmx.mgmtmsg",
		"WiMax MAC Management Message", FT_UINT8, BASE_DEC);

	/* Register dissector by name */
	register_dissector("wmx_mac_mgmt_msg_decoder", dissect_mac_mgmt_msg_decoder,
	                   proto_mac_mgmt_msg_decoder);
}

void proto_reg_handoff_mac_mgmt_msg(void)
{
	dissector_handle_t mgt_msg_handle;

	/* Find the dissectors that appear to be supported through a third-party plugin
		Keep here until third-party plugin can register through the new "wmx.mgmtmsg"
		subdissector */

	/* find the Multicast Assignment request message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mca_req_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MCA_REQ, mgt_msg_handle );

	/* find the Multicast Assignment response message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mca_rsp_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MCA_RSP, mgt_msg_handle );

	/* find the DL Burst Profile Change request message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_dbpc_req_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_DBPC_REQ, mgt_msg_handle );

	/* find the DL Burst Profile Change response message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_dbpc_rsp_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_DBPC_RSP, mgt_msg_handle );

	/* find the Config File TFTP Complete message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_tftp_cplt_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_TFTP_CPLT, mgt_msg_handle );

	/* find the Config File TFTP Complete response message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_tftp_rsp_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_TFTP_RSP, mgt_msg_handle );

	/* find the Mesh Network Configuration message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_ncfg_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MSH_NCFG, mgt_msg_handle );

	/* find the Mesh Network Entry message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_nent_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MSH_NENT, mgt_msg_handle );

	/* find the Mesh Distributed Schedule message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_dsch_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MSH_DSCH, mgt_msg_handle );

	/* find the Mesh Centralized Schedule message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_csch_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MSH_CSCH, mgt_msg_handle );

	/* find the Mesh Centralized Schedule Configuration message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_cscf_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MSH_CSCF, mgt_msg_handle );

	/* find the AAS Beam request message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_aas_beam_req_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_AAS_BEAM_REQ, mgt_msg_handle );

	/* find the AAS Beam response message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_aas_beam_rsp_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_AAS_BEAM_RSP, mgt_msg_handle );

	/* find the Sleep Request message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_slp_req_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_SLP_REQ, mgt_msg_handle );

	/* find the Sleep Response message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_slp_rsp_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_SLP_RSP, mgt_msg_handle );

	/* find the Traffic Indication message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_trf_ind_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_TRF_IND, mgt_msg_handle );

	/* find the Neighbor Advertisement message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_nbr_adv_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_NBR_ADV, mgt_msg_handle );

	/* find the Scanning Interval Allocation Reqest message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_scn_req_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_SCN_REQ, mgt_msg_handle );

	/* find the Scanning Interval Allocation Response message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_scn_rsp_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_SCN_RSP, mgt_msg_handle );

	/* find the BS HO Request message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_bsho_req_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_BSHO_REQ, mgt_msg_handle );

	/* find the MS HO Request message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_msho_req_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_MSHO_REQ, mgt_msg_handle );

	/* find the BS HO Response message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_bsho_rsp_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_BSHO_RSP, mgt_msg_handle );

	/* find the HO Indication message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_ho_ind_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_HO_IND, mgt_msg_handle );

	/* find the Scanning Result Report message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_scn_rep_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_SCN_REP, mgt_msg_handle );

	/* find the BS Broadcast Paging message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_pag_adv_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_PAG_ADV, mgt_msg_handle );

	/* find the MBS MAP message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mbs_map_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MBS_MAP, mgt_msg_handle );

	/* find the Association Result Report message handler */
	mgt_msg_handle = find_dissector("mac_mgmt_msg_mob_asc_rep_handler");
	if (mgt_msg_handle)
		dissector_add_uint( "wmx.mgmtmsg", MAC_MGMT_MSG_MOB_ASC_REP, mgt_msg_handle );
}
