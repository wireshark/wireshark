/* packet-dect-mitel-eth.c
 *
 * Dissector for the proprietary protocol of the internal ethernet link
 * between DECT burst processor and ARM processor in Aastra/Mitel DECT
 * base stations.
 *
 * Copyright 2018 by Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/value_string.h>

void proto_register_dect_mitel_eth(void);
void proto_reg_handoff_dect_mitelrfp(void);

static int proto_dect_mitel_eth = -1;

static gint hf_dect_mitel_eth_len = -1;
static gint hf_dect_mitel_eth_prim_type = -1;
static gint hf_dect_mitel_eth_mcei = -1;
static gint hf_dect_mitel_eth_info_string = -1;
static gint hf_dect_mitel_eth_pmid = -1;
static gint hf_dect_mitel_eth_subfield = -1;

static gint ett_dect_mitel_eth = -1;

static dissector_handle_t data_handle;
static dissector_handle_t dlc_handle;

#define DECT_MITEL_ETH_T_XDLC	0xA000
#define DECT_MITEL_ETH_T_DOWNLOAD	0xA002
#define DECT_MITEL_ETH_T_VIDEO	0xA003
#define DECT_MITEL_ETH_T_AUDIOLOG	0xA004

enum dect_mitel_eth_prim_coding {
	DECT_MITEL_ETH_MAC_CON_IND              = 0x01,
	DECT_MITEL_ETH_MAC_DIS_REQ              = 0x02,
	DECT_MITEL_ETH_MAC_DIS_IND              = 0x03,
	DECT_MITEL_ETH_LC_DATA_REQ              = 0x05,
	DECT_MITEL_ETH_LC_DATA_IND              = 0x06,
	DECT_MITEL_ETH_LC_DTR_IND               = 0x07,
	DECT_MITEL_ETH_MAC_PAGE_REQ             = 0x08,
	DECT_MITEL_ETH_MAC_ENC_KEY_REQ          = 0x09,
	DECT_MITEL_ETH_MAC_ENC_EKS_IND          = 0x0a,
	DECT_MITEL_ETH_HO_IN_PROGRESS_IND       = 0x0b,
	DECT_MITEL_ETH_HO_IN_PROGRESS_RES       = 0x0c,
	DECT_MITEL_ETH_HO_FAILED_IND            = 0x0d,
	DECT_MITEL_ETH_HO_FAILED_REQ            = 0x0e,
	DECT_MITEL_ETH_DLC_RFP_ERROR_IND        = 0x14,
	DECT_MITEL_ETH_MAC_CON_EXT_IND          = 0x15,
	DECT_MITEL_ETH_HO_IN_PROGRESS_EXT_IND   = 0x16,
	DECT_MITEL_ETH_MAC_MOD_REQ              = 0x17,
	DECT_MITEL_ETH_MAC_MOD_CNF              = 0x18,
	DECT_MITEL_ETH_MAC_MOD_IND              = 0x19,
	DECT_MITEL_ETH_MAC_MOD_REJ              = 0x1a,
	DECT_MITEL_ETH_MAC_RECORD_AUDIO         = 0x1b,
	DECT_MITEL_ETH_MAC_INFO_IND             = 0x1c,
	DECT_MITEL_ETH_MAC_GET_DEF_CKEY_IND     = 0x1d,
	DECT_MITEL_ETH_MAC_GET_DEF_CKEY_RES     = 0x1e,
	DECT_MITEL_ETH_MAC_CLEAR_DEF_CKEY_REQ   = 0x1f,
	DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_REQ = 0x20,
	DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_CNF = 0x21,
};

static const value_string dect_mitel_eth_prim_coding_val[] = {
	{ DECT_MITEL_ETH_MAC_CON_IND,              "MAC_CON_IND" },
	{ DECT_MITEL_ETH_MAC_DIS_REQ,              "MAC_DIS_REQ" },
	{ DECT_MITEL_ETH_MAC_DIS_IND,              "MAC_DIS_IND" },
	{ DECT_MITEL_ETH_LC_DATA_REQ,              "LC_DATA_REQ" },
	{ DECT_MITEL_ETH_LC_DATA_IND,              "LC_DATA_IND" },
	{ DECT_MITEL_ETH_LC_DTR_IND,               "LC_DTR_IND" },
	{ DECT_MITEL_ETH_MAC_PAGE_REQ,             "MAC_PAGE_REQ" },
	{ DECT_MITEL_ETH_MAC_ENC_KEY_REQ,          "MAC_ENC_KEY_REQ" },
	{ DECT_MITEL_ETH_MAC_ENC_EKS_IND,          "MAC_ENC_EKS_IND" },
	{ DECT_MITEL_ETH_HO_IN_PROGRESS_IND,       "HO_IN_PROGRRESS_IND" },
	{ DECT_MITEL_ETH_HO_IN_PROGRESS_RES,       "HO_IN_PROGRERSS_RES" },
	{ DECT_MITEL_ETH_HO_FAILED_IND,            "HO_FAILED_IND" },
	{ DECT_MITEL_ETH_HO_FAILED_REQ,            "HO_FAILED_REQ" },
	{ DECT_MITEL_ETH_DLC_RFP_ERROR_IND,        "RFP_ERROR_IND" },
	{ DECT_MITEL_ETH_MAC_CON_EXT_IND,          "MAC_CON_EXT_IND" },
	{ DECT_MITEL_ETH_HO_IN_PROGRESS_EXT_IND,   "HO_IN_PROGRESS_EXT_IND" },
	{ DECT_MITEL_ETH_MAC_MOD_REQ,              "MAC_MOD_REQ" },
	{ DECT_MITEL_ETH_MAC_MOD_CNF,              "MAC_MOD_CNF" },
	{ DECT_MITEL_ETH_MAC_MOD_IND,              "MAC_MOD_IND" },
	{ DECT_MITEL_ETH_MAC_MOD_REQ,              "MAC_MOD_REQ" },
	{ DECT_MITEL_ETH_MAC_RECORD_AUDIO,         "MAC_RECORD_AUDIO" },
	{ DECT_MITEL_ETH_MAC_INFO_IND,             "MAC_INFO_IND" },
	{ DECT_MITEL_ETH_MAC_GET_DEF_CKEY_IND,     "MAC_GET_DEF_CKEY_IND" },
	{ DECT_MITEL_ETH_MAC_GET_DEF_CKEY_RES,     "MAC_GET_DEF_CKEY_RES" },
	{ DECT_MITEL_ETH_MAC_CLEAR_DEF_CKEY_REQ,   "MAC_CLEAR_DEF_CKEY_REQ" },
	{ DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_REQ, "MAC_GET_CURR_CKEY_ID_REQ"},
	{ DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_CNF, "MAC_GET_CURR_CKEY_ID_CNF" },
	{ 0, NULL }
};

static const value_string dect_mitel_eth_subfield_val[] = {
	{ 0x00, "B0" },
	{ 0x10, "B1" },
	{ 0, NULL }
};

static int dissect_dect_mitel_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint16 mitel_eth_len, payload_len;
	guint8 prim_type, mcei;
	int offset = 0;
	tvbuff_t *payload_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MI-DECToE");
	col_clear(pinfo->cinfo, COL_INFO);

	mitel_eth_len = tvb_get_guint16(tvb, offset, 2);
	proto_tree_add_item(tree, hf_dect_mitel_eth_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if (mitel_eth_len < 3)
		return tvb_captured_length(tvb);

	prim_type = tvb_get_guint8(tvb, offset+3);
	proto_tree_add_item(tree, hf_dect_mitel_eth_prim_type, tvb, offset+3, 1, ENC_NA);

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(prim_type, dect_mitel_eth_prim_coding_val, "Unknown 0x%02x"));

	switch (prim_type) {
	case DECT_MITEL_ETH_MAC_PAGE_REQ:
		pinfo->p2p_dir = P2P_DIR_SENT;
		payload_len = tvb_get_guint8(tvb, offset+4);
		payload_tvb = tvb_new_subset_length(tvb, offset+5, payload_len);
		break;
	case DECT_MITEL_ETH_MAC_CON_IND:
		pinfo->p2p_dir = P2P_DIR_RECV;
		mcei = tvb_get_guint8(tvb, offset+4);
		conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
		col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
		proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset+4, 1, ENC_NA);
		proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset+6, 2, ENC_BIG_ENDIAN);
		break;
	case DECT_MITEL_ETH_MAC_INFO_IND:
		pinfo->p2p_dir = P2P_DIR_RECV;
		mcei = tvb_get_guint8(tvb, offset+4);
		conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
		col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
		proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset+4, 1, ENC_NA);
		/* from offset 9 onwards, there's a null-terminated string */
		proto_tree_add_item(tree, hf_dect_mitel_eth_info_string, tvb, offset+9,
					tvb_captured_length_remaining(tvb, offset+9), ENC_ASCII|ENC_NA);
		break;
	case DECT_MITEL_ETH_MAC_DIS_REQ:
	case DECT_MITEL_ETH_MAC_DIS_IND:
		if(prim_type == DECT_MITEL_ETH_MAC_DIS_REQ) {
			pinfo->p2p_dir = P2P_DIR_SENT;
		} else {
			pinfo->p2p_dir = P2P_DIR_RECV;
		}
		mcei = tvb_get_guint8(tvb, offset+4);
		conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
		col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
		proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset+4, 1, ENC_NA);
		break;
	case DECT_MITEL_ETH_LC_DTR_IND:
		pinfo->p2p_dir = P2P_DIR_RECV;
		mcei = tvb_get_guint8(tvb, offset+4);
		conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
		col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
		proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset+4, 1, ENC_NA);
		proto_tree_add_item(tree, hf_dect_mitel_eth_subfield, tvb, offset+5, 1, ENC_NA);
		break;
	case DECT_MITEL_ETH_LC_DATA_REQ:
	case DECT_MITEL_ETH_LC_DATA_IND:
		if(prim_type == DECT_MITEL_ETH_LC_DATA_REQ) {
			pinfo->p2p_dir = P2P_DIR_SENT;
		} else {
			pinfo->p2p_dir = P2P_DIR_RECV;
		}
		mcei = tvb_get_guint8(tvb, offset+4);
		conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
		col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
		proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset+4, 1, ENC_NA);
		proto_tree_add_item(tree, hf_dect_mitel_eth_subfield, tvb, offset+5, 1, ENC_NA);
		payload_len = tvb_get_guint8(tvb, offset+6);
		payload_len = tvb_get_guint8(tvb, offset+6);
		payload_tvb = tvb_new_subset_length(tvb, offset+7, payload_len);
		if (payload_tvb)
			call_dissector(dlc_handle, payload_tvb, pinfo, tree);
		payload_tvb = NULL;
		break;
	default:
		break;
	}

	if (payload_tvb)
		call_dissector(data_handle, payload_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

void proto_register_dect_mitelrfp(void)
{

	static hf_register_info hf[] =
	{
		{ &hf_dect_mitel_eth_len,
			{ "Length", "dect_mitel_eth.length", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_prim_type,
			{ "Primitive Type", "dect_mitel_eth.prim", FT_UINT8, BASE_HEX,
				 VALS(dect_mitel_eth_prim_coding_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mcei,
			{ "MCEI", "dect_mitel_eth.mcei", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_info_string,
			{ "MAC Info String", "dect_mitel_eth.mac_info_str", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_pmid,
			{ "PMID", "dect_mitel_eth.pmid", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_subfield,
			{ "Subfield", "dect_mitel_eth.subfield", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_subfield_val), 0, NULL, HFILL
			}
		},
	};

	static gint *ett[] = {
		&ett_dect_mitel_eth,
	};

	/* Register protocol */
	proto_dect_mitel_eth = proto_register_protocol("Aastra/Mitel DECT-over-Ethernet", "Mitel-DECToE", "dect_mitel_eth");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dect_mitel_eth, hf, array_length(hf));
}

void proto_reg_handoff_dect_mitel_eth(void)
{
	dissector_handle_t dect_mitel_eth_handle  =
	    create_dissector_handle(dissect_dect_mitel_eth, proto_dect_mitel_eth);
	dissector_add_uint("ethertype", DECT_MITEL_ETH_T_XDLC, dect_mitel_eth_handle);

	data_handle = find_dissector("data");
	dlc_handle = find_dissector("dect_dlc");
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
