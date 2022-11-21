/* packet-dect-mitel-eth.c
 *
 * Dissector for the proprietary protocol of the internal ethernet link
 * between DECT burst processor and ARM processor in Aastra/Mitel DECT
 * base stations.
 *
 * Copyright 2018 by Harald Welte <laforge@gnumonks.org>
 * Copyright 2022 by Bernhard Dick <bernhard@bdick.de>
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
#include <ftypes/ftypes.h>
#include <epan/proto.h>
#include <tvbuff.h>

void proto_register_dect_mitel_eth(void);
void proto_reg_handoff_dect_mitelrfp(void);

static int proto_dect_mitel_eth = -1;

static gint hf_dect_mitel_eth_len = -1;
static gint hf_dect_mitel_eth_layer = -1;
static gint hf_dect_mitel_eth_prim_type = -1;
static gint hf_dect_mitel_eth_mcei = -1;
static gint hf_dect_mitel_eth_mac_info_ind_string = -1;
static gint hf_dect_mitel_eth_pmid = -1;
static gint hf_dect_mitel_eth_subfield = -1;

static gint hf_dect_mitel_eth_mac_con_ind_flags = -1;
static gint hf_dect_mitel_eth_mac_con_ind_flag_handover = -1;

static gint hf_dect_mitel_eth_mac_dis_ind_reason = -1;

static gint hf_dect_mitel_eth_mac_page_req_flags = -1;

static gint hf_dect_mitel_eth_mac_enc_key_req_key = -1;
static gint hf_dect_mitel_eth_mac_enc_key_req_id = -1;

static gint hf_dect_mitel_eth_mac_enc_eks_ind_type = -1;
static gint hf_dect_mitel_eth_mac_enc_eks_ind_id = -1;
static gint hf_dect_mitel_eth_mac_enc_eks_ind_ppn = -1;

static gint hf_dect_mitel_eth_mac_ho_in_progress_res_key = -1;
static gint hf_dect_mitel_eth_mac_ho_in_progress_res_id = -1;

static gint hf_dect_mitel_eth_mac_ho_failed_ind_reason = -1;

static gint hf_dect_mitel_eth_mt_item_key = -1;
static gint hf_dect_mitel_eth_mt_item_length = -1;
static gint hf_dect_mitel_eth_mt_item_value = -1;

static gint ett_dect_mitel_eth = -1;

static dissector_handle_t data_handle;
static dissector_handle_t dlc_handle;

#define DECT_MITEL_ETH_T_XDLC	0xA000
#define DECT_MITEL_ETH_T_DOWNLOAD	0xA002
#define DECT_MITEL_ETH_T_VIDEO	0xA003
#define DECT_MITEL_ETH_T_AUDIOLOG	0xA004

enum dect_mitel_eth_layer_coding {
	DECT_MITEL_ETH_LAYER_RFPC = 0x78,
	DECT_MITEL_ETH_LAYER_LC   = 0x79,
	DECT_MITEL_ETH_LAYER_MAC  = 0x7A,
	DECT_MITEL_ETH_LAYER_MT   = 0x7C,
	DECT_MITEL_ETH_LAYER_SYNC = 0x7D,
};

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
	DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND   = 0x0b,
	DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES   = 0x0c,
	DECT_MITEL_ETH_MAC_HO_FAILED_IND        = 0x0d,
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

/* MAC_CON_IND */
enum dect_mitel_eth_mac_con_ind_flags_coding {
	DECT_MITEL_ETH_MAC_CON_IND_FLAG_HANDOVER = 0x02,
};

/* MAC_DIS_IND */
enum dect_mitel_eth_mac_dis_ind_reason_coding {
	DECT_MITEL_ETH_MAC_DIS_IND_REASON_UNSPECIFIED = 0x01,
	DECT_MITEL_ETH_MAC_DIS_IND_REASON_NORMAL      = 0x02,
	DECT_MITEL_ETH_MAC_DIS_IND_REASON_ABNORMAL    = 0x03,
};

/* MAC_ENC_EKS_IND */
enum dect_mitel_eth_mac_enc_eks_ind_type_coding {
	DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED         = 0x01,
	DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED_WITH_ID = 0x02,
};

/* MAC_HO_FAILED_IND */
enum dect_mitel_eth_mac_ho_failed_ind_reason_coding {
	DECT_MITEL_ETH_MAC_HO_FAILED_IND_REASON_SETUP_FAILED = 0x01,
};

static const value_string dect_mitel_eth_layer_val[] = {
	{ DECT_MITEL_ETH_LAYER_RFPC, "RFPc" },
	{ DECT_MITEL_ETH_LAYER_LC,   "Lc" },
	{ DECT_MITEL_ETH_LAYER_MAC,  "MAC" },
	{ DECT_MITEL_ETH_LAYER_MT,   "Mt" },
	{ DECT_MITEL_ETH_LAYER_SYNC, "Sync" },
	{ 0, NULL }
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
	{ DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND,   "MAC_HO_IN_PROGRRESS_IND" },
	{ DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES,   "MAC_HO_IN_PROGRERSS_RES" },
	{ DECT_MITEL_ETH_MAC_HO_FAILED_IND,        "MAC_HO_FAILED_IND" },
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

/* MAC_DIS_IND */
static const value_string dect_mitel_eth_mac_dis_ind_reason_val[] = {
	{ DECT_MITEL_ETH_MAC_DIS_IND_REASON_UNSPECIFIED, "Unspecified" },
	{ DECT_MITEL_ETH_MAC_DIS_IND_REASON_NORMAL,      "Normal" },
	{ DECT_MITEL_ETH_MAC_DIS_IND_REASON_ABNORMAL,    "Abnormal" },
	{ 0, NULL }
};

/* MAC_ENC_EKS_IND */
static const value_string dect_mitel_eth_mac_enc_eks_ind_type_val[] = {
	{ DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED,         "Encrypted" },
	{ DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED_WITH_ID, "Encrypted with ID" },
	{ 0, NULL }
};

/* MAC_HO_FAILED_IND */
static const value_string dect_mitel_eth_mac_ho_failed_ind_reason_val[] = {
	{ DECT_MITEL_ETH_MAC_HO_FAILED_IND_REASON_SETUP_FAILED, "Setup failed" },
	{ 0, NULL }
};

/*
MAC_CON_IND Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   1 | MCEI                  |
|      1 |   3 | PMID (in last 20bits) |
|      4 |   1 | Flags                 |
*/
static guint dissect_dect_mitel_eth_mac_con_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	static int *const mac_con_ind_flags[] = {
		&hf_dect_mitel_eth_mac_con_ind_flag_handover,
	};

	pinfo->p2p_dir = P2P_DIR_RECV;
	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=3;
	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_mac_con_ind_flags, ett_dect_mitel_eth, mac_con_ind_flags, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_DIS_IND Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | MCEI    |
|      1 |   1 | Reason  |
*/
static guint dissect_dect_mitel_eth_mac_dis_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	pinfo->p2p_dir = P2P_DIR_RECV;
	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_dis_ind_reason, tvb, offset, 1, ENC_NA);

	return offset;
}

/*
MAC_PAGE_REQ Message
| Offset | Len | Content         |
| ------ | --- | --------------- |
|      1 |   1 | Flags (unknown) |
 */
static guint dissect_dect_mitel_eth_mac_page_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	pinfo->p2p_dir = P2P_DIR_SENT;
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_page_req_flags, tvb, offset, 1, ENC_NA);
	offset += 3;
	return offset;
}

/*
MAC_ENC_KEY_REQ Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   8 | Key       |
|      8 |   1 | (Key?) ID |
 */
static guint dissect_dect_mitel_eth_mac_enc_key_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_key_req_key, tvb, offset, 8, ENC_NA);
	offset += 8;
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_key_req_id, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_ENC_EKS_IND Message
| Offset | Len | Content   | Comment            |
| ------ | --- | --------- | ------------------ |
|      0 |   1 | Type      |                    |
|      1 |   1 | (Key?) ID | if Type == with ID |
|      2 |   2 | PPN       | if Type == with ID |
 */
static guint dissect_dect_mitel_eth_mac_enc_eks_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 type;
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_eks_ind_type, tvb, offset, 1, ENC_NA);
	type = tvb_get_guint8(tvb, offset);
	offset++;
	if ( type == DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED_WITH_ID ) {
		proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_eks_ind_id, tvb, offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_eks_ind_ppn, tvb, offset, 2, ENC_NA);
		offset += 2;
	}
	return offset;
}

/*
DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   1 | MCEI                  |
|      1 |   3 | PMID (in last 20bits) |
 */
static guint dissect_dect_mitel_eth_mac_ho_in_progress_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_NA);
	offset += 3;
	return offset;
}

/*
DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   1 | MCEI      |
|      2 |   8 | Key       |
|     11 |   1 | (Key?) ID |
 */
static guint dissect_dect_mitel_eth_mac_ho_in_progress_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset+=2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_ho_in_progress_res_key, tvb, offset, 8, ENC_NA);
	offset += 9;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_ho_in_progress_res_id, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_HO_FAILED_IND Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | Reason  |
 */
static guint dissect_dect_mitel_eth_mac_ho_failed_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_ho_failed_ind_reason, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_INFO_IND Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   1 | MCEI                  |
|      1 |   3 | PMID (in last 20bits) |
|      5 |     | String                |
*/
static guint dissect_dect_mitel_eth_mac_info_ind(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, guint offset)
{
	guint8 mcei;

	pinfo->p2p_dir = P2P_DIR_RECV;
	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=4;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_info_ind_string, tvb, offset,
				tvb_captured_length_remaining(tvb, offset+9), ENC_ASCII|ENC_NA);
	return offset;
}

/*
MAC_CLEAR_DEF_CKEY_REQ Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   3 | PMID (in last 20bits) |
*/
static guint dissect_dect_mitel_eth_mac_clear_def_ckey_req(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, guint offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=3;
	return offset;
}

static int dissect_dect_mitel_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	guint16 mitel_eth_len, payload_len;
	guint8 prim_type, layer, mcei, mt_item_length;
	int offset = 0;
	gboolean ip_encapsulated;
	tvbuff_t *payload_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MI-DECToE");
	col_clear(pinfo->cinfo, COL_INFO);

	/*
	 * When the protocol is used within the internal Ethernet channel in the RFP there is a two byte
	 * field with not yet really known content and a two byte length field. This is not in place / consumed
	 * by the upper layer dissector if this protocol is used in OMM<>RFP communication. So the data parameter
	 * is used to get information from the dect-mitel-rfp dissector whether it was IP encapsulated or not.
     */
	if(data) {
		ip_encapsulated = *( ( gboolean* )data );
	} else {
		ip_encapsulated = false;
	}
	if(!ip_encapsulated) {
		mitel_eth_len = tvb_get_guint16(tvb, offset, 2);
		proto_tree_add_item(tree, hf_dect_mitel_eth_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		if (mitel_eth_len < 3)
			return tvb_captured_length(tvb);
		offset += 4;
	}

	proto_tree_add_item(tree, hf_dect_mitel_eth_layer, tvb, offset, 1, ENC_NA);
	layer = tvb_get_guint8(tvb, offset);
	offset++;
	prim_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_dect_mitel_eth_prim_type, tvb, offset, 1, ENC_NA);

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(prim_type, dect_mitel_eth_prim_coding_val, "Unknown 0x%02x"));
	offset++;

	switch (layer) {
		case DECT_MITEL_ETH_LAYER_RFPC:
			break;
		case DECT_MITEL_ETH_LAYER_MT:
			while ( tvb_reported_length_remaining(tvb, offset) ) {
				proto_tree_add_item(tree, hf_dect_mitel_eth_mt_item_key, tvb, offset, 1, ENC_NA);
				offset++;
				proto_tree_add_item(tree, hf_dect_mitel_eth_mt_item_length, tvb, offset, 1, ENC_NA);
				mt_item_length = tvb_get_guint8(tvb, offset);
				offset++;
				proto_tree_add_item(tree, hf_dect_mitel_eth_mt_item_value, tvb, offset, mt_item_length, ENC_NA);
				offset += mt_item_length;
			}
			break;
		case DECT_MITEL_ETH_LAYER_LC:
		case DECT_MITEL_ETH_LAYER_MAC:
			switch (prim_type) {
				case DECT_MITEL_ETH_MAC_PAGE_REQ:
					offset = dissect_dect_mitel_eth_mac_page_req(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_ENC_KEY_REQ:
					offset = dissect_dect_mitel_eth_mac_enc_key_req(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_ENC_EKS_IND:
					offset = dissect_dect_mitel_eth_mac_enc_eks_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND:
					offset = dissect_dect_mitel_eth_mac_ho_in_progress_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES:
					offset = dissect_dect_mitel_eth_mac_ho_in_progress_res(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_FAILED_IND:
					offset = dissect_dect_mitel_eth_mac_ho_failed_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_CON_IND:
					offset = dissect_dect_mitel_eth_mac_con_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_INFO_IND:
					offset = dissect_dect_mitel_eth_mac_info_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_CLEAR_DEF_CKEY_REQ:
					offset = dissect_dect_mitel_eth_mac_clear_def_ckey_req(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_DIS_REQ:
					pinfo->p2p_dir = P2P_DIR_SENT;
					mcei = tvb_get_guint8(tvb, offset);
					conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
					col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
					proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
					break;
				case DECT_MITEL_ETH_MAC_DIS_IND:
					offset = dissect_dect_mitel_eth_mac_dis_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_LC_DTR_IND:
					pinfo->p2p_dir = P2P_DIR_RECV;
					mcei = tvb_get_guint8(tvb, offset);
					conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
					col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
					proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
					offset++;
					proto_tree_add_item(tree, hf_dect_mitel_eth_subfield, tvb, offset, 1, ENC_NA);
					break;
				case DECT_MITEL_ETH_LC_DATA_REQ:
				case DECT_MITEL_ETH_LC_DATA_IND:
					if(prim_type == DECT_MITEL_ETH_LC_DATA_REQ) {
						pinfo->p2p_dir = P2P_DIR_SENT;
					} else {
						pinfo->p2p_dir = P2P_DIR_RECV;
					}
					mcei = tvb_get_guint8(tvb, offset);
					conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
					col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
					proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
					offset++;
					proto_tree_add_item(tree, hf_dect_mitel_eth_subfield, tvb, offset, 1, ENC_NA);
					offset++;
					payload_len = tvb_get_guint8(tvb, offset);
					offset++;
					payload_tvb = tvb_new_subset_length(tvb, offset, payload_len);
					if (payload_tvb)
						call_dissector(dlc_handle, payload_tvb, pinfo, tree);
					payload_tvb = NULL;
					break;
				default:
					break;
			}
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
		{ &hf_dect_mitel_eth_layer,
			{ "Interface layer", "dect_mitel_eth.layer", FT_UINT8, BASE_HEX,
				 VALS(dect_mitel_eth_layer_val), 0x0, NULL, HFILL
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
		{ &hf_dect_mitel_eth_mac_info_ind_string,
			{ "MAC Info String", "dect_mitel_eth.mac_info_str", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_pmid,
			{ "PMID", "dect_mitel_eth.pmid", FT_UINT24, BASE_HEX,
				NULL, 0x0FFFFF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_subfield,
			{ "Subfield", "dect_mitel_eth.subfield", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_subfield_val), 0, NULL, HFILL
			}
		},
		/* MAC_CON_IND */
		{ &hf_dect_mitel_eth_mac_con_ind_flags,
			{ "Flags", "dect_mitel_eth.mac_con_ind.flags", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_con_ind_flag_handover,
			{ "Handover", "dect_mitel_eth.mac_con_ind.flags.handover", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_MAC_CON_IND_FLAG_HANDOVER, NULL, HFILL
			}
		},
		/* MAC_DIS_IND */
		{ &hf_dect_mitel_eth_mac_dis_ind_reason,
			{ "Reason", "dect_mitel_eth.mac_dis_ind.reason", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_mac_dis_ind_reason_val), 0x0, NULL, HFILL
			}
		},
		/* MAC_PAGE_REQ */
		{ &hf_dect_mitel_eth_mac_page_req_flags,
			{ "Flags", "dect_mitel_eth.mac_page_req.flags", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* MAC_ENC_KEY_REQ */
		{ &hf_dect_mitel_eth_mac_enc_key_req_key,
			{ "Key", "dect_mitel_eth.mac.enc_key_req.key", FT_UINT64, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_enc_key_req_id,
			{ "ID", "dect_mitel_eth.mac.enc_key_req.id", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MAC_ENC_EKS_IND */
		{ &hf_dect_mitel_eth_mac_enc_eks_ind_type,
			{ "Type", "dect_mitel_eth.mac.enc_eks_ind.type", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_mac_enc_eks_ind_type_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_enc_eks_ind_id,
			{ "ID", "dect_mitel_eth.mac.enc_eks_ind.id", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_enc_eks_ind_ppn,
			{ "PPN", "dect_mitel_eth.mac.enc_eks_ind.ppn", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MAC_HO_IN_PROGRESS_RES */
		{ &hf_dect_mitel_eth_mac_ho_in_progress_res_key,
			{ "Key", "dect_mitel_eth.mac.ho_in_progress_res.key", FT_UINT64, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_ho_in_progress_res_id,
			{ "ID", "dect_mitel_eth.mac.ho_in_progress_res.id", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MAC_HO_FAILED_IND */
		{ &hf_dect_mitel_eth_mac_ho_failed_ind_reason,
			{ "Reason", "dect_mitel_eth.mac.ho_failed_ind.reason", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_mac_ho_failed_ind_reason_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mt_item_key,
			{ "Key", "dect_mitel_eth.mt.item.key", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mt_item_length,
			{ "Length", "dect_mitel_eth.mt.item.length", FT_UINT8, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mt_item_value,
			{ "Value", "dect_mitel_eth.mt.item.value", FT_BYTES, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
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

	register_dissector("dect_mitel_eth", dissect_dect_mitel_eth, proto_dect_mitel_eth);
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
