/* packet-dect_nwk.c
 *
 * Dissector for the DECT (Digital Enhanced Cordless Telecommunications)
 * NWK protocol layer as described in ETSI EN 300 175-5 V2.7.1 (2017-11)
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
#include <epan/packet.h>

static int proto_dect_nwk = -1;

static gint hf_nwk_ti = -1;
static gint hf_nwk_pdisc = -1;
static gint hf_nwk_msg_type_lce = -1;
static gint hf_nwk_msg_type_cc = -1;
static gint hf_nwk_msg_type_mm = -1;

static gint ett_dect_nwk = -1;

static dissector_handle_t dect_nwk_handle;

/*********************************************************************************
 * DECT DEFINITIONS
 *********************************************************************************/

/* Section 7.2 */
enum dect_nwk_proto_disc {
	DECT_NWK_PDISC_LCE		= 0x0,
	DECT_NWK_PDISC_CC		= 0x3,
	DECT_NWK_PDISC_CISS		= 0x4,
	DECT_NWK_PDISC_MM		= 0x5,
	DECT_NWK_PDISC_CMSS		= 0x6,
	DECT_NWK_PDISC_COMS		= 0x7,
};

/* Section 7.4.1 */
enum dect_nwk_cc_msg_type {
	DECT_NWK_CC_ALERTING		= 0x01,
	DECT_NWK_CC_CALL_PROC		= 0x02,
	DECT_NWK_CC_SETUP		= 0x05,
	DECT_NWK_CC_CONNECT		= 0x07,
	DECT_NWK_CC_SETUP_ACK		= 0x0d,
	DECT_NWK_CC_CONNECT_ACK		= 0x0f,
	DECT_NWK_CC_SERVICE_CHANGE	= 0x20,
	DECT_NWK_CC_SERVICE_ACCEPT	= 0x21,
	DECT_NWK_CC_SERVICE_REJECT	= 0x23,
	DECT_NWK_CC_RELEASE		= 0x4d,
	DECT_NWK_CC_RELEASE_COM		= 0x5a,
	DECT_NWK_CC_IWU_INFO		= 0x60,
	DECT_NWK_CC_NOTIFY		= 0x6e,
	DECT_NWK_CC_INFO		= 0x7b,
};

/* Section 7.4.2 */
enum dect_nwk_ss_msg_type {
	DECT_NWK_SS_CISS_RELEASE_COM	= 0x5a,
	DECT_NWK_SS_CISS_FACILITY	= 0x62,
	DECT_NWK_SS_CISS_REGISTER	= 0x64,

	DECT_NWK_SS_CRSS_HOLD		= 0x24,
	DECT_NWK_SS_CRSS_HOLD_ACK	= 0x28,
	DECT_NWK_SS_CRSS_HOLD_REJ	= 0x30,
	DECT_NWK_SS_CRSS_RETRIEVE	= 0x31,
	DECT_NWK_SS_CRSS_RETRIEVE_ACK	= 0x33,
	DECT_NWK_SS_CRSS_RETRIEVE_REJ	= 0x37,
#define DECT_NWK_SS_CRSS_FACILITY	DECT_NWK_SS_CISS_FACILITY
};

/* Section 7.4.3 */
enum dect_nwk_coms_msg_type {
	DECT_NWK_COMS_SETUP		= 0x05,
	DECT_NWK_COMS_CONNECT		= 0x07,
	DECT_NWK_COMS_NOTIFY		= 0x08,
	DECT_NWK_COMS_RELEASE		= 0x4d,
	DECT_NWK_COMS_RELEASE_COM	= 0x5a,
	DECT_NWK_COMS_INFO		= 0x7b,
	DECT_NWK_COMS_ACK		= 0x78,
};

/* Section 7.4.4 */
enum dect_nwk_clms_msg_type {
	DECT_NWK_CLMS_VARIABLE		= 0x01,
};

/* Section 7.4.5 */
enum dect_nwk_mm_msg_type {
	DECT_NWK_MM_AUTH_REQ		= 0x40,
	DECT_NWK_MM_AUTH_REPLY		= 0x41,
	DECT_NWK_MM_KEY_ALLOC		= 0x42,
	DECT_NWK_MM_AUTH_REJ		= 0x43,
	DECT_NWK_MM_ACC_RIGHTS_REQ	= 0x44,
	DECT_NWK_MM_ACC_RIGHTS_ACK	= 0x45,
	DECT_NWK_MM_ACC_RIGHTS_REJ	= 0x47,
	DECT_NWK_MM_ACC_RIGHTS_TERM_REQ	= 0x48,
	DECT_NWK_MM_ACC_RIGHTS_TERM_ACK	= 0x49,
	DECT_NWK_MM_ACC_RIGHTS_TERM_REJ	= 0x4b,
	DECT_NWK_MM_CIPH_REQ		= 0x4c,
	DECT_NWK_MM_CIPH_SUGGEST	= 0x4e,
	DECT_NWK_MM_CIPH_REJ		= 0x4f,
	DECT_NWK_MM_INFO_REQ		= 0x50,
	DECT_NWK_MM_INFO_ACK		= 0x51,
	DECT_NWK_MM_INFO_SUGGEST	= 0x52,
	DECT_NWK_MM_INFO_REJ		= 0x53,
	DECT_NWK_MM_LOCATE_REQ		= 0x54,
	DECT_NWK_MM_LOCATE_ACK		= 0x55,
	DECT_NWK_MM_DETACH		= 0x56,
	DECT_NWK_MM_LOCATE_REJ		= 0x57,
	DECT_NWK_MM_ID_REQ		= 0x58,
	DECT_NWK_MM_ID_REPLY		= 0x59,
	DECT_NWK_MM_IWU			= 0x5b,
	DECT_NWK_MM_TID_ASSIGN		= 0x5c,
	DECT_NWK_MM_TID_ASSIGN_ACK	= 0x5d,
	DECT_NWK_MM_TID_ASSIGN_REJ	= 0x5f,
	DECT_NWK_MM_NOTIFY		= 0x6e,
};

/* Section 7.4.6 */
enum dect_nwk_lce_msg_type {
	DECT_NWK_LCE_PAGE_RESP		= 0x71,
	DECT_NWK_LCE_PAGE_REJ		= 0x72,
};

/*********************************************************************************
 * DECT VALUE STRINGS
 *********************************************************************************/

/* Section 7.2 */
static const value_string nwk_pdisc_vals[] = {
	{ DECT_NWK_PDISC_LCE,		"Link Control Entity (LCE)" },
	{ DECT_NWK_PDISC_CC,		"Call Control (CC)" },
	{ DECT_NWK_PDISC_CISS,		"Call Independent Supplementary Services (CISS)" },
	{ DECT_NWK_PDISC_MM,		"Mobility Management (MM)" },
	{ DECT_NWK_PDISC_CMSS,		"ConnectionLess Message Service (CMSS)" },
	{ DECT_NWK_PDISC_COMS,		"Connection Oriented Message Service (COMS)" },
	{ 0, NULL }
};

/* Section 7.4.1 */
static const value_string nwk_cc_msgt_vals[] = {
	{ DECT_NWK_CC_ALERTING,		"CC-ALERTING" },
	{ DECT_NWK_CC_CALL_PROC,	"CC-CALL-PROC" },
	{ DECT_NWK_CC_SETUP,		"CC-SETUP" },
	{ DECT_NWK_CC_CONNECT,		"CC-CONNECT" },
	{ DECT_NWK_CC_SETUP_ACK,	"CC-SETUP-ACK" },
	{ DECT_NWK_CC_CONNECT_ACK,	"CC-CONNECT-ACK" },
	{ DECT_NWK_CC_SERVICE_CHANGE,	"CC-SERVICE-CHANGE" },
	{ DECT_NWK_CC_SERVICE_ACCEPT,	"CC-SERVICE-ACCEPT" },
	{ DECT_NWK_CC_SERVICE_REJECT,	"CC-SERVICE-REJECT" },
	{ DECT_NWK_CC_RELEASE,		"CC-RELEASE" },
	{ DECT_NWK_CC_RELEASE_COM,	"CC-RELEASE-COM" },
	{ DECT_NWK_CC_IWU_INFO,		"CC-IWU-INFO" },
	{ DECT_NWK_CC_NOTIFY,		"CC-NOTIFY" },
	{ DECT_NWK_CC_INFO,		"CC-INFO" },
	{ 0, NULL }
};

/* Section 7.4.5 */
static const value_string nwk_mm_msgt_vals[] = {
	{ DECT_NWK_MM_AUTH_REQ,		"MM-AUTH-REQ" },
	{ DECT_NWK_MM_AUTH_REPLY,	"MM-AUTH-REPLY" },
	/* FIXME: all other MM messages */
	{ 0, NULL }
};

/* Section 7.4.6 */
static const value_string nwk_lce_msgt_vals[] = {
	{ DECT_NWK_LCE_PAGE_RESP,	"LCE-PAGE-RESPONSE" },
	{ DECT_NWK_LCE_PAGE_REJ, 	"LCE-PAGE-REJECT" },
	{ 0, NULL }
};

/* TOOD: value_string for other protocols */


/*********************************************************************************
 * DECT dissector code
 *********************************************************************************/

static int dissect_dect_nwk_lce(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_nwk_msg_type_lce, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_lce_msgt_vals, "Unknown 0x%02x"));
	offset++;

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}

static int dissect_dect_nwk_cc(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_nwk_msg_type_cc, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_cc_msgt_vals, "Unknown 0x%02x"));
	offset++;

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}

static int dissect_dect_nwk_mm(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_nwk_msg_type_mm, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_mm_msgt_vals, "Unknown 0x%02x"));
	offset++;

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}


static int dissect_dect_nwk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree *nwk_tree;
	proto_item *nwk_ti;
	guint8 pdisc, msg_type;
	guint len;
	guint offset = 0;
	int available_length;

	len = tvb_reported_length(tvb);

	col_append_str(pinfo->cinfo, COL_INFO, "(NWK) ");

	nwk_ti = proto_tree_add_item(tree, proto_dect_nwk, tvb, 0, len, ENC_NA);
	nwk_tree = proto_item_add_subtree(nwk_ti, ett_dect_nwk);

	proto_tree_add_item(nwk_tree, hf_nwk_ti, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(nwk_tree, hf_nwk_pdisc, tvb, 0, 1, ENC_NA);
	pdisc = tvb_get_guint8(tvb, 0) & 0x0F;
	msg_type = tvb_get_guint8(tvb, 1);

	switch (pdisc) {
	case DECT_NWK_PDISC_LCE:
		offset = dissect_dect_nwk_lce(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_CC:
		offset = dissect_dect_nwk_cc(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_MM:
		offset = dissect_dect_nwk_mm(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_CISS:
	case DECT_NWK_PDISC_CMSS:
	case DECT_NWK_PDISC_COMS:
		/* FIXME */
	default:
		break;
	}

	/* whatever was not dissected: Use generic data dissector */
	available_length = tvb_captured_length(tvb) - offset;
	if (available_length) {
		tvbuff_t *payload = tvb_new_subset_length_caplen(tvb, offset, MIN(len-offset, available_length), len);
		call_data_dissector(payload, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

void proto_register_dect_nwk(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_nwk_ti,
			{ "Transaction Identifier", "dect_nwk.ti", FT_UINT8, BASE_HEX,
				 NULL, 0xF0, NULL, HFILL
			}
		},
		{ &hf_nwk_pdisc,
			{ "Proticol Discriminator", "dect_nwk.pdisc", FT_UINT8, BASE_HEX,
				VALS(nwk_pdisc_vals), 0x0F, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_cc,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_cc_msgt_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_mm,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_mm_msgt_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_lce,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_lce_msgt_vals), 0x0, NULL, HFILL
			}
		},


	};

	static gint *ett[] = {
		&ett_dect_nwk,
	};

	/* Register protocol */
	proto_dect_nwk = proto_register_protocol("DECT NWK", "DECT-NWK", "dect_nwk");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dect_nwk, hf, array_length(hf));

	dect_nwk_handle = register_dissector("dect_nwk", dissect_dect_nwk, proto_dect_nwk);
}

void proto_reg_handoff_dect_nwk(void)
{
	dissector_add_uint("dect_dlc.sapi", 0, dect_nwk_handle);
	dissector_add_uint("dect_dlc.sapi", 3, dect_nwk_handle);
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
