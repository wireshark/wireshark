/* packet-gsm_cbsp.c
 * Dissector for GSM / 3GPP TS 48.049 Cell Broadcast Service Protocol (CBSP)
 *
 * (C) 2018-2019 by Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/asn1.h>

#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"

/***********************************************************************
 * TLV related definitions
 ***********************************************************************/

/*! Entry in a TLV parser array */
struct tlv_p_entry {
	guint16 len;		/*!< length */
	const guint8 *val;	/*!< pointer to value */
};

/*! TLV type */
enum tlv_type {
	TLV_TYPE_NONE,		/*!< no type */
	TLV_TYPE_FIXED,		/*!< fixed-length value-only */
	TLV_TYPE_TV,		/*!< tag-value (8bit) */
	TLV_TYPE_TLV,		/*!< tag-length-value */
	TLV_TYPE_TL16V,		/*!< tag, 16 bit length, value */
};

/*! Definition of a single IE (Information Element) */
struct tlv_def {
	enum tlv_type type;	/*!< TLV type */
	guint8 fixed_len;	/*!< length in case of TLV_TYPE_FIXED */
};

/*! Definition of All 256 IE / TLV */
struct tlv_definition {
	struct tlv_def def[256];
};


/***********************************************************************
 * CBSP Protocol Definitions, see libosmocore/include/gsm/protocol/gsm_48_049.h
 ***********************************************************************/

#define CBSP_TCP_PORT 48049

/* 8.2.1 Information Element Identifiers */
enum cbsp_iei {
	CBSP_IEI_MSG_CONTENT		= 0x01,
	CBSP_IEI_OLD_SERIAL_NR		= 0x02,
	CBSP_IEI_NEW_SERIAL_NR		= 0x03,
	CBSP_IEI_CELL_LIST		= 0x04,
	CBSP_IEI_CATEGORY		= 0x05,
	CBSP_IEI_REP_PERIOD		= 0x06,
	CBSP_IEI_NUM_BCAST_REQ		= 0x07,
	CBSP_IEI_NUM_BCAST_COMPL_LIST	= 0x08,
	CBSP_IEI_FAILURE_LIST		= 0x09,
	CBSP_IEI_RR_LOADING_LIST	= 0x0a,
	CBSP_IEI_CAUSE			= 0x0b,
	CBSP_IEI_DCS			= 0x0c,
	CBSP_IEI_RECOVERY_IND		= 0x0d,
	CBSP_IEI_MSG_ID			= 0x0e,
	CBSP_IEI_EMERG_IND		= 0x0f,
	CBSP_IEI_WARN_TYPE		= 0x10,
	CBSP_IEI_WARN_SEC_INFO		= 0x11,
	CBSP_IEI_CHANNEL_IND		= 0x12,
	CBSP_IEI_NUM_OF_PAGES		= 0x13,
	CBSP_IEI_SCHEDULE_PERIOD	= 0x14,
	CBSP_IEI_NUM_OF_RES_SLOTS	= 0x15,
	CBSP_IEI_BCAST_MSG_TYPE		= 0x16,
	CBSP_IEI_WARNING_PERIOD		= 0x17,
	CBSP_IEI_KEEP_ALIVE_REP_PERIOD	= 0x18,
};

/* 8.2.2 Message Type */
enum cbsp_msg_type {
	CBSP_MSGT_WRITE_REPLACE		= 0x01,
	CBSP_MSGT_WRITE_REPLACE_COMPL	= 0x02,
	CBSP_MSGT_WRITE_REPLACE_FAIL	= 0x03,
	CBSP_MSGT_KILL			= 0x04,
	CBSP_MSGT_KILL_COMPL		= 0x05,
	CBSP_MSGT_KILL_FAIL		= 0x06,
	CBSP_MSGT_LOAD_QUERY		= 0x07,
	CBSP_MSGT_LOAD_QUERY_COMPL	= 0x08,
	CBSP_MSGT_LOAD_QUERY_FAIL	= 0x09,
	CBSP_MSGT_MSG_STATUS_QUERY	= 0x0a,
	CBSP_MSGT_MSG_STATUS_QUERY_COMPL= 0x0b,
	CBSP_MSGT_MSG_STATUS_QUERY_FAIL	= 0x0c,
	CBSP_MSGT_SET_DRX		= 0x0d,
	CBSP_MSGT_SET_DRX_COMPL		= 0x0e,
	CBSP_MSGT_SET_DRX_FAIL		= 0x0f,
	CBSP_MSGT_RESET			= 0x10,
	CBSP_MSGT_RESET_COMPL		= 0x11,
	CBSP_MSGT_RESET_FAIL		= 0x12,
	CBSP_MSGT_RESTART		= 0x13,
	CBSP_MSGT_FAILURE		= 0x14,
	CBSP_MSGT_ERROR_IND		= 0x15,
	CBSP_MSGT_KEEP_ALIVE		= 0x16,
	CBSP_MSGT_KEEP_ALIVE_COMPL	= 0x17,
};

/* 8.2.7 Category */
enum cbsp_category {
	CBSP_CATEG_HIGH_PRIO		= 0x00,
	CBSP_CATEG_BACKGROUND		= 0x01,
	CBSP_CATEG_NORMAL		= 0x02,
};

/* 8.2.9 Number of Brodacast Info */
enum cbsp_num_bcast_info {
	CBSP_NUM_BCAST_INFO_VALID	= 0x0,
	CBSP_NUM_BCAST_INFO_OVERFLOW	= 0x1,
	CBSP_NUM_BCAST_INFO_UNKNOWN	= 0x2,
};

static const value_string cbsp_num_bcast_info_vals[] = {
	{ CBSP_NUM_BCAST_INFO_VALID,	"Number of Broadcasts Complete is Valid" },
	{ CBSP_NUM_BCAST_INFO_OVERFLOW,	"Number of Broadcasts Complete has Overflown" },
	{ CBSP_NUM_BCAST_INFO_UNKNOWN,	"Number of Broadcasts Complete is undefined" },
	{ 0, NULL }
};

static const value_string cbsp_num_bcast_shortinfo_vals[] = {
	{ CBSP_NUM_BCAST_INFO_VALID,	"Valid" },
	{ CBSP_NUM_BCAST_INFO_OVERFLOW,	"Overflow" },
	{ CBSP_NUM_BCAST_INFO_UNKNOWN,	"Unknown" },
	{ 0, NULL }
};

/* Cell ID Discriminator (8.2.11, ...) */
enum cbsp_cell_id_disc {
	CBSP_CIDD_WHOLE_CGI		= 0x0,
	CBSP_CIDD_LAC_CI		= 0x1,
	CBSP_CIDD_CI			= 0x2,
	CBSP_CIDD_LAI			= 0x4,
	CBSP_CIDD_LAC			= 0x5,
	CBSP_CIDD_ALL_IN_BSC		= 0x6,
};

/* 8.2.13 Cause */
enum cbsp_cause {
	CBSP_CAUSE_PARAM_NOT_RECOGNISED			= 0x00,
	CBSP_CAUSE_PARAM_VAL_INVALID			= 0x01,
	CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED		= 0x02,
	CBSP_CAUSE_CELL_ID_NOT_VALID			= 0x03,
	CBSP_CAUSE_UNRECOGNISED_MSG			= 0x04,
	CBSP_CAUSE_MISSING_MAND_IE			= 0x05,
	CBSP_CAUSE_BSC_CAPACITY_EXCEEDED		= 0x06,
	CBSP_CAUSE_CELL_MEMORY_EXCEEDED			= 0x07,
	CBSP_CAUSE_BSC_MEMORY_EXCEEDED			= 0x08,
	CBSP_CAUSE_CB_NOT_SUPPORTED			= 0x09,
	CBSP_CAUSE_CB_NOT_OPERATIONAL			= 0x0a,
	CBSP_CAUSE_INCOMPATIBLE_DRX_PARAM		= 0x0b,
	CBSP_CAUSE_EXT_CHAN_NOT_SUPPORTED		= 0x0c,
	CBSP_CAUSE_MSG_REF_ALREADY_USED			= 0x0d,
	CBSP_CAUSE_UNSPECIFIED_ERROR			= 0x0e,
	CBSP_CAUSE_LAI_OR_LAC_NPT_VALID			= 0x0f,
};

/* 8.2.15 */
static const value_string cbsp_recov_ind_vals[] = {
	{ 0x0,	"CBS/emergency message data available" },
	{ 0x1,	"CBS/emergency message data lost" },
	{ 0, NULL }
};

/* 8.2.17 */
static const value_string cbsp_emerg_ind_vals[] = {
	{ 0x0,	"reserved" },
	{ 0x1,	"ETWS information available" },
	{ 0, NULL }
};

/* 8.2.20 */
static const value_string cbsp_chan_ind_vals[] = {
	{ 0x0,	"basic channel" },
	{ 0x1,	"extended channel" },
	{ 0, NULL }
};

/* 8.2.24 */
static const value_string cbsp_bcast_msg_type_vals[] = {
	{ 0x0,	"CBS message broadcasting" },
	{ 0x1,	"emergency message broadcasting" },
	{ 0, NULL }
};

/* conversion function from 8.2.25 warning period to seconds */
static int cbsp_warn_period_to_secs(guint8 warn_per)
{
	if (warn_per <= 0x0a)
		return warn_per;
	else if (warn_per <= 0x14)
		return 10 + (warn_per-0x0a)*2;
	else if (warn_per <= 0x26)
		return 30 + (warn_per-0x14)*5;
	else if (warn_per <= 0x56)
		return 120 + (warn_per-0x26)*10;
	else if (warn_per <= 0xba)
		return 600 + (warn_per-0x56)*60;
	else
		return -1;
}

static const value_string cbsp_cell_id_disc_vals[] = {
	{ CBSP_CIDD_WHOLE_CGI,		"CGI" },
	{ CBSP_CIDD_LAC_CI,		"LAC+CI" },
	{ CBSP_CIDD_CI,			"CI" },
	{ CBSP_CIDD_LAI,		"LAI" },
	{ CBSP_CIDD_LAC,		"LAC" },
	{ CBSP_CIDD_ALL_IN_BSC,		"BSS" },
	{ 0, NULL }
};

static const value_string cbsp_iei_names[] = {
	{ CBSP_IEI_MSG_CONTENT,		"Message Content" },
	{ CBSP_IEI_OLD_SERIAL_NR,	"Old Serial Number" },
	{ CBSP_IEI_NEW_SERIAL_NR,	"New Serial Number" },
	{ CBSP_IEI_CELL_LIST,		"Cell List" },
	{ CBSP_IEI_CATEGORY,		"Category" },
	{ CBSP_IEI_REP_PERIOD,		"Repetition Period" },
	{ CBSP_IEI_NUM_BCAST_REQ,	"Number of Broadcasts Requested" },
	{ CBSP_IEI_NUM_BCAST_COMPL_LIST,"Number of Broadcasts Completed List" },
	{ CBSP_IEI_FAILURE_LIST,	"Failure List" },
	{ CBSP_IEI_RR_LOADING_LIST,	"Radio Resource Loading List" },
	{ CBSP_IEI_CAUSE,		"Cause" },
	{ CBSP_IEI_DCS,			"Data Coding Scheme" },
	{ CBSP_IEI_RECOVERY_IND,	"Recovery Indication" },
	{ CBSP_IEI_MSG_ID,		"Message Identifier" },
	{ CBSP_IEI_EMERG_IND,		"Emergency Indicator" },
	{ CBSP_IEI_WARN_TYPE,		"Warning Type" },
	{ CBSP_IEI_WARN_SEC_INFO,	"Warning Security Information" },
	{ CBSP_IEI_CHANNEL_IND,		"Channel Indicator" },
	{ CBSP_IEI_NUM_OF_PAGES,	"Number of Pages" },
	{ CBSP_IEI_SCHEDULE_PERIOD,	"Schedule Period" },
	{ CBSP_IEI_NUM_OF_RES_SLOTS,	"Number of Reserved Slots" },
	{ CBSP_IEI_BCAST_MSG_TYPE,	"Broadcast Message Type" },
	{ CBSP_IEI_WARNING_PERIOD,	"Waring Period" },
	{ CBSP_IEI_KEEP_ALIVE_REP_PERIOD, "Keep Alive Repetition Period" },
	{ 0, NULL }
};

static const value_string cbsp_msg_type_names[] = {
	{ CBSP_MSGT_WRITE_REPLACE,		"WRITE-REPLACE" },
	{ CBSP_MSGT_WRITE_REPLACE_COMPL,	"WRITE-REPLACE COMPLETE" },
	{ CBSP_MSGT_WRITE_REPLACE_FAIL,		"WRITE-REPLACE FAILURE" },
	{ CBSP_MSGT_KILL,			"KILL" },
	{ CBSP_MSGT_KILL_COMPL,			"KILL COMPLETE" },
	{ CBSP_MSGT_KILL_FAIL,			"KILL FAILURE" },
	{ CBSP_MSGT_LOAD_QUERY,			"LOAD QUERY" },
	{ CBSP_MSGT_LOAD_QUERY_COMPL,		"LOAD QUERY COMPLETE" },
	{ CBSP_MSGT_LOAD_QUERY_FAIL,		"LOAD QUERY FAILURE" },
	{ CBSP_MSGT_MSG_STATUS_QUERY,		"MESSAGE STATUS QUERY" },
	{ CBSP_MSGT_MSG_STATUS_QUERY_COMPL,	"MESSAGE STATUS QUERY COMPLETE" },
	{ CBSP_MSGT_MSG_STATUS_QUERY_FAIL,	"MESSAGE STATUS QUERY FAILURE" },
	{ CBSP_MSGT_SET_DRX,			"SET-DRX" },
	{ CBSP_MSGT_SET_DRX_COMPL,		"SET-DRX COMPLETE" },
	{ CBSP_MSGT_SET_DRX_FAIL,		"SET-DRX FAILURE" },
	{ CBSP_MSGT_RESET,			"RESET" },
	{ CBSP_MSGT_RESET_COMPL,		"RESET COMPLETE" },
	{ CBSP_MSGT_RESET_FAIL,			"RESET FAILURE" },
	{ CBSP_MSGT_RESTART,			"RESTART" },
	{ CBSP_MSGT_FAILURE,			"FAILURE" },
	{ CBSP_MSGT_ERROR_IND,			"ERROR INDICATION" },
	{ CBSP_MSGT_KEEP_ALIVE,			"KEEP-ALIVE" },
	{ CBSP_MSGT_KEEP_ALIVE_COMPL,		"KEEP-ALIVE COMPLETE" },
	{ 0, NULL }
};

static const value_string cbsp_category_names[] = {
	{ CBSP_CATEG_HIGH_PRIO,		"High Priority" },
	{ CBSP_CATEG_BACKGROUND,	"Background" },
	{ CBSP_CATEG_NORMAL,		"Normal" },
	{ 0, NULL }
};

/* 8.2.13 */
static const value_string cbsp_cause_vals[] = {
	{ CBSP_CAUSE_PARAM_NOT_RECOGNISED,	"Parameter-not-recognized" },
	{ CBSP_CAUSE_PARAM_VAL_INVALID,		"Parameter-value-invalid" },
	{ CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED,	"Message-reference-not-identified" },
	{ CBSP_CAUSE_CELL_ID_NOT_VALID,		"Cell-identity-not-valid" },
	{ CBSP_CAUSE_UNRECOGNISED_MSG,		"Unrecognised-message" },
	{ CBSP_CAUSE_MISSING_MAND_IE,		"Missing-mandatory-element" },
	{ CBSP_CAUSE_BSC_CAPACITY_EXCEEDED,	"BSC-capacity-exceeded" },
	{ CBSP_CAUSE_CELL_MEMORY_EXCEEDED,	"Cell-memory-exceeded" },
	{ CBSP_CAUSE_BSC_MEMORY_EXCEEDED,	"BSC-memory-exceeded" },
	{ CBSP_CAUSE_CB_NOT_SUPPORTED,		"Cell-broadcast-not-supported" },
	{ CBSP_CAUSE_CB_NOT_OPERATIONAL,	"Cell-broadcast-not-operational" },
	{ CBSP_CAUSE_INCOMPATIBLE_DRX_PARAM,	"Incompatible-DRX-parameter" },
	{ CBSP_CAUSE_EXT_CHAN_NOT_SUPPORTED,	"Extended-channel-not-supported" },
	{ CBSP_CAUSE_MSG_REF_ALREADY_USED,	"Message-reference-already-used" },
	{ CBSP_CAUSE_UNSPECIFIED_ERROR,		"Unspecified-error" },
	{ CBSP_CAUSE_LAI_OR_LAC_NPT_VALID,	"LAI-or-LAC-not-valid" },
	{ 0, NULL }
};

static const struct tlv_definition cbsp_att_tlvdef = {
	.def = {
		[CBSP_IEI_MSG_CONTENT] =		{ TLV_TYPE_FIXED, 83 },
		[CBSP_IEI_OLD_SERIAL_NR] =		{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_NEW_SERIAL_NR] =		{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_CELL_LIST] =			{ TLV_TYPE_TL16V, 0 },
		[CBSP_IEI_CATEGORY] =			{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_REP_PERIOD] =			{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_NUM_BCAST_REQ] =		{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_NUM_BCAST_COMPL_LIST] =	{ TLV_TYPE_TL16V, 0 },
		[CBSP_IEI_FAILURE_LIST] =		{ TLV_TYPE_TL16V, 0 },
		[CBSP_IEI_RR_LOADING_LIST] =		{ TLV_TYPE_TL16V, 0 },
		[CBSP_IEI_CAUSE] =			{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_DCS] =			{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_RECOVERY_IND] =		{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_MSG_ID] =			{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_EMERG_IND] =			{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_WARN_TYPE] =			{ TLV_TYPE_FIXED, 2 },
		[CBSP_IEI_WARN_SEC_INFO] =		{ TLV_TYPE_FIXED, 50 },
		[CBSP_IEI_CHANNEL_IND] =		{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_NUM_OF_PAGES] =		{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_SCHEDULE_PERIOD] =		{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_NUM_OF_RES_SLOTS] =		{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_BCAST_MSG_TYPE] =		{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_WARNING_PERIOD] =		{ TLV_TYPE_TV, 0 },
		[CBSP_IEI_KEEP_ALIVE_REP_PERIOD] =	{ TLV_TYPE_TV, 0 },
	},
};

/***********************************************************************
 * Wireshark Dissector Implementation
 ***********************************************************************/

void proto_register_cbsp(void);
void proto_reg_handoff_cbsp(void);

static dissector_handle_t cbsp_handle;

static int proto_cbsp = -1;

static int hf_cbsp_msg_type = -1;
static int hf_cbsp_msg_len = -1;
static int hf_cbsp_iei = -1;
static int hf_cbsp_ie_len = -1;
static int hf_cbsp_ie_payload = -1;

static int hf_cbsp_old_serial_nr = -1;
static int hf_cbsp_new_serial_nr = -1;
static int hf_cbsp_category = -1;
static int hf_cbsp_rep_period = -1;
static int hf_cbsp_num_bcast_req = -1;
static int hf_cbsp_cause = -1;
static int hf_cbsp_dcs = -1;
static int hf_cbsp_recovery_ind = -1;
static int hf_cbsp_msg_id = -1;
static int hf_cbsp_emerg_ind = -1;
static int hf_cbsp_warn_type = -1;
static int hf_cbsp_channel_ind = -1;
static int hf_cbsp_num_of_pages = -1;
static int hf_cbsp_cb_msg_page = -1;
static int hf_cbsp_cbs_page_content = -1;
static int hf_cbsp_sched_period = -1;
static int hf_cbsp_num_of_res_slots = -1;
static int hf_cbsp_bcast_msg_type = -1;
static int hf_cbsp_warning_period = -1;
static int hf_cbsp_keepalive_period = -1;
static int hf_cbsp_user_info_length = -1;
static int hf_cbsp_cell_id_disc = -1;
static int hf_cbsp_cell_load1 = -1;
static int hf_cbsp_cell_load2 = -1;
static int hf_cbsp_num_bcast_compl = -1;
static int hf_cbsp_num_bcast_info = -1;
static int hf_cbsp_lac = -1;
static int hf_cbsp_ci = -1;

static gint ett_cbsp = -1;
static gint ett_cbsp_ie = -1;
static gint ett_cbsp_cbs_data_coding = -1;
static gint ett_cbsp_cbs_page_content = -1;
static gint ett_cbsp_cell_list = -1;
static gint ett_cbsp_fail_list = -1;
static gint ett_cbsp_load_list = -1;
static gint ett_cbsp_num_bcast_compl_list = -1;

static void
dissect_cbsp_content_ie(tvbuff_t *tvb, packet_info *pinfo, guint offset, gint len, proto_tree *tree,
			guint8 sms_encoding, proto_item *ti)
{
	proto_item *cbs_page_item;
	tvbuff_t *next_tvb, *unpacked_tvb;
	const guint8 *pstr;

	proto_tree_add_item(tree, hf_cbsp_user_info_length, tvb, offset, 1, ENC_NA);
	cbs_page_item = proto_tree_add_item(tree, hf_cbsp_cb_msg_page, tvb, offset+1, len-1, ENC_NA);
	next_tvb = tvb_new_subset_length(tvb, offset+1, len-1);

	unpacked_tvb = dissect_cbs_data(sms_encoding, next_tvb, tree, pinfo, 0);
	if (tree) {
		guint captured_len = tvb_captured_length(unpacked_tvb);
		proto_tree *cbs_page_subtree = proto_item_add_subtree(cbs_page_item, ett_cbsp_cbs_page_content);
		proto_tree_add_item_ret_string(cbs_page_subtree, hf_cbsp_cbs_page_content, unpacked_tvb,
						0, captured_len, ENC_UTF_8|ENC_NA, pinfo->pool,
						&pstr);
		proto_item_append_text(ti, ": '%s'", pstr);
	}
}

/* Section 8.2.6 Cell List */
static gint
dissect_cell_id_elem(guint8 discr, tvbuff_t *tvb, packet_info *pinfo, guint offset, gint len _U_,
		     proto_tree *tree, proto_item *ti)
{
	guint base_offs = offset;
	gchar *mcc_mnc;
	guint32 lac, ci;

	switch (discr) {
	case CBSP_CIDD_WHOLE_CGI:
		mcc_mnc = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, E212_NONE, TRUE);
		offset += 3;
		proto_tree_add_item_ret_uint(tree, hf_cbsp_lac, tvb, offset, 2, ENC_NA, &lac);
		offset += 2;
		proto_tree_add_item_ret_uint(tree, hf_cbsp_ci, tvb, offset, 2, ENC_NA, &ci);
		offset += 2;
		proto_item_append_text(ti, ": %s, LAC 0x%04x, CI 0x%04x", mcc_mnc, lac, ci);
		break;
	case CBSP_CIDD_LAC_CI:
		proto_tree_add_item_ret_uint(tree, hf_cbsp_lac, tvb, offset, 2, ENC_NA, &lac);
		offset += 2;
		proto_tree_add_item_ret_uint(tree, hf_cbsp_ci, tvb, offset, 2, ENC_NA, &ci);
		offset += 2;
		proto_item_append_text(ti, ": LAC 0%04x, CI 0x%04x", lac, ci);
		break;
	case CBSP_CIDD_CI:
		proto_tree_add_item_ret_uint(tree, hf_cbsp_ci, tvb, offset, 2, ENC_NA, &ci);
		offset += 2;
		proto_item_append_text(ti, ": CI 0x%04x", ci);
		break;
	case CBSP_CIDD_LAI:
		mcc_mnc = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, E212_NONE, TRUE);
		offset += 3;
		proto_tree_add_item_ret_uint(tree, hf_cbsp_lac, tvb, offset, 2, ENC_NA, &lac);
		offset += 2;
		proto_item_append_text(ti, ": %s, LAC 0x%04x", mcc_mnc, lac);
		break;
	case CBSP_CIDD_LAC:
		proto_tree_add_item_ret_uint(tree, hf_cbsp_lac, tvb, offset, 2, ENC_NA, &lac);
		offset += 2;
		proto_item_append_text(ti, ": LAC 0x%04x", lac);
		break;
	case CBSP_CIDD_ALL_IN_BSC:
		break;
	default:
		return -1;
	}

	return offset - base_offs;
}

/* return the length of a single list element of the given discriminator/type */
static gint cell_id_len(guint8 discr)
{
	switch (discr) {
	case CBSP_CIDD_WHOLE_CGI:
		return 7;
	case CBSP_CIDD_LAC_CI:
		return 4;
	case CBSP_CIDD_CI:
		return 2;
	case CBSP_CIDD_LAI:
		return 5;
	case CBSP_CIDD_LAC:
		return 2;
	case CBSP_CIDD_ALL_IN_BSC:
		return 0;
	default:
		return -1;
	}
}

static void
dissect_cell_id_list_ie(tvbuff_t *tvb, packet_info *pinfo, guint offset, guint len, proto_tree *tree,
			proto_item *parent_ti)
{
	guint base_offs = offset;
	guint32 discr;
	guint count = 0;

	/* list-global discriminator */
	proto_tree_add_item_ret_uint(tree, hf_cbsp_cell_id_disc, tvb, offset, 1, ENC_NA, &discr);
	discr &= 0x0f;
	offset++;

	/* iterate over list items */
	while (offset - base_offs < len) {
		proto_tree *elem_tree;
		proto_item *ti;
		int rc;

		guint remain_len = len - (offset - base_offs);
		elem_tree = proto_tree_add_subtree(tree, tvb, offset, cell_id_len(discr),
						   ett_cbsp_cell_list, &ti,
						   "Cell List Item");
		rc = dissect_cell_id_elem(discr, tvb, pinfo, offset, remain_len, elem_tree, ti);
		if (rc <= 0)
			break;
		offset += rc;
		count++;
	}
	proto_item_append_text(parent_ti, " (%s): %u items",
				val_to_str_const(discr, cbsp_cell_id_disc_vals, ""), count);
}

static void
dissect_rr_load_list_ie(tvbuff_t *tvb, packet_info *pinfo, guint offset, guint len, proto_tree *tree,
			proto_item *parent_ti)
{
	guint base_offs = offset;
	guint32 discr;
	guint count = 0;

	/* list-global discriminator */
	proto_tree_add_item_ret_uint(tree, hf_cbsp_cell_id_disc, tvb, offset, 1, ENC_NA, &discr);
	discr &= 0x0f;
	offset++;

	/* iterate over list items */
	while (offset - base_offs < len) {
		proto_tree *elem_tree;
		guint32 load1, load2;
		proto_item *ti;
		int rc;

		guint remain_len = len - (offset - base_offs);
		elem_tree = proto_tree_add_subtree(tree, tvb, offset, cell_id_len(discr)+2,
						   ett_cbsp_load_list, &ti,
						   "RR Load List Item");
		rc = dissect_cell_id_elem(discr, tvb, pinfo, offset, remain_len, elem_tree, ti);
		if (rc <= 0)
			break;
		offset += rc;

		proto_tree_add_item_ret_uint(elem_tree, hf_cbsp_cell_load1, tvb, offset++, 1,
					     ENC_NA, &load1);
		proto_tree_add_item_ret_uint(elem_tree, hf_cbsp_cell_load2, tvb, offset++, 1,
					     ENC_NA, &load2);
		proto_item_append_text(ti, ": L1=%u%%, L2=%u%%", load1, load2);
		count++;
	}
	proto_item_append_text(parent_ti, " (%s): %u items",
				val_to_str_const(discr, cbsp_cell_id_disc_vals, ""), count);
}

static void
dissect_failure_list_ie(tvbuff_t *tvb, packet_info *pinfo, guint offset, guint len, proto_tree *tree,
			proto_item *parent_ti)
{
	guint base_offs = offset;
	guint count = 0;

	/* iterate over list items, each with its own discriminator */
	while (offset - base_offs < len) {
		proto_tree *elem_tree;
		proto_item *ti;
		guint remain_len, cause;
		int rc;

		guint8 discr = tvb_get_guint8(tvb, offset) & 0x0f;
		elem_tree = proto_tree_add_subtree(tree, tvb, offset, cell_id_len(discr)+2,
						   ett_cbsp_fail_list, &ti,
						   "Failure List Item");
		proto_tree_add_item(elem_tree, hf_cbsp_cell_id_disc, tvb, offset++, 1, ENC_NA);
		remain_len = len - (offset - base_offs);
		rc = dissect_cell_id_elem(discr, tvb, pinfo, offset, remain_len, elem_tree, ti);
		if (rc <= 0)
			break;
		offset += rc;

		proto_tree_add_item_ret_uint(elem_tree, hf_cbsp_cause, tvb, offset++, 1, ENC_NA, &cause);
		proto_item_append_text(ti, ": Cause %s",
					val_to_str_const(cause, cbsp_cause_vals, "Undefined"));
		count++;
	}
	proto_item_append_text(parent_ti, ": %u items", count);

}

static void
dissect_bc_compl_list_ie(tvbuff_t *tvb, packet_info *pinfo, guint offset, guint len, proto_tree *tree,
			 proto_item *parent_ti)
{
	guint base_offs = offset;
	guint32 discr;
	guint count = 0;

	/* list-global discriminator */
	proto_tree_add_item_ret_uint(tree, hf_cbsp_cell_id_disc, tvb, offset, 1, ENC_NA, &discr);
	discr &= 0x0f;
	offset++;

	/* iterate over list items */
	while (offset - base_offs < len) {
		proto_tree *elem_tree;
		proto_item *ti;
		guint32 num_bc, num_bi;
		int rc;

		guint remain_len = len - (offset - base_offs);
		elem_tree = proto_tree_add_subtree(tree, tvb, offset, cell_id_len(discr)+3,
						   ett_cbsp_num_bcast_compl_list, &ti,
						   "Number of Broadcasts completed");
		rc = dissect_cell_id_elem(discr, tvb, pinfo, offset, remain_len, elem_tree, ti);
		if (rc <= 0)
			break;
		offset += rc;

		proto_tree_add_item_ret_uint(elem_tree, hf_cbsp_num_bcast_compl, tvb, offset, 2, ENC_NA,
					     &num_bc);
		offset += 2;
		proto_tree_add_item_ret_uint(elem_tree, hf_cbsp_num_bcast_info, tvb, offset++, 1, ENC_NA,
					     &num_bi);
		proto_item_append_text(ti, ": NumBC=%u (%s)", num_bc,
					val_to_str_const(num_bi, cbsp_num_bcast_shortinfo_vals, ""));
		count++;
	}
	proto_item_append_text(parent_ti, " (%s): %u items",
				val_to_str_const(discr, cbsp_cell_id_disc_vals, ""), count);
}

static gint
dissect_cbsp_tlvs(tvbuff_t *tvb, int base_offs, int length, packet_info *pinfo, proto_tree *tree)
{
	guint8 sms_encoding = SMS_ENCODING_7BIT;
	int offset = base_offs;

	while (offset - base_offs < length) {
		guint8 tag;		 /* Information Element Identifier */
		unsigned int len;	 /* Length of payload */
		unsigned int len_len = 0;/* Length of "length" field (may be 0) */
		proto_item *ti;
		proto_tree *att_tree, *subtree;
		guint32 tmp_u;
		int secs;

		tag = tvb_get_guint8(tvb, offset);
		offset++;

		switch (cbsp_att_tlvdef.def[tag].type) {
		case TLV_TYPE_TV:
			len = 1;
			len_len = 0;
			break;
		case TLV_TYPE_FIXED:
			len = cbsp_att_tlvdef.def[tag].fixed_len;
			len_len = 0;
			break;
		case TLV_TYPE_TLV:
			len = tvb_get_guint8(tvb, offset);
			break;
		case TLV_TYPE_TL16V:
			len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
			len_len = 2;
			break;
		default:
			return length;
		}

		att_tree = proto_tree_add_subtree_format(tree, tvb, offset-1, 1+len_len+len,
						ett_cbsp_ie, &ti, "IE: %s",
						val_to_str(tag, cbsp_iei_names, "Unknown 0x%02x"));
		proto_tree_add_item(att_tree, hf_cbsp_iei, tvb, offset-1, 1, ENC_NA);
		if (len_len)
			proto_tree_add_uint(att_tree, hf_cbsp_ie_len, tvb, offset, len_len, len);

		offset += len_len;

		switch (tag) {
		case CBSP_IEI_MSG_CONTENT:
			dissect_cbsp_content_ie(tvb, pinfo, offset, len, att_tree, sms_encoding, ti);
			break;
		case CBSP_IEI_OLD_SERIAL_NR:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_old_serial_nr, tvb, offset, len, ENC_BIG_ENDIAN, &tmp_u);
			proto_item_append_text(ti, ": 0x%04x", tmp_u);
			break;
		case CBSP_IEI_NEW_SERIAL_NR:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_new_serial_nr, tvb, offset, len, ENC_BIG_ENDIAN, &tmp_u);
			proto_item_append_text(ti, ": 0x%04x", tmp_u);
			break;
		case CBSP_IEI_CATEGORY:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_category, tvb, offset, len, ENC_NA,&tmp_u);
			proto_item_append_text(ti, ": %s", val_to_str_const(tmp_u, cbsp_category_names, ""));
			break;
		case CBSP_IEI_REP_PERIOD:
			{
				guint64 tmp_u64;
				crumb_spec_t cbsp_rep_period_crumbs[] = {
					{  0, 8 },
					{ 12, 4 },
					{  0, 0 }
				};

				proto_tree_add_split_bits_item_ret_val(att_tree, hf_cbsp_rep_period, tvb, offset<<3, cbsp_rep_period_crumbs, &tmp_u64);
				proto_item_append_text(ti, ": %u", (guint16)tmp_u64);
			}
			break;
		case CBSP_IEI_NUM_BCAST_REQ:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_num_bcast_req, tvb, offset, len, ENC_BIG_ENDIAN, &tmp_u);
			proto_item_append_text(ti, ": %u", tmp_u);
			break;
		case CBSP_IEI_CAUSE:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_cause, tvb, offset, len, ENC_NA, &tmp_u);
			proto_item_append_text(ti, ": %s", val_to_str_const(tmp_u, cbsp_cause_vals, ""));
			break;
		case CBSP_IEI_DCS:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_dcs, tvb, offset, len, ENC_NA, &tmp_u);
			subtree = proto_item_add_subtree(att_tree, ett_cbsp_cbs_data_coding);
			sms_encoding = dissect_cbs_data_coding_scheme(tvb, pinfo, subtree, offset);
			proto_item_append_text(ti, ": 0x%02x", tmp_u);
			break;
		case CBSP_IEI_RECOVERY_IND:
			proto_tree_add_item(att_tree, hf_cbsp_recovery_ind, tvb, offset, len, ENC_NA);
			break;
		case CBSP_IEI_MSG_ID:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_msg_id, tvb, offset, len, ENC_BIG_ENDIAN, &tmp_u);
			proto_item_append_text(ti, ": 0x%04x", tmp_u);
			break;
		case CBSP_IEI_EMERG_IND:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_emerg_ind, tvb, offset, len, ENC_NA, &tmp_u);
			proto_item_append_text(ti, ": %s", val_to_str_const(tmp_u, cbsp_emerg_ind_vals, ""));
			break;
		case CBSP_IEI_WARN_TYPE:
			proto_tree_add_item(att_tree, hf_cbsp_warn_type, tvb, offset, len, ENC_NA);
			break;
		case CBSP_IEI_CHANNEL_IND:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_channel_ind, tvb, offset, len, ENC_NA, &tmp_u);
			proto_item_append_text(ti, ": %s", val_to_str_const(tmp_u, cbsp_chan_ind_vals, ""));
			break;
		case CBSP_IEI_NUM_OF_PAGES:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_num_of_pages, tvb, offset, len, ENC_NA, &tmp_u);
			proto_item_append_text(ti, ": %u", tmp_u);
			break;
		case CBSP_IEI_SCHEDULE_PERIOD:
			proto_tree_add_item(att_tree, hf_cbsp_sched_period, tvb, offset, len, ENC_NA);
			break;
		case CBSP_IEI_NUM_OF_RES_SLOTS:
			proto_tree_add_item(att_tree, hf_cbsp_num_of_res_slots, tvb, offset, len, ENC_NA);
			break;
		case CBSP_IEI_BCAST_MSG_TYPE:
			proto_tree_add_item_ret_uint(att_tree, hf_cbsp_bcast_msg_type, tvb, offset, len, ENC_NA, &tmp_u);
			proto_item_append_text(ti, ": %s", val_to_str_const(tmp_u, cbsp_bcast_msg_type_vals, ""));
			break;
		case CBSP_IEI_WARNING_PERIOD:
			secs = cbsp_warn_period_to_secs(tvb_get_guint8(tvb, offset));
			proto_tree_add_uint(att_tree, hf_cbsp_warning_period, tvb, offset, len, secs);
			proto_item_append_text(ti, ": %u (s)", secs);
			break;
		case CBSP_IEI_KEEP_ALIVE_REP_PERIOD:
			secs = cbsp_warn_period_to_secs(tvb_get_guint8(tvb, offset));
			proto_tree_add_uint(att_tree, hf_cbsp_keepalive_period, tvb, offset, len, secs);
			proto_item_append_text(ti, ": %u (s)", secs);
			break;
		case CBSP_IEI_CELL_LIST:
			dissect_cell_id_list_ie(tvb, pinfo, offset, len, att_tree, ti);
			break;
		case CBSP_IEI_NUM_BCAST_COMPL_LIST:
			dissect_bc_compl_list_ie(tvb, pinfo, offset, len, att_tree, ti);
			break;
		case CBSP_IEI_FAILURE_LIST:
			dissect_failure_list_ie(tvb, pinfo, offset, len, att_tree, ti);
			break;
		case CBSP_IEI_RR_LOADING_LIST:
			dissect_rr_load_list_ie(tvb, pinfo, offset, len, att_tree, ti);
			break;
		case CBSP_IEI_WARN_SEC_INFO:
			/* this element is bogus / not used anyway, no need for a dissector */
		default:
			/* Unknown/unsupported IE: Print raw payload in addition to IEI + Length printed above */
			proto_tree_add_item(att_tree, hf_cbsp_ie_payload, tvb, offset, len, ENC_NA);
			break;
		}

		offset += len;
	}

	return offset;
}

static int
dissect_cbsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int len_ind, offset = 0;
	proto_item *ti;
	proto_tree *cbsp_tree = NULL;
	guint8 msg_type;
	const char *str;


	//len = tvb_reported_length(tvb);
	msg_type = tvb_get_guint8(tvb, offset + 0);
	len_ind = tvb_get_guint24(tvb, offset + 1, ENC_BIG_ENDIAN);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CBSP");

	col_clear(pinfo->cinfo, COL_INFO);
	str = val_to_str(msg_type, cbsp_msg_type_names, "Unknown CBSP Message Type 0x%02x");
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_cbsp, tvb, 0, len_ind+4, "CBSP %s", str);
		cbsp_tree = proto_item_add_subtree(ti, ett_cbsp);

		proto_tree_add_item(cbsp_tree, hf_cbsp_msg_type,
				    tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(cbsp_tree, hf_cbsp_msg_len, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;

		dissect_cbsp_tlvs(tvb, offset, tvb_reported_length_remaining(tvb, offset), pinfo,
				  cbsp_tree);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_cbsp(void)
{
	static hf_register_info hf[] = {
		{ &hf_cbsp_msg_type, { "Message Type", "cbsp.msg_type",
		  FT_UINT8, BASE_DEC, VALS(cbsp_msg_type_names), 0, NULL, HFILL } },
		{ &hf_cbsp_msg_len, { "Message Length", "cbsp.msg_len",
		  FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL } },

		{ &hf_cbsp_iei, { "Information Element Identifier", "cbsp.ie.iei",
		  FT_UINT8, BASE_DEC, VALS(cbsp_iei_names), 0, NULL, HFILL } },
		{ &hf_cbsp_ie_len, { "Information Element Length", "cbsp.ie.len",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_ie_payload, { "Information Element Payload", "cbsp.ie.payload",
		  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

		{ &hf_cbsp_old_serial_nr, { "Old Serial Number", "cbsp.old_serial_nr",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_new_serial_nr, { "New Serial Number", "cbsp.new_serial_nr",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_category, { "Category", "cbsp.category",
		  FT_UINT8, BASE_HEX, VALS(cbsp_category_names), 0, NULL, HFILL } },
		{ &hf_cbsp_rep_period, { "Repetition Period (units of 1.883s)", "cbsp.rep_period",
		  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_num_bcast_req, { "Number of Broadcasts Requested", "cbsp.num_bcast_req",
		  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_cause, { "Cause", "cbsp.cause",
		  FT_UINT8, BASE_HEX, VALS(cbsp_cause_vals), 0, NULL, HFILL } },
		{ &hf_cbsp_dcs, { "Data Coding Scheme", "cbsp.dcs",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_recovery_ind, { "Recovery Indication", "cbsp.recovery_ind",
		  FT_UINT8, BASE_HEX, VALS(cbsp_recov_ind_vals), 0, NULL, HFILL } },
		{ &hf_cbsp_msg_id, { "Message Identifier", "cbsp.message_id",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_emerg_ind, { "Emergency Indicator", "cbsp.emergency_ind",
		  FT_UINT8, BASE_HEX, VALS(cbsp_emerg_ind_vals), 0, NULL, HFILL } },
		{ &hf_cbsp_warn_type, { "Warning Type", "cbsp.warn_type",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_channel_ind, { "Channel Indicator", "cbsp.channel_ind",
		  FT_UINT8, BASE_HEX, VALS(cbsp_chan_ind_vals), 0, NULL, HFILL } },
		{ &hf_cbsp_num_of_pages, { "Number of Pages", "cbsp.num_of_pages",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_cb_msg_page, { "CBS Message Information Page", "cbsp.cb_msg_page",
		  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_cbs_page_content, { "CBS Page Content", "cbsp.cb_page_content",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_sched_period, { "Schedule Period", "cbsp.sched_period",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_num_of_res_slots, { "Number of Reserved Slots", "cbsp.num_of_res_slots",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_bcast_msg_type, { "Broadcast Message Type", "cbsp.bcast_msg_type",
		  FT_UINT8, BASE_DEC, VALS(cbsp_bcast_msg_type_vals), 0, NULL, HFILL } },
		{ &hf_cbsp_warning_period, { "Warning Period", "cbsp.warning_period",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_keepalive_period, { "Keepalive Repetition Period", "cbsp.keepalive_rep_period",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_user_info_length, { "User Information Length", "cbsp.user_info_len",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_cell_id_disc, { "Cell ID Discriminator", "cbsp.cell_id_disc",
		  FT_UINT8, BASE_DEC, VALS(cbsp_cell_id_disc_vals), 0, NULL, HFILL } },
		{ &hf_cbsp_cell_load1, { "Radio Resource Load 1", "cbsp.rr_load1",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_cell_load2, { "Radio Resource Load 2", "cbsp.rr_load2",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_num_bcast_compl, { "Number of Broadcasts Completed", "cbsp.num_bcast_compl",
		  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_num_bcast_info, { "Number of Broadcasts Info", "cbsp.num_bcast_info",
		  FT_UINT8, BASE_HEX, VALS(cbsp_num_bcast_info_vals), 0, NULL, HFILL } },
		{ &hf_cbsp_lac, { "Location Area Code (LAC)", "cbsp.lac",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_cbsp_ci, { "Cell Identifier (CI)", "cbsp.ci",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
	};
	static gint *ett[] = {
		&ett_cbsp,
		&ett_cbsp_ie,
		&ett_cbsp_cbs_data_coding,
		&ett_cbsp_cbs_page_content,
		&ett_cbsp_cell_list,
		&ett_cbsp_fail_list,
		&ett_cbsp_load_list,
		&ett_cbsp_num_bcast_compl_list,
	};

	proto_cbsp = proto_register_protocol("3GPP/GSM Cell Broadcast Service Protocol", "cbsp", "cbsp");
	cbsp_handle = register_dissector("cbsp", dissect_cbsp, proto_cbsp);
	proto_register_field_array(proto_cbsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cbsp(void)
{
	dissector_add_uint_with_preference("tcp.port", CBSP_TCP_PORT, cbsp_handle);
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
