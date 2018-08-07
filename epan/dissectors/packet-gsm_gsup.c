/* packet-gsm_gsup.c
 * Dissector for Osmocom Generic Subscriber Update Protocol (GSUP)
 *
 * (C) 2017-2018 by Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-dns.h"
#include "packet-ber.h"
#include "asn1.h"

/* GSUP is a non-standard, Osmocom-specific protocol used between cellular
 * network core elements and the HLR.  It is a much simplified replacement
 * for the GSM MAP (Mobile Application Part), which requires a full stack
 * of SIGTRAN transport, SCCP as well as TCP.
 *
 * More information about GSUP can be found in the OsmoHLR user manual
 * found at http://ftp.osmocom.org/docs/latest/osmohlr-usermanual.pdf
 */

/***********************************************************************
 * GSUP Protocol Definitions, see libosmocore/include/gsm/gsup.h
 ***********************************************************************/

#define OSMO_GSUP_PORT 4222
#define IPAC_PROTO_EXT_GSUP 0x05

/*! Maximum nubmer of PDP inside \ref osmo_gsup_message */
#define OSMO_GSUP_MAX_NUM_PDP_INFO		10 /* GSM 09.02 limits this to 50 */
/*! Maximum number of auth info inside \ref osmo_gsup_message */
#define OSMO_GSUP_MAX_NUM_AUTH_INFO		5
/*! Maximum number of octets encoding MSISDN in BCD format */
#define OSMO_GSUP_MAX_MSISDN_LEN		9

#define OSMO_GSUP_PDP_TYPE_SIZE			2

/*! Information Element Identifiers for GSUP IEs */
enum osmo_gsup_iei {
	OSMO_GSUP_IMSI_IE			= 0x01,
	OSMO_GSUP_CAUSE_IE			= 0x02,
	OSMO_GSUP_AUTH_TUPLE_IE			= 0x03,
	OSMO_GSUP_PDP_INFO_COMPL_IE		= 0x04,
	OSMO_GSUP_PDP_INFO_IE			= 0x05,
	OSMO_GSUP_CANCEL_TYPE_IE		= 0x06,
	OSMO_GSUP_FREEZE_PTMSI_IE		= 0x07,
	OSMO_GSUP_MSISDN_IE			= 0x08,
	OSMO_GSUP_HLR_NUMBER_IE			= 0x09,
	OSMO_GSUP_PDP_CONTEXT_ID_IE		= 0x10,
	OSMO_GSUP_PDP_TYPE_IE			= 0x11,
	OSMO_GSUP_ACCESS_POINT_NAME_IE		= 0x12,
	OSMO_GSUP_PDP_QOS_IE			= 0x13,
	OSMO_GSUP_CHARG_CHAR_IE			= 0x14,
	OSMO_GSUP_RAND_IE			= 0x20,
	OSMO_GSUP_SRES_IE			= 0x21,
	OSMO_GSUP_KC_IE				= 0x22,
	/* 3G support */
	OSMO_GSUP_IK_IE				= 0x23,
	OSMO_GSUP_CK_IE				= 0x24,
	OSMO_GSUP_AUTN_IE			= 0x25,
	OSMO_GSUP_AUTS_IE			= 0x26,
	OSMO_GSUP_RES_IE			= 0x27,
	OSMO_GSUP_CN_DOMAIN_IE			= 0x28,
	OSMO_GSUP_SESSION_ID_IE			= 0x30,
	OSMO_GSUP_SESSION_STATE_IE		= 0x31,
	OSMO_GSUP_SS_INFO_IE			= 0x35,
};

/*! GSUP message type */
enum osmo_gsup_message_type {
	OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST	= 0x04,
	OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR	= 0x05,
	OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT	= 0x06,

	OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST	= 0x08,
	OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR	= 0x09,
	OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT	= 0x0a,

	OSMO_GSUP_MSGT_AUTH_FAIL_REPORT		= 0x0b,

	OSMO_GSUP_MSGT_PURGE_MS_REQUEST		= 0x0c,
	OSMO_GSUP_MSGT_PURGE_MS_ERROR		= 0x0d,
	OSMO_GSUP_MSGT_PURGE_MS_RESULT		= 0x0e,

	OSMO_GSUP_MSGT_INSERT_DATA_REQUEST	= 0x10,
	OSMO_GSUP_MSGT_INSERT_DATA_ERROR	= 0x11,
	OSMO_GSUP_MSGT_INSERT_DATA_RESULT	= 0x12,

	OSMO_GSUP_MSGT_DELETE_DATA_REQUEST	= 0x14,
	OSMO_GSUP_MSGT_DELETE_DATA_ERROR	= 0x15,
	OSMO_GSUP_MSGT_DELETE_DATA_RESULT	= 0x16,

	OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST	= 0x1c,
	OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR	= 0x1d,
	OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT	= 0x1e,

	OSMO_GSUP_MSGT_PROC_SS_REQUEST		= 0x20,
	OSMO_GSUP_MSGT_PROC_SS_ERROR		= 0x21,
	OSMO_GSUP_MSGT_PROC_SS_RESULT		= 0x22,
};

#define OSMO_GSUP_IS_MSGT_REQUEST(msgt) (((msgt) & 0b00000011) == 0b00)
#define OSMO_GSUP_IS_MSGT_ERROR(msgt)   (((msgt) & 0b00000011) == 0b01)
#define OSMO_GSUP_TO_MSGT_ERROR(msgt)   (((msgt) & 0b11111100) | 0b01)

enum osmo_gsup_cancel_type {
	OSMO_GSUP_CANCEL_TYPE_UPDATE		= 1, /* on wire: 0 */
	OSMO_GSUP_CANCEL_TYPE_WITHDRAW		= 2, /* on wire: 1 */
};

enum osmo_gsup_cn_domain {
	OSMO_GSUP_CN_DOMAIN_PS			= 1,
	OSMO_GSUP_CN_DOMAIN_CS			= 2,
};

enum osmo_gsup_session_state {
	OSMO_GSUP_SESSION_STATE_NONE		= 0x00,
	OSMO_GSUP_SESSION_STATE_BEGIN		= 0x01,
	OSMO_GSUP_SESSION_STATE_CONTINUE	= 0x02,
	OSMO_GSUP_SESSION_STATE_END		= 0x03,
};

/***********************************************************************
 * Wireshark Dissector Implementation
 ***********************************************************************/

void proto_register_gsup(void);
void proto_reg_handoff_gsup(void);

static int proto_gsup = -1;

static int hf_gsup_msg_type = -1;
static int hf_gsup_iei = -1;
static int hf_gsup_ie_len = -1;
static int hf_gsup_ie_payload = -1;
static int hf_gsup_cause = -1;
static int hf_gsup_pdp_info_compl = -1;
static int hf_gsup_cancel_type = -1;
static int hf_gsup_freeze_ptmsi = -1;
static int hf_gsup_pdp_context_id = -1;
static int hf_gsup_charg_char = -1;
static int hf_gsup_apn = -1;
static int hf_gsup_cn_domain = -1;
static int hf_gsup_rand = -1;
static int hf_gsup_sres = -1;
static int hf_gsup_kc = -1;
static int hf_gsup_ik = -1;
static int hf_gsup_ck = -1;
static int hf_gsup_autn = -1;
static int hf_gsup_auts = -1;
static int hf_gsup_res = -1;
static int hf_gsup_session_id = -1;
static int hf_gsup_session_state = -1;

static gint ett_gsup = -1;
static gint ett_gsup_ie = -1;

static dissector_handle_t gsm_map_handle;

static const value_string gsup_iei_types[] = {
	{ OSMO_GSUP_IMSI_IE,		"IMSI" },
	{ OSMO_GSUP_CAUSE_IE,		"Cause" },
	{ OSMO_GSUP_AUTH_TUPLE_IE,	"Authentication Tuple" },
	{ OSMO_GSUP_PDP_INFO_COMPL_IE,	"PDP Information Complete" },
	{ OSMO_GSUP_PDP_INFO_IE,	"PDP Information" },
	{ OSMO_GSUP_CANCEL_TYPE_IE,	"Cancel Type" },
	{ OSMO_GSUP_FREEZE_PTMSI_IE,	"Freeze P-TMSI" },
	{ OSMO_GSUP_MSISDN_IE,		"MSISDN" },
	{ OSMO_GSUP_HLR_NUMBER_IE,	"HLR Number" },
	{ OSMO_GSUP_PDP_CONTEXT_ID_IE,	"PDP Context ID" },
	{ OSMO_GSUP_PDP_TYPE_IE,	"PDP Type" },
	{ OSMO_GSUP_ACCESS_POINT_NAME_IE, "Access Point Name (APN)" },
	{ OSMO_GSUP_PDP_QOS_IE,		"PDP Quality of Service (QoS)" },
	{ OSMO_GSUP_CHARG_CHAR_IE,	"Charging Character" },
	{ OSMO_GSUP_RAND_IE,		"RAND" },
	{ OSMO_GSUP_SRES_IE,		"SRES" },
	{ OSMO_GSUP_KC_IE,		"Kc" },
	{ OSMO_GSUP_IK_IE,		"IK" },
	{ OSMO_GSUP_CK_IE,		"CK" },
	{ OSMO_GSUP_AUTN_IE,		"AUTN" },
	{ OSMO_GSUP_AUTS_IE,		"AUTS" },
	{ OSMO_GSUP_RES_IE,		"RES" },
	{ OSMO_GSUP_CN_DOMAIN_IE,	"CN Domain" },
	{ OSMO_GSUP_SESSION_ID_IE,	"Session Id" },
	{ OSMO_GSUP_SESSION_STATE_IE,	"Session State" },
	{ OSMO_GSUP_SS_INFO_IE,		"Supplementary Service Info"},
	{ 0, NULL }
};

static const value_string gsup_msg_types[] = {
	{ OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST, 	"UpdateLocation Request" },
	{ OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR, 	"UpdateLocation Error" },
	{ OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT,	"UpdateLocation Result" },
	{ OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST,	"SendAuthInfo Request" },
	{ OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR,		"SendAuthInfo Error" },
	{ OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT,		"SendAuthInfo Result" },
	{ OSMO_GSUP_MSGT_AUTH_FAIL_REPORT,		"AuthFail Report" },
	{ OSMO_GSUP_MSGT_PURGE_MS_REQUEST,		"PurgeMS Request" },
	{ OSMO_GSUP_MSGT_PURGE_MS_ERROR,		"PurgeMS Error" },
	{ OSMO_GSUP_MSGT_PURGE_MS_RESULT,		"PurgeMS Result" },
	{ OSMO_GSUP_MSGT_INSERT_DATA_REQUEST,		"InsertSubscriberData Request" },
	{ OSMO_GSUP_MSGT_INSERT_DATA_ERROR,		"InsertSubscriberData Error" },
	{ OSMO_GSUP_MSGT_INSERT_DATA_RESULT,		"InsertSubscriberData Result" },
	{ OSMO_GSUP_MSGT_DELETE_DATA_REQUEST,		"DeleteSubscriberData Request" },
	{ OSMO_GSUP_MSGT_DELETE_DATA_ERROR,		"DeleteSubscriberData Error" },
	{ OSMO_GSUP_MSGT_DELETE_DATA_RESULT,		"DeleteSubscriberData Result" },
	{ OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST,	"LocationCancel Request" },
	{ OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR,		"LocationCancel Error" },
	{ OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT,	"LocationCancel Result" },
	{ OSMO_GSUP_MSGT_PROC_SS_REQUEST,		"Supplementary Service Request" },
	{ OSMO_GSUP_MSGT_PROC_SS_ERROR,			"Supplementary Service Error" },
	{ OSMO_GSUP_MSGT_PROC_SS_RESULT,		"Supplementary Service Result" },
	{ 0, NULL }
};

static const value_string gsup_cancel_types[] = {
	{ OSMO_GSUP_CANCEL_TYPE_UPDATE,		"Update" },
	{ OSMO_GSUP_CANCEL_TYPE_WITHDRAW,	"Withdraw" },
	{ 0, NULL }
};

static const value_string gsup_cndomain_types[] = {
	{ OSMO_GSUP_CN_DOMAIN_PS,		"PS" },
	{ OSMO_GSUP_CN_DOMAIN_CS,		"CS" },
	{ 0, NULL }
};

static const value_string gsup_session_states[] = {
	{ OSMO_GSUP_SESSION_STATE_NONE,		"NONE" },
	{ OSMO_GSUP_SESSION_STATE_BEGIN,	"BEGIN" },
	{ OSMO_GSUP_SESSION_STATE_CONTINUE,	"CONTINUE" },
	{ OSMO_GSUP_SESSION_STATE_END,		"END" },
	{ 0, NULL }
};

static void dissect_ss_info_ie(tvbuff_t *tvb, packet_info *pinfo, guint offset, guint len, proto_tree *tree)
{
	guint saved_offset;
	gint8 appclass;
	gboolean pc;
	gboolean ind = FALSE;
	guint32 component_len = 0;
	guint32 header_end_offset;
	guint32 header_len;
	asn1_ctx_t asn1_ctx;
	tvbuff_t *ss_tvb = NULL;
	static gint comp_type_tag;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	saved_offset = offset;
	col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
	col_set_fence(pinfo->cinfo, COL_PROTOCOL);
	while (len > (offset - saved_offset)) {
		/* get the length of the component. there can be multiple components in one message */
		header_end_offset = get_ber_identifier(tvb, offset, &appclass, &pc, &comp_type_tag);
		header_end_offset = get_ber_length(tvb, header_end_offset, &component_len, &ind);
		header_len = header_end_offset -offset;
		component_len += header_len;

		ss_tvb = tvb_new_subset_length(tvb, offset, component_len);
		col_append_str(pinfo->cinfo, COL_INFO, "(GSM MAP) ");
		col_set_fence(pinfo->cinfo, COL_INFO);
		call_dissector(gsm_map_handle, ss_tvb, pinfo, tree);
		offset += component_len;
	}
}

static gint
dissect_gsup_tlvs(tvbuff_t *tvb, int base_offs, int length, packet_info *pinfo, proto_tree *tree,
		  proto_item *gsup_ti)
{
	int offset = base_offs;

	while (offset - base_offs < length) {
		guint8 tag;
		unsigned int len;
		proto_item *ti;
		proto_tree *att_tree;
		const guchar *apn;
		const gchar *str;
		guint apn_len;

		tag = tvb_get_guint8(tvb, offset);
		offset++;

		len = tvb_get_guint8(tvb, offset);
		offset++;

		att_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, len+2, ett_gsup_ie, &ti,
						"IE: %s",
						val_to_str(tag, gsup_iei_types, "Unknown 0x%02x"));
		proto_tree_add_item(att_tree, hf_gsup_iei, tvb, offset-2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(att_tree, hf_gsup_ie_len, tvb, offset-1, 1, len);

		switch (tag) {
		/* Nested TLVs */
		case OSMO_GSUP_AUTH_TUPLE_IE:
		case OSMO_GSUP_PDP_INFO_IE:
			dissect_gsup_tlvs(tvb, offset, len, pinfo, att_tree, gsup_ti);
			break;
		/* Normal IEs */
		case OSMO_GSUP_RAND_IE:
			proto_tree_add_item(att_tree, hf_gsup_rand, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_SRES_IE:
			proto_tree_add_item(att_tree, hf_gsup_sres, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_KC_IE:
			proto_tree_add_item(att_tree, hf_gsup_kc, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_IK_IE:
			proto_tree_add_item(att_tree, hf_gsup_ik, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_CK_IE:
			proto_tree_add_item(att_tree, hf_gsup_ck, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_AUTN_IE:
			proto_tree_add_item(att_tree, hf_gsup_autn, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_AUTS_IE:
			proto_tree_add_item(att_tree, hf_gsup_auts, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_RES_IE:
			proto_tree_add_item(att_tree, hf_gsup_res, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_CN_DOMAIN_IE:
			proto_tree_add_item(att_tree, hf_gsup_cn_domain, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_CANCEL_TYPE_IE:
			proto_tree_add_item(att_tree, hf_gsup_cancel_type, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_IMSI_IE:
			str = dissect_e212_imsi(tvb, pinfo, att_tree, offset, len, FALSE);
			proto_item_append_text(ti, ", %s", str);
			proto_item_append_text(gsup_ti, ", IMSI: %s", str);
			break;
		case OSMO_GSUP_MSISDN_IE:
			str = dissect_e164_msisdn(tvb, att_tree, offset+1, len-1, E164_ENC_BCD);
			proto_item_append_text(ti, ", %s", str);
			proto_item_append_text(gsup_ti, ", MSISDN: %s", str);
			break;
		case OSMO_GSUP_ACCESS_POINT_NAME_IE:
			if (len == 1) {
				guint8 ch = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(att_tree, hf_gsup_ie_payload, tvb, offset, len, ENC_NA);
				if (ch == '*')
					proto_item_append_text(ti, ", '*' (Wildcard)");
			} else {
				get_dns_name(tvb, offset, len, 0, &apn, &apn_len);
				proto_tree_add_string(att_tree, hf_gsup_apn, tvb, offset, len, apn);
				proto_item_append_text(ti, ", %s", apn);
			}
			break;
		case OSMO_GSUP_PDP_CONTEXT_ID_IE:
			proto_tree_add_item(att_tree, hf_gsup_pdp_context_id, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_CHARG_CHAR_IE:
			proto_tree_add_item(att_tree, hf_gsup_charg_char, tvb, offset, len, ENC_ASCII|ENC_NA);
			break;
		case OSMO_GSUP_CAUSE_IE:
			proto_tree_add_item(att_tree, hf_gsup_cause, tvb, offset, len, ENC_NA);
			break;
		/* boolean flags: either they're present or not */
		case OSMO_GSUP_PDP_INFO_COMPL_IE:
			proto_tree_add_item(att_tree, hf_gsup_pdp_info_compl, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_FREEZE_PTMSI_IE:
			proto_tree_add_item(att_tree, hf_gsup_freeze_ptmsi, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_SESSION_ID_IE:
			proto_tree_add_item(att_tree, hf_gsup_session_id, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_SESSION_STATE_IE:
			proto_tree_add_item(att_tree, hf_gsup_session_state, tvb, offset, len, ENC_NA);
			break;
		case OSMO_GSUP_SS_INFO_IE:
			dissect_ss_info_ie(tvb, pinfo, offset, len, att_tree);
			break;
		case OSMO_GSUP_HLR_NUMBER_IE:
		case OSMO_GSUP_PDP_TYPE_IE:
		case OSMO_GSUP_PDP_QOS_IE:
		default:
			/* Unknown/unsupported IE: Print raw payload in addition to IEI + Length printed above */
			proto_tree_add_item(att_tree, hf_gsup_ie_payload, tvb, offset, len, ENC_NA);
			break;
		}

		offset += len;
	}

	return offset;
}

static int
dissect_gsup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int len, offset = 0;
	proto_item *ti;
	proto_tree *gsup_tree = NULL;
	guint8 msg_type;
	const char *str;


	len = tvb_reported_length(tvb);
	msg_type = tvb_get_guint8(tvb, offset + 0);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSUP");

	col_clear(pinfo->cinfo, COL_INFO);
	str = val_to_str(msg_type, gsup_msg_types, "Unknown GSUP Message Type 0x%02x");
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_gsup, tvb, 0, len, "GSUP %s", str);
		gsup_tree = proto_item_add_subtree(ti, ett_gsup);

		proto_tree_add_item(gsup_tree, hf_gsup_msg_type,
				    tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		dissect_gsup_tlvs(tvb, offset, tvb_reported_length_remaining(tvb, offset), pinfo,
				  gsup_tree, ti);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_gsup(void)
{
	static hf_register_info hf[] = {
		{ &hf_gsup_msg_type, { "Message Type", "gsup.msg_type",
		  FT_UINT8, BASE_DEC, VALS(gsup_msg_types), 0, NULL, HFILL } },
		{ &hf_gsup_iei, { "Information Element Identifier", "gsup.ie.iei",
		  FT_UINT8, BASE_DEC, VALS(gsup_iei_types), 0, NULL, HFILL } },
		{ &hf_gsup_ie_len, { "Information Element Length", "gsup.ie.len",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsup_ie_payload, { "Information Element Payload", "gsup.ie.payload",
		  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

		{ &hf_gsup_rand, { "RAND", "gsup.rand",
		  FT_BYTES, BASE_NONE, NULL, 0, "Random Challenge", HFILL } },
		{ &hf_gsup_sres, { "SRES", "gsup.sres",
		  FT_BYTES, BASE_NONE, NULL, 0, "GSM/GPRS Authentication Result SRES Value", HFILL } },
		{ &hf_gsup_kc, { "Kc", "gsup.kc",
		  FT_BYTES, BASE_NONE, NULL, 0, "GSM/GPRS Ciphering Key", HFILL } },
		{ &hf_gsup_ik, { "IK", "gsup.ik",
		  FT_BYTES, BASE_NONE, NULL, 0, "UMTS Integrity Protection Key", HFILL } },
		{ &hf_gsup_ck, { "CK", "gsup.ck",
		  FT_BYTES, BASE_NONE, NULL, 0, "UMTS Ciphering Key", HFILL } },
		{ &hf_gsup_autn, { "AUTN", "gsup.autn",
		  FT_BYTES, BASE_NONE, NULL, 0, "UMTS Authentication Nonce", HFILL } },
		{ &hf_gsup_auts, { "AUTN", "gsup.auts",
		  FT_BYTES, BASE_NONE, NULL, 0, "UMTS Authentication Sync", HFILL } },
		{ &hf_gsup_res, { "RES", "gsup.res",
		  FT_BYTES, BASE_NONE, NULL, 0, "UMTS Authentication Result", HFILL } },

		{ &hf_gsup_cn_domain, { "CN Domain Indicator", "gsup.cn_domain",
		  FT_UINT8, BASE_DEC, VALS(gsup_cndomain_types), 0, NULL, HFILL } },
		{ &hf_gsup_cancel_type, { "Cancel Type", "gsup.cancel_type",
		  FT_UINT8, BASE_DEC, VALS(gsup_cancel_types), 0, NULL, HFILL } },
		{ &hf_gsup_pdp_info_compl, { "PDP Information Complete", "gsup.pdp_info_compl",
		  FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_gsup_freeze_ptmsi, { "Freeze P-TMSI", "gsup.freeze_ptmsi",
		  FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_gsup_apn, { "APN", "gsup.apn",
		  FT_STRING, BASE_NONE, NULL, 0, "Access Point Name", HFILL } },
		{ &hf_gsup_pdp_context_id, { "PDP Context ID", "gsup.pdp_context_id",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsup_charg_char, { "Charging Character", "gsup.charg_char",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_gsup_cause, { "Cause", "gsup.cause",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_gsup_session_id, { "Session ID", "gsup.session_id",
		  FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_gsup_session_state, { "Session State", "gsup.session_state",
		  FT_UINT8, BASE_DEC, VALS(gsup_session_states), 0, NULL, HFILL } },
	};
	static gint *ett[] = {
		&ett_gsup,
		&ett_gsup_ie,
	};

	proto_gsup = proto_register_protocol("Osmocom General Subscriber Update Protocol", "gsup", "gsup");
	proto_register_field_array(proto_gsup, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gsup(void)
{
	dissector_handle_t gsup_handle;
	gsup_handle = create_dissector_handle(dissect_gsup, proto_gsup);
	dissector_add_uint_with_preference("ipa.osmo.protocol", IPAC_PROTO_EXT_GSUP, gsup_handle);
	gsm_map_handle = find_dissector_add_dependency("gsm_map", proto_gsup);
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
