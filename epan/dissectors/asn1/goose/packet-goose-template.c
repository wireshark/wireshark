/* packet-goose.c
 * Routines for IEC 61850 GOOSE packet dissection
 * Martin Lutz 2008
 *
 * Routines for IEC 61850 R-GOOSE packet dissection
 * Dordije Manojlovic 2020
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-acse.h"

#define GOOSE_PNAME  "GOOSE"
#define GOOSE_PSNAME "GOOSE"
#define GOOSE_PFNAME "goose"

#define R_GOOSE_PNAME  "R-GOOSE"
#define R_GOOSE_PSNAME "R-GOOSE"
#define R_GOOSE_PFNAME "r-goose"

void proto_register_goose(void);
void proto_reg_handoff_goose(void);

/* Initialize the protocol and registered fields */
static int proto_goose;
static int proto_r_goose;

static int hf_goose_session_header;
static int hf_goose_spdu_id;
static int hf_goose_session_hdr_length;
static int hf_goose_hdr_length;
static int hf_goose_content_id;
static int hf_goose_spdu_lenth;
static int hf_goose_spdu_num;
static int hf_goose_version;
static int hf_goose_security_info;
static int hf_goose_current_key_t;
static int hf_goose_next_key_t;
static int hf_goose_key_id;
static int hf_goose_init_vec_length;
static int hf_goose_init_vec;
static int hf_goose_session_user_info;
static int hf_goose_payload;
static int hf_goose_payload_length;
static int hf_goose_apdu_tag;
static int hf_goose_apdu_simulation;
static int hf_goose_apdu_appid;
static int hf_goose_apdu_length;
static int hf_goose_padding_tag;
static int hf_goose_padding_length;
static int hf_goose_padding;
static int hf_goose_hmac;
static int hf_goose_appid;
static int hf_goose_length;
static int hf_goose_reserve1;
static int hf_goose_reserve1_s_bit;
static int hf_goose_reserve2;
static int hf_goose_float_value;


/* Bit fields in the Reserved fields */
#define F_RESERVE1_S_BIT  0x8000

/* GOOSE stored data for expert info verifications */
typedef struct _goose_chk_data{
	bool s_bit;
}goose_chk_data_t;
#define GOOSE_CHK_DATA_LEN	(sizeof(goose_chk_data_t))

static expert_field ei_goose_mal_utctime;
static expert_field ei_goose_zero_pdu;
static expert_field ei_goose_invalid_sim;

#define SINGLE_FLOAT_EXP_BITS	8
#define FLOAT_ENC_LENGTH		5

#include "packet-goose-hf.c"

/* Initialize the subtree pointers */
static int ett_r_goose;
static int ett_session_header;
static int ett_security_info;
static int ett_session_user_info;
static int ett_payload;
static int ett_padding;
static int ett_goose;
static int ett_reserve1;
static int ett_expert_inf_sim;

#include "packet-goose-ett.c"

#include "packet-goose-fn.c"

static dissector_handle_t goose_handle;


#define OSI_SPDU_TUNNELED 0xA0 /* Tunneled */
#define OSI_SPDU_GOOSE    0xA1 /* GOOSE */
#define OSI_SPDU_SV       0xA2 /* Sample Value */
#define OSI_SPDU_MNGT     0xA3 /* Management */

static const value_string ositp_spdu_id[] = {
	{ OSI_SPDU_TUNNELED, "Tunneled" },
	{ OSI_SPDU_GOOSE,    "GOOSE" },
	{ OSI_SPDU_SV,       "Sample value" },
	{ OSI_SPDU_MNGT,     "Management" },
	{ 0,       NULL }
};

#define OSI_PDU_GOOSE     0x81
#define OSI_PDU_SV        0x82
#define OSI_PDU_TUNNELED  0x83
#define OSI_PDU_MNGT      0x84

static const value_string ositp_pdu_id[] = {
	{ OSI_PDU_GOOSE,     "GOOSE" },
	{ OSI_PDU_SV,        "SV" },
	{ OSI_PDU_TUNNELED,  "Tunnel" },
	{ OSI_PDU_MNGT,      "MNGT" },
	{ 0,       NULL }
};

#define APDU_HEADER_SIZE 6

/*
* Dissect GOOSE PDUs inside a PPDU.
*/
static int
dissect_goose(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			  void* data _U_)
{
	uint32_t offset = 0;
	uint32_t old_offset;
	uint32_t length;
	uint32_t reserve1_val;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	goose_chk_data_t *data_chk = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	static int * const reserve1_flags[] = {
		&hf_goose_reserve1_s_bit,
		NULL
	};

	asn1_ctx.private_data = wmem_alloc(pinfo->pool, GOOSE_CHK_DATA_LEN);
	data_chk = (goose_chk_data_t *)asn1_ctx.private_data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, GOOSE_PNAME);
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_goose, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_goose);
	add_ber_encoded_label(tvb, pinfo, parent_tree);


	/* APPID */
	proto_tree_add_item(tree, hf_goose_appid, tvb, offset, 2, ENC_BIG_ENDIAN);

	/* Length */
	proto_tree_add_item_ret_uint(tree, hf_goose_length, tvb, offset + 2, 2,
						ENC_BIG_ENDIAN, &length);

	/* Reserved 1 */
	reserve1_val = tvb_get_uint16(tvb, offset + 4, ENC_BIG_ENDIAN);
	proto_tree_add_bitmask_value(tree, tvb, offset + 4, hf_goose_reserve1, ett_reserve1,
						reserve1_flags, reserve1_val);

	/* Store the header sim value for later expert info checks */
	if(data_chk){
		if(reserve1_val & F_RESERVE1_S_BIT){
			data_chk->s_bit = true;
		}else{
			data_chk->s_bit = false;
		}
	}


	/* Reserved 2 */
	proto_tree_add_item(tree, hf_goose_reserve2, tvb, offset + 6, 2,
						ENC_BIG_ENDIAN);

	offset = 8;
	while (offset < length){
		old_offset = offset;
		offset = dissect_goose_GOOSEpdu(false, tvb, offset, &asn1_ctx , tree, -1);
		if (offset == old_offset) {
			proto_tree_add_expert(tree, pinfo, &ei_goose_zero_pdu, tvb, offset, -1);
			break;
		}
	}

	return tvb_captured_length(tvb);
}

/*
* Dissect RGOOSE PDUs inside ISO 8602/X.234 CLTP ConnecteionLess
* Transport Protocol.
*/
static int
dissect_rgoose(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			   void* data _U_)
{
	unsigned offset = 0, old_offset = 0;
	uint32_t init_v_length, payload_tag, padding_length, length;
	uint32_t payload_length, apdu_offset = 0, apdu_length, apdu_simulation;
	proto_item *item = NULL;
	proto_tree *tree = NULL, *r_goose_tree = NULL, *sess_user_info_tree = NULL;
	goose_chk_data_t *data_chk = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	asn1_ctx.private_data = wmem_alloc(pinfo->pool, GOOSE_CHK_DATA_LEN);
	data_chk = (goose_chk_data_t *)asn1_ctx.private_data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, R_GOOSE_PNAME);
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_r_goose, tvb, 0, -1, ENC_NA);
	r_goose_tree = proto_item_add_subtree(item, ett_r_goose);

	/* Session header subtree */
	item = proto_tree_add_item(r_goose_tree, hf_goose_session_header, tvb, 0,
							   -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_session_header);

	/* SPDU ID */
	proto_tree_add_item(tree, hf_goose_spdu_id, tvb, offset++, 1,
						ENC_BIG_ENDIAN);
	/* Session header length */
	proto_tree_add_item_ret_uint(tree, hf_goose_session_hdr_length, tvb, offset++, 1,
						ENC_BIG_ENDIAN, &length);
	proto_item_set_len(item, length + 2);

	/* Header content indicator */
	proto_tree_add_item(tree, hf_goose_content_id, tvb, offset++, 1,
						ENC_BIG_ENDIAN);
	/* Length */
	proto_tree_add_item(tree, hf_goose_hdr_length, tvb, offset++, 1,
						ENC_BIG_ENDIAN);
	/* SPDU length */
	proto_tree_add_item(tree, hf_goose_spdu_lenth, tvb, offset, 4,
						ENC_BIG_ENDIAN);
	offset += 4;
	/* SPDU number */
	proto_tree_add_item(tree, hf_goose_spdu_num, tvb, offset, 4,
						ENC_BIG_ENDIAN);
	offset += 4;
	/* Version */
	proto_tree_add_item(tree, hf_goose_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Security information subtree */
	item = proto_tree_add_item(tree, hf_goose_security_info, tvb, offset, -1,
							   ENC_NA);
	tree = proto_item_add_subtree(item, ett_security_info);
	/* Time of current key */
	proto_tree_add_item(tree, hf_goose_current_key_t, tvb, offset, 4,
						ENC_BIG_ENDIAN);
	offset += 4;
	/* Time of next key */
	proto_tree_add_item(tree, hf_goose_next_key_t, tvb, offset, 2,
						ENC_BIG_ENDIAN);
	offset += 2;
	/* Key ID */
	proto_tree_add_item(tree, hf_goose_key_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	/* Initialization vector length */
	proto_tree_add_item_ret_uint(tree, hf_goose_init_vec_length, tvb, offset++, 1,
						ENC_BIG_ENDIAN, &init_v_length);
	proto_item_set_len(item, init_v_length + 11);

	if (init_v_length > 0) {
		/* Initialization vector bytes */
		proto_tree_add_item(tree, hf_goose_init_vec, tvb, offset, init_v_length,
							ENC_NA);
	}
	offset += init_v_length;

	/* Session user information subtree */
	item = proto_tree_add_item(r_goose_tree, hf_goose_session_user_info, tvb,
							   offset, -1, ENC_NA);
	sess_user_info_tree = proto_item_add_subtree(item, ett_payload);

	/* Payload subtree */
	item = proto_tree_add_item(sess_user_info_tree, hf_goose_payload, tvb,
							   offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_payload);
	/* Payload length */
	proto_tree_add_item_ret_uint(tree, hf_goose_payload_length, tvb, offset, 4,
						ENC_BIG_ENDIAN, &payload_length);
	offset += 4;

	while (apdu_offset < payload_length){
		/* APDU tag */
		proto_tree_add_item_ret_uint(tree, hf_goose_apdu_tag, tvb, offset++, 1,
							ENC_BIG_ENDIAN, &payload_tag);
		/* Simulation flag */
		proto_tree_add_item_ret_uint(tree, hf_goose_apdu_simulation, tvb, offset++,
							1, ENC_BIG_ENDIAN, &apdu_simulation);
		/* APPID */
		proto_tree_add_item(tree, hf_goose_apdu_appid, tvb, offset, 2,
							ENC_BIG_ENDIAN);
		offset += 2;

		if (payload_tag != OSI_PDU_GOOSE) {
			return tvb_captured_length(tvb);
		}

		/* Store the header sim value for later expert info checks */
		if(data_chk){
			if(apdu_simulation){
				data_chk->s_bit = true;
			}else{
				data_chk->s_bit = false;
			}
		}

		/* APDU length */
		proto_tree_add_item_ret_uint(tree, hf_goose_apdu_length, tvb, offset, 2,
							ENC_BIG_ENDIAN, &apdu_length);

		apdu_offset += (APDU_HEADER_SIZE + apdu_length);
		offset += 2;

		old_offset = offset;
		offset = dissect_goose_GOOSEpdu(false, tvb, offset, &asn1_ctx , tree, -1);
		if (offset == old_offset) {
			proto_tree_add_expert(tree, pinfo, &ei_goose_zero_pdu, tvb, offset, -1);
			break;
		}
	}

	/* Check do we have padding bytes */
	if ((tvb_captured_length(tvb) > offset) &&
		(tvb_get_uint8(tvb, offset) == 0xAF)) {
		/* Padding subtree */
		item = proto_tree_add_item(sess_user_info_tree, hf_goose_padding, tvb,
								   offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_padding);

		/* Padding tag */
		proto_tree_add_item(tree, hf_goose_padding_tag, tvb, offset++, 1,
							ENC_NA);
		/* Padding length */
		proto_tree_add_item_ret_uint(tree, hf_goose_padding_length, tvb, offset++, 1,
							ENC_BIG_ENDIAN, &padding_length);
		proto_item_set_len(item, padding_length + 1);

		/* Padding bytes */
		proto_tree_add_item(tree, hf_goose_padding, tvb, offset, padding_length,
							ENC_NA);
		offset += padding_length;
	}

	/* Check do we have HMAC bytes */
	if (tvb_captured_length(tvb) > offset) {
		/* HMAC bytes */
		proto_tree_add_item(sess_user_info_tree, hf_goose_hmac, tvb, offset,
			tvb_captured_length(tvb) - offset, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

static bool
dissect_rgoose_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
					void *data)
{
	uint8_t spdu;

	/* Check do we have at least min size of Session header bytes */
	if (tvb_captured_length(tvb) < 27) {
		return false;
	}

	/* Is it R-GOOSE? */
	spdu = tvb_get_uint8(tvb, 0);
	if (spdu != OSI_SPDU_GOOSE) {
		return false;
	}

	dissect_rgoose(tvb, pinfo, parent_tree, data);
	return true;
}

/*--- proto_register_goose -------------------------------------------*/
void proto_register_goose(void) {

	/* List of fields */
	static hf_register_info hf[] =
	{
		{ &hf_goose_session_header,
		{ "Session header", "rgoose.session_hdr",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_spdu_id,
		{ "Session identifier", "rgoose.spdu_id",
		  FT_UINT8, BASE_HEX_DEC, VALS(ositp_spdu_id), 0x0, NULL, HFILL }},

		{ &hf_goose_session_hdr_length,
		{ "Session header length", "rgoose.session_hdr_len",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_content_id,
		{ "Common session header identifier", "rgoose.common_session_id",
		  FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_hdr_length,
		{ "Header length", "rgoose.hdr_len",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_spdu_lenth,
		{ "SPDU length", "rgoose.spdu_len",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_spdu_num,
		{ "SPDU number", "rgoose.spdu_num",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_version,
		{ "Version", "rgoose.version",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_security_info,
		{ "Security information", "rgoose.sec_info",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_current_key_t,
		{ "Time of current key", "rgoose.curr_key_t",
		   FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_next_key_t,
		{ "Time of next key", "rgoose.next_key_t",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_key_id,
		{ "Key ID", "rgoose.key_id",
		  FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_init_vec_length,
		{ "Initialization vector length", "rgoose.init_v_len",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_init_vec,
		{ "Initialization vector", "rgoose.init_v",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_session_user_info,
		{ "Session user information", "rgoose.session_user_info",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_payload,
		{ "Payload", "rgoose.payload",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_payload_length,
		{ "Payload length", "rgoose.payload_len",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_tag,
		{ "Payload type tag", "rgoose.pdu_tag",
		  FT_UINT8, BASE_HEX_DEC, VALS(ositp_pdu_id), 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_simulation,
		{ "Simulation flag", "rgoose.simulation",
		  FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_appid,
		{ "APPID", "rgoose.appid",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_length,
		{ "APDU length", "rgoose.apdu_len",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_padding_tag,
		{ "Padding", "rgoose.padding_tag",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_padding_length,
		{ "Padding length", "rgoose.padding_len",
		  FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_padding,
		{ "Padding", "rgoose.padding",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_hmac,
		{ "HMAC", "rgoose.hmac",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_appid,
		{ "APPID", "goose.appid",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_length,
		{ "Length", "goose.length",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_reserve1,
		{ "Reserved 1", "goose.reserve1",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_reserve1_s_bit,
		{ "Simulated",	"goose.reserve1.s_bit",
		  FT_BOOLEAN, 16, NULL, F_RESERVE1_S_BIT, NULL, HFILL } },

		{ &hf_goose_reserve2,
		{ "Reserved 2", "goose.reserve2",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_float_value,
		{ "float value", "goose.float_value",
		  FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		#include "packet-goose-hfarr.c"
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_r_goose,
		&ett_session_header,
		&ett_security_info,
		&ett_session_user_info,
		&ett_payload,
		&ett_padding,
		&ett_goose,
		&ett_reserve1,
		&ett_expert_inf_sim,
		#include "packet-goose-ettarr.c"
	};

	static ei_register_info ei[] = {
		{ &ei_goose_mal_utctime,
		{ "goose.malformed.utctime", PI_MALFORMED, PI_WARN,
		  "BER Error: malformed UTCTime encoding", EXPFILL }},
		{ &ei_goose_zero_pdu,
		{ "goose.zero_pdu", PI_PROTOCOL, PI_ERROR,
		  "Internal error, zero-byte GOOSE PDU", EXPFILL }},
		{ &ei_goose_invalid_sim,
		{ "goose.invalid_sim", PI_PROTOCOL, PI_WARN,
		  "Invalid GOOSE: S bit set and Simulation attribute clear", EXPFILL }},
	};

	expert_module_t* expert_goose;

	/* Register protocol */
	proto_goose = proto_register_protocol(GOOSE_PNAME, GOOSE_PSNAME, GOOSE_PFNAME);
	proto_r_goose = proto_register_protocol(R_GOOSE_PNAME, R_GOOSE_PSNAME, R_GOOSE_PFNAME);

	goose_handle = register_dissector("goose", dissect_goose, proto_goose);

	/* Register fields and subtrees */
	proto_register_field_array(proto_goose, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_goose = expert_register_protocol(proto_goose);
	expert_register_field_array(expert_goose, ei, array_length(ei));

}

/*--- proto_reg_handoff_goose --- */
void proto_reg_handoff_goose(void) {

	dissector_add_uint("ethertype", ETHERTYPE_IEC61850_GOOSE, goose_handle);

	heur_dissector_add("cltp", dissect_rgoose_heur,
		"R-GOOSE (GOOSE over CLTP)", "rgoose_cltp", proto_goose, HEURISTIC_ENABLE);
}
