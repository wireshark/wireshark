/* packet-gsm_abis_pgsl.c
 * Routines for packet dissection of Ericsson GSM A-bis P-GSL
 * Copyright 2010-2016 by Harald Welte <laforge@gnumonks.org>
 *
 * P-GSL is an Ericsson-specific packetized version of replacing PCU-CCU
 * TRAU frames on 8k/16k E1 sub-slots with a paketized frame format
 * which can be transported over LAPD on a SuperChannel (E1 timeslot
 * bundle) or L2TP.
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

void proto_register_abis_pgsl(void);
void proto_reg_handoff_abis_pgsl(void);

enum {
	SUB_DATA,

	SUB_MAX
};

static dissector_handle_t sub_handles[SUB_MAX];

/* initialize the protocol and registered fields */
static int proto_abis_pgsl = -1;

/* P-GSL header */
static int hf_pgsl_version = -1;
static int hf_pgsl_msg_disc = -1;
static int hf_pgsl_tn_bitmap = -1;
static int hf_pgsl_trx_seqno = -1;
static int hf_pgsl_afnd = -1;
static int hf_pgsl_afnu = -1;
static int hf_pgsl_ccu_ta = -1;
static int hf_pgsl_ack_req = -1;
static int hf_pgsl_tn_resource = -1;
static int hf_pgsl_tn_seqno = -1;
static int hf_pgsl_data_len = -1;
static int hf_pgsl_cause = -1;
static int hf_pgsl_addl_info = -1;
static int hf_pgsl_ack_ind = -1;
static int hf_pgsl_data_ind = -1;
static int hf_pgsl_ucm = -1;
static int hf_pgsl_cs = -1;
static int hf_pgsl_timing_offset = -1;
static int hf_pgsl_power_control = -1;
static int hf_pgsl_ir_tfi = -1;
static int hf_pgsl_ir_sign_type = -1;
static int hf_pgsl_codec_delay = -1;
static int hf_pgsl_codec_cs = -1;
static int hf_pgsl_codec_rxlev = -1;
static int hf_pgsl_codec_parity = -1;
static int hf_pgsl_codec_bqm = -1;
static int hf_pgsl_codec_mean_bep = -1;
static int hf_pgsl_codec_cv_bep = -1;
static int hf_pgsl_codec_q = -1;
static int hf_pgsl_codec_q1 = -1;
static int hf_pgsl_codec_q2 = -1;

/* initialize the subtree pointers */
static int ett_pgsl = -1;

#define PGSL_MSG_DLDATA_REQ	1
#define PGSL_MSG_DLDATA_IND	2
#define PGSL_MSG_ULDATA_IND	3
#define PGSL_MSG_STATUS_IND	4

static const value_string pgsl_msg_disc_vals[] = {
	{ PGSL_MSG_DLDATA_REQ,	"PGSL-DLDATA-REQ" },
	{ PGSL_MSG_DLDATA_IND,	"PGSL-DLDATA-IND" },
	{ PGSL_MSG_ULDATA_IND,	"PGSL-ULDATA-IND" },
	{ PGSL_MSG_STATUS_IND,	"PGSL-STATUS-IND" },
	{ 0, NULL }
};

static const value_string pgsl_msg_cause_vals[] = {
	{ 0, "Frame discarded in CCU, too late" },
	{ 1, "Frame discarded in CCU, too late or OOM" },
	{ 2, "Frame(s) missing in sequence detected by CCU" },
	{ 3, "Frame Format Error" },
	{ 0, NULL }
};

static const value_string pgsl_cs_vals[] = {
	{ 0,	"AB" },
	{ 1,	"CS-1" },
	{ 2,	"CS-2" },
	{ 3,	"CS-3" },
	{ 4,	"CS-4" },
	{ 5,	"Header Type 1" },
	{ 6,	"Header Type 2" },
	{ 7,	"Header Type 3" },
	{ 0, NULL }
};

static const value_string pgsl_ir_sign_type_vals[] = {
	{ 0, "IR Update Indication" },
	{ 1, "IR Start Indication" },
	{ 2, "IR Stop Indication" },
	{ 3, "No IR Information" },
	{ 0, NULL }
};

static int
dissect_abis_pgsl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *pgsl_tree;
	int offset = 0;
	tvbuff_t *next_tvb;
	guint32 msg_disc, len, ack_data_ind, cs;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P-GSL");

	ti = proto_tree_add_item(tree, proto_abis_pgsl, tvb, 0, -1, ENC_NA);
	pgsl_tree = proto_item_add_subtree(ti, ett_pgsl);

	proto_tree_add_item(pgsl_tree, hf_pgsl_version, tvb, offset, 1, ENC_NA);
	proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_msg_disc, tvb, offset, 1, ENC_NA, &msg_disc);
	offset++;

	col_append_str(pinfo->cinfo, COL_INFO, val_to_str(msg_disc, pgsl_msg_disc_vals, "Unknown (%u)"));

	switch (msg_disc) {
	case PGSL_MSG_DLDATA_REQ:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_bitmap, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_trx_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_afnd, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;
		proto_tree_add_item(pgsl_tree, hf_pgsl_ccu_ta, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_ack_req, tvb, offset++, 1, ENC_NA);
		break;
	case PGSL_MSG_DLDATA_IND:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_resource, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_afnd, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;
		ack_data_ind = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(pgsl_tree, hf_pgsl_ack_ind, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_data_ind, tvb, offset++, 1, ENC_NA);
		if (ack_data_ind & 1) {
			/* Codec Control */
			proto_tree_add_item(pgsl_tree, hf_pgsl_ucm, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_cs, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_timing_offset, tvb, offset+1, 1, ENC_NA);
			offset += 2;
			/* Power Control */
			proto_tree_add_item(pgsl_tree, hf_pgsl_power_control, tvb, offset++, 1, ENC_NA);
			/* Incremental Redundancy */
			proto_tree_add_item(pgsl_tree, hf_pgsl_ir_tfi, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_ir_sign_type, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_tn_bitmap, tvb, offset+1, 1, ENC_NA);
			offset += 2;
			/* Data length */
			proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_data_len, tvb, offset++, 1, ENC_NA, &len);
			/* Data */
			next_tvb = tvb_new_subset_length(tvb, offset, len);
			call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
		}
		break;
	case PGSL_MSG_ULDATA_IND:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_resource, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_afnu, tvb, offset, 3, ENC_NA);
		offset += 3;
		/* Codec Status */
		proto_tree_add_item(pgsl_tree, hf_pgsl_codec_delay, tvb, offset, 1, ENC_NA);
		proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_codec_cs, tvb, offset, 1, ENC_NA, &cs);
		proto_tree_add_item(pgsl_tree, hf_pgsl_codec_rxlev, tvb, offset+1, 1, ENC_NA);
		if (cs <= 4) {
			/* GPRS */
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_parity, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_bqm, tvb, offset+2, 1, ENC_NA);
		} else {
			/* EGPRS */
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_mean_bep, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_cv_bep, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_q, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_q1, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_q2, tvb, offset+3, 1, ENC_NA);
		}
		offset += 4;
		/* Data Length */
		proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_data_len, tvb, offset++, 1, ENC_NA, &len);
		/* Data */
		next_tvb = tvb_new_subset_length(tvb, offset, len);
		call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
		break;
	case PGSL_MSG_STATUS_IND:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_resource, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_afnu, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_cause, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_addl_info, tvb, offset++, 1, ENC_NA);
		break;
	}

	return offset;
}

void
proto_register_abis_pgsl(void)
{
	static hf_register_info hf[] = {
		{ &hf_pgsl_version,
			{ "Version", "gsm_abis_pgsl.version",
			  FT_UINT8, BASE_DEC, NULL, 0xf0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_msg_disc,
			{ "Message Discriminator", "gsm_abis_pgsl.msg_disc",
			  FT_UINT8, BASE_DEC, VALS(pgsl_msg_disc_vals), 0x0f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_tn_bitmap,
			{ "TN Bitmap", "gsm_abis_pgsl.tn_bitmap",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_trx_seqno,
			{ "TRX Sequence Number", "gsm_abis_pgsl.trx_seqno",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Per-TRX Sequence Number", HFILL }
		},
		{ &hf_pgsl_afnd,
			{ "aFNd", "gsm_abis_pgsl.a_fn_d",
			  FT_UINT24, BASE_DEC, NULL, 0,
			  "Frame Number (Downlink)", HFILL }
		},
		{ &hf_pgsl_afnu,
			{ "aFNu", "gsm_abis_pgsl.a_fn_u",
			  FT_UINT24, BASE_DEC, NULL, 0,
			  "Frame Number (Uplink)", HFILL }
		},
		{ &hf_pgsl_ccu_ta,
			{ "CCU TA Value", "gsm_abis_pgsl.ccu_ta",
			  FT_UINT8, BASE_DEC, NULL, 0x3f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ack_req,
			{ "ACK Requested", "gsm_abis_pgsl.ack_req",
			  FT_BOOLEAN, 8, NULL, 0x01,
			  NULL, HFILL }
		},
		{ &hf_pgsl_tn_resource,
			{ "TN Resource", "gsm_abis_pgsl.tn_resource",
			  FT_UINT8, BASE_DEC, NULL, 0x07,
			  "Timeslot Number", HFILL }
		},
		{ &hf_pgsl_tn_seqno,
			{ "TN Sequence Number", "gsm_abis_pgsl.tn_seqno",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Per-TN Sequence Number", HFILL }
		},
		{ &hf_pgsl_data_len,
			{ "Data Length", "gsm_abis_pgsl.data_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_cause,
			{ "Cause", "gsm_abis_pgsl.cause",
			  FT_UINT8, BASE_DEC, VALS(pgsl_msg_cause_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_addl_info,
			{ "Additional Info", "gsm_abis_pgsl.addl_info",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ack_ind,
			{ "ACK Indicator", "gsm_abis_pgsl.ack_ind",
			  FT_BOOLEAN, 8, NULL, 0x02,
			  NULL, HFILL }
		},
		{ &hf_pgsl_data_ind,
			{ "Data Indicator", "gsm_abis_pgsl.data_ind",
			  FT_BOOLEAN, 8, NULL, 0x01,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ucm,
			{ "Uplink Channel Mode", "gsm_abis_pgsl.ucm",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_cs,
			{ "Coding Scheme", "gsm_abis_pgsl.cs",
			  FT_UINT8, BASE_DEC, VALS(pgsl_cs_vals), 0x1f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_timing_offset,
			{ "Timing Offset", "gsm_abis_pgsl.timing_offset",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_power_control,
			{ "Power Control", "gsm_abis_pgsl.power_control",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ir_tfi,
			{ "TFI", "gsm_abis_pgsl.ir_tfi",
			  FT_UINT8, BASE_DEC, NULL, 0x7c,
			  "TBF Identifier", HFILL }
		},
		{ &hf_pgsl_ir_sign_type,
			{ "IR Signalling Type", "gsm_abis_pgsl.ir_sign_type",
			  FT_UINT8, BASE_DEC, VALS(pgsl_ir_sign_type_vals), 0x03,
			  NULL, HFILL }
		},
		{ &hf_pgsl_codec_delay,
			{ "Codec Delay", "gsm_abis_pgsl.codec_delay",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  "Estimated Accss Delay Deviation", HFILL }
		},
		{ &hf_pgsl_codec_cs,
			{ "Codec CS", "gsm_abis_pgsl.codec_csy",
			  FT_UINT8, BASE_DEC, VALS(pgsl_cs_vals), 0x1f,
			  "Coding Scheme Status", HFILL }
		},
		{ &hf_pgsl_codec_rxlev,
			{ "RxLev", "gsm_abis_pgsl.codec_csy",
			  FT_UINT8, BASE_DEC, NULL, 0x3f,
			  "Receiver Level Measurement", HFILL }
		},
		{ &hf_pgsl_codec_parity,
			{ "GPRS Parity", "gsm_abis_pgsl.gprs_parity",
			  FT_BOOLEAN, 8, NULL, 0x08,
			  "GPRS Block Status Parity", HFILL }
		},
		{ &hf_pgsl_codec_bqm,
			{ "GPRS BQM", "gsm_abis_pgsl.gprs_bqm",
			  FT_UINT8, BASE_DEC, NULL, 0x07,
			  "GPRS Block Quality Measurement", HFILL }
		},
		{ &hf_pgsl_codec_mean_bep,
			{ "EGPRS MEAN_BEP", "gsm_abis_pgsl.egprs_mean_bep",
			  FT_UINT8, BASE_DEC, NULL, 0x7f,
			  "Mean Value of BEP", HFILL }
		},
		{ &hf_pgsl_codec_cv_bep,
			{ "EGPRS CV_BEP", "gsm_abis_pgsl.egprs_cv_bep",
			  FT_UINT8, BASE_DEC, NULL, 0x07,
			  "Variation Co-Efficient of BEP", HFILL }
		},
		{ &hf_pgsl_codec_q,
			{ "EGPRS Header Quality", "gsm_abis_pgsl.egprs_q",
			  FT_BOOLEAN, 8, NULL, 0x08,
			  "EGPRS RLC/MAC Header Quality", HFILL }
		},
		{ &hf_pgsl_codec_q1,
			{ "EGPRS Data Block 1 Quality", "gsm_abis_pgsl.egprs_q1",
			  FT_BOOLEAN, 8, NULL, 0x10,
			  NULL, HFILL }
		},
		{ &hf_pgsl_codec_q2,
			{ "EGPRS Data Block 2 Quality", "gsm_abis_pgsl.egprs_q2",
			  FT_BOOLEAN, 8, NULL, 0x20,
			  NULL, HFILL }
		},
	};
	static gint *ett[] = {
		&ett_pgsl,
	};

	/* assign our custom match functions */
	proto_abis_pgsl = proto_register_protocol("GSM A-bis P-GSL", "Ericsson GSM A-bis P-GSL",
						 "gsm_abis_pgsl");

	proto_register_field_array(proto_abis_pgsl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("gsm_abis_pgsl", dissect_abis_pgsl, proto_abis_pgsl);
}

/* This function is called once at startup and every time the user hits
 * 'apply' in the preferences dialogue */
void
proto_reg_handoff_abis_pgsl(void)
{
	sub_handles[SUB_DATA] = find_dissector("data");
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
