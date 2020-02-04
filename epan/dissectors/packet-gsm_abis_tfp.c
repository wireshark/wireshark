/* packet-gsm_abis_tfp.c
 * Routines for packet dissection of Ericsson GSM A-bis TFP
 * (Traffic Forwarding Protocol)
 * Copyright 2010-2016 by Harald Welte <laforge@gnumonks.org>
 *
 * TFP is an Ericsson-specific packetized version of replacing TRAU
 * frames on 8k/16k E1 sub-slots with a paketized frame format which
 * can be transported over LAPD on a SuperChannel (E1 timeslot bundle)
 * or L2TP.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_abis_tfp(void);
void proto_reg_handoff_abis_tfp(void);

enum {
	SUB_DATA,

	SUB_MAX
};

static dissector_handle_t tfp_handle;
static dissector_handle_t sub_handles[SUB_MAX];

/* initialize the protocol and registered fields */
static int proto_abis_tfp = -1;

/* TFP header */
static int hf_tfp_hdr_atsr = -1;
static int hf_tfp_hdr_slot_rate = -1;
static int hf_tfp_hdr_seq_nr = -1;
static int hf_tfp_hdr_delay_info = -1;
static int hf_tfp_hdr_p = -1;
static int hf_tfp_hdr_s = -1;
static int hf_tfp_hdr_m = -1;
static int hf_tfp_hdr_frame_type = -1;
static int hf_tfp_amr_rate = -1;

/* initialize the subtree pointers */
static int ett_tfp = -1;

static const value_string tfp_slot_rate_vals[] = {
	{ 0,	"Full Rate (16kbps)" },
	{ 1,	"Sub-Channel 0 (8kbps)" },
	{ 2,	"Sub-Channel 1 (8kbps)" },
	{ 3,	"Reserved" },
	{ 0, NULL }
};

#define TFP_PACKED_NONE		0
#define TFP_PACKED_SCHEME_1	1

static const value_string tfp_packed_vals[] = {
	{ 0,	"Not Packed" },
	{ 1,	"Packing Scheme 1" },
	{ 0, NULL }
};

static const value_string tfp_frame_type_vals[] = {
	/* 8k */
	{ 0, 	"TFP-AMR-IND" },
	{ 1,	"TFP-SCCE-AMR-IND" },
	{ 2,	"TFP-HR-IND" },
	/* 16k */
	{ 0x80, "TFP-AMR-IND" },
	{ 0x81,	"TFP-SCCE-AMR-IND" },
	{ 0x82,	"TFP-FR-IND" },
	{ 0x83,	"TFP-EFR-IND" },
	{ 0x84,	"TFP-SCCE-EFR-IND" },
	{ 0, NULL }
};

static const value_string tfp_amr_len_rate_vals[] = {
	{  1, "SID_FIRST, ONSET, No speech/data" },
	{  5, "SID_UPDATE, SID_BAD" },
	{ 12, "4.75k" },
	{ 13, "5.15k" },
	{ 15, "5.90k" },
	{ 17, "6.70k" },
	{ 19, "7.40k" },
	{ 20, "7.95k" },
	{ 26, "10.2k" },
	{ 31, "12.2k" },
	{ 0, NULL }
};

static int
dissect_abis_tfp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *tfp_tree;
	int offset = 0;
	guint32 slot_rate, frame_bits, atsr, seq_nr;
	guint8 ftype;
	tvbuff_t *next_tvb;
	gint len_remain;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFP");

	ti = proto_tree_add_item(tree, proto_abis_tfp, tvb, 0, -1, ENC_NA);
	tfp_tree = proto_item_add_subtree(ti, ett_tfp);

	proto_tree_add_item_ret_uint(tfp_tree, hf_tfp_hdr_atsr, tvb, offset, 2, ENC_BIG_ENDIAN, &atsr);
	proto_tree_add_item_ret_uint(tfp_tree, hf_tfp_hdr_slot_rate, tvb, offset, 2, ENC_BIG_ENDIAN, &slot_rate);
	proto_tree_add_item_ret_uint(tfp_tree, hf_tfp_hdr_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &seq_nr);
	proto_tree_add_item(tfp_tree, hf_tfp_hdr_delay_info, tvb, offset+1, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tfp_tree, hf_tfp_hdr_p, tvb, offset+1, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tfp_tree, hf_tfp_hdr_s, tvb, offset+2, 1, ENC_NA);
	proto_tree_add_item(tfp_tree, hf_tfp_hdr_m, tvb, offset+2, 1, ENC_NA);
	/* Frame Type depends on Slot Rate */
	ftype = tvb_get_guint8(tvb, offset+2) & 0x1E;
	if (slot_rate == 0)
		ftype |= 0x80;
	proto_tree_add_uint_format_value(tfp_tree, hf_tfp_hdr_frame_type, tvb, offset+2, 1, ftype, "%s",
					 val_to_str(ftype, tfp_frame_type_vals, "Unknown (%u)"));
	offset += 2;

	col_append_fstr(pinfo->cinfo, COL_INFO, "TS=%u, Seq=%u, %s, %s ", atsr, seq_nr,
			val_to_str(slot_rate, tfp_slot_rate_vals, "Unknown (%u)"),
			val_to_str(ftype, tfp_frame_type_vals, "Unknown (%u)"));

	/* check for Tail bit == 1, iterate over further octests */
	while ((tvb_get_guint8(tvb, offset) & 0x01) == 0)
		offset++;
	offset++;

	switch (ftype & 0x7F) {
	case 0: /* TFP-AMR.ind */
		len_remain = tvb_captured_length_remaining(tvb, offset);
		proto_tree_add_uint(tfp_tree, hf_tfp_amr_rate, tvb, offset, 0, len_remain);
		break;
	case 1: /* TFP-SCCE-AMR.ind */
		break;
	case 2: /* TFP-HR.ind */
		break;
	case 3: /* TFP-EFR.ind */
		break;
	case 4: /* TFP-SCCE-EFR.ind */
		break;
	}

	/* FIXME: implement packed frame support */
	if (slot_rate == 0)
		frame_bits = 320;
	else
		frame_bits = 160;
	next_tvb = tvb_new_subset_length(tvb, offset, frame_bits/8);
	call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);

	return offset;
}

void
proto_register_abis_tfp(void)
{
	static hf_register_info hf[] = {
		{ &hf_tfp_hdr_atsr,
			{ "Air Timeslot Resource", "gsm_abis_tfp.atsr",
			  FT_UINT16, BASE_DEC, NULL, 0xe000,
			  NULL, HFILL }
		},
		{ &hf_tfp_hdr_slot_rate,
			{ "Slot Rate", "gsm_abis_tfp.slot_rate",
			  FT_UINT16, BASE_DEC, VALS(tfp_slot_rate_vals), 0x1800,
			  NULL, HFILL }
		},
		{ &hf_tfp_hdr_seq_nr,
			{ "Sequence Number", "gsm_abis_tfp.seq_nr",
			  FT_UINT16, BASE_DEC, NULL, 0x07c0,
			  NULL, HFILL }
		},
		{ &hf_tfp_hdr_delay_info,
			{ "Delay Information (ms)", "gsm_abis_tfp.delay_info",
			  FT_UINT16, BASE_DEC, NULL, 0x003e,
			  NULL, HFILL }
		},
		{ &hf_tfp_hdr_p,
			{ "Packing Scheme", "gsm_abis_tfp.packing_scheme",
			  FT_UINT16, BASE_DEC, VALS(tfp_packed_vals), 0x0180,
			  NULL, HFILL }
		},
		{ &hf_tfp_hdr_s,
			{ "Silence Indicator", "gsm_abis_tfp.silence_ind",
			  FT_BOOLEAN, 8, NULL, 0x40,
			  NULL, HFILL }
		},
		{ &hf_tfp_hdr_m,
			{ "Marker bit", "gsm_abis_tfp.marker",
			  FT_BOOLEAN, 8, NULL, 0x20,
			  NULL, HFILL }
		},
		{ &hf_tfp_hdr_frame_type,
			{ "Frame Type", "gsm_abis_tfp.frame_type",
			  FT_UINT8, BASE_DEC, VALS(tfp_frame_type_vals), 0x1e,
			  NULL, HFILL }
		},
		{ &hf_tfp_amr_rate,
			{ "AMR Rate", "gsm_abis_tfp.amr.rate",
			  FT_UINT8, BASE_DEC, VALS(tfp_amr_len_rate_vals), 0,
			  NULL, HFILL }
		},
	};
	static gint *ett[] = {
		&ett_tfp,
	};

	/* assign our custom match functions */
	proto_abis_tfp = proto_register_protocol("GSM A-bis TFP", "Ericsson GSM A-bis TFP",
						 "gsm_abis_tfp");

	proto_register_field_array(proto_abis_tfp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	tfp_handle = register_dissector("gsm_abis_tfp", dissect_abis_tfp, proto_abis_tfp);
}

/* This function is called once at startup and every time the user hits
 * 'apply' in the preferences dialogue */
void
proto_reg_handoff_abis_tfp(void)
{
	/* Those two SAPI values 10/11 are non-standard values, not specified by
	 * ETSI/3GPP, just like this very same protocol. */
	dissector_add_uint("lapd.gsm.sapi", 10, tfp_handle);
	dissector_add_uint("lapd.gsm.sapi", 11, tfp_handle);
	sub_handles[SUB_DATA] = find_dissector("data");
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
