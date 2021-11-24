/* packet-flexray.c
 * Routines for FlexRay dissection
 * Copyright 2016, Roman Leonhartsberger <ro.leonhartsberger@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>

#include <packet-flexray.h>


void proto_reg_handoff_flexray(void);
void proto_register_flexray(void);

static gboolean prefvar_try_heuristic_first = FALSE;

static dissector_table_t subdissector_table;
static dissector_table_t flexrayid_subdissector_table;

static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

static int proto_flexray = -1;
static int hf_flexray_measurement_header_field = -1;
static int hf_flexray_error_flags_field = -1;
static int hf_flexray_frame_field = -1;

static int hf_flexray_ti = -1;
static int hf_flexray_ch = -1;
static int hf_flexray_fcrc_err = -1;
static int hf_flexray_hcrc_err = -1;
static int hf_flexray_fes_err = -1;
static int hf_flexray_cod_err = -1;
static int hf_flexray_tss_viol = -1;
static int hf_flexray_ppi = -1;
static int hf_flexray_nfi = -1;
static int hf_flexray_sfi = -1;
static int hf_flexray_stfi = -1;
static int hf_flexray_fid = -1;
static int hf_flexray_pl = -1;
static int hf_flexray_hcrc = -1;
static int hf_flexray_cc = -1;
static int hf_flexray_sl = -1;
static int hf_flexray_flexray_id = -1;

static gint ett_flexray = -1;
static gint ett_flexray_measurement_header = -1;
static gint ett_flexray_error_flags = -1;
static gint ett_flexray_frame = -1;

static int * const error_fields[] = {
	&hf_flexray_fcrc_err,
	&hf_flexray_hcrc_err,
	&hf_flexray_fes_err,
	&hf_flexray_cod_err,
	&hf_flexray_tss_viol,
	NULL
};

static int * const frame_fields[] = {
	&hf_flexray_ppi,
	&hf_flexray_sfi,
	&hf_flexray_stfi,
	NULL
};

static expert_field ei_flexray_frame_header = EI_INIT;
static expert_field ei_flexray_frame_payload = EI_INIT;
static expert_field ei_flexray_symbol_header = EI_INIT;
static expert_field ei_flexray_symbol_frame = EI_INIT;
static expert_field ei_flexray_error_flag = EI_INIT;
static expert_field ei_flexray_stfi_flag = EI_INIT;

#define FLEXRAY_FRAME 0x01
#define FLEXRAY_SYMBOL 0x02

#define FLEXRAY_HEADER_LENGTH 5

static const value_string flexray_type_names[] = {
	{ FLEXRAY_FRAME, "FRAME" },
	{ FLEXRAY_SYMBOL, "SYMB" },
	{0, NULL}
};

static const true_false_string flexray_channel = {
	"CHB",
	"CHA"
};

static const true_false_string flexray_nfi = {
	"False",
	"True"
};

guint32
flexray_calc_flexrayid(guint16 bus_id, guint8 channel, guint16 frame_id, guint8 cycle) {
	/* Bus-ID 4bit->4bit | Channel 1bit->4bit | Frame ID 11bit->16bit | Cycle 6bit->8bit */

	return (guint32)(bus_id & 0xf) << 28 |
	       (guint32)(channel & 0x0f) << 24 |
	       (guint32)(frame_id & 0xffff) << 8 |
	       (guint32)(cycle & 0xff);
}

guint32
flexray_flexrayinfo_to_flexrayid(flexray_info_t *flexray_info) {
	return flexray_calc_flexrayid(flexray_info->bus_id, flexray_info->ch, flexray_info->id, flexray_info->cc);
}

gboolean
flexray_call_subdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, flexray_info_t *flexray_info, const gboolean use_heuristics_first) {
	guint32 flexray_id = flexray_flexrayinfo_to_flexrayid(flexray_info);

	/* lets try an exact match first */
	if (dissector_try_uint_new(flexrayid_subdissector_table, flexray_id, tvb, pinfo, tree, TRUE, flexray_info)) {
		return TRUE;
	}

	/* lets try with BUS-ID = 0 (any) */
	if (dissector_try_uint_new(flexrayid_subdissector_table, flexray_id & ~FLEXRAY_ID_BUS_ID_MASK, tvb, pinfo, tree, TRUE, flexray_info)) {
		return TRUE;
	}

	/* lets try with cycle = 0xff (any) */
	if (dissector_try_uint_new(flexrayid_subdissector_table, flexray_id | FLEXRAY_ID_CYCLE_MASK, tvb, pinfo, tree, TRUE, flexray_info)) {
		return TRUE;
	}

	/* lets try with BUS-ID = 0 (any) and cycle = 0xff (any) */
	if (dissector_try_uint_new(flexrayid_subdissector_table, (flexray_id & ~FLEXRAY_ID_BUS_ID_MASK) | FLEXRAY_ID_CYCLE_MASK, tvb, pinfo, tree, TRUE, flexray_info)) {
		return TRUE;
	}

	if (!use_heuristics_first) {
		if (!dissector_try_payload_new(subdissector_table, tvb, pinfo, tree, FALSE, flexray_info)) {
			if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, flexray_info)) {
				return FALSE;
			}
		}
	} else {
		if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, flexray_info)) {
			if (!dissector_try_payload_new(subdissector_table, tvb, pinfo, tree, FALSE, flexray_info)) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

static int
dissect_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *flexray_tree, *type_info_tree, *error_flags_tree;
	proto_tree *flexray_frame_tree = NULL;
	tvbuff_t* next_tvb;
	gint frame_length;
	gint flexray_frame_length;
	gint flexray_current_payload_length;
	gint flexray_reported_payload_length;
	guint8 frame_type;
	guint8 symbol_length;
	guint8 error_flag;
	guint8 sfi;
	guint8 stfi;
	guint8 nfi;
	gboolean call_subdissector;
	flexray_info_t flexray_info;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FLEXRAY");
	col_clear(pinfo->cinfo, COL_INFO);

	frame_length = tvb_captured_length(tvb);
	frame_type = tvb_get_guint8(tvb, 0) & 0x7f;
	flexray_info.ch = tvb_get_guint8(tvb, 0) & 0x80;
	call_subdissector = TRUE;

	ti = proto_tree_add_item(tree, proto_flexray, tvb, 0, -1, ENC_NA);
	flexray_tree = proto_item_add_subtree(ti, ett_flexray);

	ti = proto_tree_add_item(flexray_tree, hf_flexray_measurement_header_field, tvb, 0, 1, ENC_BIG_ENDIAN);
	type_info_tree = proto_item_add_subtree(ti, ett_flexray_measurement_header);

	/* TODO: Added by later patch */
	flexray_info.bus_id = 0;

	proto_tree_add_item(type_info_tree, hf_flexray_ch, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(type_info_tree, hf_flexray_ti, tvb, 0, 1, ENC_BIG_ENDIAN);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s:", val_to_str(frame_type, flexray_type_names, "Unknown (0x%02x)"));

	if (frame_type == FLEXRAY_FRAME) {

		flexray_frame_length = frame_length - 2;
		error_flag = tvb_get_guint8(tvb, 1) & 0x1f;

		ti = proto_tree_add_bitmask(flexray_tree, tvb, 1, hf_flexray_error_flags_field, ett_flexray_error_flags, error_fields, ENC_BIG_ENDIAN);
		error_flags_tree = proto_item_add_subtree(ti, ett_flexray_error_flags);

		if (error_flag) {
			expert_add_info(pinfo, error_flags_tree, &ei_flexray_error_flag);
			call_subdissector = FALSE;
		}

		if (flexray_frame_length < FLEXRAY_HEADER_LENGTH) {
			expert_add_info(pinfo, flexray_tree, &ei_flexray_frame_header);
			call_subdissector = FALSE;
		}

		if (flexray_frame_length > 0) {

			sfi = tvb_get_guint8(tvb, 2) & 0x10;
			stfi = tvb_get_guint8(tvb, 2) & 0x08;

			ti = proto_tree_add_bitmask(flexray_tree, tvb, 2, hf_flexray_frame_field, ett_flexray_frame, frame_fields, ENC_BIG_ENDIAN);
			flexray_frame_tree = proto_item_add_subtree(ti, ett_flexray_frame);

			proto_tree_add_item(flexray_frame_tree, hf_flexray_nfi, tvb, 2, 1, ENC_BIG_ENDIAN);

			if (stfi) {
				if (!sfi) {
					expert_add_info(pinfo, flexray_frame_tree, &ei_flexray_stfi_flag);
					call_subdissector = FALSE;
				}
			}
		}

		if (flexray_frame_length > 1) {

			flexray_info.id = tvb_get_ntohs(tvb, 2) & 0x07ff;

			col_append_fstr(pinfo->cinfo, COL_INFO, " ID %4d", flexray_info.id);

			proto_tree_add_item(flexray_frame_tree, hf_flexray_fid, tvb, 2, 2, ENC_BIG_ENDIAN);

			if (flexray_info.id == 0) {
				call_subdissector = FALSE;
			}
		}

		if (flexray_frame_length > 2) {

			proto_tree_add_item(flexray_frame_tree, hf_flexray_pl, tvb, 4, 1, ENC_BIG_ENDIAN);
		}

		if (flexray_frame_length > 4) {

			flexray_reported_payload_length = tvb_get_guint8(tvb, 4) & 0xfe;
			flexray_reported_payload_length = 2 * (flexray_reported_payload_length >> 1);
			flexray_current_payload_length = flexray_frame_length - FLEXRAY_HEADER_LENGTH;
			flexray_info.cc = tvb_get_guint8(tvb, 6) & 0x3f;
			nfi = tvb_get_guint8(tvb, 2) & 0x20;

			col_append_fstr(pinfo->cinfo, COL_INFO, " CC %2d", flexray_info.cc);

			proto_tree_add_item(flexray_frame_tree, hf_flexray_hcrc, tvb, 4, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(flexray_frame_tree, hf_flexray_cc, tvb, 6, 1, ENC_BIG_ENDIAN);
                        ti = proto_tree_add_uint(flexray_frame_tree, hf_flexray_flexray_id, tvb, 0, 7, flexray_flexrayinfo_to_flexrayid(&flexray_info));
                        proto_item_set_hidden(ti);

			if (nfi) {
				if (tvb != NULL && flexray_current_payload_length > 0) {
					col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, 7, flexray_current_payload_length, ' '));
				}
				if (flexray_current_payload_length != flexray_reported_payload_length) {
					expert_add_info(pinfo, flexray_frame_tree, &ei_flexray_frame_payload);
					call_subdissector = FALSE;
				}
			}
			else {
				call_subdissector = FALSE;
				col_append_fstr(pinfo->cinfo, COL_INFO, "   NF");
				if (flexray_current_payload_length != flexray_reported_payload_length && flexray_current_payload_length != 0) {
					expert_add_info(pinfo, flexray_frame_tree, &ei_flexray_frame_payload);
				}
			}

			next_tvb = tvb_new_subset_length(tvb, 7, flexray_current_payload_length);

			if (!call_subdissector || !flexray_call_subdissectors(next_tvb, pinfo, tree, &flexray_info, prefvar_try_heuristic_first)) {
				call_data_dissector(next_tvb, pinfo, tree);
			}
		}
	}

	if ((frame_type & 0x07ff) == FLEXRAY_SYMBOL) {

		flexray_frame_length = frame_length - 1;

		expert_add_info(pinfo, flexray_tree, &ei_flexray_symbol_frame);

		if (flexray_frame_length > 0) {

			symbol_length = tvb_get_guint8(tvb, 1) & 0x7f;

			col_append_fstr(pinfo->cinfo, COL_INFO, " SL %3d", symbol_length);

			proto_tree_add_item(flexray_tree, hf_flexray_sl, tvb, 1, 1, ENC_BIG_ENDIAN);
		}
		else {
			expert_add_info(pinfo, flexray_tree, &ei_flexray_symbol_header);
		}
	}

	return tvb_captured_length(tvb);
}

void
proto_register_flexray(void)
{
	module_t *flexray_module;
	expert_module_t *expert_flexray;

	static hf_register_info hf[] = {
		{ &hf_flexray_measurement_header_field,
			{ "Measurement Header", "flexray.mhf",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_flexray_ti,
			{ "Type Index", "flexray.ti",
			FT_UINT8, BASE_HEX,
			VALS(flexray_type_names), 0x7f,
			NULL, HFILL }
		},
		{ &hf_flexray_ch,
			{ "Channel", "flexray.ch",
			FT_BOOLEAN, 8,
			TFS(&flexray_channel), 0x80,
			NULL, HFILL }
		},
		{ &hf_flexray_error_flags_field,
			{ "Error Flags", "flexray.eff",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_flexray_fcrc_err,
			{ "Frame CRC error", "flexray.fcrc_err",
			FT_BOOLEAN, 8,
			NULL, 0x10,
			NULL, HFILL }
		},
		{ &hf_flexray_hcrc_err,
			{ "Header CRC error", "flexray.hcrc_err",
			FT_BOOLEAN, 8,
			NULL, 0x08,
			NULL, HFILL }
		},
		{ &hf_flexray_fes_err,
			{ "Frame End Sequence error", "flexray.fes_err",
			FT_BOOLEAN, 8,
			NULL, 0x04,
			NULL, HFILL }
		},
		{ &hf_flexray_cod_err,
			{ "Coding error", "flexray.cod_err",
			FT_BOOLEAN, 8,
			NULL, 0x02,
			NULL, HFILL }
		},
		{ &hf_flexray_tss_viol,
			{ "TSS violation", "flexray.tss_viol",
			FT_BOOLEAN, 8,
			NULL, 0x01,
			NULL, HFILL }
		},
		{ &hf_flexray_frame_field,
			{ "FlexRay Frame", "flexray.ff",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_flexray_ppi,
			{ "Payload preamble Indicator", "flexray.ppi",
			FT_BOOLEAN, 8,
			NULL, 0x40,
			NULL, HFILL }
		},
		{ &hf_flexray_nfi,
			{ "Null Frame", "flexray.nfi",
			FT_BOOLEAN, 8,
			TFS(&flexray_nfi), 0x20,
			NULL, HFILL }
		},
		{ &hf_flexray_sfi,
			{ "Sync Frame Indicator", "flexray.sfi",
			FT_BOOLEAN, 8,
			NULL, 0x10,
			NULL, HFILL }
		},
		{ &hf_flexray_stfi,
			{ "Startup Frame Indicator", "flexray.stfi",
			FT_BOOLEAN, 8,
			NULL, 0x08,
			NULL, HFILL }
		},
		{ &hf_flexray_fid,
			{ "Frame ID", "flexray.fid",
			FT_UINT16, BASE_DEC,
			NULL, 0x07ff,
			NULL, HFILL }
		},
		{ &hf_flexray_pl,
			{ "Payload length", "flexray.pl",
			FT_UINT8, BASE_DEC,
			NULL, 0xfe,
			NULL, HFILL }
		},
		{ &hf_flexray_hcrc,
			{ "Header CRC", "flexray.hcrc",
			FT_UINT24, BASE_DEC,
			NULL, 0x01ffc0,
			NULL, HFILL }
		},
		{ &hf_flexray_cc,
			{ "Cycle Counter", "flexray.cc",
			FT_UINT8, BASE_DEC,
			NULL, 0x3f,
			NULL, HFILL }
		},
		{ &hf_flexray_sl,
			{ "Symbol length", "flexray.sl",
			FT_UINT8, BASE_DEC,
			NULL, 0x7f,
			NULL, HFILL }
		},
		{ &hf_flexray_flexray_id,
			{ "FlexRay ID (combined)", "flexray.combined_id",
			FT_UINT32, BASE_HEX,
			NULL, 0,
			NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_flexray,
		&ett_flexray_measurement_header,
		&ett_flexray_error_flags,
		&ett_flexray_frame
	};

	static ei_register_info ei[] = {
		{ &ei_flexray_frame_header,
		{ "flexray.frame_header", PI_MALFORMED, PI_ERROR,
			"Frame Header is malformed", EXPFILL }
		},
		{ &ei_flexray_frame_payload,
		{ "flexray.malformed_frame_payload", PI_MALFORMED, PI_ERROR,
			"Frame Payload is malformed", EXPFILL }
		},
		{ &ei_flexray_symbol_header,
			{ "flexray.malformed_symbol_frame", PI_MALFORMED, PI_ERROR,
			"Symbol Frame is malformed", EXPFILL }
		},
		{ &ei_flexray_symbol_frame,
			{ "flexray.symbol_frame", PI_SEQUENCE, PI_CHAT,
			"Packet is a Symbol Frame", EXPFILL }
		},
		{ &ei_flexray_error_flag,
			{ "flexray.error_flag", PI_PROTOCOL, PI_WARN,
			"Error Flag is set", EXPFILL }
		},
		{ &ei_flexray_stfi_flag,
			{ "flexray.stfi_flag", PI_PROTOCOL, PI_WARN,
			"A startup frame must always be a sync frame", EXPFILL }
		}
	};

	proto_flexray = proto_register_protocol(
		"FlexRay Protocol",
		"FLEXRAY",
		"flexray"
		);

	flexray_module = prefs_register_protocol(proto_flexray, NULL);

	proto_register_field_array(proto_flexray, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_flexray = expert_register_protocol(proto_flexray);
	expert_register_field_array(expert_flexray, ei, array_length(ei));

	register_dissector("flexray", dissect_flexray, proto_flexray);

	prefs_register_bool_preference(
		flexray_module,
		"try_heuristic_first",
		"Try heuristic sub-dissectors first",
		"Try to decode a packet using an heuristic sub-dissector"
		" before using a sub-dissector registered to \"decode as\"",
		&prefvar_try_heuristic_first
		);

	subdissector_table = register_decode_as_next_proto(proto_flexray, "flexray.subdissector", "FLEXRAY next level dissector", NULL);
	flexrayid_subdissector_table = register_dissector_table("flexray.combined_id", "FlexRay ID (combined)", proto_flexray, FT_UINT32, BASE_HEX);
	heur_subdissector_list = register_heur_dissector_list("flexray", proto_flexray);
}

void
proto_reg_handoff_flexray(void)
{
	static dissector_handle_t flexray_handle;

	flexray_handle = create_dissector_handle( dissect_flexray, proto_flexray );
	dissector_add_uint("wtap_encap", WTAP_ENCAP_FLEXRAY, flexray_handle);
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
