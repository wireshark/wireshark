/* packet-jpeg.c
 *
 * Routines for RFC 2435 JPEG dissection
 *
 * Copyright 2006
 * Erwin Rol <erwin@erwinrol.com>
 * Copyright 2001,
 * Francisco Javier Cabello Torres, <fjcabello@vtools.es>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>

#include <epan/rtp_pt.h>

#include "packet-ber.h"

void proto_register_jpeg(void);
void proto_reg_handoff_jpeg(void);

static dissector_handle_t jpeg_handle;

static const range_string jpeg_ts_rvals [] = {
    {0, 0,      "Progressively scanned"},
    {1, 1,      "Odd field of interlaced signal"},
    {2, 2,      "Even field of interlaced signal"},
    {3, 3,      "Interlaced field to be line doubled"},
    {3, 0xff,   "Unspecified"},
    {0, 0,      NULL}
};

static const range_string jpeg_type_rvals [] = {
    {  0,   0,  "4:2:2 Video"},
    {  1,   1,  "4:2:0 Video"},
    {  2,   5,  "Reserved"}, /* Previously assigned by RFC 2035 */
    {  6,  63,  "Unassigned"},
    { 64,  64,  "4:2:0 Video, Restart Markers present"},
    { 65,  65,  "4:2:0 Video, Restart Markers present"},
    { 66,  69,  "Reserved"}, /* Since [2,5] are reserved */
    { 70, 127,  "Unassigned, Restart Markers present"},
    {128, 255,  "Dynamically assigned"},
    {  0,   0,  NULL}
};

static int proto_jpeg;

static int hf_rtp_jpeg_main_hdr;
static int hf_rtp_jpeg_main_hdr_height;
static int hf_rtp_jpeg_main_hdr_offs;
static int hf_rtp_jpeg_main_hdr_q;
static int hf_rtp_jpeg_main_hdr_ts;
static int hf_rtp_jpeg_main_hdr_type;
static int hf_rtp_jpeg_main_hdr_width;
static int hf_rtp_jpeg_payload;
static int hf_rtp_jpeg_qtable_hdr;
static int hf_rtp_jpeg_qtable_hdr_data;
static int hf_rtp_jpeg_qtable_hdr_length;
static int hf_rtp_jpeg_qtable_hdr_mbz;
static int hf_rtp_jpeg_qtable_hdr_prec;
static int hf_rtp_jpeg_restart_hdr;
static int hf_rtp_jpeg_restart_hdr_count;
static int hf_rtp_jpeg_restart_hdr_f;
static int hf_rtp_jpeg_restart_hdr_interval;
static int hf_rtp_jpeg_restart_hdr_l;

/* JPEG fields defining a sub tree */
static int ett_jpeg;

static int
dissect_jpeg( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
	proto_item *ti = NULL;
	proto_tree *jpeg_tree = NULL;
	proto_tree *main_hdr_tree = NULL;
	proto_tree *restart_hdr_tree = NULL;
	proto_tree *qtable_hdr_tree = NULL;
	uint32_t fragment_offset = 0;
	uint16_t len = 0;
	uint8_t type = 0;
	uint8_t q = 0;
	int h = 0;
	int w = 0;

	unsigned int offset       = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "JPEG");

	col_set_str(pinfo->cinfo, COL_INFO, "JPEG message");

	if ( tree ) {
		ti = proto_tree_add_item( tree, proto_jpeg, tvb, offset, -1, ENC_NA );
		jpeg_tree = proto_item_add_subtree( ti, ett_jpeg );

		ti = proto_tree_add_item(jpeg_tree, hf_rtp_jpeg_main_hdr, tvb, offset, 8, ENC_NA);
		main_hdr_tree = proto_item_add_subtree(ti, ett_jpeg);

		proto_tree_add_item(main_hdr_tree, hf_rtp_jpeg_main_hdr_ts, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(main_hdr_tree, hf_rtp_jpeg_main_hdr_offs, tvb, offset, 3, ENC_BIG_ENDIAN);
		fragment_offset = tvb_get_ntoh24(tvb, offset);
		offset += 3;
		proto_tree_add_item(main_hdr_tree, hf_rtp_jpeg_main_hdr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		type = tvb_get_uint8(tvb, offset);
		offset += 1;
		proto_tree_add_item(main_hdr_tree, hf_rtp_jpeg_main_hdr_q, tvb, offset, 1, ENC_BIG_ENDIAN);
		q = tvb_get_uint8(tvb, offset);
		offset += 1;
		w = tvb_get_uint8(tvb, offset) * 8;
		proto_tree_add_uint(main_hdr_tree, hf_rtp_jpeg_main_hdr_width, tvb, offset, 1, w);
		offset += 1;
		h = tvb_get_uint8(tvb, offset) * 8;
		proto_tree_add_uint(main_hdr_tree, hf_rtp_jpeg_main_hdr_height, tvb, offset, 1, h);
		offset += 1;

		if (type >= 64 && type <= 127) {
			ti = proto_tree_add_item(jpeg_tree, hf_rtp_jpeg_restart_hdr, tvb, offset, 4, ENC_NA);
			restart_hdr_tree = proto_item_add_subtree(ti, ett_jpeg);
			proto_tree_add_item(restart_hdr_tree, hf_rtp_jpeg_restart_hdr_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(restart_hdr_tree, hf_rtp_jpeg_restart_hdr_f, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(restart_hdr_tree, hf_rtp_jpeg_restart_hdr_l, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(restart_hdr_tree, hf_rtp_jpeg_restart_hdr_count, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}

		if (q >= 128 && fragment_offset == 0) {
			ti = proto_tree_add_item(jpeg_tree, hf_rtp_jpeg_qtable_hdr, tvb, offset, -1, ENC_NA);
			qtable_hdr_tree = proto_item_add_subtree(ti, ett_jpeg);
			proto_tree_add_item(qtable_hdr_tree, hf_rtp_jpeg_qtable_hdr_mbz, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(qtable_hdr_tree, hf_rtp_jpeg_qtable_hdr_prec, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(qtable_hdr_tree, hf_rtp_jpeg_qtable_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
			len = tvb_get_ntohs(tvb, offset);
			offset += 2;
			if (len > 0) {
				proto_tree_add_item(qtable_hdr_tree, hf_rtp_jpeg_qtable_hdr_data, tvb, offset, len, ENC_NA);
				offset += len;
			}
			proto_item_set_len(ti, len + 4);
		}

		/* The rest of the packet is the JPEG data */
		proto_tree_add_item( jpeg_tree, hf_rtp_jpeg_payload, tvb, offset, -1, ENC_NA );
	}
	return tvb_captured_length(tvb);
}

void
proto_register_jpeg(void)
{
	static hf_register_info hf[] = {
		{ &hf_rtp_jpeg_main_hdr,
			{ "Main Header", "jpeg.main_hdr",
			  FT_NONE, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_main_hdr_ts,
			{ "Type Specific", "jpeg.main_hdr.ts",
			  FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(jpeg_ts_rvals), 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_main_hdr_offs,
			{ "Fragment Offset", "jpeg.main_hdr.offset",
			  FT_UINT24, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_main_hdr_type,
			{ "Type", "jpeg.main_hdr.type",
			  FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(jpeg_type_rvals), 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_main_hdr_q,
			{ "Q", "jpeg.main_hdr.q",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_main_hdr_width,
			{ "Width", "jpeg.main_hdr.width",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_main_hdr_height,
			{ "Height", "jpeg.main_hdr.height",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_restart_hdr,
			{ "Restart Marker Header", "jpeg.restart_hdr",
			  FT_NONE, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_restart_hdr_interval,
			{ "Restart Interval", "jpeg.restart_hdr.interval",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_restart_hdr_f,
			{ "F", "jpeg.restart_hdr.f",
			  FT_UINT16, BASE_DEC, NULL, 0x8000,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_restart_hdr_l,
			{ "L", "jpeg.restart_hdr.l",
			  FT_UINT16, BASE_DEC, NULL, 0x4000,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_restart_hdr_count,
			{ "Restart Count", "jpeg.restart_hdr.count",
			  FT_UINT16, BASE_DEC, NULL, 0x3FFF,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_qtable_hdr,
			{ "Quantization Table Header", "jpeg.qtable_hdr",
			  FT_NONE, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_qtable_hdr_mbz,
			{ "MBZ", "jpeg.qtable_hdr.mbz",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_qtable_hdr_prec,
			{ "Precision", "jpeg.qtable_hdr.precision",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_qtable_hdr_length,
			{ "Length", "jpeg.qtable_hdr.length",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_qtable_hdr_data,
			{ "Quantization Table Data", "jpeg.qtable_hdr.data",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_rtp_jpeg_payload,
			{ "Payload", "jpeg.payload",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_jpeg,
	};

	proto_jpeg = proto_register_protocol("RFC 2435 JPEG","JPEG","jpeg");
	proto_register_field_array(proto_jpeg, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	jpeg_handle = register_dissector("jpeg", dissect_jpeg, proto_jpeg);

	/* RFC 2798 */
	register_ber_oid_dissector_handle("0.9.2342.19200300.100.1.60", jpeg_handle, proto_jpeg, "jpegPhoto");
}

void
proto_reg_handoff_jpeg(void)
{
	dissector_add_uint("rtp.pt", PT_JPEG, jpeg_handle);
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
