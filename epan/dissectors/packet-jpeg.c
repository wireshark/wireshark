/* packet-jpeg.c
 *
 * Routines for RFC 2435 JPEG dissection
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/rtp_pt.h>


/* JPEG header fields             */
static int hf_rtp_jpeg_main_hdr = -1;
static int hf_rtp_jpeg_main_hdr_ts = -1;
static int hf_rtp_jpeg_main_hdr_offs = -1;
static int hf_rtp_jpeg_main_hdr_type = -1;
static int hf_rtp_jpeg_main_hdr_q = -1;
static int hf_rtp_jpeg_main_hdr_width = -1;
static int hf_rtp_jpeg_main_hdr_height = -1;

static int hf_rtp_jpeg_restart_hdr = -1;
static int hf_rtp_jpeg_restart_hdr_interval = -1;
static int hf_rtp_jpeg_restart_hdr_f = -1;
static int hf_rtp_jpeg_restart_hdr_l = -1;
static int hf_rtp_jpeg_restart_hdr_count = -1;

static int hf_rtp_jpeg_qtable_hdr = -1;
static int hf_rtp_jpeg_qtable_hdr_mbz = -1;
static int hf_rtp_jpeg_qtable_hdr_prec = -1;
static int hf_rtp_jpeg_qtable_hdr_length = -1;
static int hf_rtp_jpeg_qtable_hdr_data = -1;

static int hf_rtp_jpeg_payload = -1;

static int proto_jpeg = -1;

/* JPEG fields defining a sub tree */
static gint ett_jpeg = -1;

static void
dissect_jpeg( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti = NULL;
	proto_tree *jpeg_tree = NULL;
	proto_tree *main_hdr_tree = NULL;
	proto_tree *restart_hdr_tree = NULL;
	proto_tree *qtable_hdr_tree = NULL;
	guint32 fragment_offset = 0;
	guint16 len = 0;
	guint8 type = 0;
	guint8 q = 0;
	gint h = 0;
	gint w = 0;

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
		type = tvb_get_guint8(tvb, offset);
		offset += 1;
		proto_tree_add_item(main_hdr_tree, hf_rtp_jpeg_main_hdr_q, tvb, offset, 1, ENC_BIG_ENDIAN);
		q = tvb_get_guint8(tvb, offset);
		offset += 1;
		w = tvb_get_guint8(tvb, offset) * 8;
		proto_tree_add_uint(main_hdr_tree, hf_rtp_jpeg_main_hdr_width, tvb, offset, 1, w);
		offset += 1;
		h = tvb_get_guint8(tvb, offset) * 8;
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
}

void
proto_register_jpeg(void)
{

	static hf_register_info hf[] =
	{
		{ &hf_rtp_jpeg_main_hdr, {
			"Main Header",
			"jpeg.main_hdr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_main_hdr_ts, {
			"Type Specific",
			"jpeg.main_hdr.ts",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_main_hdr_offs, {
			"Fragment Offset",
			"jpeg.main_hdr.offset",
			FT_UINT24, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_main_hdr_type, {
			"Type",
			"jpeg.main_hdr.type",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_main_hdr_q, {
			"Q",
			"jpeg.main_hdr.q",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_main_hdr_width, {
			"Width",
			"jpeg.main_hdr.width",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_main_hdr_height, {
			"Height",
			"jpeg.main_hdr.height",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_restart_hdr, {
			"Restart Marker Header",
			"jpeg.restart_hdr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_restart_hdr_interval, {
			"Restart Interval",
			"jpeg.restart_hdr.interval",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_restart_hdr_f, {
			"F",
			"jpeg.restart_hdr.f",
			FT_UINT16, BASE_DEC, NULL, 0x8000,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_restart_hdr_l, {
			"L",
			"jpeg.restart_hdr.l",
			FT_UINT16, BASE_DEC, NULL, 0x4000,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_restart_hdr_count, {
			"Restart Count",
			"jpeg.restart_hdr.count",
			FT_UINT16, BASE_DEC, NULL, 0x3FFF,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_qtable_hdr, {
			"Quantization Table Header",
			"jpeg.qtable_hdr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_qtable_hdr_mbz, {
			"MBZ",
			"jpeg.qtable_hdr.mbz",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_qtable_hdr_prec, {
			"Precision",
			"jpeg.qtable_hdr.precision",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_qtable_hdr_length, {
			"Length",
			"jpeg.qtable_hdr.length",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_qtable_hdr_data, {
			"Quantization Table Data",
			"jpeg.qtable_hdr.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		}},
		{ &hf_rtp_jpeg_payload, {
			"Payload",
			"jpeg.payload",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		}},
	};

	static gint *ett[] =
	{
		&ett_jpeg,
	};


	proto_jpeg = proto_register_protocol("RFC 2435 JPEG","JPEG","jpeg");
	proto_register_field_array(proto_jpeg, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_jpeg(void)
{
	dissector_handle_t jpeg_handle;

	jpeg_handle = create_dissector_handle(dissect_jpeg, proto_jpeg);
	dissector_add_uint("rtp.pt", PT_JPEG, jpeg_handle);
}
