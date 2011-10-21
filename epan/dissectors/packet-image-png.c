/* packet-image-png.c
 *
 * Routines for PNG (Portable Network Graphics) image file dissection
 *
 * $Id$
 *
 * Copyright 2006 Ronnie Sahlberg
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
/* See http://www.w3.org/TR/PNG for specification
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>


static int proto_png = -1;
static int hf_png_signature = -1;
static int hf_png_chunk_data = -1;
static int hf_png_chunk_type = -1;
static int hf_png_chunk_len = -1;
static int hf_png_chunk_crc = -1;
static int hf_png_chunk_flag_anc = -1;
static int hf_png_chunk_flag_priv = -1;
static int hf_png_chunk_flag_stc = -1;
static int hf_png_ihdr_width = -1;
static int hf_png_ihdr_height = -1;
static int hf_png_ihdr_bitdepth = -1;
static int hf_png_ihdr_colour_type = -1;
static int hf_png_ihdr_compression_method = -1;
static int hf_png_ihdr_filter_method = -1;
static int hf_png_ihdr_interlace_method = -1;
static int hf_png_text_keyword = -1;
static int hf_png_text_string = -1;
static int hf_png_time_year = -1;
static int hf_png_time_month = -1;
static int hf_png_time_day = -1;
static int hf_png_time_hour = -1;
static int hf_png_time_minute = -1;
static int hf_png_time_second = -1;
static int hf_png_phys_horiz = -1;
static int hf_png_phys_vert = -1;
static int hf_png_phys_unit = -1;
static int hf_png_bkgd_palette_index = -1;
static int hf_png_bkgd_greyscale = -1;
static int hf_png_bkgd_red = -1;
static int hf_png_bkgd_green = -1;
static int hf_png_bkgd_blue = -1;

static gint ett_png = -1;
static gint ett_png_chunk = -1;
static gint ett_png_chunk_item = -1;


static const value_string colour_type_vals[] = {
	{ 0,	"Greyscale"},
	{ 2,	"Truecolour"},
	{ 3,	"Indexed-colour"},
	{ 4,	"Greyscale with alpha"},
	{ 6,	"Truecolour with alpha"},
	{ 0, NULL }
};
static const value_string compression_method_vals[] = {
	{ 0,	"Deflate"},
	{ 0, NULL }
};
static const value_string filter_method_vals[] = {
	{ 0,	"Adaptive"},
	{ 0, NULL }
};
static const value_string interlace_method_vals[] = {
	{ 0,	"No interlace"},
	{ 1,	"Adam7"},
	{ 0, NULL }
};

static void
dissect_png_ihdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset=0;

	proto_tree_add_item(tree, hf_png_ihdr_width, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;

	proto_tree_add_item(tree, hf_png_ihdr_height, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;

	proto_tree_add_item(tree, hf_png_ihdr_bitdepth, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	proto_tree_add_item(tree, hf_png_ihdr_colour_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	proto_tree_add_item(tree, hf_png_ihdr_compression_method, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	proto_tree_add_item(tree, hf_png_ihdr_filter_method, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	proto_tree_add_item(tree, hf_png_ihdr_interlace_method, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	return;
}

static void
dissect_png_text(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset=1;

	/* find the null that separates keyword and text string */
	while(1){
		if(!tvb_get_guint8(tvb, offset)){
			break;
		}
		offset++;
	}

	proto_tree_add_item(tree, hf_png_text_keyword, tvb, 0, offset, ENC_ASCII|ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_png_text_string, tvb, offset, tvb_length_remaining(tvb, offset), ENC_ASCII|ENC_NA);

}

static void
dissect_png_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_png_time_year, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_png_time_month, tvb, 2, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_png_time_day, tvb, 3, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_png_time_hour, tvb, 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_png_time_minute, tvb, 5, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_png_time_second, tvb, 6, 1, ENC_BIG_ENDIAN);
}

static const value_string phys_unit_vals[] = {
	{ 0,	"Unit is unknown"},
	{ 1,	"Unit is METRE"},
	{ 0, NULL }
};
static void
dissect_png_phys(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_png_phys_horiz, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_png_phys_vert, tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_png_phys_unit, tvb, 8, 1, ENC_BIG_ENDIAN);
}

static void
dissect_png_bkgd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	switch(tvb_reported_length(tvb)){
	case 1: /* colour type 3 */
		proto_tree_add_item(tree, hf_png_bkgd_palette_index, tvb, 0, 1, ENC_BIG_ENDIAN);
		break;
	case 2: /* colour type 0, 4 */
		proto_tree_add_item(tree, hf_png_bkgd_greyscale, tvb, 0, 2, ENC_BIG_ENDIAN);
		break;
	case 6: /* colour type 2, 6 */
		proto_tree_add_item(tree, hf_png_bkgd_red, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_png_bkgd_green, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_png_bkgd_blue, tvb, 4, 2, ENC_BIG_ENDIAN);
		break;
	}
}

typedef struct _chunk_dissector_t {
	guint32 type;
	const char *name;
	void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
} chunk_dissector_t;

static chunk_dissector_t chunk_table[] = {
	{ 0x49484452, "Image Header", dissect_png_ihdr }, 	/* IHDR */
	{ 0x624b4744, "Background colour", dissect_png_bkgd }, 	/* bKGD */
	{ 0x70485973, "Physical pixel dimensions",
					dissect_png_phys }, 	/* pHYs */
	{ 0x74455874, "Textual data", dissect_png_text }, 	/* tEXt */
	{ 0x74494d45, "Image last-modification time",
					dissect_png_time }, 	/* tIME */
	{ 0x49454e44, "Image Trailer", NULL }, 			/* IEND */
	{ 0, NULL, NULL }
};

static const true_false_string png_chunk_anc = {
	"This is an ANCILLARY chunk",
	"This is a CRITICAL chunk"
};
static const true_false_string png_chunk_priv = {
	"This is a PRIVATE chunk",
	"This is a PUBLIC chunk"
};
static const true_false_string png_chunk_stc = {
	"This chunk is SAFE TO COPY",
	"This chunk is NOT safe to copy"
};


static gint
dissect_png(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree *tree = NULL;
	proto_item *ti;
	int offset=0;

	/* http://libpng.org/pub/png/spec/1.2/PNG-Structure.html#PNG-file-signature */
	static const guint8 magic[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };
	if (tvb_length(tvb) < 20)
		return 0;

	if (tvb_memeql(tvb, 0, magic, sizeof(magic)) != 0)
		return 0;

	col_append_str(pinfo->cinfo, COL_INFO, " (PNG)");

	if(parent_tree){
		ti=proto_tree_add_item(parent_tree, proto_png, tvb, offset, -1, ENC_NA);
		tree=proto_item_add_subtree(ti, ett_png);
	}

	proto_tree_add_item(tree, hf_png_signature, tvb, offset, 8, ENC_NA);
	offset+=8;

	while(tvb_reported_length_remaining(tvb, offset)){
		proto_tree *chunk_tree=NULL;
		proto_item *it=NULL;
		guint32 len, type;
		chunk_dissector_t *cd;
		char str[5];

		len=tvb_get_ntohl(tvb, offset);
		type=tvb_get_ntohl(tvb, offset+4);
		str[0]=tvb_get_guint8(tvb, offset+4);
		str[1]=tvb_get_guint8(tvb, offset+5);
		str[2]=tvb_get_guint8(tvb, offset+6);
		str[3]=tvb_get_guint8(tvb, offset+7);
		str[4]=0;

		if(tree){
			it=proto_tree_add_text(tree, tvb, offset, offset+8+len+4, "%s", str);
			chunk_tree=proto_item_add_subtree(it, ett_png_chunk);
		}

		proto_tree_add_item(chunk_tree, hf_png_chunk_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;


		it=proto_tree_add_item(chunk_tree, hf_png_chunk_type, tvb, offset, 4, ENC_ASCII|ENC_NA);
		proto_tree_add_item(chunk_tree, hf_png_chunk_flag_anc, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(chunk_tree, hf_png_chunk_flag_priv, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(chunk_tree, hf_png_chunk_flag_stc, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		if (len >= 1000000000)
			THROW(ReportedBoundsError);
		cd=&chunk_table[0];
		while(1){
			if(cd->type==0){
				cd=NULL;
				break;
			}
			if(cd->type==type){
				break;
			}
			cd++;
		}
		if(chunk_tree){
			proto_item_append_text(chunk_tree, " %s", cd?cd->name:"(don't know how to dissect this)");
		}

		if(!cd){
			proto_tree_add_item(chunk_tree, hf_png_chunk_data, tvb, offset, len, ENC_NA);
		} else {
			if(cd->dissector){
				tvbuff_t *next_tvb;
				proto_tree *cti=NULL;

				next_tvb=tvb_new_subset(tvb, offset, MIN(tvb_length_remaining(tvb, offset), (int)len), len);
				if(it){
					cti=proto_item_add_subtree(it, ett_png_chunk_item);
				}
				cd->dissector(next_tvb, pinfo, cti);
			}
		}
		offset+=len;

		proto_tree_add_item(chunk_tree, hf_png_chunk_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
	}
	return offset;
}

void
proto_register_png(void)
{
	static hf_register_info hf[] =
	{
	{ &hf_png_signature, {
	  "PNG Signature", "png.signature", FT_BYTES, BASE_NONE,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_chunk_type, {
	  "Chunk", "png.chunk.type", FT_STRING, BASE_NONE,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_chunk_data, {
	  "Data", "png.chunk.data", FT_NONE, BASE_NONE,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_chunk_len, {
	  "Len", "png.chunk.len", FT_UINT32, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_chunk_crc, {
	  "CRC", "png.chunk.crc", FT_UINT32, BASE_HEX,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_chunk_flag_anc, {
	  "Ancillary", "png.chunk.flag.ancillary", FT_BOOLEAN, 32,
	  TFS(&png_chunk_anc), 0x20000000, NULL, HFILL }},
	{ &hf_png_chunk_flag_priv, {
	  "Private", "png.chunk.flag.private", FT_BOOLEAN, 32,
	  TFS(&png_chunk_priv), 0x00200000, NULL, HFILL }},
	{ &hf_png_chunk_flag_stc, {
	  "Safe To Copy", "png.chunk.flag.stc", FT_BOOLEAN, 32,
	  TFS(&png_chunk_stc), 0x00000020, NULL, HFILL }},
	{ &hf_png_ihdr_width, {
	  "Width", "png.ihdr.width", FT_UINT32, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_ihdr_height, {
	  "Height", "png.ihdr.height", FT_UINT32, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_ihdr_bitdepth, {
	  "Bit Depth", "png.ihdr.bitdepth", FT_UINT8, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_ihdr_colour_type, {
	  "Colour Type", "png.ihdr.colour_type", FT_UINT8, BASE_DEC,
	  VALS(colour_type_vals), 0, NULL, HFILL }},
	{ &hf_png_ihdr_compression_method, {
	  "Compression Method", "png.ihdr.compression_method", FT_UINT8, BASE_DEC,
	  VALS(compression_method_vals), 0, NULL, HFILL }},
	{ &hf_png_ihdr_filter_method, {
	  "Filter Method", "png.ihdr.filter_method", FT_UINT8, BASE_DEC,
	  VALS(filter_method_vals), 0, NULL, HFILL }},
	{ &hf_png_ihdr_interlace_method, {
	  "Interlace Method", "png.ihdr.interlace_method", FT_UINT8, BASE_DEC,
	  VALS(interlace_method_vals), 0, NULL, HFILL }},
	{ &hf_png_text_keyword, {
	  "Keyword", "png.text.keyword", FT_STRING, BASE_NONE,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_text_string, {
	  "String", "png.text.string", FT_STRING, BASE_NONE,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_time_year, {
	  "Year", "png.time.year", FT_UINT16, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_time_month, {
	  "Month", "png.time.month", FT_UINT8, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_time_day, {
	  "Day", "png.time.day", FT_UINT8, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_time_hour, {
	  "Hour", "png.time.hour", FT_UINT8, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_time_minute, {
	  "Minute", "png.time.minute", FT_UINT8, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_time_second, {
	  "Second", "png.time.second", FT_UINT8, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_phys_horiz, {
	  "Horizontal pixels per unit", "png.phys.horiz", FT_UINT32, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_phys_vert, {
	  "Vertical pixels per unit", "png.phys.vert", FT_UINT32, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_phys_unit, {
	  "Unit", "png.phys.unit", FT_UINT8, BASE_DEC,
	  VALS(phys_unit_vals), 0, NULL, HFILL }},
	{ &hf_png_bkgd_palette_index, {
	  "Palette Index", "png.bkgd.palette_index", FT_UINT8, BASE_DEC,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_bkgd_greyscale, {
	  "Greyscale", "png.bkgd.greyscale", FT_UINT16, BASE_HEX,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_bkgd_red, {
	  "Red", "png.bkgd.red", FT_UINT16, BASE_HEX,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_bkgd_green, {
	  "Green", "png.bkgd.green", FT_UINT16, BASE_HEX,
	  NULL, 0, NULL, HFILL }},
	{ &hf_png_bkgd_blue, {
	  "Blue", "png.bkgd.blue", FT_UINT16, BASE_HEX,
	  NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] =
	{
		&ett_png,
		&ett_png_chunk,
		&ett_png_chunk_item,
	};


	proto_png = proto_register_protocol("Portable Network Graphics","PNG","png");
	proto_register_field_array(proto_png, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	new_register_dissector("png", dissect_png, proto_png);
}

static gboolean dissect_png_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_png(tvb, pinfo, tree) > 0;
}

void
proto_reg_handoff_png(void)
{
	dissector_handle_t png_handle = new_create_dissector_handle(dissect_png, proto_png);
	dissector_add_string("media_type", "image/png", png_handle);
	heur_dissector_add("http", dissect_png_heur, proto_png);
}
