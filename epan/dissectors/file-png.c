/* file-png.c
 *
 * Routines for PNG (Portable Network Graphics) image file dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/* See http://www.w3.org/TR/PNG for specification
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>


#define MAKE_TYPE_VAL(a, b, c, d)   ((a)<<24 | (b)<<16 | (c)<<8 | (d))

#define CHUNK_TYPE_IHDR   MAKE_TYPE_VAL('I', 'H', 'D', 'R')
#define CHUNK_TYPE_bKGD   MAKE_TYPE_VAL('b', 'K', 'G', 'D')
#define CHUNK_TYPE_gAMA   MAKE_TYPE_VAL('g', 'A', 'M', 'A')
#define CHUNK_TYPE_iCCP   MAKE_TYPE_VAL('i', 'C', 'C', 'P')
#define CHUNK_TYPE_cHRM   MAKE_TYPE_VAL('c', 'H', 'R', 'M')
#define CHUNK_TYPE_pHYs   MAKE_TYPE_VAL('p', 'H', 'Y', 's')
#define CHUNK_TYPE_iTXt   MAKE_TYPE_VAL('i', 'T', 'X', 't')
#define CHUNK_TYPE_tEXt   MAKE_TYPE_VAL('t', 'E', 'X', 't')
#define CHUNK_TYPE_sBIT   MAKE_TYPE_VAL('s', 'B', 'I', 'T')
#define CHUNK_TYPE_sRGB   MAKE_TYPE_VAL('s', 'R', 'G', 'B')
#define CHUNK_TYPE_tIME   MAKE_TYPE_VAL('t', 'I', 'M', 'E')
#define CHUNK_TYPE_IDAT   MAKE_TYPE_VAL('I', 'D', 'A', 'T')
#define CHUNK_TYPE_IEND   MAKE_TYPE_VAL('I', 'E', 'N', 'D')
#define CHUNK_TYPE_tRNS   MAKE_TYPE_VAL('t', 'R', 'N', 'S')
#define CHUNK_TYPE_PLTE   MAKE_TYPE_VAL('P', 'L', 'T', 'E')

static const value_string chunk_types[] = {
    { CHUNK_TYPE_IHDR, "Image Header" },
    { CHUNK_TYPE_bKGD, "Background colour" },
    { CHUNK_TYPE_gAMA, "Image gamma" },
    { CHUNK_TYPE_iCCP, "Embedded ICC profile" },
    { CHUNK_TYPE_cHRM, "Primary chromaticities and white point" },
    { CHUNK_TYPE_pHYs, "Physical pixel dimensions" },
    { CHUNK_TYPE_iTXt, "International textual data" },
    { CHUNK_TYPE_tEXt, "Textual data" },
    { CHUNK_TYPE_sBIT, "Significant bits" },
    { CHUNK_TYPE_sRGB, "Standard RGB colour space" },
    { CHUNK_TYPE_tIME, "Image last-modification time" },
    { CHUNK_TYPE_IDAT, "Image data chunk" },
    { CHUNK_TYPE_IEND, "Image Trailer" },
    { CHUNK_TYPE_tRNS, "Transparency" },
    { CHUNK_TYPE_PLTE, "Palette" },
    { 0, NULL }
};


void proto_register_png(void);
void proto_reg_handoff_png(void);

static header_field_info *hfi_png = NULL;

#define PNG_HFI_INIT HFI_INIT(proto_png)

static header_field_info hfi_png_signature PNG_HFI_INIT = {
    "PNG Signature", "png.signature", FT_BYTES, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chunk_data PNG_HFI_INIT = {
    "Data", "png.chunk.data", FT_NONE, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chunk_type_str PNG_HFI_INIT = {
    "Chunk", "png.chunk.type", FT_STRING, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chunk_len PNG_HFI_INIT = {
    "Len", "png.chunk.len", FT_UINT32, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chunk_crc PNG_HFI_INIT = {
    "CRC", "png.chunk.crc", FT_UINT32, BASE_HEX,
    NULL, 0, NULL, HFILL };

static const true_false_string png_chunk_anc = {
    "This is an ANCILLARY chunk",
    "This is a CRITICAL chunk"
};

static header_field_info hfi_png_chunk_flag_anc PNG_HFI_INIT = {
    "Ancillary", "png.chunk.flag.ancillary", FT_BOOLEAN, 32,
    TFS(&png_chunk_anc), 0x20000000, NULL, HFILL };

static const true_false_string png_chunk_priv = {
    "This is a PRIVATE chunk",
    "This is a PUBLIC chunk"
};

static header_field_info hfi_png_chunk_flag_priv PNG_HFI_INIT = {
    "Private", "png.chunk.flag.private", FT_BOOLEAN, 32,
    TFS(&png_chunk_priv), 0x00200000, NULL, HFILL };

static const true_false_string png_chunk_stc = {
    "This chunk is SAFE TO COPY",
    "This chunk is NOT safe to copy"
};

static header_field_info hfi_png_chunk_flag_stc PNG_HFI_INIT = {
    "Safe To Copy", "png.chunk.flag.stc", FT_BOOLEAN, 32,
    TFS(&png_chunk_stc), 0x00000020, NULL, HFILL };

static header_field_info hfi_png_ihdr_width PNG_HFI_INIT = {
    "Width", "png.ihdr.width", FT_UINT32, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_ihdr_height PNG_HFI_INIT = {
    "Height", "png.ihdr.height", FT_UINT32, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_ihdr_bitdepth PNG_HFI_INIT = {
    "Bit Depth", "png.ihdr.bitdepth", FT_UINT8, BASE_DEC,
    NULL, 0, NULL, HFILL };

static const value_string colour_type_vals[] = {
    { 0,    "Greyscale"},
    { 2,    "Truecolour"},
    { 3,    "Indexed-colour"},
    { 4,    "Greyscale with alpha"},
    { 6,    "Truecolour with alpha"},
    { 0, NULL }
};

static header_field_info hfi_png_ihdr_colour_type PNG_HFI_INIT = {
    "Colour Type", "png.ihdr.colour_type", FT_UINT8, BASE_DEC,
    VALS(colour_type_vals), 0, NULL, HFILL };

static const value_string compression_method_vals[] = {
    { 0,    "Deflate"},
    { 0, NULL }
};

static header_field_info hfi_png_ihdr_compression_method PNG_HFI_INIT = {
    "Compression Method", "png.ihdr.compression_method", FT_UINT8, BASE_DEC,
    VALS(compression_method_vals), 0, NULL, HFILL };

static const value_string filter_method_vals[] = {
    { 0,    "Adaptive"},
    { 0, NULL }
};

static header_field_info hfi_png_ihdr_filter_method PNG_HFI_INIT = {
    "Filter Method", "png.ihdr.filter_method", FT_UINT8, BASE_DEC,
    VALS(filter_method_vals), 0, NULL, HFILL };

static const value_string interlace_method_vals[] = {
    { 0,    "No interlace"},
    { 1,    "Adam7"},
    { 0, NULL }
};

static header_field_info hfi_png_ihdr_interlace_method PNG_HFI_INIT = {
    "Interlace Method", "png.ihdr.interlace_method", FT_UINT8, BASE_DEC,
    VALS(interlace_method_vals), 0, NULL, HFILL };

static const value_string srgb_intent_vals[] = {
    { 0, "Perceptual" },
    { 1, "Relative colorimetric" },
    { 2, "Saturation" },
    { 3, "Absolute colorimetric" },
    { 0, NULL }
};

static header_field_info hfi_png_srgb_intent PNG_HFI_INIT = {
    "Intent", "png.srgb.intent", FT_UINT8, BASE_DEC,
    VALS(srgb_intent_vals), 0, NULL, HFILL };

static header_field_info hfi_png_text_keyword PNG_HFI_INIT = {
    "Keyword", "png.text.keyword", FT_STRING, STR_UNICODE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_text_string PNG_HFI_INIT = {
    "String", "png.text.string", FT_STRING, STR_UNICODE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_time_year PNG_HFI_INIT = {
    "Year", "png.time.year", FT_UINT16, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_time_month PNG_HFI_INIT = {
    "Month", "png.time.month", FT_UINT8, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_time_day PNG_HFI_INIT = {
    "Day", "png.time.day", FT_UINT8, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_time_hour PNG_HFI_INIT = {
    "Hour", "png.time.hour", FT_UINT8, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_time_minute PNG_HFI_INIT = {
    "Minute", "png.time.minute", FT_UINT8, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_time_second PNG_HFI_INIT = {
    "Second", "png.time.second", FT_UINT8, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_phys_horiz PNG_HFI_INIT = {
    "Horizontal pixels per unit", "png.phys.horiz", FT_UINT32, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_phys_vert PNG_HFI_INIT = {
    "Vertical pixels per unit", "png.phys.vert", FT_UINT32, BASE_DEC,
    NULL, 0, NULL, HFILL };

static const value_string phys_unit_vals[] = {
    { 0,    "Unit is unknown"},
    { 1,    "Unit is METRE"},
    { 0, NULL }
};

static header_field_info hfi_png_phys_unit PNG_HFI_INIT = {
    "Unit", "png.phys.unit", FT_UINT8, BASE_DEC,
    VALS(phys_unit_vals), 0, NULL, HFILL };

static header_field_info hfi_png_bkgd_palette_index PNG_HFI_INIT = {
    "Palette Index", "png.bkgd.palette_index", FT_UINT8, BASE_DEC,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_bkgd_greyscale PNG_HFI_INIT = {
    "Greyscale", "png.bkgd.greyscale", FT_UINT16, BASE_HEX,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_bkgd_red PNG_HFI_INIT = {
    "Red", "png.bkgd.red", FT_UINT16, BASE_HEX,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_bkgd_green PNG_HFI_INIT = {
    "Green", "png.bkgd.green", FT_UINT16, BASE_HEX,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_bkgd_blue PNG_HFI_INIT = {
    "Blue", "png.bkgd.blue", FT_UINT16, BASE_HEX,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_white_x PNG_HFI_INIT = {
    "White X", "png.chrm.white.x", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_white_y PNG_HFI_INIT = {
    "White Y", "png.chrm.white.y", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_red_x PNG_HFI_INIT = {
    "Red X", "png.chrm.red.x", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_red_y PNG_HFI_INIT = {
    "Red Y", "png.chrm.red.y", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_green_x PNG_HFI_INIT = {
    "Green X", "png.chrm.green.x", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_green_y PNG_HFI_INIT = {
    "Green Y", "png.chrm.green.y", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_blue_x PNG_HFI_INIT = {
    "Blue X", "png.chrm.blue.x", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_chrm_blue_y PNG_HFI_INIT = {
    "Blue Y", "png.chrm.blue.y", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static header_field_info hfi_png_gama_gamma PNG_HFI_INIT = {
    "Gamma", "png.gama.gamma", FT_FLOAT, BASE_NONE,
    NULL, 0, NULL, HFILL };

static gint ett_png = -1;
static gint ett_png_chunk = -1;

static expert_field ei_png_chunk_too_large = EI_INIT;

static dissector_handle_t png_handle;

static void
dissect_png_ihdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, &hfi_png_ihdr_width, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_ihdr_height, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_ihdr_bitdepth, tvb, 8, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_ihdr_colour_type, tvb, 9, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_ihdr_compression_method, tvb, 10, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_ihdr_filter_method, tvb, 11, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_ihdr_interlace_method, tvb, 12, 1, ENC_BIG_ENDIAN);

}

static void
dissect_png_srgb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, &hfi_png_srgb_intent,
            tvb, 0, 1, ENC_BIG_ENDIAN);
}

static void
dissect_png_text(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset=0, nul_offset;

    nul_offset = tvb_find_guint8(tvb, offset, tvb_captured_length_remaining(tvb, offset), 0);
    /* nul_offset == 0 means empty keyword, this is not allowed by the png standard */
    if (nul_offset<=0) {
        /* XXX exception */
        return;
    }

    proto_tree_add_item(tree, &hfi_png_text_keyword, tvb, offset, nul_offset, ENC_ISO_8859_1|ENC_NA);
    offset = nul_offset+1; /* length of the key word + 0 character */

    proto_tree_add_item(tree, &hfi_png_text_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_ISO_8859_1|ENC_NA);

}

static void
dissect_png_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, &hfi_png_time_year, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_time_month, tvb, 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_time_day, tvb, 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_time_hour, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_time_minute, tvb, 5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_time_second, tvb, 6, 1, ENC_BIG_ENDIAN);
}

static void
dissect_png_phys(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, &hfi_png_phys_horiz, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_phys_vert, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, &hfi_png_phys_unit, tvb, 8, 1, ENC_BIG_ENDIAN);
}

static void
dissect_png_bkgd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    switch(tvb_reported_length(tvb)){
        case 1: /* colour type 3 */
            proto_tree_add_item(tree, &hfi_png_bkgd_palette_index, tvb, 0, 1, ENC_BIG_ENDIAN);
            break;
        case 2: /* colour type 0, 4 */
            proto_tree_add_item(tree, &hfi_png_bkgd_greyscale, tvb, 0, 2, ENC_BIG_ENDIAN);
            break;
        case 6: /* colour type 2, 6 */
            proto_tree_add_item(tree, &hfi_png_bkgd_red, tvb, 0, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, &hfi_png_bkgd_green, tvb, 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, &hfi_png_bkgd_blue, tvb, 4, 2, ENC_BIG_ENDIAN);
            break;
    }
}

static void
dissect_png_chrm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    float  wx, wy, rx, ry, gx, gy, bx, by;
    gint   offset = 0;

    wx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_white_x,
            tvb, offset, 4, wx, "%f", wx);
    offset += 4;

    wy = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_white_y,
            tvb, offset, 4, wy, "%f", wy);
    offset += 4;

    rx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_red_x,
            tvb, offset, 4, rx, "%f", rx);
    offset += 4;

    ry = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_red_y,
            tvb, offset, 4, ry, "%f", ry);
    offset += 4;

    gx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_green_x,
            tvb, offset, 4, gx, "%f", gx);
    offset += 4;

    gy = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_green_y,
            tvb, offset, 4, gy, "%f", gy);
    offset += 4;

    bx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_blue_x,
            tvb, offset, 4, bx, "%f", bx);
    offset += 4;

    by = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_chrm_blue_y,
            tvb, offset, 4, by, "%f", by);
}

static void
dissect_png_gama(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    float  gamma;

    gamma = tvb_get_ntohl(tvb, 0) / 100000.0f;
    proto_tree_add_float_format_value(tree, &hfi_png_gama_gamma,
            tvb, 0, 4, gamma, "%f", gamma);
}

static gint
dissect_png(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    proto_tree *tree;
    proto_item *ti;
    gint        offset=0;
    /* http://libpng.org/pub/png/spec/1.2/PNG-Structure.html#PNG-file-signature */
    static const guint8 magic[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };

    if (tvb_captured_length(tvb) < 20)
        return 0;
    if (tvb_memeql(tvb, 0, magic, sizeof(magic)) != 0)
        return 0;

    col_append_str(pinfo->cinfo, COL_INFO, " (PNG)");

    ti=proto_tree_add_item(parent_tree, hfi_png, tvb, offset, -1, ENC_NA);
    tree=proto_item_add_subtree(ti, ett_png);

    proto_tree_add_item(tree, &hfi_png_signature, tvb, offset, 8, ENC_NA);
    offset+=8;

    while(tvb_reported_length_remaining(tvb, offset) > 0){
        guint32     len_field;
        proto_item *len_it;
        proto_tree *chunk_tree;
        guint32     type;
        guint8     *type_str;
        tvbuff_t   *chunk_tvb;

        len_field = tvb_get_ntohl(tvb, offset);

        type = tvb_get_ntohl(tvb, offset+4);
        type_str = tvb_get_string_enc(wmem_packet_scope(),
                tvb, offset+4, 4, ENC_ASCII|ENC_NA);

        /* 4 byte len field, 4 byte chunk type, 4 byte CRC */
        chunk_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4+4+len_field+4, ett_png_chunk, NULL,
                "%s (%s)", val_to_str_const(type, chunk_types, "unknown"), type_str);

        len_it = proto_tree_add_item(chunk_tree, &hfi_png_chunk_len,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        if (len_field > G_MAXINT) {
            expert_add_info(pinfo, len_it, &ei_png_chunk_too_large);
            return offset;
        }

        proto_tree_add_item(chunk_tree, &hfi_png_chunk_type_str,
                tvb, offset, 4, ENC_ASCII|ENC_NA);

        proto_tree_add_item(chunk_tree, &hfi_png_chunk_flag_anc, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(chunk_tree, &hfi_png_chunk_flag_priv, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(chunk_tree, &hfi_png_chunk_flag_stc, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        chunk_tvb=tvb_new_subset_length(tvb, offset, len_field);
        switch (type) {
            case CHUNK_TYPE_IHDR:
                dissect_png_ihdr(chunk_tvb, pinfo, chunk_tree);
                break;
            case CHUNK_TYPE_bKGD:
                dissect_png_bkgd(chunk_tvb, pinfo, chunk_tree);
                break;
            case CHUNK_TYPE_cHRM:
                dissect_png_chrm(chunk_tvb, pinfo, chunk_tree);
                break;
            case CHUNK_TYPE_gAMA:
                dissect_png_gama(chunk_tvb, pinfo, chunk_tree);
                break;
            case CHUNK_TYPE_pHYs:
                dissect_png_phys(chunk_tvb, pinfo, chunk_tree);
                break;
            case CHUNK_TYPE_sRGB:
                dissect_png_srgb(chunk_tvb, pinfo, chunk_tree);
                break;
            case CHUNK_TYPE_tEXt:
                dissect_png_text(chunk_tvb, pinfo, chunk_tree);
                break;
            case CHUNK_TYPE_tIME:
                dissect_png_time(chunk_tvb, pinfo, chunk_tree);
                break;
            default:
                if (len_field>0) {
                    proto_tree_add_item(chunk_tree, &hfi_png_chunk_data,
                            tvb, offset, len_field, ENC_NA);
                }
                break;
        }
        offset += len_field;

        proto_tree_add_item(chunk_tree, &hfi_png_chunk_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
    }
    return offset;
}

void
proto_register_png(void)
{
#ifndef HAVE_HFI_SECTION_INIT
    static header_field_info *hfi[] =
    {
        &hfi_png_signature,
        &hfi_png_chunk_type_str,
        &hfi_png_chunk_data,
        &hfi_png_chunk_len,
        &hfi_png_chunk_crc,
        &hfi_png_chunk_flag_anc,
        &hfi_png_chunk_flag_priv,
        &hfi_png_chunk_flag_stc,
        &hfi_png_ihdr_width,
        &hfi_png_ihdr_height,
        &hfi_png_ihdr_bitdepth,
        &hfi_png_ihdr_colour_type,
        &hfi_png_ihdr_compression_method,
        &hfi_png_ihdr_filter_method,
        &hfi_png_ihdr_interlace_method,
        &hfi_png_srgb_intent,
        &hfi_png_text_keyword,
        &hfi_png_text_string,
        &hfi_png_time_year,
        &hfi_png_time_month,
        &hfi_png_time_day,
        &hfi_png_time_hour,
        &hfi_png_time_minute,
        &hfi_png_time_second,
        &hfi_png_phys_horiz,
        &hfi_png_phys_vert,
        &hfi_png_phys_unit,
        &hfi_png_bkgd_palette_index,
        &hfi_png_bkgd_greyscale,
        &hfi_png_bkgd_red,
        &hfi_png_bkgd_green,
        &hfi_png_bkgd_blue,
        &hfi_png_chrm_white_x,
        &hfi_png_chrm_white_y,
        &hfi_png_chrm_red_x,
        &hfi_png_chrm_red_y,
        &hfi_png_chrm_green_x,
        &hfi_png_chrm_green_y,
        &hfi_png_chrm_blue_x,
        &hfi_png_chrm_blue_y,
        &hfi_png_gama_gamma
    };
#endif

    static gint *ett[] =
    {
        &ett_png,
        &ett_png_chunk,
    };

    static ei_register_info ei[] = {
        { &ei_png_chunk_too_large,
            { "png.chunk_too_large", PI_PROTOCOL, PI_WARN,
                "chunk size too large, dissection of this chunk is not supported", EXPFILL }}
    };
    expert_module_t *expert_png;

    int proto_png;

    proto_png = proto_register_protocol("Portable Network Graphics","PNG","png");
    hfi_png = proto_registrar_get_nth(proto_png);

    proto_register_fields(proto_png, hfi, array_length(hfi));
    proto_register_subtree_array(ett, array_length(ett));

    expert_png = expert_register_protocol(proto_png);
    expert_register_field_array(expert_png, ei, array_length(ei));

    png_handle = register_dissector("png", dissect_png, proto_png);
}

static gboolean dissect_png_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_png(tvb, pinfo, tree, NULL) > 0;
}

void
proto_reg_handoff_png(void)
{
    dissector_add_string("media_type", "image/png", png_handle);
    heur_dissector_add("http", dissect_png_heur, "PNG file in HTTP", "png_http", hfi_png->id, HEURISTIC_ENABLE);
    heur_dissector_add("wtap_file", dissect_png_heur, "PNG file in HTTP", "png_wtap", hfi_png->id, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
