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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* See http://www.w3.org/TR/PNG for specification
 */
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

static const value_string colour_type_vals[] = {
    { 0,    "Greyscale"},
    { 2,    "Truecolour"},
    { 3,    "Indexed-colour"},
    { 4,    "Greyscale with alpha"},
    { 6,    "Truecolour with alpha"},
    { 0, NULL }
};

static const value_string compression_method_vals[] = {
    { 0,    "Deflate"},
    { 0, NULL }
};

static const value_string filter_method_vals[] = {
    { 0,    "Adaptive"},
    { 0, NULL }
};

static const value_string interlace_method_vals[] = {
    { 0,    "No interlace"},
    { 1,    "Adam7"},
    { 0, NULL }
};

static const value_string srgb_intent_vals[] = {
    { 0, "Perceptual" },
    { 1, "Relative colorimetric" },
    { 2, "Saturation" },
    { 3, "Absolute colorimetric" },
    { 0, NULL }
};

static const value_string phys_unit_vals[] = {
    { 0,    "Unit is unknown"},
    { 1,    "Unit is METRE"},
    { 0, NULL }
};

static int proto_png;

static int hf_png_bkgd_blue;
static int hf_png_bkgd_green;
static int hf_png_bkgd_greyscale;
static int hf_png_bkgd_palette_index;
static int hf_png_bkgd_red;
static int hf_png_chrm_blue_x;
static int hf_png_chrm_blue_y;
static int hf_png_chrm_green_x;
static int hf_png_chrm_green_y;
static int hf_png_chrm_red_x;
static int hf_png_chrm_red_y;
static int hf_png_chrm_white_x;
static int hf_png_chrm_white_y;
static int hf_png_chunk_crc;
static int hf_png_chunk_data;
static int hf_png_chunk_flag_anc;
static int hf_png_chunk_flag_priv;
static int hf_png_chunk_flag_stc;
static int hf_png_chunk_len;
static int hf_png_chunk_type_str;
static int hf_png_gama_gamma;
static int hf_png_ihdr_bitdepth;
static int hf_png_ihdr_colour_type;
static int hf_png_ihdr_compression_method;
static int hf_png_ihdr_filter_method;
static int hf_png_ihdr_height;
static int hf_png_ihdr_interlace_method;
static int hf_png_ihdr_width;
static int hf_png_phys_horiz;
static int hf_png_phys_unit;
static int hf_png_phys_vert;
static int hf_png_signature;
static int hf_png_srgb_intent;
static int hf_png_text_keyword;
static int hf_png_text_string;
static int hf_png_time_day;
static int hf_png_time_hour;
static int hf_png_time_minute;
static int hf_png_time_month;
static int hf_png_time_second;
static int hf_png_time_year;

static int ett_png;
static int ett_png_chunk;

static expert_field ei_png_chunk_too_large;

static dissector_handle_t png_handle;

static void
dissect_png_ihdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_png_ihdr_width, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_png_ihdr_height, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_png_ihdr_bitdepth, tvb, 8, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_png_ihdr_colour_type, tvb, 9, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_png_ihdr_compression_method, tvb, 10, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_png_ihdr_filter_method, tvb, 11, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_png_ihdr_interlace_method, tvb, 12, 1, ENC_BIG_ENDIAN);

}

static void
dissect_png_srgb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_png_srgb_intent,
            tvb, 0, 1, ENC_BIG_ENDIAN);
}

static void
dissect_png_text(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    int offset=0, nul_offset;

    nul_offset = tvb_find_guint8(tvb, offset, tvb_captured_length_remaining(tvb, offset), 0);
    /* nul_offset == 0 means empty keyword, this is not allowed by the png standard */
    if (nul_offset<=0) {
        /* XXX exception */
        return;
    }

    proto_tree_add_item(tree, hf_png_text_keyword, tvb, offset, nul_offset, ENC_ISO_8859_1|ENC_NA);
    offset = nul_offset+1; /* length of the key word + 0 character */

    proto_tree_add_item(tree, hf_png_text_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_ISO_8859_1|ENC_NA);

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

static void
dissect_png_chrm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    float  wx, wy, rx, ry, gx, gy, bx, by;
    int    offset = 0;

    wx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_white_x,
            tvb, offset, 4, wx);
    offset += 4;

    wy = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_white_y,
            tvb, offset, 4, wy);
    offset += 4;

    rx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_red_x,
            tvb, offset, 4, rx);
    offset += 4;

    ry = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_red_y,
            tvb, offset, 4, ry);
    offset += 4;

    gx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_green_x,
            tvb, offset, 4, gx);
    offset += 4;

    gy = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_green_y,
            tvb, offset, 4, gy);
    offset += 4;

    bx = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_blue_x,
            tvb, offset, 4, bx);
    offset += 4;

    by = tvb_get_ntohl(tvb, offset) / 100000.0f;
    proto_tree_add_float(tree, hf_png_chrm_blue_y,
            tvb, offset, 4, by);
}

static void
dissect_png_gama(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    float  gamma;

    gamma = tvb_get_ntohl(tvb, 0) / 100000.0f;
    proto_tree_add_float(tree, hf_png_gama_gamma,
            tvb, 0, 4, gamma);
}

static int
dissect_png(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    proto_tree *tree;
    proto_item *ti;
    int         offset=0;
    /* http://libpng.org/pub/png/spec/1.2/PNG-Structure.html#PNG-file-signature */
    static const uint8_t magic[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };

    if (tvb_captured_length(tvb) < 20)
        return 0;
    if (tvb_memeql(tvb, 0, magic, sizeof(magic)) != 0)
        return 0;

    col_append_str(pinfo->cinfo, COL_INFO, " (PNG)");

    ti=proto_tree_add_item(parent_tree, proto_png, tvb, offset, -1, ENC_NA);
    tree=proto_item_add_subtree(ti, ett_png);

    proto_tree_add_item(tree, hf_png_signature, tvb, offset, 8, ENC_NA);
    offset+=8;

    while(tvb_reported_length_remaining(tvb, offset) > 0){
        uint32_t    len_field;
        proto_item *len_it;
        proto_tree *chunk_tree;
        uint32_t    type;
        uint8_t    *type_str;
        tvbuff_t   *chunk_tvb;

        len_field = tvb_get_ntohl(tvb, offset);

        type = tvb_get_ntohl(tvb, offset+4);
        type_str = tvb_get_string_enc(pinfo->pool,
                tvb, offset+4, 4, ENC_ASCII|ENC_NA);

        /* 4 byte len field, 4 byte chunk type, 4 byte CRC */
        chunk_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4+4+len_field+4, ett_png_chunk, NULL,
                "%s (%s)", val_to_str_const(type, chunk_types, "unknown"), type_str);

        len_it = proto_tree_add_item(chunk_tree, hf_png_chunk_len,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        if (len_field > INT_MAX) {
            expert_add_info(pinfo, len_it, &ei_png_chunk_too_large);
            return offset;
        }

        proto_tree_add_item(chunk_tree, hf_png_chunk_type_str,
                tvb, offset, 4, ENC_ASCII);

        proto_tree_add_item(chunk_tree, hf_png_chunk_flag_anc, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(chunk_tree, hf_png_chunk_flag_priv, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(chunk_tree, hf_png_chunk_flag_stc, tvb, offset, 4, ENC_BIG_ENDIAN);
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
                    proto_tree_add_item(chunk_tree, hf_png_chunk_data,
                            tvb, offset, len_field, ENC_NA);
                }
                break;
        }
        offset += len_field;

        proto_tree_add_item(chunk_tree, hf_png_chunk_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
    }
    return offset;
}

void
proto_register_png(void)
{
    static hf_register_info hf[] = {
        { &hf_png_signature,
            { "PNG Signature", "png.signature",
              FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chunk_data,
            { "Data", "png.chunk.data",
              FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chunk_type_str,
            { "Type", "png.chunk.type",
              FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chunk_len,
            { "Len", "png.chunk.len",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chunk_crc,
            { "CRC", "png.chunk.crc",
              FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chunk_flag_anc,
            { "Ancillary", "png.chunk.flag.ancillary",
              FT_BOOLEAN, 32, TFS(&png_chunk_anc), 0x20000000,
              NULL, HFILL }
        },
        { &hf_png_chunk_flag_priv,
            { "Private", "png.chunk.flag.private",
              FT_BOOLEAN, 32, TFS(&png_chunk_priv), 0x00200000,
              NULL, HFILL }
        },
        { &hf_png_chunk_flag_stc,
            { "Safe To Copy", "png.chunk.flag.stc",
              FT_BOOLEAN, 32, TFS(&png_chunk_stc), 0x00000020,
              NULL, HFILL }
        },
        { &hf_png_ihdr_width,
            { "Width", "png.ihdr.width",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_ihdr_height,
            { "Height", "png.ihdr.height",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_ihdr_bitdepth,
            { "Bit Depth", "png.ihdr.bitdepth",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_ihdr_colour_type,
            { "Colour Type", "png.ihdr.colour_type",
              FT_UINT8, BASE_DEC, VALS(colour_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_png_ihdr_compression_method,
            { "Compression Method", "png.ihdr.compression_method",
              FT_UINT8, BASE_DEC, VALS(compression_method_vals), 0,
              NULL, HFILL }
        },
        { &hf_png_ihdr_filter_method,
            { "Filter Method", "png.ihdr.filter_method",
              FT_UINT8, BASE_DEC, VALS(filter_method_vals), 0,
              NULL, HFILL }
        },
        { &hf_png_ihdr_interlace_method,
            { "Interlace Method", "png.ihdr.interlace_method",
              FT_UINT8, BASE_DEC, VALS(interlace_method_vals), 0,
              NULL, HFILL }
        },
        { &hf_png_srgb_intent,
            { "Intent", "png.srgb.intent",
              FT_UINT8, BASE_DEC, VALS(srgb_intent_vals), 0,
              NULL, HFILL }
        },
        { &hf_png_text_keyword,
            { "Keyword", "png.text.keyword",
              FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_text_string,
            { "String", "png.text.string",
              FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_time_year,
            { "Year", "png.time.year",
              FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_time_month,
            { "Month", "png.time.month",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_time_day,
            { "Day", "png.time.day",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_time_hour,
            { "Hour", "png.time.hour",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_time_minute,
            { "Minute", "png.time.minute",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_time_second,
            { "Second", "png.time.second",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_phys_horiz,
            { "Horizontal pixels per unit", "png.phys.horiz",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_phys_vert,
            { "Vertical pixels per unit", "png.phys.vert",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_phys_unit,
            { "Unit", "png.phys.unit",
              FT_UINT8, BASE_DEC, VALS(phys_unit_vals), 0,
              NULL, HFILL }
        },
        { &hf_png_bkgd_palette_index,
            { "Palette Index", "png.bkgd.palette_index",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_bkgd_greyscale,
            { "Greyscale", "png.bkgd.greyscale",
              FT_UINT16, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_bkgd_red,
            { "Red", "png.bkgd.red",
              FT_UINT16, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_bkgd_green,
            { "Green", "png.bkgd.green",
              FT_UINT16, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_bkgd_blue,
            { "Blue", "png.bkgd.blue",
              FT_UINT16, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_white_x,
            { "White X", "png.chrm.white.x",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_white_y,
            { "White Y", "png.chrm.white.y",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_red_x,
            { "Red X", "png.chrm.red.x",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_red_y,
            { "Red Y", "png.chrm.red.y",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_green_x,
            { "Green X", "png.chrm.green.x",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_green_y,
            { "Green Y", "png.chrm.green.y",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_blue_x,
            { "Blue X", "png.chrm.blue.x",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_chrm_blue_y,
            { "Blue Y", "png.chrm.blue.y",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_png_gama_gamma,
            { "Gamma", "png.gama.gamma",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
    };

    static int *ett[] =
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

    proto_png = proto_register_protocol("Portable Network Graphics","PNG","png");
    proto_register_field_array(proto_png, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_png = expert_register_protocol(proto_png);
    expert_register_field_array(expert_png, ei, array_length(ei));

    png_handle = register_dissector("png", dissect_png, proto_png);
}

static bool dissect_png_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_png(tvb, pinfo, tree, data) > 0;
}

void
proto_reg_handoff_png(void)
{
    dissector_add_string("media_type", "image/png", png_handle);
    heur_dissector_add("http", dissect_png_heur, "PNG file in HTTP", "png_http", proto_png, HEURISTIC_ENABLE);
    heur_dissector_add("wtap_file", dissect_png_heur, "PNG file in HTTP", "png_wtap", proto_png, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
