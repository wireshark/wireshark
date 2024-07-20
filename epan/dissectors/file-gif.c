/* file-gif.c
 *
 * Routines for image/gif media dissection
 * Copyright 2003, 2004, Olivier Biot.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Compuserve GIF media decoding functionality provided by Olivier Biot.
 *
 * The two GIF specifications are found at several locations, such as W3C:
 * http://www.w3.org/Graphics/GIF/spec-gif87.txt
 * http://www.w3.org/Graphics/GIF/spec-gif89a.txt
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

void proto_register_gif(void);
void proto_reg_handoff_gif(void);


/************************** Variable declarations **************************/

static const value_string vals_true_false[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL },
};

static const value_string vals_extensions[] = {
    { 0xF9, "Graphics Control" },
    { 0xFE, "Comment" },
    { 0xFF, "Application" },
    { 0x01, "Plain Text" },
    { 0x00, NULL },
};

enum {
    GIF_87a = 0x87,
    GIF_89a = 0x89
};

static dissector_handle_t gif_handle;

static int proto_gif;

static int hf_background_color;
static int hf_data_block;
static int hf_extension;
static int hf_extension_label;
static int hf_global_color_map;
static int hf_global_color_map_ordered;
static int hf_global_color_map_present;
static int hf_global_color_resolution;
static int hf_global_image_bpp;
static int hf_image;
static int hf_image_code_size;
static int hf_image_height;
static int hf_image_left;
static int hf_image_top;
static int hf_image_width;
static int hf_local_color_map;
static int hf_local_color_map_ordered;
static int hf_local_color_map_present;
static int hf_local_color_resolution;
static int hf_local_image_bpp;
static int hf_pixel_aspect_ratio;
static int hf_screen_height;
static int hf_screen_width;
static int hf_trailer;
static int hf_version;

/* Initialize the subtree pointers */
static int ett_gif;
static int ett_global_flags;
static int ett_local_flags;
static int ett_extension;
static int ett_image;

static expert_field ei_gif_unknown_data_block_type;

/****************** GIF protocol dissection functions ******************/

static int
dissect_gif_data_block_seq(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    int offset_start = offset;
    uint8_t len;
    proto_item *db_ti;

    do {
        /* Read length of data block */
        len = tvb_get_uint8(tvb, offset);
        db_ti = proto_tree_add_item(tree, hf_data_block,
                tvb, offset, 1, ENC_NA);
        proto_item_append_text(db_ti, " (length = %u)", len);
        offset += (1 + len);
    } while (len > 0);

    return offset - offset_start;
}

/* There are two Compuserve GIF standards: GIF87a and GIF89a. GIF image files
 * always convey their version in the first 6 bytes, written as an US-ASCII
 * string representation of the version: "GIF87a" or "GIF89a".
 */

static int
dissect_gif(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *gif_tree; /* Main GIF tree */
    proto_tree *subtree;
    unsigned offset = 0;
    uint8_t peek;
    bool color_map_present;
    uint8_t color_resolution;
    uint8_t image_bpp;
    const uint8_t *ver_str;
    uint8_t version;

    if (tvb_reported_length(tvb) < 20)
        return 0;

    /* Check whether we're processing a GIF object */
    /* see http://www.w3.org/Graphics/GIF/spec-gif89a.txt section 17 */
    if (tvb_strneql(tvb, 0, "GIF87a", 6) == 0) {
        version = GIF_87a;
    } else if (tvb_strneql(tvb, 0, "GIF89a", 6) == 0) {
        version = GIF_89a;
    } else {
        /* Not a GIF image! */
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_gif, tvb, offset, -1, ENC_NA);
    gif_tree = proto_item_add_subtree(ti, ett_gif);

    /* GIF signature */
    proto_tree_add_item_ret_string(gif_tree, hf_version,
            tvb, offset, 6, ENC_ASCII|ENC_NA, pinfo->pool, &ver_str);
    proto_item_append_text(ti, ", Version: %s", ver_str);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", ver_str);
    offset += 6;

    /* Screen descriptor */
    proto_tree_add_item(gif_tree, hf_screen_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(gif_tree, hf_screen_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    peek = tvb_get_uint8(tvb, offset);
    /* Bitfield gccc 0ppp
     *          g... .... : global color map present
     *          .ccc .... : color resolution in bits (add one)
     *          .... 0... : GIF87a - reserved (no use)
     *                      GIF89a - ordered (most important color 1st)
     *          .... .ppp : bits per pixel in image (add one)
     */
    color_map_present = peek & 0x80;
    color_resolution = 1 + ((peek & 0x60) >> 4);
    image_bpp = 1 + (peek & 0x07);

    subtree = proto_tree_add_subtree(gif_tree, tvb, offset, 1, ett_global_flags, &ti,
            "Global settings:");
    if (color_map_present)
        proto_item_append_text(ti, " (Global color table present)");
    proto_item_append_text(ti,
            " (%u bit%s per color) (%u bit%s per pixel)",
            color_resolution, plurality(color_resolution, "", "s"),
            image_bpp, plurality(image_bpp, "", "s"));
    proto_tree_add_item(subtree, hf_global_color_map_present,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_global_color_resolution,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    if (version == GIF_89a) {
        proto_tree_add_item(subtree, hf_global_color_map_ordered,
                tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(subtree, hf_global_image_bpp,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* Background color */
    proto_tree_add_item(gif_tree, hf_background_color,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* byte at offset 12 is 0x00 - reserved in GIF87a but encodes the
     * pixel aspect ratio in GIF89a as:
     *      aspect-ratio = (15 + pixel-aspect-ratio) / 64
     * where the aspect-ratio is not computed if pixel-aspect-ratio == 0
     */
    if (version == GIF_89a) {
        peek = tvb_get_uint8(tvb, offset);
        if (peek) {
            /* Only display if different from 0 */
            proto_tree_add_uint_format(gif_tree, hf_pixel_aspect_ratio,
                    tvb, offset, 1, peek,
                    "%u, yields an aspect ratio of (15 + %u) / 64 = %.2f",
                    peek, peek, (float)(15 + peek) / 64.0);
        }
    }
    offset++;

    /* Global color map
     * If present, it takes 2 ^ (image_bpp) byte tuples (R, G, B)
     * that contain the Red, Green and Blue intensity of the colors
     * in the Global Color Map */
    if (color_map_present) {
        unsigned len;

        len = 3 * (1 << image_bpp);
        proto_tree_add_item(gif_tree, hf_global_color_map,
                tvb, offset, len, ENC_NA);
        offset += len;
    }


    /* From now on, a set of images prefixed with the image separator
     * character 0x2C (',') will appear in the byte stream. Each image
     * hence consists of:
     * - The image separator character 0x2C
     * - Image left (16 bits LSB first): pixels from left border
     * - Image top (16 bits LSB first): pixels from to border
     * - Image width (16 bits LSB first)
     * - Image height (16 bits LSB first)
     * - A bitfield MI00 0ppp
     *              M... .... : Use global color map if unset (ignore ppp);
     *                          if set a local color map will be defined.
     *              .I.. .... : Image formatted in interlaced order if set;
     *                          otherwise it is plain sequential order
     *              ..0. .... : GIF87a - Reserved
     *              ..s. ....   GIF89a - Set if local color map is ordered
     *              ...0 0... : Reserved
     *              .... .ppp : bits per pixel in image (add one)
     * - If the local color map bit is set, then a local color table follows
     *   with length = 3 x 2 ^ (1 + bits per pixel)
     * - The raster data
     *
     * NOTE that the GIF specification only requires that:
     *      image left + image width  <= screen width
     *      image top  + image height <= screen height
     *
     * The Raster Data is encoded as follows:
     * - Code size (1 byte)
     * - Blocks consisting of
     *      o Byte count (1 byte): number of bytes in the block
     *      o Data bytes: as many as specified in the byte count
     *   End of data is given with an empty block (byte count == 0).
     *
     *
     * GIF terminator
     * This is a synchronization method, based on the final character 0x3B
     * (';') at the end of an image
     *
     *
     * GIF extension
     * This is a block of data encoded as:
     * - The GIF extension block introducer 0x21 ('!')
     * - The extension function code (1 byte)
     * - Blocks consisting of
     *      o Byte count (1 byte): number of bytes in the block
     *      o Data bytes: as many as specified in the byte count
     *   End of data is given with an empty block (byte count == 0).
     *
     * NOTE that the GIF extension block can only appear at the following
     * locations:
     * - Immediately before an Image Descriptor
     * - Before the GIF termination character
     */
    while (tvb_reported_length_remaining(tvb, offset)) {
        int ret;
        int offset_start = offset;

        peek = tvb_get_uint8(tvb, offset);
        if (peek == 0x21) { /* GIF extension block */
            ti = proto_tree_add_item(gif_tree, hf_extension,
                    tvb, offset, 1, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_extension);
            offset++;
            proto_tree_add_item(subtree, hf_extension_label,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            peek = tvb_get_uint8(tvb, offset);
            proto_item_append_text(ti, ": %s",
                    val_to_str(peek, vals_extensions,
                        "<Warning: Unknown extension 0x%02X>"));
            offset++;
            ret = dissect_gif_data_block_seq(tvb, offset, subtree);
            if (ret <= 0)
                break;
            offset += ret;
        } else if (peek == 0x2C) { /* Image separator */
            proto_tree *subtree2;
            proto_item *ti2;

            ti = proto_tree_add_item(gif_tree, hf_image,
                    tvb, offset, 1, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_image);
            offset++;
            /* Screen descriptor */
            proto_tree_add_item(subtree, hf_image_left,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
            proto_tree_add_item(subtree, hf_image_top,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
            proto_tree_add_item(subtree, hf_image_width,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
            proto_tree_add_item(subtree, hf_image_height,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
            /* bit field */
            peek = tvb_get_uint8(tvb, offset);
            color_map_present = peek & 0x80;
            color_resolution = 1 + ((peek & 0x60) >> 4);
            image_bpp = 1 + (peek & 0x07);

            subtree2 = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_local_flags, &ti2,
                    "Local settings:");
            if (color_map_present)
                proto_item_append_text(ti2, " (Local color table present)");
            proto_item_append_text(ti2,
                    " (%u bit%s per color) (%u bit%s per pixel)",
                    color_resolution, plurality(color_resolution, "", "s"),
                    image_bpp, plurality(image_bpp, "", "s"));
            proto_tree_add_item(subtree2, hf_local_color_map_present,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(subtree2, hf_local_color_resolution,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if (version == GIF_89a) {
                proto_tree_add_item(subtree2, hf_local_color_map_ordered,
                        tvb, offset, 1, ENC_LITTLE_ENDIAN);
            }
            proto_tree_add_item(subtree2, hf_global_image_bpp,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            /* Local color map
             * If present, it takes 2 ^ (image_bpp) byte tuples (R, G, B)
             * that contain the Red, Green and Blue intensity of the colors
             * in the Local Color Map */
            if (color_map_present) {
                unsigned len;

                len = 3 * (1 << image_bpp);
                proto_tree_add_item(subtree, hf_local_color_map,
                        tvb, offset, len, ENC_NA);
                offset += len;
            }

            proto_tree_add_item(subtree, hf_image_code_size,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            ret = dissect_gif_data_block_seq(tvb, offset, subtree);
            if (ret <= 0)
                break;
            offset += ret;
        } else if (peek == 0x3B) { /* Trailer byte */
            /* GIF processing stops at this very byte */
            proto_tree_add_item(gif_tree, hf_trailer,
                    tvb, offset, 1, ENC_NA);
            offset++;
            break;
        } else {
            proto_tree_add_expert(gif_tree, pinfo,
                    &ei_gif_unknown_data_block_type,
                    tvb, offset, 1);
            offset++;
        }
        proto_item_set_len(ti, offset-offset_start);
    } /* while */

    return offset;
}

static bool
dissect_gif_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_gif(tvb, pinfo, tree, data) > 0;
}


/****************** Register the protocol with Wireshark ******************/


/* This format is required because a script is used to build the C function
 * that calls the protocol registration. */

void
proto_register_gif(void)
{
    static hf_register_info hf[] = {
        { &hf_version,
            { "Version", "image-gif.version",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "GIF Version", HFILL }
        },
        { &hf_screen_width,
            { "Screen width", "image-gif.screen.width",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_screen_height,
            { "Screen height", "image-gif.screen.height",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_global_color_map_present,
            { "Global color map is present", "image-gif.global.color_map.present",
              FT_UINT8, BASE_DEC, VALS(vals_true_false), 0x80,
              "Indicates if the global color map is present", HFILL }
        },
        { &hf_global_color_resolution,
            { "Bits per color minus 1", "image-gif.global.color_bpp",
              FT_UINT8, BASE_DEC, NULL, 0x70,
              "The number of bits per color is one plus the field value.", HFILL }
        },
        { &hf_global_color_map_ordered,
            { "Global color map is ordered", "image-gif.global.color_map.ordered",
              FT_UINT8, BASE_DEC, VALS(vals_true_false), 0x08,
              "Indicates whether the global color map is ordered.", HFILL }
        },
        { &hf_global_image_bpp,
            { "Image bits per pixel minus 1", "image-gif.global.bpp",
              FT_UINT8, BASE_DEC, NULL, 0x07,
              "The number of bits per pixel is one plus the field value.", HFILL }
        },
        { &hf_background_color,
            { "Background color index", "image-gif.image_background_index",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Index of the background color in the color map.", HFILL }
        },
        { &hf_pixel_aspect_ratio,
            { "Global pixel aspect ratio", "image-gif.global.pixel_aspect_ratio",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Gives an approximate value of the aspect ratio of the pixels.", HFILL }
        },
        { &hf_global_color_map,
            { "Global color map", "image-gif.global.color_map",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              "Global color map.", HFILL }
        },
        { &hf_image_left,
            { "Image left position", "image-gif.image.left",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Offset between left of Screen and left of Image.", HFILL }
        },
        { &hf_image_top,
            { "Image top position", "image-gif.image.top",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Offset between top of Screen and top of Image.", HFILL }
        },
        { &hf_image_width,
            { "Image width", "image-gif.image.width",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Image width.", HFILL }
        },
        { &hf_image_height,
            { "Image height", "image-gif.image.height",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Image height.", HFILL }
        },
        { &hf_local_color_map_present,
            { "Local color map is present", "image-gif.local.color_map.present",
              FT_UINT8, BASE_DEC, VALS(vals_true_false), 0x80,
              "Indicates if the local color map is present", HFILL }
        },
        { &hf_local_color_resolution,
            { "Bits per color minus 1", "image-gif.local.color_bpp",
              FT_UINT8, BASE_DEC, NULL, 0x70,
              "The number of bits per color is one plus the field value.", HFILL }
        },
        { &hf_local_color_map_ordered,
            { "Local color map is ordered", "image-gif.local.color_map.ordered",
              FT_UINT8, BASE_DEC, VALS(vals_true_false), 0x08,
              "Indicates whether the local color map is ordered.", HFILL }
        },
        { &hf_local_image_bpp,
            { "Image bits per pixel minus 1", "image-gif.local.bpp",
              FT_UINT8, BASE_DEC, NULL, 0x07,
              "The number of bits per pixel is one plus the field value.", HFILL }
        },
        { &hf_local_color_map,
            { "Local color map", "image-gif.local.color_map",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              "Local color map.", HFILL }
        },
        { &hf_extension,
            { "Extension", "image-gif.extension",
              FT_NONE, BASE_NONE, NULL, 0x00,
              "Extension.", HFILL }
        },
        { &hf_extension_label,
            { "Extension label", "image-gif.extension.label",
              FT_UINT8, BASE_HEX, VALS(vals_extensions), 0x00,
              "Extension label.", HFILL }
        },
        { &hf_image,
            { "Image", "image-gif.image",
              FT_NONE, BASE_NONE, NULL, 0x00,
              "Image.", HFILL }
        },
        { &hf_image_code_size,
            { "LZW minimum code size", "image-gif.image.code_size",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Minimum code size for the LZW compression.", HFILL }
        },
        { &hf_trailer,
            { "Trailer (End of the GIF stream)", "image-gif.end",
              FT_NONE, BASE_NONE, NULL, 0x00,
              "This byte tells the decoder that the data stream is finished.", HFILL }
        },
        { &hf_data_block,
            { "Data block", "image-gif.data_block",
              FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x00,
              NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_gif,
        &ett_global_flags,
        &ett_local_flags,
        &ett_extension,
        &ett_image,
    };

    static ei_register_info ei[] = {
        { &ei_gif_unknown_data_block_type,
            { "gif.data_block_type.unknown", PI_PROTOCOL, PI_WARN,
                "Unknown GIF data block type", EXPFILL }
        }
    };

    expert_module_t* expert_gif;

    /* Register the protocol name and description */
    proto_gif = proto_register_protocol(
            "Compuserve GIF",
            "GIF image",
            "image-gif"
    );

    /* Required function calls to register the header fields
     * and subtrees used */
    proto_register_field_array(proto_gif, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_gif = expert_register_protocol(proto_gif);
    expert_register_field_array(expert_gif, ei, array_length(ei));

    gif_handle = register_dissector("image-gif", dissect_gif, proto_gif);
}


void
proto_reg_handoff_gif(void)
{
    /* Register the GIF media type */
    dissector_add_string("media_type", "image/gif", gif_handle);
    heur_dissector_add("http", dissect_gif_heur, "GIF file in HTTP", "gif_http", proto_gif, HEURISTIC_ENABLE);
    heur_dissector_add("wtap_file", dissect_gif_heur, "GIF file", "gif_wtap", proto_gif, HEURISTIC_ENABLE);
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
