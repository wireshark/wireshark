/* packet-image-jfif.c
 *
 * Routines for JFIF image/jpeg media dissection
 * Copyright 2004, Olivier Biot.
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * JFIF media decoding functionality provided by Olivier Biot.
 *
 * The JFIF specifications are found at several locations, such as:
 * http://www.jpeg.org/public/jfif.pdf
 * http://www.w3.org/Graphics/JPEG/itu-t81.pdf
 *
 * The Exif specifications are found at several locations, such as:
 * http://www.exif.org/
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

#include <string.h>

#include <glib.h>

#include <epan/packet.h>

/* General-purpose debug logger.
 * Requires double parentheses because of variable arguments of printf().
 *
 * Enable debug logging for JFIF by defining AM_CFLAGS
 * so that it contains "-DDEBUG_image_jfif" or "-DDEBUG_image"
 */
#if (defined(DEBUG_image_jfif) || defined(DEBUG_image))
#define DebugLog(x) \
    g_print("%s:%u: ", __FILE__, __LINE__); \
    g_print x
#else
#define DebugLog(x) ;
#endif

#define IMG_JFIF "image-jfif"

/************************** Variable declarations **************************/

#define MARKER_TEM      0xFF01

/* 0xFF02 -- 0xFFBF are reserved */

#define MARKER_SOF0     0xFFC0
#define MARKER_SOF1     0xFFC1
#define MARKER_SOF2     0xFFC2
#define MARKER_SOF3     0xFFC3

#define MARKER_DHT      0xFFC4

#define MARKER_SOF5     0xFFC5
#define MARKER_SOF6     0xFFC6
#define MARKER_SOF7     0xFFC7
#define MARKER_SOF8     0xFFC8
#define MARKER_SOF9     0xFFC9
#define MARKER_SOF10    0xFFCA
#define MARKER_SOF11    0xFFCB

#define MARKER_DAC      0xFFCC

#define MARKER_SOF13    0xFFCD
#define MARKER_SOF14    0xFFCE
#define MARKER_SOF15    0xFFCF

#define MARKER_RST0     0xFFD0
#define MARKER_RST1     0xFFD1
#define MARKER_RST2     0xFFD2
#define MARKER_RST3     0xFFD3
#define MARKER_RST4     0xFFD4
#define MARKER_RST5     0xFFD5
#define MARKER_RST6     0xFFD6
#define MARKER_RST7     0xFFD7

#define MARKER_FFDB     0xFFDB
#define MARKER_SOI      0xFFD8
#define MARKER_EOI      0xFFD9
#define MARKER_SOS      0xFFDA
#define MARKER_DQT      0xFFDB
#define MARKER_DNL      0xFFDC
#define MARKER_DRI      0xFFDD
#define MARKER_DHP      0xFFDE
#define MARKER_EXP      0xFFDF

#define MARKER_APP0     0xFFE0
#define MARKER_APP1     0xFFE1
#define MARKER_APP2     0xFFE2
#define MARKER_APP3     0xFFE3
#define MARKER_APP4     0xFFE4
#define MARKER_APP5     0xFFE5
#define MARKER_APP6     0xFFE6
#define MARKER_APP7     0xFFE7
#define MARKER_APP8     0xFFE8
#define MARKER_APP9     0xFFE9
#define MARKER_APP10    0xFFEA
#define MARKER_APP11    0xFFEB
#define MARKER_APP12    0xFFEC
#define MARKER_APP13    0xFFED
#define MARKER_APP14    0xFFEE
#define MARKER_APP15    0xFFEF

#define MARKER_JPG0     0xFFF0
#define MARKER_JPG1     0xFFF1
#define MARKER_JPG2     0xFFF2
#define MARKER_JPG3     0xFFF3
#define MARKER_JPG4     0xFFF4
#define MARKER_JPG5     0xFFF5
#define MARKER_JPG6     0xFFF6
#define MARKER_JPG7     0xFFF7
#define MARKER_JPG8     0xFFF8
#define MARKER_JPG9     0xFFF9
#define MARKER_JPG10    0xFFFA
#define MARKER_JPG11    0xFFFB
#define MARKER_JPG12    0xFFFC
#define MARKER_JPG13    0xFFFD

#define MARKER_COM      0xFFFE

#define marker_has_length(marker) ( ! ( \
       ((marker) == MARKER_TEM) \
    || ((marker) == MARKER_SOI) \
    || ((marker) == MARKER_EOI) \
    || ( ((marker) >= MARKER_RST0) && ((marker) <= MARKER_RST7) ) \
    ) )


static const value_string vals_marker[] = {
    { MARKER_TEM,   "Reserved - For temporary private use in arithmetic coding" },
    { MARKER_SOF0,  "Start of Frame (non-differential, Huffman coding) - Baseline DCT" },
    { MARKER_SOF1,  "Start of Frame (non-differential, Huffman coding) - Extended sequential DCT" },
    { MARKER_SOF2,  "Start of Frame (non-differential, Huffman coding) - Progressive DCT" },
    { MARKER_SOF3,  "Start of Frame (non-differential, Huffman coding) - Lossless (sequential)" },
    { MARKER_DHT,   "Define Huffman table(s)" },
    { MARKER_SOF5,  "Start of Frame (differential, Huffman coding) - Differential sequential DCT" },
    { MARKER_SOF6,  "Start of Frame (differential, Huffman coding) - Differential progressive DCT" },
    { MARKER_SOF7,  "Start of Frame (differential, Huffman coding) - Differential lossless (sequential)" },
    { MARKER_SOF8,  "Start of Frame (non-differential, arithmetic coding) - Reserved for JPEG extensions" },
    { MARKER_SOF9,  "Start of Frame (non-differential, arithmetic coding) - Extended sequential DCT" },
    { MARKER_SOF10, "Start of Frame (non-differential, arithmetic coding) - Progressive DCT" },
    { MARKER_SOF11, "Start of Frame (non-differential, arithmetic coding) - Lossless (sequential)" },
    { MARKER_DAC,   "Define arithmetic coding conditioning(s)" },
    { MARKER_SOF13, "Start of Frame (differential, arithmetic coding) - Differential sequential DCT" },
    { MARKER_SOF14, "Start of Frame (differential, arithmetic coding) - Differential progressive DCT" },
    { MARKER_SOF15, "Start of Frame (differential, arithmetic coding) - Differential lossless (sequential)" },
    { MARKER_RST0,  "Restart interval termination - Restart with modulo 8 count 0" },
    { MARKER_RST1,  "Restart interval termination - Restart with modulo 8 count 1" },
    { MARKER_RST2,  "Restart interval termination - Restart with modulo 8 count 2" },
    { MARKER_RST3,  "Restart interval termination - Restart with modulo 8 count 3" },
    { MARKER_RST4,  "Restart interval termination - Restart with modulo 8 count 4" },
    { MARKER_RST5,  "Restart interval termination - Restart with modulo 8 count 5" },
    { MARKER_RST6,  "Restart interval termination - Restart with modulo 8 count 6" },
    { MARKER_RST7,  "Restart interval termination - Restart with modulo 8 count 7" },
    { MARKER_SOI,   "Start of Image" },
    { MARKER_EOI,   "End of Image" },
    { MARKER_SOS,   "Start of Scan" },
    { MARKER_DQT,   "Define quantization table(s)" },
    { MARKER_DNL,   "Define number of lines" },
    { MARKER_DRI,   "Define restart interval" },
    { MARKER_DHP,   "Define hierarchical progression" },
    { MARKER_EXP,   "Expand reference component(s)" },
    { MARKER_APP0,  "Reserved for application segments - 0" },
    { MARKER_APP1,  "Reserved for application segments - 1" },
    { MARKER_APP2,  "Reserved for application segments - 2" },
    { MARKER_APP3,  "Reserved for application segments - 3" },
    { MARKER_APP4,  "Reserved for application segments - 4" },
    { MARKER_APP5,  "Reserved for application segments - 5" },
    { MARKER_APP6,  "Reserved for application segments - 6" },
    { MARKER_APP7,  "Reserved for application segments - 7" },
    { MARKER_APP8,  "Reserved for application segments - 8" },
    { MARKER_APP9,  "Reserved for application segments - 9" },
    { MARKER_APP10, "Reserved for application segments - 10" },
    { MARKER_APP11, "Reserved for application segments - 11" },
    { MARKER_APP12, "Reserved for application segments - 12" },
    { MARKER_APP13, "Reserved for application segments - 13" },
    { MARKER_APP14, "Reserved for application segments - 14" },
    { MARKER_APP15, "Reserved for application segments - 15" },
    { MARKER_JPG0,  "Reserved for JPEG extensions - 0" },
    { MARKER_JPG1,  "Reserved for JPEG extensions - 1" },
    { MARKER_JPG2,  "Reserved for JPEG extensions - 2" },
    { MARKER_JPG3,  "Reserved for JPEG extensions - 3" },
    { MARKER_JPG4,  "Reserved for JPEG extensions - 4" },
    { MARKER_JPG5,  "Reserved for JPEG extensions - 5" },
    { MARKER_JPG6,  "Reserved for JPEG extensions - 6" },
    { MARKER_JPG7,  "Reserved for JPEG extensions - 7" },
    { MARKER_JPG8,  "Reserved for JPEG extensions - 8" },
    { MARKER_JPG9,  "Reserved for JPEG extensions - 9" },
    { MARKER_JPG10, "Reserved for JPEG extensions - 10" },
    { MARKER_JPG11, "Reserved for JPEG extensions - 11" },
    { MARKER_JPG12, "Reserved for JPEG extensions - 12" },
    { MARKER_JPG13, "Reserved for JPEG extensions - 13" },
    { MARKER_COM,   "Comment" },
    { 0x00, NULL }
};

static const value_string vals_units[] = {
    { 0, "No units; Xdensity and Ydensity specify the pixel aspect ratio" },
    { 1, "Dots per inch" },
    { 2, "Dots per centimeter" },
    { 0x00, NULL }
};

static const value_string vals_extension_code[] = {
    { 0x10, "Thumbnail encoded using JPEG" },
    { 0x11, "Thumbnail encoded using 1 byte (8 bits) per pixel" },
    { 0x13, "Thumbnail encoded using 3 bytes (24 bits) per pixel" },
    { 0x00, NULL }
};

static const value_string vals_exif_tags[] = {
    /*
     * Tags related to image data structure:
     */
    { 0x0100, "ImageWidth" },
    { 0x0101, "ImageLength" },
    { 0x0102, "BitsPerSample" },
    { 0x0103, "Compression" },
    { 0x0106, "PhotometricInterpretation" },
    { 0x0112, "Orientation" },
    { 0x0115, "SamplesPerPixel" },
    { 0x011C, "PlanarConfiguration" },
    { 0x0212, "YCbCrSubSampling" },
    { 0x0213, "YCbCrPositioning" },
    { 0x011A, "XResolution" },
    { 0x011B, "YResolution" },
    { 0x0128, "ResolutionUnit" },
    /*
     * Tags relating to recording offset:
     */
    { 0x0111, "StripOffsets" },
    { 0x0116, "RowsPerStrip" },
    { 0x0117, "StripByteCounts" },
    { 0x0201, "JPEGInterchangeFormat" },
    { 0x0202, "JPEGInterchangeFormatLength" },
    /*
     * Tags relating to image data characteristics:
     */
    { 0x012D, "TransferFunction" },
    { 0x013E, "WhitePoint" },
    { 0x013F, "PrimaryChromaticities" },
    { 0x0211, "YCbCrCoefficients" },
    { 0x0214, "ReferenceBlackWhite" },
    /*
     * Other tags:
     */
    { 0x0132, "DateTime" },
    { 0x010E, "ImageDescription" },
    { 0x010F, "Make" },
    { 0x0110, "Model" },
    { 0x0131, "Software" },
    { 0x013B, "Artist" },
    { 0x8296, "Copyright" },
    /*
     * Exif-specific IFD:
     */
    { 0x8769, "Exif IFD Pointer"},
    { 0x8825, "GPS IFD Pointer"},
    { 0xA005, "Interoperability IFD Pointer"},

    { 0x0000, NULL }
};

static const value_string vals_exif_types[] = {
    { 0x0001, "BYTE" },
    { 0x0002, "ASCII" },
    { 0x0003, "SHORT" },
    { 0x0004, "LONG" },
    { 0x0005, "RATIONAL" },
    /* 0x0006 */
    { 0x0007, "UNDEFINED" },
    /* 0x0008 */
    { 0x0009, "SLONG" },
    { 0x000A, "SRATIONAL" },

    { 0x0000, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_jfif = -1;

/* Marker */
static gint hf_marker = -1;
/* Marker segment */
static gint hf_marker_segment = -1;
static gint hf_len = -1;
/* MARKER_APP0 */
static gint hf_identifier = -1;
/* MARKER_APP0 - JFIF */
static gint hf_version = -1;
static gint hf_version_major = -1;
static gint hf_version_minor = -1;
static gint hf_units = -1;
static gint hf_xdensity = -1;
static gint hf_ydensity = -1;
static gint hf_xthumbnail = -1;
static gint hf_ythumbnail = -1;
static gint hf_rgb = -1;
/* MARKER_APP0 - JFXX */
static gint hf_extension_code = -1;
/* start of Frame */
static gint hf_sof_header = -1;
static gint hf_sof_precision = -1;
static gint hf_sof_lines = -1;
static gint hf_sof_samples_per_line = -1;
static gint hf_sof_nf = -1;
static gint hf_sof_c_i = -1;
static gint hf_sof_h_i = -1;
static gint hf_sof_v_i = -1;
static gint hf_sof_tq_i = -1;

/* Start of Scan */
static gint hf_sos_header = -1;
static gint hf_sos_ns = -1;
static gint hf_sos_cs_j = -1;
static gint hf_sos_td_j = -1;
static gint hf_sos_ta_j = -1;
static gint hf_sos_ss = -1;
static gint hf_sos_se = -1;
static gint hf_sos_ah = -1;
static gint hf_sos_al = -1;

/* Initialize the subtree pointers */
static gint ett_jfif = -1;
static gint ett_marker_segment = -1;
static gint ett_details = -1;


/****************** JFIF protocol dissection functions ******************/

#define ErrorInvalidJFIF "This is not a valid JFIF (JPEG) object"


/*
 * Process a marker segment (with length).
 */
static void
process_marker_segment(proto_tree *tree, tvbuff_t *tvb, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;

    if (! tree)
        return;

    ti = proto_tree_add_item(tree, hf_marker_segment,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_text(subtree, tvb, 4, -1,
            "Remaining segment data (%u bytes)", len - 2);
}

/*
 * Process a Start of Frame header (with length).
 */
static void
process_sof_header(proto_tree *tree, tvbuff_t *tvb, guint32 len _U_,
        guint16 marker, const char *marker_name)
{
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;

    if (! tree)
        return;

    ti = proto_tree_add_item(tree, hf_sof_header,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sof_precision, tvb, 4, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sof_lines, tvb, 5, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sof_samples_per_line, tvb, 7, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sof_nf, tvb, 9, 1, ENC_BIG_ENDIAN);
    {
        guint8 count = tvb_get_guint8(tvb, 9);
        guint32 offset = 10;
        while (count > 0) {
            proto_tree_add_item(subtree, hf_sof_c_i, tvb, offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_sof_h_i, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_sof_v_i, tvb, offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_sof_tq_i, tvb, offset++, 1, ENC_BIG_ENDIAN);
            count--;
        }
    }
}

/*
 * Process a Start of Segment header (with length).
 */
static void
process_sos_header(proto_tree *tree, tvbuff_t *tvb, guint32 len _U_,
        guint16 marker, const char *marker_name)
{
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;
    guint32 offset;

    if (! tree)
        return;

    ti = proto_tree_add_item(tree, hf_sos_header,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sos_ns, tvb, 4, 1, ENC_BIG_ENDIAN);
    {
        guint8 count = tvb_get_guint8(tvb, 4);
        offset = 5;
        while (count > 0) {
            proto_tree_add_item(subtree, hf_sos_cs_j, tvb, offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_sos_td_j, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_sos_ta_j, tvb, offset++, 1, ENC_BIG_ENDIAN);
            count--;
        }
    }

    proto_tree_add_item(subtree, hf_sos_ss, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sos_se, tvb, offset++, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sos_ah, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sos_al, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* offset ++ */;
}

/* Process an APP0 block.
 *
 * XXX - This code only works on US-ASCII systems!!!
 */
static int
process_app0_segment(proto_tree *tree, tvbuff_t *tvb, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;
    proto_tree *subtree_details = NULL;
    guint32 offset;
    char *str;
    gint str_size;

    if (!tree)
        return 0 ;

    ti = proto_tree_add_item(tree, hf_marker_segment,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    str = tvb_get_ephemeral_stringz(tvb, 4, &str_size);
    ti = proto_tree_add_item(subtree, hf_identifier, tvb, 4, str_size, ENC_ASCII|ENC_NA);
    if (strcmp(str, "JFIF") == 0) {
        /* Version */
        ti = proto_tree_add_none_format(subtree, hf_version,
                tvb, 9, 2, "Version: %u.%u",
                tvb_get_guint8(tvb, 9),
                tvb_get_guint8(tvb, 10));
        subtree_details = proto_item_add_subtree(ti, ett_details);
        proto_tree_add_item(subtree_details, hf_version_major,
                tvb, 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree_details, hf_version_minor,
                tvb, 10, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(subtree, hf_units,
                tvb, 11, 1, ENC_BIG_ENDIAN);

        /* Aspect ratio */
        proto_tree_add_item(subtree, hf_xdensity,
                tvb, 12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ydensity,
                tvb, 14, 2, ENC_BIG_ENDIAN);

        /* Thumbnail */
        proto_tree_add_item(subtree, hf_xthumbnail,
                tvb, 16, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ythumbnail,
                tvb, 17, 1, ENC_BIG_ENDIAN);
        {
            guint16 x = tvb_get_guint8(tvb, 16);
            guint16 y = tvb_get_guint8(tvb, 17);
            if (x || y) {
                proto_tree_add_item(subtree, hf_rgb,
                        tvb, 18, 3 * (x * y), ENC_NA);
                offset = 18 + (3 * (x * y));
            } else {
                offset = 18;
            }
        }
    } else if (strcmp(str, "JFXX") == 0) {
        proto_tree_add_item(subtree, hf_extension_code,
                tvb, 9, 1, ENC_BIG_ENDIAN);
        {
            guint8 code = tvb_get_guint8(tvb, 9);
            switch (code) {
                case 0x10: /* Thumbnail coded using JPEG */
                    break;
                case 0x11: /* thumbnail stored using 1 byte per pixel */
                    break;
                case 0x13: /* thumbnail stored using 3 bytes per pixel */
                    break;
                default: /* Error */
                    break;
            }
        }
        offset = 10;
    } else { /* Unknown */
        proto_item_append_text(ti, " (unknown identifier)");
        offset = 4 + str_size;

        proto_tree_add_text(subtree, tvb, offset, -1,
                "Remaining segment data (%u bytes)", len - 2 - str_size);
    }
    return offset;
}

/* Process an APP1 block.
 *
 * XXX - This code only works on US-ASCII systems!!!
 */
static int
process_app1_segment(proto_tree *tree, tvbuff_t *tvb, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;
    char *str;
    gint str_size;
    int offset = 0;
    int tiff_start;

    if (!tree)
        return 0;

    ti = proto_tree_add_item(tree, hf_marker_segment,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    str = tvb_get_ephemeral_stringz(tvb, offset, &str_size);
    ti = proto_tree_add_item(subtree, hf_identifier, tvb, offset, str_size, ENC_ASCII|ENC_NA);
    offset += str_size;
    if (strcmp(str, "Exif") == 0) {
        /*
         * Endianness
         */
        gboolean is_little_endian;
        guint16 val_16;
        guint32 val_32;
        guint16 num_fields;

        offset++; /* Skip a byte supposed to be 0x00 */

        tiff_start = offset;
        val_16 = tvb_get_ntohs(tvb, offset);
        if (val_16 == 0x4949) {
            is_little_endian = TRUE;
            proto_tree_add_text(subtree, tvb, offset, 2, "Endianness: little endian");
        } else if (val_16 == 0x4D4D) {
            is_little_endian = FALSE;
            proto_tree_add_text(subtree, tvb, offset, 2, "Endianness: big endian");
        } else {
            /* Error: invalid endianness encoding */
            proto_tree_add_text(subtree, tvb, offset, 2,
                    "Incorrect endianness encoding - skipping the remainder of this application marker");
            return offset;
        }
        offset += 2;
        /*
         * Fixed value 42 = 0x002a
         */
        offset += 2;
        /*
         * Offset to IFD
         */
        if (is_little_endian) {
            val_32 = tvb_get_letohl(tvb, offset);
        } else {
            val_32 = tvb_get_ntohl(tvb, offset);
        }
        /*
         * Check for a bogus val_32 value.
         * XXX - bogus value message should also deal with a
         * value that's too large and causes an overflow.
         * Or should it just check against the segment length,
         * which is 16 bits?
         */
        if (val_32 + tiff_start < (guint32)offset + 4) {
            proto_tree_add_text(subtree, tvb, offset, 4,
                "Start offset of IFD starting from the TIFF header start: %u bytes (bogus, should be >= %u",
                val_32, offset + 4 - tiff_start);
            return offset;
        }
        proto_tree_add_text(subtree, tvb, offset, 4,
            "Start offset of IFD starting from the TIFF header start: %u bytes",
            val_32);
        offset += 4;
        /*
         * Skip the following portion
         */
        if (val_32 + tiff_start > (guint32)offset) {
            proto_tree_add_text(subtree, tvb, offset, val_32 + tiff_start - offset,
                "Skipped data between end of TIFF header and start of IFD (%u bytes)",
                val_32 + tiff_start - offset);
        }
        for (;;) {
            offset = val_32 + tiff_start;
            /*
             * Process the IFD
             */
            if (is_little_endian) {
                num_fields = tvb_get_letohs(tvb, offset);
            } else {
                num_fields = tvb_get_ntohs(tvb, offset);
            }
            proto_tree_add_text(subtree, tvb, offset, 2, "Number of fields in this IFD: %u", num_fields);
            offset += 2;
            while (num_fields-- > 0) {
                guint16 tag, type;
                guint32 count, off;

                if (is_little_endian) {
                    tag = tvb_get_letohs(tvb, offset);
                    type = tvb_get_letohs(tvb, offset + 2);
                    count = tvb_get_letohl(tvb, offset + 4);
                    off = tvb_get_letohl(tvb, offset + 8);
                } else {
                    tag = tvb_get_ntohs(tvb, offset);
                    type = tvb_get_ntohs(tvb, offset + 2);
                    count = tvb_get_ntohl(tvb, offset + 4);
                    off = tvb_get_ntohl(tvb, offset + 8);
                }
                /* TODO - refine this */
                proto_tree_add_text(subtree, tvb, offset, 2,
                    "Exif Tag: 0x%04X (%s), Type: %u (%s), Count: %u, "
                    "Value offset from start of TIFF header: %u",
                    tag, val_to_str_const(tag, vals_exif_tags, "Unknown Exif tag"),
                    type, val_to_str_const(type, vals_exif_types, "Unknown Exif type"),
                    count, off);
                offset += 12;
            }
            /*
             * Offset to the next IFD
             */
            if (is_little_endian) {
                val_32 = tvb_get_letohl(tvb, offset);
            } else {
                val_32 = tvb_get_ntohl(tvb, offset);
            }
            if (val_32 != 0 &&
                val_32 + tiff_start < (guint32)offset + 4) {
                proto_tree_add_text(subtree, tvb, offset, 4,
                    "Offset to next IFD from start of TIFF header: %u bytes (bogus, should be >= %u)",
                    val_32, offset + 4 - tiff_start);
                return offset;
            }
            proto_tree_add_text(subtree, tvb, offset, 4,
                "Offset to next IFD from start of TIFF header: %u bytes",
                val_32);
            offset += 4;
            if (val_32 == 0)
                break;
        }
    } else {
        proto_tree_add_text(subtree, tvb, offset, -1,
                "Remaining segment data (%u bytes)", len - 2 - str_size);
        proto_item_append_text(ti, " (Unknown identifier)");
    }
    return offset;
}

/* Process an APP2 block.
 *
 * XXX - This code only works on US-ASCII systems!!!
 */
static void
process_app2_segment(proto_tree *tree, tvbuff_t *tvb, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;
    char *str;
    gint str_size;

    if (!tree)
        return;

    ti = proto_tree_add_item(tree, hf_marker_segment,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    str = tvb_get_ephemeral_stringz(tvb, 4, &str_size);
    ti = proto_tree_add_item(subtree, hf_identifier, tvb, 4, str_size, ENC_ASCII|ENC_NA);
    if (strcmp(str, "FPXR") == 0) {
        proto_tree_add_text(tree, tvb, 0, -1, "Exif FlashPix APP2 application marker");
    } else {
        proto_tree_add_text(subtree, tvb, 4 + str_size, -1,
                "Remaining segment data (%u bytes)", len - 2 - str_size);
        proto_item_append_text(ti, " (Unknown identifier)");
    }
}

static gint
dissect_jfif(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = NULL;
    proto_item *ti = NULL;
    guint tvb_len = tvb_reported_length(tvb);
    guint32 offset = 0;

    /* check if we have a full JFIF in tvb */
    if (tvb_len < 20)
        return 0;
    if (tvb_get_ntohs(tvb, 0) != MARKER_SOI)
        return 0;
    if (tvb_memeql(tvb, 6, "JFIF", 5))
        return 0;

    /* Add summary to INFO column if it is enabled */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(JPEG JFIF image)");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_jfif,
                tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_jfif);
        proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);
    }

    offset = 2;     /* skip MARKER_SOI */

    /*
     * Process the remaining markers and marker segments
     */
    while (offset < tvb_len) {
        const char *str;
        const guint16 marker = tvb_get_ntohs(tvb, offset);
        str = match_strval(marker, vals_marker);
        if (str) { /* Known marker */
            if (marker_has_length(marker)) { /* Marker segment */
                /* Length of marker segment = 2 + len */
                const guint16 len = tvb_get_ntohs(tvb, offset + 2);
                tvbuff_t *tmp_tvb = tvb_new_subset(tvb, offset, 2 + len, 2 + len);
                switch (marker) {
                    case MARKER_APP0:
                        process_app0_segment(subtree, tmp_tvb, len, marker, str);
                        break;
                    case MARKER_APP1:
                        process_app1_segment(subtree, tmp_tvb, len, marker, str);
                        break;
                    case MARKER_APP2:
                        process_app2_segment(subtree, tmp_tvb, len, marker, str);
                        break;
                    case MARKER_SOF0:
                    case MARKER_SOF1:
                    case MARKER_SOF2:
                    case MARKER_SOF3:
                    case MARKER_SOF5:
                    case MARKER_SOF6:
                    case MARKER_SOF7:
                    case MARKER_SOF8:
                    case MARKER_SOF9:
                    case MARKER_SOF10:
                    case MARKER_SOF11:
                    case MARKER_SOF13:
                    case MARKER_SOF14:
                    case MARKER_SOF15:
                        process_sof_header(subtree, tmp_tvb, len, marker, str);
                        break;
                    case MARKER_SOS:
                        process_sos_header(subtree, tmp_tvb, len, marker, str);
                        /*
                         * TODO - dissect a scan; the scan data is encoded.
                         */
                        proto_tree_add_text(subtree, tvb, offset + 2 + len, -1,
                                "JFIF dissection stops here (dissection of a scan is not yet implemented)");
                        return tvb_len;
                        break;
                    default:
                        process_marker_segment(subtree, tmp_tvb, len, marker, str);
                        break;
                }
                offset += 2 + len;
            } else { /* Marker but no segment */
                /* Length = 2 */
                proto_tree_add_item(subtree, hf_marker,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
        } else { /* Reserved! */
            ti = proto_tree_add_item(subtree, hf_marker,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, " (Reserved)");
            return tvb_len;
        }
    }

    return tvb_len;
}

static gboolean
dissect_jfif_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_jfif(tvb, pinfo, tree, NULL) > 0;
}

/****************** Register the protocol with Wireshark ******************/

void
proto_register_jfif(void)
{
    /*
     * Setup list of header fields.
     */
    static hf_register_info hf[] = {
        /* Marker */
        { &hf_marker,
          {   "Marker",
              IMG_JFIF ".marker",
              FT_UINT8, BASE_HEX, VALS(vals_marker), 0x00,
              "JFIF Marker",
              HFILL
          }
        },
        /* Marker segment */
        { &hf_marker_segment,
          {   "Marker segment",
              IMG_JFIF ".marker_segment",
              FT_NONE, BASE_NONE, NULL, 0x00,
              NULL,
              HFILL
          }
        },
        { &hf_len,
          {   "Length",
              IMG_JFIF ".length",
              FT_UINT16, BASE_DEC, 0, 0x00,
              "Length of segment (including length field)",
              HFILL
          }
        },
        /* MARKER_APP0 */
        { &hf_identifier,
          {   "Identifier",
              IMG_JFIF ".identifier",
              FT_STRINGZ, BASE_NONE, NULL, 0x00,
              "Identifier of the segment",
              HFILL
          }
        },
        /* MARKER_APP0 - JFIF */
        { &hf_version,
          {   "Version",
              IMG_JFIF ".version",
              FT_NONE, BASE_NONE, NULL, 0x00,
              "JFIF Version",
              HFILL
          }
        },
        { &hf_version_major,
          {   "Major Version",
              IMG_JFIF ".version.major",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "JFIF Major Version",
              HFILL
          }
        },
        { &hf_version_minor,
          {   "Minor Version",
              IMG_JFIF ".version.minor",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "JFIF Minor Version",
              HFILL
          }
        },
        { &hf_units,
          {   "Units",
              IMG_JFIF ".units",
              FT_UINT8, BASE_DEC, VALS(vals_units), 0x00,
              "Units used in this segment",
              HFILL
          }
        },
        { &hf_xdensity,
          {   "Xdensity",
              IMG_JFIF ".Xdensity",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Horizontal pixel density",
              HFILL
          }
        },
        { &hf_ydensity,
          {   "Ydensity",
              IMG_JFIF ".Ydensity",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Vertical pixel density",
              HFILL
          }
        },
        { &hf_xthumbnail,
          {   "Xthumbnail",
              IMG_JFIF ".Xthumbnail",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Thumbnail horizontal pixel count",
              HFILL
          }
        },
        { &hf_ythumbnail,
          {   "Ythumbnail",
              IMG_JFIF ".Ythumbnail",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Thumbnail vertical pixel count",
              HFILL
          }
        },
        { &hf_rgb,
          {   "RGB values of thumbnail pixels",
              IMG_JFIF ".RGB",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              "RGB values of the thumbnail pixels (24 bit per pixel, Xthumbnail x Ythumbnail pixels)",
              HFILL
          }
        },
        /* MARKER_APP0 - JFXX */
        { &hf_extension_code,
          {   "Extension code",
              IMG_JFIF ".extension.code",
              FT_UINT8, BASE_HEX, VALS(vals_extension_code), 0x00,
              "JFXX extension code for thumbnail encoding",
              HFILL
          }
        },
        /* Header: Start of Frame (MARKER_SOF) */
        { &hf_sof_header,
          {   "Start of Frame header",
              IMG_JFIF ".sof",
              FT_NONE, BASE_NONE, NULL, 0x00,
              NULL,
              HFILL
          }
        },
        { &hf_sof_precision,
          {   "Sample Precision (bits)",
              IMG_JFIF ".sof.precision",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Specifies the precision in bits for the samples of the components in the frame.",
              HFILL
          }
        },
        { &hf_sof_lines,
          {   "Lines",
              IMG_JFIF ".sof.lines",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Specifies the maximum number of lines in the source image.",
              HFILL
          }
        },
        { &hf_sof_samples_per_line,
          {   "Samples per line",
              IMG_JFIF ".sof.samples_per_line",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "Specifies the maximum number of samples per line in the source image.",
              HFILL
          }
        },
        { &hf_sof_nf,
          {   "Number of image components in frame",
              IMG_JFIF ".sof.nf",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Specifies the number of source image components in the frame.",
              HFILL
          }
        },
        { &hf_sof_c_i,
          {   "Component identifier",
              IMG_JFIF ".sof.c_i",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Assigns a unique label to the ith component in the sequence of frame component specification parameters.",
              HFILL
          }
        },
        { &hf_sof_h_i,
          {   "Horizontal sampling factor",
              IMG_JFIF ".sof.h_i",
              FT_UINT8, BASE_DEC, NULL, 0xF0,
              "Specifies the relationship between the component horizontal dimension and maximum image dimension X.",
              HFILL
          }
        },
        { &hf_sof_v_i,
          {   "Vertical sampling factor",
              IMG_JFIF ".sof.v_i",
              FT_UINT8, BASE_DEC, NULL, 0x0F,
              "Specifies the relationship between the component vertical dimension and maximum image dimension Y.",
              HFILL
          }
        },
        { &hf_sof_tq_i,
          {   "Quantization table destination selector",
              IMG_JFIF ".sof.tq_i",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Specifies one of four possible quantization table destinations from which the quantization table to"
              " use for dequantization of DCT coefficients of component Ci is retrieved.",
              HFILL
          }
        },

        /* Header: Start of Segment (MARKER_SOS) */
        { &hf_sos_header,
          {   "Start of Segment header",
              IMG_JFIF ".header.sos",
              FT_NONE, BASE_NONE, NULL, 0x00,
              NULL,
              HFILL
          }
        },
        { &hf_sos_ns,
          {   "Number of image components in scan",
              IMG_JFIF ".sos.ns",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Specifies the number of source image components in the scan.",
              HFILL
          }
        },
        { &hf_sos_cs_j,
          {   "Scan component selector",
              IMG_JFIF ".sos.component_selector",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Selects which of the Nf image components specified in the frame parameters shall be the jth"
              " component in the scan.",
              HFILL
          }
        },
        { &hf_sos_td_j,
          {   "DC entropy coding table destination selector",
              IMG_JFIF ".sos.dc_entropy_selector",
              FT_UINT8, BASE_DEC, NULL, 0xF0,
              "Specifies one of four possible DC entropy coding table destinations from which the entropy"
              " table needed for decoding of the DC coefficients of component Csj is retrieved.",
              HFILL
          }
        },
        { &hf_sos_ta_j,
          {   "AC entropy coding table destination selector",
              IMG_JFIF ".sos.ac_entropy_selector",
              FT_UINT8, BASE_DEC, NULL, 0x0F,
              "Specifies one of four possible AC entropy coding table destinations from which the entropy"
              " table needed for decoding of the AC coefficients of component Csj is retrieved.",
              HFILL
          }
        },
        { &hf_sos_ss,
          {   "Start of spectral or predictor selection",
              IMG_JFIF ".sos.ss",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "In the DCT modes of operation, this parameter specifies the first DCT coefficient in"
              " each block in zig-zag order which shall be coded in the scan. This parameter shall"
              " be set to zero for the sequential DCT processes. In the lossless mode of operations"
              " this parameter is used to select the predictor.",
              HFILL
          }
        },
        { &hf_sos_se,
          {   "End of spectral selection",
              IMG_JFIF ".sos.se",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Specifies the last DCT coefficient in each block in zig-zag order which shall be coded"
              " in the scan. This parameter shall be set to 63 for the sequential DCT processes. In the"
              " lossless mode of operations this parameter has no meaning. It shall be set to zero.",
              HFILL
          }
        },
        { &hf_sos_ah,
          {   "Successive approximation bit position high",
              IMG_JFIF ".sos.ah",
              FT_UINT8, BASE_DEC, NULL, 0xF0,
              "This parameter specifies the point transform used in the preceding scan (i.e. successive"
              " approximation bit position low in the preceding scan) for the band of coefficients"
              " specified by Ss and Se. This parameter shall be set to zero for the first scan of each"
              " band of coefficients. In the lossless mode of operations this parameter has no meaning."
              " It shall be set to zero.",
              HFILL
          }
        },
        { &hf_sos_al,
          {   "Successive approximation bit position low or point transform",
              IMG_JFIF ".sos.al",
              FT_UINT8, BASE_DEC, NULL, 0x0F,
              "In the DCT modes of operation this parameter specifies the point transform, i.e. bit"
              " position low, used before coding the band of coefficients specified by Ss and Se."
              " This parameter shall be set to zero for the sequential DCT processes. In the lossless"
              " mode of operations, this parameter specifies the point transform, Pt.",
              HFILL
          }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_jfif,
        &ett_marker_segment,
        &ett_details,
    };

    /* Register the protocol name and description */
    proto_jfif = proto_register_protocol(
        "JPEG File Interchange Format",
        "JFIF (JPEG) image",
        IMG_JFIF
        );

    /* Required function calls to register the header fields
     * and subtrees used */
    proto_register_field_array(proto_jfif, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector(IMG_JFIF, dissect_jfif, proto_jfif);
}


void
proto_reg_handoff_jfif(void)
{
    dissector_handle_t jfif_handle = find_dissector(IMG_JFIF);

    /* Register the JPEG media type */
    dissector_add_string("media_type", "image/jfif", jfif_handle);
    dissector_add_string("media_type", "image/jpg", jfif_handle);
    dissector_add_string("media_type", "image/jpeg", jfif_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_JPEG_JFIF, jfif_handle);

    heur_dissector_add("http", dissect_jfif_heur, proto_jfif);
    heur_dissector_add("wtap_file", dissect_jfif_heur, proto_jfif);
}
