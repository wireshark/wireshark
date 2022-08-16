/* file-tiff.c
 *
 * Routines for image/tiff dissection
 * Copyright 2021, Daniel Dulaney.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * The TIFF 6 specification can be found at:
 * https://www.adobe.io/content/dam/udp/en/open/standards/tiff/TIFF6.pdf
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

void proto_reg_handoff_tiff(void);
void proto_register_tiff(void);

static int proto_tiff = -1;

// Header fields
static int hf_tiff_header_endianness = -1;
static int hf_tiff_header_magic = -1;
static int hf_tiff_header_lead_ifd = -1;

// IFD fields
static int hf_tiff_ifd_count = -1;
static int hf_tiff_ifd_next = -1;

// Entry fields
static int hf_tiff_entry_tag = -1;
static int hf_tiff_entry_type = -1;
static int hf_tiff_entry_count = -1;
static int hf_tiff_entry_offset = -1;
static int hf_tiff_entry_unknown = -1;

// Expert fields
static expert_field ei_tiff_unknown_tag = EI_INIT;
static expert_field ei_tiff_bad_entry = EI_INIT;

static gint ett_tiff = -1;
static gint ett_ifd = -1;
static gint ett_t6 = -1;

#define TIFF_TAG_NEW_SUBFILE_TYPE 254
// Fields TBD

#define TIFF_TAG_SUBFILE_TYPE 255
// Fields TBD

#define TIFF_TAG_IMAGE_WIDTH 256
static int hf_tiff_image_width = -1;

#define TIFF_TAG_IMAGE_LENGTH 257
static int hf_tiff_image_length = -1;

#define TIFF_TAG_BITS_PER_SAMPLE 258
static int hf_tiff_bits_per_sample = -1;

#define TIFF_TAG_COMPRESSION 259
static int hf_tiff_compression = -1;

#define TIFF_TAG_PHOTOMETRIC_INTERPRETATION 262
static int hf_tiff_photometric_interp = -1;

#define TIFF_TAG_THRESHHOLDING 263
static int hf_tiff_threshholding = -1;

#define TIFF_TAG_CELL_WIDTH 264
static int hf_tiff_cell_width = -1;

#define TIFF_TAG_CELL_LENGTH 265
static int hf_tiff_cell_length = -1;

#define TIFF_TAG_FILL_ORDER 266
static int hf_tiff_fill_order = -1;

#define TIFF_TAG_DOCUMENT_NAME 269
static int hf_tiff_document_name = -1;

#define TIFF_TAG_IMAGE_DESCRIPTION 270
static int hf_tiff_image_description = -1;

#define TIFF_TAG_MAKE 271
static int hf_tiff_make = -1;

#define TIFF_TAG_MODEL 272
static int hf_tiff_model = -1;

#define TIFF_TAG_STRIP_OFFSETS 273
static int hf_tiff_strip_offset = -1;

#define TIFF_TAG_ORIENTATION 274
static int hf_tiff_orientation = -1;

#define TIFF_TAG_SAMPLES_PER_PIXEL 277
static int hf_tiff_samples_per_pixel = -1;

#define TIFF_TAG_ROWS_PER_STRIP 278
static int hf_tiff_rows_per_strip = -1;

#define TIFF_TAG_STRIP_BYTE_COUNTS 279
static int hf_tiff_strip_byte_count = -1;

#define TIFF_TAG_MIN_SAMPLE_VALUE 280
// Fields TBD

#define TIFF_TAG_MAX_SAMPLE_VALUE 281
// Fields TBD

#define TIFF_TAG_X_RESOLUTION 282
static int hf_tiff_x_res_numer = -1;
static int hf_tiff_x_res_denom = -1;
static int hf_tiff_x_res_approx = -1;

#define TIFF_TAG_Y_RESOLUTION 283
static int hf_tiff_y_res_numer = -1;
static int hf_tiff_y_res_denom = -1;
static int hf_tiff_y_res_approx = -1;

#define TIFF_TAG_PLANAR_CONFIGURATION 284
static int hf_tiff_planar_configuration = -1;

#define TIFF_TAG_PAGE_NAME 285
static int hf_tiff_page_name = -1;

#define TIFF_TAG_X_POSITION 286
// Fields TBD

#define TIFF_TAG_Y_POSITION 287
// Fields TBD

#define TIFF_TAG_FREE_OFFSETS 288
// Fields TBD

#define TIFF_TAG_FREE_BYTE_COUNTS 289
// Fields TBD

#define TIFF_TAG_GRAY_RESPONSE_UNIT 290
static int hf_tiff_gray_response_unit = -1;

#define TIFF_TAG_GRAY_RESPONSE_CURVE 291
// Fields TBD

#define TIFF_TAG_T4_OPTIONS 292
// Fields TBD

#define TIFF_TAG_T6_OPTIONS 293
static int hf_tiff_t6_options = -1;
static int hf_tiff_t6_unused = -1;
static int hf_tiff_t6_allow_uncompresed = -1;

#define TIFF_TAG_RESOLUTION_UNIT 296
static int hf_tiff_resolution_unit = -1;

#define TIFF_TAG_PAGE_NUMBER 297
// Fields TBD

#define TIFF_TAG_TRANSFER_FUNCTION 301
// Fields TBD

#define TIFF_TAG_SOFTWARE 305
static int hf_tiff_software = -1;

#define TIFF_TAG_DATE_TIME 306
static int hf_tiff_date_time = -1;

#define TIFF_TAG_ARTIST 315
static int hf_tiff_artist = -1;

#define TIFF_TAG_HOST_COMPUTER 316
static int hf_tiff_host_computer = -1;

#define TIFF_TAG_PREDICTOR 317
static int hf_tiff_predictor = -1;

#define TIFF_TAG_WHITE_POINT 318
// Fields TBD

#define TIFF_TAG_PRIMARY_CHROMATICITIES 319
// Fields TBD

#define TIFF_TAG_COLOR_MAP 320
// Fields TBD

#define TIFF_TAG_HALFTONE_HINTS 321
// Fields TBD

#define TIFF_TAG_TILE_WIDTH 322
static int hf_tiff_tile_width = -1;

#define TIFF_TAG_TILE_LENGTH 323
static int hf_tiff_tile_length = -1;

#define TIFF_TAG_TILE_OFFSETS 324
// Fields TBD

#define TIFF_TAG_TILE_BYTE_COUNTS 325
// Fields TBD

#define TIFF_TAG_INK_SET 332
static int hf_tiff_ink_set = -1;

#define TIFF_TAG_INK_NAMES 333
// Fields TBD

#define TIFF_TAG_NUMBER_OF_INKS 334
static int hf_tiff_number_of_inks = -1;

#define TIFF_TAG_DOT_RANGE 336
// Fields TBD

#define TIFF_TAG_TARGET_PRINTER 337
static int hf_tiff_target_printer = -1;

#define TIFF_TAG_EXTRA_SAMPLES 338
// Fields TBD

#define TIFF_TAG_SAMPLE_FORMAT 339
// Fields TBD

#define TIFF_TAG_S_MIN_SAMPLE_VALUE 340
// Fields TBD

#define TIFF_TAG_S_MAX_SAMPLE_VALUE 341
// Fields TBD

#define TIFF_TAG_TRANSFER_RANGE 342
// Fields TBD

#define TIFF_TAG_JPEG_PROC 512
// Fields TBD

#define TIFF_TAG_JPEG_INTERCHANGE_FORMAT 513
// Fields TBD

#define TIFF_TAG_JPEG_INTERCHANGE_FORMAT_LENGTH 514
// Fields TBD

#define TIFF_TAG_JPEG_RESTART_INTERVAL 515
// Fields TBD

#define TIFF_TAG_JPEG_LOSSLESS_PREDICTORS 517
// Fields TBD

#define TIFF_TAG_JPEG_POINT_TRANSFORMS 518
// Fields TBD

#define TIFF_TAG_JPEG_Q_TABLES 519
// Fields TBD

#define TIFF_TAG_JPEG_DC_TABLES 520
// Fields TBD

#define TIFF_TAG_JPEG_AC_TABLES 521
// Fields TBD

#define TIFF_TAG_YCBCR_COEFFICIENTS 529
// Fields TBD

#define TIFF_TAG_YCBCR_SUBSAMPLING 530
// Fields TBD

#define TIFF_TAG_YCBCR_POSITIONING 531
// Fields TBD

#define TIFF_TAG_REFERENCE_BLACK_WHITE 532
// Fields TBD

#define TIFF_TAG_COPYRIGHT 0x8298
static int hf_tiff_copyright = -1;

static const value_string tiff_endianness_names[] = {
    { 0x4949, "Little-Endian" },
    { 0x4D4D, "Big-Endian" },
    { 0, NULL },
};

static const value_string tiff_tag_names[] = {
    { TIFF_TAG_NEW_SUBFILE_TYPE, "New Subfile Type" },
    { TIFF_TAG_SUBFILE_TYPE, "Subfile Type" },
    { TIFF_TAG_IMAGE_WIDTH, "Image Width" },
    { TIFF_TAG_IMAGE_LENGTH, "Image Length" },
    { TIFF_TAG_BITS_PER_SAMPLE, "Bits Per Sample" },
    { TIFF_TAG_COMPRESSION, "Compression" },
    { TIFF_TAG_PHOTOMETRIC_INTERPRETATION, "Photometric Interpretation" },
    { TIFF_TAG_THRESHHOLDING, "Threshholding" },
    { TIFF_TAG_CELL_WIDTH, "Cell Width" },
    { TIFF_TAG_CELL_LENGTH, "Cell Length" },
    { TIFF_TAG_FILL_ORDER, "Fill Order" },
    { TIFF_TAG_DOCUMENT_NAME, "Document Name" },
    { TIFF_TAG_IMAGE_DESCRIPTION, "Image Description" },
    { TIFF_TAG_MAKE, "Make" },
    { TIFF_TAG_MODEL, "Model" },
    { TIFF_TAG_STRIP_OFFSETS, "Strip Offsets" },
    { TIFF_TAG_ORIENTATION, "Orientation" },
    { TIFF_TAG_SAMPLES_PER_PIXEL, "Samples Per Pixel" },
    { TIFF_TAG_ROWS_PER_STRIP, "Rows Per Strip" },
    { TIFF_TAG_STRIP_BYTE_COUNTS, "Strip Byte Counts" },
    { TIFF_TAG_MIN_SAMPLE_VALUE, "Min Sample Value" },
    { TIFF_TAG_MAX_SAMPLE_VALUE, "Max Sample Value" },
    { TIFF_TAG_X_RESOLUTION, "X Resolution" },
    { TIFF_TAG_Y_RESOLUTION, "Y Resolution" },
    { TIFF_TAG_PLANAR_CONFIGURATION, "Planar Configuration" },
    { TIFF_TAG_PAGE_NAME, "Page Name" },
    { TIFF_TAG_X_POSITION, "X Position" },
    { TIFF_TAG_Y_POSITION, "Y Position" },
    { TIFF_TAG_FREE_OFFSETS, "Free Offsets" },
    { TIFF_TAG_FREE_BYTE_COUNTS, "Free Byte Counts" },
    { TIFF_TAG_GRAY_RESPONSE_UNIT, "Gray Response Unit" },
    { TIFF_TAG_GRAY_RESPONSE_CURVE, "Gray Response Curve" },
    { TIFF_TAG_T4_OPTIONS, "T4 Options" },
    { TIFF_TAG_T6_OPTIONS, "T6 Options" },
    { TIFF_TAG_RESOLUTION_UNIT, "Resolution Unit" },
    { TIFF_TAG_PAGE_NUMBER, "Page Number" },
    { TIFF_TAG_TRANSFER_FUNCTION, "Transfer Function" },
    { TIFF_TAG_SOFTWARE, "Software" },
    { TIFF_TAG_DATE_TIME, "Date Time" },
    { TIFF_TAG_ARTIST, "Artist" },
    { TIFF_TAG_HOST_COMPUTER, "Host Computer" },
    { TIFF_TAG_PREDICTOR, "Predictor" },
    { TIFF_TAG_WHITE_POINT, "White Point" },
    { TIFF_TAG_PRIMARY_CHROMATICITIES, "Primary Chromaticities" },
    { TIFF_TAG_COLOR_MAP, "Color Map" },
    { TIFF_TAG_HALFTONE_HINTS, "Halftone Hints" },
    { TIFF_TAG_TILE_WIDTH, "Tile Width" },
    { TIFF_TAG_TILE_LENGTH, "Tile Length" },
    { TIFF_TAG_TILE_OFFSETS, "Tile Offsets" },
    { TIFF_TAG_TILE_BYTE_COUNTS, "Tile Byte Counts" },
    { TIFF_TAG_INK_SET, "Ink Set" },
    { TIFF_TAG_INK_NAMES, "Ink Names" },
    { TIFF_TAG_NUMBER_OF_INKS, "Number Of Inks" },
    { TIFF_TAG_DOT_RANGE, "Dot Range" },
    { TIFF_TAG_TARGET_PRINTER, "Target Printer" },
    { TIFF_TAG_EXTRA_SAMPLES, "Extra Samples" },
    { TIFF_TAG_SAMPLE_FORMAT, "Sample Format" },
    { TIFF_TAG_S_MIN_SAMPLE_VALUE, "S Min Sample Value" },
    { TIFF_TAG_S_MAX_SAMPLE_VALUE, "S Max Sample Value" },
    { TIFF_TAG_TRANSFER_RANGE, "Transfer Range" },
    { TIFF_TAG_JPEG_PROC, "JPEG Proc" },
    { TIFF_TAG_JPEG_INTERCHANGE_FORMAT, "JPEG Interchange Format" },
    { TIFF_TAG_JPEG_INTERCHANGE_FORMAT_LENGTH, "JPEG Interchange Format Length" },
    { TIFF_TAG_JPEG_RESTART_INTERVAL, "JPEG Restart Interval" },
    { TIFF_TAG_JPEG_LOSSLESS_PREDICTORS, "JPEG Lossless Predictors" },
    { TIFF_TAG_JPEG_POINT_TRANSFORMS, "JPEG Point Transforms" },
    { TIFF_TAG_JPEG_Q_TABLES, "JPEG Q Tables" },
    { TIFF_TAG_JPEG_DC_TABLES, "JPEG DC Tables" },
    { TIFF_TAG_JPEG_AC_TABLES, "JPEG AC Tables" },
    { TIFF_TAG_YCBCR_COEFFICIENTS, "YCbCr Coefficients" },
    { TIFF_TAG_YCBCR_SUBSAMPLING, "YCbCr Subsampling" },
    { TIFF_TAG_YCBCR_POSITIONING, "YCbCr Positioning" },
    { TIFF_TAG_REFERENCE_BLACK_WHITE, "Reference Black White" },
    { TIFF_TAG_COPYRIGHT, "Copyright" },
    { 0, NULL },
};

#define TIFF_TYPE_BYTE 1
#define TIFF_TYPE_ASCII 2
#define TIFF_TYPE_SHORT 3
#define TIFF_TYPE_LONG 4
#define TIFF_TYPE_RATIONAL 5
#define TIFF_TYPE_SBYTE 6
#define TIFF_TYPE_UNDEFINED 7
#define TIFF_TYPE_SSHORT 8
#define TIFF_TYPE_SLONG 9
#define TIFF_TYPE_SRATIONAL 10
#define TIFF_TYPE_FLOAT 11
#define TIFF_TYPE_DOUBLE 12

static const value_string tiff_type_names[] = {
    { TIFF_TYPE_BYTE, "Byte" },
    { TIFF_TYPE_ASCII, "ASCII" },
    { TIFF_TYPE_SHORT, "Unsigned Short" },
    { TIFF_TYPE_LONG, "Unsigned Long" },
    { TIFF_TYPE_RATIONAL, "Rational" },
    { TIFF_TYPE_SBYTE, "Signed Byte" },
    { TIFF_TYPE_UNDEFINED, "Undefined" },
    { TIFF_TYPE_SSHORT, "Signed Short" },
    { TIFF_TYPE_SLONG, "Signed Long" },
    { TIFF_TYPE_SRATIONAL, "Signed Rational" },
    { TIFF_TYPE_FLOAT, "Float" },
    { TIFF_TYPE_DOUBLE, "Double" },
    { 0, NULL },
};

static const value_string tiff_compression_names[] = {
    { 1, "Uncompressed" },
    { 2, "CITT 1D" },
    { 3, "Group 3 Fax" },
    { 4, "Group 4 Fax" },
    { 5, "LZW" },
    { 6, "JPEG" },
    { 32773, "PackBits" },
    { 0, NULL },
};

static const value_string tiff_photometric_interp_names[] = {
    { 0, "White is Zero" },
    { 1, "Black is Zero" },
    { 2, "RGB" },
    { 3, "RGB Palette" },
    { 4, "Transparency Mask" },
    { 5, "CMYK" },
    { 6, "YCbCr" },
    { 8, "CIELab" },
    { 0, NULL },
};

static const value_string tiff_threshholding_names[] = {
    { 0, "None" },
    { 1, "Ordered" },
    { 2, "Randomized" },
    { 0, NULL },
};

static const value_string tiff_fill_order_names[] = {
    { 1, "High-order first" },
    { 2, "Low-order first" },
    { 0, NULL },
};

static const value_string tiff_orientation_names[] = {
    { 1, "Origin at Top-Left, Horizontal Rows" },
    { 2, "Origin at Top-Right, Horizontal Rows" },
    { 3, "Origin at Bottom-Right, Horizontal Rows" },
    { 4, "Origin at Bottom-Left, Horizontal Rows" },
    { 5, "Origin at Top-Left, Vertical Rows" },
    { 6, "Origin at Top-Right, Vertical Rows" },
    { 7, "Origin at Bottom-Right, Vertical Rows" },
    { 8, "Origin at Bottom-Left, Vertical Rows" },
    { 0, NULL },
};

static const value_string tiff_planar_configuration_names[] = {
    { 1, "Chunky" },
    { 2, "Planar" },
    { 0, NULL },
};

static const value_string tiff_gray_response_unit_names[] = {
    { 1, "Tenths" },
    { 2, "Hundredths" },
    { 3, "Thousandths" },
    { 4, "Ten-thousandths" },
    { 5, "Hundred-thousandths" },
    { 0, NULL },
};

static const value_string tiff_allow_uncompressed_names[] = {
    { 0, "Not Allowed" },
    { 1, "Allowed" },
    { 0, NULL },
};

static const value_string tiff_resolution_unit_names[] = {
    { 1, "None" },
    { 2, "Inch" },
    { 3, "Centimeter" },
    { 0, NULL },
};

static const value_string tiff_predictor_names[] = {
    { 1, "No Predictor" },
    { 2, "Horizontal Differencing" },
    { 0, NULL },
};

static const value_string tiff_ink_set_names[] = {
    { 1, "CMYK" },
    { 2, "Not CMYK" },
    { 0, NULL },
};

// Return the length of the given data type.
//
// If the type isn't known, return -1.
static gint
tiff_type_len(const guint16 type) {
    switch (type) {
    case TIFF_TYPE_BYTE: return 1;
    case TIFF_TYPE_ASCII: return 1;
    case TIFF_TYPE_SHORT: return 2;
    case TIFF_TYPE_LONG: return 4;
    case TIFF_TYPE_RATIONAL: return 8;
    case TIFF_TYPE_SBYTE: return 1;
    case TIFF_TYPE_UNDEFINED: return 1;
    case TIFF_TYPE_SSHORT: return 2;
    case TIFF_TYPE_SLONG: return 4;
    case TIFF_TYPE_SRATIONAL: return 8;
    case TIFF_TYPE_FLOAT: return 4;
    case TIFF_TYPE_DOUBLE: return 8;

    default: return -1;
    }
}

// Return the length of the given array of data.
//
// If the type isn't known, return -1.
static gint
tiff_data_len(const guint16 type, const guint32 count) {
    const gint field = tiff_type_len(type);
    if (field < 0) return -1;
    else return field * count;
}

static void
dissect_tiff_tag_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint16 type, guint32 count, gint encoding _U_)
{
    const gint len = tiff_data_len(type, count);

    expert_add_info(pinfo, tree, &ei_tiff_unknown_tag);

    guint32 item_offset;
    if (len <= 0) {
        // If we can't determine the length, that's an issue
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Could not determine length of entry");
        return;
    } else if (len <= 4) {
        // If the length is <= 4, the item is located directly at the offset
        item_offset = offset;
    } else {
        // If the length is >4, the offset is a pointer indicating where the item is located
        proto_tree_add_item_ret_uint(tree, hf_tiff_entry_offset, tvb, offset, 4, encoding, &item_offset);
    }

    proto_tree_add_item(tree, hf_tiff_entry_unknown, tvb, item_offset, len, encoding);
}

static void
dissect_tiff_single_uint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint16 type, guint32 count, gint encoding, int hfindex) {
    if (count != 1) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected a single item; found %d items", count);
        return;
    }

    if (type == TIFF_TYPE_BYTE) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 1, encoding);
    } else if (type == TIFF_TYPE_SHORT) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 2, encoding);
    } else if (type == TIFF_TYPE_LONG) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 4, encoding);
    } else {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected an unsigned integer, found type %s", val_to_str_const(type, tiff_type_names, "Unknown"));
    }
}

static void
dissect_tiff_array_uint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint16 type, guint32 count, gint encoding, int hfindex) {
    if (!(type == TIFF_TYPE_BYTE || type == TIFF_TYPE_SHORT || type == TIFF_TYPE_LONG)) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected an unsigned integer, found type %s", val_to_str_const(type, tiff_type_names, "Unknown"));
        return;
    }

    if (count < 1) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "At least 1 item; found %d items", count);
        return;
    }

    const gint item_len = tiff_type_len(type);
    const gint len = tiff_data_len(type, count);

    guint32 item_offset;
    if (len <= 0 || item_len <= 0) {
        // If we can't determine the length, that's an issue
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Could not determine length of entry");
        return;
    } else if (len <= 4) {
        // If the length is <= 4, the item is located directly at the offset
        item_offset = offset;
    } else {
        // If the length is >4, the offset is a pointer indicating where the item is located
        proto_tree_add_item_ret_uint(tree, hf_tiff_entry_offset, tvb, offset, 4, encoding, &item_offset);
    }

    // Add each item
    for (guint32 i = 0; i < count; i++) {
        proto_tree_add_item(tree, hfindex, tvb, item_offset + item_len * i, item_len, encoding);
    }
}

static void
dissect_tiff_single_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint16 type, guint32 count, gint encoding, int hfindex) {
    if (type != TIFF_TYPE_ASCII) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected an ASCII string");
        return;
    }

    guint32 item_offset;
    if (count == 0) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected at least one byte for an ASCII string; got zero");
        return;
    } else if (count <= 4) {
        // If there are 4 or fewer bytes, the string is embedded in the pointer
        item_offset = offset;
    } else {
        // If the length is >4, the offset is a pointer indicating where the item is located
        proto_tree_add_item_ret_uint(tree, hf_tiff_entry_offset, tvb, offset, 4, encoding, &item_offset);
    }

    proto_tree_add_item(tree, hfindex, tvb, item_offset, count, ENC_ASCII);
}

static void
dissect_tiff_single_urational(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint16 type, guint32 count, gint encoding, int hfnumer, int hfdenom, int hfapprox) {
    if (count != 1) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected a single item; found %d items", count);
        return;
    }

    if (type != TIFF_TYPE_RATIONAL) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected an unsigned rational");
        return;
    }

    guint32 item_offset;
    proto_tree_add_item_ret_uint(tree, hf_tiff_entry_offset, tvb, offset, 4, encoding, &item_offset);

    guint32 numer = 0;
    guint32 denom = 0;
    proto_tree_add_item_ret_uint(tree, hfnumer, tvb, item_offset, 4, encoding, &numer);
    proto_tree_add_item_ret_uint(tree, hfdenom, tvb, item_offset + 4, 4, encoding, &denom);

    proto_item *approx_item = proto_tree_add_double(tree, hfapprox, tvb, item_offset, 8, (double)numer / (double)denom);
    proto_item_set_generated(approx_item);
}

static void
dissect_tiff_t6_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint16 type, guint32 count, gint encoding) {
    if (count != 1) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected a single item; found %d items", count);
        return;
    }

    if (type != TIFF_TYPE_LONG) {
        expert_add_info_format(pinfo, tree, &ei_tiff_bad_entry, "Expected an unsigned long");
        return;
    }

    proto_item *t6_ti = proto_tree_add_item(tree, hf_tiff_t6_options, tvb, offset, 4, encoding);
    proto_tree *t6_tree = proto_item_add_subtree(t6_ti, ett_t6);
    proto_tree_add_item(t6_tree, hf_tiff_t6_unused, tvb, offset, 4, encoding);
    proto_tree_add_item(t6_tree, hf_tiff_t6_allow_uncompresed, tvb, offset, 4, encoding);
}

static void
dissect_tiff_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gint encoding) {
    const guint16 tag = tvb_get_guint16(tvb, offset, encoding);

    proto_tree *entry_tree = proto_tree_add_subtree_format(tree, tvb, offset, 12, ett_ifd, NULL, "%s", val_to_str_const(tag, tiff_tag_names, "Unknown Entry"));

    proto_tree_add_item(entry_tree, hf_tiff_entry_tag, tvb, offset, 2, encoding);

    guint32 type = 0;
    guint32 count = 0;
    proto_tree_add_item_ret_uint(entry_tree, hf_tiff_entry_type, tvb, offset + 2, 2, encoding, &type);
    proto_tree_add_item_ret_uint(entry_tree, hf_tiff_entry_count, tvb, offset + 4, 4, encoding, &count);

    switch (tag) {
    case TIFF_TAG_IMAGE_WIDTH:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_image_width);
        break;
    case TIFF_TAG_IMAGE_LENGTH:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_image_length);
        break;
    case TIFF_TAG_BITS_PER_SAMPLE:
        dissect_tiff_array_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_bits_per_sample);
        break;
    case TIFF_TAG_COMPRESSION:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_compression);
        break;
    case TIFF_TAG_PHOTOMETRIC_INTERPRETATION:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_photometric_interp);
        break;
    case TIFF_TAG_THRESHHOLDING:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_threshholding);
        break;
    case TIFF_TAG_CELL_WIDTH:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_cell_width);
        break;
    case TIFF_TAG_CELL_LENGTH:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_cell_length);
        break;
    case TIFF_TAG_FILL_ORDER:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_fill_order);
        break;
    case TIFF_TAG_DOCUMENT_NAME:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_document_name);
        break;
    case TIFF_TAG_IMAGE_DESCRIPTION:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_image_description);
        break;
    case TIFF_TAG_MAKE:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_make);
        break;
    case TIFF_TAG_MODEL:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_model);
        break;
    case TIFF_TAG_STRIP_OFFSETS:
        dissect_tiff_array_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_strip_offset);
        break;
    case TIFF_TAG_ORIENTATION:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_orientation);
        break;
    case TIFF_TAG_SAMPLES_PER_PIXEL:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_samples_per_pixel);
        break;
    case TIFF_TAG_ROWS_PER_STRIP:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_rows_per_strip);
        break;
    case TIFF_TAG_STRIP_BYTE_COUNTS:
        dissect_tiff_array_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_strip_byte_count);
        break;
    case TIFF_TAG_X_RESOLUTION:
        dissect_tiff_single_urational(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_x_res_numer, hf_tiff_x_res_denom, hf_tiff_x_res_approx);
        break;
    case TIFF_TAG_Y_RESOLUTION:
        dissect_tiff_single_urational(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_y_res_numer, hf_tiff_y_res_denom, hf_tiff_y_res_approx);
        break;
    case TIFF_TAG_PLANAR_CONFIGURATION:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_planar_configuration);
        break;
    case TIFF_TAG_PAGE_NAME:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_page_name);
        break;
    case TIFF_TAG_GRAY_RESPONSE_UNIT:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_gray_response_unit);
        break;
    case TIFF_TAG_T6_OPTIONS:
        dissect_tiff_t6_options(tvb, pinfo, entry_tree, offset + 8, type, count, encoding);
        break;
    case TIFF_TAG_RESOLUTION_UNIT:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_resolution_unit);
        break;
    case TIFF_TAG_SOFTWARE:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_software);
        break;
    case TIFF_TAG_DATE_TIME:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_date_time);
        break;
    case TIFF_TAG_ARTIST:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_artist);
        break;
    case TIFF_TAG_HOST_COMPUTER:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_host_computer);
        break;
    case TIFF_TAG_PREDICTOR:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_predictor);
        break;
    case TIFF_TAG_TILE_WIDTH:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_tile_width);
        break;
    case TIFF_TAG_TILE_LENGTH:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_tile_length);
        break;
    case TIFF_TAG_INK_SET:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_ink_set);
        break;
    case TIFF_TAG_NUMBER_OF_INKS:
        dissect_tiff_single_uint(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_number_of_inks);
        break;
    case TIFF_TAG_TARGET_PRINTER:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_target_printer);
        break;
    case TIFF_TAG_COPYRIGHT:
        dissect_tiff_single_string(tvb, pinfo, entry_tree, offset + 8, type, count, encoding, hf_tiff_copyright);
        break;
    default:
        dissect_tiff_tag_unknown(tvb, pinfo, entry_tree, offset + 8, type, count, encoding);
    }
}

// Dissect an IFD with all of its fields, starting at the given offset
//
// Return the offset of the next IFD, or 0 if there isn't one
static guint32
dissect_tiff_ifd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, gint encoding) {
    guint16 ifd_count = tvb_get_guint16(tvb, offset, encoding);
    gint ifd_length = 2 + (ifd_count * 12) + 4;

    proto_tree *ifd_tree = proto_tree_add_subtree(tree, tvb, offset, ifd_length, ett_ifd, NULL, "Image File Directory");

    proto_tree_add_item(ifd_tree, hf_tiff_ifd_count, tvb, offset, 2, encoding);
    offset += 2;

    for (gint i = 0; i < ifd_count; i++) {
        dissect_tiff_entry(tvb, pinfo, ifd_tree, offset, encoding);
        offset += 12;
    }

    proto_tree_add_item(ifd_tree, hf_tiff_ifd_next, tvb, offset, 4, encoding);
    guint32 ifd_next = tvb_get_guint32(tvb, offset, encoding);

    return ifd_next;
}

static int
dissect_tiff(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int encoding;

    // Reject if we don't have enough room for the heuristics
    if (tvb_captured_length(tvb) < 4) {
        return 0;
    }

    // Figure out if we're big-endian or little endian
    guint16 raw_encoding = tvb_get_ntohs(tvb, 0);
    guint16 magic;
    guint32 ifd_offset;
    if (raw_encoding == 0x4949) {
        encoding = ENC_LITTLE_ENDIAN;
    } else if (raw_encoding == 0x4D4D) {
        encoding = ENC_BIG_ENDIAN;
    } else {
        // If we don't recognize the endianness, abort with nothing decoded
        return 0;
    }

    magic = tvb_get_guint16(tvb, 2, encoding);

    // If the magic number isn't 42, abort with nothing decoded
    if (magic != 42) {
        return 0;
    }

    proto_item *ti = proto_tree_add_item(tree, proto_tiff, tvb, 0, -1, ENC_NA);
    proto_tree *tiff_tree = proto_item_add_subtree(ti, ett_tiff);

    // Dissect the rest of the header
    proto_tree_add_item(tiff_tree, hf_tiff_header_endianness, tvb, 0, 2, encoding);
    proto_tree_add_item(tiff_tree, hf_tiff_header_magic, tvb, 2, 2, encoding);
    proto_tree_add_item_ret_uint(tiff_tree, hf_tiff_header_lead_ifd, tvb, 4, 4, encoding, &ifd_offset);

    // Keep dissecting IFDs until the offset to the next one is zero
    while (ifd_offset != 0) {
        ifd_offset = dissect_tiff_ifd(tvb, pinfo, tiff_tree, ifd_offset, encoding);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_tiff(void)
{
    static hf_register_info hf[] = {
        { &hf_tiff_header_endianness,
            { "Endianness", "tiff.endianness",
            FT_UINT16, BASE_HEX, VALS(tiff_endianness_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_header_magic,
            { "Magic", "tiff.magic",
            FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_header_lead_ifd,
            { "Lead IFD Offset", "tiff.lead_ifd",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_ifd_count,
            { "Number of Entries", "tiff.ifd_count",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_ifd_next,
            { "Next IFD Offset", "tiff.next_ifd",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_entry_tag,
            { "Tag", "tiff.tag",
            FT_UINT16, BASE_DEC, VALS(tiff_tag_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_entry_type,
            { "Type", "tiff.type",
            FT_UINT16, BASE_DEC, VALS(tiff_type_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_entry_count,
            { "Count", "tiff.count",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_entry_offset,
            { "Offset", "tiff.offset",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_entry_unknown,
            { "Unknown Data", "tiff.unknown",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_image_width,
            { "Image Width", "tiff.image_width",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_image_length,
            { "Image Length", "tiff.image_length",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_bits_per_sample,
            { "Bits per Sample", "tiff.bits_per_sample",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_compression,
            { "Compression", "tiff.compression",
            FT_UINT16, BASE_DEC, VALS(tiff_compression_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_photometric_interp,
            { "Photometric Interpretation", "tiff.photometric_interp",
            FT_UINT16, BASE_DEC, VALS(tiff_photometric_interp_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_threshholding,
            { "Threshholding", "tiff.threshholding",
            FT_UINT16, BASE_DEC, VALS(tiff_threshholding_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_cell_width,
            { "Cell Width", "tiff.cell_width",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_cell_length,
            { "Cell Length", "tiff.cell_length",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_fill_order,
            { "Fill Order", "tiff.fill_order",
            FT_UINT16, BASE_DEC, VALS(tiff_fill_order_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_document_name,
            { "Document Name", "tiff.document_name",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_image_description,
            { "Image Description", "tiff.image_description",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_make,
            { "Make", "tiff.make",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_model,
            { "Model", "tiff.model",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_strip_offset,
            { "Strip Offset", "tiff.strip_offset",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_orientation,
            { "Orientation", "tiff.orientation",
            FT_UINT16, BASE_DEC, VALS(tiff_orientation_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_samples_per_pixel,
            { "Samples per Pixel", "tiff.samples_per_pixel",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_rows_per_strip,
            { "Rows per Strip", "tiff.rows_per_strip",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_strip_byte_count,
            { "Strip Byte Count", "tiff.strip_byte_count",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_x_res_numer,
            { "X Resolution Numerator", "tiff.x_res_numer",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_x_res_denom,
            { "X Resolution Denominator", "tiff.x_res_denom",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_x_res_approx,
            { "X Resolution Approximation", "tiff.x_res_approx",
            FT_DOUBLE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_y_res_numer,
            { "Y Resolution Numerator", "tiff.y_res_numer",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_y_res_denom,
            { "Y Resolution Denominator", "tiff.y_res_denom",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_y_res_approx,
            { "Y Resolution Approximation", "tiff.y_res_approx",
            FT_DOUBLE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_planar_configuration,
            { "Planar Configuration", "tiff.planar_configuration",
            FT_UINT16, BASE_DEC, VALS(tiff_planar_configuration_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_page_name,
            { "Page Name", "tiff.page_name",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_gray_response_unit,
            { "Gray Response Unit", "tiff.gray_response_unit",
            FT_UINT16, BASE_DEC, VALS(tiff_gray_response_unit_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_t6_options,
            { "T6 Options", "tiff.t6",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_t6_unused,
            { "Unused", "tiff.t6.unused",
            FT_UINT32, BASE_HEX, NULL,
            0xFFFFFFFD, NULL, HFILL }
        },
        { &hf_tiff_t6_allow_uncompresed,
            { "Allow Uncompressed", "tiff.t6.allow_uncompressed",
            FT_UINT32, BASE_HEX, VALS(tiff_allow_uncompressed_names),
            0x00000002, NULL, HFILL }
        },
        { &hf_tiff_resolution_unit,
            { "Resolution Unit", "tiff.resolution_unit",
            FT_UINT16, BASE_DEC, VALS(tiff_resolution_unit_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_software,
            { "Software", "tiff.software",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_date_time,
            { "Date/Time", "tiff.date_time",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_artist,
            { "Artist", "tiff.artist",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_host_computer,
            { "Host Computer", "tiff.host_computer",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_predictor,
            { "Predictor", "tiff.predictor",
            FT_UINT16, BASE_DEC, VALS(tiff_predictor_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_tile_width,
            { "Tile Width", "tiff.tile_width",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_tile_length,
            { "Tile Width", "tiff.tile_length",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_ink_set,
            { "Ink Set", "tiff.ink_set",
            FT_UINT16, BASE_DEC, VALS(tiff_ink_set_names),
            0x0, NULL, HFILL }
        },
        { &hf_tiff_number_of_inks,
            { "Number of Inks", "tiff.number_of_inks",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_target_printer,
            { "Target Printer", "tiff.target_printer",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_tiff_copyright,
            { "Copyright", "tiff.copyright",
            FT_STRINGZ, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_tiff,
        &ett_ifd,
        &ett_t6,
    };

    static ei_register_info ei[] = {
        { &ei_tiff_unknown_tag,
            { "tiff.unknown_tag", PI_UNDECODED, PI_NOTE,
            "Unknown tag", EXPFILL }
        },
        { &ei_tiff_bad_entry,
            { "tiff.bad_entry", PI_PROTOCOL, PI_WARN,
            "Invalid entry contents", EXPFILL }
        },
    };

    proto_tiff = proto_register_protocol(
        "Tagged Image File Format",
        "TIFF image",
        "tiff"
        );

    register_dissector("tiff", dissect_tiff, proto_tiff);
    proto_register_field_array(proto_tiff, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_tiff = expert_register_protocol(proto_tiff);
    expert_register_field_array(expert_tiff, ei, array_length(ei));
}

static gboolean
dissect_tiff_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_tiff(tvb, pinfo, tree, NULL) > 0;
}

void
proto_reg_handoff_tiff(void)
{
    dissector_handle_t tiff_handle = find_dissector("tiff");

    // Register the TIFF media type
    dissector_add_string("media_type", "image/tiff", tiff_handle);

    // Register the TIFF heuristic dissector
    heur_dissector_add("wtap_file", dissect_tiff_heur, "TIFF file", "tiff_wtap", proto_tiff, HEURISTIC_ENABLE);
}
