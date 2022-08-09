/* file-jpeg.c
 *
 * Routines for JFIF image/jpeg media dissection
 * Copyright 2004, Olivier Biot.
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
 * https://www.w3.org/Graphics/JPEG/jfif3.pdf
 * https://www.w3.org/Graphics/JPEG/itu-t81.pdf
 *
 * The Exif specifications are found at several locations, such as:
 * http://www.exif.org/
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>

#include <inttypes.h>

void proto_register_jfif(void);
void proto_reg_handoff_jfif(void);

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

enum {
    EXIF_TAG_EXIF_IFD_POINTER = 0x8769,
    EXIF_TAG_GPS_IFD_POINTER = 0x8825,
    EXIF_TAG_INTEROP_IFD_POINTER = 0xA005,
};

static const value_string vals_ifd_tags[] = {
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
    { 0x8298, "Copyright" },
    /*
     * Exif-specific IFD:
     */
    { EXIF_TAG_EXIF_IFD_POINTER, "Exif IFD Pointer"},
    { EXIF_TAG_GPS_IFD_POINTER, "GPS IFD Pointer"},
    { EXIF_TAG_INTEROP_IFD_POINTER, "Interoperability IFD Pointer"},

    { 0x0000, NULL }
};

static const value_string vals_ifd_tags_exif[] = {
    /*
     * Tags relating to version:
     */
    { 0x9000, "ExifVersion" },
    { 0xA000, "FlashpixVersion" },
    /*
     * Tags relating to image data characteristics:
     */
    { 0xA001, "ColorSpace" },
    { 0xA500, "Gamma" },
    /*
     * Tags relating to image configuration:
     */
    { 0x9101, "ComponentsConfiguration" },
    { 0x9102, "CompressedBitsPerPixel" },
    { 0xA002, "PixelXDimension" },
    { 0xA003, "PixelYDimension" },
    /*
     * Tags relating to user information:
     */
    { 0x927C, "MakerNote" },
    { 0x9286, "UserComment" },
    /*
     * Tags relating to related file information:
     */
    { 0xA004, "RelatedSoundFile" },
    /*
     * Tags relating to date and time:
     */
    { 0x9003, "DateTimeOriginal" },
    { 0x9004, "DateTimeDigitized" },
    { 0x9010, "OffsetTime" },
    { 0x9011, "OffsetTimeOriginal" },
    { 0x9012, "OffsetTimeDigitized" },
    { 0x9290, "SubSecTime" },
    { 0x9291, "SubSecTimeOriginal" },
    { 0x9292, "SubSecTimeDigitized" },
    /*
     * Tags relating to picture-taking conditions:
     */
    { 0x829A, "ExposureTime" },
    { 0x829D, "FNumber" },
    { 0x8822, "ExposureProgram" },
    { 0x8824, "SpectralSensitivity" },
    { 0x8827, "PhotographicSensitivity" },
    { 0x8828, "OECF" },
    { 0x8830, "SensitivityType" },
    { 0x8831, "StandardOutputSensitivity" },
    { 0x8832, "RecommendedExposureIndex" },
    { 0x8833, "ISOSpeed" },
    { 0x8834, "ISOSpeedLatitudeyyy" },
    { 0x8835, "ISOSpeedLatitudezzz" },
    { 0x9201, "ShutterSpeedValue" },
    { 0x9202, "ApertureValue" },
    { 0x9203, "BrightnessValue" },
    { 0x9204, "ExposureBiasValue" },
    { 0x9205, "MaxApertureValue" },
    { 0x9206, "SubjectDistance" },
    { 0x9207, "MeteringMode" },
    { 0x9208, "LightSource" },
    { 0x9209, "Flash" },
    { 0x920A, "FocalLength" },
    { 0x9214, "SubjectArea" },
    { 0xA20B, "FlashEnergy" },
    { 0xA20C, "SpatialFrequencyResponse" },
    { 0xA20E, "FocalPlaneXResolution" },
    { 0xA20F, "FocalPlaneYResolution" },
    { 0xA210, "FocalPlaneResolutionUnit" },
    { 0xA214, "SubjectLocation" },
    { 0xA215, "ExposureIndex" },
    { 0xA217, "SensingMethod" },
    { 0xA300, "FileSource" },
    { 0xA301, "SceneType" },
    { 0xA302, "CFAPattern" },
    { 0xA401, "CustomRendered" },
    { 0xA402, "ExposureMode" },
    { 0xA403, "WhiteBalance" },
    { 0xA404, "DigitalZoomRatio" },
    { 0xA405, "FocalLengthIn35mmFilm" },
    { 0xA406, "SceneCaptureType" },
    { 0xA407, "GainControl" },
    { 0xA408, "Contrast" },
    { 0xA409, "Saturation" },
    { 0xA40A, "Sharpness" },
    { 0xA40B, "DeviceSettingDescription" },
    { 0xA40C, "SubjectDistanceRange" },
    { 0xA460, "CompositeImage" },
    { 0xA461, "SourceImageNumberOfCompositeImage" },
    { 0xA462, "SourceExposureTimesOfCompositeImage" },
    /*
     * Tags relating to shooting situation:
     */
    { 0x9400, "Temperature" },
    { 0x9401, "Humidity" },
    { 0x9402, "Pressure" },
    { 0x9403, "WaterDepth" },
    { 0x9404, "Acceleration" },
    { 0x9405, "CameraElevationAngle" },
    /*
     * Other tags:
     */
    { 0xA420, "ImageUniqueID" },
    { 0xA430, "CameraOwnerName" },
    { 0xA431, "BodySerialNumber" },
    { 0xA432, "LensSpecification" },
    { 0xA433, "LensMake" },
    { 0xA434, "LensModel" },
    { 0xA435, "LensSerialNumber" },

    { 0x0000, NULL }
};

static const value_string vals_ifd_tags_gps[] = {
    /*
     * Tags relating to GPS:
     */
    { 0x00, "GPSVersionID" },
    { 0x01, "GPSLatitudeRef" },
    { 0x02, "GPSLatitude" },
    { 0x03, "GPSLongitudeRef" },
    { 0x04, "GPSLongitude" },
    { 0x05, "GPSAltitudeRef" },
    { 0x06, "GPSAltitude" },
    { 0x07, "GPSTimeStamp" },
    { 0x08, "GPSSatellites" },
    { 0x09, "GPSStatus" },
    { 0x0A, "GPSMeasureMode" },
    { 0x0B, "GPSDOP" },
    { 0x0C, "GPSSpeedRef" },
    { 0x0D, "GPSSpeed" },
    { 0x0E, "GPSTrackRef" },
    { 0x0F, "GPSTrack" },
    { 0x10, "GPSImgDirectionRef" },
    { 0x11, "GPSImgDirection" },
    { 0x12, "GPSMapDatum" },
    { 0x13, "GPSDestLatitudeRef" },
    { 0x14, "GPSDestLatitude" },
    { 0x15, "GPSDestLongitudeRef" },
    { 0x16, "GPSDestLongitude" },
    { 0x17, "GPSDestBearingRef" },
    { 0x18, "GPSDestBearing" },
    { 0x19, "GPSDestDistanceRef" },
    { 0x1A, "GPSDestDistance" },
    { 0x1B, "GPSProcessingMethod" },
    { 0x1C, "GPSAreaInformation" },
    { 0x1D, "GPSDateStamp" },
    { 0x1E, "GPSDifferential" },
    { 0x1F, "GPSHPositioningError" },
    { 0x00, NULL }
};

static const value_string vals_ifd_tags_interop[] = {
    /*
     * Tags relating to interoperability:
     */
    { 0x1, "InteroperabilityIndex" },
    { 0x0, NULL }
};

enum {
    EXIF_TYPE_BYTE      = 0x0001,
    EXIF_TYPE_ASCII     = 0x0002,
    EXIF_TYPE_SHORT     = 0x0003,
    EXIF_TYPE_LONG      = 0x0004,
    EXIF_TYPE_RATIONAL  = 0x0005,
    /* 0x0006 */
    EXIF_TYPE_UNDEFINED = 0x0007,
    /* 0x0008 */
    EXIF_TYPE_SLONG     = 0x0009,
    EXIF_TYPE_SRATIONAL = 0x000A,
};

static const value_string vals_exif_types[] = {
    { EXIF_TYPE_BYTE,      "BYTE" },
    { EXIF_TYPE_ASCII,     "ASCII" },
    { EXIF_TYPE_SHORT,     "SHORT" },
    { EXIF_TYPE_LONG,      "LONG" },
    { EXIF_TYPE_RATIONAL,  "RATIONAL" },
    { EXIF_TYPE_UNDEFINED, "UNDEFINED" },
    { EXIF_TYPE_SLONG,     "SLONG" },
    { EXIF_TYPE_SRATIONAL, "SRATIONAL" },

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

/* Comment */
static gint hf_comment_header = -1;
static gint hf_comment = -1;

static gint hf_remain_seg_data = -1;
static gint hf_endianness = -1;
static gint hf_start_ifd_offset = -1;
static gint hf_next_ifd_offset = -1;
static gint hf_exif_flashpix_marker = -1;
static gint hf_entropy_coded_segment = -1;
static gint hf_fill_bytes = -1;
static gint hf_skipped_tiff_data = -1;
static gint hf_ifd_num_fields = -1;
static gint hf_ifd_tag = -1;
static gint hf_ifd_tag_exif = -1;
static gint hf_ifd_tag_gps = -1;
static gint hf_ifd_tag_interop = -1;
static gint hf_ifd_type = -1;
static gint hf_ifd_count = -1;
static gint hf_ifd_offset = -1;
static gint hf_ifd_value_byte = -1;
static gint hf_ifd_value_ascii = -1;
static gint hf_ifd_value_short = -1;
static gint hf_ifd_value_long = -1;
static gint hf_ifd_value_rational = -1;
static gint hf_ifd_value_rational_numerator = -1;
static gint hf_ifd_value_rational_denominator = -1;
static gint hf_ifd_value_undefined = -1;
static gint hf_ifd_value_slong = -1;
static gint hf_ifd_value_srational = -1;
static gint hf_ifd_value_srational_numerator = -1;
static gint hf_ifd_value_srational_denominator = -1;


/* Initialize the subtree pointers */
static gint ett_jfif = -1;
static gint ett_marker_segment = -1;
static gint ett_details = -1;
static gint ett_ifd = -1;
static gint ett_rational = -1;
static gint ett_srational = -1;

static expert_field ei_file_jpeg_first_identifier_not_jfif   = EI_INIT;
static expert_field ei_start_ifd_offset   = EI_INIT;
static expert_field ei_next_ifd_offset   = EI_INIT;
static expert_field ei_ifd_value_offset   = EI_INIT;

/****************** JFIF protocol dissection functions ******************/


/*
 * Process a marker segment (with length).
 */
static void
process_marker_segment(proto_tree *tree, tvbuff_t *tvb, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti;
    proto_tree *subtree;

    if (!tree)
        return;

    ti = proto_tree_add_item(tree, hf_marker_segment,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_bytes_format_value(subtree, hf_remain_seg_data, tvb, 4, -1, NULL, "%u bytes", len - 2);
}

/*
 * Process a Start of Frame header (with length).
 */
static void
process_sof_header(proto_tree *tree, tvbuff_t *tvb, guint32 len _U_,
        guint16 marker, const char *marker_name)
{
    proto_item *ti;
    proto_tree *subtree;
    guint8 count;
    guint32 offset;

    if (!tree)
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
    count = tvb_get_guint8(tvb, 9);
    offset = 10;
    while (count > 0) {
        proto_tree_add_item(subtree, hf_sof_c_i, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_sof_h_i, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_sof_v_i, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_sof_tq_i, tvb, offset++, 1, ENC_BIG_ENDIAN);
        count--;
    }
}

/*
 * Process a Start of Segment header (with length).
 */
static void
process_sos_header(proto_tree *tree, tvbuff_t *tvb, guint32 len _U_,
        guint16 marker, const char *marker_name)
{
    proto_item *ti;
    proto_tree *subtree;
    guint8 count;
    guint32 offset;

    if (!tree)
        return;

    ti = proto_tree_add_item(tree, hf_sos_header,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sos_ns, tvb, 4, 1, ENC_BIG_ENDIAN);
    count = tvb_get_guint8(tvb, 4);
    offset = 5;
    while (count > 0) {
        proto_tree_add_item(subtree, hf_sos_cs_j, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_sos_td_j, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_sos_ta_j, tvb, offset++, 1, ENC_BIG_ENDIAN);
        count--;
    }

    proto_tree_add_item(subtree, hf_sos_ss, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sos_se, tvb, offset++, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_sos_ah, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sos_al, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* offset ++ */;
}

/*
 * Process a Comment header (with length).
 */
static void
process_comment_header(proto_tree *tree, tvbuff_t *tvb, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti;
    proto_tree *subtree;

    if (!tree)
        return;

    ti = proto_tree_add_item(tree, hf_comment_header,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_comment, tvb, 4, len-2, ENC_ASCII);
}


/* Process an APP0 block.
 *
 * XXX - This code only works on US-ASCII systems!!!
 */
static int
process_app0_segment(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti;
    proto_tree *subtree;
    proto_tree *subtree_details = NULL;
    guint32 offset;
    char *str;
    gint str_size;
    guint16 x, y;

    if (!tree)
        return 0;

    ti = proto_tree_add_item(tree, hf_marker_segment,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, 0, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_len, tvb, 2, 2, ENC_BIG_ENDIAN);

    str = (char *)tvb_get_stringz_enc(pinfo->pool, tvb, 4, &str_size, ENC_ASCII);
    ti = proto_tree_add_item(subtree, hf_identifier, tvb, 4, str_size, ENC_ASCII);
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
        x = tvb_get_guint8(tvb, 16);
        y = tvb_get_guint8(tvb, 17);
        if (x || y) {
            proto_tree_add_item(subtree, hf_rgb,
                    tvb, 18, 3 * (x * y), ENC_NA);
            offset = 18 + (3 * (x * y));
        } else {
            offset = 18;
        }
    }
    else if (strcmp(str, "JFXX") == 0) {
        proto_tree_add_item(subtree, hf_extension_code,
                tvb, 9, 1, ENC_BIG_ENDIAN);
        /* XXX - dissect the extension based on its extension code */
        offset = 10;
    }
    else { /* Unknown */
        proto_item_append_text(ti, " (unknown identifier)");
        offset = 4 + str_size;

        proto_tree_add_bytes_format_value(subtree, hf_remain_seg_data, tvb, offset, -1, NULL, "%u bytes", len - 2 - str_size);
    }
    return offset;
}

static void
process_tiff_ifd_chain(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        guint encoding, guint32 start_ifd_offset,
        int hf_tag, const char *ifd_type_desc)
{
    guint32 next_ifd_offset = start_ifd_offset;

    for (unsigned ifd_index = 0;; ++ifd_index) {
        int offset = next_ifd_offset;
        /*
         * Process the IFD
         */
        guint32 num_fields = tvb_get_guint16(tvb, offset, encoding);
        proto_tree *subtree_ifd = proto_tree_add_subtree_format(tree, tvb, offset, num_fields * 12 + 6,
                ett_ifd, NULL, "%s #%u", ifd_type_desc, ifd_index);
        proto_tree_add_item(subtree_ifd, hf_ifd_num_fields, tvb, offset, 2, encoding);
        offset += 2;
        while (num_fields-- > 0) {
            guint32 field_tag, field_type, value_count, value_size;
            gint value_hf;

            proto_tree_add_item_ret_uint(subtree_ifd, hf_tag, tvb, offset, 2, encoding, &field_tag);
            offset += 2;
            proto_tree_add_item_ret_uint(subtree_ifd, hf_ifd_type, tvb, offset, 2, encoding, &field_type);
            offset += 2;
            proto_tree_add_item_ret_uint(subtree_ifd, hf_ifd_count, tvb, offset, 4, encoding, &value_count);
            offset += 4;

            switch (field_type) {
            case EXIF_TYPE_BYTE:
                value_size = 1; value_hf = hf_ifd_value_byte; break;
            case EXIF_TYPE_ASCII:
                value_size = 1; value_hf = hf_ifd_value_ascii; break;
            case EXIF_TYPE_SHORT:
                value_size = 2; value_hf = hf_ifd_value_short; break;
            case EXIF_TYPE_LONG:
                value_size = 4; value_hf = hf_ifd_value_long; break;
            case EXIF_TYPE_RATIONAL:
                value_size = 8; value_hf = hf_ifd_value_rational; break;
            case EXIF_TYPE_UNDEFINED:
                value_size = 1; value_hf = hf_ifd_value_undefined; break;
            case EXIF_TYPE_SLONG:
                value_size = 4; value_hf = hf_ifd_value_slong; break;
            case EXIF_TYPE_SRATIONAL:
                value_size = 8; value_hf = hf_ifd_value_srational; break;
            default:
                value_size = 0; value_hf = -1; break;
            }

            int value_offset = -1;
            proto_tree *value_parent = NULL;

            if (value_size == 0 || 4 / value_size < value_count) {
                /* The value(s) are located outside the IFD, and the offset field points to them. */
                guint32 value_offset_uint;
                proto_item *offset_item = proto_tree_add_item_ret_uint(
                        subtree_ifd, hf_ifd_offset, tvb, offset, 4, encoding, &value_offset_uint);

                if (value_offset_uint < tvb_reported_length(tvb)) {
                    value_offset = (int)value_offset_uint;
                } else {
                    expert_add_info_format(pinfo, offset_item, &ei_ifd_value_offset,
                            "bogus, should be < %u", tvb_reported_length(tvb));
                }

                value_parent = tree;
            } else {
                /* The value(s) are small enough to fit directly in the offset field. */
                value_offset = offset;
                value_parent = subtree_ifd;
            }

            if (value_offset >= 0) {
                if (value_hf == hf_ifd_value_ascii || value_hf == hf_ifd_value_undefined)
                    proto_tree_add_item(value_parent, value_hf, tvb, value_offset, value_count, ENC_NA);
                else if (value_size != 0)
                    for (guint32 i = 0; i < value_count; ++i) {
                        proto_item *value_item = proto_tree_add_item(value_parent, value_hf, tvb,
                                value_offset, value_size, encoding);

                        if (value_hf == hf_ifd_value_rational) {
                            proto_tree *subtree_value = proto_item_add_subtree(value_item, ett_rational);
                            guint32 num, denom;
                            proto_tree_add_item_ret_uint(
                                    subtree_value, hf_ifd_value_rational_numerator, tvb,
                                    value_offset, 4, encoding, &num);
                            proto_tree_add_item_ret_uint(
                                    subtree_value, hf_ifd_value_rational_denominator, tvb,
                                    value_offset + 4, 4, encoding, &denom);
                            proto_item_set_text(value_item, "Value: %"PRIu32"/%"PRIu32, num, denom);
                        }
                        else if (value_hf == hf_ifd_value_srational) {
                            proto_tree *subtree_value = proto_item_add_subtree(value_item, ett_srational);
                            gint32 num, denom;
                            proto_tree_add_item_ret_int(
                                    subtree_value, hf_ifd_value_srational_numerator, tvb,
                                    value_offset, 4, encoding, &num);
                            proto_tree_add_item_ret_int(
                                    subtree_value, hf_ifd_value_srational_denominator, tvb,
                                    value_offset + 4, 4, encoding, &denom);
                            proto_item_set_text(value_item, "Value: %"PRIi32"/%"PRIi32, num, denom);
                        }
                        else if (value_hf == hf_ifd_value_long && value_count == 1 && hf_tag == hf_ifd_tag) {
                            guint32 extension_ifd_offset = tvb_get_guint32(tvb, value_offset, encoding);
                            int extension_hf_ifd_tag = -1;
                            const char *extension_ifd_type_desc = NULL;

                            switch (field_tag) {
                            case EXIF_TAG_EXIF_IFD_POINTER:
                                extension_hf_ifd_tag = hf_ifd_tag_exif;
                                extension_ifd_type_desc = "Exif IFD";
                                break;
                            case EXIF_TAG_GPS_IFD_POINTER:
                                extension_hf_ifd_tag = hf_ifd_tag_gps;
                                extension_ifd_type_desc = "GPS IFD";
                                break;
                            case EXIF_TAG_INTEROP_IFD_POINTER:
                                extension_hf_ifd_tag = hf_ifd_tag_interop;
                                extension_ifd_type_desc = "Interoperability IFD";
                                break;
                            }

                            if (extension_ifd_type_desc) {
                                if (extension_ifd_offset < tvb_reported_length(tvb)) {
                                    process_tiff_ifd_chain(tree, tvb, pinfo, encoding,
                                            extension_ifd_offset, extension_hf_ifd_tag,
                                            extension_ifd_type_desc);
                                } else {
                                    expert_add_info_format(pinfo, value_item, &ei_start_ifd_offset,
                                        "bogus, should be < %u", tvb_reported_length(tvb));
                                }
                            }
                        }

                        value_offset += value_size;
                    }
            }
            offset += 4;
        }
        /*
         * Offset to the next IFD
         */
        proto_item *next_ifd_offset_item = proto_tree_add_item_ret_uint(
                subtree_ifd, hf_next_ifd_offset, tvb, offset, 4, encoding, &next_ifd_offset);
        offset += 4;

        if (next_ifd_offset == 0)
            break;

        if (next_ifd_offset < (guint32)offset) {
            expert_add_info_format(pinfo, next_ifd_offset_item, &ei_next_ifd_offset,
                    " (bogus, should be >= %u)", offset);
            return;
        }
    }
}

static void
process_tiff(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo)
{
    /*
     * Endianness
     */
    guint encoding;
    int offset = 0;

    guint16 byte_order = tvb_get_ntohs(tvb, offset);
    if (byte_order == 0x4949) {
        encoding = ENC_LITTLE_ENDIAN;
        proto_tree_add_uint_format_value(tree, hf_endianness, tvb, offset, 2, byte_order, "little endian");
    } else if (byte_order == 0x4D4D) {
        encoding = ENC_BIG_ENDIAN;
        proto_tree_add_uint_format_value(tree, hf_endianness, tvb, offset, 2, byte_order, "big endian");
    } else {
        /* Error: invalid endianness encoding */
        proto_tree_add_uint_format_value(tree, hf_endianness, tvb, offset, 2, byte_order,
                "Incorrect encoding 0x%04x- skipping the remainder of this application marker", byte_order);
        return;
    }
    offset += 2;
    /*
     * Fixed value 42 = 0x002a
     */
    offset += 2;
    /*
     * Offset to IFD
     */
    guint32 start_ifd_offset;
    proto_item* start_ifd_offset_item = proto_tree_add_item_ret_uint(
            tree, hf_start_ifd_offset, tvb, offset, 4, encoding, &start_ifd_offset);
    offset += 4;
    /*
     * Check for a bogus offset value.
     * XXX - bogus value message should also deal with a
     * value that's too large and causes an overflow.
     * Or should it just check against the segment length,
     * which is 16 bits?
     */
    if (start_ifd_offset < (guint32)offset) {
        expert_add_info_format(pinfo, start_ifd_offset_item, &ei_start_ifd_offset,
                " (bogus, should be >= %u)", offset);
        return;
    }

    process_tiff_ifd_chain(tree, tvb, pinfo, encoding, start_ifd_offset,
            hf_ifd_tag, "Image File Directory");
}

/* Process an APP1 block.
 *
 * XXX - This code only works on US-ASCII systems!!!
 */
static void
process_app1_segment(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 len,
        guint16 marker, const char *marker_name, gboolean show_first_identifier_not_jfif)
{
    proto_item *ti;
    proto_tree *subtree;
    char *str;
    gint str_size;
    int offset = 0;

    ti = proto_tree_add_item(tree, hf_marker_segment,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_marker_segment);

    proto_item_append_text(ti, ": %s (0x%04X)", marker_name, marker);
    proto_tree_add_item(subtree, hf_marker, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    str = (char*)tvb_get_stringz_enc(pinfo->pool, tvb, offset, &str_size, ENC_ASCII);
    ti = proto_tree_add_item(subtree, hf_identifier, tvb, offset, str_size, ENC_ASCII);
    offset += str_size;

    if (show_first_identifier_not_jfif && strcmp(str, "JFIF") != 0) {
        expert_add_info(pinfo, ti, &ei_file_jpeg_first_identifier_not_jfif);
    }

    if (strcmp(str, "Exif") == 0) {
        offset++; /* Skip a byte supposed to be 0x00 */

        tvbuff_t *tvb_tiff = tvb_new_subset_remaining(tvb, offset);
        process_tiff(subtree, tvb_tiff, pinfo);
    } else {
        proto_tree_add_bytes_format_value(subtree, hf_remain_seg_data, tvb, offset, -1, NULL, "%u bytes", len - 2 - str_size);
        proto_item_append_text(ti, " (Unknown identifier)");
    }
}

/* Process an APP2 block.
 *
 * XXX - This code only works on US-ASCII systems!!!
 */
static void
process_app2_segment(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 len,
        guint16 marker, const char *marker_name)
{
    proto_item *ti;
    proto_tree *subtree;
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

    str = (char*)tvb_get_stringz_enc(pinfo->pool, tvb, 4, &str_size, ENC_ASCII);
    ti = proto_tree_add_item(subtree, hf_identifier, tvb, 4, str_size, ENC_ASCII);
    if (strcmp(str, "FPXR") == 0) {
        proto_tree_add_item(tree, hf_exif_flashpix_marker, tvb, 0, -1, ENC_NA);
    } else {
        proto_tree_add_bytes_format_value(subtree, hf_remain_seg_data, tvb, 4 + str_size, -1, NULL, "%u bytes", len - 2 - str_size);
        proto_item_append_text(ti, " (Unknown identifier)");
    }
}

static gint
dissect_jfif(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree;
    proto_item *ti;
    gint tvb_len = tvb_reported_length(tvb);
    gint32 start_entropy = 0;
    gint32 start_fill, start_marker;
    gboolean show_first_identifier_not_jfif = FALSE;

    /* check if we have a full JFIF in tvb */
    if (tvb_len < 20)
        return 0;
    /* Start Of Image marker must come first */
    if (tvb_get_ntohs(tvb, 0) != MARKER_SOI)
        return 0;
    /* Check identifier field in first App segment is "JFIF", although "Exif" from App1
       can/does appear here too... */
    if (tvb_memeql(tvb, 6, (const guint8*)"Exif", 5) == 0) {
        show_first_identifier_not_jfif = TRUE;
    }
    else if (tvb_memeql(tvb, 6, (const guint8*)"JFIF", 5)) {
        return 0;
    }

    /* Add summary to INFO column if it is enabled */
    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(JPEG JFIF image)");

    ti = proto_tree_add_item(tree, proto_jfif,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_jfif);

    for (; ; ) {
        const char *str;
        guint16 marker;

        start_fill = start_entropy;

        for (; ; ) {
            start_fill = tvb_find_guint8(tvb, start_fill, -1, 0xFF);

            if (start_fill == -1 || tvb_len - start_fill == 1
              || tvb_get_guint8(tvb, start_fill + 1) != 0) /* FF 00 is FF escaped */
                break;

            start_fill += 2;
        }

        if (start_fill == -1) start_fill = tvb_len;

        if (start_fill != start_entropy)
            proto_tree_add_item(subtree, hf_entropy_coded_segment, tvb, start_entropy, start_fill - start_entropy, ENC_NA);

        if (start_fill == tvb_len) break;

        start_marker = start_fill;

        while (tvb_get_guint8(tvb, start_marker + 1) == 0xFF)
            ++start_marker;

        if (start_marker != start_fill)
            proto_tree_add_item(subtree, hf_fill_bytes, tvb, start_fill, start_marker - start_fill, ENC_NA);

        marker = tvb_get_ntohs(tvb, start_marker);
        str = try_val_to_str(marker, vals_marker);
        if (str) { /* Known marker */
            if (marker_has_length(marker)) { /* Marker segment */
                /* Length of marker segment = 2 + len */
                const guint16 len = tvb_get_ntohs(tvb, start_marker + 2);
                tvbuff_t *tmp_tvb = tvb_new_subset_length(tvb, start_marker, 2 + len);
                switch (marker) {
                    case MARKER_APP0:
                        process_app0_segment(subtree, tmp_tvb, pinfo, len, marker, str);
                        break;
                    case MARKER_APP1:
                        process_app1_segment(subtree, tmp_tvb, pinfo, len, marker, str, show_first_identifier_not_jfif);
                        show_first_identifier_not_jfif = FALSE;
                        break;
                    case MARKER_APP2:
                        process_app2_segment(subtree, tmp_tvb, pinfo, len, marker, str);
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
                        break;
                    case MARKER_COM:
                        process_comment_header(subtree, tmp_tvb, len, marker, str);
                        break;
                    default:
                        process_marker_segment(subtree, tmp_tvb, len, marker, str);
                        break;
                }
                start_entropy = start_marker + 2 + len;
            } else { /* Marker but no segment */
                /* Length = 2 */
                proto_tree_add_item(subtree, hf_marker,
                        tvb, start_marker, 2, ENC_BIG_ENDIAN);
                start_entropy = start_marker + 2;
            }
        } else { /* Reserved! */
            ti = proto_tree_add_item(subtree, hf_marker,
                    tvb, start_marker, 2, ENC_BIG_ENDIAN);
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
              "image-jfif.marker",
              FT_UINT16, BASE_HEX, VALS(vals_marker), 0x0,
              "JFIF Marker",
              HFILL
          }
        },
        /* Marker segment */
        { &hf_marker_segment,
          {   "Marker segment",
              "image-jfif.marker_segment",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_len,
          {   "Length",
              "image-jfif.length",
              FT_UINT16, BASE_DEC, 0, 0x0,
              "Length of segment (including length field)",
              HFILL
          }
        },
        /* MARKER_APP0 */
        { &hf_identifier,
          {   "Identifier",
              "image-jfif.identifier",
              FT_STRINGZ, BASE_NONE, NULL, 0x0,
              "Identifier of the segment",
              HFILL
          }
        },
        /* MARKER_APP0 - JFIF */
        { &hf_version,
          {   "Version",
              "image-jfif.version",
              FT_NONE, BASE_NONE, NULL, 0x0,
              "JFIF Version",
              HFILL
          }
        },
        { &hf_version_major,
          {   "Major Version",
              "image-jfif.version.major",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "JFIF Major Version",
              HFILL
          }
        },
        { &hf_version_minor,
          {   "Minor Version",
              "image-jfif.version.minor",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "JFIF Minor Version",
              HFILL
          }
        },
        { &hf_units,
          {   "Units",
              "image-jfif.units",
              FT_UINT8, BASE_DEC, VALS(vals_units), 0x0,
              "Units used in this segment",
              HFILL
          }
        },
        { &hf_xdensity,
          {   "Xdensity",
              "image-jfif.Xdensity",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Horizontal pixel density",
              HFILL
          }
        },
        { &hf_ydensity,
          {   "Ydensity",
              "image-jfif.Ydensity",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Vertical pixel density",
              HFILL
          }
        },
        { &hf_xthumbnail,
          {   "Xthumbnail",
              "image-jfif.Xthumbnail",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Thumbnail horizontal pixel count",
              HFILL
          }
        },
        { &hf_ythumbnail,
          {   "Ythumbnail",
              "image-jfif.Ythumbnail",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Thumbnail vertical pixel count",
              HFILL
          }
        },
        { &hf_rgb,
          {   "RGB values of thumbnail pixels",
              "image-jfif.RGB",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "RGB values of the thumbnail pixels (24 bit per pixel, Xthumbnail x Ythumbnail pixels)",
              HFILL
          }
        },
        /* MARKER_APP0 - JFXX */
        { &hf_extension_code,
          {   "Extension code",
              "image-jfif.extension.code",
              FT_UINT8, BASE_HEX, VALS(vals_extension_code), 0x0,
              "JFXX extension code for thumbnail encoding",
              HFILL
          }
        },
        /* Header: Start of Frame (MARKER_SOF) */
        { &hf_sof_header,
          {   "Start of Frame header",
              "image-jfif.sof",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_sof_precision,
          {   "Sample Precision (bits)",
              "image-jfif.sof.precision",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifies the precision in bits for the samples of the components in the frame.",
              HFILL
          }
        },
        { &hf_sof_lines,
          {   "Lines",
              "image-jfif.sof.lines",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifies the maximum number of lines in the source image.",
              HFILL
          }
        },
        { &hf_sof_samples_per_line,
          {   "Samples per line",
              "image-jfif.sof.samples_per_line",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifies the maximum number of samples per line in the source image.",
              HFILL
          }
        },
        { &hf_sof_nf,
          {   "Number of image components in frame",
              "image-jfif.sof.nf",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifies the number of source image components in the frame.",
              HFILL
          }
        },
        { &hf_sof_c_i,
          {   "Component identifier",
              "image-jfif.sof.c_i",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Assigns a unique label to the ith component in the sequence of frame component specification parameters.",
              HFILL
          }
        },
        { &hf_sof_h_i,
          {   "Horizontal sampling factor",
              "image-jfif.sof.h_i",
              FT_UINT8, BASE_DEC, NULL, 0xF0,
              "Specifies the relationship between the component horizontal dimension and maximum image dimension X.",
              HFILL
          }
        },
        { &hf_sof_v_i,
          {   "Vertical sampling factor",
              "image-jfif.sof.v_i",
              FT_UINT8, BASE_DEC, NULL, 0x0F,
              "Specifies the relationship between the component vertical dimension and maximum image dimension Y.",
              HFILL
          }
        },
        { &hf_sof_tq_i,
          {   "Quantization table destination selector",
              "image-jfif.sof.tq_i",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifies one of four possible quantization table destinations from which the quantization table to"
              " use for dequantization of DCT coefficients of component Ci is retrieved.",
              HFILL
          }
        },

        /* Header: Start of Segment (MARKER_SOS) */
        { &hf_sos_header,
          {   "Start of Segment header",
              "image-jfif.header.sos",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_sos_ns,
          {   "Number of image components in scan",
              "image-jfif.sos.ns",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifies the number of source image components in the scan.",
              HFILL
          }
        },
        { &hf_sos_cs_j,
          {   "Scan component selector",
              "image-jfif.sos.component_selector",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Selects which of the Nf image components specified in the frame parameters shall be the jth"
              " component in the scan.",
              HFILL
          }
        },
        { &hf_sos_td_j,
          {   "DC entropy coding table destination selector",
              "image-jfif.sos.dc_entropy_selector",
              FT_UINT8, BASE_DEC, NULL, 0xF0,
              "Specifies one of four possible DC entropy coding table destinations from which the entropy"
              " table needed for decoding of the DC coefficients of component Csj is retrieved.",
              HFILL
          }
        },
        { &hf_sos_ta_j,
          {   "AC entropy coding table destination selector",
              "image-jfif.sos.ac_entropy_selector",
              FT_UINT8, BASE_DEC, NULL, 0x0F,
              "Specifies one of four possible AC entropy coding table destinations from which the entropy"
              " table needed for decoding of the AC coefficients of component Csj is retrieved.",
              HFILL
          }
        },
        { &hf_sos_ss,
          {   "Start of spectral or predictor selection",
              "image-jfif.sos.ss",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "In the DCT modes of operation, this parameter specifies the first DCT coefficient in"
              " each block in zig-zag order which shall be coded in the scan. This parameter shall"
              " be set to zero for the sequential DCT processes. In the lossless mode of operations"
              " this parameter is used to select the predictor.",
              HFILL
          }
        },
        { &hf_sos_se,
          {   "End of spectral selection",
              "image-jfif.sos.se",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifies the last DCT coefficient in each block in zig-zag order which shall be coded"
              " in the scan. This parameter shall be set to 63 for the sequential DCT processes. In the"
              " lossless mode of operations this parameter has no meaning. It shall be set to zero.",
              HFILL
          }
        },
        { &hf_sos_ah,
          {   "Successive approximation bit position high",
              "image-jfif.sos.ah",
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
              "image-jfif.sos.al",
              FT_UINT8, BASE_DEC, NULL, 0x0F,
              "In the DCT modes of operation this parameter specifies the point transform, i.e. bit"
              " position low, used before coding the band of coefficients specified by Ss and Se."
              " This parameter shall be set to zero for the sequential DCT processes. In the lossless"
              " mode of operations, this parameter specifies the point transform, Pt.",
              HFILL
          }
        },

        /* Header: Comment (MARKER_COM) */
        { &hf_comment_header,
          {   "Comment header",
              "image-jfif.header.comment",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_comment,
          {   "Comment",
              "image-jfif.comment",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_remain_seg_data,
          {   "Remaining segment data",
              "image-jfif.remain_seg_data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_endianness,
          {   "Endianness",
              "image-jfif.endianness",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_start_ifd_offset,
          {   "Start offset of IFD starting from the TIFF header start",
              "image-jfif.start_ifd_offset",
              FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_next_ifd_offset,
          {   "Offset to next IFD from start of TIFF header",
              "image-jfif.next_ifd_offset",
              FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_exif_flashpix_marker,
          {   "Exif FlashPix APP2 application marker",
              "image-jfif.exif_flashpix_marker",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_entropy_coded_segment,
          {   "Entropy-coded segment (dissection is not yet implemented)",
              "image-jfif.entropy_coded_segment",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_fill_bytes,
          {   "Fill bytes",
              "image-jfif.fill_bytes",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_skipped_tiff_data,
          {   "Skipped data between end of TIFF header and start of IFD",
              "image-jfif.skipped_tiff_data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_num_fields,
          {   "Number of fields in this IFD",
              "image-jfif.ifd.num_fields",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_tag,
          {   "Tag",
              "image-jfif.ifd.tag",
              FT_UINT16, BASE_DEC, VALS(vals_ifd_tags), 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_tag_exif,
          {   "Tag",
              "image-jfif.ifd.tag_exif",
              FT_UINT16, BASE_DEC, VALS(vals_ifd_tags_exif), 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_tag_gps,
          {   "Tag",
              "image-jfif.ifd.tag_gps",
              FT_UINT16, BASE_DEC, VALS(vals_ifd_tags_gps), 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_tag_interop,
          {   "Tag",
              "image-jfif.ifd.tag_interop",
              FT_UINT16, BASE_DEC, VALS(vals_ifd_tags_interop), 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_type,
          {   "Type",
              "image-jfif.ifd.type",
              FT_UINT16, BASE_DEC, VALS(vals_exif_types), 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_count,
          {   "Count",
              "image-jfif.ifd.count",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_offset,
          {   "Value offset from start of TIFF header",
              "image-jfif.ifd.offset",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_byte,
          {   "Value",
              "image-jfif.ifd.value_byte",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_ascii,
          {   "Value",
              "image-jfif.ifd.value_ascii",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_short,
          {   "Value",
              "image-jfif.ifd.value_short",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_long,
          {   "Value",
              "image-jfif.ifd.value_long",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_rational,
          {   "Value",
              "image-jfif.ifd.value_rational",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_rational_numerator,
          {   "Numerator",
              "image-jfif.ifd.value_rational.numerator",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_rational_denominator,
          {   "Denominator",
              "image-jfif.ifd.value_rational.denominator",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_undefined,
          {   "Value (raw)",
              "image-jfif.ifd.value_undefined",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_slong,
          {   "Value",
              "image-jfif.ifd.value_slong",
              FT_INT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_srational,
          {   "Value",
              "image-jfif.ifd.value_srational",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_srational_numerator,
          {   "Numerator",
              "image-jfif.ifd.value_srational.numerator",
              FT_INT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
        { &hf_ifd_value_srational_denominator,
          {   "Denominator",
              "image-jfif.ifd.value_srational.denominator",
              FT_INT32, BASE_DEC, NULL, 0x0,
              NULL,
              HFILL
          }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_jfif,
        &ett_marker_segment,
        &ett_details,
        &ett_ifd,
        &ett_rational,
        &ett_srational,
    };

    static ei_register_info ei[] = {
        { &ei_file_jpeg_first_identifier_not_jfif,
          { "image-jfif.app0-identifier-not-jfif", PI_PROTOCOL, PI_WARN,
            "Initial App0 segment with \"JFIF\" Identifier not found", EXPFILL }},
        { &ei_start_ifd_offset,
          { "image-jfif.start_ifd_offset.invalid", PI_PROTOCOL, PI_WARN,
            "Invalid value", EXPFILL }},
        { &ei_next_ifd_offset,
          { "image-jfif.next_ifd_offset.invalid", PI_PROTOCOL, PI_WARN,
            "Invalid value", EXPFILL }},
        { &ei_ifd_value_offset,
          { "image-jfif.ifd_value_offset.invalid", PI_PROTOCOL, PI_WARN,
            "Invalid value", EXPFILL }},
    };

    expert_module_t* expert_jfif;

    /* Register the protocol name and description */
    proto_jfif = proto_register_protocol(
        "JPEG File Interchange Format",
        "JFIF (JPEG) image",
        "image-jfif"
        );

    /* Required function calls to register the header fields
     * and subtrees used */
    proto_register_field_array(proto_jfif, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_jfif = expert_register_protocol(proto_jfif);
    expert_register_field_array(expert_jfif, ei, array_length(ei));

    register_dissector("image-jfif", dissect_jfif, proto_jfif);
}


void
proto_reg_handoff_jfif(void)
{
    dissector_handle_t jfif_handle = find_dissector("image-jfif");

    /* Register the JPEG media type */
    dissector_add_string("media_type", "image/jfif", jfif_handle);
    dissector_add_string("media_type", "image/jpg", jfif_handle);
    dissector_add_string("media_type", "image/jpeg", jfif_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_JPEG_JFIF, jfif_handle);

    heur_dissector_add("http", dissect_jfif_heur, "JPEG file in HTTP", "jfif_http", proto_jfif, HEURISTIC_ENABLE);
    heur_dissector_add("wtap_file", dissect_jfif_heur, "JPEG file", "jfif_wtap", proto_jfif, HEURISTIC_ENABLE);
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
