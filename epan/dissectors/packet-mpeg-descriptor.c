/* packet-mpeg-descriptor.c
 * Routines for MPEG2 (ISO/ISO 13818-1 and co) descriptors
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/dvb_chartbl.h>
#include "packet-mpeg-sect.h"
#include "packet-mpeg-descriptor.h"

void proto_register_mpeg_descriptor(void);

static int proto_mpeg_descriptor = -1;
static int hf_mpeg_descriptor_tag = -1;
static int hf_mpeg_descriptor_length = -1;
static int hf_mpeg_descriptor_data = -1;

static gint ett_mpeg_descriptor = -1;

static const value_string mpeg_descriptor_tag_vals[] = {
    /* From ISO/IEC 13818-1 */
    { 0x00, "Reserved" },
    { 0x01, "Reserved" },
    { 0x02, "Video Stream Descriptor" },
    { 0x03, "Audio Stream Descriptor" },
    { 0x04, "Hierarchy Descriptor" },
    { 0x05, "Registration Descriptor" },
    { 0x06, "Data Stream Alignment Descriptor" },
    { 0x07, "Target Background Grid Descriptor" },
    { 0x08, "Video Window Descriptor" },
    { 0x09, "CA Descriptor" },
    { 0x0A, "ISO 639 Language Descriptor" },
    { 0x0B, "System Clock Descriptor" },
    { 0x0C, "Multiplex Buffer Utilization Descriptor" },
    { 0x0D, "Copyright Descriptor" },
    { 0x0E, "Maximum Bitrate Descriptor" },
    { 0x0F, "Private Data Indicator Descriptor" },
    { 0x10, "Smoothing Buffer Descriptor" },
    { 0x11, "STD Descriptor" },
    { 0x12, "IBP Descriptor" },

    /* From ETSI TR 101 202 */
    { 0x13, "Carousel Identifier Descriptor" },
    { 0x14, "Association Tag Descriptor" },
    { 0x15, "Deferred Association Tag Descriptor" },

    /* From ISO/IEC 13818-1 */
    { 0x1B, "MPEG 4 Video Descriptor" },
    { 0x1C, "MPEG 4 Audio Descriptor" },
    { 0x1D, "IOD Descriptor" },
    { 0x1E, "SL Descriptor" },
    { 0x1F, "FMC Descriptor" },
    { 0x20, "External ES ID Descriptor" },
    { 0x21, "MuxCode Descriptor" },
    { 0x22, "FmxBufferSize Descriptor" },
    { 0x23, "MultiplexBuffer Descriptor" },
    { 0x24, "Content Labeling Descriptor" },
    { 0x25, "Metadata Pointer Descriptor" },
    { 0x26, "Metadata Descriptor" },
    { 0x27, "Metadata STD Descriptor" },
    { 0x28, "AVC Video Descriptor" },
    { 0x29, "IPMP Descriptor" },
    { 0x2A, "AVC Timing and HRD Descriptor" },
    { 0x2B, "MPEG2 AAC Descriptor" },
    { 0x2C, "FlexMuxTiming Descriptor" },

    /* From ETSI EN 300 468 */
    { 0x40, "Network Name Descriptor" },
    { 0x41, "Service List Descriptor" },
    { 0x42, "Stuffing Descriptor" },
    { 0x43, "Satellite Delivery System Descriptor" },
    { 0x44, "Cable Delivery System Descriptor" },
    { 0x45, "VBI Data Descriptor" },
    { 0x46, "VBI Teletext Descriptor" },
    { 0x47, "Bouquet Name Descriptor" },
    { 0x48, "Service Descriptor" },
    { 0x49, "Country Availability Descriptor" },
    { 0x4A, "Linkage Descriptor" },
    { 0x4B, "NVOD Reference Descriptor" },
    { 0x4C, "Time Shifted Service Descriptor" },
    { 0x4D, "Short Event Descriptor" },
    { 0x4E, "Extended Event Descriptor" },
    { 0x4F, "Time Shifted Event Descriptor" },
    { 0x50, "Component Descriptor" },
    { 0x51, "Mosaic Descriptor" },
    { 0x52, "Stream Identifier Descriptor" },
    { 0x53, "CA Identifier Descriptor" },
    { 0x54, "Content Descriptor" },
    { 0x55, "Parent Rating Descriptor" },
    { 0x56, "Teletext Descriptor" },
    { 0x57, "Telephone Descriptor" },
    { 0x58, "Local Time Offset Descriptor" },
    { 0x59, "Subtitling Descriptor" },
    { 0x5A, "Terrestrial Delivery System Descriptor" },
    { 0x5B, "Multilingual Network Name Descriptor" },
    { 0x5C, "Multilingual Bouquet Name Descriptor" },
    { 0x5D, "Multilingual Service Name Descriptor" },
    { 0x5E, "Multilingual Component Descriptor" },
    { 0x5F, "Private Data Specifier Descriptor" },
    { 0x60, "Service Move Descriptor" },
    { 0x61, "Short Smoothing Buffer Descriptor" },
    { 0x62, "Frequency List Descriptor" },
    { 0x63, "Partial Transport Stream Descriptor" },
    { 0x64, "Data Broadcast Descriptor" },
    { 0x65, "Scrambling Descriptor" },
    { 0x66, "Data Broadcast ID Descriptor" },
    { 0x67, "Transport Stream Descriptor" },
    { 0x68, "DSNG Descriptor" },
    { 0x69, "PDC Descriptor" },
    { 0x6A, "AC-3 Descriptor" },
    { 0x6B, "Ancillary Data Descriptor" },
    { 0x6C, "Cell List Descriptor" },
    { 0x6D, "Cell Frequency Link Descriptor" },
    { 0x6E, "Announcement Support Descriptor" },
    { 0x6F, "Application Signalling Descriptor" },
    { 0x70, "Adaptation Field Data Descriptor" },
    { 0x71, "Service Identifier Descriptor" },
    { 0x72, "Service Availability Descriptor" },
    { 0x73, "Default Authority Descriptor" },
    { 0x74, "Related Content Descriptor" },
    { 0x75, "TVA ID Descriptor" },
    { 0x76, "Content Identifier Descriptor" },
    { 0x77, "Time Slice FEC Identifier Descriptor" },
    { 0x78, "ECM Repetition Rate Descriptor" },
    { 0x79, "S2 Satellite Delivery System Descriptor" },
    { 0x7A, "Enhanced AC-3 Descriptor" },
    { 0x7B, "DTS Descriptor" },
    { 0x7C, "AAC Descriptor" },
    { 0x7D, "XAIT Content Location Descriptor" },
    { 0x7E, "FTA Content Management Descriptor" },
    { 0x7F, "Extension Descriptor" },

    /* From ETSI EN 301 790 */
    { 0xA0, "Network Layer Info Descriptor" },
    { 0xA1, "Correction Message Descriptor" },
    { 0xA2, "Logon Initialize Descriptor" },
    { 0xA3, "ACQ Assign Descriptor" },
    { 0xA4, "SYNC Assign Descriptor" },
    { 0xA5, "Encrypted Logon ID Descriptor" },
    { 0xA6, "Echo Value Descriptor" },
    { 0xA7, "RCS Content Descriptor" },
    { 0xA8, "Satellite Forward Link Descriptor" },
    { 0xA9, "Satellite Return Link Descriptor" },
    { 0xAA, "Table Update Descriptor" },
    { 0xAB, "Contention Control Descriptor" },
    { 0xAC, "Correction Control Descriptor" },
    { 0xAD, "Forward Interaction Path Descriptor" },
    { 0xAE, "Return Interaction Path Descriptor" },
    { 0xAf, "Connection Control Descriptor" },
    { 0xB0, "Mobility Control Descriptor" },
    { 0xB1, "Correction Message Extension Descriptor" },
    { 0xB2, "Return Transmission Modes Descriptor" },
    { 0xB3, "Mesh Logon Initialize Descriptor" },
    { 0xB5, "Implementation Type Descriptor" },
    { 0xB6, "LL FEC Identifier Descriptor" },

    { 0x00, NULL}
};
static value_string_ext mpeg_descriptor_tag_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descriptor_tag_vals);

/* 0x02 Video Stream Descriptor */
static int hf_mpeg_descr_video_stream_multiple_frame_rate_flag = -1;
static int hf_mpeg_descr_video_stream_frame_rate_code = -1;
static int hf_mpeg_descr_video_stream_mpeg1_only_flag = -1;
static int hf_mpeg_descr_video_stream_constrained_parameter_flag = -1;
static int hf_mpeg_descr_video_stream_still_picture_flag = -1;
static int hf_mpeg_descr_video_stream_profile_and_level_indication = -1;
static int hf_mpeg_descr_video_stream_chroma_format = -1;
static int hf_mpeg_descr_video_stream_frame_rate_extension_flag = -1;
static int hf_mpeg_descr_video_stream_reserved = -1;

#define MPEG_DESCR_VIDEO_STREAM_MULTIPLE_FRAME_RATE_FLAG_MASK   0x80
#define MPEG_DESCR_VIDEO_STREAM_FRAME_RATE_CODE_MASK            0x78
#define MPEG_DESCR_VIDEO_STREAM_MPEG1_ONLY_FLAG_MASK            0x04
#define MPEG_DESCR_VIDEO_STREAM_CONSTRAINED_PARAMETER_FLAG_MASK 0x02
#define MPEG_DESCR_VIDEO_STREAM_STILL_PICTURE_FLAG_MASK         0x01
#define MPEG_DESCR_VIDEO_STREAM_CHROMA_FORMAT_MASK              0xC0
#define MPEG_DESCR_VIDEO_STREAM_FRAME_RATE_EXTENSION_FLAG_MASK  0x20
#define MPEG_DESCR_VIDEO_STREAM_RESERVED_MASK                   0x1F

static const value_string mpeg_descr_video_stream_multiple_frame_rate_flag_vals[] = {
    { 0x00, "Single frame rate present" },
    { 0x01, "Multiple frame rate present" },

    { 0x00, NULL }
};

static void
proto_mpeg_descriptor_dissect_video_stream(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

    guint8 mpeg1_only_flag;

    mpeg1_only_flag = tvb_get_guint8(tvb, offset) & MPEG_DESCR_VIDEO_STREAM_MPEG1_ONLY_FLAG_MASK;
    proto_tree_add_item(tree, hf_mpeg_descr_video_stream_multiple_frame_rate_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_video_stream_frame_rate_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_video_stream_mpeg1_only_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_video_stream_constrained_parameter_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_video_stream_still_picture_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    if (mpeg1_only_flag == 0) {

        proto_tree_add_item(tree, hf_mpeg_descr_video_stream_profile_and_level_indication, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_video_stream_chroma_format, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_video_stream_frame_rate_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_video_stream_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}

/* 0x03 Audio Stream Descriptor */
static int hf_mpeg_descr_audio_stream_free_format_flag = -1;
static int hf_mpeg_descr_audio_stream_id = -1;
static int hf_mpeg_descr_audio_stream_layer = -1;
static int hf_mpeg_descr_audio_stream_variable_rate_audio_indicator = -1;
static int hf_mpeg_descr_audio_stream_reserved = -1;

#define MPEG_DESCR_AUDIO_STREAM_FREE_FORMAT_FLAG_MASK                   0x80
#define MPEG_DESCR_AUDIO_STREAM_ID_MASK                                 0x40
#define MPEG_DESCR_AUDIO_STREAM_LAYER_MASK                              0x30
#define MPEG_DESCR_AUDIO_STREAM_VARIABLE_RATE_AUDIO_INDICATOR_MASK      0x08
#define MPEG_DESCR_AUDIO_STREAM_RESERVED_MASK                           0x07

static const value_string mpeg_descr_audio_stream_free_format_flag_vals[] = {
    { 0x00, "bitrate_index is not 0" },
    { 0x01, "One more more audio frame has bitrate_index = 0" },

    { 0x00, NULL }
};

static const value_string mpeg_descr_audio_stream_id_vals[] = {
    { 0x00, "ID not set to 1 in all the frames" },
    { 0x01, "ID set to 1 in all the frames" },

    { 0x00, NULL }
};

static const value_string mpeg_descr_audio_stream_variable_rate_audio_indicator_vals[] = {
    { 0x00, "Constant bitrate" },
    { 0x01, "Variable bitrate" },

    { 0x00, NULL }

};

static void
proto_mpeg_descriptor_dissect_audio_stream(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_free_format_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_layer, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_variable_rate_audio_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x05 Registration Descriptor */
static int hf_mpeg_descr_reg_form_id = -1;
static int hf_mpeg_descr_reg_add_id_inf = -1;

static void
proto_mpeg_descriptor_dissect_registration(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint  offset_start;

    offset_start = offset;
    proto_tree_add_item(tree, hf_mpeg_descr_reg_form_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    while (offset-offset_start<len) {
        proto_tree_add_item(tree, hf_mpeg_descr_reg_add_id_inf, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
}

/* 0x06 Data Stream Alignment Descriptor */
static int hf_mpeg_descr_data_stream_alignment = -1;

static const value_string mpeg_descr_data_stream_alignment_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Slice, or video access unit" },
    { 0x02, "Video access unit" },
    { 0x03, "GOP, or SEQ" },
    { 0x04, "SEQ" },

    { 0x00, NULL }
};

static void
proto_mpeg_descriptor_dissect_data_stream_alignment(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_data_stream_alignment, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x09 CA Descriptor */
static int hf_mpeg_descr_ca_system_id = -1;
static int hf_mpeg_descr_ca_reserved = -1;
static int hf_mpeg_descr_ca_pid = -1;
static int hf_mpeg_descr_ca_private = -1;

#define MPEG_DESCR_CA_RESERVED_MASK 0xE000
#define MPEG_DESCR_CA_PID_MASK      0x1FFF

static void
proto_mpeg_descriptor_dissect_ca(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_ca_system_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_ca_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ca_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (len > 4)
        proto_tree_add_item(tree, hf_mpeg_descr_ca_private, tvb, offset, len - 4, ENC_NA);
}


/* 0x0A ISO 639 Language Descriptor */
static int hf_mpeg_descr_iso639_lang = -1;
static int hf_mpeg_descr_iso639_type = -1;

static const value_string mpeg_descr_iso639_type_vals[] = {
    { 0x00, "Undefined" },
    { 0x01, "Clean Effects" },
    { 0x02, "Hearing Impaired" },
    { 0x03, "Visual Impaired Commentary" },

    { 0x00, NULL }
};

static void
proto_mpeg_descriptor_dissect_iso639(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    if (len > 1)
        proto_tree_add_item(tree, hf_mpeg_descr_iso639_lang, tvb, offset, len - 1, ENC_ASCII|ENC_NA);
    offset += len - 1;
    proto_tree_add_item(tree, hf_mpeg_descr_iso639_type, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x0B System Clock Descriptor */
static int hf_mpeg_descr_system_clock_external_clock_reference_indicator = -1;
static int hf_mpeg_descr_system_clock_reserved1 = -1;
static int hf_mpeg_descr_system_clock_accuracy_integer = -1;
static int hf_mpeg_descr_system_clock_accuracy_exponent = -1;
static int hf_mpeg_descr_system_clock_reserved2 = -1;

#define MPEG_DESCR_SYSTEM_CLOCK_EXTERNAL_CLOCK_REFERENCE_INDICATOR_MASK 0x80
#define MPEG_DESCR_SYSTEM_CLOCK_RESERVED1_MASK                          0x40
#define MPEG_DESCR_SYSTEM_CLOCK_ACCURACY_INTEGER_MASK                   0x3F
#define MPEG_DESCR_SYSTEM_CLOCK_ACCURACY_EXPONENT_MASK                  0xE0
#define MPEG_DESCR_SYSTEM_CLOCK_RESERVED2_MASK                          0x1F

static void
proto_mpeg_descriptor_dissect_system_clock(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_external_clock_reference_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_accuracy_integer, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_accuracy_exponent, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x0E Maximum Bitrate Descriptor */
static int hf_mpeg_descr_max_bitrate_reserved = -1;
static int hf_mpeg_descr_max_bitrate = -1;

#define MPEG_DESCR_MAX_BITRATE_RESERVED_MASK    0xC00000
#define MPEG_DESCR_MAX_BITRATE_MASK     0x3FFFFF

static void
proto_mpeg_descriptor_dissect_max_bitrate(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_item *rate_item;

    guint32 rate;

    proto_tree_add_item(tree, hf_mpeg_descr_max_bitrate_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    rate = tvb_get_ntoh24(tvb, offset) & MPEG_DESCR_MAX_BITRATE_MASK;
    rate_item = proto_tree_add_item(tree, hf_mpeg_descr_max_bitrate, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(rate_item, " (%u bytes/sec)", rate * 50);
}

/* 0x10 Smoothing Buffer Descriptor */
static int hf_mpeg_descr_smoothing_buffer_reserved1 = -1;
static int hf_mpeg_descr_smoothing_buffer_leak_rate = -1;
static int hf_mpeg_descr_smoothing_buffer_reserved2 = -1;
static int hf_mpeg_descr_smoothing_buffer_size = -1;

#define MPEG_DESCR_SMOOTHING_BUFFER_RESERVED1_MASK  0xC00000
#define MPEG_DESCR_SMOOTHING_BUFFER_LEAK_RATE_MASK  0x3FFFFF
#define MPEG_DESCR_SMOOTHING_BUFFER_RESERVED2_MASK  0xC00000
#define MPEG_DESCR_SMOOTHING_BUFFER_SIZE_MASK       0x3FFFFF

static void
proto_mpeg_descriptor_dissect_smoothing_buffer(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_item *leak_rate_item;

    guint32 leak_rate;

    proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_reserved1, tvb, offset, 3, ENC_BIG_ENDIAN);
    leak_rate = tvb_get_ntoh24(tvb, offset) & MPEG_DESCR_SMOOTHING_BUFFER_LEAK_RATE_MASK;
    leak_rate_item = proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_leak_rate, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(leak_rate_item, " (%u bytes/sec)", leak_rate * 400 / 8);
    offset += 3;

    proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_reserved2, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_size, tvb, offset, 3, ENC_BIG_ENDIAN);

}

/* 0x11 STD Descriptor */
static int hf_mpeg_descr_std_reserved = -1;
static int hf_mpeg_descr_std_leak_valid = -1;

#define MPEG_DESCR_STD_RESERVED_MASK    0xFE
#define MPEG_DESCR_STD_LEAK_VALID_MASK  0x01

static void
proto_mpeg_descriptor_dissect_std(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_std_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_std_leak_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x13 Carousel Identifier Descriptor */
static int hf_mpeg_descr_carousel_identifier_id = -1;
static int hf_mpeg_descr_carousel_identifier_format_id = -1;
static int hf_mpeg_descr_carousel_identifier_module_version = -1;
static int hf_mpeg_descr_carousel_identifier_module_id = -1;
static int hf_mpeg_descr_carousel_identifier_block_size = -1;
static int hf_mpeg_descr_carousel_identifier_module_size = -1;
static int hf_mpeg_descr_carousel_identifier_compression_method = -1;
static int hf_mpeg_descr_carousel_identifier_original_size = -1;
static int hf_mpeg_descr_carousel_identifier_timeout = -1;
static int hf_mpeg_descr_carousel_identifier_object_key_len = -1;
static int hf_mpeg_descr_carousel_identifier_object_key_data = -1;
static int hf_mpeg_descr_carousel_identifier_private = -1;

static const value_string mpeg_descr_carousel_identifier_format_id_vals[] = {
    { 0x00, "No Format Specifier" },
    { 0x01, "Format Specifier" },

    { 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_carousel_identifier(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint  key_len;
    guint8 format_id;
    guint  private_len = 0;

    proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    format_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_format_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (format_id == 0x01) {
        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_module_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_module_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_block_size, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_module_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_compression_method, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_original_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        key_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_object_key_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_object_key_data, tvb, offset, key_len, ENC_NA);
        offset += key_len;

        if (len > (key_len + 20))
            private_len = len - 20 - key_len;

    } else {
        if (len > 5)
            private_len = len - 5;
    }

    if (private_len)
        proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_private, tvb, offset, private_len, ENC_NA);

}

/* 0x14 Association Tag Descriptor */
static int hf_mpeg_descr_association_tag = -1;
static int hf_mpeg_descr_association_tag_use = -1;
static int hf_mpeg_descr_association_tag_selector_len = -1;
static int hf_mpeg_descr_association_tag_transaction_id = -1;
static int hf_mpeg_descr_association_tag_timeout = -1;
static int hf_mpeg_descr_association_tag_selector_bytes = -1;
static int hf_mpeg_descr_association_tag_private_bytes = -1;

static void
proto_mpeg_descriptor_dissect_association_tag(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint   end = offset + len;
    guint16 use;
    guint8  selector_len;

    proto_tree_add_item(tree, hf_mpeg_descr_association_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    use = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_association_tag_use, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    selector_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_association_tag_selector_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset ++;

    if (use == 0x00) {
        if (selector_len != 8)
            return;
        proto_tree_add_item(tree, hf_mpeg_descr_association_tag_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_mpeg_descr_association_tag_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

    } else {
        proto_tree_add_item(tree, hf_mpeg_descr_association_tag_selector_bytes, tvb, offset, selector_len, ENC_NA);
        offset += selector_len;
    }

    if (offset < end)
        proto_tree_add_item(tree, hf_mpeg_descr_association_tag_private_bytes, tvb, offset, end - offset, ENC_NA);
}

/* 0x28 AVC Video Descriptor */
static int hf_mpeg_descr_avc_vid_profile_idc = -1;
static int hf_mpeg_descr_avc_vid_constraint_set0_flag = -1;
static int hf_mpeg_descr_avc_vid_constraint_set1_flag = -1;
static int hf_mpeg_descr_avc_vid_constraint_set2_flag = -1;
static int hf_mpeg_descr_avc_vid_compatible_flags = -1;
static int hf_mpeg_descr_avc_vid_level_idc = -1;
static int hf_mpeg_descr_avc_vid_still_present = -1;
static int hf_mpeg_descr_avc_vid_24h_picture_flag = -1;
static int hf_mpeg_descr_avc_vid_reserved = -1;

#define MPEG_DESCR_AVC_VID_CONSTRAINT_SET0_FLAG_MASK    0x80
#define MPEG_DESCR_AVC_VID_CONSTRAINT_SET1_FLAG_MASK    0x40
#define MPEG_DESCR_AVC_VID_CONSTRAINT_SET2_FLAG_MASK    0x20
#define MPEG_DESCR_AVC_VID_COMPATIBLE_FLAGS_MASK        0x1F
#define MPEG_DESCR_AVC_VID_STILL_PRESENT_MASK           0x80
#define MPEG_DESCR_AVC_VID_24H_PICTURE_FLAG_MASK        0x40
#define MPEG_DESCR_AVC_VID_RESERVED_MASK                0x3F

static void
proto_mpeg_descriptor_dissect_avc_vid(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_profile_idc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_constraint_set0_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_constraint_set1_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_constraint_set2_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_compatible_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_level_idc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_still_present, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_24h_picture_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_avc_vid_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x40 Network Name Descriptor */
static int hf_mpeg_descr_network_name_descriptor = -1;

static void
proto_mpeg_descriptor_dissect_network_name(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_network_name_descriptor, tvb, offset, len, ENC_ASCII|ENC_NA);
}

/* 0x41 Service List Descriptor */
static int hf_mpeg_descr_service_list_id = -1;
static int hf_mpeg_descr_service_list_type = -1;

static gint ett_mpeg_descriptor_service_list = -1;

static void
proto_mpeg_descriptor_dissect_service_list(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint   end = offset + len;
    guint16 svc_id;

    proto_tree *svc_tree;


    while (offset < end) {
        svc_id = tvb_get_ntohs(tvb, offset);

        svc_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3,
                    ett_mpeg_descriptor_service_list, NULL, "Service 0x%02x", svc_id);

        proto_tree_add_item(svc_tree, hf_mpeg_descr_service_list_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(svc_tree, hf_mpeg_descr_service_list_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
}

/* 0x42 Stuffing Descriptor */
static int hf_mpeg_descr_stuffing = -1;

static void
proto_mpeg_descriptor_stuffing(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_stuffing, tvb, offset, len, ENC_NA);
}

/* 0x43 Satellite Delivery System Descriptor */
static int hf_mpeg_descr_satellite_delivery_frequency = -1;
static int hf_mpeg_descr_satellite_delivery_orbital_position = -1;
static int hf_mpeg_descr_satellite_delivery_west_east_flag = -1;
static int hf_mpeg_descr_satellite_delivery_polarization = -1;
static int hf_mpeg_descr_satellite_delivery_roll_off = -1;
static int hf_mpeg_descr_satellite_delivery_zero = -1;
static int hf_mpeg_descr_satellite_delivery_modulation_system = -1;
static int hf_mpeg_descr_satellite_delivery_modulation_type = -1;
static int hf_mpeg_descr_satellite_delivery_symbol_rate = -1;
static int hf_mpeg_descr_satellite_delivery_fec_inner = -1;

#define MPEG_DESCR_SATELLITE_DELIVERY_WEST_EAST_FLAG_MASK       0x80
#define MPEG_DESCR_SATELLITE_DELIVERY_POLARIZATION_MASK         0x60
#define MPEG_DESCR_SATELLITE_DELIVERY_ROLL_OFF_MASK             0x18
#define MPEG_DESCR_SATELLITE_DELIVERY_ZERO_MASK                 0x18
#define MPEG_DESCR_SATELLITE_DELIVERY_MODULATION_SYSTEM_MASK    0x04
#define MPEG_DESCR_SATELLITE_DELIVERY_MODULATION_TYPE_MASK      0x03
#define MPEG_DESCR_SATELLITE_DELIVERY_FEC_INNER_MASK            0x0F

static const value_string mpeg_descr_satellite_delivery_west_east_flag_vals[] = {
    { 0x0, "West" },
    { 0x1, "East" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_satellite_delivery_polarization_vals[] = {
    { 0x0, "Linear - Horizontal" },
    { 0x1, "Linear - Vertical" },
    { 0x2, "Circular - Left" },
    { 0x3, "Circular - Right" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_satellite_delivery_roll_off_vals[] = {
    { 0x0, "alpha = 0,35" },
    { 0x1, "alpha = 0,25" },
    { 0x2, "alpha = 0,20" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_satellite_delivery_modulation_system_vals[] = {
    { 0x0, "DVB-S" },
    { 0x1, "DVB-S2" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_satellite_delivery_modulation_type_vals[] = {
    { 0x0, "Auto" },
    { 0x1, "QPSK" },
    { 0x2, "8PSK" },
    { 0x3, "16-QAM (n/a for DVB-S2)" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_satellite_delivery_fec_inner_vals[] = {
    { 0x0, "Not defined" },
    { 0x1, "1/2 convolutional code rate" },
    { 0x2, "2/3 convolutional code rate" },
    { 0x3, "3/4 convolutional code rate" },
    { 0x4, "5/6 convolutional code rate" },
    { 0x5, "7/8 convolutional code rate" },
    { 0x6, "8/9 convolutional code rate" },
    { 0x7, "3/5 convolutional code rate" },
    { 0x8, "4/5 convolutional code rate" },
    { 0x9, "9/10 convolutional code rate" },
    { 0xF, "No convolutional coding" },

    { 0x0, NULL }
};
static value_string_ext mpeg_descr_satellite_delivery_fec_inner_vals_ext =
    VALUE_STRING_EXT_INIT(mpeg_descr_satellite_delivery_fec_inner_vals);

static void
proto_mpeg_descriptor_dissect_satellite_delivery(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

    double frequency, symbol_rate;
    float orbital_position;
    guint8  modulation_system;

    frequency = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset)) * 10.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1)) / 10.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+2)) / 1000.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+3)) / 100000.0;
    proto_tree_add_double_format_value(tree, hf_mpeg_descr_satellite_delivery_frequency,
            tvb, offset, 4, frequency, "%f GHz", frequency);
    offset += 4;

    orbital_position = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset)) * 10.0f +
                       MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1)) / 10.0f;
    proto_tree_add_float_format_value(tree, hf_mpeg_descr_satellite_delivery_orbital_position,
            tvb, offset, 2, orbital_position, "%f degrees", orbital_position);
    offset += 2;

    modulation_system = tvb_get_guint8(tvb, offset) & MPEG_DESCR_SATELLITE_DELIVERY_MODULATION_SYSTEM_MASK;

    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_west_east_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_polarization, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (modulation_system)
        proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_roll_off, tvb, offset, 1, ENC_BIG_ENDIAN);
    else
        proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_zero, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_modulation_system, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_modulation_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    symbol_rate = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset)) * 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1)) / 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+2)) / 1000.0 +
                  /* symbol rate is 28 bits, only the upper 4 bits of this byte are used */
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+3)>>4) / 10000.0;
    proto_tree_add_double_format_value(tree, hf_mpeg_descr_satellite_delivery_symbol_rate,
            tvb, offset, 4, symbol_rate, "%3.4f MSym/s", symbol_rate);
    offset += 3;

    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_fec_inner, tvb, offset, 1, ENC_BIG_ENDIAN);

}

/* 0x44 Cable Delivery System Descriptor */
static int hf_mpeg_descr_cable_delivery_frequency = -1;
static int hf_mpeg_descr_cable_delivery_reserved = -1;
static int hf_mpeg_descr_cable_delivery_fec_outer = -1;
static int hf_mpeg_descr_cable_delivery_modulation = -1;
static int hf_mpeg_descr_cable_delivery_symbol_rate = -1;
static int hf_mpeg_descr_cable_delivery_fec_inner = -1;

#define MPEG_DESCR_CABLE_DELIVERY_RESERVED_MASK     0xFFF0
#define MPEG_DESCR_CABLE_DELIVERY_FEC_OUTER_MASK    0x000F
#define MPEG_DESCR_CABLE_DELIVERY_FEC_INNER_MASK    0x0F

static const value_string mpeg_descr_cable_delivery_fec_outer_vals[] = {
    { 0x0, "Not defined" },
    { 0x1, "No outer FEC coding" },
    { 0x2, "RS(204/188)" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_cable_delivery_modulation_vals[] = {
    { 0x00, "Not defined" },
    { 0x01, "16-QAM" },
    { 0x02, "32-QAM" },
    { 0x03, "64-QAM" },
    { 0x04, "128-QAM" },
    { 0x05, "256-QAM" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_cable_delivery_fec_inner_vals[] = {
    { 0x0, "Not defined" },
    { 0x1, "1/2 convolutional code rate" },
    { 0x2, "2/3 convolutional code rate" },
    { 0x3, "3/4 convolutional code rate" },
    { 0x4, "5/6 convolutional code rate" },
    { 0x5, "7/8 convolutional code rate" },
    { 0x6, "8/9 convolutional code rate" },
    { 0x7, "3/5 convolutional code rate" },
    { 0x8, "4/5 convolutional code rate" },
    { 0x9, "9/10 convolutional code rate" },
    { 0xF, "No convolutional coding" },

    { 0x0, NULL }
};
static value_string_ext mpeg_descr_cable_delivery_fec_inner_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_cable_delivery_fec_inner_vals);

static void
proto_mpeg_descriptor_dissect_cable_delivery(tvbuff_t *tvb, guint offset, proto_tree *tree) {

    double frequency, symbol_rate;

    frequency = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset)) * 100.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1)) +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+2)) / 100.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+3)) / 10000.0;
    proto_tree_add_double_format_value(tree, hf_mpeg_descr_cable_delivery_frequency,
            tvb, offset, 4, frequency, "%4.4f MHz", frequency);
    offset += 4;

    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_fec_outer, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_modulation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    symbol_rate = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset)) * 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1)) / 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+2)) / 1000.0 +
                  /* symbol rate is 28 bits, only the upper 4 bits of this byte are used */
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+3)>>4) / 10000.0;
    proto_tree_add_double_format_value(tree, hf_mpeg_descr_cable_delivery_symbol_rate,
            tvb, offset, 4, symbol_rate, "%3.4f MSymbol/s", symbol_rate);
    offset += 3;
    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_fec_inner, tvb, offset, 1, ENC_BIG_ENDIAN);


}

/* 0x45 VBI Data Descriptor */
static int hf_mpeg_descr_vbi_data_service_id = -1;
static int hf_mpeg_descr_vbi_data_descr_len = -1;
static int hf_mpeg_descr_vbi_data_reserved1 = -1;
static int hf_mpeg_descr_vbi_data_field_parity = -1;
static int hf_mpeg_descr_vbi_data_line_offset = -1;
static int hf_mpeg_descr_vbi_data_reserved2 = -1;

#define MPEG_DESCR_VBI_DATA_RESERVED1_MASK  0xC0
#define MPEG_DESCR_VBI_DATA_FIELD_PARITY_MASK   0x20
#define MPEG_DESCR_VBI_DATA_LINE_OFFSET_MASK    0x1F

static gint ett_mpeg_descriptor_vbi_data_service = -1;

static const value_string mpeg_descr_vbi_data_service_id_vals[] = {

    { 0x00, "Reserved" },
    { 0x01, "EBU Teletext" },
    { 0x02, "Inverted Teletext" },
    { 0x03, "Reserved" },
    { 0x04, "VPS" },
    { 0x05, "WSS" },
    { 0x06, "Closed Captioning" },
    { 0x07, "Monochrome 4:2:2 samples" },

    { 0, NULL }
};

static const value_string mpeg_descr_vbi_data_field_parity_vals[] = {
    { 0x00, "Second (even) field of frame" },
    { 0x01, "First (odd) field of frame" },

    { 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_vbi_data(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{

    guint8 svc_id, svc_len;
    guint  end = offset + len, svc_end;

    proto_tree *svc_tree;

    while (offset < end) {
        svc_id  = tvb_get_guint8(tvb, offset);
        svc_len = tvb_get_guint8(tvb, offset + 1);
        svc_tree = proto_tree_add_subtree_format(tree, tvb, offset, svc_len + 2,
                    ett_mpeg_descriptor_vbi_data_service, NULL, "Service 0x%02x", svc_id);

        proto_tree_add_item(svc_tree, hf_mpeg_descr_vbi_data_service_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(svc_tree, hf_mpeg_descr_vbi_data_descr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        switch (svc_id) {
            case 0x01:
            case 0x02:
            case 0x04:
            case 0x05:
            case 0x06:
            case 0x07:
                svc_end = offset + svc_len;
                while (offset < svc_end) {
                    proto_tree_add_item(svc_tree, hf_mpeg_descr_vbi_data_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(svc_tree, hf_mpeg_descr_vbi_data_field_parity, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(svc_tree, hf_mpeg_descr_vbi_data_line_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }
                break;
            default:
                proto_tree_add_item(svc_tree, hf_mpeg_descr_vbi_data_reserved2, tvb, offset, svc_len, ENC_NA);
                offset += svc_len;
                break;
        }

    }
}

/* 0x47 Bouquet Name Descriptor */
static int hf_mpeg_descr_bouquet_name = -1;

static void
proto_mpeg_descriptor_dissect_bouquet_name(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_bouquet_name, tvb, offset, len, ENC_ASCII|ENC_NA);
}

/* 0x48 Service Descriptor */
static int hf_mpeg_descr_service_type = -1;
static int hf_mpeg_descr_service_provider_name_length = -1;
static int hf_mpeg_descr_service_provider_name_encoding = -1;
static int hf_mpeg_descr_service_provider = -1;
static int hf_mpeg_descr_service_name_length = -1;
static int hf_mpeg_descr_service_name_encoding = -1;
static int hf_mpeg_descr_service_name = -1;

static const value_string mpeg_descr_service_type_vals[] = {

    { 0x00, "reserved" },
    { 0x01, "digital television service" },
    { 0x02, "digital radio sound service" },
    { 0x03, "Teletext service" },
    { 0x04, "NVOD reference service" },
    { 0x05, "NVOD time-shifted service" },
    { 0x06, "mosaic service" },
    { 0x07, "FM radio service" },
    { 0x08, "DVB SRM service" },
    { 0x09, "reserved" },
    { 0x0A, "advanced codec digital radio sound service" },
    { 0x0B, "advanced codec mosaic service" },
    { 0x0C, "data broadcast service" },
    { 0x0D, "reserved for Common Interface Usage (EN 50221)" },
    { 0x0E, "RCS Map (see EN 301 790)" },
    { 0x0F, "RCS FLS (see EN 301 790)" },
    { 0x10, "DVB MHP service" },
    { 0x11, "MPEG-2 HD digital television service" },
    { 0x16, "advanced codec SD digital television service" },
    { 0x17, "advanced codec SD NVOD time-shifted service" },
    { 0x18, "advanced codec SD NVOD reference service" },
    { 0x19, "advanced codec HD digital television service" },
    { 0x1A, "advanced codec HD NVOD time-shifted service" },
    { 0x1F, "HEVC digital television service" },

    { 0x00, NULL }
};
/* global variable that's shared e.g. with DVB-CI */
value_string_ext mpeg_descr_service_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_service_type_vals);

static void
proto_mpeg_descriptor_dissect_service(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint8          prov_len, name_len;
    guint           enc_len;
    dvb_encoding_e  encoding;

    proto_tree_add_item(tree, hf_mpeg_descr_service_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    prov_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_service_provider_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (prov_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, prov_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_service_provider_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(tree, hf_mpeg_descr_service_provider,
                tvb, offset+enc_len, prov_len-enc_len, dvb_enc_to_item_enc(encoding));
    }
    offset += prov_len;

    name_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_service_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (name_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, name_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_service_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(tree, hf_mpeg_descr_service_name,
                tvb, offset+enc_len, name_len-enc_len, dvb_enc_to_item_enc(encoding));
    }

}

/* 0x4A Linkage Descriptor */
static int hf_mpeg_descr_linkage_transport_stream_id = -1;
static int hf_mpeg_descr_linkage_original_network_id = -1;
static int hf_mpeg_descr_linkage_service_id = -1;
static int hf_mpeg_descr_linkage_linkage_type = -1;

static int hf_mpeg_descr_linkage_hand_over_type = -1;
static int hf_mpeg_descr_linkage_reserved1 = -1;
static int hf_mpeg_descr_linkage_origin_type = -1;
static int hf_mpeg_descr_linkage_network_id = -1;
static int hf_mpeg_descr_linkage_initial_service_id = -1;

static int hf_mpeg_descr_linkage_target_event_id = -1;
static int hf_mpeg_descr_linkage_target_listed = -1;
static int hf_mpeg_descr_linkage_event_simulcast = -1;
static int hf_mpeg_descr_linkage_reserved2 = -1;

static int hf_mpeg_descr_linkage_interactive_network_id = -1;
static int hf_mpeg_descr_linkage_population_id_loop_count = -1;
static int hf_mpeg_descr_linkage_population_id = -1;
static int hf_mpeg_descr_linkage_population_id_base = -1;
static int hf_mpeg_descr_linkage_population_id_mask = -1;

static int hf_mpeg_descr_linkage_private_data_byte = -1;

static gint ett_mpeg_descriptor_linkage_population_id = -1;

#define MPEG_DESCR_LINKAGE_HAND_OVER_TYPE_MASK  0xF0
#define MPEG_DESCR_LINKAGE_HAND_OVER_TYPE_SHIFT 0x04
#define MPEG_DESCR_LINKAGE_RESERVED1_MASK   0x0E
#define MPEG_DESCR_LINKAGE_ORIGIN_TYPE_MASK 0x01

#define MPEG_DESCR_LINKAGE_TARGET_LISTED_MASK   0x80
#define MPEG_DESCR_LINKAGE_EVENT_SIMULCAST_MASK 0x40
#define MPEG_DESCR_LINKAGE_RESERVED2_MASK   0x3F

static const value_string mpeg_descr_linkage_linkage_type_vals[] = {
    { 0x01, "Information service" },
    { 0x02, "EPG service" },
    { 0x03, "CA replacement service" },
    { 0x04, "TS containing complete Network/Bouquet SI" },
    { 0x05, "Service replacement service" },
    { 0x06, "Data broadcast service" },
    { 0x07, "RCS Map" },
    { 0x08, "Mobile hand-over" },
    { 0x09, "System Software Update Service" },
    { 0x0A, "TS containing SSU BAT or NIT" },
    { 0x0B, "IP/MAC Notification Service" },
    { 0x0C, "TS containing INT BAT or NIT" },
    { 0x0D, "Event linkage" },
    { 0x81, "RCS FLS" },

    { 0x00, NULL }
};
static value_string_ext mpeg_descr_linkage_linkage_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_linkage_linkage_type_vals);

#if 0
static const value_string mpeg_descr_linkage_hand_over_type_vals[] = {
    { 0x01, "DVB hand-over to an identical service in a neighbouring country" },
    { 0x02, "DVB hand-over to a local variation of the same service" },
    { 0x03, "DVB hand-over to an associated service" },

    { 0x00, NULL }
};
#endif

static const value_string mpeg_descr_linkage_origin_type_vals[] = {
    { 0x0, "NIT" },
    { 0x1, "SDT" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_linkage_target_listed_vals[] = {
    { 0x0, "Service may not be included in SDT" },
    { 0x1, "Service should be included in SDT" },

    { 0x0, NULL}
};

static const value_string mpeg_descr_linkage_event_simulcast_vals[] = {
    { 0x0, "Events are offset in time" },
    { 0x1, "Target and source events are being simulcast" },

    { 0x0, NULL }
};

static void
proto_mpeg_descriptor_dissect_linkage(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{

    guint8  linkage_type, hand_over_type, origin_type;
    guint   end = offset + len;
    guint   population_id_loop_count;
    guint16 population_id_base, population_id_mask;

    proto_item *pi;
    proto_tree *population_tree;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_transport_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_original_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_linkage_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    linkage_type = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (linkage_type == 0x08) {
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_hand_over_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_origin_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        hand_over_type = (tvb_get_guint8(tvb, offset) & MPEG_DESCR_LINKAGE_HAND_OVER_TYPE_MASK) >> MPEG_DESCR_LINKAGE_HAND_OVER_TYPE_SHIFT;
        origin_type = tvb_get_guint8(tvb, offset) & MPEG_DESCR_LINKAGE_ORIGIN_TYPE_MASK;
        offset += 1;

        if ((hand_over_type == 1) || (hand_over_type == 2) || (hand_over_type == 3)) {
            proto_tree_add_item(tree, hf_mpeg_descr_linkage_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

        if (origin_type) {
            proto_tree_add_item(tree, hf_mpeg_descr_linkage_initial_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

    } else if (linkage_type == 0x0D) {
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_target_event_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_mpeg_descr_linkage_target_listed, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_event_simulcast, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else if (linkage_type == 0x81) {
        /* linkage type 0x81 is "user defined" in the DVB-SI spec (EN 300468)
           it is defined in the interaction channel spec (EN 301790)
           it seems that in practice, 0x81 is also used for other purposes than interaction channel
           if the following data really belongs to interaction channel, we need at least another 7 bytes */
        if (offset+7>end)
            return;

        proto_tree_add_item(tree, hf_mpeg_descr_linkage_interactive_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        population_id_loop_count = tvb_get_guint8(tvb, offset) + 1;
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_population_id_loop_count, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        while (population_id_loop_count--) {
            population_id_base = tvb_get_ntohs(tvb, offset);
            population_id_mask = tvb_get_ntohs(tvb, offset + 2);
            pi = proto_tree_add_uint_format_value(tree, hf_mpeg_descr_linkage_population_id, tvb, offset, 4,
                    population_id_base<<16|population_id_mask,
                    "0x%04x / 0x%04x", population_id_base, population_id_mask);
            population_tree = proto_item_add_subtree(pi, ett_mpeg_descriptor_linkage_population_id);

            proto_tree_add_item(population_tree, hf_mpeg_descr_linkage_population_id_base, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(population_tree, hf_mpeg_descr_linkage_population_id_mask, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

    }

    if (end - offset > 0)
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_private_data_byte, tvb, offset, end - offset, ENC_NA);
}

/* 0x4D Short Event Descriptor */
static int hf_mpeg_descr_short_event_lang_code = -1;
static int hf_mpeg_descr_short_event_name_length = -1;
static int hf_mpeg_descr_short_event_name_encoding = -1;
static int hf_mpeg_descr_short_event_name = -1;
static int hf_mpeg_descr_short_event_text_length = -1;
static int hf_mpeg_descr_short_event_text_encoding = -1;
static int hf_mpeg_descr_short_event_text = -1;

static void
proto_mpeg_descriptor_dissect_short_event(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint8          name_len, text_len;
    guint           enc_len;
    dvb_encoding_e  encoding;

    proto_tree_add_item(tree, hf_mpeg_descr_short_event_lang_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
    offset += 3;

    name_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_short_event_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (name_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, name_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_short_event_name_encoding, tvb, offset, enc_len, encoding);
        proto_tree_add_item(tree, hf_mpeg_descr_short_event_name,
                tvb, offset+enc_len, name_len-enc_len, dvb_enc_to_item_enc(encoding));
    }
    offset += name_len;

    text_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_short_event_text_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (text_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, text_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_short_event_text_encoding, tvb, offset, enc_len, encoding);
        proto_tree_add_item(tree, hf_mpeg_descr_short_event_text,
                tvb, offset+enc_len, text_len-enc_len, dvb_enc_to_item_enc(encoding));
    }
}

/* 0x4E Extended Event Descriptor */
static int hf_mpeg_descr_extended_event_descriptor_number = -1;
static int hf_mpeg_descr_extended_event_last_descriptor_number = -1;
static int hf_mpeg_descr_extended_event_lang_code = -1;
static int hf_mpeg_descr_extended_event_length_of_items = -1;
static int hf_mpeg_descr_extended_event_item_description_length = -1;
static int hf_mpeg_descr_extended_event_item_description_char = -1;
static int hf_mpeg_descr_extended_event_item_length = -1;
static int hf_mpeg_descr_extended_event_item_char = -1;
static int hf_mpeg_descr_extended_event_text_length = -1;
static int hf_mpeg_descr_extended_event_text_encoding = -1;
static int hf_mpeg_descr_extended_event_text = -1;

#define MPEG_DESCR_EXTENDED_EVENT_DESCRIPTOR_NUMBER_MASK    0xF0
#define MPEG_DESCR_EXTENDED_EVENT_LAST_DESCRIPTOR_NUMBER_MASK   0x0F

static gint ett_mpeg_descriptor_extended_event_item = -1;

static void
proto_mpeg_descriptor_dissect_extended_event(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

    guint8          items_len, item_descr_len, item_len, text_len;
    guint           items_end;
    proto_tree     *item_tree;
    guint           enc_len;
    dvb_encoding_e  encoding;

    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_descriptor_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_last_descriptor_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_lang_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
    offset += 3;

    items_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_length_of_items, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    items_end = offset + items_len;

    while (offset < items_end) {
        item_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mpeg_descriptor_extended_event_item, NULL, "Item");

        item_descr_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_description_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_description_char, tvb, offset, item_descr_len, ENC_ASCII|ENC_NA);
        offset += item_descr_len;

        item_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_char, tvb, offset, item_len, ENC_ASCII|ENC_NA);
        offset += item_len;
    }

    text_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_text_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (text_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, text_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_extended_event_text_encoding, tvb, offset, enc_len, encoding);
        proto_tree_add_item(tree, hf_mpeg_descr_extended_event_text,
                tvb, offset+enc_len, text_len-enc_len, dvb_enc_to_item_enc(encoding));
    }

}

/* 0x50 Component Descriptor */
static int hf_mpeg_descr_component_reserved = -1;
static int hf_mpeg_descr_component_stream_content = -1;
static int hf_mpeg_descr_component_type = -1;
static int hf_mpeg_descr_component_content_type = -1;
static int hf_mpeg_descr_component_tag = -1;
static int hf_mpeg_descr_component_lang_code = -1;
static int hf_mpeg_descr_component_text = -1;

#define MPEG_DESCR_COMPONENT_RESERVED_MASK      0xF0
#define MPEG_DESCR_COMPONENT_STREAM_CONTENT_MASK    0x0F
#define MPEG_DESCR_COMPONENT_CONTENT_TYPE_MASK      0x0FFF

static gint ett_mpeg_descriptor_component_content_type = -1;

static const value_string mpeg_descr_component_stream_content_vals[] = {

    { 0x01, "Video (MPEG-2)" },
    { 0x02, "Audio (MPEG-1 Layer 2)" },
    { 0x03, "EBU Data (Teletext, Subtitle, ...)" },
    { 0x04, "Audio (AC-3)" },
    { 0x05, "Video (H.264/AVC)" },
    { 0x06, "Audio (HE-AAC)" },
    { 0x07, "Audio (DTS)" },
    { 0x09, "HEVC" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_component_content_type_vals[] = {

    { 0x0101, "MPEG-2 video, 4:3 aspect ratio, 25 Hz" },
    { 0x0102, "MPEG-2 video, 16:9 aspect ratio with pan vectors, 25 Hz" },
    { 0x0103, "MPEG-2 video, 16:9 aspect ratio without pan vectors, 25 Hz" },
    { 0x0104, "MPEG-2 video, > 16:9 aspect ratio, 25 Hz" },
    { 0x0105, "MPEG-2 video, 4:3 aspect ratio, 30 Hz" },
    { 0x0106, "MPEG-2 video, 16:9 aspect ratio with pan vectors, 30 Hz" },
    { 0x0107, "MPEG-2 video, 16:9 aspect ratio without pan vectors, 30 Hz" },
    { 0x0108, "MPEG-2 video, > 16:9 aspect ratio, 30 Hz" },
    { 0x0109, "MPEG-2 high definition video, 4:3 aspect ratio, 25 Hz" },
    { 0x010A, "MPEG-2 high definition video, 16:9 aspect ratio with pan vectors, 25 Hz" },
    { 0x010B, "MPEG-2 high definition video, 16:9 aspect ratio without pan vectors, 25 Hz" },
    { 0x010C, "MPEG-2 high definition video, > 16:9 aspect ratio, 25 Hz" },
    { 0x010D, "MPEG-2 high definition video, 4:3 aspect ratio, 30 Hz" },
    { 0x010E, "MPEG-2 high definition video, 16:9 aspect ratio with pan vectors, 30 Hz" },
    { 0x010F, "MPEG-2 high definition video, 16:9 aspect ratio without pan vectors, 30 Hz" },
    { 0x0110, "MPEG-2 high definition video, > 16:9 aspect ratio, 30 Hz" },
    { 0x0201, "MPEG-1 Layer 2 audio, single mono channel" },
    { 0x0202, "MPEG-1 Layer 2 audio, dual mono channel" },
    { 0x0203, "MPEG-1 Layer 2 audio, stereo" },
    { 0x0204, "MPEG-1 Layer 2 audio, multi-lingual, multi-channel" },
    { 0x0205, "MPEG-1 Layer 2 audio, surround sound" },
    { 0x0240, "MPEG-1 Layer 2 audio description for the visually impaired" },
    { 0x0241, "MPEG-1 Layer 2 audio for the hard of hearing" },
    { 0x0242, "receiver-mixed supplementary audio as per annex E of TS 101 154 [9]" },
    { 0x0247, "MPEG-1 Layer 2 audio, receiver mix audio description as per annex E of TS 101 154 [9]" },
    { 0x0248, "MPEG-1 Layer 2 audio, broadcaster mix audio description" },
    { 0x0301, "EBU Teletext subtitles" },
    { 0x0302, "associated EBU Teletext" },
    { 0x0303, "VBI data" },
    { 0x0310, "DVB subtitles (normal) with no monitor aspect ratio criticality" },
    { 0x0311, "DVB subtitles (normal) for display on 4:3 aspect ratio monitor" },
    { 0x0312, "DVB subtitles (normal) for display on 16:9 aspect ratio monitor" },
    { 0x0313, "DVB subtitles (normal) for display on 2.21:1 aspect ratio monitor" },
    { 0x0314, "DVB subtitles (normal) for display on a high definition monitor" },
    { 0x0320, "DVB subtitles (for the hard of hearing) with no monitor aspect ratio criticality" },
    { 0x0321, "DVB subtitles (for the hard of hearing) for display on 4:3 aspect ratio monitor" },
    { 0x0322, "DVB subtitles (for the hard of hearing) for display on 16:9 aspect ratio monitor" },
    { 0x0323, "DVB subtitles (for the hard of hearing) for display on 2.21:1 aspect ratio monitor" },
    { 0x0324, "DVB subtitles (for the hard of hearing) for display on a high definition monitor" },
    { 0x0330, "Open (in-vision) sign language interpretation for the deaf" },
    { 0x0331, "Closed sign language interpretation for the deaf" },
    { 0x0340, "video up-sampled from standard definition source material" },
    { 0x0501, "H.264/AVC standard definition video, 4:3 aspect ratio, 25 Hz" },
    { 0x0503, "H.264/AVC standard definition video, 16:9 aspect ratio, 25 Hz" },
    { 0x0504, "H.264/AVC standard definition video, > 16:9 aspect ratio, 25 Hz" },
    { 0x0505, "H.264/AVC standard definition video, 4:3 aspect ratio, 30 Hz" },
    { 0x0507, "H.264/AVC standard definition video, 16:9 aspect ratio, 30 Hz" },
    { 0x0508, "H.264/AVC standard definition video, > 16:9 aspect ratio, 30 Hz" },
    { 0x050B, "H.264/AVC high definition video, 16:9 aspect ratio, 25 Hz" },
    { 0x050C, "H.264/AVC high definition video, > 16:9 aspect ratio, 25 Hz" },
    { 0x050F, "H.264/AVC high definition video, 16:9 aspect ratio, 30 Hz" },
    { 0x0510, "H.264/AVC high definition video, > 16:9 aspect ratio, 30 Hz" },
    { 0x0601, "HE-AAC audio, single mono channel" },
    { 0x0603, "HE-AAC audio, stereo" },
    { 0x0605, "HE-AAC audio, surround sound" },
    { 0x0640, "HE-AAC audio description for the visually impaired" },
    { 0x0641, "HE-AAC audio for the hard of hearing" },
    { 0x0642, "HE-AAC receiver-mixed supplementary audio as per annex E of TS 101 154 [9]" },
    { 0x0643, "HE-AAC v2 audio, stereo" },
    { 0x0644, "HE-AAC v2 audio description for the visually impaired" },
    { 0x0645, "HE-AAC v2 audio for the hard of hearing" },
    { 0x0646, "HE-AAC v2 receiver-mixed supplementary audio as per annex E of TS 101 154 [9]" },
    { 0x0647, "HE-AAC receiver mix audio description for the visually impaired" },
    { 0x0648, "HE-AAC broadcaster mix audio description for the visually impaired" },
    { 0x0649, "HE-AAC v2 receiver mix audio description for the visually impaired" },
    { 0x064A, "HE-AAC v2 broadcaster mix audio description for the visually impaired" },
    { 0x0801, "DVB SRM data" },
    { 0x0900, "HEVC Main Profile high definition video, 50 Hz" },
    { 0x0901, "HEVC Main 10 Profile high definition video, 50 Hz" },
    { 0x0902, "HEVC Main Profile high definition video, 60 Hz" },
    { 0x0903, "HEVC Main 10 Profile high definition video, 60 Hz" },
    { 0x0904, "HEVC ultra high definition video" },

    { 0x0, NULL }
};
static value_string_ext mpeg_descr_component_content_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_component_content_type_vals);

static void
proto_mpeg_descriptor_dissect_component(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{

    proto_item *cti;
    proto_tree *content_type_tree;

    proto_tree_add_item(tree, hf_mpeg_descr_component_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

    cti = proto_tree_add_item(tree, hf_mpeg_descr_component_content_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    content_type_tree = proto_item_add_subtree(cti, ett_mpeg_descriptor_component_content_type);

    proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_stream_content, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_component_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_component_lang_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
    offset += 3;

    if (offset < len)
        proto_tree_add_item(tree, hf_mpeg_descr_component_text, tvb, offset, len - offset, ENC_ASCII|ENC_NA);
}

/* 0x52 Stream Identifier Descriptor */
static int hf_mpeg_descr_stream_identifier_component_tag = -1;

static void
proto_mpeg_descriptor_dissect_stream_identifier(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_stream_identifier_component_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x53 CA Identifier Descriptor */
static int hf_mpeg_descr_ca_identifier_system_id = -1;

static void
proto_mpeg_descriptor_dissect_ca_identifier(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint end = offset + len;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_ca_identifier_system_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

}

/* 0x54 Content Descriptor */
static int hf_mpeg_descr_content_nibble = -1;
static int hf_mpeg_descr_content_nibble_level_1 = -1;
static int hf_mpeg_descr_content_nibble_level_2 = -1;
static int hf_mpeg_descr_content_user_byte = -1;

#define MPEG_DESCR_CONTENT_NIBBLE_LEVEL_1_MASK  0xF0
#define MPEG_DESCR_CONTENT_NIBBLE_LEVEL_2_MASK  0x0F

static gint ett_mpeg_descriptor_content_nibble = -1;

static const value_string mpeg_descr_content_nibble_vals[] = {

    { 0x10, "movie/drama (general)" },
    { 0x11, "detective/thriller" },
    { 0x12, "adventure/western/war" },
    { 0x13, "science fiction/fantasy/horror" },
    { 0x14, "comedy" },
    { 0x15, "soap/melodrama/folkloric" },
    { 0x16, "romance" },
    { 0x17, "serious/classical/religious/historical movie/drama" },
    { 0x18, "adult movie/drama" },
    { 0x1F, "user defined (movie/drama)" },

    { 0x20, "news/current affairs (general)" },
    { 0x21, "news/weather report" },
    { 0x22, "news magazine" },
    { 0x23, "documentary" },
    { 0x24, "discussion/interview/debate" },
    { 0x2F, "user defined (news/current affairs)" },

    { 0x30, "show/game show (general)" },
    { 0x31, "game show/quiz/contest" },
    { 0x32, "variety show" },
    { 0x33, "talk show" },
    { 0x3F, "user defined (show/game show)" },

    { 0x40, "sports (general)" },
    { 0x41, "special events (Olympic Games, World Cup, etc.)" },
    { 0x42, "sports magazines" },
    { 0x43, "football/soccer" },
    { 0x44, "tennis/squash" },
    { 0x45, "team sports (excluding football)" },
    { 0x46, "athletics" },
    { 0x47, "motor sport" },
    { 0x48, "water sport" },
    { 0x49, "winter sports" },
    { 0x4A, "equestrian" },
    { 0x4B, "martial sports" },
    { 0x4F, "user defined (sports)" },

    { 0x50, "children's/youth programmes (general)" },
    { 0x51, "pre-school children's programmes" },
    { 0x52, "entertainment programmes for 6 to14" },
    { 0x53, "entertainment programmes for 10 to 16" },
    { 0x54, "informational/educational/school programmes" },
    { 0x55, "cartoons/puppets" },
    { 0x5F, "user defined (children's/youth programmes)" },

    { 0x60, "music/ballet/dance (general)" },
    { 0x61, "rock/pop" },
    { 0x62, "serious music/classical music" },
    { 0x63, "folk/traditional music" },
    { 0x64, "jazz" },
    { 0x65, "musical/opera" },
    { 0x66, "ballet" },
    { 0x6F, "user defined (music/ballet/dance)" },

    { 0x70, "arts/culture (without music, general)" },
    { 0x71, "performing arts" },
    { 0x72, "fine arts" },
    { 0x73, "religion" },
    { 0x74, "popular culture/traditional arts" },
    { 0x75, "literature" },
    { 0x76, "film/cinema" },
    { 0x77, "experimental film/video" },
    { 0x78, "broadcasting/press" },
    { 0x79, "new media" },
    { 0x7A, "arts/culture magazines" },
    { 0x7B, "fashion" },
    { 0x7F, "user defined (arts/culture)" },

    { 0x80, "social/political issues/economics (general)" },
    { 0x81, "magazines/reports/documentary" },
    { 0x82, "economics/social advisory" },
    { 0x83, "remarkable people" },
    { 0x8F, "user defined (social/political issues/economics)" },

    { 0x90, "education/science/factual topics (general)" },
    { 0x91, "nature/animals/environment" },
    { 0x92, "technology/natural sciences" },
    { 0x93, "medicine/physiology/psychology" },
    { 0x94, "foreign countries/expeditions" },
    { 0x95, "social/spiritual sciences" },
    { 0x96, "further education" },
    { 0x97, "languages" },
    { 0x9F, "user defined (education/science/factual topics)" },

    { 0xA0, "leisure hobbies (general)" },
    { 0xA1, "tourism/travel" },
    { 0xA2, "handicraft" },
    { 0xA3, "motoring" },
    { 0xA4, "fitness and health" },
    { 0xA5, "cooking" },
    { 0xA6, "advertisement/shopping" },
    { 0xA7, "gardening" },
    { 0xAF, "user defined (leisure hobbies)" },

    { 0xB0, "original language" },
    { 0xB1, "black and white" },
    { 0xB2, "unpublished" },
    { 0xB3, "live broadcast" },
    { 0xBF, "user defined (special characteristics)" },

    { 0x00, NULL }
};
static value_string_ext mpeg_descr_content_nibble_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_content_nibble_vals);

static const value_string mpeg_descr_content_nibble_level_1_vals[] = {

    { 0x1, "Movie/Drama" },
    { 0x2, "News/Current affairs" },
    { 0x3, "Show/Game show" },
    { 0x4, "Sports" },
    { 0x5, "Children's/Youth programmes" },
    { 0x6, "Music/Ballet/Dance" },
    { 0x7, "Arts/Culture (without music)" },
    { 0x8, "Social/Political issues/Economics" },
    { 0x9, "Education/Science/Factual topics" },
    { 0xA, "Leisure hobbies" },
    { 0xB, "Special characteristics" },

    { 0x00, NULL }
};
static value_string_ext mpeg_descr_content_nibble_level_1_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_content_nibble_level_1_vals);

static void
proto_mpeg_descriptor_dissect_content(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    proto_item *ni;
    proto_tree *nibble_tree;

    guint end = offset + len;

    while (offset < end) {
        ni = proto_tree_add_item(tree, hf_mpeg_descr_content_nibble, tvb, offset, 1, ENC_BIG_ENDIAN);
        nibble_tree = proto_item_add_subtree(ni, ett_mpeg_descriptor_content_nibble);

        proto_tree_add_item(nibble_tree, hf_mpeg_descr_content_nibble_level_1, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(nibble_tree, hf_mpeg_descr_content_nibble_level_2, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_content_user_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

}

/* 0x55 Parental Rating Descriptor */
static int hf_mpeg_descr_parental_rating_country_code = -1;
static int hf_mpeg_descr_parental_rating_rating = -1;

static const value_string mpeg_descr_parental_rating_vals[] = {
    { 0x00, "Undefined" },
    { 0x01, "Minimum 4 year old" },
    { 0x02, "Minimum 5 year old" },
    { 0x03, "Minimum 6 year old" },
    { 0x04, "Minimum 7 year old" },
    { 0x05, "Minimum 8 year old" },
    { 0x06, "Minimum 9 year old" },
    { 0x07, "Minimum 10 year old" },
    { 0x08, "Minimum 11 year old" },
    { 0x09, "Minimum 12 year old" },
    { 0x0A, "Minimum 13 year old" },
    { 0x0B, "Minimum 14 year old" },
    { 0x0C, "Minimum 15 year old" },
    { 0x0D, "Minimum 16 year old" },
    { 0x0E, "Minimum 17 year old" },
    { 0x0F, "Minimum 18 year old" },

    { 0x00, NULL }
};
static value_string_ext mpeg_descr_parental_rating_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_parental_rating_vals);


static void
proto_mpeg_descriptor_dissect_parental_rating(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_parental_rating_country_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_mpeg_descr_parental_rating_rating, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x56 Teletext Descriptor */
static int hf_mpeg_descr_teletext_lang_code = -1;
static int hf_mpeg_descr_teletext_type = -1;
static int hf_mpeg_descr_teletext_magazine_number = -1;
static int hf_mpeg_descr_teletext_page_number = -1;

#define MPEG_DESCR_TELETEXT_TYPE_MASK           0xF8
#define MPEG_DESCR_TELETEXT_MAGAZINE_NUMBER_MASK    0x07

static const value_string mpeg_descr_teletext_type_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Initial Teletext Page" },
    { 0x02, "Teletext Subtitle Page" },
    { 0x03, "Additional Information Page" },
    { 0x04, "Programme Schedule Page" },
    { 0x05, "Teletext Subtitle Page for hearing impaired people" },

    { 0, NULL }

};

static void
proto_mpeg_descriptor_dissect_teletext(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint end = offset + len;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_teletext_lang_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_teletext_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_teletext_magazine_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_teletext_page_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
}

/* 0x58 Local Time Offset Descriptor */
static int hf_mpeg_descr_local_time_offset_country_code = -1;
static int hf_mpeg_descr_local_time_offset_region_id = -1;
static int hf_mpeg_descr_local_time_offset_reserved = -1;
static int hf_mpeg_descr_local_time_offset_polarity = -1;
static int hf_mpeg_descr_local_time_offset_offset = -1;
static int hf_mpeg_descr_local_time_offset_time_of_change = -1;
static int hf_mpeg_descr_local_time_offset_next_time_offset = -1;

#define MPEG_DESCR_LOCAL_TIME_OFFSET_COUNTRY_REGION_ID_MASK 0xFC
#define MPEG_DESCR_LOCAL_TIME_OFFSET_RESERVED_MASK      0x02
#define MPEG_DESCR_LOCAL_TIME_OFFSET_POLARITY           0x01

static const value_string mpeg_descr_local_time_offset_polarity_vals[] = {
    { 0x0, "Positive (local time ahead of UTC)" },
    { 0x1, "Negative (local time behind UTC)" },

    { 0x0, NULL }
};

static void
proto_mpeg_descriptor_dissect_local_time_offset(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint    end = offset + len;
    guint8   hour, min;
    nstime_t local_time_offset, time_of_change, next_time_offset;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_country_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_region_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_polarity, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        hour = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset));
        min = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1));
        nstime_set_zero(&local_time_offset);
        local_time_offset.secs = hour*60*60 + min*60;
        proto_tree_add_time_format_value(tree, hf_mpeg_descr_local_time_offset_offset,
                tvb, offset, 2, &local_time_offset, "%02d:%02d", hour, min);
        offset += 2;


        if (packet_mpeg_sect_mjd_to_utc_time(tvb, offset, &time_of_change) < 0) {
            proto_tree_add_time_format_value(tree, hf_mpeg_descr_local_time_offset_time_of_change, tvb, offset, 5, &time_of_change, "Unparseable time");
        } else {
            proto_tree_add_time(tree, hf_mpeg_descr_local_time_offset_time_of_change, tvb, offset, 5, &time_of_change);
        }
        offset += 5;

        hour = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset));
        min = MPEG_SECT_BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1));
        nstime_set_zero(&next_time_offset);
        next_time_offset.secs = hour*60*60 + min*60;
        proto_tree_add_time_format_value(tree, hf_mpeg_descr_local_time_offset_next_time_offset,
                tvb, offset, 2, &next_time_offset, "%02d:%02d", hour, min);
        offset += 2;
    }
}

/* 0x59 Subtitling Descriptor */
static int hf_mpeg_descr_subtitling_lang_code = -1;
static int hf_mpeg_descr_subtitling_type = -1;
static int hf_mpeg_descr_subtitling_composition_page_id = -1;
static int hf_mpeg_descr_subtitling_ancillary_page_id = -1;


static const value_string mpeg_descr_subtitling_type_vals[] = {
    { 0x01, "EBU Teletext subtitles" },
    { 0x02, "associated EBU Teletext" },
    { 0x03, "VBI data" },
    { 0x10, "DVB subtitles (normal) with no monitor aspect ratio criticality" },
    { 0x11, "DVB subtitles (normal) for display on 4:3 aspect ratio monitor" },
    { 0x12, "DVB subtitles (normal) for display on 16:9 aspect ratio monitor" },
    { 0x13, "DVB subtitles (normal) for display on 2.21:1 aspect ratio monitor" },
    { 0x14, "DVB subtitles (normal) for display on a high definition monitor" },
    { 0x20, "DVB subtitles (for the hard of hearing) with no monitor aspect ratio criticality" },
    { 0x21, "DVB subtitles (for the hard of hearing) for display on 4:3 aspect ratio monitor" },
    { 0x22, "DVB subtitles (for the hard of hearing) for display on 16:9 aspect ratio monitor" },
    { 0x23, "DVB subtitles (for the hard of hearing) for display on 2.21:1 aspect ratio monitor" },
    { 0x24, "DVB subtitles (for the hard of hearing) for display on a high definition monitor" },
    { 0x30, "Open (in-vision) sign language interpretation for the deaf" },
    { 0x31, "Closed sign language interpretation for the deaf" },
    { 0x40, "video up-sampled from standard definition source material" },

    { 0, NULL }
};
static value_string_ext mpeg_descr_subtitling_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_subtitling_type_vals);

static void
proto_mpeg_descriptor_dissect_subtitling(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint end = offset + len;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_subtitling_lang_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_subtitling_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_subtitling_composition_page_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_mpeg_descr_subtitling_ancillary_page_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

    }
}

/* 0x5A Terrestrial Delivery System Descriptor */
static int hf_mpeg_descr_terrestrial_delivery_centre_frequency = -1;
static int hf_mpeg_descr_terrestrial_delivery_bandwidth = -1;
static int hf_mpeg_descr_terrestrial_delivery_priority = -1;
static int hf_mpeg_descr_terrestrial_delivery_time_slicing_indicator = -1;
static int hf_mpeg_descr_terrestrial_delivery_mpe_fec_indicator = -1;
static int hf_mpeg_descr_terrestrial_delivery_reserved1 = -1;
static int hf_mpeg_descr_terrestrial_delivery_constellation = -1;
static int hf_mpeg_descr_terrestrial_delivery_hierarchy_information = -1;
static int hf_mpeg_descr_terrestrial_delivery_code_rate_hp_stream = -1;
static int hf_mpeg_descr_terrestrial_delivery_code_rate_lp_stream = -1;
static int hf_mpeg_descr_terrestrial_delivery_guard_interval = -1;
static int hf_mpeg_descr_terrestrial_delivery_transmission_mode = -1;
static int hf_mpeg_descr_terrestrial_delivery_other_frequency_flag = -1;
static int hf_mpeg_descr_terrestrial_delivery_reserved2 = -1;

#define MPEG_DESCR_TERRESTRIAL_DELIVERY_BANDWIDTH_MASK          0xE0
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_PRIORITY_MASK           0x10
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_TIME_SLICING_INDICATOR_MASK 0x08
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_MPE_FEC_INDICATOR_MASK      0x04
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_RESERVED1_MASK          0x03
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_CONSTELLATION_MASK      0xC0
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_HIERARCHY_INFORMATION_MASK  0x38
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_CODE_RATE_HP_STREAM_MASK    0x07
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_CODE_RATE_LP_STREAM_MASK    0xE0
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_GUARD_INTERVAL_MASK     0x18
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_TRANSMISSION_MODE_MASK      0x06
#define MPEG_DESCR_TERRESTRIAL_DELIVERY_OTHER_FREQUENCY_FLAG_MASK   0x01

static const value_string mpeg_descr_terrestrial_delivery_bandwidth_vals[] = {
    { 0x0, "8 MHz" },
    { 0x1, "7 MHz" },
    { 0x2, "6 MHz" },
    { 0x3, "5 Mhz" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_priority_vals[] = {
    { 0x0, "Low Priority" },
    { 0x1, "High Priority (or N/A if not hierarchical stream)" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_time_slicing_indicator_vals[] = {
    { 0x0, "At least one elementary stream uses Time Slicing" },
    { 0x1, "Time Slicing not used" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_mpe_fec_indicator_vals[] = {
    { 0x0, "At least one elementary stream uses MPE-FEC" },
    { 0x1, "MPE-FEC not used" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_constellation_vals[] = {
    { 0x0, "QPSK" },
    { 0x1, "16-QAM" },
    { 0x2, "64-QAM" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_hierarchy_information_vals[] = {
    { 0x0, "Non-hierarchical, native interleaver" },
    { 0x1, "alpha = 1, native interleaver" },
    { 0x2, "alpha = 2, native interleaver" },
    { 0x3, "alpha = 4, native interleaver" },
    { 0x4, "Non-hierarchical, in-depth interleaver" },
    { 0x5, "alpha = 1, in-depth interleaver" },
    { 0x6, "alpha = 2, in-depth interleaver" },
    { 0x7, "alpha = 4, in-depth interleaver" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_code_rate_vals[] = {
    { 0x0, "1/2 convolutional code rate" },
    { 0x1, "2/3 convolutional code rate" },
    { 0x2, "3/4 convolutional code rate" },
    { 0x3, "5/6 convolutional code rate" },
    { 0x4, "7/8 convolutional code rate" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_guard_interval_vals[] = {
    { 0x0, "1/32" },
    { 0x1, "1/16" },
    { 0x2, "1/8" },
    { 0x3, "1/4" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_other_frequency_flag_vals[] = {
    { 0x0, "No other frequency is in use" },
    { 0x1, "One or more frequencies are in use" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_terrestrial_delivery_transmission_mode_vals[] = {
    { 0x0, "2k mode" },
    { 0x1, "8k mode" },
    { 0x2, "4k mode" },

    { 0x0, NULL }
};

static void
proto_mpeg_descriptor_dissect_terrestrial_delivery(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint64 centre_freq;

    /* the descriptor stores the centre frequency in units of 10Hz (so
       that they can get away with 32bits), we're using Hz here */
    centre_freq = tvb_get_ntohl(tvb, offset) * 10;

    proto_tree_add_uint64_format_value(tree, hf_mpeg_descr_terrestrial_delivery_centre_frequency, tvb, offset, 4,
        centre_freq, "%d.%06d MHz", (guint)centre_freq/(1000*1000), (guint)centre_freq%(1000*1000));
    offset += 4;

    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_bandwidth, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_time_slicing_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_mpe_fec_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_constellation, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_hierarchy_information, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_code_rate_hp_stream, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_code_rate_lp_stream, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_guard_interval, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_transmission_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_other_frequency_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_terrestrial_delivery_reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);

}


/* 0x5F Private Data Specifier */
static int hf_mpeg_descr_private_data_specifier_id = -1;

#define PRIVATE_DATA_SPECIFIER_RESERVED    0x00000000
#define PRIVATE_DATA_SPECIFIER_NORDIG      0x00000029
#define PRIVATE_DATA_SPECIFIER_CIPLUS_LLP  0x00000040
#define PRIVATE_DATA_SPECIFIER_EUTELSAT_SA 0x0000055F

static const value_string mpeg_descr_data_specifier_id_vals[] = {
    { PRIVATE_DATA_SPECIFIER_RESERVED,   "reserved" },
    { PRIVATE_DATA_SPECIFIER_NORDIG,     "NorDig" },
    { PRIVATE_DATA_SPECIFIER_CIPLUS_LLP, "CI+ LLP" },
    { PRIVATE_DATA_SPECIFIER_EUTELSAT_SA, "Eutelsat S.A." },
    /* See dvbservices.com for complete and current list */

    { 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_private_data_specifier(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_private_data_specifier_id, tvb, offset, 4, ENC_BIG_ENDIAN);
}

/* 0x64 Data Broadcast Descriptor */
static int hf_mpeg_descr_data_bcast_bcast_id = -1;
static int hf_mpeg_descr_data_bcast_component_tag = -1;
static int hf_mpeg_descr_data_bcast_selector_len = -1;
static int hf_mpeg_descr_data_bcast_selector_bytes = -1;
static int hf_mpeg_descr_data_bcast_lang_code = -1;
static int hf_mpeg_descr_data_bcast_text_len = -1;
static int hf_mpeg_descr_data_bcast_text = -1;

static const value_string mpeg_descr_data_bcast_id_vals[] = {

    { 0x0001, "Data pipe" },
    { 0x0002, "Asynchronous data stream" },
    { 0x0003, "Synchronous data stream" },
    { 0x0004, "Synchronised data stream" },
    { 0x0005, "Multi protocol encapsulation" },
    { 0x0006, "Data Carousel" },
    { 0x0007, "Object Carousel" },
    { 0x0008, "DVB ATM streams" },
    { 0x0009, "Higher Protocols based on asynchronous data streams" },
    { 0x000A, "System Software Update service" },
    { 0x000B, "IP/MAC Notification service" },
    { 0x00F0, "MHP Object Carousel" },
    { 0x00F1, "MHP Multiprotocol Encapsulation" },
    { 0x0122, "CI+ Data Carousel" },
    { 0x0123, "HbbTV Carousel" },
    /* See dvbservices.com for complete and current list */

    { 0, NULL }
};
/* global variable that's shared e.g. with DVB-CI */
value_string_ext mpeg_descr_data_bcast_id_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_data_bcast_id_vals);

static void
proto_mpeg_descriptor_dissect_data_bcast(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

    guint8 selector_len, text_len;

    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_bcast_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_component_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    selector_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_selector_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (selector_len > 0) {
        proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_selector_bytes, tvb, offset, selector_len, ENC_NA);
        offset += selector_len;
    }

    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_lang_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
    offset += 3;

    text_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_text_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (text_len > 0)
        proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_text, tvb, offset, text_len, ENC_ASCII|ENC_NA);
}

/* 0x66 Data Broadcast ID Descriptor */
static int hf_mpeg_descr_data_bcast_id_bcast_id = -1;
static int hf_mpeg_descr_data_bcast_id_id_selector_bytes = -1;

static void
proto_mpeg_descriptor_dissect_data_bcast_id(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_id_bcast_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (len > 2)
        proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_id_id_selector_bytes, tvb, offset, len - 2, ENC_NA);
}

/* 0x6A AC-3 Descriptor */
static int hf_mpeg_descr_ac3_component_type_flag = -1;
static int hf_mpeg_descr_ac3_bsid_flag = -1;
static int hf_mpeg_descr_ac3_mainid_flag = -1;
static int hf_mpeg_descr_ac3_asvc_flag = -1;
static int hf_mpeg_descr_ac3_reserved = -1;
static int hf_mpeg_descr_ac3_component_type_reserved_flag = -1;
static int hf_mpeg_descr_ac3_component_type_full_service_flag = -1;
static int hf_mpeg_descr_ac3_component_type_service_type_flags = -1;
static int hf_mpeg_descr_ac3_component_type_number_of_channels_flags = -1;
static int hf_mpeg_descr_ac3_bsid = -1;
static int hf_mpeg_descr_ac3_mainid = -1;
static int hf_mpeg_descr_ac3_asvc = -1;
static int hf_mpeg_descr_ac3_additional_info = -1;

static gint ett_mpeg_descriptor_ac3_component_type = -1;

#define MPEG_DESCR_AC3_COMPONENT_TYPE_FLAG_MASK 0x80
#define MPEG_DESCR_AC3_BSID_FLAG_MASK           0x40
#define MPEG_DESCR_AC3_MAINID_FLAG_MASK         0x20
#define MPEG_DESCR_AC3_ASVC_FLAG_MASK           0x10
#define MPEG_DESCR_AC3_RESERVED_MASK            0x0F

#define MPEG_DESCR_AC3_COMPONENT_TYPE_RESERVED_FLAG_MASK        0x80
#define MPEG_DESCR_AC3_COMPONENT_TYPE_FULL_SERVICE_FLAG_MASK    0x40
#define MPEG_DESCR_AC3_COMPONENT_TYPE_SERVICE_TYPE_FLAGS_MASK   0x38
#define MPEG_DESCR_AC3_COMPONENT_TYPE_NUMBER_OF_CHANNELS_FLAGS  0x07

static const value_string mpeg_descr_ac3_component_type_flag_vals[] = {
    { 0x0, "Component type field not included" },
    { 0x1, "Component type field included" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_ac3_bsid_flag_vals[] = {
    { 0x0, "BSID field not included" },
    { 0x1, "BSID field included" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_ac3_mainid_flag_vals[] = {
    { 0x0, "Main ID field not included" },
    { 0x1, "Main ID field included" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_ac3_asvc_flag_vals[] = {
    { 0x0, "ASVC field not included" },
    { 0x1, "ASVC field included" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_ac3_component_type_full_service_flag_vals[] = {
    { 0x0, "Decoded audio stream is intended to be combined with another decoded audio stream" },
    { 0x1, "Decoded audio stream is a full service" },

    { 0x0, NULL}
};

static const value_string mpeg_descr_ac3_component_type_service_type_flags_vals[] = {
    { 0x0, "Complete Main (CM)" },
    { 0x1, "Music and effects (ME)" },
    { 0x2, "Visually impaired (VI)" },
    { 0x3, "Hearing impaired (HI)" },
    { 0x4, "Dialogue (D)" },
    { 0x5, "Commentary (C)" },
    { 0x6, "Emergency (E)" },
    { 0x7, "Voiceover (VO) if Full Service Flag is 0, else Karaoke" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_ac3_component_type_number_of_channels_flags_vals[] = {
    { 0x0, "Mono" },
    { 0x1, "1+1 Mode" },
    { 0x2, "2 Channel (stereo)" },
    { 0x3, "2 Channel Dolby surround encoded (stereo)" },
    { 0x4, "Multichannel audio (> 2 channels)" },

    { 0x0, NULL }
};

static void
proto_mpeg_descriptor_dissect_ac3(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint  end = offset + len;
    guint8 flags, component_type;

    proto_tree *component_type_tree;

    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_component_type_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_bsid_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_mainid_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_asvc_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (flags & MPEG_DESCR_AC3_COMPONENT_TYPE_FLAG_MASK) {
        component_type = tvb_get_guint8(tvb, offset);
        component_type_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3,
                    ett_mpeg_descriptor_ac3_component_type, NULL, "Component Type 0x%02x", component_type);
        proto_tree_add_item(component_type_tree, hf_mpeg_descr_ac3_component_type_reserved_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(component_type_tree, hf_mpeg_descr_ac3_component_type_full_service_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(component_type_tree, hf_mpeg_descr_ac3_component_type_service_type_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(component_type_tree, hf_mpeg_descr_ac3_component_type_number_of_channels_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (flags & MPEG_DESCR_AC3_BSID_FLAG_MASK) {
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_bsid, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (flags & MPEG_DESCR_AC3_MAINID_FLAG_MASK) {
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_mainid, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (flags & MPEG_DESCR_AC3_ASVC_FLAG_MASK) {
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_asvc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (offset < end)
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_additional_info, tvb, offset, end - offset, ENC_NA);
}

/* 0x6F Application Signalling Descriptor */
static int hf_mpeg_descr_app_sig_app_type = -1;
static int hf_mpeg_descr_app_sig_ait_ver = -1;

static void
proto_mpeg_descriptor_dissect_app_sig(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint  offset_start;

    offset_start = offset;
    while ((offset - offset_start) < len) {
        proto_tree_add_item(tree, hf_mpeg_descr_app_sig_app_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_mpeg_descr_app_sig_ait_ver, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 1;
    }
}

/* 0x73 Default Authority Descriptor */
static int hf_mpeg_descr_default_authority_name = -1;

static void
proto_mpeg_descriptor_dissect_default_authority(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_default_authority_name, tvb, offset, len, ENC_ASCII|ENC_NA);
}

/* 0x76 Content Identifier Descriptor */
static int hf_mpeg_descr_content_identifier_crid_type = -1;
static int hf_mpeg_descr_content_identifier_crid_location = -1;
static int hf_mpeg_descr_content_identifier_crid_length = -1;
static int hf_mpeg_descr_content_identifier_crid_bytes = -1;
static int hf_mpeg_descr_content_identifier_cird_ref = -1;

#define MPEG_DESCR_CONTENT_IDENTIFIER_CRID_TYPE_MASK        0xFC
#define MPEG_DESCR_CONTENT_IDENTIFIER_CRID_LOCATION_MASK    0x03

static gint ett_mpeg_descriptor_content_identifier_crid = -1;

static const value_string mpeg_descr_content_identifier_crid_type_vals[] = {
    { 0x00, "No type defined" },
    { 0x01, "CRID references the item of content that this event is an instance of" },
    { 0x02, "CRID references a series that this event belongs to" },
    { 0x03, "CRID references a recommendation" },

    { 0, NULL }
};

static const value_string mpeg_descr_content_identifier_crid_location_vals[] = {
    { 0x00, "Carried explicitly within descriptor" },
    { 0x01, "Carried in Content Identifier Table (CIT)" },

    { 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_content_identifier(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint  end = offset + len, crid_len;
    guint8 crid, crid_location, crid_type;

    proto_tree *crid_tree;

    while (offset < end) {
        crid = tvb_get_guint8(tvb, offset);
        crid_type = (crid & MPEG_DESCR_CONTENT_IDENTIFIER_CRID_TYPE_MASK) >> 2;
        crid_location = crid & MPEG_DESCR_CONTENT_IDENTIFIER_CRID_LOCATION_MASK;

        if (crid_location == 0) {
            crid_len = 2 + tvb_get_guint8(tvb, offset + 1);
        } else if (crid_location == 1) {
            crid_len = 3;
        } else {
            crid_len = 1;
        }

        crid_tree = proto_tree_add_subtree_format(tree, tvb, offset, crid_len,
                ett_mpeg_descriptor_content_identifier_crid, NULL, "CRID type=0%02x", crid_type);

        proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_crid_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_crid_location, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (crid_location == 0x00) {
            crid_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_crid_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_crid_bytes, tvb, offset, crid_len, ENC_NA);
            offset += crid_len;
        } else if (crid_location == 0x01) {
            proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_cird_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
        }

    }


}

/* 0x7F Extension Descriptor */
static int hf_mpeg_descr_extension_tag_extension = -1;
static int hf_mpeg_descr_extension_data = -1;
/* Supplementary Audio (Sub-)Descriptor */
static int hf_mpeg_descr_extension_supp_audio_mix_type = -1;
static int hf_mpeg_descr_extension_supp_audio_ed_cla = -1;
static int hf_mpeg_descr_extension_supp_audio_lang_code_present = -1;
static int hf_mpeg_descr_extension_supp_audio_lang_code = -1;

static int hf_mpeg_descr_private_data = -1;

#define EXT_TAG_IMG_ICON      0x00
#define EXT_TAG_CPCM_DLV      0x01
#define EXT_TAG_CP            0x02
#define EXT_TAG_CP_ID         0x03
#define EXT_TAG_T2            0x04
#define EXT_TAG_SH            0x05
#define EXT_TAG_SUPP_AUDIO    0x06
#define EXT_TAG_NW_CHANGE     0x07
#define EXT_TAG_MSG           0x08
#define EXT_TAG_TRGT_REG      0x09
#define EXT_TAG_TRGT_REG_NAME 0x0A
#define EXT_TAG_SVC_RELOC     0x0B

static const value_string mpeg_descr_extension_tag_extension_vals[] = {
    { EXT_TAG_IMG_ICON,      "Image Icon Descriptor" },
    { EXT_TAG_CPCM_DLV,      "CPCM Delivery Signalling Descriptor" },
    { EXT_TAG_CP,            "CP Descriptor" },
    { EXT_TAG_CP_ID,         "CP Identifier Descriptor" },
    { EXT_TAG_T2,            "T2 Delivery System Descriptor" },
    { EXT_TAG_SH,            "SH Delivery System Descriptor" },
    { EXT_TAG_SUPP_AUDIO,    "Supplementary Audio Descriptor" },
    { EXT_TAG_NW_CHANGE,     "Network Change Notify Descriptor" },
    { EXT_TAG_MSG,           "Message Descriptor" },
    { EXT_TAG_TRGT_REG,      "Target Region Descriptor" },
    { EXT_TAG_TRGT_REG_NAME, "Target Region Name Descriptor" },
    { EXT_TAG_SVC_RELOC,     "Service Relocated Descriptor" },
    { 0x0, NULL }
};
static value_string_ext mpeg_descr_extension_tag_extension_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_extension_tag_extension_vals);

static const value_string supp_audio_mix_type_vals[] = {
    { 0x00, "Audio stream is a supplementary stream" },
    { 0x01, "Audio stream is a complete and independent stream" },
    { 0x0, NULL }
};

/* if we wanted to distinguish between reserved and user defined,
   we'd have to convert this into a range string */
static const value_string supp_audio_ed_cla[] = {
    { 0x00, "Main audio" },
    { 0x01, "Audio description for the visually impaired" },
    { 0x02, "Clean audio for the hearing impaired" },
    { 0x03, "Spoken subtitles for the visually impaired" },
    { 0x0, NULL }
};


static void
proto_mpeg_descriptor_dissect_extension(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint     offset_start;
    guint8    tag_ext;
    gboolean  lang_code_present;
    guint     already_dissected;

    offset_start = offset;

    tag_ext = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_extension_tag_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (tag_ext) {
        case EXT_TAG_SUPP_AUDIO:
            proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_mix_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_ed_cla, tvb, offset, 1, ENC_BIG_ENDIAN);
            lang_code_present = ((tvb_get_guint8(tvb, offset) & 0x01) == 0x01);
            proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_lang_code_present, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            if (lang_code_present) {
                proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_lang_code, tvb, offset, 3, ENC_ASCII|ENC_NA);
                offset += 3;
            }
            already_dissected = offset-offset_start;
            if (already_dissected<len)
                proto_tree_add_item(tree, hf_mpeg_descr_private_data, tvb, offset, len-already_dissected, ENC_NA);
            break;
        default:
            already_dissected = offset-offset_start;
            if (already_dissected<len)
                proto_tree_add_item(tree, hf_mpeg_descr_extension_data, tvb, offset, len-already_dissected, ENC_NA);
            break;
    }

}

/* 0xA2 Logon Initialize Descriptor */
static int hf_mpeg_descr_logon_initialize_group_id = -1;
static int hf_mpeg_descr_logon_initialize_logon_id = -1;
static int hf_mpeg_descr_logon_initialize_continuous_carrier_reserved = -1;
static int hf_mpeg_descr_logon_initialize_continuous_carrier = -1;
static int hf_mpeg_descr_logon_initialize_security_handshake_required = -1;
static int hf_mpeg_descr_logon_initialize_prefix_flag = -1;
static int hf_mpeg_descr_logon_initialize_data_unit_labelling_flag = -1;
static int hf_mpeg_descr_logon_initialize_mini_slot_flag = -1;
static int hf_mpeg_descr_logon_initialize_contention_based_mini_slot_flag = -1;
static int hf_mpeg_descr_logon_initialize_capacity_type_flag_reserved = -1;
static int hf_mpeg_descr_logon_initialize_capacity_type_flag = -1;
static int hf_mpeg_descr_logon_initialize_traffic_burst_type = -1;
static int hf_mpeg_descr_logon_initialize_connectivity = -1;
static int hf_mpeg_descr_logon_initialize_return_vpi_reserved = -1;
static int hf_mpeg_descr_logon_initialize_return_vpi = -1;
static int hf_mpeg_descr_logon_initialize_return_vci = -1;
static int hf_mpeg_descr_logon_initialize_return_signalling_vpi_reserved = -1;
static int hf_mpeg_descr_logon_initialize_return_signalling_vpi = -1;
static int hf_mpeg_descr_logon_initialize_return_signalling_vci = -1;
static int hf_mpeg_descr_logon_initialize_forward_signalling_vpi_reserved = -1;
static int hf_mpeg_descr_logon_initialize_forward_signalling_vpi = -1;
static int hf_mpeg_descr_logon_initialize_forward_signalling_vci = -1;

static int hf_mpeg_descr_logon_initialize_return_trf_pid = -1;
static int hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid_reserved = -1;
static int hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid = -1;

static int hf_mpeg_descr_logon_initialize_cra_level = -1;
static int hf_mpeg_descr_logon_initialize_vbdc_max_reserved = -1;
static int hf_mpeg_descr_logon_initialize_vbdc_max = -1;
static int hf_mpeg_descr_logon_initialize_rbdc_max = -1;
static int hf_mpeg_descr_logon_initialize_rbdc_timeout = -1;


#define MPEG_DESCR_LOGON_INITIALIZE_CONTINUOUS_CARRIER_RESERVED_MASK              0xC0
#define MPEG_DESCR_LOGON_INITIALIZE_CONTINUOUS_CARRIER_MASK                       0x20
#define MPEG_DESCR_LOGON_INITIALIZE_SECURITY_HANDSHAKE_REQUIRED_MASK              0x10
#define MPEG_DESCR_LOGON_INITIALIZE_PREFIX_FLAG_MASK                              0x08
#define MPEG_DESCR_LOGON_INITIALIZE_DATA_UNIT_LABELLING_FLAG_MASK                 0x04
#define MPEG_DESCR_LOGON_INITIALIZE_MINI_SLOT_FLAG_MASK                           0x02
#define MPEG_DESCR_LOGON_INITIALIZE_CONTENTION_BASED_MINI_SLOT_FLAG_MASK          0x01

#define MPEG_DESCR_LOGON_INITIALIZE_CAPACITY_TYPE_FLAG_RESERVED_MASK              0x80
#define MPEG_DESCR_LOGON_INITIALIZE_CAPACITY_TYPE_FLAG_MASK                       0x40
#define MPEG_DESCR_LOGON_INITIALIZE_TRAFFIC_BURST_TYPE_MASK                       0x20

#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_TRF_PID_MASK                         0x1FFF
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_CTRL_MNGM_PID_RESERVED_MASK          0xE000
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_CTRL_MNGM_PID_MASK                   0x1FFF

#define MPEG_DESCR_LOGON_INITIALIZE_CONNECTIVITY_MASK                           0x1000
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_VPI_RESERVED_MASK                    0x0F00
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_VPI_MASK                             0x00FF

#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_RESERVED_MASK         0x0F00
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_MASK                  0x00FF
#define MPEG_DESCR_LOGON_INITIALIZE_FORWARD_SIGNALLING_VPI_RESERVED_MASK        0xFF00
#define MPEG_DESCR_LOGON_INITIALIZE_FORWARD_SIGNALLING_VPI_MASK                 0x00FF

#define MPEG_DESCR_LOGON_INITIALIZE_VDBC_MAX_RESERVED_MASK                      0xF800
#define MPEG_DESCR_LOGON_INITIALIZE_VDBC_MAX_MASK                               0x0700


static void
proto_mpeg_descriptor_dissect_logon_initialize(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{

    guint   end    = offset + len;
    guint8  flags;
    guint16 flags2;

    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_group_id,                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_logon_id,                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_continuous_carrier_reserved,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_continuous_carrier,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_security_handshake_required,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_prefix_flag,                     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_data_unit_labelling_flag,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_mini_slot_flag,                  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_contention_based_mini_slot_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    flags = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_capacity_type_flag_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_capacity_type_flag,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_traffic_burst_type,          tvb, offset, 1, ENC_BIG_ENDIAN);
    if (flags & MPEG_DESCR_LOGON_INITIALIZE_TRAFFIC_BURST_TYPE_MASK) {
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_connectivity, tvb, offset, 2, ENC_BIG_ENDIAN);
        flags2 = tvb_get_ntohs(tvb, offset);
        if (flags2 & MPEG_DESCR_LOGON_INITIALIZE_CONNECTIVITY_MASK) {
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_signalling_vpi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_signalling_vpi, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_signalling_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_forward_signalling_vpi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_forward_signalling_vpi, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_forward_signalling_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        } else {
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_vpi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_vpi, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

        }
    } else {
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_trf_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if ((offset < end) && (flags & MPEG_DESCR_LOGON_INITIALIZE_CAPACITY_TYPE_FLAG_MASK)) {

        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_cra_level,         tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_vbdc_max_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_vbdc_max,          tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_rbdc_max,          tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_rbdc_timeout,      tvb, offset, 2, ENC_BIG_ENDIAN);
        /*offset += 2;*/
    }
}

/* 0xA7 RCS Content Descriptor */
static int hf_mpeg_descr_rcs_content_table_id = -1;

static void
proto_mpeg_descriptor_dissect_rcs_content(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree)
{
    guint end = offset + len;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_rcs_content_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
}

/* Private descriptors
   these functions replace proto_mpeg_descriptor_dissect(), they get to see the whole descriptor */

#define CIPLUS_DESC_TAG_CNT_LBL 0xCB
#define CIPLUS_DESC_TAG_SVC     0xCC
#define CIPLUS_DESC_TAG_PROT    0xCE

static const value_string mpeg_descriptor_ciplus_tag_vals[] = {
    /* From CI+ 1.3.1 */
    { CIPLUS_DESC_TAG_CNT_LBL, "CI+ Content Label Descriptor" },
    { CIPLUS_DESC_TAG_SVC,     "CI+ Service Descriptor" },
    { CIPLUS_DESC_TAG_PROT,    "CI+ Protection Descriptor" },
    { 0x00, NULL}
};

/* 0xCB CI+ Content Label Descriptor */
static int hf_mpeg_descr_ciplus_cl_cb_min = -1;
static int hf_mpeg_descr_ciplus_cl_cb_max = -1;
static int hf_mpeg_descr_ciplus_cl_lang = -1;
static int hf_mpeg_descr_ciplus_cl_label = -1;

/* 0xCC CI+ Service Descriptor */
static int hf_mpeg_descr_ciplus_svc_id = -1;
static int hf_mpeg_descr_ciplus_svc_type = -1;
static int hf_mpeg_descr_ciplus_svc_visible = -1;
static int hf_mpeg_descr_ciplus_svc_selectable = -1;
static int hf_mpeg_descr_ciplus_svc_lcn = -1;
static int hf_mpeg_descr_ciplus_svc_prov_name = -1;
static int hf_mpeg_descr_ciplus_svc_name = -1;

/* 0xCE CI+ Protection Descriptor */
static int hf_mpeg_descr_ciplus_prot_free_ci_mode = -1;
static int hf_mpeg_descr_ciplus_prot_match_brand_flag = -1;
static int hf_mpeg_descr_ciplus_prot_num_entries = -1;
static int hf_mpeg_descr_ciplus_prot_brand_id = -1;

static const true_false_string tfs_prot_noprot = { "CI+ protection required", "CI+ protection not required" };


static guint
proto_mpeg_descriptor_dissect_private_ciplus(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint        offset_start;
    guint8       tag, len;
    const gchar *tag_str;
    proto_item  *di;
    proto_tree  *descriptor_tree;

    offset_start=offset;

    tag = tvb_get_guint8(tvb, offset);
    tag_str = try_val_to_str(tag, mpeg_descriptor_ciplus_tag_vals);
    if (!tag_str)
        return 0;

    descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset_start, -1,
                ett_mpeg_descriptor, &di, "CI+ private descriptor Tag=0x%02x", tag);

    proto_tree_add_uint_format(descriptor_tree, hf_mpeg_descriptor_tag,
            tvb, offset, 1, tag, "Descriptor Tag: %s (0x%02x)", tag_str, tag);
    offset += 1;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(descriptor_tree, hf_mpeg_descriptor_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (tag==CIPLUS_DESC_TAG_CNT_LBL) {
        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_cb_min, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_cb_max, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_lang, tvb, offset, 3, ENC_ASCII|ENC_NA);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_label, tvb, offset, len-offset, ENC_ASCII|ENC_NA);
        offset += len-offset;
    }
    else if (tag==CIPLUS_DESC_TAG_SVC) {
        guint8  str_len_byte;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_visible, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_selectable, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_lcn, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        str_len_byte = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_prov_name, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        offset += 1+str_len_byte;

        str_len_byte = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_name, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        offset += 1+str_len_byte;
    }
    else if (tag==CIPLUS_DESC_TAG_PROT) {
        gboolean  match_brand_flag;
        guint8    num_brands, i;
        guint     remaining;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_prot_free_ci_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
        match_brand_flag = ((tvb_get_guint8(tvb, offset) & 0x40) == 0x40);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_prot_match_brand_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (match_brand_flag) {
            num_brands = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_prot_num_entries, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            for (i=0; i<num_brands; i++) {
                proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_prot_brand_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
        }

        remaining = offset_start+2+len - offset;
        if (remaining > 0) {
            proto_tree_add_item(descriptor_tree, hf_mpeg_descr_private_data, tvb, offset, remaining, ENC_NA);
            offset += remaining;
        }
    }

    proto_item_set_len(di, offset-offset_start);
    return offset-offset_start;
}


/* Common dissector */

guint
proto_mpeg_descriptor_dissect(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint       tag, len;

    proto_tree *descriptor_tree;

    tag = tvb_get_guint8(tvb, offset);
    len = tvb_get_guint8(tvb, offset + 1);

    descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset, len + 2,
                        ett_mpeg_descriptor, NULL, "Descriptor Tag=0x%02x", tag);

    proto_tree_add_item(descriptor_tree, hf_mpeg_descriptor_tag,    tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(descriptor_tree, hf_mpeg_descriptor_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (len == 0)
        return 2;

    switch (tag) {
        case 0x02: /* Video Stream Descriptor */
            proto_mpeg_descriptor_dissect_video_stream(tvb, offset, descriptor_tree);
            break;
        case 0x03: /* Audio Stream Descriptor */
            proto_mpeg_descriptor_dissect_audio_stream(tvb, offset, descriptor_tree);
            break;
        case 0x05: /* Registration Descriptor */
            proto_mpeg_descriptor_dissect_registration(tvb, offset, len, descriptor_tree);
            break;
        case 0x06: /* Data Stream Alignment Descriptor */
            proto_mpeg_descriptor_dissect_data_stream_alignment(tvb, offset, descriptor_tree);
            break;
        case 0x09: /* CA Descriptor */
            proto_mpeg_descriptor_dissect_ca(tvb, offset, len, descriptor_tree);
            break;
        case 0x0A: /* ISO 639 Language Descriptor */
            proto_mpeg_descriptor_dissect_iso639(tvb, offset, len, descriptor_tree);
            break;
        case 0x0B: /* System Clock Descriptor */
            proto_mpeg_descriptor_dissect_system_clock(tvb, offset, descriptor_tree);
            break;
        case 0x0E: /* Maximum Bitrate Descriptor */
            proto_mpeg_descriptor_dissect_max_bitrate(tvb, offset, descriptor_tree);
            break;
        case 0x10: /* Smoothing Buffer Descriptor */
            proto_mpeg_descriptor_dissect_smoothing_buffer(tvb, offset, descriptor_tree);
            break;
        case 0x11: /* STD Descriptor */
            proto_mpeg_descriptor_dissect_std(tvb, offset, descriptor_tree);
            break;
        case 0x13: /* Carousel Identifier Descriptor */
            proto_mpeg_descriptor_dissect_carousel_identifier(tvb, offset, len, descriptor_tree);
            break;
        case 0x14: /* Association Tag Descriptor */
            proto_mpeg_descriptor_dissect_association_tag(tvb, offset, len, descriptor_tree);
            break;
        case 0x28: /* AVC Video Descriptor */
            proto_mpeg_descriptor_dissect_avc_vid(tvb, offset, descriptor_tree);
            break;
        case 0x40: /* Network Name Descriptor */
            proto_mpeg_descriptor_dissect_network_name(tvb, offset, len, descriptor_tree);
            break;
        case 0x41: /* Service List Descriptor */
            proto_mpeg_descriptor_dissect_service_list(tvb, offset, len, descriptor_tree);
            break;
        case 0x42: /* Stuffing Descriptor */
            proto_mpeg_descriptor_stuffing(tvb, offset, len, descriptor_tree);
            break;
        case 0x43: /* Satellite Delivery System Descriptor */
            proto_mpeg_descriptor_dissect_satellite_delivery(tvb, offset, descriptor_tree);
            break;
        case 0x44: /* Cable Delivery System Descriptor */
            proto_mpeg_descriptor_dissect_cable_delivery(tvb, offset, descriptor_tree);
            break;
        case 0x45: /* VBI Data Descriptor */
            proto_mpeg_descriptor_dissect_vbi_data(tvb, offset, len, descriptor_tree);
            break;
        case 0x47: /* Bouquet Name Descriptor */
            proto_mpeg_descriptor_dissect_bouquet_name(tvb, offset, len, descriptor_tree);
            break;
        case 0x48: /* Service Descriptor */
            proto_mpeg_descriptor_dissect_service(tvb, offset, descriptor_tree);
            break;
        case 0x4A: /* Linkage Descriptor */
            proto_mpeg_descriptor_dissect_linkage(tvb, offset, len, descriptor_tree);
            break;
        case 0x4D: /* Short Event Descriptor */
            proto_mpeg_descriptor_dissect_short_event(tvb, offset, descriptor_tree);
            break;
        case 0x4E: /* Extended Event Descriptor */
            proto_mpeg_descriptor_dissect_extended_event(tvb, offset, descriptor_tree);
            break;
        case 0x50: /* Component Descriptor */
            proto_mpeg_descriptor_dissect_component(tvb, offset, len, descriptor_tree);
            break;
        case 0x52: /* Stream Identifier Descriptor */
            proto_mpeg_descriptor_dissect_stream_identifier(tvb, offset, descriptor_tree);
            break;
        case 0x53: /* CA Identifier Descriptor */
            proto_mpeg_descriptor_dissect_ca_identifier(tvb, offset, len, descriptor_tree);
            break;
        case 0x54: /* Content Descriptor */
            proto_mpeg_descriptor_dissect_content(tvb, offset, len, descriptor_tree);
            break;
        case 0x55: /* Parental Rating Descriptor */
            proto_mpeg_descriptor_dissect_parental_rating(tvb, offset, descriptor_tree);
            break;
        case 0x56: /* Teletext Descriptor */
            proto_mpeg_descriptor_dissect_teletext(tvb, offset, len, descriptor_tree);
            break;
        case 0x58: /* Local Time Offset Descriptor */
            proto_mpeg_descriptor_dissect_local_time_offset(tvb, offset, len, descriptor_tree);
            break;
        case 0x59: /* Subtitling Descriptor */
            proto_mpeg_descriptor_dissect_subtitling(tvb, offset, len, descriptor_tree);
            break;
        case 0x5A: /* Terrestrial Delivery System Descriptor */
            proto_mpeg_descriptor_dissect_terrestrial_delivery(tvb, offset, descriptor_tree);
            break;
        case 0x5F: /* Private Data Specifier Descriptor */
            proto_mpeg_descriptor_dissect_private_data_specifier(tvb, offset, descriptor_tree);
            break;
        case 0x64: /* Data Broadcast Descriptor */
            proto_mpeg_descriptor_dissect_data_bcast(tvb, offset, descriptor_tree);
            break;
        case 0x66: /* Data Broadcast ID Descriptor */
            proto_mpeg_descriptor_dissect_data_bcast_id(tvb, offset, len, descriptor_tree);
            break;
        case 0x6A: /* AC-3 Descriptor */
            proto_mpeg_descriptor_dissect_ac3(tvb, offset, len, descriptor_tree);
            break;
        case 0x6F: /* Application Signalling Descriptor */
            proto_mpeg_descriptor_dissect_app_sig(tvb, offset, len, descriptor_tree);
            break;
        case 0x73: /* Default Authority Descriptor */
            proto_mpeg_descriptor_dissect_default_authority(tvb, offset, len, descriptor_tree);
            break;
        case 0x76: /* Content Identifier Descriptor */
            proto_mpeg_descriptor_dissect_content_identifier(tvb, offset, len, descriptor_tree);
            break;
        case 0x7F: /* Extension Descriptor */
            proto_mpeg_descriptor_dissect_extension(tvb, offset, len, descriptor_tree);
            break;
        case 0xA2: /* Logon Initialize Descriptor */
            proto_mpeg_descriptor_dissect_logon_initialize(tvb, offset, len, descriptor_tree);
            break;
        case 0xA7: /* RCS Content Descriptor */
            proto_mpeg_descriptor_dissect_rcs_content(tvb, offset, len, descriptor_tree);
            break;
        default:
            proto_tree_add_item(descriptor_tree, hf_mpeg_descriptor_data, tvb, offset, len, ENC_NA);
            break;
    }

    return len + 2;
}


/* dissect a descriptor loop consisting of one or more descriptors
   take into account the contexts defined a private data specifier descriptors */
guint
proto_mpeg_descriptor_loop_dissect(tvbuff_t *tvb, guint offset, guint loop_len, proto_tree *tree)
{
    /* we use the reserved value to indicate that no private context is active */
    guint32 private_data_specifier = PRIVATE_DATA_SPECIFIER_RESERVED;
    guint   offset_start;
    guint   desc_len;
    guint8  tag;

    offset_start = offset;

    while ((offset - offset_start) < loop_len) {
        /* don't increment offset in our pre-checks */
        tag = tvb_get_guint8(tvb, offset);
        if (tag == 0x5F) {
            /* we have a private data specifier descriptor: get the private data specifier */
            /* offset+1 is length byte, offset+2 is start of payload */
            private_data_specifier = tvb_get_ntohl(tvb, offset+2);
        }

         /* the default descriptor function takes precedence
            however, if it does not know the current descriptor, we search for a context-specific subfunction
            this subfunction gets to see the entire descriptor, including tag and len */
        if (try_val_to_str(tag, mpeg_descriptor_tag_vals)) {
            desc_len = proto_mpeg_descriptor_dissect(tvb, offset, tree);
        }
        else {
            switch (private_data_specifier) {
                case PRIVATE_DATA_SPECIFIER_CIPLUS_LLP:
                    desc_len = proto_mpeg_descriptor_dissect_private_ciplus(tvb, offset, tree);
                    break;
                default:
                    desc_len = 0;
                    break;
            }
            if (desc_len == 0) {
                /* either there was no subfunction or it could not handle the descriptor
                   fall back to the default (which will dissect it as unknown) */
                desc_len = proto_mpeg_descriptor_dissect(tvb, offset, tree);
            }
        }

        offset += desc_len;
    }

    return offset-offset_start;
}


void
proto_register_mpeg_descriptor(void)
{

    static hf_register_info hf[] = {
        { &hf_mpeg_descriptor_tag, {
            "Descriptor Tag", "mpeg_descr.tag",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descriptor_tag_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descriptor_length, {
            "Descriptor Length", "mpeg_descr.len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descriptor_data, {
            "Descriptor Data", "mpeg_descr.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x02 Video Stream Descriptor */
        { &hf_mpeg_descr_video_stream_multiple_frame_rate_flag, {
            "Multiple Frame Rate Flag", "mpeg_descr.video_stream.multiple_frame_rate_flag",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_video_stream_multiple_frame_rate_flag_vals),
            MPEG_DESCR_VIDEO_STREAM_MULTIPLE_FRAME_RATE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_frame_rate_code, {
            "Frame Rate Code", "mpeg_descr.video_stream.frame_rate_code",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_VIDEO_STREAM_FRAME_RATE_CODE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_mpeg1_only_flag, {
            "MPEG1 Only Flag", "mpeg_descr.video_stream.mpeg1_only_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_VIDEO_STREAM_MPEG1_ONLY_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_constrained_parameter_flag, {
            "Constrained Parameter Flag", "mpeg_descr.video_stream.constrained_parameter_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_VIDEO_STREAM_CONSTRAINED_PARAMETER_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_still_picture_flag, {
            "Still Picture Flag", "mpeg_descr.video_stream.still_picture_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_VIDEO_STREAM_STILL_PICTURE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_profile_and_level_indication, {
            "Profile and Level Indication", "mpeg_descr.video_stream.profile_level_ind",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_chroma_format, {
            "Chroma Format", "mpeg_descr.video_stream.chroma_format",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_frame_rate_extension_flag, {
            "Frame Rate Extension Flag", "mpeg_descr.video_stream.frame_rate_extension_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_VIDEO_STREAM_FRAME_RATE_EXTENSION_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_video_stream_reserved, {
            "Reserved", "mpeg_descr.video_stream.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_VIDEO_STREAM_RESERVED_MASK, NULL, HFILL
        } },

        /* 0x03 Audio Stream Descriptor */
        { &hf_mpeg_descr_audio_stream_free_format_flag, {
            "Free Format Flag", "mpeg_descr.audio_stream.free_format_flag",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_audio_stream_free_format_flag_vals), MPEG_DESCR_AUDIO_STREAM_FREE_FORMAT_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_audio_stream_id, {
            "ID", "mpeg_descr.audio_stream.id",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_audio_stream_id_vals), MPEG_DESCR_AUDIO_STREAM_ID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_audio_stream_layer, {
            "Layer", "mpeg_descr.audio_stream.layer",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AUDIO_STREAM_LAYER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_audio_stream_variable_rate_audio_indicator, {
            "Variable Rate Audio Indicator", "mpeg_descr.audio_stream.vbr_indicator",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_audio_stream_variable_rate_audio_indicator_vals),
            MPEG_DESCR_AUDIO_STREAM_VARIABLE_RATE_AUDIO_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_audio_stream_reserved, {
            "Reserved", "mpeg_descr.audio_stream.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_AUDIO_STREAM_RESERVED_MASK, NULL, HFILL
        } },

        /* 0x05 Registration Descriptor */
        { &hf_mpeg_descr_reg_form_id, {
            "Format identifier", "mpeg_descr.registration.format_identifier",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_reg_add_id_inf, {
            "Additional identification info", "mpeg_descr.registration.add_id_info",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x06 Data Stream Alignment Descriptor */
        { &hf_mpeg_descr_data_stream_alignment, {
            "Data Stream Alignment", "mpeg_descr.data_stream_alignment.alignment",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_data_stream_alignment_vals), 0, NULL, HFILL
        } },

        /* 0x09 CA Descriptor */
        { &hf_mpeg_descr_ca_system_id, {
            "System ID", "mpeg_descr.ca.sys_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ca_reserved, {
            "Reserved", "mpeg_descr.ca.reserved",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_CA_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ca_pid, {
            "CA PID", "mpeg_descr.ca.pid",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_CA_PID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ca_private, {
            "Private bytes", "mpeg_descr.ca.private",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x0A ISO 639 Language Descriptor */
        { &hf_mpeg_descr_iso639_lang, {
            "ISO 639 Language Code", "mpeg_descr.lang.code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_iso639_type, {
            "ISO 639 Language Type", "mpeg_descr.lang.type",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_iso639_type_vals), 0, NULL, HFILL
        } },

        /* 0x0B System Clock Descriptor */
        { &hf_mpeg_descr_system_clock_external_clock_reference_indicator, {
            "External Clock Reference Indicator", "mpeg_descr.sys_clk.external_clk_ref_ind",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_SYSTEM_CLOCK_EXTERNAL_CLOCK_REFERENCE_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_system_clock_reserved1, {
            "Reserved", "mpeg_descr.sys_clk.reserved1",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_SYSTEM_CLOCK_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_system_clock_accuracy_integer, {
            "Accuracy Integer", "mpeg_descr.sys_clk.accuracy_integer",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_SYSTEM_CLOCK_ACCURACY_INTEGER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_system_clock_accuracy_exponent, {
            "Accuracy Exponent", "mpeg_descr.sys_clk.accuracy_exponent",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_SYSTEM_CLOCK_ACCURACY_EXPONENT_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_system_clock_reserved2, {
            "Reserved", "mpeg_descr.sys_clk.reserved2",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_SYSTEM_CLOCK_RESERVED2_MASK, NULL, HFILL
        } },

        /* 0x0E Maximum Bitrate Descriptor */
        { &hf_mpeg_descr_max_bitrate_reserved, {
            "Maximum Bitrate Reserved", "mpeg_descr.max_bitrate.reserved",
            FT_UINT24, BASE_HEX, NULL, MPEG_DESCR_MAX_BITRATE_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_max_bitrate, {
            "Maximum Bitrate", "mpeg_descr.max_bitrate.rate",
            FT_UINT24, BASE_DEC, NULL, MPEG_DESCR_MAX_BITRATE_MASK, NULL, HFILL
        } },

        /* 0x10 Smoothing Buffer Descriptor */
        { &hf_mpeg_descr_smoothing_buffer_reserved1, {
            "Reserved", "mpeg_descr.smoothing_buf.reserved1",
            FT_UINT24, BASE_HEX, NULL, MPEG_DESCR_SMOOTHING_BUFFER_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_smoothing_buffer_leak_rate, {
            "Leak Rate", "mpeg_descr.smoothing_buf.leak_rate",
            FT_UINT24, BASE_DEC, NULL, MPEG_DESCR_SMOOTHING_BUFFER_LEAK_RATE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_smoothing_buffer_reserved2, {
            "Reserved", "mpeg_descr.smoothing_buf.reserved2",
            FT_UINT24, BASE_HEX, NULL, MPEG_DESCR_SMOOTHING_BUFFER_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_smoothing_buffer_size, {
            "Buffer Size", "mpeg_descr.smoothing_buf.size",
            FT_UINT24, BASE_DEC, NULL, MPEG_DESCR_SMOOTHING_BUFFER_SIZE_MASK, NULL, HFILL
        } },

        /* 0x11 STD Descriptor */
        { &hf_mpeg_descr_std_reserved, {
            "Reserved", "mpeg_descr.std.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_STD_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_std_leak_valid, {
            "Leak Valid", "mpeg_descr.std.leak_valid",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_STD_LEAK_VALID_MASK, NULL, HFILL
        } },

        /* 0x13 Carousel Identifier Descriptor */
        { &hf_mpeg_descr_carousel_identifier_id, {
            "Carousel ID", "mpeg_descr.carousel_identifier.id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_format_id, {
            "Format ID", "mpeg_descr.carousel_identifier.format_id",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_carousel_identifier_format_id_vals), 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_module_version, {
            "Module Version", "mpeg_descr.carousel_identifier.module_version",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_module_id, {
            "Module ID", "mpeg_descr.carousel_identifier.module_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_block_size, {
            "Block Size", "mpeg_descr.carousel_identifier.block_size",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_module_size, {
            "Module Size", "mpeg_descr.carousel_identifier.module_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_compression_method, {
            "Compression Method", "mpeg_descr.carousel_identifier.comp_method",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_original_size, {
            "Original Size", "mpeg_descr.carousel_identifier.orig_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_timeout, {
            "Timeout", "mpeg_descr.carousel_identifier.timeout",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_object_key_len, {
            "Object Key Length", "mpeg_descr.carousel_identifier.key_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_object_key_data, {
            "Object Key Data", "mpeg_descr.carousel_identifier.key_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_carousel_identifier_private, {
            "Private Bytes", "mpeg_descr.carousel_identifier.private",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x14 Association Tag Descriptor */
        { &hf_mpeg_descr_association_tag, {
            "Association Tag", "mpeg_descr.assoc_tag.tag",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_association_tag_use, {
            "Use", "mpeg_descr.assoc_tag.use",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_association_tag_selector_len, {
            "Selector Length", "mpeg_descr.assoc_tag.selector_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_association_tag_transaction_id, {
            "Transaction ID", "mpeg_descr.assoc_tag.transaction_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_association_tag_timeout, {
            "Timeout", "mpeg_descr.assoc_tag.timeout",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_association_tag_selector_bytes, {
            "Selector Bytes", "mpeg_descr.assoc_tag.selector_bytes",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_association_tag_private_bytes, {
            "Private Bytes", "mpeg_descr.assoc_tag.private_bytes",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x28 AVC Video Descriptor */
        { &hf_mpeg_descr_avc_vid_profile_idc, {
            "Profile IDC", "mpeg_descr.avc_vid.profile_idc",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_constraint_set0_flag, {
            "Constraint Set0 Flag", "mpeg_descr.avc_vid.contraint_set0",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AVC_VID_CONSTRAINT_SET0_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_constraint_set1_flag, {
            "Constraint Set1 Flag", "mpeg_descr.avc_vid.contraint_set1",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AVC_VID_CONSTRAINT_SET1_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_constraint_set2_flag, {
            "Constraint Set2 Flag", "mpeg_descr.avc_vid.contraint_set2",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AVC_VID_CONSTRAINT_SET2_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_compatible_flags, {
            "Constraint Compatible Flags", "mpeg_descr.avc_vid.compatible_flags",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_AVC_VID_COMPATIBLE_FLAGS_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_level_idc, {
            "Level IDC", "mpeg_descr.avc_vid.level_idc",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_still_present, {
            "AVC Still Present", "mpeg_descr.avc_vid.still_present",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AVC_VID_STILL_PRESENT_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_24h_picture_flag, {
            "AVC 24 Hour Picture Flag", "mpeg_descr.avc_vid.24h_picture_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AVC_VID_24H_PICTURE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_reserved, {
            "Reserved", "mpeg_descr.avc_vid.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_AVC_VID_RESERVED_MASK, NULL, HFILL
        } },

        /* 0x40 Network Name Descriptor */
        { &hf_mpeg_descr_network_name_descriptor, {
            "Network Name", "mpeg_descr.net_name.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x41 Service List Descriptor */
        { &hf_mpeg_descr_service_list_id, {
            "Service ID", "mpeg_descr.svc_list.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_list_type, {
            "Service Type", "mpeg_descr.svc_list.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_service_type_vals_ext, 0, NULL, HFILL
        } },

        /* 0x42 Stuffing Descriptor */
        { &hf_mpeg_descr_stuffing, {
            "Stuffing", "mpeg_descr.stuffing",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x43 Satellite Delivery System Descriptor */
        { &hf_mpeg_descr_satellite_delivery_frequency, {
            "Frequency", "mpeg_descr.sat_delivery.freq",
            FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_orbital_position, {
            "Orbital Position", "mpeg_descr.sat_delivery.orbital_pos",
            FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_west_east_flag, {
            "West East Flag", "mpeg_descr.sat_delivery.west_east_flag",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_satellite_delivery_west_east_flag_vals),
            MPEG_DESCR_SATELLITE_DELIVERY_WEST_EAST_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_polarization, {
            "Polarization", "mpeg_descr.sat_delivery.polarization",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_satellite_delivery_polarization_vals),
            MPEG_DESCR_SATELLITE_DELIVERY_POLARIZATION_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_roll_off, {
            "Roll Off", "mpeg_descr.sat_delivery.roll_off",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_satellite_delivery_roll_off_vals),
            MPEG_DESCR_SATELLITE_DELIVERY_ROLL_OFF_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_zero, {
            "Zero", "mpeg_descr.sat_delivery.zero",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_SATELLITE_DELIVERY_ZERO_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_modulation_system, {
            "Modulation System", "mpeg_descr.sat_delivery.modulation_system",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_satellite_delivery_modulation_system_vals),
            MPEG_DESCR_SATELLITE_DELIVERY_MODULATION_SYSTEM_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_modulation_type, {
            "Modulation Type", "mpeg_descr.sat_delivery.modulation_type",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_satellite_delivery_modulation_type_vals),
            MPEG_DESCR_SATELLITE_DELIVERY_MODULATION_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_symbol_rate, {
            "Symbol Rate", "mpeg_descr.sat_delivery.symbol_rate",
            FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_fec_inner, {
            "FEC Inner", "mpeg_descr.sat_delivery.fec_inner",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_satellite_delivery_fec_inner_vals_ext,
            MPEG_DESCR_SATELLITE_DELIVERY_FEC_INNER_MASK, NULL, HFILL
        } },

        /* 0x44 Cable Delivery System Descriptor */
        { &hf_mpeg_descr_cable_delivery_frequency, {
            "Frequency", "mpeg_descr.cable_delivery.freq",
            FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_cable_delivery_reserved, {
            "Reserved", "mpeg_descr.cable_delivery.reserved",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_CABLE_DELIVERY_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_cable_delivery_fec_outer, {
            "FEC Outer", "mpeg_descr.cable_delivery.fec_outer",
            FT_UINT16, BASE_HEX, VALS(mpeg_descr_cable_delivery_fec_outer_vals),
            MPEG_DESCR_CABLE_DELIVERY_FEC_OUTER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_cable_delivery_modulation, {
            "Modulation", "mpeg_descr.cable_delivery.modulation",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_cable_delivery_modulation_vals), 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_cable_delivery_symbol_rate, {
            "Symbol Rate", "mpeg_descr.cable_delivery.sym_rate",
            FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_cable_delivery_fec_inner, {
            "FEC Inner", "mpeg_descr.cable_delivery.fec_inner",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_cable_delivery_fec_inner_vals_ext,
            MPEG_DESCR_CABLE_DELIVERY_FEC_INNER_MASK, NULL, HFILL
        } },

        /* 0x45 VBI Data Descriptor */
        { &hf_mpeg_descr_vbi_data_service_id, {
            "Data Service ID", "mpeg_descr.vbi_data.svc_id",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_vbi_data_service_id_vals), 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_vbi_data_descr_len, {
            "Data Descriptor Length", "mpeg_descr.vbi_data.decr_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_vbi_data_reserved1, {
            "Reserved", "mpeg_descr.vbi_data.reserved1",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_VBI_DATA_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_vbi_data_field_parity, {
            "Field Parity", "mpeg_descr.vbi_data.field_parity",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_vbi_data_field_parity_vals),
            MPEG_DESCR_VBI_DATA_FIELD_PARITY_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_vbi_data_line_offset, {
            "Line offset", "mpeg_descr.vbi_data.line_offset",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_vbi_data_reserved2, {
            "Reserved", "mpeg_descr.vbi_data.reserved2",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x47 Bouquet Name Descriptor */
        { &hf_mpeg_descr_bouquet_name, {
            "Bouquet Name Descriptor", "mpeg_descr.bouquet_name.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x48 Service Descriptor */
        { &hf_mpeg_descr_service_type, {
            "Service Type", "mpeg_descr.svc.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_service_type_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_provider_name_length, {
            "Provider Name Length", "mpeg_descr.svc.provider_name_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_provider_name_encoding, {
            "Provider Name Encoding", "mpeg_descr.svc.provider_name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_provider, {
            "Service Provider Name", "mpeg_descr.svc.provider_name",
            FT_STRING, STR_UNICODE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_name_length, {
            "Service Name Length", "mpeg_descr.svc.svc_name_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_name_encoding, {
            "Service Name Encoding", "mpeg_descr.svc.svn_name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_name, {
            "Service Name", "mpeg_descr.svc.svc_name",
            FT_STRING, STR_UNICODE, NULL, 0, NULL, HFILL
        } },

        /* 0x4A Linkage Descriptor */
        { &hf_mpeg_descr_linkage_transport_stream_id, {
            "Transport Stream ID", "mpeg_descr.linkage.tsid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_original_network_id, {
            "Original Network ID", "mpeg_descr.linkage.original_nid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_service_id, {
            "Service ID", "mpeg_descr.linkage.svc_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_linkage_type, {
            "Linkage Type", "mpeg_descr.linkage.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_linkage_linkage_type_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_hand_over_type, {
            "Hand-Over Type", "mpeg_descr.linkage.hand_over_type",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LINKAGE_HAND_OVER_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_reserved1, {
            "Reserved", "mpeg_descr.linkage.reserved1",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LINKAGE_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_origin_type, {
            "Origin Type", "mpeg_descr.linkage.origin_type",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_linkage_origin_type_vals), 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_network_id, {
            "Network ID", "mpeg_descr.linkage.network_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_initial_service_id, {
            "Initial Service ID", "mpeg_descr.linkage.initial_svc_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_target_event_id, {
            "Target Event ID", "mpeg_descr.linkage.target_evt_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_target_listed, {
            "Target Listed", "mpeg_descr.linkage.target_listed",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_linkage_target_listed_vals),
            MPEG_DESCR_LINKAGE_TARGET_LISTED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_event_simulcast, {
            "Event Simulcast", "mpeg_descr.linkage.evt_simulcast",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_linkage_event_simulcast_vals),
            MPEG_DESCR_LINKAGE_EVENT_SIMULCAST_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_reserved2, {
            "Reserved", "mpeg_descr.linkage.reserved2",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LINKAGE_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_private_data_byte, {
            "Private Data", "mpeg_descr.linkage.private_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_interactive_network_id, {
            "Interactive Network ID", "mpeg_descr.interactive_network_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_population_id_loop_count, {
            "Population ID loop count", "mpeg_descr.population_id_loop_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_population_id, {
            "Population ID", "mpeg_descr.population_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_population_id_base, {
            "Population ID Base", "mpeg_descr.population_id_base",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_linkage_population_id_mask, {
            "Population ID Mask", "mpeg_descr.population_id_mask",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x4D Short Event Descriptor */
        { &hf_mpeg_descr_short_event_lang_code, {
            "Language Code", "mpeg_descr.short_evt.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_event_name_length, {
            "Event Name Length", "mpeg_descr.short_evt.name_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_event_name_encoding, {
            "Event Name Encoding", "mpeg_descr.short_evt.name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_event_name, {
            "Event Name", "mpeg_descr.short_evt.name",
            FT_STRING, STR_UNICODE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_event_text_length, {
            "Event Text Length", "mpeg_descr.short_evt.txt_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_event_text_encoding, {
            "Event Text Encoding", "mpeg_descr.short_evt.txt_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_event_text, {
            "Event Text", "mpeg_descr.short_evt.txt",
            FT_STRING, STR_UNICODE, NULL, 0, NULL, HFILL
        } },

        /* 0x4E Extended Event Descriptor */
        { &hf_mpeg_descr_extended_event_descriptor_number, {
            "Descriptor Number", "mpeg_descr.ext_evt.descr_num",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_EXTENDED_EVENT_DESCRIPTOR_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_last_descriptor_number, {
            "Last Descriptor Number", "mpeg_descr.ext_evt.last_descr_num",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_EXTENDED_EVENT_LAST_DESCRIPTOR_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_lang_code, {
            "Language Code", "mpeg_descr.ext_evt.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_length_of_items, {
            "Length of items", "mpeg_descr.ext_evt.items_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_item_description_length, {
            "Item Description Length", "mpeg_descr.ext_evt.item_descr_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_item_description_char, {
            "Item Description", "mpeg_descr.ext_evt.item_descr",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_item_length, {
            "Item Length", "mpeg_descr.ext_evt.item_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_item_char, {
            "Item", "mpeg_descr.ext_evt.item",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_text_length, {
            "Text Length", "mpeg_descr.ext_evt.txt_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_text_encoding, {
            "Text Encoding", "mpeg_descr.ext_evt.txt_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extended_event_text, {
            "Text", "mpeg_descr.ext_evt.txt",
            FT_STRING, STR_UNICODE, NULL, 0, NULL, HFILL
        } },

        /* 0x50 Component Descriptor */
        { &hf_mpeg_descr_component_reserved, {
            "Reserved", "mpeg_descr.component.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_COMPONENT_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_stream_content, {
            "Stream Content", "mpeg_descr.component.stream_content",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_component_stream_content_vals),
            MPEG_DESCR_COMPONENT_STREAM_CONTENT_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_type, {
            "Component Type", "mpeg_descr.component.type",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_content_type, {
            "Stream Content and Component Type", "mpeg_descr.component.content_type",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_component_content_type_vals_ext,
            MPEG_DESCR_COMPONENT_CONTENT_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_tag, {
            "Component Tag", "mpeg_descr.component.tag",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_lang_code, {
            "Language Code", "mpeg_descr.component.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_text, {
            "Text", "mpeg_descr.component.text",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x52 Stream Identifier Descriptor */
        { &hf_mpeg_descr_stream_identifier_component_tag, {
            "Component Tag", "mpeg_descr.stream_id.component_tag",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x53 CA Identifier Descriptor */
        { &hf_mpeg_descr_ca_identifier_system_id, {
            "CA System ID", "mpeg_descr.ca_id.sys_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x54 Content Descriptor */
        { &hf_mpeg_descr_content_nibble, {
            "Nibble Level 1 and 2", "mpeg_descr.content.nibble_1_2",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_content_nibble_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_content_nibble_level_1, {
            "Nibble Level 1", "mpeg_descr.content.nibble_lvl_1",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_content_nibble_level_1_vals_ext,
            MPEG_DESCR_CONTENT_NIBBLE_LEVEL_1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_content_nibble_level_2, {
            "Nibble Level 2", "mpeg_descr.content.nibble_lvl_2",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_CONTENT_NIBBLE_LEVEL_2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_content_user_byte, {
            "User Byte", "mpeg_descr.content.user",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x56 Teletext Descriptor */
        { &hf_mpeg_descr_teletext_lang_code, {
            "Language Code", "mpeg_descr.teletext.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_teletext_type, {
            "Teletext Type", "mpeg_descr.teletext.type",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_teletext_type_vals),
            MPEG_DESCR_TELETEXT_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_teletext_magazine_number, {
            "Magazine Number", "mpeg_descr.teletext.magazine_num",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_TELETEXT_MAGAZINE_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_teletext_page_number, {
            "Page Number", "mpeg_descr.teletext.page_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        /* 0x55 Parental Rating Descriptor */
        { &hf_mpeg_descr_parental_rating_country_code, {
            "Country Code", "mpeg_descr.parental_rating.country_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_parental_rating_rating, {
            "Rating", "mpeg_descr.parental_rating.rating",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_parental_rating_vals_ext, 0, NULL, HFILL
        } },

        /* 0x58 Local Time Offset Descriptor */
        { &hf_mpeg_descr_local_time_offset_country_code, {
            "Country Code", "mpeg_descr.local_time_offset.country_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_local_time_offset_region_id, {
            "Region ID", "mpeg_descr.local_time_offset.region_id",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOCAL_TIME_OFFSET_COUNTRY_REGION_ID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_local_time_offset_reserved, {
            "Reserved", "mpeg_descr.local_time_offset.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOCAL_TIME_OFFSET_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_local_time_offset_polarity, {
            "Time Offset Polarity", "mpeg_descr.local_time_offset.polarity",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_local_time_offset_polarity_vals),
            MPEG_DESCR_LOCAL_TIME_OFFSET_POLARITY, NULL, HFILL
        } },

        { &hf_mpeg_descr_local_time_offset_offset, {
            "Local Time Offset", "mpeg_descr.local_time_offset.offset",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_local_time_offset_time_of_change, {
            "Time of Change", "mpeg_descr.local_time_offset.time_of_change",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_local_time_offset_next_time_offset, {
            "Next Time Offset", "mpeg_descr.local_time_offset.next_time_offset",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x59 Subtitling Descriptor */
        { &hf_mpeg_descr_subtitling_lang_code, {
            "Language Code", "mpeg_descr.subtitling.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_subtitling_type, {
            "Subtitling Type", "mpeg_descr.subtitling.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_subtitling_type_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_subtitling_composition_page_id, {
            "Composition Page ID", "mpeg_descr.subtitling.composition_page_id",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_subtitling_ancillary_page_id, {
            "Ancillary Page ID", "mpeg_descr.subtitling.ancillary_page_id",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        /* 0x5A Terrestrial Delivery System Descriptor */
        { &hf_mpeg_descr_terrestrial_delivery_centre_frequency, {
            "Centre Frequency", "mpeg_descr.terr_delivery.centre_freq",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_bandwidth, {
            "Bandwidth", "mpeg_descr.terr_delivery.bandwidth",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_bandwidth_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_BANDWIDTH_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_priority, {
            "Priority", "mpeg_descr.terr_delivery.priority",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_priority_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_PRIORITY_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_time_slicing_indicator, {
            "Time Slicing Indicator", "mpeg_descr.terr_delivery.time_slicing_ind",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_time_slicing_indicator_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_TIME_SLICING_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_mpe_fec_indicator, {
            "MPE-FEC Indicator", "mpeg_descr.terr_delivery.mpe_fec_ind",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_mpe_fec_indicator_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_MPE_FEC_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_reserved1, {
            "Reserved", "mpeg_descr.terr_delivery.reserved1",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_TERRESTRIAL_DELIVERY_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_constellation, {
            "Constellation", "mpeg_descr.terr_delivery.constellation",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_constellation_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_CONSTELLATION_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_hierarchy_information, {
            "Hierarchy Information", "mpeg_descr.terr_delivery.hierarchy_information",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_hierarchy_information_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_HIERARCHY_INFORMATION_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_code_rate_hp_stream, {
            "Code Rate High Priority Stream", "mpeg_descr.terr_delivery.code_rate_hp_stream",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_code_rate_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_CODE_RATE_HP_STREAM_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_code_rate_lp_stream, {
            "Code Rate Low Priority Stream", "mpeg_descr.terr_delivery.code_rate_lp_stream",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_code_rate_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_CODE_RATE_LP_STREAM_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_guard_interval, {
            "Guard Interval", "mpeg_descr.terr_delivery.guard_interval",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_guard_interval_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_GUARD_INTERVAL_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_transmission_mode, {
            "Transmission Mode", "mpeg_descr.terr_delivery.transmission_mode",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_transmission_mode_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_TRANSMISSION_MODE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_other_frequency_flag, {
            "Other Frequency Flag", "mpeg_descr.terr_delivery.other_freq_flag",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_terrestrial_delivery_other_frequency_flag_vals),
            MPEG_DESCR_TERRESTRIAL_DELIVERY_OTHER_FREQUENCY_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_terrestrial_delivery_reserved2, {
            "Reserved", "mpeg_descr.terr_delivery.reserved2",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },


        /* 0x5F Private Data Specifier */
        { &hf_mpeg_descr_private_data_specifier_id, {
            "Private Data Specifier", "mpeg_descr.private_data_specifier.id",
            FT_UINT32, BASE_HEX, VALS(mpeg_descr_data_specifier_id_vals), 0, NULL, HFILL
        } },

        /* 0x64 Data Broadcast Descriptor */
        { &hf_mpeg_descr_data_bcast_bcast_id, {
            "Data Broadcast ID", "mpeg_descr.data_bcast.id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_data_bcast_id_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_data_bcast_component_tag, {
            "Component Tag", "mpeg_descr.data_bcast.component_tag",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_data_bcast_selector_len, {
            "Selector Length", "mpeg_descr.data_bcast.selector_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_data_bcast_selector_bytes, {
            "Selector Bytes", "mpeg_descr.data_bcast.selector_bytes",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_data_bcast_lang_code, {
            "Language Code", "mpeg_descr.data_bcast.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_data_bcast_text_len, {
            "Text Length", "mpeg_descr.data_bcast.text_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_data_bcast_text, {
            "Text", "mpeg_descr.data_bcast.text",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x66 Data Broadcast ID Descriptor */
        { &hf_mpeg_descr_data_bcast_id_bcast_id, {
            "Data Broadcast ID", "mpeg_descr.data_bcast_id.id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_data_bcast_id_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_data_bcast_id_id_selector_bytes, {
            "ID Selector Bytes", "mpeg_descr.data_bcast_id.id_selector_bytes",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x6A AC-3 Descriptor */
        { &hf_mpeg_descr_ac3_component_type_flag, {
            "Component Type Flag", "mpeg_descr.ac3.component_type_flag",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_ac3_component_type_flag_vals),
            MPEG_DESCR_AC3_COMPONENT_TYPE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_bsid_flag, {
            "BSID Flag", "mpeg_descr.ac3.bsid_flag",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_ac3_bsid_flag_vals),
            MPEG_DESCR_AC3_BSID_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_mainid_flag, {
            "Main ID Flag", "mpeg_descr.ac3_main_id_flag",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_ac3_mainid_flag_vals),
            MPEG_DESCR_AC3_MAINID_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_asvc_flag, {
            "ASVC Flag", "mpeg_descr.ac3.asvc_flag",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_ac3_asvc_flag_vals),
            MPEG_DESCR_AC3_ASVC_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_reserved, {
            "Reserved", "mpeg_descr.ac3.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_AC3_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_component_type_reserved_flag, {
            "Type Reserved Flag", "mpeg_descr.ac3.component_type.reserved_flag",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_AC3_COMPONENT_TYPE_RESERVED_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_component_type_full_service_flag, {
            "Full Service Flag", "mpeg_descr.ac3.component_type.full_service_flag",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_component_type_full_service_flag_vals),
            MPEG_DESCR_AC3_COMPONENT_TYPE_FULL_SERVICE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_component_type_service_type_flags, {
            "Service Type Flags", "mpeg_descr.ac3.component_type.service_type_flags",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_component_type_service_type_flags_vals),
            MPEG_DESCR_AC3_COMPONENT_TYPE_SERVICE_TYPE_FLAGS_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_component_type_number_of_channels_flags, {
            "Number of Channels Flags", "mpeg_descr.ac3.component_type.number_chan_flags",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_component_type_number_of_channels_flags_vals),
            MPEG_DESCR_AC3_COMPONENT_TYPE_NUMBER_OF_CHANNELS_FLAGS, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_bsid, {
            "BSID", "mpeg_descr.ac3.bsid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_mainid, {
            "Main ID", "mpeg_descr.ac3.mainid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_asvc, {
            "ASVC", "mpeg_descr.ac3.asvc",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_additional_info, {
            "Additional Info", "mpeg_descr.ac3.additional_info",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x6F Application Signalling Descriptor */
        { &hf_mpeg_descr_app_sig_app_type, {
            "Application type", "mpeg_descr.app_sig.app_type",
            FT_UINT16, BASE_HEX, NULL, 0x7FFF, NULL, HFILL
        } },

        { &hf_mpeg_descr_app_sig_ait_ver, {
            "AIT version", "mpeg_descr.app_sig.ait_ver",
            FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL
        } },

        /* 0x73 Default Authority Descriptor */
        { &hf_mpeg_descr_default_authority_name, {
            "Default Authority Name", "mpeg_descr.default_authority.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x77 Content Identifier Descriptor */
        { &hf_mpeg_descr_content_identifier_crid_type, {
            "CRID Type", "mpeg_descr.content_identifier.crid_type",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_content_identifier_crid_type_vals),
            MPEG_DESCR_CONTENT_IDENTIFIER_CRID_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_content_identifier_crid_location, {
            "CRID Location", "mpeg_descr.content_identifier.crid_location",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_content_identifier_crid_location_vals),
            MPEG_DESCR_CONTENT_IDENTIFIER_CRID_LOCATION_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_content_identifier_crid_length, {
            "CRID Length", "mpeg_descr.content_identifier.crid_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_content_identifier_crid_bytes, {
            "CRID Bytes", "mpeg_descr.content_identifier.crid_bytes",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_content_identifier_cird_ref, {
            "CRID Reference", "mpeg_descr.content_identifier.crid_ref",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x7F Extension Descriptor */
        { &hf_mpeg_descr_extension_tag_extension, {
            "Descriptor Tag Extension", "mpeg_descr.ext.tag",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_extension_tag_extension_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_extension_data, {
            "Descriptor Extension Data", "mpeg_descr.ext.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* Supplementary Audio Descriptor (part of Extension Descriptor) */
        { &hf_mpeg_descr_extension_supp_audio_mix_type, {
            "Mix type", "mpeg_descr.ext.supp_audio.mix_type",
            FT_UINT8, BASE_HEX, VALS(supp_audio_mix_type_vals), 0x80, NULL, HFILL
        } },

        { &hf_mpeg_descr_extension_supp_audio_ed_cla, {
            "Editorial classification", "mpeg_descr.ext.supp_audio.ed_cla",
            FT_UINT8, BASE_HEX, VALS(supp_audio_ed_cla), 0x7C, NULL, HFILL
        } },

        { &hf_mpeg_descr_extension_supp_audio_lang_code_present, {
            "Language code present", "mpeg_descr.ext.supp_audio.lang_code_present",
            FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL
        } },

        { &hf_mpeg_descr_extension_supp_audio_lang_code, {
            "ISO 639 language code", "mpeg_descr.ext.supp_audio.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_private_data, {
            "Private data", "mpeg_descr.private_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0xA2 Logon Initialize Descriptor */
        { &hf_mpeg_descr_logon_initialize_group_id, {
            "Group ID", "mpeg_descr.logon_init.group_id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_logon_id, {
            "Logon ID", "mpeg_descr.logon_init.logon_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_continuous_carrier_reserved, {
            "Continuous Carrier Reserved", "mpeg_descr.logon_init.continuous_carrier_reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_CONTINUOUS_CARRIER_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_continuous_carrier, {
            "Continuous Carrier", "mpeg_descr.logon_init.continuous_carrier",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_CONTINUOUS_CARRIER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_security_handshake_required, {
            "Security Handshake Required", "mpeg_descr.logon_init.security_handshake_required",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_SECURITY_HANDSHAKE_REQUIRED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_prefix_flag, {
            "Prefix Flag", "mpeg_descr.logon_init.prefix_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_PREFIX_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_data_unit_labelling_flag, {
            "Unit Labelling Flag", "mpeg_descr.logon_init.data_unit_labelling_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_DATA_UNIT_LABELLING_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_mini_slot_flag, {
            "Mini Slot Flag", "mpeg_descr.logon_init.mini_slot_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_MINI_SLOT_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_contention_based_mini_slot_flag, {
            "Contention Based Mini Slot Flag", "mpeg_descr.logon_init.contention_based_mini_slot_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_CONTENTION_BASED_MINI_SLOT_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_capacity_type_flag_reserved, {
            "Capacity Type Flag Reserved", "mpeg_descr.logon_init.capactity_type_flag_reserved",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_CAPACITY_TYPE_FLAG_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_capacity_type_flag, {
            "Capacity Type Flag", "mpeg_descr.logon_init.capactity_type_flag",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_CAPACITY_TYPE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_traffic_burst_type, {
            "Traffic Burst Type", "mpeg_descr.logon_init.traffic_burst_type",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_TRAFFIC_BURST_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_trf_pid, {
            "Return TRF PID", "mpeg_descr.logon_init.return_trf_pid",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_TRF_PID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid_reserved, {
            "Return CTRL MNGM PID Reserved", "mpeg_descr.logon_init.return_mngm_pid_reserved",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_CTRL_MNGM_PID_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid, {
            "Return CTRL MNGM PID", "mpeg_descr.logon_init.return_mngm_pid",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_CTRL_MNGM_PID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_connectivity, {
            "Connectivity", "mpeg_descr.logon_init.connectivity",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_CONNECTIVITY_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_vpi_reserved, {
            "Return VPI Reserved", "mpeg_descr.logon_init.return_vpi_reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_VPI_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_vpi, {
            "Return VPI", "mpeg_descr.logon_init.return_vpi",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_VPI_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_vci, {
            "Return VCI", "mpeg_descr.logon_init.return_vci",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_signalling_vpi_reserved, {
            "Return Signalling VPI Reserved", "mpeg_descr.logon_init.return_signalling_vpi_reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_signalling_vpi, {
            "Return Signalling VPI", "mpeg_descr.logon_init.return_signalling_vpi",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_return_signalling_vci, {
            "Return Signalling VCI", "mpeg_descr.logon_init.return_signalling_vci",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_forward_signalling_vpi_reserved, {
            "Forward Signalling VPI Reserved", "mpeg_descr.logon_init.forward_signalling_vpi_reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_forward_signalling_vpi, {
            "Forward Signalling VPI", "mpeg_descr.logon_init.forward_signalling_vpi",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_forward_signalling_vci, {
            "Forward Signalling VCI", "mpeg_descr.logon_init.forward_signalling_vci",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_cra_level, {
            "CRA Level", "mpeg_descr.logon_init.cra_level",
            FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_vbdc_max_reserved, {
            "VDBC Max Reserved", "mpeg_descr.logon_init.vdbc_max_reserved",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_LOGON_INITIALIZE_VDBC_MAX_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_vbdc_max, {
            "VDBC Max", "mpeg_descr.logon_init.vdbc_max",
            FT_UINT16, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_VDBC_MAX_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_rbdc_max, {
            "RDBC Max", "mpeg_descr.logon_init.rdbc_max",
            FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_rbdc_timeout, {
            "RDBC Timeout", "mpeg_descr.logon_init.rdbc_timeout",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        /* 0xA7 RCS Content Descriptor */
        { &hf_mpeg_descr_rcs_content_table_id, {
            "Table ID", "mpeg_descr.rcs_content.tid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0xCB CI+ Content Label Descriptor */
        { &hf_mpeg_descr_ciplus_cl_cb_min, {
           "Content byte minimum value", "mpeg_descr.ciplus_content_label.content_byte_min",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_cl_cb_max, {
           "Content byte maximum value", "mpeg_descr.ciplus_content_label.content_byte_max",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_cl_lang, {
         "ISO 639 language code", "mpeg_descr.ciplus_content_label.lang_code",
         FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_cl_label, {
          "Content label", "mpeg_descr.ciplus_content_label.label",
          FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0xCC CI+ Service Descriptor */
        { &hf_mpeg_descr_ciplus_svc_id, {
            "Service ID", "mpeg_descr.ciplus_svc.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_svc_type, {
            "Service type", "mpeg_descr.ciplus_svc.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_service_type_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_svc_visible, {
            "Visible Service Flag", "mpeg_descr.ciplus_svc.visible",
            FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_svc_selectable, {
            "Selectable Service Flag", "mpeg_descr.ciplus_svc.selectable",
            FT_UINT16, BASE_HEX, NULL, 0x4000, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_svc_lcn, {
            "Logical Channel Number", "mpeg_descr.ciplus_svc.lcn",
            FT_UINT16, BASE_DEC, NULL, 0x3FFF, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_svc_prov_name, {
            "Service Provider Name", "mpeg_descr.ciplus_svc.provider_name",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_svc_name, {
            "Service Name", "mpeg_descr.ciplus_svc.name",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_prot_free_ci_mode, {
            "Free CI mode", "mpeg_descr.ciplus_prot.free_ci_mode",
            FT_BOOLEAN, 8, TFS(&tfs_prot_noprot), 0x80, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_prot_match_brand_flag, {
            "Match brand flag", "mpeg_descr.ciplus_prot.match_brand_flag",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_prot_num_entries, {
            "Number of entries", "mpeg_descr.ciplus_prot.num_entries",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ciplus_prot_brand_id, {
            "CICAM brand identifier", "mpeg_descr.ciplus_prot.brand_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } }
    };

    static gint *ett[] = {
        &ett_mpeg_descriptor,
        &ett_mpeg_descriptor_extended_event_item,
        &ett_mpeg_descriptor_component_content_type,
        &ett_mpeg_descriptor_content_nibble,
        &ett_mpeg_descriptor_vbi_data_service,
        &ett_mpeg_descriptor_content_identifier_crid,
        &ett_mpeg_descriptor_service_list,
        &ett_mpeg_descriptor_ac3_component_type,
        &ett_mpeg_descriptor_linkage_population_id
    };

    proto_mpeg_descriptor = proto_register_protocol("MPEG2 Descriptors", "MPEG Descriptor", "mpeg_descr");
    proto_register_field_array(proto_mpeg_descriptor, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
