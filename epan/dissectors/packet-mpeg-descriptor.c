/* packet-mpeg-descriptor.c
 * Routines for MPEG2 (ISO/ISO 13818-1 and co) descriptors
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/dvb_chartbl.h>
#include "packet-mpeg-sect.h"
#include "packet-mpeg-descriptor.h"

void proto_register_mpeg_descriptor(void);

static int proto_mpeg_descriptor;
static int hf_mpeg_descriptor_tag;
static int hf_mpeg_descriptor_length;
static int hf_mpeg_descriptor_data;

static int ett_mpeg_descriptor;

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
    /* SID (0x71) from ETSI TS 102 812 */
    { 0x71, "Service Identifier Descriptor" },
    { 0x72, "Service Availability Descriptor" },
    /* 0x73...0x76 from ETSI TS 102 323 */
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
    /* 0x7D from ETSI TS 102 727 */
    { 0x7D, "XAIT Content Location Descriptor" },
    { 0x7E, "FTA Content Management Descriptor" },
    { 0x7F, "Extension Descriptor" },

    /* From ATSC A/52 */
    { 0x81, "ATSC A/52 AC-3 Audio Descriptor" },

    /* From Nordig Unified Requirements */
    { 0x83, "NorDig Logical Channel Descriptor v1" },
    { 0x87, "NorDig Logical Channel Descriptor v2" },

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
static int hf_mpeg_descr_video_stream_multiple_frame_rate_flag;
static int hf_mpeg_descr_video_stream_frame_rate_code;
static int hf_mpeg_descr_video_stream_mpeg1_only_flag;
static int hf_mpeg_descr_video_stream_constrained_parameter_flag;
static int hf_mpeg_descr_video_stream_still_picture_flag;
static int hf_mpeg_descr_video_stream_profile_and_level_indication;
static int hf_mpeg_descr_video_stream_chroma_format;
static int hf_mpeg_descr_video_stream_frame_rate_extension_flag;
static int hf_mpeg_descr_video_stream_reserved;

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
proto_mpeg_descriptor_dissect_video_stream(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{

    uint8_t mpeg1_only_flag;

    mpeg1_only_flag = tvb_get_uint8(tvb, offset) & MPEG_DESCR_VIDEO_STREAM_MPEG1_ONLY_FLAG_MASK;
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
static int hf_mpeg_descr_audio_stream_free_format_flag;
static int hf_mpeg_descr_audio_stream_id;
static int hf_mpeg_descr_audio_stream_layer;
static int hf_mpeg_descr_audio_stream_variable_rate_audio_indicator;
static int hf_mpeg_descr_audio_stream_reserved;

#define MPEG_DESCR_AUDIO_STREAM_FREE_FORMAT_FLAG_MASK                   0x80
#define MPEG_DESCR_AUDIO_STREAM_ID_MASK                                 0x40
#define MPEG_DESCR_AUDIO_STREAM_LAYER_MASK                              0x30
#define MPEG_DESCR_AUDIO_STREAM_VARIABLE_RATE_AUDIO_INDICATOR_MASK      0x08
#define MPEG_DESCR_AUDIO_STREAM_RESERVED_MASK                           0x07

static const value_string mpeg_descr_audio_stream_free_format_flag_vals[] = {
    { 0x00, "bitrate_index is not 0" },
    { 0x01, "One or more audio frame has bitrate_index = 0" },

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
proto_mpeg_descriptor_dissect_audio_stream(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_free_format_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_layer, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_variable_rate_audio_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_audio_stream_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x05 Registration Descriptor */

static const value_string mpeg_descr_registration_reg_form_vals[] = {
    { 0x41432D33u, "AC-3 - Advanced Television Systems Committee" },
    { 0x41444652u, "ADFR - SNPTV" },
    { 0x414d434eu, "AMCN - AMC Networks Inc." },
    { 0x41525253u, "ARRS - Arris Group, Inc." },
    { 0x41563031u, "AV01 - Alliance for Open Media" },
    { 0x41565341u, "AVSA - Audio Video Coding Standard Working Group of China" },
    { 0x41565356u, "AVSV - Audio Video Coding Standard Working Group of China" },
    { 0x42444330u, "BDC0 - Broadcast Data Corporation" },
    { 0x42535344u, "BSSD - Society of Motion Picture and Television Engineers" },
    { 0x4341504fu, "CAPO - SMPTE" },
    { 0x43554549u, "CUEI - Society of Cable Telecommunications Engineers" },
    { 0x44444544u, "DDED - LGEUS" },
    { 0x44495343u, "DISC - DISCOVERY COMMUNICATIONS, LLC." },
    { 0x44495348u, "DISH - EchoStar Communications Corporation" },
    { 0x646d6174u, "dmat - Dolby Laboratories, Inc." },
    { 0x44524131u, "DRA1 - Digital Rise" },
    { 0x64726163u, "drac - British Broadcasting Corporation" },
    { 0x44544731u, "DTG1 - Digital TV Group" },
    { 0x44545331u, "DTS1 - DTS Inc." },
    { 0x44545332u, "DTS2 - DTS Inc." },
    { 0x44545333u, "DTS3 - DTS Inc." },
    { 0x44545649u, "DTVI - DTV Innovations" },
    { 0x44564446u, "DVDF - DVD Format/Logo Licensing Corporation" },
    { 0x45414333u, "EAC3 - Dolby Laboratories, Inc." },
    { 0x45425030u, "EBP0 - Cable Television Laboratories, Inc." },
    { 0x45425031u, "EBP1 - Cable Television Laboratories, Inc." },
    { 0x45425032u, "EBP2 - Cable Television Laboratories, Inc." },
    { 0x45425033u, "EBP3 - Cable Television Laboratories, Inc." },
    { 0x45425034u, "EBP4 - Cable Television Laboratories, Inc." },
    { 0x45425035u, "EBP5 - Cable Television Laboratories, Inc." },
    { 0x45425036u, "EBP6 - Cable Television Laboratories, Inc." },
    { 0x45425037u, "EBP7 - Cable Television Laboratories, Inc." },
    { 0x45425038u, "EBP8 - Cable Television Laboratories, Inc." },
    { 0x45425039u, "EBP9 - Cable Television Laboratories, Inc." },
    { 0x45545631u, "ETV1 - Cable Television Laboratories, Inc." },
    { 0x464f5843u, "FOXC - FOX Corporation" },
    { 0x47413934u, "GA94 - Advanced Television Systems Committee" },
    { 0x47574b53u, "GWKS - GuideWorks" },
    { 0x48444d56u, "HDMV - Sony Corporation" },
    { 0x48444d58u, "HDMX - Matsushita Electric Industrial Co. Ltd" },
    { 0x48445052u, "HDPR - Network Business Group" },
    { 0x484c4954u, "HLIT - Harmonic Inc." },
    { 0x49443320u, "ID3  - Organization Apple, Inc." },
    { 0x4b4c5641u, "KLVA - Society of Motion Picture and Television Engineers" },
    { 0x4c41534cu, "LASL - LaSalle Media LLC" },
    { 0x4c495053u, "LIPS - Society of Motion Picture and Television Engineers" },
    { 0x4c552d41u, "LU-A - Harris Corporation" },
    { 0x6d6c7061u, "mlpa - Dolby Laboratories, Inc." },
    { 0x4d54524du, "MTRM - Victor Company of Japan, Limited" },
    { 0x4e424355u, "NBCU - NBC Universal" },
    { 0x4e4d5231u, "NMR1 - Nielsen Media Research" },
    { 0x4e504f31u, "NPO1 - Nederlandse Publieke Omroep (NPO, Dutch Public Broadcasting)" },
    { 0x4e575456u, "NWTV - Digital TV Information Research Group" },
    { 0x4f4d5643u, "OMVC - Open Mobile Video Coalition (OMVC)" },
    { 0x4f707573u, "Opus - Mozilla" },
    { 0x50415558u, "PAUX - Philips DVS" },
    { 0x504d5346u, "PMSF - Sony Corporation" },
    { 0x50524d43u, "PRMC - Philips DVS" },
    { 0x50585341u, "PXSA - Proximus" },
    { 0x52544c4eu, "RTLN - RTL Nederland" },
    { 0x53425342u, "SBSB - SBS Broadcasting" },
    { 0x53435445u, "SCTE - Society of Cable Telecommunications Engineers" },
    { 0x53454e31u, "SEN1 - Sencore" },
    { 0x53455346u, "SESF - Sony Corporation" },
    { 0x534f5049u, "SOPI - Sony Corporation" },
    { 0x53504c43u, "SPLC - Society of Motion Picture and Television Engineers" },
    { 0x53564d44u, "SVMD - Society of Motion Picture and Television Engineers" },
    { 0x53594e43u, "SYNC - Syncbak, Inc." },
    { 0x535a4d49u, "SZMI - Building B, Inc" },
    { 0x54524956u, "TRIV - Triveni Digital" },
    { 0x54534256u, "TSBV - Toshiba Corporation Digital Media Network Company" },
    { 0x54534856u, "TSHV - Sony Corporation" },
    { 0x54534d56u, "TSMV - Sony Corporation" },
    { 0x54544130u, "TTA0 - Telecommunication Technology Association(TTA)" },
    { 0x54564731u, "TVG1 - Rovi Corporation" },
    { 0x54564732u, "TVG2 - Rovi Corporation" },
    { 0x54564733u, "TVG3 - Rovi Corporation" },
    { 0x554c4531u, "ULE1 - University of Aberdeen (on behalf of the Internet Engineering Task Force, IETF)" },
    { 0x554c4930u, "ULI0 - Update Logic, Inc." },
    { 0x56432d31u, "VC-1 - Society of Motion Picture and Television Engineers" },
    { 0x56432d34u, "VC-4 - Society of Motion Picture and Television Engineers" },
    { 0x564d4e55u, "VMNU - Viacom" },
    { 0x584d505fu, "XMP_ - Adobe Systems" },

    { 0x55533030u, "US00 - US Government Registration 00" },
    { 0x55533031u, "US01 - US Government Registration 01" },
    { 0x55533032u, "US02 - US Government Registration 02" },
    { 0x55533033u, "US03 - US Government Registration 03" },
    { 0x55533034u, "US04 - US Government Registration 04" },
    { 0x55533035u, "US05 - US Government Registration 05" },
    { 0x55533036u, "US06 - US Government Registration 06" },
    { 0x55533037u, "US07 - US Government Registration 07" },
    { 0x55533038u, "US08 - US Government Registration 08" },
    { 0x55533039u, "US09 - US Government Registration 09" },

    { 0x55533130u, "US10 - US Government Registration 10" },
    { 0x55533131u, "US11 - US Government Registration 11" },
    { 0x55533132u, "US12 - US Government Registration 12" },
    { 0x55533133u, "US13 - US Government Registration 13" },
    { 0x55533134u, "US14 - US Government Registration 14" },
    { 0x55533135u, "US15 - US Government Registration 15" },
    { 0x55533136u, "US16 - US Government Registration 16" },
    { 0x55533137u, "US17 - US Government Registration 17" },
    { 0x55533138u, "US18 - US Government Registration 18" },
    { 0x55533139u, "US19 - US Government Registration 19" },

    { 0x55533230u, "US20 - US Government Registration 20" },
    { 0x55533231u, "US21 - US Government Registration 21" },
    { 0x55533232u, "US22 - US Government Registration 22" },
    { 0x55533233u, "US23 - US Government Registration 23" },
    { 0x55533234u, "US24 - US Government Registration 24" },
    { 0x55533235u, "US25 - US Government Registration 25" },
    { 0x55533236u, "US26 - US Government Registration 26" },
    { 0x55533237u, "US27 - US Government Registration 27" },
    { 0x55533238u, "US28 - US Government Registration 28" },
    { 0x55533239u, "US29 - US Government Registration 29" },

    { 0x55533330u, "US30 - US Government Registration 30" },
    { 0x55533331u, "US31 - US Government Registration 31" },
    { 0x55533332u, "US32 - US Government Registration 32" },
    { 0x55533333u, "US33 - US Government Registration 33" },
    { 0x55533334u, "US34 - US Government Registration 34" },
    { 0x55533335u, "US35 - US Government Registration 35" },
    { 0x55533336u, "US36 - US Government Registration 36" },
    { 0x55533337u, "US37 - US Government Registration 37" },
    { 0x55533338u, "US38 - US Government Registration 38" },
    { 0x55533339u, "US39 - US Government Registration 39" },

    { 0x55533430u, "US40 - US Government Registration 40" },
    { 0x55533431u, "US41 - US Government Registration 41" },
    { 0x55533432u, "US42 - US Government Registration 42" },
    { 0x55533433u, "US43 - US Government Registration 43" },
    { 0x55533434u, "US44 - US Government Registration 44" },
    { 0x55533435u, "US45 - US Government Registration 45" },
    { 0x55533436u, "US46 - US Government Registration 46" },
    { 0x55533437u, "US47 - US Government Registration 47" },
    { 0x55533438u, "US48 - US Government Registration 48" },
    { 0x55533439u, "US49 - US Government Registration 49" },

    { 0x55533530u, "US50 - US Government Registration 50" },
    { 0x55533531u, "US51 - US Government Registration 51" },
    { 0x55533532u, "US52 - US Government Registration 52" },
    { 0x55533533u, "US53 - US Government Registration 53" },
    { 0x55533534u, "US54 - US Government Registration 54" },
    { 0x55533535u, "US55 - US Government Registration 55" },
    { 0x55533536u, "US56 - US Government Registration 56" },
    { 0x55533537u, "US57 - US Government Registration 57" },
    { 0x55533538u, "US58 - US Government Registration 58" },
    { 0x55533539u, "US59 - US Government Registration 59" },

    { 0x55533630u, "US60 - US Government Registration 60" },
    { 0x55533631u, "US61 - US Government Registration 61" },
    { 0x55533632u, "US62 - US Government Registration 62" },
    { 0x55533633u, "US63 - US Government Registration 63" },
    { 0x55533634u, "US64 - US Government Registration 64" },
    { 0x55533635u, "US65 - US Government Registration 65" },
    { 0x55533636u, "US66 - US Government Registration 66" },
    { 0x55533637u, "US67 - US Government Registration 67" },
    { 0x55533638u, "US68 - US Government Registration 68" },
    { 0x55533639u, "US69 - US Government Registration 69" },

    { 0x55533730u, "US70 - US Government Registration 70" },
    { 0x55533731u, "US71 - US Government Registration 71" },
    { 0x55533732u, "US72 - US Government Registration 72" },
    { 0x55533733u, "US73 - US Government Registration 73" },
    { 0x55533734u, "US74 - US Government Registration 74" },
    { 0x55533735u, "US75 - US Government Registration 75" },
    { 0x55533736u, "US76 - US Government Registration 76" },
    { 0x55533737u, "US77 - US Government Registration 77" },
    { 0x55533738u, "US78 - US Government Registration 78" },
    { 0x55533739u, "US79 - US Government Registration 79" },

    { 0x55533830u, "US80 - US Government Registration 80" },
    { 0x55533831u, "US81 - US Government Registration 81" },
    { 0x55533832u, "US82 - US Government Registration 82" },
    { 0x55533833u, "US83 - US Government Registration 83" },
    { 0x55533834u, "US84 - US Government Registration 84" },
    { 0x55533835u, "US85 - US Government Registration 85" },
    { 0x55533836u, "US86 - US Government Registration 86" },
    { 0x55533837u, "US87 - US Government Registration 87" },
    { 0x55533838u, "US88 - US Government Registration 88" },
    { 0x55533839u, "US89 - US Government Registration 89" },

    { 0x55533930u, "US90 - US Government Registration 90" },
    { 0x55533931u, "US91 - US Government Registration 91" },
    { 0x55533932u, "US92 - US Government Registration 92" },
    { 0x55533933u, "US93 - US Government Registration 93" },
    { 0x55533934u, "US94 - US Government Registration 94" },
    { 0x55533935u, "US95 - US Government Registration 95" },
    { 0x55533936u, "US96 - US Government Registration 96" },
    { 0x55533937u, "US97 - US Government Registration 97" },
    { 0x55533938u, "US98 - US Government Registration 98" },
    { 0x55533939u, "US99 - US Government Registration 99" },

    { 0x00, NULL }
};

static int hf_mpeg_descr_reg_form_id;
static int hf_mpeg_descr_reg_add_id_inf;

static void
proto_mpeg_descriptor_dissect_registration(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned  offset_start;

    offset_start = offset;
    proto_tree_add_item(tree, hf_mpeg_descr_reg_form_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    while (offset-offset_start<len) {
        proto_tree_add_item(tree, hf_mpeg_descr_reg_add_id_inf, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
}

/* 0x06 Data Stream Alignment Descriptor */
static int hf_mpeg_descr_data_stream_alignment;

static const value_string mpeg_descr_data_stream_alignment_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Slice, or video access unit" },
    { 0x02, "Video access unit" },
    { 0x03, "GOP, or SEQ" },
    { 0x04, "SEQ" },

    { 0x00, NULL }
};

static void
proto_mpeg_descriptor_dissect_data_stream_alignment(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_data_stream_alignment, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x09 CA Descriptor */
static int hf_mpeg_descr_ca_system_id;
static int hf_mpeg_descr_ca_reserved;
static int hf_mpeg_descr_ca_pid;
static int hf_mpeg_descr_ca_private;

#define MPEG_DESCR_CA_RESERVED_MASK 0xE000
#define MPEG_DESCR_CA_PID_MASK      0x1FFF

static void
proto_mpeg_descriptor_dissect_ca(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
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
static int hf_mpeg_descr_iso639_lang;
static int hf_mpeg_descr_iso639_type;

static const value_string mpeg_descr_iso639_type_vals[] = {
    { 0x00, "Undefined" },
    { 0x01, "Clean Effects" },
    { 0x02, "Hearing Impaired" },
    { 0x03, "Visual Impaired Commentary" },

    { 0x00, NULL }
};

static void
proto_mpeg_descriptor_dissect_iso639(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    if (len > 1)
        proto_tree_add_item(tree, hf_mpeg_descr_iso639_lang, tvb, offset, len - 1, ENC_ASCII);
    offset += len - 1;
    proto_tree_add_item(tree, hf_mpeg_descr_iso639_type, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x0B System Clock Descriptor */
static int hf_mpeg_descr_system_clock_external_clock_reference_indicator;
static int hf_mpeg_descr_system_clock_reserved1;
static int hf_mpeg_descr_system_clock_accuracy_integer;
static int hf_mpeg_descr_system_clock_accuracy_exponent;
static int hf_mpeg_descr_system_clock_reserved2;

#define MPEG_DESCR_SYSTEM_CLOCK_EXTERNAL_CLOCK_REFERENCE_INDICATOR_MASK 0x80
#define MPEG_DESCR_SYSTEM_CLOCK_RESERVED1_MASK                          0x40
#define MPEG_DESCR_SYSTEM_CLOCK_ACCURACY_INTEGER_MASK                   0x3F
#define MPEG_DESCR_SYSTEM_CLOCK_ACCURACY_EXPONENT_MASK                  0xE0
#define MPEG_DESCR_SYSTEM_CLOCK_RESERVED2_MASK                          0x1F

static void
proto_mpeg_descriptor_dissect_system_clock(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_external_clock_reference_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_accuracy_integer, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_accuracy_exponent, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_system_clock_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x0E Maximum Bitrate Descriptor */
static int hf_mpeg_descr_max_bitrate_reserved;
static int hf_mpeg_descr_max_bitrate;

#define MPEG_DESCR_MAX_BITRATE_RESERVED_MASK    0xC00000
#define MPEG_DESCR_MAX_BITRATE_MASK     0x3FFFFF

static void
proto_mpeg_descriptor_dissect_max_bitrate(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_item *rate_item;

    uint32_t rate;

    proto_tree_add_item(tree, hf_mpeg_descr_max_bitrate_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    rate = tvb_get_ntoh24(tvb, offset) & MPEG_DESCR_MAX_BITRATE_MASK;
    rate_item = proto_tree_add_item(tree, hf_mpeg_descr_max_bitrate, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(rate_item, " (%u bytes/sec)", rate * 50);
}

/* 0x10 Smoothing Buffer Descriptor */
static int hf_mpeg_descr_smoothing_buffer_reserved1;
static int hf_mpeg_descr_smoothing_buffer_leak_rate;
static int hf_mpeg_descr_smoothing_buffer_reserved2;
static int hf_mpeg_descr_smoothing_buffer_size;

#define MPEG_DESCR_SMOOTHING_BUFFER_RESERVED1_MASK  0xC00000
#define MPEG_DESCR_SMOOTHING_BUFFER_LEAK_RATE_MASK  0x3FFFFF
#define MPEG_DESCR_SMOOTHING_BUFFER_RESERVED2_MASK  0xC00000
#define MPEG_DESCR_SMOOTHING_BUFFER_SIZE_MASK       0x3FFFFF

static void
proto_mpeg_descriptor_dissect_smoothing_buffer(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_item *leak_rate_item;

    uint32_t leak_rate;

    proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_reserved1, tvb, offset, 3, ENC_BIG_ENDIAN);
    leak_rate = tvb_get_ntoh24(tvb, offset) & MPEG_DESCR_SMOOTHING_BUFFER_LEAK_RATE_MASK;
    leak_rate_item = proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_leak_rate, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(leak_rate_item, " (%u bytes/sec)", leak_rate * 400 / 8);
    offset += 3;

    proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_reserved2, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_smoothing_buffer_size, tvb, offset, 3, ENC_BIG_ENDIAN);

}

/* 0x11 STD Descriptor */
static int hf_mpeg_descr_std_reserved;
static int hf_mpeg_descr_std_leak_valid;

#define MPEG_DESCR_STD_RESERVED_MASK    0xFE
#define MPEG_DESCR_STD_LEAK_VALID_MASK  0x01

static void
proto_mpeg_descriptor_dissect_std(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_std_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_std_leak_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x13 Carousel Identifier Descriptor */
static int hf_mpeg_descr_carousel_identifier_id;
static int hf_mpeg_descr_carousel_identifier_format_id;
static int hf_mpeg_descr_carousel_identifier_module_version;
static int hf_mpeg_descr_carousel_identifier_module_id;
static int hf_mpeg_descr_carousel_identifier_block_size;
static int hf_mpeg_descr_carousel_identifier_module_size;
static int hf_mpeg_descr_carousel_identifier_compression_method;
static int hf_mpeg_descr_carousel_identifier_original_size;
static int hf_mpeg_descr_carousel_identifier_timeout;
static int hf_mpeg_descr_carousel_identifier_object_key_len;
static int hf_mpeg_descr_carousel_identifier_object_key_data;
static int hf_mpeg_descr_carousel_identifier_private;

static const value_string mpeg_descr_carousel_identifier_format_id_vals[] = {
    { 0x00, "No Format Specifier" },
    { 0x01, "Format Specifier" },

    { 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_carousel_identifier(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned  key_len;
    uint8_t format_id;
    unsigned  private_len = 0;

    proto_tree_add_item(tree, hf_mpeg_descr_carousel_identifier_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    format_id = tvb_get_uint8(tvb, offset);
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

        key_len = tvb_get_uint8(tvb, offset);
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
static int hf_mpeg_descr_association_tag;
static int hf_mpeg_descr_association_tag_use;
static int hf_mpeg_descr_association_tag_selector_len;
static int hf_mpeg_descr_association_tag_transaction_id;
static int hf_mpeg_descr_association_tag_timeout;
static int hf_mpeg_descr_association_tag_selector_bytes;
static int hf_mpeg_descr_association_tag_private_bytes;

static void
proto_mpeg_descriptor_dissect_association_tag(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned   end = offset + len;
    uint16_t use;
    uint8_t selector_len;

    proto_tree_add_item(tree, hf_mpeg_descr_association_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    use = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_association_tag_use, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    selector_len = tvb_get_uint8(tvb, offset);
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
static int hf_mpeg_descr_avc_vid_profile_idc;
static int hf_mpeg_descr_avc_vid_constraint_set0_flag;
static int hf_mpeg_descr_avc_vid_constraint_set1_flag;
static int hf_mpeg_descr_avc_vid_constraint_set2_flag;
static int hf_mpeg_descr_avc_vid_compatible_flags;
static int hf_mpeg_descr_avc_vid_level_idc;
static int hf_mpeg_descr_avc_vid_still_present;
static int hf_mpeg_descr_avc_vid_24h_picture_flag;
static int hf_mpeg_descr_avc_vid_reserved;

#define MPEG_DESCR_AVC_VID_CONSTRAINT_SET0_FLAG_MASK    0x80
#define MPEG_DESCR_AVC_VID_CONSTRAINT_SET1_FLAG_MASK    0x40
#define MPEG_DESCR_AVC_VID_CONSTRAINT_SET2_FLAG_MASK    0x20
#define MPEG_DESCR_AVC_VID_COMPATIBLE_FLAGS_MASK        0x1F
#define MPEG_DESCR_AVC_VID_STILL_PRESENT_MASK           0x80
#define MPEG_DESCR_AVC_VID_24H_PICTURE_FLAG_MASK        0x40
#define MPEG_DESCR_AVC_VID_RESERVED_MASK                0x3F

static void
proto_mpeg_descriptor_dissect_avc_vid(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
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
static int hf_mpeg_descr_network_name_encoding;
static int hf_mpeg_descr_network_name_descriptor;

static void
proto_mpeg_descriptor_dissect_network_name(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    dvb_encoding_e  encoding;
    unsigned enc_len = dvb_analyze_string_charset(tvb, offset, len, &encoding);
    dvb_add_chartbl(tree, hf_mpeg_descr_network_name_encoding, tvb, offset, enc_len, encoding);

    proto_tree_add_item(tree, hf_mpeg_descr_network_name_descriptor, tvb, offset+enc_len, len-enc_len, dvb_enc_to_item_enc(encoding));
}

/* 0x41 Service List Descriptor */
static int hf_mpeg_descr_service_list_id;
static int hf_mpeg_descr_service_list_type;

static int ett_mpeg_descriptor_service_list;

static void
proto_mpeg_descriptor_dissect_service_list(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned   end = offset + len;
    uint16_t svc_id;

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
static int hf_mpeg_descr_stuffing;

static void
proto_mpeg_descriptor_stuffing(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_stuffing, tvb, offset, len, ENC_NA);
}

/* 0x43 Satellite Delivery System Descriptor */
static int hf_mpeg_descr_satellite_delivery_frequency;
static int hf_mpeg_descr_satellite_delivery_orbital_position;
static int hf_mpeg_descr_satellite_delivery_west_east_flag;
static int hf_mpeg_descr_satellite_delivery_polarization;
static int hf_mpeg_descr_satellite_delivery_roll_off;
static int hf_mpeg_descr_satellite_delivery_zero;
static int hf_mpeg_descr_satellite_delivery_modulation_system;
static int hf_mpeg_descr_satellite_delivery_modulation_type;
static int hf_mpeg_descr_satellite_delivery_symbol_rate;
static int hf_mpeg_descr_satellite_delivery_fec_inner;

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
proto_mpeg_descriptor_dissect_satellite_delivery(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{

    double frequency, symbol_rate;
    float orbital_position;
    uint8_t modulation_system;

    frequency = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset)) * 10.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+1)) / 10.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+2)) / 1000.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+3)) / 100000.0;
    proto_tree_add_double(tree, hf_mpeg_descr_satellite_delivery_frequency,
            tvb, offset, 4, frequency);
    offset += 4;

    orbital_position = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset)) * 10.0f +
                       MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+1)) / 10.0f;
    proto_tree_add_float(tree, hf_mpeg_descr_satellite_delivery_orbital_position,
            tvb, offset, 2, orbital_position);
    offset += 2;

    modulation_system = tvb_get_uint8(tvb, offset) & MPEG_DESCR_SATELLITE_DELIVERY_MODULATION_SYSTEM_MASK;

    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_west_east_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_polarization, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (modulation_system)
        proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_roll_off, tvb, offset, 1, ENC_BIG_ENDIAN);
    else
        proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_zero, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_modulation_system, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_modulation_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    symbol_rate = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset)) * 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+1)) / 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+2)) / 1000.0 +
                  /* symbol rate is 28 bits, only the upper 4 bits of this byte are used */
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+3)>>4) / 10000.0;
    proto_tree_add_double_format_value(tree, hf_mpeg_descr_satellite_delivery_symbol_rate,
            tvb, offset, 4, symbol_rate, "%3.4f MSym/s", symbol_rate);
    offset += 3;

    proto_tree_add_item(tree, hf_mpeg_descr_satellite_delivery_fec_inner, tvb, offset, 1, ENC_BIG_ENDIAN);

}

/* 0x44 Cable Delivery System Descriptor */
static int hf_mpeg_descr_cable_delivery_frequency;
static int hf_mpeg_descr_cable_delivery_reserved;
static int hf_mpeg_descr_cable_delivery_fec_outer;
static int hf_mpeg_descr_cable_delivery_modulation;
static int hf_mpeg_descr_cable_delivery_symbol_rate;
static int hf_mpeg_descr_cable_delivery_fec_inner;

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
proto_mpeg_descriptor_dissect_cable_delivery(tvbuff_t *tvb, unsigned offset, proto_tree *tree) {

    double frequency, symbol_rate;

    frequency = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset)) * 100.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+1)) +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+2)) / 100.0 +
                MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+3)) / 10000.0;
    proto_tree_add_double_format_value(tree, hf_mpeg_descr_cable_delivery_frequency,
            tvb, offset, 4, frequency, "%4.4f MHz", frequency);
    offset += 4;

    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_fec_outer, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_modulation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    symbol_rate = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset)) * 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+1)) / 10.0 +
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+2)) / 1000.0 +
                  /* symbol rate is 28 bits, only the upper 4 bits of this byte are used */
                  MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+3)>>4) / 10000.0;
    proto_tree_add_double_format_value(tree, hf_mpeg_descr_cable_delivery_symbol_rate,
            tvb, offset, 4, symbol_rate, "%3.4f MSymbol/s", symbol_rate);
    offset += 3;
    proto_tree_add_item(tree, hf_mpeg_descr_cable_delivery_fec_inner, tvb, offset, 1, ENC_BIG_ENDIAN);


}

/* 0x45 VBI Data Descriptor */
static int hf_mpeg_descr_vbi_data_service_id;
static int hf_mpeg_descr_vbi_data_descr_len;
static int hf_mpeg_descr_vbi_data_reserved1;
static int hf_mpeg_descr_vbi_data_field_parity;
static int hf_mpeg_descr_vbi_data_line_offset;
static int hf_mpeg_descr_vbi_data_reserved2;

#define MPEG_DESCR_VBI_DATA_RESERVED1_MASK  0xC0
#define MPEG_DESCR_VBI_DATA_FIELD_PARITY_MASK   0x20
#define MPEG_DESCR_VBI_DATA_LINE_OFFSET_MASK    0x1F

static int ett_mpeg_descriptor_vbi_data_service;

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
proto_mpeg_descriptor_dissect_vbi_data(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{

    uint8_t svc_id, svc_len;
    unsigned  end = offset + len, svc_end;

    proto_tree *svc_tree;

    while (offset < end) {
        svc_id  = tvb_get_uint8(tvb, offset);
        svc_len = tvb_get_uint8(tvb, offset + 1);
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
static int hf_mpeg_descr_bouquet_name_encoding;
static int hf_mpeg_descr_bouquet_name;

static void
proto_mpeg_descriptor_dissect_bouquet_name(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    dvb_encoding_e  encoding;
    unsigned enc_len = dvb_analyze_string_charset(tvb, offset, len, &encoding);
    dvb_add_chartbl(tree, hf_mpeg_descr_bouquet_name_encoding, tvb, offset, enc_len, encoding);

    proto_tree_add_item(tree, hf_mpeg_descr_bouquet_name, tvb, offset+enc_len, len-enc_len, dvb_enc_to_item_enc(encoding));
}

/* 0x48 Service Descriptor */
static int hf_mpeg_descr_service_type;
static int hf_mpeg_descr_service_provider_name_length;
static int hf_mpeg_descr_service_provider_name_encoding;
static int hf_mpeg_descr_service_provider;
static int hf_mpeg_descr_service_name_length;
static int hf_mpeg_descr_service_name_encoding;
static int hf_mpeg_descr_service_name;

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
    { 0x16, "H.264/AVC SD digital television service" },
    { 0x17, "H.264/AVC SD NVOD time-shifted service" },
    { 0x18, "H.264/AVC SD NVOD reference service" },
    { 0x19, "H.264/AVC HD digital television service" },
    { 0x1A, "H.264/AVC HD NVOD time-shifted service" },
    { 0x1B, "H.264/AVC NVOD reference service" },
    { 0x1C, "H.264/AVC frame compatible plano-stereoscopic HD digital television service" },
    { 0x1D, "H.264/AVC rame compatible plano-stereoscopic HD NVOD time-shifted service" },
    { 0x1E, "H.264/AVC frame compatible plano-stereoscopic HD NVOD reference service" },
    { 0x1F, "HEVC digital television service" },
    { 0x20, "HEVC UHD DTV service with either: a resolution up to 3840x2160, HDR and/or a frame rate of 100 Hz, \
120000/1001Hz, or 120 Hz; or a resolution greater than 3840x2160, SDR or HDR, up to 60Hz." },

    { 0x00, NULL }
};
/* global variable that's shared e.g. with DVB-CI */
value_string_ext mpeg_descr_service_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_service_type_vals);

static void
proto_mpeg_descriptor_dissect_service(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    uint8_t         prov_len, name_len;
    unsigned        enc_len;
    dvb_encoding_e  encoding;

    proto_tree_add_item(tree, hf_mpeg_descr_service_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    prov_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_service_provider_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (prov_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, prov_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_service_provider_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(tree, hf_mpeg_descr_service_provider,
                tvb, offset+enc_len, prov_len-enc_len, dvb_enc_to_item_enc(encoding));
    }
    offset += prov_len;

    name_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_service_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (name_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, name_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_service_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(tree, hf_mpeg_descr_service_name,
                tvb, offset+enc_len, name_len-enc_len, dvb_enc_to_item_enc(encoding));
    }

}

/* 0x49 Country Availability Descriptor */
static int hf_mpeg_descr_country_availability_flag;
static int hf_mpeg_descr_country_availability_reserved_future_use;
static int hf_mpeg_descr_country_availability_country_code;

static int ett_mpeg_descriptor_country_availability_countries;

#define MPEG_DESCR_COUNTRY_AVAILABILITY_FLAG_MASK           0x80
#define MPEG_DESCR_COUNTRY_AVAILABILITY_RESERVED_MASK       0x7F

static const value_string mpeg_descr_country_availability_flag_vals[] = {
    { 0x0, "Reception of the service is not intended" },
    { 0x1, "Reception of the service is intended" },

    { 0x0, NULL }
};

static void
proto_mpeg_descriptor_dissect_country_availability_descriptor(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset+len;

    proto_tree *countries_tree;

    proto_tree_add_item(tree, hf_mpeg_descr_country_availability_flag , tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_country_availability_reserved_future_use , tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    countries_tree = proto_tree_add_subtree_format(tree, tvb, offset, end - offset, ett_mpeg_descriptor_country_availability_countries, NULL, "Countries");

    while (offset < end) {
        proto_tree_add_item(countries_tree, hf_mpeg_descr_country_availability_country_code, tvb, offset, 3, ENC_ASCII);
        offset += 3;
    }
}

/* 0x4A Linkage Descriptor */
static int hf_mpeg_descr_linkage_transport_stream_id;
static int hf_mpeg_descr_linkage_original_network_id;
static int hf_mpeg_descr_linkage_service_id;
static int hf_mpeg_descr_linkage_linkage_type;

static int hf_mpeg_descr_linkage_hand_over_type;
static int hf_mpeg_descr_linkage_reserved1;
static int hf_mpeg_descr_linkage_origin_type;
static int hf_mpeg_descr_linkage_network_id;
static int hf_mpeg_descr_linkage_initial_service_id;

static int hf_mpeg_descr_linkage_target_event_id;
static int hf_mpeg_descr_linkage_target_listed;
static int hf_mpeg_descr_linkage_event_simulcast;
static int hf_mpeg_descr_linkage_reserved2;

static int hf_mpeg_descr_linkage_interactive_network_id;
static int hf_mpeg_descr_linkage_population_id_loop_count;
static int hf_mpeg_descr_linkage_population_id;
static int hf_mpeg_descr_linkage_population_id_base;
static int hf_mpeg_descr_linkage_population_id_mask;

static int hf_mpeg_descr_linkage_private_data_byte;

static int ett_mpeg_descriptor_linkage_population_id;

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
proto_mpeg_descriptor_dissect_linkage(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{

    uint8_t linkage_type, hand_over_type, origin_type;
    unsigned   end = offset + len;
    unsigned   population_id_loop_count;
    uint16_t population_id_base, population_id_mask;

    proto_item *pi;
    proto_tree *population_tree;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_transport_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_original_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_linkage_linkage_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    linkage_type = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (linkage_type == 0x08) {
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_hand_over_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_linkage_origin_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        hand_over_type = (tvb_get_uint8(tvb, offset) & MPEG_DESCR_LINKAGE_HAND_OVER_TYPE_MASK) >> MPEG_DESCR_LINKAGE_HAND_OVER_TYPE_SHIFT;
        origin_type = tvb_get_uint8(tvb, offset) & MPEG_DESCR_LINKAGE_ORIGIN_TYPE_MASK;
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

        population_id_loop_count = tvb_get_uint8(tvb, offset) + 1;
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

/* 0x4B NVOD Reference Descriptor */
static int hf_mpeg_descr_nvod_reference_tsid;
static int hf_mpeg_descr_nvod_reference_onid;
static int hf_mpeg_descr_nvod_reference_sid;

static int ett_mpeg_descriptor_nvod_reference_triplet;

static void
proto_mpeg_descriptor_dissect_nvod_reference(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;

    proto_tree * triplet_tree;

    while (offset < end) {
        unsigned tsid = tvb_get_uint16(tvb, offset + 0, ENC_BIG_ENDIAN);
        unsigned onid = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
        unsigned sid  = tvb_get_uint16(tvb, offset + 4, ENC_BIG_ENDIAN);

        triplet_tree = proto_tree_add_subtree_format(tree, tvb, offset, 6, ett_mpeg_descriptor_nvod_reference_triplet, NULL, "NVOD Service Triplet (0x%04X:0x%04X:0x%04X)", tsid, onid, sid);

        proto_tree_add_item(triplet_tree, hf_mpeg_descr_nvod_reference_tsid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(triplet_tree, hf_mpeg_descr_nvod_reference_onid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(triplet_tree, hf_mpeg_descr_nvod_reference_sid,  tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
}

/* 0x4C Time Shifted Service Descriptor */
static int hf_mpeg_descr_time_shifted_service_id;

static void
proto_mpeg_descriptor_dissect_time_shifted_service(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_time_shifted_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/* 0x4D Short Event Descriptor */
static int hf_mpeg_descr_short_event_lang_code;
static int hf_mpeg_descr_short_event_name_length;
static int hf_mpeg_descr_short_event_name_encoding;
static int hf_mpeg_descr_short_event_name;
static int hf_mpeg_descr_short_event_text_length;
static int hf_mpeg_descr_short_event_text_encoding;
static int hf_mpeg_descr_short_event_text;

static void
proto_mpeg_descriptor_dissect_short_event(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    uint8_t         name_len, text_len;
    unsigned        enc_len;
    dvb_encoding_e  encoding;

    proto_tree_add_item(tree, hf_mpeg_descr_short_event_lang_code, tvb, offset, 3, ENC_ASCII);
    offset += 3;

    name_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_short_event_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (name_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, name_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_short_event_name_encoding, tvb, offset, enc_len, encoding);
        proto_tree_add_item(tree, hf_mpeg_descr_short_event_name,
                tvb, offset+enc_len, name_len-enc_len, dvb_enc_to_item_enc(encoding));
    }
    offset += name_len;

    text_len = tvb_get_uint8(tvb, offset);
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
static int hf_mpeg_descr_extended_event_descriptor_number;
static int hf_mpeg_descr_extended_event_last_descriptor_number;
static int hf_mpeg_descr_extended_event_lang_code;
static int hf_mpeg_descr_extended_event_length_of_items;
static int hf_mpeg_descr_extended_event_item_description_length;
static int hf_mpeg_descr_extended_event_item_description_char;
static int hf_mpeg_descr_extended_event_item_length;
static int hf_mpeg_descr_extended_event_item_char;
static int hf_mpeg_descr_extended_event_text_length;
static int hf_mpeg_descr_extended_event_text_encoding;
static int hf_mpeg_descr_extended_event_text;

#define MPEG_DESCR_EXTENDED_EVENT_DESCRIPTOR_NUMBER_MASK    0xF0
#define MPEG_DESCR_EXTENDED_EVENT_LAST_DESCRIPTOR_NUMBER_MASK   0x0F

static int ett_mpeg_descriptor_extended_event_item;

static void
proto_mpeg_descriptor_dissect_extended_event(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{

    uint8_t         items_len, item_descr_len, item_len, text_len;
    unsigned        items_end;
    proto_tree     *item_tree;
    unsigned        enc_len;
    dvb_encoding_e  encoding;

    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_descriptor_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_last_descriptor_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_lang_code, tvb, offset, 3, ENC_ASCII);
    offset += 3;

    items_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_length_of_items, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    items_end = offset + items_len;

    while (offset < items_end) {
        item_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mpeg_descriptor_extended_event_item, NULL, "Item");

        item_descr_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_description_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_description_char, tvb, offset, item_descr_len, ENC_ASCII);
        offset += item_descr_len;

        item_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(item_tree, hf_mpeg_descr_extended_event_item_char, tvb, offset, item_len, ENC_ASCII);
        offset += item_len;
    }

    text_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_extended_event_text_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (text_len>0) {
        enc_len = dvb_analyze_string_charset(tvb, offset, text_len, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_extended_event_text_encoding, tvb, offset, enc_len, encoding);
        proto_tree_add_item(tree, hf_mpeg_descr_extended_event_text,
                tvb, offset+enc_len, text_len-enc_len, dvb_enc_to_item_enc(encoding));
    }

}

/* 0x4F Time Shifted Event Descriptor */
static int hf_mpeg_descr_time_shifted_event_reference_service_id;
static int hf_mpeg_descr_time_shifted_event_reference_event_id;

static void
proto_mpeg_descriptor_dissect_time_shifted_event(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_time_shifted_event_reference_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_time_shifted_event_reference_event_id, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/* 0x50 Component Descriptor */
static int hf_mpeg_descr_component_stream_content_ext;
static int hf_mpeg_descr_component_stream_content;
static int hf_mpeg_descr_component_type;
static int hf_mpeg_descr_component_content_type;
static int hf_mpeg_descr_component_tag;
static int hf_mpeg_descr_component_lang_code;
static int hf_mpeg_descr_component_text_encoding;
static int hf_mpeg_descr_component_text;

static int hf_mpeg_descr_component_high_stream_content_ext;
static int hf_mpeg_descr_component_high_stream_content;
static int hf_mpeg_descr_component_high_stream_content_both;
static int hf_mpeg_descr_component_high_component_type;
static int hf_mpeg_descr_component_high_stream_content_n_component_type;

static int hf_mpeg_descr_component_nga_bits_b7_reserved;
static int hf_mpeg_descr_component_nga_bits_b6_headphones;
static int hf_mpeg_descr_component_nga_bits_b5_interactivity;
static int hf_mpeg_descr_component_nga_bits_b4_dialogue_enhancement;
static int hf_mpeg_descr_component_nga_bits_b3_spoken_subtitles;
static int hf_mpeg_descr_component_nga_bits_b2_audio_description;
static int hf_mpeg_descr_component_nga_bits_b10_channel_layout;

#define MPEG_DESCR_COMPONENT_STREAM_CONTENT_EXT_MASK      0xF0
#define MPEG_DESCR_COMPONENT_STREAM_CONTENT_MASK    0x0F
#define MPEG_DESCR_COMPONENT_CONTENT_TYPE_MASK      0x0FFF

#define MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_EXT_MASK       0xF000
#define MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_MASK           0x0F00
#define MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_BOTH_MASK      0xFF00
#define MPEG_DESCR_COMPONENT_HIGH_COMPONENT_TYPE_MASK           0x00FF
#define MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_N_COMPONENT_TYPE_MASK      0xFFFF

#define MPEG_DESCR_COMPONENT_NGA_BITS_B7_MASK    0x0080
#define MPEG_DESCR_COMPONENT_NGA_BITS_B6_MASK    0x0040
#define MPEG_DESCR_COMPONENT_NGA_BITS_B5_MASK    0x0020
#define MPEG_DESCR_COMPONENT_NGA_BITS_B4_MASK    0x0010
#define MPEG_DESCR_COMPONENT_NGA_BITS_B3_MASK    0x0008
#define MPEG_DESCR_COMPONENT_NGA_BITS_B2_MASK    0x0004
#define MPEG_DESCR_COMPONENT_NGA_BITS_B10_MASK   0x0003

static int ett_mpeg_descriptor_component_content_type;

static const value_string mpeg_descr_component_stream_content_vals[] = {

    { 0x01, "Video (MPEG-2)" },
    { 0x02, "Audio (MPEG-1 Layer 2)" },
    { 0x03, "EBU Data (Teletext, Subtitle, ...)" },
    { 0x04, "Audio (AC-3)" },
    { 0x05, "Video (H.264/AVC)" },
    { 0x06, "Audio (HE-AAC)" },
    { 0x07, "Audio (DTS)" },

    { 0x0, NULL }
};

static const value_string mpeg_descr_component_high_stream_content_vals[] = {
    { 0x09, "Video (HEVC)"},
    { 0x19, "Audio (AC-4/DTS-UHD)"},
    { 0x29, "TTML subtitles"},
    { 0xEB, "NGA flags"},
    { 0xFB, "Component tag based combination"},

    { 0x0, NULL }
};

static const value_string mpeg_descr_component_preferred_reproduction_channel_layout_vals[] = {
    { 0x00, "no preference" },
    { 0x01, "stereo" },
    { 0x02, "two-dimensional" },
    { 0x03, "three-dimensional" },

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
    { 0x0242, "Receiver-mixed supplementary audio as per annex E of TS 101 154 [9]" },
    { 0x0247, "MPEG-1 Layer 2 audio, receiver mix audio description as per annex E of TS 101 154 [9]" },
    { 0x0248, "MPEG-1 Layer 2 audio, broadcaster mix audio description" },
    { 0x0301, "EBU Teletext subtitles" },
    { 0x0302, "Associated EBU Teletext" },
    { 0x0303, "VBI data" },
    { 0x0310, "DVB subtitles (normal) with no monitor aspect ratio criticality" },
    { 0x0311, "DVB subtitles (normal) for display on 4:3 aspect ratio monitor" },
    { 0x0312, "DVB subtitles (normal) for display on 16:9 aspect ratio monitor" },
    { 0x0313, "DVB subtitles (normal) for display on 2.21:1 aspect ratio monitor" },
    { 0x0314, "DVB subtitles (normal) for display on a high definition monitor" },
    { 0x0315, "DVB subtitles (normal) with plano-stereoscopic disparity for display on a high definition monitor" },
    { 0x0316, "DVB subtitles (normal) for display on an ultra high definition monitor" },
    { 0x0320, "DVB subtitles (for the hard of hearing) with no monitor aspect ratio criticality" },
    { 0x0321, "DVB subtitles (for the hard of hearing) for display on 4:3 aspect ratio monitor" },
    { 0x0322, "DVB subtitles (for the hard of hearing) for display on 16:9 aspect ratio monitor" },
    { 0x0323, "DVB subtitles (for the hard of hearing) for display on 2.21:1 aspect ratio monitor" },
    { 0x0324, "DVB subtitles (for the hard of hearing) for display on a high definition monitor" },
    { 0x0325, "DVB subtitles (for the hard of hearing) with plano-stereoscopic disparity for display on a high definition monitor" },
    { 0x0326, "DVB subtitles (for the hard of hearing) for display on an ultra high definition monitor" },
    { 0x0330, "Open (in-vision) sign language interpretation for the deaf" },
    { 0x0331, "Closed sign language interpretation for the deaf" },
    { 0x0340, "video up-sampled from standard definition source material" },
    { 0x0341, "Video is standard dynamic range (SDR)" },
    { 0x0342, "Video is high dynamic range (HDR) remapped from standard dynamic range (SDR) source material" },
    { 0x0343, "Video is high dynamic range (HDR) up-converted from standard dynamic range (SDR) source material" },
    { 0x0344, "Video is standard frame rate, less than or equal to 60 Hz" },
    { 0x0345, "High frame rate video generated from lower frame rate source material" },
    { 0x0380, "dependent SAOC-DE data stream" },
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
    { 0x0580, "H.264/AVC plano-stereoscopic frame compatible high definition video, 16:9 aspect ratio, 25 Hz, Side-by-Side" },
    { 0x0581, "H.264/AVC plano-stereoscopic frame compatible high definition video, 16:9 aspect ratio, 25 Hz, Top-and-Bottom" },
    { 0x0582, "H.264/AVC plano-stereoscopic frame compatible high definition video, 16:9 aspect ratio, 30 Hz, Side-by-Side" },
    { 0x0583, "H.264/AVC stereoscopic frame compatible high definition video, 16:9 aspect ratio, 30 Hz, Top-and-Bottom" },
    { 0x0584, "H.264/MVC dependent view, plano-stereoscopic service compatible video" },
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
    { 0x06A0, "HE-AAC, or HE-AAC v2 with SAOC-DE ancillary data" },
    { 0x0801, "DVB SRM data" },

    { 0x0, NULL }
};
static value_string_ext mpeg_descr_component_content_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_component_content_type_vals);

static const value_string mpeg_descr_component_high_content_type_vals[] = {

    { 0x0900, "HEVC Main Profile high definition video, 50 Hz" },
    { 0x0901, "HEVC Main 10 Profile high definition video, 50 Hz" },
    { 0x0902, "HEVC Main Profile high definition video, 60 Hz" },
    { 0x0903, "HEVC Main 10 Profile high definition video, 60 Hz" },
    { 0x0904, "HEVC UHD up to 3840x2160 (SDR up to 3840x2160@60Hz, SDR HFR dual PID with tmp. scal-ty \
up to 3840x2160, HDR with HLG10 up to 3840x2160@60Hz, HDR with HLG10 HFR dual PID and tmp. scal-ty \
up to 3840x2160)" },
    { 0x0905, "HEVC UHD PQ10 HDR up to 60Hz (HDR PQ10 up to 3840x2160@60Hz) or HEVC UHD PQ10 HDR 100Hz/\
(120000/1001)Hz/120Hz with a half frame rate HEVC tmp. video sub-bit-stream (HDR PQ10 HFR dual PID \
and tmp. scal-ty up to 3840x2160)" },
    { 0x0906, "HEVC UHD video up to 3840x2160@100Hz/(120000/1001)Hz/120Hz w/o a half frame rate HEVC tmp. \
video sub-bit-stream (SDR HFR single PID up to 3840x2160, HDR with HLG10 HFR single PID up to 3840x2160)" },
    { 0x0907, "HEVC UHD PQ10 HDR, 100Hz/(120000/1001)Hz/120Hz without a half frame rate HEVC tmp. \
video sub-bit-stream (HDR with PQ10 HFR single PID resolution up to 3840x2160)" },
    { 0x0908, "HEVC UHD video up to 7680x4320 (SDR up to 7680x4320@60Hz, HDR with PQ10 up to 7680x4320@60Hz, \
HDR with HLG10 up to 7680x4320@60Hz)" },
    { 0x1900, "AC-4 main audio, mono" },
    { 0x1901, "AC-4 main audio, mono, dialogue enhancement enabled" },
    { 0x1902, "AC-4 main audio, stereo" },
    { 0x1903, "AC-4 main audio, stereo, dialogue enhancement enabled" },
    { 0x1904, "AC-4 main audio, multichannel" },
    { 0x1905, "AC-4 main audio, multichannel, dialogue enhancement enabled" },
    { 0x1906, "AC-4 broadcast-mix audio description, mono, for the visually impaired" },
    { 0x1907, "AC-4 broadcast-mix audio description, mono, for the visually impaired, dialogue enhancement enabled" },
    { 0x1908, "AC-4 broadcast-mix audio description, stereo, for the visually impaired" },
    { 0x1909, "AC-4 broadcast-mix audio description, stereo, for the visually impaired, dialogue enhancement enabled" },
    { 0x190A, "AC-4 broadcast-mix audio description, multichannel, for the visually impaired" },
    { 0x190B, "AC-4 broadcast-mix audio description, multichannel, for the visually impaired, dialogue enhancement enabled" },
    { 0x190C, "AC-4 receiver-mix audio description, mono, for the visually impaired" },
    { 0x190D, "AC-4 receiver-mix audio description, stereo, for the visually impaired" },
    { 0x190E, "AC-4 Part-2" },
    { 0x190F, "MPEG-H Audio LC Profile" },
    { 0x1910, "DTS-UHD main audio, mono" },
    { 0x1911, "DTS-UHD main audio, mono, dialogue enhancement enabled" },
    { 0x1912, "DTS-UHD main audio, stereo" },
    { 0x1913, "DTS-UHD main audio, stereo, dialogue enhancement enabled" },
    { 0x1914, "DTS-UHD main audio, multichannel" },
    { 0x1915, "DTS-UHD main audio, multichannel, dialogue enhancement enabled" },
    { 0x1916, "DTS-UHD broadcast-mix audio description, mono, for the visually impaired" },
    { 0x1917, "DTS-UHD broadcast-mix audio description, mono, for the visually impaired, dialogue enhancement enabled" },
    { 0x1918, "DTS-UHD broadcast-mix audio description, stereo, for the visually impaired" },
    { 0x1919, "DTS-UHD broadcast-mix audio description, stereo, for the visually impaired, dialogue enhancement enabled" },
    { 0x191A, "DTS-UHD broadcast-mix audio description, multichannel, for the visually impaired" },
    { 0x191B, "DTS-UHD broadcast-mix audio description, multichannel, for the visually impaired, dialogue enhancement enabled" },
    { 0x191C, "DTS-UHD receiver-mix audio description, mono, for the visually impaired" },
    { 0x191D, "DTS-UHD receiver-mix audio description, stereo, for the visually impaired" },
    { 0x191E, "DTS-UHD NGA Audio" },
    { 0xFB00, "less than 16:9 aspect ratio" },
    { 0xFB01, "16:9 aspect ratio" },
    { 0xFB02, "greater than 16:9 aspect ratio" },
    { 0xFB03, "plano-stereoscopic top and bottom (TaB) framepacking" },
    { 0xFB04, "HLG10 HDR" },
    { 0xFB05, "HEVC temporal video subset for a frame rate of 100 Hz, 120 000/1 001 Hz, or 120 Hz" },
    { 0xFB06, "SMPTE ST 2094-10 DMI format as defined in clause 5.14.4.4.3.4.3 of ETSI TS 101 154" },
    { 0xFB07, "SL-HDR2 DMI format as defined in clause 5.14.4.4.3.4.4 of ETSI TS 101 154" },
    { 0xFB08, "SMPTE ST 2094-40 DMI format as defined in clause 5.14.4.4.3.4.5 of ETSI TS 101 154" },

    { 0x0, NULL }
};
static value_string_ext mpeg_descr_component_high_content_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_descr_component_high_content_type_vals);

static void
proto_mpeg_descriptor_dissect_component(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{

    proto_item *cti;
    proto_tree *content_type_tree;
    unsigned end = offset + len;

    if (len < 6) {
        return;
    }

    unsigned stream_content     = tvb_get_bits8(tvb, offset * 8 + 4, 4);

    if (stream_content >= 0x09) {
        unsigned stream_content_ext = tvb_get_bits8(tvb, offset * 8, 4);

        cti = proto_tree_add_item(tree, hf_mpeg_descr_component_high_stream_content_n_component_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        content_type_tree = proto_item_add_subtree(cti, ett_mpeg_descriptor_component_content_type);

        proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_high_stream_content_both, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_high_stream_content_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_high_stream_content, tvb, offset, 2, ENC_BIG_ENDIAN);

        if (stream_content_ext == 0x0E && stream_content == 0x0B) {
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_nga_bits_b7_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_nga_bits_b6_headphones, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_nga_bits_b5_interactivity, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_nga_bits_b4_dialogue_enhancement, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_nga_bits_b3_spoken_subtitles, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_nga_bits_b2_audio_description, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_nga_bits_b10_channel_layout, tvb, offset, 2, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_high_component_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset += 2;
        goto mpeg_descr_component_tail;
    }

    proto_tree_add_item(tree, hf_mpeg_descr_component_stream_content_ext, tvb, offset, 1, ENC_BIG_ENDIAN);

    cti = proto_tree_add_item(tree, hf_mpeg_descr_component_content_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    content_type_tree = proto_item_add_subtree(cti, ett_mpeg_descriptor_component_content_type);

    proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_stream_content, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(content_type_tree, hf_mpeg_descr_component_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

mpeg_descr_component_tail:

    proto_tree_add_item(tree, hf_mpeg_descr_component_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_component_lang_code, tvb, offset, 3, ENC_ASCII);
    offset += 3;

    if (offset < end)
    {
        dvb_encoding_e  encoding;
        unsigned enc_len = dvb_analyze_string_charset(tvb, offset, end - offset, &encoding);
        dvb_add_chartbl(tree, hf_mpeg_descr_component_text_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(tree, hf_mpeg_descr_component_text, tvb, offset+enc_len, end-offset-enc_len, dvb_enc_to_item_enc(encoding));
    }
}

/* 0x51 Mosaic Descriptor */
static int hf_mpeg_descr_mosaic_mosaic_entry_point;
static int hf_mpeg_descr_mosaic_number_of_horizontal_elementary_cells;
static int hf_mpeg_descr_mosaic_reserved_future_use1;
static int hf_mpeg_descr_mosaic_number_of_vertical_elementary_cells;
static int hf_mpeg_descr_mosaic_logical_cell_id;
static int hf_mpeg_descr_mosaic_reserved_future_use2;
static int hf_mpeg_descr_mosaic_logical_cell_presentation_info;
static int hf_mpeg_descr_mosaic_elementary_cell_field_length;
static int hf_mpeg_descr_mosaic_reserved_future_use3;
static int hf_mpeg_descr_mosaic_elementary_cell_id;
static int hf_mpeg_descr_mosaic_cell_linkage_info;
static int hf_mpeg_descr_mosaic_bouquet_id;
static int hf_mpeg_descr_mosaic_original_network_id;
static int hf_mpeg_descr_mosaic_transport_stream_id;
static int hf_mpeg_descr_mosaic_service_id;
static int hf_mpeg_descr_mosaic_event_id;

#define MPEG_DESCR_MOSAIC_ENTRY_POINT_MASK              0x80
#define MPEG_DESCR_MOSAIC_NUM_OF_H_CELLS_MASK           0x70
#define MPEG_DESCR_MOSAIC_RESERVED1_MASK                0x08
#define MPEG_DESCR_MOSAIC_NUM_OF_V_CELLS_MASK           0x07
#define MPEG_DESCR_MOSAIC_LOGICAL_CELL_ID_MASK          0xFC00
#define MPEG_DESCR_MOSAIC_RESERVED2_MASK                0x03F8
#define MPEG_DESCR_MOSAIC_CELL_PRESENTATION_INFO_MASK   0x0007
#define MPEG_DESCR_MOSAIC_RESERVED3_MASK                0xC0
#define MPEG_DESCR_MOSAIC_ELEMENTARY_CELL_ID_MASK       0x3F

static int ett_mpeg_descriptor_mosaic_logical_cell;
static int ett_mpeg_descriptor_mosaic_elementary_cells;

static const value_string mpeg_descr_mosaic_number_of_e_cells_vals[] = {
    { 0x00, "One cell" },
    { 0x01, "Two cells" },
    { 0x02, "Three cells" },
    { 0x03, "Four cells" },
    { 0x04, "Five cells" },
    { 0x05, "Six cells" },
    { 0x06, "Seven cells" },
    { 0x07, "Eight cells" },

    { 0, NULL }
};

static const range_string mpeg_descr_mosaic_logical_cell_presentation_info_vals[] = {
    { 0x00, 0x00, "Undefined" },
    { 0x01, 0x01, "Video" },
    { 0x02, 0x02, "Still picture" },
    { 0x03, 0x03, "Graphics/Text" },
    { 0x04, 0x07, "Reserved for future use" },

    { 0x00, 0x00, NULL }
};

static const range_string mpeg_descr_mosaic_cell_linkage_info_vals[] = {
    { 0x00, 0x00, "Underfined" },
    { 0x01, 0x01, "Bouquet related" },
    { 0x02, 0x02, "Service related" },
    { 0x03, 0x03, "Other mosaic related" },
    { 0x04, 0x04, "Event related" },
    { 0x05, 0xFF, "Reserved for future use" },

    { 0x00, 0x00, NULL }
};

static unsigned
proto_mpeg_descriptor_dissect_mosaic_measure_l_cell_len(tvbuff_t *tvb, unsigned offset)
{
    unsigned l_offset = offset;

    l_offset += 2;
    uint8_t elementary_cell_field_length = tvb_get_uint8(tvb, l_offset);
    l_offset += 1;
    l_offset += elementary_cell_field_length;

    uint8_t cell_linkage_info = tvb_get_uint8(tvb, l_offset);
    l_offset += 1;

    switch (cell_linkage_info) {
        case 0x01 :
            l_offset += 2;
            break;
        case 0x02 :
        case 0x03 :
            l_offset += 6;
            break;
        case 0x04 :
            l_offset += 8;
            break;
    }

    return l_offset - offset;
}

static void
proto_mpeg_descriptor_dissect_mosaic(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;

    proto_tree_add_item(tree, hf_mpeg_descr_mosaic_mosaic_entry_point, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_mosaic_number_of_horizontal_elementary_cells, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_mosaic_reserved_future_use1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_mosaic_number_of_vertical_elementary_cells, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    while (offset < end) {
        unsigned l_cell_len = proto_mpeg_descriptor_dissect_mosaic_measure_l_cell_len(tvb, offset);

        uint8_t logical_cell_id = tvb_get_bits(tvb, offset*8, 6, ENC_BIG_ENDIAN);
        proto_tree *cell_tree = proto_tree_add_subtree_format(tree, tvb, offset, l_cell_len, ett_mpeg_descriptor_mosaic_logical_cell, NULL, "Logical Cell 0x%02x", logical_cell_id);
        proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_logical_cell_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_reserved_future_use2, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_logical_cell_presentation_info, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        uint8_t elementary_cell_field_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_elementary_cell_field_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree *field_tree = NULL;
        if (elementary_cell_field_length > 0) {
            field_tree = proto_tree_add_subtree(cell_tree, tvb, offset, elementary_cell_field_length, ett_mpeg_descriptor_mosaic_elementary_cells, NULL, "Elementary Cells");
        }
        while (elementary_cell_field_length > 0) {
            proto_tree_add_item(field_tree, hf_mpeg_descr_mosaic_reserved_future_use3, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_tree, hf_mpeg_descr_mosaic_elementary_cell_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            elementary_cell_field_length -= 1;
        }

        uint8_t cell_linkage_info = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_cell_linkage_info, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        switch (cell_linkage_info) {
            case 0x01 :
                proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_bouquet_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 0x02 :
            case 0x03 :
            case 0x04 :
                proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_original_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_transport_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
        }

        if (cell_linkage_info == 0x04) {
            proto_tree_add_item(cell_tree, hf_mpeg_descr_mosaic_event_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }
}

/* 0x52 Stream Identifier Descriptor */
static int hf_mpeg_descr_stream_identifier_component_tag;

static void
proto_mpeg_descriptor_dissect_stream_identifier(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_stream_identifier_component_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x53 CA Identifier Descriptor */
static int hf_mpeg_descr_ca_identifier_system_id;

static void
proto_mpeg_descriptor_dissect_ca_identifier(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_ca_identifier_system_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

}

/* 0x54 Content Descriptor */
static int hf_mpeg_descr_content_nibble;
static int hf_mpeg_descr_content_nibble_level_1;
static int hf_mpeg_descr_content_nibble_level_2;
static int hf_mpeg_descr_content_user_byte;

#define MPEG_DESCR_CONTENT_NIBBLE_LEVEL_1_MASK  0xF0
#define MPEG_DESCR_CONTENT_NIBBLE_LEVEL_2_MASK  0x0F

static int ett_mpeg_descriptor_content_nibble;

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
proto_mpeg_descriptor_dissect_content(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    proto_item *ni;
    proto_tree *nibble_tree;

    unsigned end = offset + len;

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
static int hf_mpeg_descr_parental_rating_country_code;
static int hf_mpeg_descr_parental_rating_rating;

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
proto_mpeg_descriptor_dissect_parental_rating(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_parental_rating_country_code, tvb, offset, 3, ENC_ASCII);
    offset += 3;

    proto_tree_add_item(tree, hf_mpeg_descr_parental_rating_rating, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x56 Teletext Descriptor */
static int hf_mpeg_descr_teletext_lang_code;
static int hf_mpeg_descr_teletext_type;
static int hf_mpeg_descr_teletext_magazine_number;
static int hf_mpeg_descr_teletext_page_number;

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
proto_mpeg_descriptor_dissect_teletext(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_teletext_lang_code, tvb, offset, 3, ENC_ASCII);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_teletext_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_teletext_magazine_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_teletext_page_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
}

/* 0x57 Telephone Descriptor */
static int hf_mpeg_descr_telephone_reserved_future_use1;
static int hf_mpeg_descr_telephone_foreign_availability;
static int hf_mpeg_descr_telephone_connection_type;
static int hf_mpeg_descr_telephone_reserved_future_use2;
static int hf_mpeg_descr_telephone_country_prefix_length;
static int hf_mpeg_descr_telephone_international_area_code_length;
static int hf_mpeg_descr_telephone_operator_code_length;
static int hf_mpeg_descr_telephone_reserved_future_use3;
static int hf_mpeg_descr_telephone_national_area_code_length;
static int hf_mpeg_descr_telephone_core_number_length;
static int hf_mpeg_descr_telephone_number;
static int hf_mpeg_descr_telephone_country_prefix;
static int hf_mpeg_descr_telephone_international_area_code;
static int hf_mpeg_descr_telephone_operator_code;
static int hf_mpeg_descr_telephone_national_area_code;
static int hf_mpeg_descr_telephone_core_number;

#define MPEG_DESCR_TELEPHONE_RESERVED1_MASK                 0xC0
#define MPEG_DESCR_TELEPHONE_FOREIGN_AVAILABILITY_MASK      0x20
#define MPEG_DESCR_TELEPHONE_CONNECTION_TYPE_MASK           0x1F
#define MPEG_DESCR_TELEPHONE_RESERVED2_MASK                 0x80
#define MPEG_DESCR_TELEPHONE_COUNTRY_PREFIX_LEN_MASK        0x60
#define MPEG_DESCR_TELEPHONE_INTERNATIONAL_CODE_LEN_MASK    0x1C
#define MPEG_DESCR_TELEPHONE_OPERATOR_CODE_LEN_MASK         0x03
#define MPEG_DESCR_TELEPHONE_RESERVED3_MASK                 0x80
#define MPEG_DESCR_TELEPHONE_NATIONAL_CODE_LEN_MASK         0x70
#define MPEG_DESCR_TELEPHONE_CORE_NUMBER_LEN_MASK           0x0F

static const value_string mpeg_descr_telephone_foreign_availability_vals[] = {
    { 0x0, "Inside country only" },
    { 0x1, "Foreign call available" },

    { 0x0, NULL }
};

static const range_string mpeg_descr_telephone_connection_type_vals[] = {
    { 0x00, 0x1F, "Unknown" },

    { 0, 0, NULL }
};

static int ett_mpeg_descriptor_telephone_number;

static void
proto_mpeg_descriptor_dissect_telephone(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    uint32_t country_prefix_length;
    uint32_t international_area_code_length;
    uint32_t operator_code_length;
    uint32_t national_area_code_length;
    uint32_t core_number_length;

    proto_item * ni;
    proto_tree * number_tree;

    proto_tree_add_item(tree, hf_mpeg_descr_telephone_reserved_future_use1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_telephone_foreign_availability, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_telephone_connection_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_telephone_reserved_future_use2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_mpeg_descr_telephone_country_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN, &country_prefix_length);
    proto_tree_add_item_ret_uint(tree, hf_mpeg_descr_telephone_international_area_code_length, tvb, offset, 1, ENC_BIG_ENDIAN, &international_area_code_length);
    proto_tree_add_item_ret_uint(tree, hf_mpeg_descr_telephone_operator_code_length, tvb, offset, 1, ENC_BIG_ENDIAN, &operator_code_length);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_telephone_reserved_future_use3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_mpeg_descr_telephone_national_area_code_length, tvb, offset, 1, ENC_BIG_ENDIAN, &national_area_code_length);
    proto_tree_add_item_ret_uint(tree, hf_mpeg_descr_telephone_core_number_length, tvb, offset, 1, ENC_BIG_ENDIAN, &core_number_length);
    offset += 1;

    uint32_t number_l = country_prefix_length + international_area_code_length + operator_code_length + national_area_code_length + core_number_length;

    if (number_l == 0) return;
    ni = proto_tree_add_item(tree, hf_mpeg_descr_telephone_number, tvb, offset, number_l, ENC_ISO_8859_1);
    number_tree = proto_item_add_subtree(ni, ett_mpeg_descriptor_telephone_number);

    if (country_prefix_length != 0) {
        proto_tree_add_item(number_tree, hf_mpeg_descr_telephone_country_prefix, tvb, offset, country_prefix_length, ENC_ISO_8859_1);
        offset += country_prefix_length;
    }

    if (international_area_code_length != 0) {
        proto_tree_add_item(number_tree, hf_mpeg_descr_telephone_international_area_code, tvb, offset, international_area_code_length, ENC_ISO_8859_1);
        offset += international_area_code_length;
    }

    if (operator_code_length != 0) {
        proto_tree_add_item(number_tree, hf_mpeg_descr_telephone_operator_code, tvb, offset, operator_code_length, ENC_ISO_8859_1);
        offset += operator_code_length;
    }

    if (national_area_code_length != 0) {
        proto_tree_add_item(number_tree, hf_mpeg_descr_telephone_national_area_code, tvb, offset, national_area_code_length, ENC_ISO_8859_1);
        offset += national_area_code_length;
    }

    if (core_number_length == 0) return;
    proto_tree_add_item(number_tree, hf_mpeg_descr_telephone_core_number, tvb, offset, core_number_length, ENC_ISO_8859_1);
}

/* 0x58 Local Time Offset Descriptor */
static int hf_mpeg_descr_local_time_offset_country_code;
static int hf_mpeg_descr_local_time_offset_region_id;
static int hf_mpeg_descr_local_time_offset_reserved;
static int hf_mpeg_descr_local_time_offset_polarity;
static int hf_mpeg_descr_local_time_offset_offset;
static int hf_mpeg_descr_local_time_offset_time_of_change;
static int hf_mpeg_descr_local_time_offset_next_time_offset;

#define MPEG_DESCR_LOCAL_TIME_OFFSET_COUNTRY_REGION_ID_MASK 0xFC
#define MPEG_DESCR_LOCAL_TIME_OFFSET_RESERVED_MASK      0x02
#define MPEG_DESCR_LOCAL_TIME_OFFSET_POLARITY           0x01

static const value_string mpeg_descr_local_time_offset_polarity_vals[] = {
    { 0x0, "Positive (local time ahead of UTC)" },
    { 0x1, "Negative (local time behind UTC)" },

    { 0x0, NULL }
};

static void
proto_mpeg_descriptor_dissect_local_time_offset(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;
    uint8_t  hour, min;
    nstime_t local_time_offset, time_of_change, next_time_offset;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_country_code, tvb, offset, 3, ENC_ASCII);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_region_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_local_time_offset_polarity, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        hour = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset));
        min = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+1));
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

        hour = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset));
        min = MPEG_SECT_BCD44_TO_DEC(tvb_get_uint8(tvb, offset+1));
        nstime_set_zero(&next_time_offset);
        next_time_offset.secs = hour*60*60 + min*60;
        proto_tree_add_time_format_value(tree, hf_mpeg_descr_local_time_offset_next_time_offset,
                tvb, offset, 2, &next_time_offset, "%02d:%02d", hour, min);
        offset += 2;
    }
}

/* 0x59 Subtitling Descriptor */
static int hf_mpeg_descr_subtitling_lang_code;
static int hf_mpeg_descr_subtitling_type;
static int hf_mpeg_descr_subtitling_composition_page_id;
static int hf_mpeg_descr_subtitling_ancillary_page_id;


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
proto_mpeg_descriptor_dissect_subtitling(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;

    while (offset < end) {
        proto_tree_add_item(tree, hf_mpeg_descr_subtitling_lang_code, tvb, offset, 3, ENC_ASCII);
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
static int hf_mpeg_descr_terrestrial_delivery_centre_frequency;
static int hf_mpeg_descr_terrestrial_delivery_bandwidth;
static int hf_mpeg_descr_terrestrial_delivery_priority;
static int hf_mpeg_descr_terrestrial_delivery_time_slicing_indicator;
static int hf_mpeg_descr_terrestrial_delivery_mpe_fec_indicator;
static int hf_mpeg_descr_terrestrial_delivery_reserved1;
static int hf_mpeg_descr_terrestrial_delivery_constellation;
static int hf_mpeg_descr_terrestrial_delivery_hierarchy_information;
static int hf_mpeg_descr_terrestrial_delivery_code_rate_hp_stream;
static int hf_mpeg_descr_terrestrial_delivery_code_rate_lp_stream;
static int hf_mpeg_descr_terrestrial_delivery_guard_interval;
static int hf_mpeg_descr_terrestrial_delivery_transmission_mode;
static int hf_mpeg_descr_terrestrial_delivery_other_frequency_flag;
static int hf_mpeg_descr_terrestrial_delivery_reserved2;

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
proto_mpeg_descriptor_dissect_terrestrial_delivery(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    uint64_t centre_freq;

    /* the descriptor stores the centre frequency in units of 10Hz (so
       that they can get away with 32bits), we're using Hz here */
    centre_freq = tvb_get_ntohl(tvb, offset) * 10;

    proto_tree_add_uint64_format_value(tree, hf_mpeg_descr_terrestrial_delivery_centre_frequency, tvb, offset, 4,
        centre_freq, "%d.%06d MHz", (unsigned)centre_freq/(1000*1000), (unsigned)centre_freq%(1000*1000));
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

/* 0x5B Multilingual Network Name Descriptor */
static int hf_mpeg_descr_multilng_network_name_desc_iso639_language_code;
static int hf_mpeg_descr_multilng_network_name_desc_name_length;
static int hf_mpeg_descr_multilng_network_name_desc_name_encoding;
static int hf_mpeg_descr_multilng_network_name_desc_name;

static int ett_mpeg_descriptor_multilng_network_name_desc_lng;

static unsigned
proto_mpeg_descriptor_dissect_multilng_network_name_desc_measure_lng_len(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    unsigned l_offset = offset;
    unsigned cnt = len;

    if (cnt < 3) return l_offset - offset;
    cnt      -= 3;
    l_offset += 3;

    if (cnt < 1) return l_offset - offset;
    unsigned network_name_length = tvb_get_uint8(tvb, l_offset);
    cnt      -= 1;
    l_offset += 1;

    network_name_length = MIN(network_name_length, cnt);
    l_offset += network_name_length;

    return l_offset - offset;
}

static void
proto_mpeg_descriptor_dissect_multilng_network_name_desc(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned cnt = len;

    while (cnt > 0)
    {
        char *lng_str;
        proto_tree * lng_tree;
        proto_item * lng_item;

        if (cnt < 3) return;
        unsigned lng_len = proto_mpeg_descriptor_dissect_multilng_network_name_desc_measure_lng_len(tvb, offset, cnt);
        lng_tree = proto_tree_add_subtree(tree, tvb, offset, lng_len,
                    ett_mpeg_descriptor_multilng_network_name_desc_lng, &lng_item, NULL);

        proto_tree_add_item_ret_display_string(lng_tree, hf_mpeg_descr_multilng_network_name_desc_iso639_language_code, tvb, offset, 3, ENC_ASCII,
                                                wmem_packet_scope(), &lng_str);
        proto_item_set_text(lng_item, "Language \"%s\"", lng_str);
        offset += 3;
        cnt    -= 3;

        if (cnt < 1) return;
        unsigned network_name_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_network_name_desc_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        network_name_length = MIN(network_name_length, cnt);
        if (cnt < network_name_length) return;
        dvb_encoding_e  encoding;
        unsigned enc_len = dvb_analyze_string_charset(tvb, offset, network_name_length, &encoding);
        dvb_add_chartbl(lng_tree, hf_mpeg_descr_multilng_network_name_desc_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_network_name_desc_name, tvb, offset+enc_len, network_name_length-enc_len, dvb_enc_to_item_enc(encoding));
        offset += network_name_length;
        cnt    -= network_name_length;
    }
}

/* 0x5C Multilingual Bouquet Name Descriptor */
static int hf_mpeg_descr_multilng_bouquet_name_desc_iso639_language_code;
static int hf_mpeg_descr_multilng_bouquet_name_desc_name_length;
static int hf_mpeg_descr_multilng_bouquet_name_desc_name_encoding;
static int hf_mpeg_descr_multilng_bouquet_name_desc_name;

static int ett_mpeg_descriptor_multilng_bouquet_name_desc_lng;

static unsigned
proto_mpeg_descriptor_dissect_multilng_bouquet_name_desc_measure_lng_len(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    unsigned l_offset = offset;
    unsigned cnt = len;

    if (cnt < 3) return l_offset - offset;
    cnt      -= 3;
    l_offset += 3;

    if (cnt < 1) return l_offset - offset;
    unsigned bouquet_name_length = tvb_get_uint8(tvb, l_offset);
    cnt      -= 1;
    l_offset += 1;

    bouquet_name_length = MIN(bouquet_name_length, cnt);
    l_offset += bouquet_name_length;

    return l_offset - offset;
}

static void
proto_mpeg_descriptor_dissect_multilng_bouquet_name_desc(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned cnt = len;

    while (cnt > 0)
    {
        char* lng_str;
        proto_tree * lng_tree;
        proto_item * lng_item;

        if (cnt < 3) return;
        unsigned lng_len = proto_mpeg_descriptor_dissect_multilng_bouquet_name_desc_measure_lng_len(tvb, offset, cnt);
        lng_tree = proto_tree_add_subtree(tree, tvb, offset, lng_len,
                    ett_mpeg_descriptor_multilng_bouquet_name_desc_lng, &lng_item, NULL);

        proto_tree_add_item_ret_display_string(lng_tree, hf_mpeg_descr_multilng_bouquet_name_desc_iso639_language_code, tvb, offset, 3, ENC_ASCII,
                                                wmem_packet_scope(), &lng_str);
        proto_item_set_text(lng_item, "Language \"%s\"", lng_str);
        offset += 3;
        cnt    -= 3;

        if (cnt < 1) return;
        unsigned bouquet_name_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_bouquet_name_desc_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        bouquet_name_length = MIN(bouquet_name_length, cnt);
        if (cnt < bouquet_name_length) return;
        dvb_encoding_e  encoding;
        unsigned enc_len = dvb_analyze_string_charset(tvb, offset, bouquet_name_length, &encoding);
        dvb_add_chartbl(lng_tree, hf_mpeg_descr_multilng_bouquet_name_desc_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_bouquet_name_desc_name, tvb, offset+enc_len, bouquet_name_length-enc_len, dvb_enc_to_item_enc(encoding));
        offset += bouquet_name_length;
        cnt    -= bouquet_name_length;
    }
}

/* 0x5D Multilingual Service Name Descriptor */
static int hf_mpeg_descr_multilng_srv_name_desc_iso639_language_code;
static int hf_mpeg_descr_multilng_srv_name_desc_service_provider_name_length;
static int hf_mpeg_descr_multilng_srv_name_desc_service_provider_name_encoding;
static int hf_mpeg_descr_multilng_srv_name_desc_service_provider_name;
static int hf_mpeg_descr_multilng_srv_name_desc_service_name_length;
static int hf_mpeg_descr_multilng_srv_name_desc_service_name_encoding;
static int hf_mpeg_descr_multilng_srv_name_desc_service_name;

static int ett_mpeg_descriptor_multilng_srv_name_desc_lng;

static unsigned
proto_mpeg_descriptor_dissect_multilng_srv_name_desc_measure_lng_len(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    unsigned l_offset = offset;
    unsigned cnt = len;

    if (cnt < 3) return l_offset - offset;
    cnt      -= 3;
    l_offset += 3;

    if (cnt < 1) return l_offset - offset;
    unsigned service_provider_name_length = tvb_get_uint8(tvb, l_offset);
    cnt      -= 1;
    l_offset += 1;

    service_provider_name_length = MIN(service_provider_name_length, cnt);
    cnt      -= service_provider_name_length;
    l_offset += service_provider_name_length;

    if (cnt < 1) return l_offset - offset;
    unsigned service_name_length = tvb_get_uint8(tvb, l_offset);
    cnt      -= 1;
    l_offset += 1;

    service_name_length = MIN(service_name_length, cnt);
    l_offset += service_name_length;

    return l_offset - offset;
}

static void
proto_mpeg_descriptor_dissect_multilng_srv_name_desc(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned cnt = len;

    while (cnt > 0)
    {
        char *lng_str;
        proto_tree * lng_tree;
        proto_item * lng_item;

        if (cnt < 3) return;
        unsigned lng_len = proto_mpeg_descriptor_dissect_multilng_srv_name_desc_measure_lng_len(tvb, offset, cnt);
        lng_tree = proto_tree_add_subtree(tree, tvb, offset, lng_len,
                    ett_mpeg_descriptor_multilng_srv_name_desc_lng, &lng_item, NULL);

        proto_tree_add_item_ret_display_string(lng_tree, hf_mpeg_descr_multilng_srv_name_desc_iso639_language_code, tvb, offset, 3, ENC_ASCII,
                                                wmem_packet_scope(), &lng_str);
        proto_item_set_text(lng_item, "Language \"%s\"", lng_str);
        offset += 3;
        cnt    -= 3;

        if (cnt < 1) return;
        unsigned service_provider_name_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_srv_name_desc_service_provider_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        service_provider_name_length = MIN(service_provider_name_length, cnt);
        if (cnt < service_provider_name_length) return;
        dvb_encoding_e  encoding;
        unsigned enc_len = dvb_analyze_string_charset(tvb, offset, service_provider_name_length, &encoding);
        dvb_add_chartbl(lng_tree, hf_mpeg_descr_multilng_srv_name_desc_service_provider_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_srv_name_desc_service_provider_name, tvb, offset+enc_len, service_provider_name_length-enc_len, dvb_enc_to_item_enc(encoding));
        offset += service_provider_name_length;
        cnt    -= service_provider_name_length;

        if (cnt < 1) return;
        unsigned service_name_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_srv_name_desc_service_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        service_name_length = MIN(service_name_length, cnt);
        if (cnt < service_name_length) return;
        enc_len = dvb_analyze_string_charset(tvb, offset, service_name_length, &encoding);
        dvb_add_chartbl(lng_tree, hf_mpeg_descr_multilng_srv_name_desc_service_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_srv_name_desc_service_name, tvb, offset+enc_len, service_name_length-enc_len, dvb_enc_to_item_enc(encoding));
        offset += service_name_length;
        cnt    -= service_name_length;
    }
}

/* 0x5E Multilingual Component Descriptor */
static int hf_mpeg_descr_multilng_component_desc_iso639_language_code;
static int hf_mpeg_descr_multilng_component_desc_tag;
static int hf_mpeg_descr_multilng_component_desc_text_length;
static int hf_mpeg_descr_multilng_component_desc_text_encoding;
static int hf_mpeg_descr_multilng_component_desc_text;

static int ett_mpeg_descriptor_multilng_component_desc_lng;

static unsigned
proto_mpeg_descriptor_dissect_multilng_component_desc_measure_lng_len(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    unsigned l_offset = offset;
    unsigned cnt = len;

    if (cnt < 3) return l_offset - offset;
    cnt      -= 3;
    l_offset += 3;

    if (cnt < 1) return l_offset - offset;
    unsigned text_length = tvb_get_uint8(tvb, l_offset);
    cnt      -= 1;
    l_offset += 1;

    text_length = MIN(text_length, cnt);
    l_offset += text_length;

    return l_offset - offset;
}

static void
proto_mpeg_descriptor_dissect_multilng_component_desc(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned cnt = len;

    if (cnt < 1) return;
    proto_tree_add_item(tree, hf_mpeg_descr_multilng_component_desc_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    cnt    -= 1;

    while (cnt > 0)
    {
        char *lng_str;
        proto_tree * lng_tree;
        proto_item * lng_item;

        if (cnt < 3) return;
        unsigned lng_len = proto_mpeg_descriptor_dissect_multilng_component_desc_measure_lng_len(tvb, offset, cnt);
        lng_tree = proto_tree_add_subtree(tree, tvb, offset, lng_len,
                    ett_mpeg_descriptor_multilng_component_desc_lng, &lng_item, NULL);

        proto_tree_add_item_ret_display_string(lng_tree, hf_mpeg_descr_multilng_component_desc_iso639_language_code, tvb, offset, 3, ENC_ASCII,
                                                wmem_packet_scope(), &lng_str);
        proto_item_set_text(lng_item, "Language \"%s\"", lng_str);
        offset += 3;
        cnt    -= 3;

        if (cnt < 1) return;
        unsigned text_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_component_desc_text_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        text_length = MIN(text_length, cnt);
        if (cnt < text_length) return;
        dvb_encoding_e  encoding;
        unsigned enc_len = dvb_analyze_string_charset(tvb, offset, text_length, &encoding);
        dvb_add_chartbl(lng_tree, hf_mpeg_descr_multilng_component_desc_text_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(lng_tree, hf_mpeg_descr_multilng_component_desc_text, tvb, offset+enc_len, text_length-enc_len, dvb_enc_to_item_enc(encoding));
        offset += text_length;
        cnt    -= text_length;
    }
}

/* 0x5F Private Data Specifier */
static int hf_mpeg_descr_private_data_specifier_id;

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
proto_mpeg_descriptor_dissect_private_data_specifier(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_private_data_specifier_id, tvb, offset, 4, ENC_BIG_ENDIAN);
}

/* 0x61 Short Smoothing Buffer Descriptor */
static int hf_mpeg_descr_short_smoothing_buffer_sb_size;
static int hf_mpeg_descr_short_smoothing_buffer_sb_leak_rate;
static int hf_mpeg_descr_short_smoothing_buffer_dvb_reserved;

#define MPEG_DESCR_SHORT_SMOOTHING_BUFFER_SB_SIZE_MASK      0xC0
#define MPEG_DESCR_SHORT_SMOOTHING_BUFFER_SB_LEAK_RATE_MASK 0x3F

static const value_string mpeg_descr_ssb_sb_size_vals[] = {
    { 0, "DVB_reserved" },
    { 1, "1 536" },
    { 2, "DVB_reserved" },
    { 3, "DVB_reserved" },
    { 0, NULL }
};

static const value_string mpeg_descr_ssb_sb_leak_rate_vals[] = {
    { 0, "DVB_reserved" },
    { 1, "0,0009 Mbit/s" },
    { 2, "0,0018 Mbit/s" },
    { 3, "0,0036 Mbit/s" },
    { 4, "0,0072 Mbit/s" },
    { 5, "0,0108 Mbit/s" },
    { 6, "0,0144 Mbit/s" },
    { 7, "0,0216 Mbit/s" },
    { 8, "0,0288 Mbit/s" },
    { 9, "0,075 Mbit/s" },
    { 10, "0,5 Mbit/s" },
    { 11, "0,5625 Mbit/s" },
    { 12, "0,8437 Mbit/s" },
    { 13, "1,0 Mbit/s" },
    { 14, "1,1250 Mbit/s" },
    { 15, "1,5 Mbit/s" },
    { 16, "1,6875 Mbit/s" },
    { 17, "2,0 Mbit/s" },
    { 18, "2,2500 Mbit/s" },
    { 19, "2,5 Mbit/s" },
    { 20, "3,0 Mbit/s" },
    { 21, "3,3750 Mbit/s" },
    { 22, "3,5 Mbit/s" },
    { 23, "4,0 Mbit/s" },
    { 24, "4,5 Mbit/s" },
    { 25, "5,0 Mbit/s" },
    { 26, "5,5 Mbit/s" },
    { 27, "6,0 Mbit/s" },
    { 28, "6,5 Mbit/s" },
    { 29, "6,7500 Mbit/s" },
    { 30, "7,0 Mbit/s" },
    { 31, "7,5 Mbit/s" },
    { 32, "8,0 Mbit/s" },
    { 33, "9,0 Mbit/s" },
    { 34, "10,0 Mbit/s" },
    { 35, "11,0 Mbit/s" },
    { 36, "12,0 Mbit/s" },
    { 37, "13,0 Mbit/s" },
    { 38, "13,5 Mbit/s" },
    { 39, "14,0 Mbit/s" },
    { 40, "15,0 Mbit/s" },
    { 41, "16,0 Mbit/s" },
    { 42, "17,0 Mbit/s" },
    { 43, "18,0 Mbit/s" },
    { 44, "20,0 Mbit/s" },
    { 45, "22,0 Mbit/s" },
    { 46, "24,0 Mbit/s" },
    { 47, "26,0 Mbit/s" },
    { 48, "27,0 Mbit/s" },
    { 49, "28,0 Mbit/s" },
    { 50, "30,0 Mbit/s" },
    { 51, "32,0 Mbit/s" },
    { 52, "34,0 Mbit/s" },
    { 53, "36,0 Mbit/s" },
    { 54, "38,0 Mbit/s" },
    { 55, "40,0 Mbit/s" },
    { 56, "44,0 Mbit/s" },
    { 57, "48,0 Mbit/s" },
    { 58, "54,0 Mbit/s" },
    { 59, "72,0 Mbit/s" },
    { 60, "108,0 Mbit/s" },
    { 61, "DVB_reserved" },
    { 62, "DVB_reserved" },
    { 63, "DVB_reserved" },
    { 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_short_smoothing_buffer(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_short_smoothing_buffer_sb_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_short_smoothing_buffer_sb_leak_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (len == 1) return;

    proto_tree_add_item(tree, hf_mpeg_descr_short_smoothing_buffer_dvb_reserved, tvb, offset, len-1, ENC_NA);
}

/* 0x63 Partial Transport Stream Descriptor */
static int hf_mpeg_descr_partial_transport_stream_reserved_future_use1;
static int hf_mpeg_descr_partial_transport_stream_peak_rate;
static int hf_mpeg_descr_partial_transport_stream_reserved_future_use2;
static int hf_mpeg_descr_partial_transport_stream_minimum_overall_smoothing_rate;
static int hf_mpeg_descr_partial_transport_stream_reserved_future_use3;
static int hf_mpeg_descr_partial_transport_stream_maximum_overall_smoothing_buffer;

#define PARTIAL_TRANSPORT_STREAM_DESCR_RESERVED_FUTURE_USE1_MASK   0xC00000
#define PARTIAL_TRANSPORT_STREAM_DESCR_PEAK_RATE_MASK              0x3FFFFF
#define PARTIAL_TRANSPORT_STREAM_DESCR_RESERVED_FUTURE_USE2_MASK   0xC00000
#define PARTIAL_TRANSPORT_STREAM_DESCR_MINIMUM_SMOOTHING_RATE_MASK 0x3FFFFF
#define PARTIAL_TRANSPORT_STREAM_DESCR_RESERVED_FUTURE_USE3_MASK     0xC000
#define PARTIAL_TRANSPORT_STREAM_DESCR_MAXIMUM_SMOOTHING_BUFF_MASK   0x3FFF

static void
proto_mpeg_descriptor_dissect_partial_transport_stream(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned cnt = len;

    if (cnt < 3) return;
    proto_tree_add_item(tree, hf_mpeg_descr_partial_transport_stream_reserved_future_use1, tvb, offset, 3, ENC_BIG_ENDIAN);
    unsigned rate = tvb_get_uint24(tvb, offset, ENC_NA) & PARTIAL_TRANSPORT_STREAM_DESCR_PEAK_RATE_MASK;
    proto_tree_add_uint_bits_format_value(tree, hf_mpeg_descr_partial_transport_stream_peak_rate, tvb, (offset*8)+2,
    22, rate, ENC_BIG_ENDIAN, "%u bits/s", rate*400);
    offset += 3;
    cnt    -= 3;

    if (cnt < 3) return;
    proto_tree_add_item(tree, hf_mpeg_descr_partial_transport_stream_reserved_future_use2, tvb, offset, 3, ENC_BIG_ENDIAN);
    rate = tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN) & PARTIAL_TRANSPORT_STREAM_DESCR_MINIMUM_SMOOTHING_RATE_MASK;
    proto_tree_add_uint_bits_format_value(tree, hf_mpeg_descr_partial_transport_stream_minimum_overall_smoothing_rate, tvb,
    (offset*8)+2, 22, rate, ENC_BIG_ENDIAN, (rate==0x3FFFFFu)?"Underfined (0x3FFFFF)":"%u bits/s", rate*400u);
    offset += 3;
    cnt    -= 3;

    if (cnt < 2) return;
    proto_tree_add_item(tree, hf_mpeg_descr_partial_transport_stream_reserved_future_use3, tvb, offset, 2, ENC_BIG_ENDIAN);
    unsigned buffer = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & PARTIAL_TRANSPORT_STREAM_DESCR_MAXIMUM_SMOOTHING_BUFF_MASK;
    proto_tree_add_uint_bits_format_value(tree, hf_mpeg_descr_partial_transport_stream_maximum_overall_smoothing_buffer, tvb,
    (offset*8)+2, 14, buffer, ENC_BIG_ENDIAN, (buffer==0x3FFFu)?"Underfined (0x3FFF)":"%u bytes", buffer);
}

/* 0x64 Data Broadcast Descriptor */
static int hf_mpeg_descr_data_bcast_bcast_id;
static int hf_mpeg_descr_data_bcast_component_tag;
static int hf_mpeg_descr_data_bcast_selector_len;
static int hf_mpeg_descr_data_bcast_selector_bytes;
static int hf_mpeg_descr_data_bcast_lang_code;
static int hf_mpeg_descr_data_bcast_text_len;
static int hf_mpeg_descr_data_bcast_text;

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
proto_mpeg_descriptor_dissect_data_bcast(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{

    uint8_t selector_len, text_len;

    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_bcast_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_component_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    selector_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_selector_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (selector_len > 0) {
        proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_selector_bytes, tvb, offset, selector_len, ENC_NA);
        offset += selector_len;
    }

    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_lang_code, tvb, offset, 3, ENC_ASCII);
    offset += 3;

    text_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_text_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (text_len > 0)
        proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_text, tvb, offset, text_len, ENC_ASCII);
}

/* 0x66 Data Broadcast ID Descriptor */
static int hf_mpeg_descr_data_bcast_id_bcast_id;
static int hf_mpeg_descr_data_bcast_id_id_selector_bytes;

static void
proto_mpeg_descriptor_dissect_data_bcast_id(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_id_bcast_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (len > 2)
        proto_tree_add_item(tree, hf_mpeg_descr_data_bcast_id_id_selector_bytes, tvb, offset, len - 2, ENC_NA);
}

/* 0x69 PDC Descriptor */
static int hf_mpeg_descr_pdc_reserved;
static int hf_mpeg_descr_pdc_pil;
static int hf_mpeg_descr_pdc_day;
static int hf_mpeg_descr_pdc_month;
static int hf_mpeg_descr_pdc_hour;
static int hf_mpeg_descr_pdc_minute;

#define MPEG_DESCR_PDC_RESERVED_MASK    0xF00000
#define MPEG_DESCR_PDC_PIL_MASK         0x0FFFFF
#define MPEG_DESCR_PDC_DAY_MASK         0x0F8000
#define MPEG_DESCR_PDC_MONTH_MASK       0x007800
#define MPEG_DESCR_PDC_HOUR_MASK        0x0007C0
#define MPEG_DESCR_PDC_MINUTE_MASK      0x00003F

static int ett_mpeg_descriptor_pdc_pil;

static void
proto_mpeg_descriptor_dissect_pdc(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    proto_item * pi;
    proto_tree * pil_tree;

    proto_tree_add_item(tree, hf_mpeg_descr_pdc_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    pi = proto_tree_add_item(tree, hf_mpeg_descr_pdc_pil, tvb, offset, 3, ENC_BIG_ENDIAN);
    pil_tree = proto_item_add_subtree(pi, ett_mpeg_descriptor_pdc_pil);
    proto_tree_add_item(pil_tree, hf_mpeg_descr_pdc_day, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pil_tree, hf_mpeg_descr_pdc_month, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pil_tree, hf_mpeg_descr_pdc_hour, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pil_tree, hf_mpeg_descr_pdc_minute, tvb, offset, 3, ENC_BIG_ENDIAN);
}

/* 0x6A AC-3 Descriptor */
static int hf_mpeg_descr_ac3_component_type_flag;
static int hf_mpeg_descr_ac3_bsid_flag;
static int hf_mpeg_descr_ac3_mainid_flag;
static int hf_mpeg_descr_ac3_asvc_flag;
static int hf_mpeg_descr_ac3_reserved;
static int hf_mpeg_descr_ac3_component_type_reserved_flag;
static int hf_mpeg_descr_ac3_component_type_full_service_flag;
static int hf_mpeg_descr_ac3_component_type_service_type_flags;
static int hf_mpeg_descr_ac3_component_type_number_of_channels_flags;
static int hf_mpeg_descr_ac3_bsid;
static int hf_mpeg_descr_ac3_mainid;
static int hf_mpeg_descr_ac3_asvc;
static int hf_mpeg_descr_ac3_additional_info;

static int ett_mpeg_descriptor_ac3_component_type;

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
proto_mpeg_descriptor_dissect_ac3(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned  end = offset + len;
    uint8_t flags, component_type;

    proto_tree *component_type_tree;

    flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_component_type_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_bsid_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_mainid_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_asvc_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (flags & MPEG_DESCR_AC3_COMPONENT_TYPE_FLAG_MASK) {
        component_type = tvb_get_uint8(tvb, offset);
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
static int hf_mpeg_descr_app_sig_app_type;
static int hf_mpeg_descr_app_sig_ait_ver;

static void
proto_mpeg_descriptor_dissect_app_sig(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned  offset_start;

    offset_start = offset;
    while ((offset - offset_start) < len) {
        proto_tree_add_item(tree, hf_mpeg_descr_app_sig_app_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_mpeg_descr_app_sig_ait_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
}

/* 0x71 Service Identifier Descriptor */
static int hf_mpeg_descr_service_identifier;

static void
proto_mpeg_descriptor_dissect_service_identifier(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_service_identifier, tvb, offset, len, ENC_ASCII);
}

/* 0x72 Service Availability Descriptor */
static int hf_mpeg_descr_service_availability_flag;
static int hf_mpeg_descr_service_availability_reserved;
static int hf_mpeg_descr_service_availability_cell_id;

#define MPEG_DESCR_SRV_AVAIL_FLAG_MASK      0x80
#define MPEG_DESCR_SRV_AVAIL_RESERVED_MASK  0x7F

static int ett_mpeg_descriptor_srv_avail_cells;

static const value_string mpeg_descr_srv_avail_flag_vals[] = {
    { 0x0, "Service is unavailable on the cells" },
    { 0x1, "Service is available on the cells" },

    { 0x0, NULL }
};

static void
proto_mpeg_descriptor_dissect_service_availability(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;

    proto_tree * cells_tree;

    proto_tree_add_item(tree, hf_mpeg_descr_service_availability_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_service_availability_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    cells_tree = proto_tree_add_subtree(tree, tvb, offset, end - offset, ett_mpeg_descriptor_srv_avail_cells, NULL, "Cells");

    while (offset < end) {
        proto_tree_add_item(cells_tree, hf_mpeg_descr_service_availability_cell_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
}

/* 0x73 Default Authority Descriptor */
static int hf_mpeg_descr_default_authority_name;

static void
proto_mpeg_descriptor_dissect_default_authority(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mpeg_descr_default_authority_name, tvb, offset, len, ENC_ASCII);
}

/* 0x75 TVA ID Descriptor */
static int hf_mpeg_descr_tva_id;
static int hf_mpeg_descr_tva_reserved;
static int hf_mpeg_descr_tva_running_status;

static int ett_mpeg_descriptor_tva;

#define MPEG_DESCR_TVA_RESREVED_MASK        0xF8
#define MPEG_DESCR_TVA_RUNNING_STATUS_MASK  0x07

static const value_string mpeg_descr_tva_running_status_vals[] = {
    { 0, "Reserved" },
    { 1, "Not yet running" },
    { 2, "Starts (or restarts) shortly" },
    { 3, "Paused" },
    { 4, "Running" },
    { 5, "Cancelled" },
    { 6, "Completed" },
    { 7, "Reserved" },
    { 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_tva_id(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;
    unsigned tva_cnt = 0;

    proto_tree * tva_tree;

    while (offset < end) {
        unsigned id = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        tva_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3, ett_mpeg_descriptor_tva, NULL, "TVA %u (0x%04X)", tva_cnt, id);
        proto_tree_add_item(tva_tree, hf_mpeg_descr_tva_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        tva_cnt += 1;

        proto_tree_add_item(tva_tree, hf_mpeg_descr_tva_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tva_tree, hf_mpeg_descr_tva_running_status, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
}

/* 0x76 Content Identifier Descriptor */
static int hf_mpeg_descr_content_identifier_crid_type;
static int hf_mpeg_descr_content_identifier_crid_location;
static int hf_mpeg_descr_content_identifier_crid_length;
static int hf_mpeg_descr_content_identifier_crid_bytes;
static int hf_mpeg_descr_content_identifier_cird_ref;

#define MPEG_DESCR_CONTENT_IDENTIFIER_CRID_TYPE_MASK        0xFC
#define MPEG_DESCR_CONTENT_IDENTIFIER_CRID_LOCATION_MASK    0x03

static int ett_mpeg_descriptor_content_identifier_crid;

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
proto_mpeg_descriptor_dissect_content_identifier(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned  end = offset + len, crid_len;
    uint8_t crid, crid_location, crid_type;

    proto_tree *crid_tree;

    while (offset < end) {
        crid = tvb_get_uint8(tvb, offset);
        crid_type = (crid & MPEG_DESCR_CONTENT_IDENTIFIER_CRID_TYPE_MASK) >> 2;
        crid_location = crid & MPEG_DESCR_CONTENT_IDENTIFIER_CRID_LOCATION_MASK;

        if (crid_location == 0) {
            crid_len = 2 + tvb_get_uint8(tvb, offset + 1);
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
            crid_len = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_crid_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_crid_bytes, tvb, offset, crid_len, ENC_NA);
            offset += crid_len;
        } else if (crid_location == 0x01) {
            proto_tree_add_item(crid_tree, hf_mpeg_descr_content_identifier_cird_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
        }

    }


}

/* 0x7D XAIT Content Location Descriptor */
static int hf_mpeg_descr_xait_onid;
static int hf_mpeg_descr_xait_sid;
static int hf_mpeg_descr_xait_version_number;
static int hf_mpeg_descr_xait_update_policy;

#define MPEG_DESCR_XAIT_VERSION_NUM_MASK    0xF8
#define MPEG_DESCR_XAIT_UPDATE_POLICY_MASK  0x07

static const range_string mpeg_descr_xait_update_policy_vals[] = {
    { 0, 0, "When the XAIT version changes, immediately re-load the XAIT" },
    { 1, 1, "Ignore XAIT version changes until a reset or reinitialize" },
    { 2, 7, "Reserved for future use" },
    { 0, 0, NULL }
};

static void
proto_mpeg_descriptor_dissect_xait(tvbuff_t *tvb, unsigned offset, proto_tree *tree) {
    proto_tree_add_item(tree, hf_mpeg_descr_xait_onid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_xait_sid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mpeg_descr_xait_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_xait_update_policy, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x7E FTA Content Management Descriptor */
static int hf_mpeg_descr_fta_user_defined;
static int hf_mpeg_descr_fta_reserved_future_use;
static int hf_mpeg_descr_fta_do_not_scramble;
static int hf_mpeg_descr_fta_control_remote_access_over_internet;
static int hf_mpeg_descr_fta_do_not_apply_revocation;

#define MPEG_DESCR_FTA_USER_DEFINED_MASK 0x80
#define MPEG_DESCR_FTA_RESERVED_MASK 0x70
#define MPEG_DESCR_FTA_DO_NOT_SCRAMBLE_MASK 0x08
#define MPEG_DESCR_FTA_REMOTE_MASK 0x06
#define MPEG_DESCR_FTA_REVOCATION_MASK 0x01

static const value_string fta_control_remote_access_over_internet_vals[] = {
    { 0, "Redistribution over the Internet is enabled." },
    { 1, "Redistribution over the Internet is enabled but only within a managed domain." },
    { 2, "Redistribution over the Internet is enabled but only within a managed domain and after a certain short period of time (e.g. 24 hours)." },
    { 3, "Redistribution over the Internet is not allowed with the following exception: Redistribution over the Internet within a managed domain is enabled after a specified long (possibly indefinite) period of time." },
    { 0, NULL }
};

static const true_false_string tfs_fta_do_not_scramble = { "Scrambling shall not be applied for the purposes of content protection", "Scrambling shall be applied where applicable for content protection" };
static const true_false_string tfs_fta_do_not_apply_revocation = { "Content revocation process shall not be applied", "Content revocation process shall be applied" };

static void
proto_mpeg_descriptor_dissect_fta(tvbuff_t *tvb, unsigned offset, proto_tree *tree) {
    proto_tree_add_item(tree, hf_mpeg_descr_fta_user_defined, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_fta_reserved_future_use, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_fta_do_not_scramble, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_fta_control_remote_access_over_internet, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_fta_do_not_apply_revocation, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 0x7F Extension Descriptor */
static int hf_mpeg_descr_extension_tag_extension;
static int hf_mpeg_descr_extension_data;
/* Supplementary Audio (Sub-)Descriptor */
static int hf_mpeg_descr_extension_supp_audio_mix_type;
static int hf_mpeg_descr_extension_supp_audio_ed_cla;
static int hf_mpeg_descr_extension_supp_audio_lang_code_present;
static int hf_mpeg_descr_extension_supp_audio_lang_code;

static int hf_mpeg_descr_private_data;

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
proto_mpeg_descriptor_dissect_extension(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned  offset_start;
    uint8_t   tag_ext;
    bool      lang_code_present;
    unsigned  already_dissected;

    offset_start = offset;

    tag_ext = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_extension_tag_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (tag_ext) {
        case EXT_TAG_SUPP_AUDIO:
            proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_mix_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_ed_cla, tvb, offset, 1, ENC_BIG_ENDIAN);
            lang_code_present = ((tvb_get_uint8(tvb, offset) & 0x01) == 0x01);
            proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_lang_code_present, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            if (lang_code_present) {
                proto_tree_add_item(tree, hf_mpeg_descr_extension_supp_audio_lang_code, tvb, offset, 3, ENC_ASCII);
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

#define MPEG_DESCR_AC3_SYSA_SRATE_MASK 0xe0
#define MPEG_DESCR_AC3_SYSA_BSID_MASK 0x1f
#define MPEG_DESCR_AC3_SYSA_BITRATE_CODE_LIMIT_MASK 0x80
#define MPEG_DESCR_AC3_SYSA_BITRATE_CODE_MASK 0x7c
#define MPEG_DESCR_AC3_SYSA_SURROUND_MODE_MASK 0x03
#define MPEG_DESCR_AC3_SYSA_BSMOD_MASK 0xe0
#define MPEG_DESCR_AC3_SYSA_NUM_CHANNELS_MASK 0x1e
#define MPEG_DESCR_AC3_SYSA_FULL_SVC_MASK 0x01
#define MPEG_DESCR_AC3_SYSA_MAINID_MASK 0xe0
#define MPEG_DESCR_AC3_SYSA_PRIORITY_MASK 0x18
#define MPEG_DESCR_AC3_SYSA_RESERVED_MASK 0x07
#define MPEG_DESCR_AC3_SYSA_TEXTLEN_MASK 0xfe
#define MPEG_DESCR_AC3_SYSA_TEXTCODE_MASK 0x01
#define MPEG_DESCR_AC3_SYSA_LANG1_MASK 0x80
#define MPEG_DESCR_AC3_SYSA_LANG2_MASK 0x40

static int hf_mpeg_descr_ac3_sysa_srate;
static int hf_mpeg_descr_ac3_sysa_bsid;
static int hf_mpeg_descr_ac3_sysa_bitrate;
static int hf_mpeg_descr_ac3_sysa_bitrate_limit;
static int hf_mpeg_descr_ac3_sysa_surround;
static int hf_mpeg_descr_ac3_sysa_bsmod;
static int hf_mpeg_descr_ac3_sysa_num_channels;
static int hf_mpeg_descr_ac3_sysa_full_svc;
static int hf_mpeg_descr_ac3_sysa_langcode;
static int hf_mpeg_descr_ac3_sysa_langcode2;
static int hf_mpeg_descr_ac3_sysa_mainid;
static int hf_mpeg_descr_ac3_sysa_priority;
static int hf_mpeg_descr_ac3_sysa_reserved;
static int hf_mpeg_descr_ac3_sysa_asvcflags;
static int hf_mpeg_descr_ac3_sysa_textlen;
static int hf_mpeg_descr_ac3_sysa_textcode;
static int hf_mpeg_descr_ac3_sysa_lang1;
static int hf_mpeg_descr_ac3_sysa_lang2;
static int hf_mpeg_descr_ac3_sysa_lang1_bytes;
static int hf_mpeg_descr_ac3_sysa_lang2_bytes;

/* ATSC A/52 Annex A Table A4.2*/
static const value_string mpeg_descr_ac3_sysa_srate_flag_vals[] = {
    { 0x0, "48 KHz" },
    { 0x1, "44.1 KHz" },
    { 0x2, "32 KHz" },
    { 0x3, "Reserved" },
    { 0x4, "48 or 44.1 KHz" },
    { 0x5, "48 or 32 KHz" },
    { 0x6, "44.1 or 32 KHz" },
    { 0x7, "48, 44.1 or 32 KHz" },
    { 0x0, NULL }
};

/* ATSC A/52 Annex A Table A4.3 */
static const value_string mpeg_descr_ac3_sysa_bitrate_code_limit_vals[] = {
    { 0, "Exact bitrate" },
    { 1, "Upper limit bitrate" },
    { 0x0, NULL }
};

static const value_string mpeg_descr_ac3_sysa_bitrate_code_vals[] = {
    { 0, "32 KHz" },
    { 1, "40 KHz" },
    { 2, "48 KHz" },
    { 3, "56 KHz" },
    { 4, "64 KHz" },
    { 5, "80 KHz" },
    { 6, "96 KHz" },
    { 7, "112 KHz" },
    { 8, "128 KHz" },
    { 9, "160 KHz" },
    { 10, "192 KHz" },
    { 11, "224 KHz" },
    { 12, "256 KHz" },
    { 13, "320 KHz" },
    { 14, "384 KHz" },
    { 15, "448 KHz" },
    { 16, "512 KHz" },
    { 17, "576 KHz" },
    { 18, "640 KHz" },
    { 0x0, NULL }
};

/* ATSC A/52 Annex A Table A4.4 */
static const value_string mpeg_descr_ac3_sysa_surround_mode_vals[] = {
    { 0x0, "Not indicated" },
    { 0x1, "NOT Dolby Surround Sound" },
    { 0x2, "Dolby Surround Sound" },
    { 0x3, "Reserved" },
    { 0x0, NULL }
};

/* ATSC A/52 Annex A Table A4.5*/
static const value_string mpeg_descr_ac3_sysa_num_channels_vals[] = {
    { 0x0, "1 + 1 channels" },
    { 0x1, "1/0 channels" },
    { 0x2, "2/0 channels" },
    { 0x3, "3/0 channels" },
    { 0x4, "2/1 channels" },
    { 0x5, "3/1 channels" },
    { 0x6, "2/2 channels" },
    { 0x7, "3/2 channels" },
    { 0x8, "1 channel" },
    { 0x9, "<= 2 channels" },
    { 0xa, "<= 3 channels" },
    { 0xb, "<= 4 channels" },
    { 0xc, "<= 5 channels" },
    { 0xd, "<= 6 channels" },
    { 0xe, "Reserved" },
    { 0xf, "Reserved" },
    { 0x0, NULL }
};

/* ATSC A/52 Annex A Table A4.6 */
static const value_string mpeg_descr_ac3_sysa_priority_vals[] = {
    { 0x0, "Reserved" },
    { 0x1, "Primary Audio" },
    { 0x2, "Other Audio" },
    { 0x3, "Not specified" },
    { 0x0, NULL }
};

/* According to ATSC A/52, Annex A, there are two separate ATSC descriptors.  "System A" is used
   by ATSC, and "System B" is used by DVB.  See A/52 Sec A.4.1 for the System A definition */
static void
proto_mpeg_descriptor_dissect_ac3_system_a(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned  end = offset + len;
    uint8_t bsmod_chans_fullsvc, bsmod, num_channels, textlen, lang;

    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_srate, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_bsid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_bitrate_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_bitrate, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_surround, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    bsmod_chans_fullsvc = tvb_get_uint8(tvb, offset);
    bsmod = (bsmod_chans_fullsvc & 0xe0) >> 5;
    num_channels = (bsmod_chans_fullsvc & 0x1e) >> 1;
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_bsmod, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_num_channels, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_full_svc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset >= end) return;

    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_langcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset >= end) return;

    if (num_channels == 0) {
        /* 1+1 mode, so there is the possibility the second mono is in a different language */
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_langcode2, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (offset >= end) return;

    if (bsmod < 2) {
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_mainid, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_asvcflags, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;

    if (offset >= end) return;

    textlen = tvb_get_uint8(tvb, offset) >> 1;
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_textlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_textcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    offset += textlen;

    if (offset >= end) return;

    lang = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_lang1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_lang2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset >= end) return;

    if (lang & 0x80) {
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_lang1_bytes, tvb, offset, 3, ENC_ASCII);
        offset += 3;
    }

    if (offset >= end) return;

    if (lang & 0x40) {
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_sysa_lang2_bytes, tvb, offset, 3, ENC_ASCII);
        offset += 3;
    }

    if (offset < end)
        proto_tree_add_item(tree, hf_mpeg_descr_ac3_additional_info, tvb, offset, end - offset, ENC_NA);
}

/* 0x83 NorDig Logical Channel Descriptor (version 1) */
static int hf_mpeg_descr_nordig_lcd_v1_service_list_id;
static int hf_mpeg_descr_nordig_lcd_v1_service_list_visible_service_flag;
static int hf_mpeg_descr_nordig_lcd_v1_service_list_reserved;
static int hf_mpeg_descr_nordig_lcd_v1_service_list_logical_channel_number;

static int ett_mpeg_descriptor_nordig_lcd_v1_service_list;

#define MPEG_DESCR_NORDIG_LCD_V1_VISIBLE_SERVICE_FLAG_MASK 0x8000
#define MPEG_DESCR_NORDIG_LCD_V1_RESERVED_MASK             0x4000
#define MPEG_DESCR_NORDIG_LCD_V1_LCN_MASK                  0x3fff

static void
proto_mpeg_descriptor_dissect_nordig_lcd_v1(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned   end    = offset + len;

    if (len%4 != 0) {
        return;
    }

    uint16_t svc_id;
    proto_tree * svc_tree;

    while (offset < end) {
        svc_id = tvb_get_ntohs(tvb, offset);

        svc_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3,
                    ett_mpeg_descriptor_nordig_lcd_v1_service_list, NULL, "Service 0x%04x", svc_id);

        proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v1_service_list_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v1_service_list_visible_service_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v1_service_list_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v1_service_list_logical_channel_number, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

}

/* 0x87 NorDig Logical Channel Descriptor (version 2) */
static int hf_mpeg_descr_nordig_lcd_v2_channel_list_id;
static int hf_mpeg_descr_nordig_lcd_v2_channel_list_name_length;
static int hf_mpeg_descr_nordig_lcd_v2_channel_list_name_encoding;
static int hf_mpeg_descr_nordig_lcd_v2_channel_list_name;
static int hf_mpeg_descr_nordig_lcd_v2_country_code;
static int hf_mpeg_descr_nordig_lcd_v2_descriptor_length;
static int hf_mpeg_descr_nordig_lcd_v2_service_id;
static int hf_mpeg_descr_nordig_lcd_v2_visible_service_flag;
static int hf_mpeg_descr_nordig_lcd_v2_reserved;
static int hf_mpeg_descr_nordig_lcd_v2_logical_channel_number;

static int ett_mpeg_descriptor_nordig_lcd_v2_channel_list_list;
static int ett_mpeg_descriptor_nordig_lcd_v2_service_list;

#define MPEG_DESCR_NORDIG_LCD_V2_VISIBLE_SERVICE_FLAG_MASK 0x8000
#define MPEG_DESCR_NORDIG_LCD_V2_RESERVED_MASK             0x7c00
#define MPEG_DESCR_NORDIG_LCD_V2_LCN_MASK                  0x03ff

static int
proto_mpeg_descriptor_dissect_nordig_lcd_v2_measure_ch_list(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    unsigned l_offset = offset;
    if (len < 2) {
        return len;
    }
    uint8_t channel_list_name_length = tvb_get_uint8(tvb, l_offset + 1);
    l_offset += 2 + channel_list_name_length + 4;
    if (l_offset > offset + len) {
        return len;
    }
    uint8_t descriptor_len = tvb_get_uint8(tvb, l_offset - 1);
    l_offset += descriptor_len;
    if (l_offset > offset + len) {
        return len;
    } else {
        return l_offset - offset;
    }
}

static void
proto_mpeg_descriptor_dissect_nordig_lcd_v2(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned   cnt    = len;
    unsigned   end    = offset + len;

    proto_tree * channel_list_tree;

    while (cnt > 0) {
        int ch_list_len = proto_mpeg_descriptor_dissect_nordig_lcd_v2_measure_ch_list(tvb, offset, end - offset);
        uint8_t channel_list_id;
        uint8_t channel_list_name_length;
        uint8_t descriptor_length;

        channel_list_id = tvb_get_uint8(tvb, offset);
        channel_list_tree = proto_tree_add_subtree_format(tree, tvb, offset, ch_list_len,
                    ett_mpeg_descriptor_nordig_lcd_v2_channel_list_list, NULL, "Channel list 0x%02x", channel_list_id);
        proto_tree_add_item(channel_list_tree, hf_mpeg_descr_nordig_lcd_v2_channel_list_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        if (cnt < 1) return;
        channel_list_name_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(channel_list_tree, hf_mpeg_descr_nordig_lcd_v2_channel_list_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        channel_list_name_length = MIN(cnt, channel_list_name_length);
        dvb_encoding_e  encoding;
        unsigned enc_len = dvb_analyze_string_charset(tvb, offset, channel_list_name_length, &encoding);
        dvb_add_chartbl(channel_list_tree, hf_mpeg_descr_nordig_lcd_v2_channel_list_name_encoding, tvb, offset, enc_len, encoding);

        proto_tree_add_item(channel_list_tree, hf_mpeg_descr_nordig_lcd_v2_channel_list_name, tvb, offset+enc_len, channel_list_name_length-enc_len, dvb_enc_to_item_enc(encoding));
        offset += channel_list_name_length;
        cnt    -= channel_list_name_length;

        if (cnt < 3) return;
        proto_tree_add_item(channel_list_tree, hf_mpeg_descr_nordig_lcd_v2_country_code, tvb, offset, 3, ENC_ASCII);
        offset += 3;
        cnt    -= 3;

        if (cnt < 1) return;
        descriptor_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(channel_list_tree, hf_mpeg_descr_nordig_lcd_v2_descriptor_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        cnt    -= 1;

        descriptor_length = MIN(descriptor_length, cnt);
        while (descriptor_length > 0) {
            uint16_t svc_id;
            proto_tree * svc_tree;

            if (cnt < 2) return;
            svc_id = tvb_get_ntohs(tvb, offset);

            svc_tree = proto_tree_add_subtree_format(channel_list_tree, tvb, offset, 4,
                        ett_mpeg_descriptor_nordig_lcd_v2_service_list, NULL, "Service 0x%04x", svc_id);

            proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v2_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            cnt    -= 2;
            descriptor_length -= 2;

            if (cnt < 2) return;
            proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v2_visible_service_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v2_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(svc_tree, hf_mpeg_descr_nordig_lcd_v2_logical_channel_number, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            cnt    -= 2;
            descriptor_length -= 2;
        }

    }
}

/* 0xA2 Logon Initialize Descriptor */
static int hf_mpeg_descr_logon_initialize_group_id;
static int hf_mpeg_descr_logon_initialize_logon_id;
static int hf_mpeg_descr_logon_initialize_continuous_carrier_reserved;
static int hf_mpeg_descr_logon_initialize_continuous_carrier;
static int hf_mpeg_descr_logon_initialize_security_handshake_required;
static int hf_mpeg_descr_logon_initialize_prefix_flag;
static int hf_mpeg_descr_logon_initialize_data_unit_labelling_flag;
static int hf_mpeg_descr_logon_initialize_mini_slot_flag;
static int hf_mpeg_descr_logon_initialize_contention_based_mini_slot_flag;
static int hf_mpeg_descr_logon_initialize_capacity_type_flag_reserved;
static int hf_mpeg_descr_logon_initialize_capacity_type_flag;
static int hf_mpeg_descr_logon_initialize_traffic_burst_type;
static int hf_mpeg_descr_logon_initialize_connectivity;
static int hf_mpeg_descr_logon_initialize_return_vpi_reserved;
static int hf_mpeg_descr_logon_initialize_return_vpi;
static int hf_mpeg_descr_logon_initialize_return_vci;
static int hf_mpeg_descr_logon_initialize_return_signalling_vpi_reserved;
static int hf_mpeg_descr_logon_initialize_return_signalling_vpi;
static int hf_mpeg_descr_logon_initialize_return_signalling_vci;
static int hf_mpeg_descr_logon_initialize_forward_signalling_vpi_reserved;
static int hf_mpeg_descr_logon_initialize_forward_signalling_vpi;
static int hf_mpeg_descr_logon_initialize_forward_signalling_vci;

static int hf_mpeg_descr_logon_initialize_return_trf_pid;
static int hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid_reserved;
static int hf_mpeg_descr_logon_initialize_return_ctrl_mngm_pid;

static int hf_mpeg_descr_logon_initialize_cra_level;
static int hf_mpeg_descr_logon_initialize_vbdc_max_reserved;
static int hf_mpeg_descr_logon_initialize_vbdc_max;
static int hf_mpeg_descr_logon_initialize_rbdc_max;
static int hf_mpeg_descr_logon_initialize_rbdc_timeout;


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
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_VPI_RESERVED_MASK                    0xF0
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_VPI_MASK                             0x0F

#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_RESERVED_MASK         0xF0
#define MPEG_DESCR_LOGON_INITIALIZE_RETURN_SIGNALLING_VPI_MASK                  0x0F
#define MPEG_DESCR_LOGON_INITIALIZE_FORWARD_SIGNALLING_VPI_RESERVED_MASK        0xFF00
#define MPEG_DESCR_LOGON_INITIALIZE_FORWARD_SIGNALLING_VPI_MASK                 0x00FF

#define MPEG_DESCR_LOGON_INITIALIZE_VDBC_MAX_RESERVED_MASK                      0xF800
#define MPEG_DESCR_LOGON_INITIALIZE_VDBC_MAX_MASK                               0x07FF

/* ETSI EN 301 790 - 8.5.5.10.4 Logon Initialize descriptor */
static void
proto_mpeg_descriptor_dissect_logon_initialize(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{

    unsigned   end    = offset + len;
    uint8_t flags;
    uint16_t flags2;

    if (len >= 1)
    {
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_group_id,                        tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (len >= 3)
    {
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_logon_id,                        tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (len >= 4)
    {
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_continuous_carrier_reserved,     tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_continuous_carrier,              tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_security_handshake_required,     tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_prefix_flag,                     tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_data_unit_labelling_flag,        tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_mini_slot_flag,                  tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_contention_based_mini_slot_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (len >= 5)
    {
        flags = tvb_get_uint8(tvb, offset);

        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_capacity_type_flag_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_capacity_type_flag,          tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_traffic_burst_type,          tvb, offset, 1, ENC_BIG_ENDIAN);
        /* If (Traffic_burst_type == 0) { */
        if (flags & MPEG_DESCR_LOGON_INITIALIZE_TRAFFIC_BURST_TYPE_MASK) {
            /* Connectivity */
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_connectivity, tvb, offset, 2, ENC_BIG_ENDIAN);
            flags2 = tvb_get_ntohs(tvb, offset);
            if (flags2 & MPEG_DESCR_LOGON_INITIALIZE_CONNECTIVITY_MASK) {
                /* Else    { (out of order) */

                /* Return_signalling_VPI (4 bits reserved, 4 bits) */
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_signalling_vpi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_signalling_vpi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Return_signalling_VCI (16 bits) */
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_signalling_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Forward_signalling_VPI (4 bits reserved, then 4 bits) */
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_forward_signalling_vpi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_forward_signalling_vpi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Forward_signalling_VCI (16 bits) */
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_forward_signalling_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            } else {
                /* If (Connectivity == 0) {  */

                /* Return_signalling_VPI (4 bits reserved, then 4 bits) */
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_vpi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_return_vpi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Return_signalling_VCI (16 bits) */
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

            /* CRA_level (3 bytes) */
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_cra_level,         tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            /* VBDC_max (5 bits reserved, 11 bits) */
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_vbdc_max_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_vbdc_max,          tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* RBDC_max (3 bytes) */
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_rbdc_max,          tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            /* RBDC timeout (2 bytes) */
            proto_tree_add_item(tree, hf_mpeg_descr_logon_initialize_rbdc_timeout,      tvb, offset, 2, ENC_BIG_ENDIAN);
            /*offset += 2;*/
        }
    }
}

/* 0xA7 RCS Content Descriptor */
static int hf_mpeg_descr_rcs_content_table_id;

static void
proto_mpeg_descriptor_dissect_rcs_content(tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree)
{
    unsigned end = offset + len;

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
static int hf_mpeg_descr_ciplus_cl_cb_min;
static int hf_mpeg_descr_ciplus_cl_cb_max;
static int hf_mpeg_descr_ciplus_cl_lang;
static int hf_mpeg_descr_ciplus_cl_label;

/* 0xCC CI+ Service Descriptor */
static int hf_mpeg_descr_ciplus_svc_id;
static int hf_mpeg_descr_ciplus_svc_type;
static int hf_mpeg_descr_ciplus_svc_visible;
static int hf_mpeg_descr_ciplus_svc_selectable;
static int hf_mpeg_descr_ciplus_svc_lcn;
static int hf_mpeg_descr_ciplus_svc_prov_name;
static int hf_mpeg_descr_ciplus_svc_name;

/* 0xCE CI+ Protection Descriptor */
static int hf_mpeg_descr_ciplus_prot_free_ci_mode;
static int hf_mpeg_descr_ciplus_prot_match_brand_flag;
static int hf_mpeg_descr_ciplus_prot_num_entries;
static int hf_mpeg_descr_ciplus_prot_brand_id;

static const true_false_string tfs_prot_noprot = { "CI+ protection required", "CI+ protection not required" };


static unsigned
proto_mpeg_descriptor_dissect_private_ciplus(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    unsigned     offset_start;
    uint8_t      tag, len;
    const char *tag_str;
    proto_item  *di;
    proto_tree  *descriptor_tree;

    offset_start=offset;

    tag = tvb_get_uint8(tvb, offset);
    tag_str = try_val_to_str(tag, mpeg_descriptor_ciplus_tag_vals);
    if (!tag_str)
        return 0;

    descriptor_tree = proto_tree_add_subtree_format(tree, tvb, offset_start, -1,
                ett_mpeg_descriptor, &di, "CI+ private descriptor Tag=0x%02x", tag);

    proto_tree_add_uint_format(descriptor_tree, hf_mpeg_descriptor_tag,
            tvb, offset, 1, tag, "Descriptor Tag: %s (0x%02x)", tag_str, tag);
    offset += 1;

    len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(descriptor_tree, hf_mpeg_descriptor_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (tag==CIPLUS_DESC_TAG_CNT_LBL) {
        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_cb_min, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_cb_max, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_lang, tvb, offset, 3, ENC_ASCII);
        offset += 3;

        proto_tree_add_item(tree, hf_mpeg_descr_ciplus_cl_label, tvb, offset, len-offset, ENC_ASCII);
        offset += len-offset;
    }
    else if (tag==CIPLUS_DESC_TAG_SVC) {
        uint8_t str_len_byte;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_visible, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_selectable, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_lcn, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        str_len_byte = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_prov_name, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        offset += 1+str_len_byte;

        str_len_byte = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_svc_name, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        offset += 1+str_len_byte;
    }
    else if (tag==CIPLUS_DESC_TAG_PROT) {
        bool      match_brand_flag;
        uint8_t   num_brands, i;
        unsigned  remaining;

        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_prot_free_ci_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
        match_brand_flag = ((tvb_get_uint8(tvb, offset) & 0x40) == 0x40);
        proto_tree_add_item(descriptor_tree, hf_mpeg_descr_ciplus_prot_match_brand_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (match_brand_flag) {
            num_brands = tvb_get_uint8(tvb, offset);
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

unsigned
proto_mpeg_descriptor_dissect(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    unsigned    tag, len;

    proto_tree *descriptor_tree;

    tag = tvb_get_uint8(tvb, offset);
    len = tvb_get_uint8(tvb, offset + 1);

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
        case 0x49: /* Country Availability Descriptor */
            proto_mpeg_descriptor_dissect_country_availability_descriptor(tvb, offset, len, descriptor_tree);
            break;
        case 0x4A: /* Linkage Descriptor */
            proto_mpeg_descriptor_dissect_linkage(tvb, offset, len, descriptor_tree);
            break;
        case 0x4B: /* NVOD Reference Descriptor */
            proto_mpeg_descriptor_dissect_nvod_reference(tvb, offset, len, descriptor_tree);
            break;
        case 0x4C: /* Time Shifted Service Descriptor */
            proto_mpeg_descriptor_dissect_time_shifted_service(tvb, offset, descriptor_tree);
            break;
        case 0x4D: /* Short Event Descriptor */
            proto_mpeg_descriptor_dissect_short_event(tvb, offset, descriptor_tree);
            break;
        case 0x4E: /* Extended Event Descriptor */
            proto_mpeg_descriptor_dissect_extended_event(tvb, offset, descriptor_tree);
            break;
        case 0x4F: /* Time Shifted Event Descriptor */
            proto_mpeg_descriptor_dissect_time_shifted_event(tvb, offset, descriptor_tree);
            break;
        case 0x50: /* Component Descriptor */
            proto_mpeg_descriptor_dissect_component(tvb, offset, len, descriptor_tree);
            break;
        case 0x51: /* Mosaic Descriptor */
            proto_mpeg_descriptor_dissect_mosaic(tvb, offset, len, descriptor_tree);
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
        case 0x57: /* Telephone Descriptor */
            proto_mpeg_descriptor_dissect_telephone(tvb, offset, descriptor_tree);
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
        case 0x5B: /* Multilingual Network Name Descriptor */
            proto_mpeg_descriptor_dissect_multilng_network_name_desc(tvb, offset, len, descriptor_tree);
            break;
        case 0x5C: /* Multilingual Bouquet Name Descriptor */
            proto_mpeg_descriptor_dissect_multilng_bouquet_name_desc(tvb, offset, len, descriptor_tree);
            break;
        case 0x5D: /* Multilingual Service Name Descriptor */
            proto_mpeg_descriptor_dissect_multilng_srv_name_desc(tvb, offset, len, descriptor_tree);
            break;
        case 0x5E: /* Multilingual Component Descriptor */
            proto_mpeg_descriptor_dissect_multilng_component_desc(tvb, offset, len, descriptor_tree);
            break;
        case 0x5F: /* Private Data Specifier Descriptor */
            proto_mpeg_descriptor_dissect_private_data_specifier(tvb, offset, descriptor_tree);
            break;
        case 0x61: /* Short Smoothing Buffer Descriptor */
            proto_mpeg_descriptor_dissect_short_smoothing_buffer(tvb, offset, len, descriptor_tree);
            break;
        case 0x63: /* Partial Transport Stream Descriptor */
            proto_mpeg_descriptor_dissect_partial_transport_stream(tvb, offset, len, descriptor_tree);
            break;
        case 0x64: /* Data Broadcast Descriptor */
            proto_mpeg_descriptor_dissect_data_bcast(tvb, offset, descriptor_tree);
            break;
        case 0x66: /* Data Broadcast ID Descriptor */
            proto_mpeg_descriptor_dissect_data_bcast_id(tvb, offset, len, descriptor_tree);
            break;
        case 0x69: /* PDC Descriptor */
            proto_mpeg_descriptor_dissect_pdc(tvb, offset, descriptor_tree);
            break;
        case 0x6A: /* AC-3 Descriptor */
            proto_mpeg_descriptor_dissect_ac3(tvb, offset, len, descriptor_tree);
            break;
        case 0x6F: /* Application Signalling Descriptor */
            proto_mpeg_descriptor_dissect_app_sig(tvb, offset, len, descriptor_tree);
            break;
        case 0x71: /* Service Identifier Descriptor */
            proto_mpeg_descriptor_dissect_service_identifier(tvb, offset, len, descriptor_tree);
            break;
        case 0x72: /* Service Availability Descriptor */
            proto_mpeg_descriptor_dissect_service_availability(tvb, offset, len, descriptor_tree);
            break;
        case 0x73: /* Default Authority Descriptor */
            proto_mpeg_descriptor_dissect_default_authority(tvb, offset, len, descriptor_tree);
            break;
        case 0x75: /* TVA ID Descriptor */
            proto_mpeg_descriptor_dissect_tva_id(tvb, offset, len, descriptor_tree);
            break;
        case 0x76: /* Content Identifier Descriptor */
            proto_mpeg_descriptor_dissect_content_identifier(tvb, offset, len, descriptor_tree);
            break;
        case 0x7D: /* XAIT Content Location Descriptor */
            proto_mpeg_descriptor_dissect_xait(tvb, offset, descriptor_tree);
            break;
        case 0x7E: /* FTA Content Management Descriptor */
            proto_mpeg_descriptor_dissect_fta(tvb, offset, descriptor_tree);
            break;
        case 0x7F: /* Extension Descriptor */
            proto_mpeg_descriptor_dissect_extension(tvb, offset, len, descriptor_tree);
            break;
        case 0x81: /* ATSC A/52 AC-3 Audio Descriptor */
            proto_mpeg_descriptor_dissect_ac3_system_a(tvb, offset, len, descriptor_tree);
            break;
        case 0x83: /* NorDig Logical Channel Descriptor (version 1) */
            proto_mpeg_descriptor_dissect_nordig_lcd_v1(tvb, offset, len, descriptor_tree);
            break;
        case 0x87: /* NorDig Logical Channel Descriptor (version 2) */
            proto_mpeg_descriptor_dissect_nordig_lcd_v2(tvb, offset, len, descriptor_tree);
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
unsigned
proto_mpeg_descriptor_loop_dissect(tvbuff_t *tvb, unsigned offset, unsigned loop_len, proto_tree *tree)
{
    /* we use the reserved value to indicate that no private context is active */
    uint32_t private_data_specifier = PRIVATE_DATA_SPECIFIER_RESERVED;
    unsigned   offset_start;
    unsigned   desc_len;
    uint8_t tag;

    offset_start = offset;

    while ((offset - offset_start) < loop_len) {
        /* don't increment offset in our pre-checks */
        tag = tvb_get_uint8(tvb, offset);
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
            FT_UINT32, BASE_HEX, VALS(mpeg_descr_registration_reg_form_vals), 0, NULL, HFILL
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
            "Constraint Set0 Flag", "mpeg_descr.avc_vid.constraint_set0",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AVC_VID_CONSTRAINT_SET0_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_constraint_set1_flag, {
            "Constraint Set1 Flag", "mpeg_descr.avc_vid.constraint_set1",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_AVC_VID_CONSTRAINT_SET1_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_avc_vid_constraint_set2_flag, {
            "Constraint Set2 Flag", "mpeg_descr.avc_vid.constraint_set2",
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
        { &hf_mpeg_descr_network_name_encoding, {
            "Network Name Encoding", "mpeg_descr.net_name.name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

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
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_ghz, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_satellite_delivery_orbital_position, {
            "Orbital Position", "mpeg_descr.sat_delivery.orbital_pos",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_degree_degrees, 0, NULL, HFILL
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
        { &hf_mpeg_descr_bouquet_name_encoding, {
            "Bouquet Name Encoding", "mpeg_descr.bouquet_name.name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_bouquet_name, {
            "Bouquet Name", "mpeg_descr.bouquet_name.name",
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
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
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
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x49 Country Availability Descriptor */
        { &hf_mpeg_descr_country_availability_flag, {
            "Country Availability Flag", "mpeg_descr.country_avail.avail_flag",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_country_availability_flag_vals),
            MPEG_DESCR_COUNTRY_AVAILABILITY_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_country_availability_reserved_future_use, {
            "Reserved Future Use", "mpeg_descr.country_avail.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_COUNTRY_AVAILABILITY_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_country_availability_country_code, {
            "Country Code", "mpeg_descr.country_avail.country_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
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

        /* 0x4B NVOD Reference Descriptor */
        { &hf_mpeg_descr_nvod_reference_tsid, {
            "Transport Stream ID", "mpeg_descr.nvod_ref.tsid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nvod_reference_onid, {
            "Original Network ID", "mpeg_descr.nvod_ref.onid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nvod_reference_sid, {
            "Stream ID", "mpeg_descr.nvod_ref.sid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x4C Time Shifted Service Descriptor */
        { &hf_mpeg_descr_time_shifted_service_id, {
            "Reference Service ID", "mpeg_descr.time_shifted_service.id",
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
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
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
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
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
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x4F Time Shifted Event Descriptor */
        { &hf_mpeg_descr_time_shifted_event_reference_service_id, {
            "Reference Service ID", "mpeg_descr.tshift_evt.sid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_time_shifted_event_reference_event_id, {
            "Reference Event ID", "mpeg_descr.tshift_evt.eid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x50 Component Descriptor */
        { &hf_mpeg_descr_component_nga_bits_b7_reserved, {
            "Reserved zero for future use", "mpeg_descr.component.nga.reserved",
            FT_UINT16, BASE_HEX, NULL,
            MPEG_DESCR_COMPONENT_NGA_BITS_B7_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_nga_bits_b6_headphones, {
            "Pre-rendered for consumption with headphones", "mpeg_descr.component.nga.headphones",
            FT_UINT16, BASE_HEX, NULL,
            MPEG_DESCR_COMPONENT_NGA_BITS_B6_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_nga_bits_b5_interactivity, {
            "Enables interactivity", "mpeg_descr.component.nga.interactivity",
            FT_UINT16, BASE_HEX, NULL,
            MPEG_DESCR_COMPONENT_NGA_BITS_B5_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_nga_bits_b4_dialogue_enhancement, {
            "Enables dialogue enhancement", "mpeg_descr.component.nga.dialogue_enhancement",
            FT_UINT16, BASE_HEX, NULL,
            MPEG_DESCR_COMPONENT_NGA_BITS_B4_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_nga_bits_b3_spoken_subtitles, {
            "Contains spoken subtitles", "mpeg_descr.component.nga.spoken_subtitles",
            FT_UINT16, BASE_HEX, NULL,
            MPEG_DESCR_COMPONENT_NGA_BITS_B3_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_nga_bits_b2_audio_description, {
            "Contains audio description", "mpeg_descr.component.nga.audio_description",
            FT_UINT16, BASE_HEX, NULL,
            MPEG_DESCR_COMPONENT_NGA_BITS_B2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_nga_bits_b10_channel_layout, {
            "Preferred reproduction channel layout", "mpeg_descr.component.nga.channel_layout",
            FT_UINT16, BASE_HEX, VALS(mpeg_descr_component_preferred_reproduction_channel_layout_vals),
            MPEG_DESCR_COMPONENT_NGA_BITS_B10_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_high_stream_content_n_component_type, {
            "Stream Content and Component Type", "mpeg_descr.component.content_type",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &mpeg_descr_component_high_content_type_vals_ext,
            MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_N_COMPONENT_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_high_stream_content_both, {
            "Stream Content both", "mpeg_descr.component.stream_content_both",
            FT_UINT16, BASE_HEX, VALS(mpeg_descr_component_high_stream_content_vals),
            MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_BOTH_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_high_stream_content_ext, {
            "Stream Content Ext", "mpeg_descr.component.stream_content_ext",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_EXT_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_high_stream_content, {
            "Stream Content", "mpeg_descr.component.stream_content",
            FT_UINT16, BASE_HEX, NULL,
            MPEG_DESCR_COMPONENT_HIGH_STREAM_CONTENT_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_high_component_type, {
            "Component Type", "mpeg_descr.component.type",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_COMPONENT_HIGH_COMPONENT_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_stream_content_ext, {
            "Stream Content Ext", "mpeg_descr.component.stream_content_ext",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_COMPONENT_STREAM_CONTENT_EXT_MASK, NULL, HFILL
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

        { &hf_mpeg_descr_component_text_encoding, {
            "Text Encoding", "mpeg_descr.component.text_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_component_text, {
            "Text", "mpeg_descr.component.text",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x51 Mosaic Descriptor */
        { &hf_mpeg_descr_mosaic_mosaic_entry_point, {
            "Mosaic Entry Point", "mpeg_descr.mosaic.entry_point",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_MOSAIC_ENTRY_POINT_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_number_of_horizontal_elementary_cells, {
            "Number Of Horizontal Elementary Cells", "mpeg_descr.mosaic.h_cells_num",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_mosaic_number_of_e_cells_vals),
            MPEG_DESCR_MOSAIC_NUM_OF_H_CELLS_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_reserved_future_use1, {
            "Reserved Future Use", "mpeg_descr.mosaic.reserved1",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_MOSAIC_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_number_of_vertical_elementary_cells, {
            "Number Of Vertical Elementary Cells", "mpeg_descr.mosaic.v_cells_num",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_mosaic_number_of_e_cells_vals),
            MPEG_DESCR_MOSAIC_NUM_OF_V_CELLS_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_logical_cell_id, {
            "Logical Cell ID", "mpeg_descr.mosaic.l_cell_id",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_MOSAIC_LOGICAL_CELL_ID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_reserved_future_use2, {
            "Reserved Future Use", "mpeg_descr.mosaic.reserved2",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_MOSAIC_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_logical_cell_presentation_info, {
            "Logical Cell Presentation Info", "mpeg_descr.mosaic.l_cell_pr_info",
            FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(mpeg_descr_mosaic_logical_cell_presentation_info_vals),
            MPEG_DESCR_MOSAIC_CELL_PRESENTATION_INFO_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_elementary_cell_field_length, {
            "Elementary Cell Field Length", "mpeg_descr.mosaic.e_cell_field_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_reserved_future_use3, {
            "Reserved Future Use", "mpeg_descr.mosaic.reserved3",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_MOSAIC_RESERVED3_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_elementary_cell_id, {
            "Elementary Cell ID", "mpeg_descr.mosaic.e_cell_id",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_MOSAIC_ELEMENTARY_CELL_ID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_cell_linkage_info, {
            "Cell Linkage Info", "mpeg_descr.mosaic.cell_link_info",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(mpeg_descr_mosaic_cell_linkage_info_vals), 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_bouquet_id, {
            "Bouquet ID", "mpeg_descr.mosaic.bouquet_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_original_network_id, {
            "Original Network ID", "mpeg_descr.mosaic.onid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_transport_stream_id, {
            "Transport Stream ID", "mpeg_descr.mosaic.tsid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_service_id, {
            "Service ID", "mpeg_descr.mosaic.sid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_mosaic_event_id, {
            "Event ID", "mpeg_descr.mosaic.event_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
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

        /* 0x57 Telephone Descriptor */
        { &hf_mpeg_descr_telephone_reserved_future_use1, {
            "Reserved Future Use", "mpeg_descr.phone.reserved1",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_TELEPHONE_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_foreign_availability, {
            "Foreign Availability", "mpeg_descr.phone.foreign",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_telephone_foreign_availability_vals),
            MPEG_DESCR_TELEPHONE_FOREIGN_AVAILABILITY_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_connection_type, {
            "Connection Type", "mpeg_descr.phone.conn_t",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(mpeg_descr_telephone_connection_type_vals),
            MPEG_DESCR_TELEPHONE_CONNECTION_TYPE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_reserved_future_use2, {
            "Reserved Future Use", "mpeg_descr.phone.reserved2",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_TELEPHONE_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_country_prefix_length, {
            "Country Prefix Length", "mpeg_descr.phone.nat_code_len",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_TELEPHONE_COUNTRY_PREFIX_LEN_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_international_area_code_length, {
            "International Area Code Length", "mpeg_descr.phone.int_code_len",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_TELEPHONE_INTERNATIONAL_CODE_LEN_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_operator_code_length, {
            "Operator Code Length", "mpeg_descr.phone.op_code_len",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_TELEPHONE_OPERATOR_CODE_LEN_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_reserved_future_use3, {
            "Reserved Future Use", "mpeg_descr.phone.reserved3",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_TELEPHONE_RESERVED3_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_national_area_code_length, {
            "National Area Code Length", "mpeg_descr.phone.nat_code_len",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_TELEPHONE_NATIONAL_CODE_LEN_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_core_number_length, {
            "Core Number Length", "mpeg_descr.phone.core_n_len",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_TELEPHONE_CORE_NUMBER_LEN_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_number, {
            "Telephone Number", "mpeg_descr.phone.number",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_country_prefix, {
            "Country Prefix", "mpeg_descr.phone.country",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_international_area_code, {
            "International Area Code", "mpeg_descr.phone.int_area",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_operator_code, {
            "Operator Code", "mpeg_descr.phone.operator",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_national_area_code, {
            "National Area Code", "mpeg_descr.phone.nat_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_telephone_core_number, {
            "Core Number", "mpeg_descr.phone.core",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
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

        /* 0x5B Multilingual Network Name Descriptor */
        { &hf_mpeg_descr_multilng_network_name_desc_iso639_language_code, {
            "Language ISO 639-2 Code", "mpeg_descr.net_name.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_network_name_desc_name_length, {
            "Network Name Length", "mpeg_descr.net_name.name_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_network_name_desc_name_encoding, {
            "Network Name Encoding", "mpeg_descr.net_name.name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_network_name_desc_name, {
            "Network Name", "mpeg_descr.net_name.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },


        /* 0x5C Multilingual Bouquet Name Descriptor */
        { &hf_mpeg_descr_multilng_bouquet_name_desc_iso639_language_code, {
            "Language ISO 639-2 Code", "mpeg_descr.bouquet_name.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_bouquet_name_desc_name_length, {
            "Bouquet Name Length", "mpeg_descr.bouquet_name.name_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_bouquet_name_desc_name_encoding, {
            "Bouquet Name Encoding", "mpeg_descr.bouquet_name.name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_bouquet_name_desc_name, {
            "Bouquet Name", "mpeg_descr.bouquet_name.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x5D Multilingual Service Name Descriptor */
        { &hf_mpeg_descr_multilng_srv_name_desc_iso639_language_code, {
            "Language ISO 639-2 Code", "mpeg_descr.svc.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_srv_name_desc_service_provider_name_length, {
            "Service Provider Name Length", "mpeg_descr.svc.provider_name_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_srv_name_desc_service_provider_name_encoding, {
            "Service Provider Name Encoding", "mpeg_descr.svc.provider_name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_srv_name_desc_service_provider_name, {
            "Service Provider Name", "mpeg_descr.svc.provider_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_srv_name_desc_service_name_length, {
            "Service Name Length", "mpeg_descr.svc.svc_name_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_srv_name_desc_service_name_encoding, {
            "Service Name Encoding", "mpeg_descr.svc.svn_name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_srv_name_desc_service_name, {
            "Service Name", "mpeg_descr.svc.svc_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x5E Multilingual Component Descriptor */
        { &hf_mpeg_descr_multilng_component_desc_tag, {
            "Component Tag", "mpeg_descr.component.tag",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_component_desc_iso639_language_code, {
            "Language ISO 639-2 Code", "mpeg_descr.component.lang_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_component_desc_text_length, {
            "Text Length", "mpeg_descr.component.text_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_component_desc_text_encoding, {
            "Text Encoding", "mpeg_descr.component.text_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_multilng_component_desc_text, {
            "Text", "mpeg_descr.component.text",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x5F Private Data Specifier */
        { &hf_mpeg_descr_private_data_specifier_id, {
            "Private Data Specifier", "mpeg_descr.private_data_specifier.id",
            FT_UINT32, BASE_HEX, VALS(mpeg_descr_data_specifier_id_vals), 0, NULL, HFILL
        } },

        /* 0x61 Short Smoothing Buffer Descriptor */
        { &hf_mpeg_descr_short_smoothing_buffer_sb_size, {
            "SB Size", "mpeg_descr.ssb.sb_size",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ssb_sb_size_vals),
            MPEG_DESCR_SHORT_SMOOTHING_BUFFER_SB_SIZE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_smoothing_buffer_sb_leak_rate, {
            "SB Leak Rate", "mpeg_descr.ssb.sb_leak_rate",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ssb_sb_leak_rate_vals),
            MPEG_DESCR_SHORT_SMOOTHING_BUFFER_SB_LEAK_RATE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_short_smoothing_buffer_dvb_reserved, {
            "DVB Reserved", "mpeg_descr.ssb.dvb_reserved",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x63 Partial Transport Stream Descriptor */
        { &hf_mpeg_descr_partial_transport_stream_reserved_future_use1, {
            "Reserved", "mpeg_descr.partial_transport_stream.reserved_future_use1",
            FT_UINT24, BASE_HEX, NULL, PARTIAL_TRANSPORT_STREAM_DESCR_RESERVED_FUTURE_USE1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_partial_transport_stream_peak_rate, {
            "Peak Rate", "mpeg_descr.partial_transport_stream.peak_rate",
            FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_partial_transport_stream_reserved_future_use2, {
            "Reserved", "mpeg_descr.partial_transport_stream.reserved_future_use2",
            FT_UINT24, BASE_HEX, NULL, PARTIAL_TRANSPORT_STREAM_DESCR_RESERVED_FUTURE_USE2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_partial_transport_stream_minimum_overall_smoothing_rate, {
            "Minimum Overall Smoothing Rate", "mpeg_descr.partial_transport_stream.minimum_overall_smoothing_rate",
            FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_partial_transport_stream_reserved_future_use3, {
            "Reserved", "mpeg_descr.partial_transport_stream.reserved_future_use3",
            FT_UINT16, BASE_HEX, NULL, PARTIAL_TRANSPORT_STREAM_DESCR_RESERVED_FUTURE_USE3_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_partial_transport_stream_maximum_overall_smoothing_buffer, {
            "Maximum Overall Smoothing Buffer", "mpeg_descr.partial_transport_stream.maximum_overall_smoothing_buffer",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
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

        /* 0x69 PDC Descriptor */
        { &hf_mpeg_descr_pdc_reserved, {
            "Reserved Future Use", "mpeg_descr.pdc.reserved",
            FT_UINT24, BASE_HEX, NULL, MPEG_DESCR_PDC_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_pdc_pil, {
            "Program Identification Label (PIL)", "mpeg_descr.pdc.pil",
            FT_UINT24, BASE_HEX, NULL, MPEG_DESCR_PDC_PIL_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_pdc_day, {
            "Day", "mpeg_descr.pdc.day",
            FT_UINT24, BASE_DEC, NULL, MPEG_DESCR_PDC_DAY_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_pdc_month, {
            "Month", "mpeg_descr.pdc.month",
            FT_UINT24, BASE_DEC, NULL, MPEG_DESCR_PDC_MONTH_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_pdc_hour, {
            "Hour", "mpeg_descr.pdc.hour",
            FT_UINT24, BASE_DEC, NULL, MPEG_DESCR_PDC_HOUR_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_pdc_minute, {
            "Minute", "mpeg_descr.pdc.minute",
            FT_UINT24, BASE_DEC, NULL, MPEG_DESCR_PDC_MINUTE_MASK, NULL, HFILL
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

        /* 0x71 Service Identifier Descriptor */
        { &hf_mpeg_descr_service_identifier, {
            "Service Textual Identifier", "mpeg_descr.sid.txt_identifier",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x72 Service Availability Descriptor */
        { &hf_mpeg_descr_service_availability_flag, {
            "Availability Flag", "mpeg_descr.srv_avail.flag",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_srv_avail_flag_vals),
            MPEG_DESCR_SRV_AVAIL_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_availability_reserved, {
            "Reserved", "mpeg_descr.srv_avail.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_SRV_AVAIL_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_service_availability_cell_id, {
            "Cell ID", "mpeg_descr.srv_avail.cid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        /* 0x73 Default Authority Descriptor */
        { &hf_mpeg_descr_default_authority_name, {
            "Default Authority Name", "mpeg_descr.default_authority.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        /* 0x75 TVA ID Descriptor */
        { &hf_mpeg_descr_tva_id, {
            "TVA ID", "mpeg_descr.tva.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_tva_reserved, {
            "Reserved", "mpeg_descr.tva.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_TVA_RESREVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_tva_running_status, {
            "Running Status", "mpeg_descr.tva.status",
            FT_UINT8, BASE_DEC, VALS(mpeg_descr_tva_running_status_vals),
            MPEG_DESCR_TVA_RUNNING_STATUS_MASK, NULL, HFILL
        } },

        /* 0x76 Content Identifier Descriptor */
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

        /* 0x7D XAIT Content Location Descriptor */
        { &hf_mpeg_descr_xait_onid, {
            "Original Network ID", "mpeg_descr.xait.onid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_xait_sid, {
            "Service ID", "mpeg_descr.xait.sid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_xait_version_number, {
            "Version Number", "mpeg_descr.xait.version",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_XAIT_VERSION_NUM_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_xait_update_policy, {
            "Update Policy", "mpeg_descr.xait.update_policy",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(mpeg_descr_xait_update_policy_vals),
            MPEG_DESCR_XAIT_UPDATE_POLICY_MASK, NULL, HFILL
        } },

        /* 0x7E FTA Content Management Descriptor */
        { &hf_mpeg_descr_fta_user_defined, {
            "User Defined", "mpeg_descr.fta.user_defined",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_FTA_USER_DEFINED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_fta_reserved_future_use, {
            "Reserved Future Use", "mpeg_descr.fta.reserved",
            FT_UINT8, BASE_HEX, NULL, MPEG_DESCR_FTA_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_fta_do_not_scramble, {
            "Do Not Scramble Flag", "mpeg_descr.fta.scramble",
            FT_BOOLEAN, 8, TFS(&tfs_fta_do_not_scramble), MPEG_DESCR_FTA_DO_NOT_SCRAMBLE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_fta_control_remote_access_over_internet, {
            "Control Remote Access Over Internet", "mpeg_descr.fta.remote",
            FT_UINT8, BASE_HEX, VALS(fta_control_remote_access_over_internet_vals),
            MPEG_DESCR_FTA_REMOTE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_fta_do_not_apply_revocation, {
            "Do Not Apply Revocation Flag", "mpeg_descr.fta.revocation",
            FT_BOOLEAN, 8, TFS(&tfs_fta_do_not_apply_revocation), MPEG_DESCR_FTA_REVOCATION_MASK, NULL, HFILL
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

        /* 0x81 ATSC A/52 AC-3 Descriptor */
        { &hf_mpeg_descr_ac3_sysa_srate, {
            "Sample Rate", "mpeg_descr.ac3.sysa_sample_rate",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_sysa_srate_flag_vals),
            MPEG_DESCR_AC3_SYSA_SRATE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_bsid, {
            "bsid", "mpeg_descr.ac3.sysa_bsid",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_BSID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_bitrate_limit, {
            "Bitrate Code limit type", "mpeg_descr.ac3.sysa_bitrate_code_limit",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_sysa_bitrate_code_limit_vals),
            MPEG_DESCR_AC3_SYSA_BITRATE_CODE_LIMIT_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_bitrate, {
            "Bitrate Code", "mpeg_descr.ac3.sysa_bitrate_code",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_sysa_bitrate_code_vals),
            MPEG_DESCR_AC3_SYSA_BITRATE_CODE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_surround, {
            "Surround Mode", "mpeg_descr.ac3.sysa_surround_mode",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_sysa_surround_mode_vals),
            MPEG_DESCR_AC3_SYSA_SURROUND_MODE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_bsmod, {
            "Bsmod", "mpeg_descr.ac3.sysa_bsmod",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_BSMOD_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_num_channels, {
            "Number of Channels", "mpeg_descr.ac3.sysa_num_channels",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_sysa_num_channels_vals),
            MPEG_DESCR_AC3_SYSA_NUM_CHANNELS_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_full_svc, {
            "Full Service", "mpeg_descr.ac3.sysa_full_svc",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_FULL_SVC_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_langcode, {
            "Language Code (Deprecated)", "mpeg_descr.ac3.sysa_langcode",
            FT_UINT8, BASE_HEX, NULL,  0x0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_langcode2, {
            "Language Code 2 (Deprecated)", "mpeg_descr.ac3.sysa_langcode2",
            FT_UINT8, BASE_HEX, NULL,  0x0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_mainid, {
            "Main ID", "mpeg_descr.ac3.sysa_mainid",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_MAINID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_priority, {
            "Priority", "mpeg_descr.ac3.sysa_priority",
            FT_UINT8, BASE_HEX, VALS(mpeg_descr_ac3_sysa_priority_vals),
            MPEG_DESCR_AC3_SYSA_PRIORITY_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_reserved, {
            "Reserved", "mpeg_descr.ac3.sysa_reserved",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_asvcflags, {
            "Associated Service Flags", "mpeg_descr.ac3.sysa_asvcflags",
            FT_UINT8, BASE_HEX, NULL,  0xff, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_textlen, {
            "Text length", "mpeg_descr.ac3.sysa_textlen",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_TEXTLEN_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_textcode, {
            "Text Code", "mpeg_descr.ac3.sysa_textcode",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_TEXTCODE_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_lang1, {
            "Language 1 Present", "mpeg_descr.ac3.sysa_lang1",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_LANG1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_lang2, {
            "Language 2 Present", "mpeg_descr.ac3.sysa_lang2",
            FT_UINT8, BASE_HEX, NULL,  MPEG_DESCR_AC3_SYSA_LANG2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_lang1_bytes, {
            "Language 1 ISO 639 language code", "mpeg_descr.ac3.sysa_lang1_bytes",
            FT_STRING, BASE_NONE, NULL,  0, NULL, HFILL
        } },

        { &hf_mpeg_descr_ac3_sysa_lang2_bytes, {
            "Language 2 ISO 639 language code", "mpeg_descr.ac3.sysa_lang2_bytes",
            FT_STRING, BASE_NONE, NULL,  0, NULL, HFILL
        } },

        /* 0x83 NorDig Logical Channel Descriptor (version 1) */
        { &hf_mpeg_descr_nordig_lcd_v1_service_list_id, {
            "Service ID", "mpeg_descr.nordig.lcd.svc_list.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v1_service_list_visible_service_flag, {
            "Visible", "mpeg_descr.nordig.lcd.svc_list.visible",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_NORDIG_LCD_V1_VISIBLE_SERVICE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v1_service_list_reserved, {
            "Reserved", "mpeg_descr.nordig.lcd.svc_list.reserved",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_NORDIG_LCD_V1_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v1_service_list_logical_channel_number, {
            "Logical Channel Number", "mpeg_descr.nordig.lcd.svc_list.lcn",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_NORDIG_LCD_V1_LCN_MASK, NULL, HFILL
        } },

        /* 0x87 NorDig Logical Channel Descriptor (version 2) */
        { &hf_mpeg_descr_nordig_lcd_v2_channel_list_id, {
            "Channel List ID", "mpeg_descr.nordig.lcd.ch_list.id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_channel_list_name_length, {
            "Channel List Name Length", "mpeg_descr.nordig.lcd.ch_list.name_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_channel_list_name_encoding, {
            "Channel List Name Encoding", "mpeg_descr.nordig.lcd.ch_list.name_enc",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_channel_list_name, {
            "Channel List Name", "mpeg_descr.nordig.lcd.ch_list.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_country_code, {
            "Country Code", "mpeg_descr.nordig.lcd.country_code",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_descriptor_length, {
            "Descriptor Length", "mpeg_descr.nordig.lcd.ch_list.descriptor_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_service_id, {
            "Service ID", "mpeg_descr.nordig.lcd.svc_list.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_visible_service_flag, {
            "Visible", "mpeg_descr.nordig.lcd.svc_list.visible",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_NORDIG_LCD_V2_VISIBLE_SERVICE_FLAG_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_reserved, {
            "Reserved", "mpeg_descr.nordig.lcd.svc_list.reserved",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_NORDIG_LCD_V2_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_nordig_lcd_v2_logical_channel_number, {
            "Logical Channel Number", "mpeg_descr.nordig.lcd.svc_list.lcn",
            FT_UINT16, BASE_HEX, NULL, MPEG_DESCR_NORDIG_LCD_V2_LCN_MASK, NULL, HFILL
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
            "Capacity Type Flag Reserved", "mpeg_descr.logon_init.capacity_type_flag_reserved",
            FT_UINT8, BASE_DEC, NULL, MPEG_DESCR_LOGON_INITIALIZE_CAPACITY_TYPE_FLAG_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_mpeg_descr_logon_initialize_capacity_type_flag, {
            "Capacity Type Flag", "mpeg_descr.logon_init.capacity_type_flag",
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

    static int *ett[] = {
        &ett_mpeg_descriptor,
        &ett_mpeg_descriptor_extended_event_item,
        &ett_mpeg_descriptor_component_content_type,
        &ett_mpeg_descriptor_content_nibble,
        &ett_mpeg_descriptor_multilng_network_name_desc_lng,
        &ett_mpeg_descriptor_multilng_bouquet_name_desc_lng,
        &ett_mpeg_descriptor_multilng_srv_name_desc_lng,
        &ett_mpeg_descriptor_multilng_component_desc_lng,
        &ett_mpeg_descriptor_country_availability_countries,
        &ett_mpeg_descriptor_nvod_reference_triplet,
        &ett_mpeg_descriptor_vbi_data_service,
        &ett_mpeg_descriptor_srv_avail_cells,
        &ett_mpeg_descriptor_tva,
        &ett_mpeg_descriptor_content_identifier_crid,
        &ett_mpeg_descriptor_mosaic_logical_cell,
        &ett_mpeg_descriptor_mosaic_elementary_cells,
        &ett_mpeg_descriptor_service_list,
        &ett_mpeg_descriptor_telephone_number,
        &ett_mpeg_descriptor_pdc_pil,
        &ett_mpeg_descriptor_nordig_lcd_v1_service_list,
        &ett_mpeg_descriptor_nordig_lcd_v2_channel_list_list,
        &ett_mpeg_descriptor_nordig_lcd_v2_service_list,
        &ett_mpeg_descriptor_ac3_component_type,
        &ett_mpeg_descriptor_linkage_population_id
    };

    proto_mpeg_descriptor = proto_register_protocol("MPEG2 Descriptors", "MPEG Descriptor", "mpeg_descr");
    proto_register_field_array(proto_mpeg_descriptor, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
