/* packet-btavdtp.c
 * Routines for Bluetooth AVDTP dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/wmem/wmem.h>
#include <wiretap/wtap.h>

#include "packet-btl2cap.h"
#include "packet-btsdp.h"
#include "packet-btavdtp.h"
#include "packet-rtp.h"

#define AVDTP_MESSAGE_TYPE_MASK  0x03
#define AVDTP_PACKET_TYPE_MASK   0x0C
#define AVDTP_TRANSACTION_MASK   0xF0
#define AVDTP_SIGNAL_ID_MASK     0x3F
#define AVDTP_RFA0_MASK          0xC0

#define MESSAGE_TYPE_COMMAND          0x00
#define MESSAGE_TYPE_GENERAL_REJECT   0x01
#define MESSAGE_TYPE_ACCEPT           0x02
#define MESSAGE_TYPE_REJECT           0x03

#define PACKET_TYPE_SINGLE            0x00
#define PACKET_TYPE_START             0x01
#define PACKET_TYPE_CONTINUE          0x02
#define PACKET_TYPE_END               0x03

#define SIGNAL_ID_DISCOVER                  0x01
#define SIGNAL_ID_GET_CAPABILITIES          0x02
#define SIGNAL_ID_SET_CONFIGURATION         0x03
#define SIGNAL_ID_GET_CONFIGURATION         0x04
#define SIGNAL_ID_RECONFIGURE               0x05
#define SIGNAL_ID_OPEN                      0x06
#define SIGNAL_ID_START                     0x07
#define SIGNAL_ID_CLOSE                     0x08
#define SIGNAL_ID_SUSPEND                   0x09
#define SIGNAL_ID_ABORT                     0x0A
#define SIGNAL_ID_SECURITY_CONTROL          0x0B
#define SIGNAL_ID_GET_ALL_CAPABILITIES      0x0C
#define SIGNAL_ID_DELAY_REPORT              0x0D

#define SERVICE_CATEGORY_MEDIA_TRANSPORT     0x01
#define SERVICE_CATEGORY_REPORTING           0x02
#define SERVICE_CATEGORY_RECOVERY            0x03
#define SERVICE_CATEGORY_CONTENT_PROTECTION  0x04
#define SERVICE_CATEGORY_HEADER_COMPRESSION  0x05
#define SERVICE_CATEGORY_MULTIPLEXING        0x06
#define SERVICE_CATEGORY_MEDIA_CODEC         0x07
#define SERVICE_CATEGORY_DELAY_REPORTING     0x08

#define MEDIA_TYPE_AUDIO   0x00
#define MEDIA_TYPE_VIDEO   0x01

#define SEID_ACP     0x00
#define SEID_INT     0x01

#define STREAM_TYPE_MEDIA   0x00
#define STREAM_TYPE_SIGNAL  0x01

#define CODEC_DEFAULT         0xFFFF
#define CODEC_SBC             0x00
#define CODEC_MPEG12_AUDIO    0x01
#define CODEC_MPEG24_AAC      0x02
#define CODEC_ATRAC           0x04

#define CODEC_H263_BASELINE   0x01
#define CODEC_MPEG4_VSP       0x02
#define CODEC_H263_PROFILE_3  0x03
#define CODEC_H263_PROFILE_8  0x04

#define CODEC_VENDOR          0xFF

#define HEADER_SIZE  2
#define SEP_MAX     64
#define SEP_SIZE     2

/* ========================================================== */
/* Story: RTP Player, conversation (probably reassemble too) use address:port as
   "key" to separate devices/streams. In Bluetooth World it is not enough to
   separate devices/streams. Example key:
        guint32 interface_id (aka frame.interface_id)
        guint32 adapter_id (interface like "bluetooth-monitor" or USB provide
                            more than one device over interface, so we must
                            separate information provided by each one)
        guint16 hci_chandle (aka "connection handle" use to separate connections to devices)
        guint16 l2cap_psm (like hci_chandle but over l2cap layer, need hci_chandle info because
                           the same PSM can be used over chandles)
        guint8 rfcomm_channel (like l2cap_psm, but over RFCOMM layer...)
        etc. like
        guint8  stram_endpoint_number
        guint32 stream_number (to separate multiple streams for RTP Player)

    So keys can be various (length or type) and "ports" are not enough to sore
    all needed information. If one day that changed then all RTP_PLAYER_WORKAROUND
    block can be removed. This workaround use global number of streams (aka stream ID)
    to be used as port number in RTP Player to separate streams.
        */
#define RTP_PLAYER_WORKAROUND TRUE

#if RTP_PLAYER_WORKAROUND == TRUE
    wmem_tree_t *file_scope_stream_number = NULL;
#endif
/* ========================================================== */

static int proto_btavdtp = -1;

static int hf_btavdtp_data                                                 = -1;
static int hf_btavdtp_message_type                                         = -1;
static int hf_btavdtp_packet_type                                          = -1;
static int hf_btavdtp_transaction                                          = -1;
static int hf_btavdtp_signal                                               = -1;
static int hf_btavdtp_signal_id                                            = -1;
static int hf_btavdtp_rfa0                                                 = -1;
static int hf_btavdtp_number_of_signal_packets                             = -1;
static int hf_btavdtp_sep_seid                                             = -1;
static int hf_btavdtp_sep_inuse                                            = -1;
static int hf_btavdtp_sep_rfa0                                             = -1;
static int hf_btavdtp_sep_media_type                                       = -1;
static int hf_btavdtp_sep_type                                             = -1;
static int hf_btavdtp_sep_rfa1                                             = -1;
static int hf_btavdtp_error_code                                           = -1;
static int hf_btavdtp_acp_sep                                              = -1;
static int hf_btavdtp_acp_seid_item                                        = -1;
static int hf_btavdtp_int_seid_item                                        = -1;
static int hf_btavdtp_acp_seid                                             = -1;
static int hf_btavdtp_int_seid                                             = -1;
static int hf_btavdtp_service_category                                     = -1;
static int hf_btavdtp_rfa_seid                                             = -1;
static int hf_btavdtp_delay                                                = -1;
static int hf_btavdtp_length_of_service_category                           = -1;
static int hf_btavdtp_recovery_type                                        = -1;
static int hf_btavdtp_maximum_recovery_window_size                         = -1;
static int hf_btavdtp_maximum_number_of_media_packet_in_parity_code        = -1;
static int hf_btavdtp_multiplexing_fragmentation                           = -1;
static int hf_btavdtp_multiplexing_rfa                                     = -1;
static int hf_btavdtp_multiplexing_tsid                                    = -1;
static int hf_btavdtp_multiplexing_tcid                                    = -1;
static int hf_btavdtp_multiplexing_entry_rfa                               = -1;
static int hf_btavdtp_header_compression_backch                            = -1;
static int hf_btavdtp_header_compression_media                             = -1;
static int hf_btavdtp_header_compression_recovery                          = -1;
static int hf_btavdtp_header_compression_rfa                               = -1;
static int hf_btavdtp_content_protection_type                              = -1;
static int hf_btavdtp_media_codec_media_type                               = -1;
static int hf_btavdtp_media_codec_rfa                                      = -1;
static int hf_btavdtp_media_codec_unknown_type                             = -1;
static int hf_btavdtp_media_codec_audio_type                               = -1;
static int hf_btavdtp_media_codec_video_type                               = -1;
static int hf_btavdtp_sbc_sampling_frequency_16000                         = -1;
static int hf_btavdtp_sbc_sampling_frequency_32000                         = -1;
static int hf_btavdtp_sbc_sampling_frequency_44100                         = -1;
static int hf_btavdtp_sbc_sampling_frequency_48000                         = -1;
static int hf_btavdtp_sbc_channel_mode_mono                                = -1;
static int hf_btavdtp_sbc_channel_mode_dual_channel                        = -1;
static int hf_btavdtp_sbc_channel_mode_stereo                              = -1;
static int hf_btavdtp_sbc_channel_mode_joint_stereo                        = -1;
static int hf_btavdtp_sbc_block_4                                          = -1;
static int hf_btavdtp_sbc_block_8                                          = -1;
static int hf_btavdtp_sbc_block_12                                         = -1;
static int hf_btavdtp_sbc_block_16                                         = -1;
static int hf_btavdtp_sbc_subbands_4                                       = -1;
static int hf_btavdtp_sbc_subbands_8                                       = -1;
static int hf_btavdtp_sbc_allocation_method_snr                            = -1;
static int hf_btavdtp_sbc_allocation_method_loudness                       = -1;
static int hf_btavdtp_sbc_min_bitpool                                      = -1;
static int hf_btavdtp_sbc_max_bitpool                                      = -1;
static int hf_btavdtp_mpeg12_layer_1                                       = -1;
static int hf_btavdtp_mpeg12_layer_2                                       = -1;
static int hf_btavdtp_mpeg12_layer_3                                       = -1;
static int hf_btavdtp_mpeg12_crc_protection                                = -1;
static int hf_btavdtp_mpeg12_channel_mode_mono                             = -1;
static int hf_btavdtp_mpeg12_channel_mode_dual_channel                     = -1;
static int hf_btavdtp_mpeg12_channel_mode_stereo                           = -1;
static int hf_btavdtp_mpeg12_channel_mode_joint_stereo                     = -1;
static int hf_btavdtp_mpeg12_rfa                                           = -1;
static int hf_btavdtp_mpeg12_mpf_2                                         = -1;
static int hf_btavdtp_mpeg12_sampling_frequency_16000                      = -1;
static int hf_btavdtp_mpeg12_sampling_frequency_22050                      = -1;
static int hf_btavdtp_mpeg12_sampling_frequency_24000                      = -1;
static int hf_btavdtp_mpeg12_sampling_frequency_32000                      = -1;
static int hf_btavdtp_mpeg12_sampling_frequency_44100                      = -1;
static int hf_btavdtp_mpeg12_sampling_frequency_48000                      = -1;
static int hf_btavdtp_mpeg12_vbr_supported                                 = -1;
static int hf_btavdtp_mpeg12_bit_rate                                      = -1;
static int hf_btavdtp_mpeg24_object_type_mpeg2_aac_lc                      = -1;
static int hf_btavdtp_mpeg24_object_type_mpeg4_aac_lc                      = -1;
static int hf_btavdtp_mpeg24_object_type_mpeg4_aac_ltp                     = -1;
static int hf_btavdtp_mpeg24_object_type_mpeg4_aac_scalable                = -1;
static int hf_btavdtp_mpeg24_object_type_rfa                               = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_8000                       = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_11025                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_12000                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_16000                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_22050                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_24000                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_32000                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_44100                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_48000                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_64000                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_88200                      = -1;
static int hf_btavdtp_mpeg24_sampling_frequency_96000                      = -1;
static int hf_btavdtp_mpeg24_channels_1                                    = -1;
static int hf_btavdtp_mpeg24_channels_2                                    = -1;
static int hf_btavdtp_mpeg24_rfa                                           = -1;
static int hf_btavdtp_mpeg24_vbr_supported                                 = -1;
static int hf_btavdtp_mpeg24_bit_rate                                      = -1;
static int hf_btavdtp_atrac_version                                        = -1;
static int hf_btavdtp_atrac_channel_mode_single_channel                    = -1;
static int hf_btavdtp_atrac_channel_mode_dual_channel                      = -1;
static int hf_btavdtp_atrac_channel_mode_joint_stereo                      = -1;
static int hf_btavdtp_atrac_rfa1                                           = -1;
static int hf_btavdtp_atrac_rfa2                                           = -1;
static int hf_btavdtp_atrac_sampling_frequency_44100                       = -1;
static int hf_btavdtp_atrac_sampling_frequency_48000                       = -1;
static int hf_btavdtp_atrac_vbr_supported                                  = -1;
static int hf_btavdtp_atrac_bit_rate                                       = -1;
static int hf_btavdtp_atrac_maximum_sul                                    = -1;
static int hf_btavdtp_atrac_rfa3                                           = -1;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_16000        = -1;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_32000        = -1;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_44100        = -1;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_48000        = -1;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_mono               = -1;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_dual_channel       = -1;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_stereo             = -1;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_joint_stereo       = -1;
static int hf_btavdtp_h263_level_10                                        = -1;
static int hf_btavdtp_h263_level_20                                        = -1;
static int hf_btavdtp_h263_level_30                                        = -1;
static int hf_btavdtp_h263_level_rfa                                       = -1;
static int hf_btavdtp_mpeg4_level_0                                        = -1;
static int hf_btavdtp_mpeg4_level_1                                        = -1;
static int hf_btavdtp_mpeg4_level_2                                        = -1;
static int hf_btavdtp_mpeg4_level_3                                        = -1;
static int hf_btavdtp_mpeg4_level_rfa                                      = -1;
static int hf_btavdtp_vendor_id                                            = -1;
static int hf_btavdtp_vendor_specific_codec_id                             = -1;
static int hf_btavdtp_vendor_specific_value                                = -1;
static int hf_btavdtp_vendor_specific_apt_codec_id                         = -1;
static int hf_btavdtp_capabilities                                         = -1;
static int hf_btavdtp_service                                              = -1;
static int hf_btavdtp_service_multiplexing_entry                           = -1;

static gint ett_btavdtp               = -1;
static gint ett_btavdtp_sep           = -1;
static gint ett_btavdtp_capabilities  = -1;
static gint ett_btavdtp_service       = -1;

static expert_field ei_btavdtp_sbc_min_bitpool_out_of_range = EI_INIT;
static expert_field ei_btavdtp_sbc_max_bitpool_out_of_range = EI_INIT;
static expert_field ei_btavdtp_unexpected_losc_data = EI_INIT;

static dissector_handle_t btavdtp_handle;
static dissector_handle_t bta2dp_handle;
static dissector_handle_t btvdp_handle;
static dissector_handle_t rtp_handle;

static wmem_tree_t *channels             = NULL;
static wmem_tree_t *sep_list             = NULL;
static wmem_tree_t *sep_open             = NULL;
static wmem_tree_t *media_packet_times   = NULL;

/* A2DP declarations */
static gint proto_bta2dp                        = -1;
static gint ett_bta2dp                          = -1;
static gint proto_bta2dp_cph_scms_t             = -1;
static gint ett_bta2dp_cph_scms_t               = -1;

static int hf_bta2dp_acp_seid                           = -1;
static int hf_bta2dp_int_seid                           = -1;
static int hf_bta2dp_codec                              = -1;
static int hf_bta2dp_vendor_id                          = -1;
static int hf_bta2dp_vendor_codec_id                    = -1;
static int hf_bta2dp_content_protection                 = -1;
static int hf_bta2dp_stream_number                      = -1;
static int hf_bta2dp_l_bit                              = -1;
static int hf_bta2dp_cp_bit                             = -1;
static int hf_bta2dp_reserved                           = -1;

static dissector_handle_t sbc_handle;
static dissector_handle_t mp2t_handle;
static dissector_handle_t mpeg_audio_handle;
static dissector_handle_t atrac_handle;

static gboolean  force_a2dp_scms_t = FALSE;
static gint      force_a2dp_codec = CODEC_DEFAULT;

static const enum_val_t pref_a2dp_codec[] = {
    { "default",     "Default",      CODEC_DEFAULT },
    { "sbc",         "SBC",          CODEC_SBC },
    { "mp2t",        "MPEG12 AUDIO", CODEC_MPEG12_AUDIO },
    { "mpeg-audio",  "MPEG24 AAC",   CODEC_MPEG24_AAC },
/* XXX: Not supported in Wireshark yet  { "atrac",      "ATRAC",                                  CODEC_ATRAC },*/
    { NULL, NULL, 0 }
};


/* VDP declarations */
static gint proto_btvdp                         = -1;
static gint ett_btvdp                           = -1;
static gint proto_btvdp_cph_scms_t              = -1;
static gint ett_btvdp_cph_scms_t                = -1;

static int hf_btvdp_acp_seid                           = -1;
static int hf_btvdp_int_seid                           = -1;
static int hf_btvdp_codec                              = -1;
static int hf_btvdp_content_protection                 = -1;
static int hf_btvdp_l_bit                              = -1;
static int hf_btvdp_cp_bit                             = -1;
static int hf_btvdp_reserved                           = -1;

static dissector_handle_t h263_handle;
static dissector_handle_t mp4v_es_handle;

static gboolean  force_vdp_scms_t = FALSE;
static gint      force_vdp_codec = CODEC_H263_BASELINE;

static const enum_val_t pref_vdp_codec[] = {
    { "h263",    "H263",      CODEC_H263_BASELINE },
    { "mp4v-es", "MPEG4 VSP", CODEC_MPEG4_VSP },
    { NULL, NULL, 0 }
};

/* APT-X Codec */
static int  proto_aptx                            = -1;
static int  hf_aptx_data                          = -1;
static int  hf_aptx_cummulative_frame_duration    = -1;
static int  hf_aptx_delta_time                    = -1;
static int  hf_aptx_delta_time_from_the_beginning = -1;
static int  hf_aptx_cummulative_duration          = -1;
static int  hf_aptx_diff                          = -1;
static gint ett_aptx                              = -1;
static dissector_handle_t aptx_handle;


static const value_string message_type_vals[] = {
    { 0x00,  "Command" },
    { 0x01,  "GeneralReject" },
    { 0x02,  "ResponseAccept" },
    { 0x03,  "ResponseReject" },
    { 0, NULL }
};

static const value_string packet_type_vals[] = {
    { 0x00,  "Single" },
    { 0x01,  "Start" },
    { 0x02,  "Continue" },
    { 0x03,  "End" },
    { 0, NULL }
};

static const value_string signal_id_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Discover" },
    { 0x02, "GetCapabilities" },
    { 0x03, "SetConfiguration" },
    { 0x04, "GetConfiguration" },
    { 0x05, "Reconfigure" },
    { 0x06, "Open" },
    { 0x07, "Start" },
    { 0x08, "Close" },
    { 0x09, "Suspend" },
    { 0x0A, "Abort" },
    { 0x0B, "SecurityControl" },
    { 0x0C, "GetAllCapabilities" },
    { 0x0D, "DelayReport" },
    { 0, NULL }
};

static const value_string media_type_vals[] = {
    { 0x00,  "Audio" },
    { 0x01,  "Video" },
    { 0x02,  "Multimedia" },
    { 0, NULL }
};

static const value_string sep_type_vals[] = {
    { 0x00,  "Source" },
    { 0x01,  "Sink" },
    { 0, NULL }
};

static const value_string true_false[] = {
    { 0x00,  "False" },
    { 0x01,  "True" },
    { 0, NULL }
};

static const value_string error_code_vals[] = {
    /* ACP to INT, Signal Response Header Error Codes */
    { 0x01,  "Bad Header Format" },
    /* ACP to INT, Signal Response Payload Format Error Codes */
    { 0x11,  "Bad Length" },
    { 0x12,  "Bad ACP SEID" },
    { 0x13,  "SEP In Use" },
    { 0x14,  "SEP Not In Use" },
    { 0x17,  "Bad Service Category" },
    { 0x18,  "Bad Payload Format" },
    { 0x19,  "Not Supported Command" },
    { 0x1A,  "Invalid Capabilities" },
    /* ACP to INT, Signal Response Transport Service Capabilities Error Codes */
    { 0x22,  "Bad Recovery Type" },
    { 0x23,  "Bad Media Transport Format" },
    { 0x25,  "Bad Recovery Format" },
    { 0x26,  "Bad Header Compression Format" },
    { 0x27,  "Bad Content Protection Format" },
    { 0x28,  "Bad Multiplexing Format" },
    { 0x29,  "Unsupported Configuration" },
    /* ACP to INT, Procedure Error Codes */
    { 0x31,  "Bad State" },
    { 0, NULL }
};

static const value_string service_category_vals[] = {
    { 0x01,  "Media Transport" },
    { 0x02,  "Reporting" },
    { 0x03,  "Recovery" },
    { 0x04,  "Content Protection" },
    { 0x05,  "Header Compression" },
    { 0x06,  "Multiplexing" },
    { 0x07,  "Media Codec" },
    { 0x08,  "Delay Reporting" },
    { 0, NULL }
};

static const value_string recovery_type_vals[] = {
    { 0x00,  "Forbidden" },
    { 0x01,  "RFC2733" },
    { 0, NULL }
};

static const value_string multiplexing_tsid_vals[] = {
    { 0x00,  "Used for TSID query" },
    { 0x1F,  "RFD" },
    { 0, NULL }
};

static const value_string multiplexing_tcid_vals[] = {
    { 0x00,  "Used for TCID query" },
    { 0x1F,  "RFD" },
    { 0, NULL }
};

static const value_string media_codec_audio_type_vals[] = {
    { 0x00,  "SBC" },
    { 0x01,  "MPEG-1,2 Audio" },
    { 0x02,  "MPEG-2,4 AAC" },
    { 0x04,  "ATRAC family" },
    { 0xFF,  "non-A2DP" },
    { 0, NULL }
};

static const value_string media_codec_video_type_vals[] = {
    { 0x01,  "H.263 baseline" },
    { 0x02,  "MPEG-4 Visual Simple Profile" },
    { 0x03,  "H.263 profile 3" },
    { 0x04,  "H.263 profile 8" },
    { 0xFF,  "non-VDP" },
    { 0, NULL }
};

static const value_string content_protection_type_vals[] = {
    { 0x01,  "DTCP" },
    { 0x02,  "SCMS-T" },
    { 0, NULL }
};

static const value_string vendor_apt_codec_vals[] = {
    { 0x0001,  "APT-X" },
    { 0, NULL }
};

extern value_string_ext bthci_evt_comp_id_ext;

enum sep_state {
    SEP_STATE_FREE,
    SEP_STATE_OPEN,
    SEP_STATE_IN_USE
};

typedef struct _sep_entry_t {
    guint8         seid;
    guint8         type;
    guint8         media_type;
    guint8         int_seid;
    gint           codec;
    guint32        vendor_id;
    guint16        vendor_codec;
    gint           content_protection_type;

    enum sep_state state;
} sep_entry_t;

typedef struct _sep_data_t {
    gint      codec;
    guint32   vendor_id;
    guint16   vendor_codec;
    guint8    acp_seid;
    guint8    int_seid;
    gint      content_protection_type;
    guint32   stream_number;
    media_packet_info_t  *previous_media_packet_info;
    media_packet_info_t  *current_media_packet_info;
} sep_data_t;

typedef struct _media_stream_number_value_t {
    guint32      stream_number;
} media_stream_number_value_t;

typedef struct _channels_info_t {
    guint32       control_local_cid;
    guint32       control_remote_cid;
    guint32       media_local_cid;
    guint32       media_remote_cid;
    wmem_tree_t  *stream_numbers;
    guint32       disconnect_in_frame;
    guint32      *l2cap_disconnect_in_frame;
    guint32      *hci_disconnect_in_frame;
    guint32      *adapter_disconnect_in_frame;
    sep_entry_t  *sep;
} channels_info_t;


void proto_register_btavdtp(void);
void proto_reg_handoff_btavdtp(void);
void proto_register_bta2dp(void);
void proto_reg_handoff_bta2dp(void);
void proto_register_bta2dp_content_protection_header_scms_t(void);
void proto_register_btvdp(void);
void proto_reg_handoff_btvdp(void);
void proto_register_btvdp_content_protection_header_scms_t(void);
void proto_register_aptx(void);


static const char *
get_sep_type(guint32 interface_id,
    guint32 adapter_id, guint32 chandle, guint32 direction, guint32 seid, guint32 frame_number)
{
    wmem_tree_key_t   key[6];
    wmem_tree_t      *subtree;
    sep_entry_t      *sep;

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &chandle;
    key[3].length = 1;
    key[3].key    = &direction;
    key[4].length = 1;
    key[4].key    = &seid;
    key[5].length = 0;
    key[5].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
    if (sep) {
        return val_to_str_const(sep->type, sep_type_vals, "unknown");
    }

    return "unknown";
}

static const char *
get_sep_media_type(guint32 interface_id,
    guint32 adapter_id, guint32 chandle, guint32 direction, guint32 seid, guint32 frame_number)
{
    wmem_tree_key_t   key[6];
    wmem_tree_t      *subtree;
    sep_entry_t      *sep;

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &chandle;
    key[3].length = 1;
    key[3].key    = &direction;
    key[4].length = 1;
    key[4].key    = &seid;
    key[5].length = 0;
    key[5].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
    if (sep) {
        return val_to_str_const(sep->media_type, media_type_vals, "unknown");
    }

    return "unknown";
}


static gint
dissect_sep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
    guint32 interface_id, guint32 adapter_id, guint32 chandle)
{
    proto_tree       *sep_tree;
    proto_item       *sep_item;
    guint            i_sep  = 1;
    guint            media_type;
    guint            type;
    guint            seid;
    guint            in_use;
    guint            items;
    guint32          direction;

    /* Reverse direction to avoid mass reversing it, because this is only case
       when SEP is provided in ACP role, otherwise INT frequently asking for it
    */
    direction = (pinfo->p2p_dir == P2P_DIR_SENT) ? P2P_DIR_RECV : P2P_DIR_SENT;
    items = tvb_length_remaining(tvb, offset) / 2;
    while (tvb_length_remaining(tvb, offset) > 0) {
        seid = tvb_get_guint8(tvb, offset);
        in_use = seid & 0x02;
        seid = seid >> 2;
        media_type = tvb_get_guint8(tvb, offset + 1) >> 4;
        type = (tvb_get_guint8(tvb, offset + 1) & 0x08) >> 3;
        sep_item = proto_tree_add_none_format(tree, hf_btavdtp_acp_sep, tvb, offset, 2, "ACP SEP [%u - %s %s] item %u/%u",
                seid, val_to_str_const(media_type, media_type_vals, "unknown"),
                val_to_str_const(type, sep_type_vals, "unknown"), i_sep, items);
        sep_tree = proto_item_add_subtree(sep_item, ett_btavdtp_sep);

        proto_tree_add_item(sep_tree, hf_btavdtp_sep_seid , tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_inuse, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_rfa0 , tvb, offset, 1, ENC_NA);
        offset+=1;

        proto_tree_add_item(sep_tree, hf_btavdtp_sep_media_type, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_type      , tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_rfa1      , tvb, offset, 1, ENC_NA);

        if (!pinfo->fd->flags.visited) {
            sep_entry_t     *sep_data;
            wmem_tree_key_t  key[7];
            guint32          frame_number = pinfo->fd->num;

            key[0].length = 1;
            key[0].key    = &interface_id;
            key[1].length = 1;
            key[1].key    = &adapter_id;
            key[2].length = 1;
            key[2].key    = &chandle;
            key[3].length = 1;
            key[3].key    = &direction;
            key[4].length = 1;
            key[4].key    = &seid;
            key[5].length = 1;
            key[5].key    = &frame_number;
            key[6].length = 0;
            key[6].key    = NULL;

            sep_data = wmem_new(wmem_file_scope(), sep_entry_t);
            sep_data->seid = seid;
            sep_data->type = type;
            sep_data->media_type = media_type;
            sep_data->int_seid = 0;
            sep_data->codec = -1;
            sep_data->content_protection_type = 0;
            if (in_use) {
                sep_data->state = SEP_STATE_IN_USE;
            } else {
                sep_data->state = SEP_STATE_FREE;
            }

            wmem_tree_insert32_array(sep_list, key, sep_data);
        }

        offset += 1;
        i_sep += 1;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " - items: %u", items);
    return offset;
}


static gint
dissect_codec(tvbuff_t *tvb, packet_info *pinfo, proto_item *service_item, proto_tree *tree, gint offset,
        guint losc, gint media_type, gint media_codec_type, guint32 *vendor_id, guint16 *vendor_codec)
{
    proto_item    *pitem;
    guint32        value;
    guint8        *value8 = (guint8 *) &value;

    switch(media_type) {
        case MEDIA_TYPE_AUDIO:
            switch(media_codec_type) {
                case CODEC_SBC:
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_16000, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_32000, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_44100, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_48000, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_mono, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_dual_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_stereo, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_joint_stereo, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_4, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_8, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_12, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_16, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_subbands_4, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_subbands_8, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_allocation_method_snr, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_allocation_method_loudness, tvb, offset + 1, 1, ENC_NA);

                    pitem = proto_tree_add_item(tree, hf_btavdtp_sbc_min_bitpool, tvb, offset + 2, 1, ENC_NA);
                    value = tvb_get_guint8(tvb, offset + 2);
                    if (value < 2 || value > 250) {
                        expert_add_info(pinfo, pitem, &ei_btavdtp_sbc_min_bitpool_out_of_range);
                    }

                    pitem = proto_tree_add_item(tree, hf_btavdtp_sbc_max_bitpool, tvb, offset + 3, 1, ENC_NA);
                    value = tvb_get_guint8(tvb, offset + 3);
                    if (value < 2 || value > 250) {
                        expert_add_info(pinfo, pitem, &ei_btavdtp_sbc_max_bitpool_out_of_range);
                    }

                    value = tvb_get_h_guint32(tvb, offset);
                    if (value) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s%s%s%s%s| %s%s%s%s%s| block: %s%s%s%s%s| subbands: %s%s%s| allocation: %s%s%s| bitpool: %u..%u)",
                            (value8[0] & 0x80) ? "16000 " : "",
                            (value8[0] & 0x40) ? "32000 " : "",
                            (value8[0] & 0x20) ? "44100 " : "",
                            (value8[0] & 0x10) ? "48000 " : "",
                            (value8[0] & 0xF0) ? "" : "not set ",
                            (value8[0] & 0x08) ? "Mono " : "",
                            (value8[0] & 0x04) ? "DualChannel " : "",
                            (value8[0] & 0x02) ? "Stereo " : "",
                            (value8[0] & 0x01) ? "JointStereo " : "",
                            (value8[0] & 0x0F) ? "" : "not set ",
                            (value8[1] & 0x80) ? "4 " : "",
                            (value8[1] & 0x40) ? "8 " : "",
                            (value8[1] & 0x20) ? "12 " : "",
                            (value8[1] & 0x10) ? "16 " : "",
                            (value8[1] & 0xF0) ? "" : "not set ",
                            (value8[1] & 0x08) ? "4 " : "",
                            (value8[1] & 0x04) ? "8 " : "",
                            (value8[1] & 0x0C) ? "" : "not set ",
                            (value8[1] & 0x02) ? "SNR " : "",
                            (value8[1] & 0x01) ? "Loudness " : "",
                            (value8[0] & 0x03) ? "" : "not set ",
                            value8[2],
                            value8[3]);

                        proto_item_append_text(service_item, " (%s%s%s%s%s| %s%s%s%s%s| block: %s%s%s%s%s| subbands: %s%s%s| allocation: %s%s%s| bitpool: %u..%u)",
                            (value8[0] & 0x80) ? "16000 " : "",
                            (value8[0] & 0x40) ? "32000 " : "",
                            (value8[0] & 0x20) ? "44100 " : "",
                            (value8[0] & 0x10) ? "48000 " : "",
                            (value8[0] & 0xF0) ? "" : "not set ",
                            (value8[0] & 0x08) ? "Mono " : "",
                            (value8[0] & 0x04) ? "DualChannel " : "",
                            (value8[0] & 0x02) ? "Stereo " : "",
                            (value8[0] & 0x01) ? "JointStereo " : "",
                            (value8[0] & 0x0F) ? "" : "not set ",
                            (value8[1] & 0x80) ? "4 " : "",
                            (value8[1] & 0x40) ? "8 " : "",
                            (value8[1] & 0x20) ? "12 " : "",
                            (value8[1] & 0x10) ? "16 " : "",
                            (value8[1] & 0xF0) ? "" : "not set ",
                            (value8[1] & 0x08) ? "4 " : "",
                            (value8[1] & 0x04) ? "8 " : "",
                            (value8[1] & 0x0C) ? "" : "not set ",
                            (value8[1] & 0x02) ? "SNR " : "",
                            (value8[1] & 0x01) ? "Loudness " : "",
                            (value8[0] & 0x03) ? "" : "not set ",
                            value8[2],
                            value8[3]);
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (none)");
                        proto_item_append_text(service_item, " (none)");
                    }

                    break;
                case CODEC_MPEG12_AUDIO:
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_layer_1, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_layer_2, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_layer_3, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_crc_protection, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_mono, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_dual_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_stereo, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_joint_stereo, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_rfa, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_mpf_2, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_16000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_22050, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_24000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_32000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_44100, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_48000, tvb, offset + 1, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_vbr_supported, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_bit_rate, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                    break;
                case CODEC_MPEG24_AAC:
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg2_aac_lc, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg4_aac_lc, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg4_aac_ltp, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg4_aac_scalable, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_rfa, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_8000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_11025, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_12000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_16000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_22050, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_24000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_32000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_44100, tvb, offset + 1, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_48000, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_64000, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_88200, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_96000, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_channels_1, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_channels_2, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_rfa, tvb, offset + 2, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_vbr_supported, tvb, offset + 3, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_bit_rate, tvb, offset + 3, 3, ENC_BIG_ENDIAN);
                    break;
                case CODEC_ATRAC:
                    proto_tree_add_item(tree, hf_btavdtp_atrac_version, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_channel_mode_single_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_channel_mode_dual_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_channel_mode_joint_stereo, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_rfa1, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_atrac_rfa2, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_sampling_frequency_44100, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_sampling_frequency_48000, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_vbr_supported, tvb, offset + 3, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_bit_rate, tvb, offset + 3, 3, ENC_BIG_ENDIAN);

                    proto_tree_add_item(tree, hf_btavdtp_atrac_maximum_sul, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

                    proto_tree_add_item(tree, hf_btavdtp_atrac_rfa3, tvb, offset + 6, 1, ENC_NA);
                    break;
                case CODEC_VENDOR: /* non-A2DP */
                    proto_tree_add_item(tree, hf_btavdtp_vendor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);

                    if (vendor_id)
                        *vendor_id = tvb_get_letohl(tvb, offset);

                    if (vendor_codec)
                        *vendor_codec = tvb_get_letohs(tvb, offset + 4);

                    switch (tvb_get_letohl(tvb, offset)) {
                        case 0x004F: /* APT Licensing Ltd. */
                            proto_tree_add_item(tree, hf_btavdtp_vendor_specific_apt_codec_id, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
                            value = tvb_get_letohs(tvb, offset + 4);

                            if (value == 0x0001) { /* APT-X Codec */
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_16000, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_32000, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_44100, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_48000, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_mono, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_dual_channel, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_stereo, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_joint_stereo, tvb, offset + 6, 1, ENC_NA);

                                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s -",
                                    val_to_str_const(value, vendor_apt_codec_vals, "unknown codec"));
                                proto_item_append_text(service_item, " (%s -",
                                    val_to_str_const(value, vendor_apt_codec_vals, "unknown codec"));

                                value = tvb_get_guint8(tvb, offset + 6);
                                if (value) {
                                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s%s%s%s,%s%s%s%s%s)",
                                        (value & 0x80) ? " 16000" : "",
                                        (value & 0x40) ? " 32000" : "",
                                        (value & 0x20) ? " 44100" : "",
                                        (value & 0x10) ? " 48000" : "",
                                        (value & 0xF0) ? "" : "not set ",
                                        (value & 0x08) ? " Mono" : "",
                                        (value & 0x04) ? " DualChannel" : "",
                                        (value & 0x02) ? " Stereo" : "",
                                        (value & 0x01) ? " JointStereo" : "",
                                        (value & 0x0F) ? "" : "not set ");

                                    proto_item_append_text(service_item, "%s%s%s%s%s,%s%s%s%s%s)",
                                        (value & 0x80) ? " 16000" : "",
                                        (value & 0x40) ? " 32000" : "",
                                        (value & 0x20) ? " 44100" : "",
                                        (value & 0x10) ? " 48000" : "",
                                        (value & 0xF0) ? "" : "not set ",
                                        (value & 0x08) ? " Mono" : "",
                                        (value & 0x04) ? " DualChannel" : "",
                                        (value & 0x02) ? " Stereo" : "",
                                        (value & 0x01) ? " JointStereo" : "",
                                        (value & 0x0F) ? "" : "not set ");
                                } else {
                                    col_append_fstr(pinfo->cinfo, COL_INFO, " none)");
                                    proto_item_append_text(service_item, " none)");
                                }
                            } else {
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_value, tvb, offset + 6, losc - 6, ENC_NA);
                            }
                            break;
                        default:
                            proto_tree_add_item(tree, hf_btavdtp_vendor_specific_codec_id, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(tree, hf_btavdtp_vendor_specific_value, tvb, offset + 6, losc - 6, ENC_NA);
                    }

                    break;
                default:
                    proto_tree_add_item(tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
            }
            break;
        case MEDIA_TYPE_VIDEO:
            switch(media_codec_type) {
                case CODEC_H263_BASELINE:
                case CODEC_H263_PROFILE_3:
                case CODEC_H263_PROFILE_8:
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_10, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_20, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_30, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_rfa, tvb, offset, 1, ENC_NA);
                    break;
                case CODEC_MPEG4_VSP:
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_0, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_1, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_2, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_3, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_rfa, tvb, offset, 1, ENC_NA);
                    break;
                case CODEC_VENDOR: /* non-VDP */
                    proto_tree_add_item(tree, hf_btavdtp_vendor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_codec_id, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_value, tvb, offset + 6, losc - 6, ENC_NA);
                    break;
                default:
                    proto_tree_add_item(tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
            }
            break;
        default:
            proto_tree_add_item(tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
    }

    offset += losc;

    return offset;
}


static gint
dissect_capabilities(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, gint offset, gint *codec,
        gint *content_protection_type, guint32 *vendor_id, guint16 *vendor_codec)
{
    proto_item  *pitem                                        = NULL;
    proto_item  *ptree                                        = NULL;
    proto_tree  *capabilities_tree;
    proto_item  *capabilities_item;
    proto_tree  *service_tree                                 = NULL;
    proto_item  *service_item                                 = NULL;
    gint        service_category                              = 0;
    gint        losc                                          = 0;
    gint        recovery_type                                 = 0;
    gint        maximum_recovery_window_size                  = 0;
    gint        maximum_number_of_media_packet_in_parity_code = 0;
    gint        media_type                                    = 0;
    gint        media_codec_type                              = 0;

    capabilities_item = proto_tree_add_item(tree, hf_btavdtp_capabilities, tvb, offset, tvb_length(tvb) - offset, ENC_NA);
    capabilities_tree = proto_item_add_subtree(capabilities_item, ett_btavdtp_capabilities);

    if (codec)
        *codec = -1;

    if (vendor_id)
        *vendor_id = 0x003F; /* Bluetooth SIG */

    if (vendor_codec)
        *vendor_codec = 0;

    while (tvb_length_remaining(tvb, offset) > 0) {
        service_category = tvb_get_guint8(tvb, offset);
        losc = tvb_get_guint8(tvb, offset + 1);
        service_item = proto_tree_add_none_format(capabilities_tree, hf_btavdtp_service, tvb, offset, 2 + losc, "Service: %s", val_to_str_const(service_category, service_category_vals, "RFD"));
        service_tree = proto_item_add_subtree(service_item, ett_btavdtp_service);

        proto_tree_add_item(service_tree, hf_btavdtp_service_category, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(service_tree, hf_btavdtp_length_of_service_category, tvb, offset, 1, ENC_NA);
        offset += 1;

        switch (service_category) {
            case SERVICE_CATEGORY_MEDIA_TRANSPORT:
            case SERVICE_CATEGORY_REPORTING:
            case SERVICE_CATEGORY_DELAY_REPORTING:
                /* losc should be 0 */
                break;
            case SERVICE_CATEGORY_RECOVERY:
                recovery_type = tvb_get_guint8(tvb, offset);
                pitem = proto_tree_add_item(service_tree, hf_btavdtp_recovery_type, tvb, offset, 1, ENC_NA);
                proto_item_append_text(pitem, " (%s)", val_to_str_const(recovery_type, recovery_type_vals, "RFD"));
                offset += 1;
                losc -= 1;

                maximum_recovery_window_size = tvb_get_guint8(tvb, offset);
                pitem = proto_tree_add_item(service_tree, hf_btavdtp_maximum_recovery_window_size, tvb, offset, 1, ENC_NA);
                if (maximum_recovery_window_size == 0x00) {
                    proto_item_append_text(pitem, " (Forbidden)");
                } else if (maximum_recovery_window_size >= 0x18) {
                    proto_item_append_text(pitem, " (Undocumented)");
                }
                offset += 1;
                losc -= 1;

                maximum_number_of_media_packet_in_parity_code = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(service_tree, hf_btavdtp_maximum_number_of_media_packet_in_parity_code, tvb, offset, 1, ENC_NA);
                pitem = proto_tree_add_item(service_tree, hf_btavdtp_maximum_recovery_window_size, tvb, offset, 1, ENC_NA);
                if (maximum_number_of_media_packet_in_parity_code == 0x00) {
                    proto_item_append_text(pitem, " (Forbidden)");
                } else if (maximum_number_of_media_packet_in_parity_code >= 0x18) {
                    proto_item_append_text(pitem, " (Undocumented)");
                }
                offset += 1;
                losc -= 1;
                break;
            case SERVICE_CATEGORY_MEDIA_CODEC:
                media_type = tvb_get_guint8(tvb, offset) >> 4;
                proto_tree_add_item(service_tree, hf_btavdtp_media_codec_media_type, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_media_codec_rfa , tvb, offset, 1, ENC_NA);
                offset += 1;
                losc -= 1;

                media_codec_type = tvb_get_guint8(tvb, offset);
                if (codec) {
                    *codec = media_codec_type;
                }

                if (media_type == MEDIA_TYPE_AUDIO) {
                    proto_tree_add_item(service_tree, hf_btavdtp_media_codec_audio_type, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(service_item, " - Audio %s",
                            val_to_str_const(media_codec_type, media_codec_audio_type_vals, "unknown codec"));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - Audio %s",
                            val_to_str_const(media_codec_type, media_codec_audio_type_vals, "unknown codec"));
                } else if (media_type == MEDIA_TYPE_VIDEO) {
                    proto_tree_add_item(service_tree, hf_btavdtp_media_codec_video_type, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(service_item, " - Video %s",
                            val_to_str_const(media_codec_type, media_codec_video_type_vals, "unknown codec"));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - Video %s",
                            val_to_str_const(media_codec_type, media_codec_video_type_vals, "unknown codec"));
                } else {
                    proto_tree_add_item(service_tree, hf_btavdtp_media_codec_unknown_type, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(service_item, " - Unknown 0x%02x", media_codec_type);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - Unknown 0x%02x", media_codec_type);
                }
                offset += 1;
                losc -= 1;

                offset = dissect_codec(tvb, pinfo, service_item, service_tree,
                        offset, losc, media_type, media_codec_type,
                        vendor_id, vendor_codec);
                losc = 0;
                break;
            case SERVICE_CATEGORY_CONTENT_PROTECTION:
                proto_tree_add_item(service_tree, hf_btavdtp_content_protection_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                if (content_protection_type) {
                    *content_protection_type = tvb_get_letohs(tvb, offset);
                }
                proto_item_append_text(service_item, " - %s",
                    val_to_str_const(tvb_get_letohs(tvb, offset), content_protection_type_vals, "unknown"));

                offset += 2;
                losc -= 2;

                if (losc > 0) {
                    proto_tree_add_item(service_tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
                    offset += losc;
                    losc = 0;
                }
                break;
            case SERVICE_CATEGORY_HEADER_COMPRESSION:
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_backch,   tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_media,    tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_recovery, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_rfa,      tvb, offset, 1, ENC_NA);
                offset += 1;
                losc -= 1;
                break;
            case SERVICE_CATEGORY_MULTIPLEXING:
                proto_tree_add_item(service_tree, hf_btavdtp_multiplexing_fragmentation, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_multiplexing_rfa, tvb, offset, 1, ENC_NA);
                offset += 1;
                losc -= 1;

                if (losc >= 2) {
                    pitem = proto_tree_add_none_format(service_tree, hf_btavdtp_service_multiplexing_entry, tvb, offset, 1 + losc, "Entry: Media Transport Session");
                    ptree = proto_item_add_subtree(pitem, ett_btavdtp_service);

                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tsid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tcid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                }

                if (losc >= 2) {
                    pitem = proto_tree_add_none_format(service_tree, hf_btavdtp_service_multiplexing_entry, tvb, offset, 1 + losc, "Entry: Reporting Transport Session");
                    ptree = proto_item_add_subtree(pitem, ett_btavdtp_service);

                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tsid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tcid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc  -= 1;
                }

                if (losc >= 2) {
                    pitem = proto_tree_add_none_format(service_tree, hf_btavdtp_service_multiplexing_entry, tvb, offset, 1 + losc, "Entry: Recovery Transport Session");
                    ptree = proto_item_add_subtree(pitem, ett_btavdtp_service);

                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tsid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tcid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                }
                break;
            default:
                proto_tree_add_item(service_tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
                offset += losc;
                losc = 0;
        }

        if (losc > 0) {
            pitem = proto_tree_add_item(service_tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
            offset += losc;

            expert_add_info(pinfo, pitem, &ei_btavdtp_unexpected_losc_data);
        }
    }

    return offset;
}

static gint
dissect_seid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
             gint seid_side, gint i_item, guint32 *sep_seid,
             guint32 interface_id, guint32 adapter_id, guint32 chandle,
             guint32 frame_number)
{
    guint32      seid;
    proto_tree  *seid_tree     = NULL;
    proto_item  *seid_item     = NULL;
    guint32      direction;

    seid = tvb_get_guint8(tvb, offset) >> 2;
    if (sep_seid) {
        *sep_seid = seid;
    }

    if (seid_side == SEID_ACP) {
        direction = pinfo->p2p_dir;
        seid_item = proto_tree_add_none_format(tree, hf_btavdtp_acp_seid_item, tvb, offset, 1,
                "ACP SEID [%u - %s %s]", seid,
                    get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                    get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
        seid_tree = proto_item_add_subtree(seid_item, ett_btavdtp_sep);
        proto_tree_add_item(seid_tree, hf_btavdtp_acp_seid, tvb, offset, 1, ENC_NA);
        if (i_item > 0) proto_item_append_text(seid_item, " item %u", i_item);

        col_append_fstr(pinfo->cinfo, COL_INFO, " - ACP SEID [%u - %s %s]",
                seid, get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
    } else {
        direction = (pinfo->p2p_dir == P2P_DIR_SENT) ? P2P_DIR_RECV : P2P_DIR_SENT;
        seid_item = proto_tree_add_none_format(tree, hf_btavdtp_int_seid_item, tvb, offset, 1,
                "INT SEID [%u - %s %s]", seid,
                    get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                    get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
        seid_tree = proto_item_add_subtree(seid_item, ett_btavdtp_sep);
        proto_tree_add_item(seid_tree, hf_btavdtp_int_seid, tvb, offset, 1, ENC_NA);
        if (i_item > 0) proto_item_append_text(seid_item, " item %u", i_item);

        col_append_fstr(pinfo->cinfo, COL_INFO, " - INT SEID [%u - %s %s]",
                seid, get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
    }

    proto_tree_add_item(seid_tree, hf_btavdtp_rfa_seid, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}


static gint
dissect_btavdtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *ti;
    proto_tree       *btavdtp_tree       = NULL;
    proto_tree       *signal_tree        = NULL;
    proto_item       *signal_item        = NULL;
    btl2cap_data_t   *l2cap_data;
    gint             offset = 0;
    gint             i_sep         = 1;
    gint             packet_type   = 0;
    gint             message_type  = 0;
    gint             signal_id     = 0;
    guint            delay;
    wmem_tree_t      *subtree;
    wmem_tree_key_t  key[8];
    channels_info_t  *channels_info;
    guint32          interface_id;
    guint32          adapter_id;
    guint32          chandle;
    guint32          psm;
    guint32          direction;
    guint32          cid;
    guint32          frame_number;
    sep_entry_t      *sep;
    tvbuff_t         *next_tvb;
    guint32          seid;
    gint             codec = -1;
    gint             content_protection_type = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AVDTP");

    direction = pinfo->p2p_dir;
    switch (direction) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;

        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                direction);
            goto LABEL_data;
            break;
    }

    l2cap_data = (btl2cap_data_t *) data;
    DISSECTOR_ASSERT(l2cap_data);

    interface_id = l2cap_data->interface_id;
    adapter_id = l2cap_data->adapter_id;
    chandle = l2cap_data->chandle;
    psm = l2cap_data->psm;
    cid = l2cap_data->cid;
    frame_number = pinfo->fd->num;

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &chandle;
    key[3].length = 1;
    key[3].key    = &psm;
    key[4].length = 0;
    key[4].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(channels, key);
    channels_info = (subtree) ? (channels_info_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
    if (!(channels_info &&
            *channels_info->adapter_disconnect_in_frame >= pinfo->fd->num &&
            *channels_info->hci_disconnect_in_frame >= pinfo->fd->num &&
            *channels_info->l2cap_disconnect_in_frame >= pinfo->fd->num &&
            channels_info->disconnect_in_frame >= pinfo->fd->num)) {

        channels_info = (channels_info_t *) wmem_new (wmem_file_scope(), channels_info_t);
        channels_info->control_local_cid = l2cap_data->local_cid;
        channels_info->control_remote_cid = l2cap_data->remote_cid;
        channels_info->media_local_cid = BTL2CAP_UNKNOWN_CID;
        channels_info->media_remote_cid = BTL2CAP_UNKNOWN_CID;
        channels_info->disconnect_in_frame = G_MAXUINT32;
        channels_info->l2cap_disconnect_in_frame   = l2cap_data->disconnect_in_frame;
        channels_info->hci_disconnect_in_frame     = l2cap_data->hci_disconnect_in_frame;
        channels_info->adapter_disconnect_in_frame = l2cap_data->adapter_disconnect_in_frame;
        channels_info->sep = NULL;

        if (!pinfo->fd->flags.visited) {
            key[4].length = 1;
            key[4].key    = &frame_number;
            key[5].length = 0;
            key[5].key    = NULL;

            channels_info->stream_numbers = wmem_tree_new(wmem_file_scope());
            wmem_tree_insert32_array(channels, key, channels_info);
        } else {
            channels_info->stream_numbers = NULL;
        }
    }

    if (!(l2cap_data->local_cid == channels_info->control_local_cid &&
            l2cap_data->remote_cid == channels_info->control_remote_cid) &&
            (channels_info->media_local_cid == BTL2CAP_UNKNOWN_CID ||
            (l2cap_data->local_cid == channels_info->media_local_cid &&
            l2cap_data->remote_cid == channels_info->media_remote_cid))) {

        if (!pinfo->fd->flags.visited && channels_info->media_local_cid == BTL2CAP_UNKNOWN_CID) {
            channels_info->media_local_cid = l2cap_data->local_cid;
            channels_info->media_remote_cid = l2cap_data->remote_cid;
        }
        /* Media Channel */

        if (!channels_info->sep) {
            ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
            btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Media stream on cid=0x%04x", l2cap_data->cid);
            proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Media stream ACP SEID [%u - %s %s]",
                    channels_info->sep->seid, get_sep_media_type(
                            interface_id, adapter_id, chandle, direction,
                            channels_info->sep->seid,
                            frame_number),
                    get_sep_type(interface_id, adapter_id, chandle, direction,
                            channels_info->sep->seid,
                            frame_number));

            if (channels_info->sep->media_type == MEDIA_TYPE_AUDIO) {
                sep_data_t                    sep_data;
                media_stream_number_value_t  *media_stream_number_value;
                media_packet_info_t          *previous_media_packet_info;
                media_packet_info_t          *current_media_packet_info;
                nstime_t                      first_abs_ts;
                gdouble                       cummulative_frame_duration;

                sep_data.codec        = channels_info->sep->codec;
                sep_data.vendor_id    = channels_info->sep->vendor_id;
                sep_data.vendor_codec = channels_info->sep->vendor_codec;
                sep_data.acp_seid     = channels_info->sep->seid;
                sep_data.int_seid     = channels_info->sep->int_seid;
                sep_data.content_protection_type = channels_info->sep->content_protection_type;

                media_stream_number_value = (media_stream_number_value_t *) wmem_tree_lookup32_le(channels_info->stream_numbers, frame_number - 1);
                if (media_stream_number_value) {
                    sep_data.stream_number = media_stream_number_value->stream_number;
                } else {
                    sep_data.stream_number = 1;
                }

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &chandle;
                key[3].length = 1;
                key[3].key    = &cid;
                key[4].length = 1;
                key[4].key    = &direction;
                key[5].length = 0;
                key[5].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(media_packet_times, key);
                previous_media_packet_info = (subtree) ? (media_packet_info_t *) wmem_tree_lookup32_le(subtree, frame_number - 1) : NULL;
                if (previous_media_packet_info && previous_media_packet_info->stream_number == sep_data.stream_number ) {
                    sep_data.previous_media_packet_info = previous_media_packet_info;
                    first_abs_ts = previous_media_packet_info->first_abs_ts;
                    cummulative_frame_duration = previous_media_packet_info->cummulative_frame_duration;
                } else {
                    first_abs_ts = pinfo->fd->abs_ts;
                    cummulative_frame_duration = 0.0;
                    sep_data.previous_media_packet_info = (media_packet_info_t *) wmem_new(wmem_epan_scope(), media_packet_info_t);
                    sep_data.previous_media_packet_info->abs_ts = pinfo->fd->abs_ts;
                    sep_data.previous_media_packet_info->first_abs_ts = first_abs_ts;
                    sep_data.previous_media_packet_info->cummulative_frame_duration = cummulative_frame_duration;
                    sep_data.previous_media_packet_info->stream_number = sep_data.stream_number;
                }

                if (!pinfo->fd->flags.visited) {
                    key[5].length = 1;
                    key[5].key    = &frame_number;
                    key[6].length = 0;
                    key[6].key    = NULL;

                    current_media_packet_info = wmem_new(wmem_file_scope(), media_packet_info_t);
                    current_media_packet_info->abs_ts = pinfo->fd->abs_ts;
                    current_media_packet_info->first_abs_ts = first_abs_ts;
                    current_media_packet_info->cummulative_frame_duration = cummulative_frame_duration;
                    current_media_packet_info->stream_number = sep_data.stream_number;

                    wmem_tree_insert32_array(media_packet_times, key, current_media_packet_info);
                }

                key[5].length = 0;
                key[5].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(media_packet_times, key);
                current_media_packet_info = (subtree) ? (media_packet_info_t *) wmem_tree_lookup32(subtree, frame_number) : NULL;
                if (current_media_packet_info)
                    sep_data.current_media_packet_info = current_media_packet_info;
                else
                    sep_data.current_media_packet_info = NULL;

                next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector_with_data(bta2dp_handle, next_tvb, pinfo, tree, &sep_data);
            } else if (channels_info->sep->media_type == MEDIA_TYPE_VIDEO) {
                sep_data_t  sep_data;

                sep_data.codec    = channels_info->sep->codec;
                sep_data.acp_seid = channels_info->sep->seid;
                sep_data.int_seid = channels_info->sep->int_seid;
                sep_data.content_protection_type = channels_info->sep->content_protection_type;

                next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector_with_data(btvdp_handle, next_tvb, pinfo, tree, &sep_data);
            } else {
                ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
                btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Media stream on cid=0x%04x", l2cap_data->cid);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
            }
        }

        return tvb_length(tvb);
    } else if (!(l2cap_data->local_cid == channels_info->control_local_cid &&
            l2cap_data->remote_cid == channels_info->control_remote_cid)) {
        /* Unknown Stream Channel */
        ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
        btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown channel stream on cid=0x%04x", l2cap_data->cid);
        proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
        return tvb_length(tvb);
    }

    /* Signaling Channel */
    ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
    btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

    /* AVDTP signaling*/
    message_type = (tvb_get_guint8(tvb, offset) & AVDTP_MESSAGE_TYPE_MASK);
    packet_type = (tvb_get_guint8(tvb, offset) & AVDTP_PACKET_TYPE_MASK) >> 2;

    signal_item = proto_tree_add_item(btavdtp_tree, hf_btavdtp_signal, tvb, offset,
            (packet_type == PACKET_TYPE_START) ? 3 : 2, ENC_NA);
    signal_tree = proto_item_add_subtree(signal_item, ett_btavdtp_sep);

    proto_tree_add_item(signal_tree, hf_btavdtp_transaction, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(signal_tree, hf_btavdtp_packet_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(signal_tree, hf_btavdtp_message_type, tvb, offset, 1, ENC_NA);

    if (packet_type == PACKET_TYPE_START) {
        offset += 1;
        proto_tree_add_item(signal_tree, hf_btavdtp_number_of_signal_packets, tvb, offset, 1, ENC_NA);
    }

    if (packet_type == PACKET_TYPE_CONTINUE || packet_type == PACKET_TYPE_END) goto LABEL_data;

    offset += 1;
    proto_tree_add_item(signal_tree, hf_btavdtp_rfa0,         tvb, offset, 1, ENC_NA);
    proto_tree_add_item(signal_tree, hf_btavdtp_signal_id,    tvb, offset, 1, ENC_NA);

    signal_id   = tvb_get_guint8(tvb, offset) & AVDTP_SIGNAL_ID_MASK;
    proto_item_append_text(signal_item, ": %s (%s)",
            val_to_str_const(signal_id, signal_id_vals, "Unknown signal"),
            val_to_str_const(message_type, message_type_vals, "Unknown message type"));

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s - %s",
                    val_to_str_const(message_type, message_type_vals, "Unknown message type"),
                    val_to_str_const(signal_id, signal_id_vals, "Unknown signal"));

    offset += 1;
    if (message_type != MESSAGE_TYPE_GENERAL_REJECT) switch (signal_id) {
        case SIGNAL_ID_DISCOVER:
            if (message_type == MESSAGE_TYPE_COMMAND) break;
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            offset = dissect_sep(tvb, pinfo, btavdtp_tree, offset,
                    interface_id, adapter_id, chandle);
            break;
        case SIGNAL_ID_GET_CAPABILITIES:
        case SIGNAL_ID_GET_ALL_CAPABILITIES:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset, NULL, NULL, NULL, NULL);
            break;
        case SIGNAL_ID_SET_CONFIGURATION:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                guint32  int_seid;
                guint32  vendor_id;
                guint16  vendor_codec;

                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, &seid, interface_id,
                        adapter_id, chandle, frame_number);
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_INT, 0, &int_seid, interface_id,
                        adapter_id, chandle, frame_number);
                offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset,
                        &codec, &content_protection_type, &vendor_id, &vendor_codec);

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &chandle;
                key[3].length = 1;
                key[3].key    = &direction;
                key[4].length = 1;
                key[4].key    = &seid;
                key[5].length = 0;
                key[5].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
                sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                if (sep) {
                    sep->codec = codec;
                    sep->vendor_id = vendor_id;
                    sep->vendor_codec = vendor_codec;
                    sep->content_protection_type = content_protection_type;
                    sep->int_seid = int_seid;
                }

                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_service_category, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
        case SIGNAL_ID_GET_CONFIGURATION:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset, NULL, NULL, NULL, NULL);
            break;
        case SIGNAL_ID_RECONFIGURE:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                guint32  vendor_id;
                guint16  vendor_codec;

                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, &seid, interface_id,
                        adapter_id, chandle, frame_number);
                offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset,
                        &codec, &content_protection_type, &vendor_id, &vendor_codec);

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &chandle;
                key[3].length = 1;
                key[3].key    = &direction;
                key[4].length = 1;
                key[4].key    = &seid;
                key[5].length = 0;
                key[5].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
                sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                if (sep) {
                    sep->codec = codec;
                    sep->vendor_id = vendor_id;
                    sep->vendor_codec = vendor_codec;
                    sep->content_protection_type = content_protection_type;
                }

                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_service_category, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
        case SIGNAL_ID_OPEN:
             if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, &seid, interface_id,
                        adapter_id, chandle, frame_number);

                if (!pinfo->fd->flags.visited) {
                    key[0].length = 1;
                    key[0].key    = &interface_id;
                    key[1].length = 1;
                    key[1].key    = &adapter_id;
                    key[2].length = 1;
                    key[2].key    = &chandle;
                    key[3].length = 1;
                    key[3].key    = &direction;
                    key[4].length = 1;
                    key[4].key    = &seid;
                    key[5].length = 0;
                    key[5].key    = NULL;

                    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
                    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                    if (sep) {
                        sep->state = SEP_STATE_OPEN;

                        key[3].length = 1;
                        key[3].key    = &frame_number;
                        key[4].length = 0;
                        key[4].key    = NULL;

                        wmem_tree_insert32_array(sep_open, key, sep);
                    }
                }
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            if (message_type == MESSAGE_TYPE_ACCEPT && !pinfo->fd->flags.visited) {

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &chandle;
                key[3].length = 0;
                key[3].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_open, key);
                sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                if (sep && sep->state == SEP_STATE_OPEN) {
                    sep->state = SEP_STATE_IN_USE;
                    channels_info->sep = sep;
                }
            }
            break;
        case SIGNAL_ID_START:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                i_sep = 1;
                while (tvb_length_remaining(tvb, offset) > 0) {
                    offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                            SEID_ACP, i_sep, NULL,
                            interface_id, adapter_id, chandle, frame_number);
                    i_sep += 1;
                }
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL,
                        interface_id, adapter_id, chandle, frame_number);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }

            if (message_type == MESSAGE_TYPE_ACCEPT && !pinfo->fd->flags.visited) {
                media_stream_number_value_t  *media_stream_number_value;
                guint32                       stream_number = 0;

                media_stream_number_value = (media_stream_number_value_t *) wmem_tree_lookup32_le(channels_info->stream_numbers, frame_number - 1);
#if RTP_PLAYER_WORKAROUND == TRUE
                {
                    media_stream_number_value_t  *file_scope_stream_number_value;

                    if (media_stream_number_value) {
                        stream_number = media_stream_number_value->stream_number;
                    } else {
                        file_scope_stream_number_value = (media_stream_number_value_t *) wmem_tree_lookup32_le(file_scope_stream_number, frame_number - 1);
                        if (file_scope_stream_number_value)
                            stream_number = file_scope_stream_number_value->stream_number + 1;
                        else
                            stream_number = 0;
                    }

                    file_scope_stream_number_value = wmem_new(wmem_file_scope(), media_stream_number_value_t);
                    file_scope_stream_number_value->stream_number = stream_number;
                    wmem_tree_insert32(file_scope_stream_number, frame_number, file_scope_stream_number_value);
                }
#else
                if (media_stream_number_value)
                    stream_number = media_stream_number_value->stream_number;
                else
                    stream_number = 0;
#endif

                media_stream_number_value = wmem_new(wmem_file_scope(), media_stream_number_value_t);
                media_stream_number_value->stream_number = stream_number + 1;

                wmem_tree_insert32(channels_info->stream_numbers, frame_number, media_stream_number_value);
            }
            break;
        case SIGNAL_ID_CLOSE:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            if (!pinfo->fd->flags.visited && message_type == MESSAGE_TYPE_ACCEPT &&
                    channels_info->disconnect_in_frame > pinfo->fd->num) {
                channels_info->disconnect_in_frame = pinfo->fd->num;
            }
            break;
        case SIGNAL_ID_SUSPEND:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                i_sep = 1;
                while (tvb_length_remaining(tvb, offset) > 0) {
                    offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                            SEID_ACP, i_sep, NULL,
                            interface_id, adapter_id, chandle, frame_number);
                    i_sep += 1;
                }
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
        case SIGNAL_ID_ABORT:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            if (!pinfo->fd->flags.visited && message_type == MESSAGE_TYPE_ACCEPT &&
                    channels_info->disconnect_in_frame > pinfo->fd->num) {
                channels_info->disconnect_in_frame = pinfo->fd->num;
            }
            break;
        case SIGNAL_ID_SECURITY_CONTROL:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
                offset += tvb_length_remaining(tvb, offset);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }

            proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
            offset += tvb_length_remaining(tvb, offset);
            break;
        case SIGNAL_ID_DELAY_REPORT:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                proto_item  *pitem;
                delay = tvb_get_ntohs(tvb, offset + 1);
                col_append_fstr(pinfo->cinfo, COL_INFO, "(%u.%u ms)", delay/10, delay%10);
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL,
                        interface_id, adapter_id, chandle, frame_number);
                pitem = proto_tree_add_item(btavdtp_tree, hf_btavdtp_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(pitem, " (1/10 ms)");
                offset += 2;
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
    }

    LABEL_data:

    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
    }

    return offset;
}


void
proto_register_btavdtp(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_btavdtp_signal,
            { "Signal",                   "btavdtp.signal",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_message_type,
            { "Message Type",                   "btavdtp.message_type",
            FT_UINT8, BASE_HEX, VALS(message_type_vals), AVDTP_MESSAGE_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_packet_type,
            { "Packet Type",                    "btavdtp.packet_type",
            FT_UINT8, BASE_HEX, VALS(packet_type_vals), AVDTP_PACKET_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_transaction,
            { "Transaction",                    "btavdtp.transaction",
            FT_UINT8, BASE_HEX, NULL, AVDTP_TRANSACTION_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_signal_id,
            { "Signal",                         "btavdtp.signal_id",
            FT_UINT8, BASE_HEX, VALS(signal_id_vals), AVDTP_SIGNAL_ID_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_rfa0,
            { "RFA",                            "btavdtp.rfa0",
            FT_UINT8, BASE_HEX, NULL, AVDTP_RFA0_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_number_of_signal_packets,
            { "Number of signal packets",       "btavdtp.num_signal_packets",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btavdtp_error_code,
            { "Error Code",                     "btavdtp.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_seid,
            { "SEID",                           "btavdtp.sep_seid",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_inuse,
            { "In Use",                         "btavdtp.sep_inuse",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_rfa0,
            { "RFA0",                           "btavdtp.sep_rfa0",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_media_type,
            { "Media Type",                     "btavdtp.sep_media_type",
            FT_UINT8, BASE_HEX, VALS(media_type_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_type,
            { "Type",                           "btavdtp.sep_type",
            FT_UINT8, BASE_HEX, VALS(sep_type_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_rfa1,
            { "RFA1",                           "btavdtp.sep_rfa1",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btavdtp_acp_sep,
            { "ACP SEP",                        "btavdtp.acp_sep",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_acp_seid_item,
            { "ACP SEID",                       "btavdtp.acp_seid_item",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_int_seid_item,
            { "INT SEID",                       "btavdtp.int_seid_item",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_acp_seid,
            { "ACP SEID",                       "btavdtp.acp_seid",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_btavdtp_int_seid,
            { "INT SEID",                       "btavdtp.int_seid",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_btavdtp_rfa_seid,
            { "RFA",                            "btavdtp.rfa_seid",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btavdtp_service_category,
            { "Service Category",               "btavdtp.service_category",
            FT_UINT8, BASE_HEX, VALS(service_category_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_length_of_service_category,
            { "Length of Service Category",     "btavdtp.length_of_service_category",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_delay,
            { "Delay",                          "btavdtp.delay",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_recovery_type,
            { "Service Category",               "btavdtp.recovery_type",
            FT_UINT8, BASE_HEX, VALS(recovery_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_maximum_recovery_window_size,
            { "Service Category",               "btavdtp.maximum_recovery_window_size",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_maximum_number_of_media_packet_in_parity_code,
            { "Service Category",               "btavdtp.maximum_number_of_media_packet_in_parity_code",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_fragmentation,
            { "Fragmentation",                  "btavdtp.multiplexing_fragmentation",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_rfa,
            { "RFA",                            "btavdtp.multiplexing_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_tsid,
            { "TSID",                           "btavdtp.multiplexing_tsid",
            FT_UINT8, BASE_HEX, VALS(multiplexing_tsid_vals), 0xF8,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_tcid,
            { "TCID",                           "btavdtp.multiplexing_tcid",
            FT_UINT8, BASE_HEX, VALS(multiplexing_tcid_vals), 0xF8,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_entry_rfa,
            { "RFA",                            "btavdtp.multiplexing_entry_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_backch,
            { "BackCh",                         "btavdtp.header_compression_backch",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_media,
            { "Media",                          "btavdtp.header_compression_media",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_recovery,
            { "Recovery",                       "btavdtp.header_compression_recovery",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_rfa,
            { "RFA",                            "btavdtp.header_compression_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_btavdtp_content_protection_type,
            { "Type",                           "btavdtp.content_protection_type",
            FT_UINT16, BASE_HEX, VALS(content_protection_type_vals), 0x0000,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_media_type,
            { "Media Type",                     "btavdtp.media_codec_media_type",
            FT_UINT8, BASE_HEX, VALS(media_type_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_rfa,
            { "RFA",                            "btavdtp.media_codec_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_audio_type,
            { "Media Codec Audio Type",         "btavdtp.media_codec_audio_type",
            FT_UINT8, BASE_HEX, VALS(media_codec_audio_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_video_type,
            { "Media Codec Video Type",         "btavdtp.media_codec_video_type",
            FT_UINT8, BASE_HEX, VALS(media_codec_video_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_unknown_type,
            { "Media Codec Unknown Type",       "btavdtp.media_codec_unknown_type",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.sbc.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.sbc.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.sbc.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.sbc.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.sbc.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.sbc.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.sbc.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.sbc.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_4,
            { "Block Length 4",                 "btavdtp.codec.sbc.block.4",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_8,
            { "Block Length 8",                 "btavdtp.codec.sbc.block.8",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_12,
            { "Block Length 12",                "btavdtp.codec.sbc.block.12",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_16,
            { "Block Length 16",                "btavdtp.codec.sbc.block.16",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_subbands_4,
            { "Subbands 4",                     "btavdtp.codec.sbc.subbands.4",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_subbands_8,
            { "Subbands 8",                     "btavdtp.codec.sbc.subbands.8",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_allocation_method_snr,
            { "Allocation Method SNR",          "btavdtp.codec.sbc.allocation_method.snr",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_allocation_method_loudness,
            { "Allocation Method Loudness",     "btavdtp.codec.sbc.allocation_method.loudness",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_min_bitpool,
            { "Minumum Bitpool",                "btavdtp.codec.sbc.minimum_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_max_bitpool,
            { "Maximum Bitpool",                "btavdtp.codec.sbc.maximum_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_layer_1,
            { "MP1",                            "btavdtp.codec.mpeg12.layer_1",
            FT_BOOLEAN, 8, NULL, 0x80,
            "MPEG Layer 1", HFILL }
        },
        { &hf_btavdtp_mpeg12_layer_2,
            { "MP2",                            "btavdtp.codec.mpeg12.layer_2",
            FT_BOOLEAN, 8, NULL, 0x40,
            "MPEG Layer 2", HFILL }
        },
        { &hf_btavdtp_mpeg12_layer_3,
            { "MP3",                            "btavdtp.codec.mpeg12.layer_3",
            FT_BOOLEAN, 8, NULL, 0x20,
            "MPEG Layer 3", HFILL }
        },
        { &hf_btavdtp_mpeg12_crc_protection,
            { "CRC Protection",                 "btavdtp.codec.mpeg12.crc_protection",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.mpeg12.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.mpeg12.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.mpeg12.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.mpeg12.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_rfa,
            { "RFA",                            "btavdtp.codec.mpeg12.rfa",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_mpf_2,
            { "Media Payload Format 2",         "btavdtp.codec.mpeg12.mpf_2",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.sbc.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_22050,
            { "Sampling Frequency 22050 Hz",    "btavdtp.codec.sbc.sampling_frequency.22050",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_24000,
            { "Sampling Frequency 24000 Hz",    "btavdtp.codec.sbc.sampling_frequency.24000",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.sbc.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.sbc.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.sbc.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_vbr_supported,
            { "VBR Supported",                  "btavdtp.codec.mpeg12.vbr",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_bit_rate,
            { "Bit Rate",                       "btavdtp.codec.mpeg12.bit_rate",
            FT_UINT16, BASE_HEX, NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg2_aac_lc,
            { "MPEG2 ACC LC",                   "btavdtp.codec.mpeg24.object_type.mpeg2_aac_lc",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg4_aac_lc,
            { "MPEG4 ACC LC",                   "btavdtp.codec.mpeg24.object_type.mpeg4_aac_lc",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg4_aac_ltp,
            { "MPEG4 ACC LTP",                  "btavdtp.codec.mpeg24.object_type.mpeg4_aac_ltp",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg4_aac_scalable,
            { "MPEG4 ACC Scalable",             "btavdtp.codec.mpeg24.object_type.mpeg4_aac_scalable",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_rfa,
            { "RFA",                            "btavdtp.codec.mpeg24.object_type.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_8000,
            { "Sampling Frequency 8000 Hz",     "btavdtp.codec.mpeg24.sampling_frequency.8000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_11025,
            { "Sampling Frequency 11025 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.11025",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_12000,
            { "Sampling Frequency 12000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.12000",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_22050,
            { "Sampling Frequency 22050 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.22050",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_24000,
            { "Sampling Frequency 24000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.24000",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_64000,
            { "Sampling Frequency 64000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.64000",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_88200,
            { "Sampling Frequency 88200 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.88200",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_96000,
            { "Sampling Frequency 96000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.96000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_channels_1,
            { "Channels 1",                     "btavdtp.codec.mpeg24.channels.1",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_channels_2,
            { "Channels 2",                     "btavdtp.codec.mpeg24.channels.2",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_rfa,
            { "RFA",                            "btavdtp.codec.mpeg24.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_vbr_supported,
            { "VBR Supported",                  "btavdtp.codec.mpeg24.vbr",
            FT_BOOLEAN, 24, NULL, 0x800000,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_bit_rate,
            { "Bit Rate",                       "btavdtp.codec.mpeg24.bit_rate",
            FT_UINT24, BASE_HEX, NULL, 0x7FFFFF,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_version,
            { "Version",                        "btavdtp.codec.atrac.version",
            FT_UINT8, BASE_DEC, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_channel_mode_single_channel,
            { "Channel Mode Single Channel",    "btavdtp.codec.atrac.channel_mode.single_channel",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.atrac.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.atrac.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_rfa1,
            { "RFA",                            "btavdtp.codec.atrac.rfa1",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_rfa2,
            { "RFA",                            "btavdtp.codec.atrac.rfa2",
            FT_UINT24, BASE_HEX, NULL, 0xC00000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.sbc.sampling_frequency.44100",
            FT_BOOLEAN, 24, NULL, 0x200000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.sbc.sampling_frequency.48000",
            FT_BOOLEAN, 24, NULL, 0x100000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_vbr_supported,
            { "VBR Supported",                  "btavdtp.codec.atrac.vbr",
            FT_BOOLEAN, 24, NULL, 0x080000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_bit_rate,
            { "Bit Rate",                       "btavdtp.codec.atrac.bit_rate",
            FT_UINT24, BASE_HEX, NULL, 0x07FFFF,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_maximum_sul,
            { "Maximum SUL",                    "btavdtp.codec.atrac.maximum_sul",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Sound Unit Length (SUL) is one of the parameters that determine bit rate of the audio stream.", HFILL }
        },
        { &hf_btavdtp_atrac_rfa3,
            { "RFA",                            "btavdtp.codec.atrac.rfa3",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_10,
            { "H264 Level 10",                  "btavdtp.codec.h264.level.10",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_20,
            { "H264 Level 20",                  "btavdtp.codec.h264.level.20",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_30,
            { "H264 Level 30",                  "btavdtp.codec.h264.level.30",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_rfa,
            { "H264 Level RFA",                 "btavdtp.codec.h264.level.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_0,
            { "MPEG Level 0",                   "btavdtp.codec.mpeg4.level.0",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_1,
            { "MPEG Level 1",                   "btavdtp.codec.mpeg4.level.1",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_2,
            { "MPEG Level 2",                   "btavdtp.codec.mpeg4.level.2",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_3,
            { "MPEG4 Level 3",                  "btavdtp.codec.mpeg4.level.3",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_rfa,
            { "MPEG4 Level RFA",                "btavdtp.codec.mpeg4.level.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_id,
            { "Vendor ID",                      "btavdtp.codec.vendor.vendor_id",
            FT_UINT32, BASE_HEX|BASE_EXT_STRING, &bthci_evt_comp_id_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_codec_id,
            { "Codec",                          "btavdtp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_value,
            { "Value",                          "btavdtp.codec.vendor.value",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_apt_codec_id,
            { "Codec",                          "btavdtp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, VALS(vendor_apt_codec_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.aptx.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.aptx.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.aptx.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.aptx.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.aptx.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.aptx.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.aptx.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.aptx.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_capabilities,
            { "Capabilities",                   "btavdtp.capabilities",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_service,
            { "Service",                        "btavdtp.service",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_service_multiplexing_entry,
            { "Entry",                          "btavdtp.service_multiplexing_entry",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_data,
            { "Data",                           "btavdtp.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btavdtp,
        &ett_btavdtp_sep,
        &ett_btavdtp_capabilities,
        &ett_btavdtp_service,
    };

    proto_btavdtp = proto_register_protocol("Bluetooth AVDTP Protocol", "BT AVDTP", "btavdtp");
    btavdtp_handle = new_register_dissector("btavdtp", dissect_btavdtp, proto_btavdtp);

    proto_register_field_array(proto_btavdtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_btavdtp, NULL);
    prefs_register_static_text_preference(module, "avdtp.version",
            "Bluetooth Protocol AVDTP version: 1.3",
            "Version of protocol supported by this dissector.");

    channels             = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    sep_list             = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    sep_open             = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    media_packet_times   = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
#if RTP_PLAYER_WORKAROUND == TRUE
    file_scope_stream_number = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
#endif
}

void
proto_reg_handoff_btavdtp(void)
{
    dissector_add_uint("btl2cap.service", BTSDP_AVDTP_PROTOCOL_UUID, btavdtp_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_AVDTP, btavdtp_handle);

    dissector_add_for_decode_as("btl2cap.cid", btavdtp_handle);
}


static gint
dissect_aptx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *aptx_item;
    proto_tree          *aptx_tree;
    proto_item          *pitem;
    bta2dp_codec_info_t *info;
    gdouble              cummulative_frame_duration = 0;

    info = (bta2dp_codec_info_t *) data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "APT-X");

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "APT-X");

    aptx_item = proto_tree_add_item(tree, proto_aptx, tvb, 0, -1, ENC_NA);
    aptx_tree = proto_item_add_subtree(aptx_item, ett_aptx);

    proto_tree_add_item(aptx_tree, hf_aptx_data, tvb, 0, -1, ENC_NA);
    {
    /*       expected_speed_data = (frame_length * frequency) / (sbc_subbands * sbc_blocks);
        frame_duration = (((double) frame_length / (double) expected_speed_data) * 1000.0);
        cummulative_frame_duration += frame_duration;*/
    double expected_speed_data;
    double frame_duration;
    double frame_length = 2 * 2 * 4;

    /* INT 32 = 2 channels * 4 *4
     OUT 4 (2*2)*/

    expected_speed_data = 48000.0 * (16.0 / 8.0) * 2.0;
    frame_duration = (((double) frame_length / (double) expected_speed_data) * 1000.0);

    cummulative_frame_duration = (tvb_reported_length(tvb) / 4.0) * frame_duration;
    }
    pitem = proto_tree_add_double(aptx_tree, hf_aptx_cummulative_frame_duration, tvb, 0, 0, cummulative_frame_duration);
    proto_item_append_text(pitem, " ms");
    PROTO_ITEM_SET_GENERATED(pitem);

    if (info) {
        nstime_t  delta;

        nstime_delta(&delta, &pinfo->fd->abs_ts, &info->previous_media_packet_info->abs_ts);
        pitem = proto_tree_add_double(aptx_tree, hf_aptx_delta_time, tvb, 0, 0, nstime_to_msec(&delta));
        proto_item_append_text(pitem, " ms");
        PROTO_ITEM_SET_GENERATED(pitem);

        nstime_delta(&delta, &pinfo->fd->abs_ts, &info->previous_media_packet_info->first_abs_ts);
        pitem = proto_tree_add_double(aptx_tree, hf_aptx_delta_time_from_the_beginning, tvb, 0, 0, nstime_to_msec(&delta));
        proto_item_append_text(pitem, " ms");
        PROTO_ITEM_SET_GENERATED(pitem);

        if (!pinfo->fd->flags.visited)
            info->current_media_packet_info->cummulative_frame_duration += cummulative_frame_duration;

        pitem = proto_tree_add_double(aptx_tree, hf_aptx_cummulative_duration, tvb, 0, 0, info->previous_media_packet_info->cummulative_frame_duration);
        proto_item_append_text(pitem, " ms");
        PROTO_ITEM_SET_GENERATED(pitem);

        pitem = proto_tree_add_double(aptx_tree, hf_aptx_diff, tvb, 0, 0, info->previous_media_packet_info->cummulative_frame_duration - nstime_to_msec(&delta));
        proto_item_append_text(pitem, " ms");
        PROTO_ITEM_SET_GENERATED(pitem);
    }

    return tvb_reported_length(tvb);
}

void
proto_register_aptx(void)
{
    static hf_register_info hf[] = {
        { &hf_aptx_data,
            { "Data",                            "aptx.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_cummulative_frame_duration,
            { "Cummulative Frame Duration",      "aptx.cummulative_frame_duration",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_delta_time,
            { "Delta time",                      "aptx.delta_time",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_delta_time_from_the_beginning,
            { "Delta time from the beginning",   "aptx.delta_time_from_the_beginning",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_cummulative_duration,
            { "Cummulative Music Duration",      "aptx.cummulative_music_duration",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_diff,
            { "Diff",                            "aptx.diff",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_aptx
    };

    proto_aptx = proto_register_protocol("APT-X Codec", "APT-X", "aptx");
    proto_register_field_array(proto_bta2dp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    aptx_handle = new_register_dissector("aptx", dissect_aptx, proto_aptx);
}


static gint
dissect_bta2dp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *ti;
    proto_tree          *bta2dp_tree;
    proto_item          *pitem;
    gint                 offset = 0;
    dissector_handle_t   codec_dissector = NULL;
    bta2dp_codec_info_t  bta2dp_codec_info;
    sep_data_t           sep_data;
    gboolean             no_avdtp_session;

    no_avdtp_session = (proto_btavdtp != (gint) GPOINTER_TO_UINT(wmem_list_frame_data(
                wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));

    sep_data.codec = CODEC_SBC;
    sep_data.content_protection_type = 0;
    sep_data.acp_seid = 0;
    sep_data.int_seid = 0;
    sep_data.previous_media_packet_info = NULL;
    sep_data.current_media_packet_info = NULL;
    sep_data.stream_number = 1;
    sep_data.vendor_id = 0;
    sep_data.vendor_codec = 0;

    if (force_a2dp_scms_t || force_a2dp_codec != CODEC_DEFAULT) {
        if (force_a2dp_scms_t)
            sep_data.content_protection_type = 2;
        else if (data && !no_avdtp_session)
            sep_data.content_protection_type = ((sep_data_t *) data)->content_protection_type;

        if (force_a2dp_codec != CODEC_DEFAULT)
            sep_data.codec = force_a2dp_codec;
        else if (data && !no_avdtp_session)
            sep_data.codec = ((sep_data_t *) data)->codec;
    } else {
        if (data && !no_avdtp_session)
            sep_data = *((sep_data_t *) data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "A2DP");

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    ti = proto_tree_add_item(tree, proto_bta2dp, tvb, offset, -1, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Audio stream - %s",
            val_to_str_const(sep_data.codec, media_codec_audio_type_vals, "unknown codec"));

    bta2dp_tree = proto_item_add_subtree(ti, ett_bta2dp);

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_acp_seid, tvb, 0, 0, sep_data.acp_seid);
    PROTO_ITEM_SET_GENERATED(pitem);

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_int_seid, tvb, 0, 0, sep_data.int_seid);
    PROTO_ITEM_SET_GENERATED(pitem);

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_codec, tvb, 0, 0, sep_data.codec);
    PROTO_ITEM_SET_GENERATED(pitem);

    if (sep_data.codec == 0xFF) { /* Vendor Specific Codec */
        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_vendor_id, tvb, 0, 0, sep_data.vendor_id);
        PROTO_ITEM_SET_GENERATED(pitem);

        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_vendor_codec_id, tvb, 0, 0, sep_data.vendor_codec);
        PROTO_ITEM_SET_GENERATED(pitem);

        if (sep_data.vendor_id == 0x004F && sep_data.vendor_codec == 0x0001)
            codec_dissector = aptx_handle;
    }

    if (sep_data.content_protection_type > 0) {
        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_content_protection, tvb, 0, 0, sep_data.content_protection_type);
        PROTO_ITEM_SET_GENERATED(pitem);
    }

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_stream_number, tvb, 0, 0, sep_data.stream_number);
    PROTO_ITEM_SET_GENERATED(pitem);

    switch (sep_data.codec) {
        case CODEC_SBC:
            codec_dissector = sbc_handle;
            break;
         case CODEC_MPEG12_AUDIO:
            codec_dissector = mp2t_handle;
            break;
        case CODEC_MPEG24_AAC:
            codec_dissector = mpeg_audio_handle;
            break;
        case CODEC_ATRAC:
            codec_dissector = atrac_handle;
            break;
    }

    bta2dp_codec_info.codec_dissector = codec_dissector;
    bta2dp_codec_info.content_protection_type = sep_data.content_protection_type;
    bta2dp_codec_info.previous_media_packet_info = sep_data.previous_media_packet_info;
    bta2dp_codec_info.current_media_packet_info  = sep_data.current_media_packet_info;

#if RTP_PLAYER_WORKAROUND == TRUE
    /* XXX: Workaround to get multiple RTP streams, because converation are too
       weak to recognize Bluetooth streams (key is: guint32 interface_id, guint32 adapter_id, guint32 chandle, guint32 cid, guint32 direction -> guint32 stream_number) */
    pinfo->srcport = sep_data.stream_number;
    pinfo->destport = sep_data.stream_number;
#endif

    bluetooth_add_address(pinfo, &pinfo->net_dst, sep_data.stream_number, "BT A2DP", pinfo->fd->num, FALSE, &bta2dp_codec_info);
    call_dissector(rtp_handle, tvb, pinfo, tree);

    offset += tvb_length_remaining(tvb, offset);

    return offset;
}

void
proto_register_bta2dp(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_bta2dp_acp_seid,
            { "ACP SEID",                        "bta2dp.acp_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_int_seid,
            { "INT SEID",                        "bta2dp.int_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_codec,
            { "Codec",                           "bta2dp.codec",
            FT_UINT8, BASE_HEX, VALS(media_codec_audio_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_vendor_id,
            { "Vendor ID",                       "bta2dp.codec.vendor.vendor_id",
            FT_UINT32, BASE_HEX|BASE_EXT_STRING, &bthci_evt_comp_id_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_vendor_codec_id,
            { "Vendor Codec",                    "bta2dp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_content_protection,
            { "Content Protection",              "bta2dp.content_protection",
            FT_UINT16, BASE_HEX, VALS(content_protection_type_vals), 0x0000,
            NULL, HFILL }
        },
        { &hf_bta2dp_stream_number,
            { "Stream Number",                   "bta2dp.stream_number",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_bta2dp
    };

    proto_bta2dp = proto_register_protocol("Bluetooth A2DP Profile", "BT A2DP", "bta2dp");
    proto_register_field_array(proto_bta2dp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bta2dp_handle = new_register_dissector("bta2dp", dissect_bta2dp, proto_bta2dp);

    module = prefs_register_protocol(proto_bta2dp, NULL);
    prefs_register_static_text_preference(module, "a2dp.version",
            "Bluetooth Profile A2DP version: 1.3",
            "Version of profile supported by this dissector.");

    prefs_register_bool_preference(module, "a2dp.content_protection.scms_t",
            "Force SCMS-T decoding",
            "Force decoding stream as A2DP with Content Protection SCMS-T ",
            &force_a2dp_scms_t);

    prefs_register_enum_preference(module, "a2dp.codec",
            "Force codec",
            "Force decoding stream as A2DP with specified codec",
            &force_a2dp_codec, pref_a2dp_codec, FALSE);
}

void
proto_reg_handoff_bta2dp(void)
{
    sbc_handle = find_dissector("sbc");
    mp2t_handle = find_dissector("mp2t");
    mpeg_audio_handle = find_dissector("mpeg-audio");
/* TODO: ATRAC dissector does not exist yet */
    atrac_handle = find_dissector("atrac");
    aptx_handle = find_dissector("aptx");

    rtp_handle   = find_dissector("rtp");

    dissector_add_uint("btl2cap.service", BTSDP_A2DP_SOURCE_SERVICE_UUID, bta2dp_handle);
    dissector_add_uint("btl2cap.service", BTSDP_A2DP_SINK_SERVICE_UUID, bta2dp_handle);
    dissector_add_uint("btl2cap.service", BTSDP_A2DP_DISTRIBUTION_SERVICE_UUID, bta2dp_handle);
    dissector_add_for_decode_as("btl2cap.cid", bta2dp_handle);
}

static gint
dissect_btvdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *ti;
    proto_tree          *btvdp_tree;
    proto_item          *pitem;
    gint                 offset = 0;
    dissector_handle_t   codec_dissector = NULL;
    btvdp_codec_info_t   btvdp_codec_info;
    sep_data_t           sep_data;
    gboolean             no_avdtp_session;

    no_avdtp_session = (proto_btavdtp != (gint) GPOINTER_TO_UINT(wmem_list_frame_data(
                wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));

    sep_data.codec = CODEC_H263_BASELINE;
    sep_data.content_protection_type = 0;
    sep_data.acp_seid = 0;
    sep_data.int_seid = 0;
    sep_data.previous_media_packet_info = NULL;
    sep_data.current_media_packet_info = NULL;
    sep_data.stream_number = 1;
    sep_data.vendor_id = 0;
    sep_data.vendor_codec = 0;

    if (force_vdp_scms_t || force_vdp_codec) {
        if (force_vdp_scms_t)
            sep_data.content_protection_type = 2;
        else if (data  && !no_avdtp_session)
            sep_data.content_protection_type = ((sep_data_t *) data)->content_protection_type;

        if (force_vdp_codec)
            sep_data.codec = force_vdp_codec;
        else if (data  && !no_avdtp_session)
            sep_data.codec = ((sep_data_t *) data)->codec;
    } else {
        if (data  && !no_avdtp_session)
            sep_data = *((sep_data_t *) data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VDP");

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    ti = proto_tree_add_item(tree, proto_btvdp, tvb, offset, -1, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Video stream - %s",
            val_to_str_const(sep_data.codec, media_codec_video_type_vals, "unknown codec"));

    btvdp_tree = proto_item_add_subtree(ti, ett_btvdp);

    pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_acp_seid, tvb, 0, 0, sep_data.acp_seid);
    PROTO_ITEM_SET_GENERATED(pitem);

    pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_int_seid, tvb, 0, 0, sep_data.int_seid);
    PROTO_ITEM_SET_GENERATED(pitem);

    pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_codec, tvb, 0, 0, sep_data.codec);
    PROTO_ITEM_SET_GENERATED(pitem);

    if (sep_data.content_protection_type > 0) {
        pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_content_protection, tvb, 0, 0, sep_data.content_protection_type);
        PROTO_ITEM_SET_GENERATED(pitem);
    }

    switch (sep_data.codec) {
        case CODEC_H263_BASELINE:
        case CODEC_H263_PROFILE_3:
        case CODEC_H263_PROFILE_8:
            codec_dissector = h263_handle;
            break;
        case CODEC_MPEG4_VSP:
            codec_dissector = mp4v_es_handle;
            break;
    }

    btvdp_codec_info.codec_dissector = codec_dissector;
    btvdp_codec_info.content_protection_type = sep_data.content_protection_type;

    bluetooth_add_address(pinfo, &pinfo->net_dst, 0, "BT VDP", pinfo->fd->num, TRUE, &btvdp_codec_info);
    call_dissector(rtp_handle, tvb, pinfo, tree);
    offset += tvb_length_remaining(tvb, offset);

    return offset;
}

void
proto_register_btvdp(void)
{
    module_t *module;
    expert_module_t* expert_btavdtp;

    static hf_register_info hf[] = {
        { &hf_btvdp_acp_seid,
            { "ACP SEID",                        "btvdp.acp_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_int_seid,
            { "INT SEID",                        "btvdp.int_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_codec,
            { "Codec",                           "btvdp.codec",
            FT_UINT8, BASE_HEX, VALS(media_codec_video_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_content_protection,
            { "Content Protection",              "btvdp.content_protection",
            FT_UINT16, BASE_HEX, VALS(content_protection_type_vals), 0x0000,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btvdp
    };

    static ei_register_info ei[] = {
        { &ei_btavdtp_sbc_min_bitpool_out_of_range, { "btavdtp.codec.sbc.minimum_bitpool.out_of_range", PI_PROTOCOL, PI_WARN, "Bitpool is out of range. Should be 2..250.", EXPFILL }},
        { &ei_btavdtp_sbc_max_bitpool_out_of_range, { "btavdtp.codec.sbc.maximum_bitpool.out_of_range", PI_PROTOCOL, PI_WARN, "Bitpool is out of range. Should be 2..250.", EXPFILL }},
        { &ei_btavdtp_unexpected_losc_data, { "btavdtp.unexpected_losc_data", PI_PROTOCOL, PI_WARN, "Unexpected losc data", EXPFILL }},
    };

    proto_btvdp = proto_register_protocol("Bluetooth VDP Profile", "BT VDP", "btvdp");
    btvdp_handle = new_register_dissector("btvdp", dissect_btvdp, proto_btvdp);
    proto_register_field_array(proto_bta2dp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btavdtp = expert_register_protocol(proto_btvdp);
    expert_register_field_array(expert_btavdtp, ei, array_length(ei));

    module = prefs_register_protocol(proto_btvdp, NULL);
    prefs_register_static_text_preference(module, "vdp.version",
            "Bluetooth Profile VDP version: 1.1",
            "Version of profile supported by this dissector.");

    prefs_register_bool_preference(module, "vdp.content_protection.scms_t",
            "Force SCMS-T decoding",
            "Force decoding stream as VDP with Content Protection SCMS-T ",
            &force_vdp_scms_t);

    prefs_register_enum_preference(module, "vdp.codec",
            "Force codec",
            "Force decoding stream as VDP with specified codec",
            &force_vdp_codec, pref_vdp_codec, FALSE);
}

void
proto_reg_handoff_btvdp(void)
{
    h263_handle = find_dissector("h263");
    mp4v_es_handle = find_dissector("mp4v-es");

    rtp_handle   = find_dissector("rtp");

    dissector_add_uint("btl2cap.service", BTSDP_VDP_SOURCE_SERVICE_UUID, btvdp_handle);
    dissector_add_uint("btl2cap.service", BTSDP_VDP_SINK_SERVICE_UUID, btvdp_handle);
    dissector_add_uint("btl2cap.service", BTSDP_VDP_DISTRIBUTION_SERVICE_UUID, btvdp_handle);
    dissector_add_for_decode_as("btl2cap.cid", btvdp_handle);
}



static gint
dissect_a2dp_cp_scms_t(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    gint         offset = 0;

    main_item = proto_tree_add_item(tree, proto_bta2dp_cph_scms_t, tvb, offset, 1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bta2dp_cph_scms_t);

    proto_tree_add_item(main_tree, hf_bta2dp_reserved , tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_bta2dp_cp_bit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_bta2dp_l_bit , tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_bta2dp_content_protection_header_scms_t(void)
{
    static hf_register_info hf[] = {
        { &hf_bta2dp_l_bit,
            { "L-bit",                           "bta2dp.content_protection_header.scms_t.l_bit",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bta2dp_cp_bit,
            { "Cp-bit",                          "bta2dp.content_protection_header.scms_t.cp_bit",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bta2dp_reserved,
            { "Reserved",                        "bta2dp.content_protection_header.scms_t.reserved",
            FT_BOOLEAN, 8, NULL, 0xFC,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_bta2dp_cph_scms_t
    };

    proto_bta2dp_cph_scms_t = proto_register_protocol("Bluetooth A2DP Content Protection Header SCMS-T", "BT A2DP Content Protection Header SCMS-T", "bta2dp_content_protection_header_scms_t");
    proto_register_field_array(proto_bta2dp_cph_scms_t, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("bta2dp_content_protection_header_scms_t", dissect_a2dp_cp_scms_t, proto_bta2dp_cph_scms_t);
}

static gint
dissect_vdp_cp_scms_t(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    gint         offset = 0;

    main_item = proto_tree_add_item(tree, proto_btvdp_cph_scms_t, tvb, offset, 1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btvdp_cph_scms_t);

    proto_tree_add_item(main_tree, hf_btvdp_reserved , tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_btvdp_cp_bit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_btvdp_l_bit , tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_btvdp_content_protection_header_scms_t(void)
{
    static hf_register_info hf[] = {
        { &hf_btvdp_l_bit,
            { "L-bit",                           "btvdp.content_protection_header.scms_t.l_bit",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btvdp_cp_bit,
            { "Cp-bit",                          "btvdp.content_protection_header.scms_t.cp_bit",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btvdp_reserved,
            { "Reserved",                        "btvdp.content_protection_header.scms_t.reserved",
            FT_BOOLEAN, 8, NULL, 0xFC,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btvdp_cph_scms_t
    };

    proto_btvdp_cph_scms_t = proto_register_protocol("Bluetooth VDP Content Protection Header SCMS-T", "BT VDP Content Protection Header SCMS-T", "btvdp_content_protection_header_scms_t");
    proto_register_field_array(proto_btvdp_cph_scms_t, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("btvdp_content_protection_header_scms_t", dissect_vdp_cp_scms_t, proto_btvdp_cph_scms_t);
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
