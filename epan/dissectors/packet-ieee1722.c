/* packet-ieee1722.c
 * Routines for AVTP (Audio Video Transport Protocol) dissection
 * Copyright 2010, Torrey Atcitty <tatcitty@harman.com>
 *                 Dave Olsen <dave.olsen@harman.com>
 *                 Levi Pearson <levi.pearson@harman.com>
 *
 * Copyright 2011, Thomas Bottom <tom.bottom@labxtechnologies.com>
 *
 * Copyright 2016, Andreas Leibold <andreas.leibold@harman.com>
 *                 Dissection for the following 1722 subtypes added:
 *                 Clock Reference Format (CRF).
 *                 IEC 61883-4 MPEG-TS data transmission.
 *                 IEC 61883-6 audio/music data transmission protocol improved.
 *                 Changes to meet 1722 Draft 15 specification.
 *
 * Copyright 2017, Marouen Ghodhbane <marouen.ghodhbane@nxp.com>
 *                 Dissection for the 1722 Compressed Video subtype added.
 *                 CVF Format subtype supported: H264 and MJPEG
 *                 The dissection meets the 1722-2016 specification.
 *
 * Copyright 2019, Dmitry Linikov <linikov@arrival.com>
 *                 Dissection for the 1722 Time-Sensitive and Non-Time-Sensitive
 *                 Control formats added.
 *                 ACF Message types supported: CAN, CAN_BRIEF, LIN
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The 1722 Protocol specification can be found at the following:
 * http://grouper.ieee.org/groups/1722/
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include "packet-socketcan.h"

#include "packet-mp2t.h"

void proto_register_1722(void);
void proto_reg_handoff_1722(void);
void proto_register_1722_crf(void);
void proto_reg_handoff_1722_crf(void);
void proto_register_1722_aaf(void);
void proto_reg_handoff_1722_aaf(void);
void proto_register_1722_61883(void);
void proto_reg_handoff_1722_61883(void);
void proto_register_1722_cvf(void);
void proto_reg_handoff_1722_cvf(void);
void proto_register_1722_ntscf(void);
void proto_reg_handoff_1722_ntscf(void);
void proto_register_1722_tscf(void);
void proto_reg_handoff_1722_tscf(void);
void proto_register_1722_acf(void);
void proto_reg_handoff_1722_acf(void);
void proto_register_1722_acf_can(void);
void proto_reg_handoff_1722_acf_can(void);
void proto_register_1722_acf_lin(void);
void proto_reg_handoff_1722_acf_lin(void);

static dissector_handle_t avtp_handle_eth;
static dissector_handle_t avtp_handle_udp;
static dissector_handle_t avb1722_61883_handle;
static dissector_handle_t avb1722_aaf_handle;
static dissector_handle_t avb1722_cvf_handle;
static dissector_handle_t avb1722_crf_handle;
static dissector_handle_t avb1722_ntscf_handle;
static dissector_handle_t avb1722_tscf_handle;
static dissector_handle_t avb1722_acf_lin_handle;

static dissector_handle_t jpeg_handle;
static dissector_handle_t h264_handle;
static dissector_handle_t mp2t_handle;

#define UDP_PORT_IEEE_1722   17220 /* One of two IANA registered ports */

enum IEEE_1722_TRANSPORT {
    IEEE_1722_TRANSPORT_ETH,
    IEEE_1722_TRANSPORT_UDP,
};

typedef struct _ieee1722_seq_data_t {
    uint32_t    seqnum_exp;
} ieee1722_seq_data_t;

/**************************************************************************************************/
/* 1722                                                                                           */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_SUBTYPE_61883             0x00
#define IEEE_1722_SUBTYPE_AAF               0x02
#define IEEE_1722_SUBTYPE_CVF               0x03
#define IEEE_1722_SUBTYPE_CRF               0x04
#define IEEE_1722_SUBTYPE_TSCF              0x05
#define IEEE_1722_SUBTYPE_NTSCF             0x82

/* Bit Field Masks */
#define IEEE_1722_SV_MASK        0x80
#define IEEE_1722_VER_MASK       0x70

/**************************************************************************************************/
/* subtype IEC 61883                                                                              */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_CIP_HEADER_SIZE           8
#define IEEE_1722_61883_TAG_NO_CIP          0x00
#define IEEE_1722_61883_TAG_CIP             0x40
#define IEEE_1722_61883_CHANNEL_AVTP        31
#define IEEE_1722_61883_SID_AVTP            63
#define IEEE_1722_61883_4_LEN_SOURCE_PACKET 192
#define IEEE_1722_61883_4_LEN_SP_TIMESTAMP  4
#define IEEE_1722_61883_4                   0x20
#define IEEE_1722_61883_6                   0x10

/* Bit Field Masks */
#define IEEE_1722_MR_MASK       0x08
#define IEEE_1722_GV_MASK       0x02
#define IEEE_1722_TV_MASK       0x01
#define IEEE_1722_TU_MASK       0x01
#define IEEE_1722_TAG_MASK      0xc0
#define IEEE_1722_CHANNEL_MASK  0x3f
#define IEEE_1722_TCODE_MASK    0xf0
#define IEEE_1722_SY_MASK       0x0f
#define IEEE_1722_QI1_MASK      0xc0
#define IEEE_1722_SID_MASK      0x3f
#define IEEE_1722_FN_MASK       0xc0
#define IEEE_1722_QPC_MASK      0x38
#define IEEE_1722_SPH_MASK      0x04
#define IEEE_1722_QI2_MASK      0xc0
#define IEEE_1722_FMT_MASK      0x3f
#define IEEE_1722_FDF_TSF_MASK  0x80
#define IEEE_1722_FDF_MASK      0xf8

/**************************************************************************************************/
/* subtype AAF                                                                                    */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_AAF_FORMAT_USER                       0x00
#define IEEE_1722_AAF_FORMAT_FLOAT_32_BIT               0x01
#define IEEE_1722_AAF_FORMAT_INT_32_BIT                 0x02
#define IEEE_1722_AAF_FORMAT_INT_24_BIT                 0x03
#define IEEE_1722_AAF_FORMAT_INT_16_BIT                 0x04
#define IEEE_1722_AAF_FORMAT_AES3_32_BIT                0x05

/* Bit Field Masks */
#define IEEE_1722_MR_MASK                               0x08
#define IEEE_1722_TV_MASK                               0x01
#define IEEE_1722_SEQ_NUM_MASK                          0x0
#define IEEE_1722_TU_MASK                               0x01
#define IEEE_1722_STREAM_ID_MASK                        0x0
#define IEEE_1722_TIMESTAMP_MASK                        0x0
#define IEEE_1722_FORMAT_MASK                           0x0
#define IEEE_1722_NOM_SAMPLE_RATE_MASK                  0xf000
#define IEEE_1722_CHANNEL_PER_FRAME_MASK                0x03ff
#define IEEE_1722_BIT_DEPTH_MASK                        0x0
#define IEEE_1722_AES3_DATA_TYPE_H_MASK                 0x0
#define IEEE_1722_STREAM_DATA_LENGTH_MASK               0x0
#define IEEE_1722_AES3_DATA_TYPE_REFERENCE_MASK         0xe0
#define IEEE_1722_SP_MASK                               0x10
#define IEEE_1722_EVT_MASK                              0x0f
#define IEEE_1722_AES3_DATA_TYPE_L_MASK                 0x0
#define IEEE_1722_DATA_MASK                             0x0
#define IEEE_1722_SAMPLE_MASK                           0x0

/**************************************************************************************************/
/* subtype CVF                                                                                    */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_CVF_FORMAT_RFC                        0x02
#define IEEE_1722_CVF_FORMAT_SUBTYPE_MJPEG              0x0
#define IEEE_1722_CVF_FORMAT_SUBTYPE_H264               0x01
#define IEEE_1722_CVF_FORMAT_SUBTYPE_JPEG2000           0x02

/* More bit Field Masks */
#define IEEE_1722_FORMAT_SUBTYPE_MASK                   0x0
#define IEEE_1722_CVF_H264_TIMESTAMP_MASK               0x0
#define IEEE_1722_H264_PTV_MASK                         0x20
#define IEEE_1722_MARKER_BIT_MASK                       0x10

/**************************************************************************************************/
/* subtype CRF                                                                                    */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_CRF_TIMESTAMP_SIZE        8 /* size of the CRF timestamp in bytes */

/* Bit Field Masks */
#define IEEE_1722_MR_MASK                   0x08
#define IEEE_1722_FS_MASK                   0x02
#define IEEE_1722_TU_MASK                   0x01
#define IEEE_1722_PULL_MASK                 0xe0000000
#define IEEE_1722_BASE_FREQUENCY_MASK       0x1fffffff

/**************************************************************************************************/
/* subtype NTSCF                                                                                  */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_NTSCF_HEADER_SIZE                     12      /* including common header */

/* Bit Field Masks */
#define IEEE_1722_NTSCF_R_MASK                          0x0800
#define IEEE_1722_NTSCF_DATA_LENGTH_MASK                0x07ff
#define IEEE_1722_NTSCF_SEQ_NUM_MASK                    0xff
#define IEEE_1722_NTSCF_STREAM_ID_MASK                  0x00

/**************************************************************************************************/
/* subtype TSCF                                                                                   */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_TSCF_HEADER_SIZE                      24      /* including common header */

/* Bit Field Masks */
#define IEEE_1722_TSCF_MR_MASK                          0x08
#define IEEE_1722_TSCF_RSV1_MASK                        0x06
#define IEEE_1722_TSCF_TV_MASK                          0x01
#define IEEE_1722_TSCF_SEQNUM_MASK                      0x0
#define IEEE_1722_TSCF_RSV2_MASK                        0xFE
#define IEEE_1722_TSCF_TU_MASK                          0x01
#define IEEE_1722_TSCF_STREAM_ID_MASK                   0x0
#define IEEE_1722_TSCF_AVTP_TIMESTAMP_MASK              0x0
#define IEEE_1722_TSCF_RSV3_MASK                        0x0
#define IEEE_1722_TSCF_DATA_LENGTH_MASK                 0x0
#define IEEE_1722_TSCF_RSV4_MASK                        0x0

/**************************************************************************************************/
/* AVTP Control Format (ACF) Message Header                                                       */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_ACF_HEADER_SIZE                       2

/* ACF message types */
#define IEEE_1722_ACF_TYPE_FLEXRAY                      0x00
#define IEEE_1722_ACF_TYPE_CAN                          0x01
#define IEEE_1722_ACF_TYPE_CAN_BRIEF                    0x02
#define IEEE_1722_ACF_TYPE_LIN                          0x03
#define IEEE_1722_ACF_TYPE_MOST                         0x04
#define IEEE_1722_ACF_TYPE_GPC                          0x05
#define IEEE_1722_ACF_TYPE_SERIAL                       0x06
#define IEEE_1722_ACF_TYPE_PARALLEL                     0x07
#define IEEE_1722_ACF_TYPE_SENSOR                       0x08
#define IEEE_1722_ACF_TYPE_SENSOR_BRIEF                 0x09
#define IEEE_1722_ACF_TYPE_AECP                         0x0A
#define IEEE_1722_ACF_TYPE_ANCILLARY                    0x0B
#define IEEE_1722_ACF_TYPE_USER0                        0x78
#define IEEE_1722_ACF_TYPE_USER1                        0x79
#define IEEE_1722_ACF_TYPE_USER2                        0x7A
#define IEEE_1722_ACF_TYPE_USER3                        0x7B
#define IEEE_1722_ACF_TYPE_USER4                        0x7C
#define IEEE_1722_ACF_TYPE_USER5                        0x7D
#define IEEE_1722_ACF_TYPE_USER6                        0x7E
#define IEEE_1722_ACF_TYPE_USER7                        0x7F

/* Bit Field Masks */
#define IEEE_1722_ACF_MSG_TYPE_MASK                     0xFE00
#define IEEE_1722_ACF_MSG_LENGTH_MASK                   0x01FF

/**************************************************************************************************/
/* ACF CAN Message                                                                                */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_ACF_CAN_BRIEF_HEADER_SIZE             6
#define IEEE_1722_ACF_CAN_HEADER_SIZE                   14

/* Bit Field Masks */
#define IEEE_1722_ACF_CAN_PAD_MASK                      0xC0u
#define IEEE_1722_ACF_CAN_FLAGS_MASK                    0x3Fu
#define IEEE_1722_ACF_CAN_MTV_MASK                      0x20u
#define IEEE_1722_ACF_CAN_RTR_MASK                      0x10u
#define IEEE_1722_ACF_CAN_EFF_MASK                      0x08u
#define IEEE_1722_ACF_CAN_BRS_MASK                      0x04u
#define IEEE_1722_ACF_CAN_FDF_MASK                      0x02u
#define IEEE_1722_ACF_CAN_ESI_MASK                      0x01u
#define IEEE_1722_ACF_CAN_RSV1_MASK                     0xE0u
#define IEEE_1722_ACF_CAN_BUS_ID_MASK                   0x1Fu
#define IEEE_1722_ACF_CAN_MSG_TIMESTAMP_MASK            0x00u
#define IEEE_1722_ACF_CAN_RSV2_MASK                     0xE0000000u
#define IEEE_1722_ACF_CAN_IDENTIFIER_MASK               0x1FFFFFFFu
#define IEEE_1722_ACF_CAN_11BIT_ID_MASK                 0x7FFu

/* Definitions to forge socketcan frame from acf-can message */
#define SOCKETCAN_HEADER_SIZE       8
#define SOCKETCAN_PAYLOAD_SIZE      8
#define SOCKETCANFD_PAYLOAD_SIZE    64
#define SOCKETCAN_FRAME_SIZE        (SOCKETCAN_HEADER_SIZE + SOCKETCAN_PAYLOAD_SIZE)
#define SOCKETCANFD_FRAME_SIZE      (SOCKETCAN_HEADER_SIZE + SOCKETCANFD_PAYLOAD_SIZE)
#define SOCKETCAN_MAX_FRAME_SIZE    SOCKETCANFD_FRAME_SIZE
#define SOCKETCAN_BRS_FLAG          0x01
#define SOCKETCAN_ESI_FLAG          0x02


/**************************************************************************************************/
/* ACF LIN Message                                                                                */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_ACF_LIN_HEADER_SIZE                   10

/* Bit Field Masks */
#define IEEE_1722_ACF_LIN_PAD_MASK                      0xC0
#define IEEE_1722_ACF_LIN_MTV_MASK                      0x20
#define IEEE_1722_ACF_LIN_BUS_ID_MASK                   0x1F
#define IEEE_1722_ACF_LIN_IDENTIFIER_MASK               0x0
#define IEEE_1722_ACF_LIN_MSG_TIMESTAMP_MASK            0x0

/**************************************************************************************************/
/* 1722                                                                                           */
/*                                                                                                */
/**************************************************************************************************/
static const range_string subtype_range_rvals[] = {
    { 0,    0,      "IEC 61883/IIDC Format" },
    { 1,    1,      "MMA Streams" },
    { 2,    2,      "AVTP Audio Format" },
    { 3,    3,      "Compressed Video Format" },
    { 4,    4,      "Clock Reference Format" },
    { 5,    5,      "Time Synchronous Control Format" },
    { 6,    6,      "SDI Video Format" },
    { 7,    7,      "Raw Video Format" },
    { 8,    0x6d,   "Reserved for future protocols" },
    { 0x6e, 0x6e,   "AES Encrypted Format Continuous" },
    { 0x6f, 0x6f,   "Vendor Specific Format Stream" },
    { 0x70, 0x7e,   "Reserved for future protocols" },
    { 0x7f, 0x7f,   "Experimental Format Stream" },
    { 0x80, 0x81,   "Reserved for future protocols" },
    { 0x82, 0x82,   "Non Time Synchronous Control Format" },
    { 0x83, 0xeb,   "Reserved for future protocols" },
    { 0xec, 0xec,   "ECC Signed Control Format" },
    { 0xed, 0xed,   "ECC Encrypted Control Format" },
    { 0xee, 0xee,   "AES Encrypted Format Discrete" },
    { 0xef, 0xf9,   "Reserved for future protocols" },
    { 0xfa, 0xfa,   "AVDECC Discovery Protocol" },
    { 0xfb, 0xfb,   "AVDECC Enumeration and Control Protocol" },
    { 0xfc, 0xfc,   "AVDECC Connection Management Protocol" },
    { 0xfd, 0xfd,   "Reserved for future protocols" },
    { 0xfe, 0xfe,   "MAAP" },
    { 0xff, 0xff,   "Experimental Format Control" },
    { 0,    0,      NULL }
};

/* Initialize the protocol and registered fields          */
static int proto_1722;
static int hf_1722_encap_seqnum;
static int hf_1722_subtype;
static int hf_1722_svfield;
static int hf_1722_verfield;

/* Initialize the subtree pointers */
static int ett_1722;

static expert_field ei_1722_encap_seqnum_dup;
static expert_field ei_1722_encap_seqnum_ooo;

static dissector_table_t avb_dissector_table;

/**************************************************************************************************/
/* subtype IEC 61883                                                                              */
/*                                                                                                */
/**************************************************************************************************/
static const value_string tag_vals [] = {
    {0, "No CIP header included"},
    {1, "CIP header included"},
    {2, "Reserved by IEEE 1394.1 clock adjustment"},
    {3, "Global asynchronous stream packet format"},
    {0, NULL}
};

static const range_string format_rvals [] = {
    {0,                 0,                  "DVCR transmission"},
    {1,                 0x0f,               "Reserved"},
    {IEEE_1722_61883_4, IEEE_1722_61883_4,  "IEC 61883-4: MPEG2-TS data transmission"},
    {0x11,              0x1d,               "Reserved"},
    {0x1e,              0x1e,               "Free (vendor unique)"},
    {0x1f,              0x1f,               "Reserved"},
    {IEEE_1722_61883_6, IEEE_1722_61883_6,  "IEC 61883-6: Audio and music transmission"},
    {0x21,              0x21,               "ITU-R B0.1294 System B transmission"},
    {0x22,              0x2d,               "Reserved"},
    {0x3e,              0x3e,               "Free (vendor unique)"},
    {0x3f,              0x3f,               "No data"},
    {0,                 0,                  NULL}
};

static const value_string fraction_number_vals [] = {
    {0,    "Not divided"},
    {1,    "Divided into 2 datablocks"},
    {2,    "Divided into 4 datablocks"},
    {3,    "Divided into 8 datablocks"},
    {0,    NULL}
};

static const range_string fdf_rvals [] = {
    {0x00, 0x07,    "Basic format for AM824"},
    {0x08, 0x0f,    "Basic format for AM824. Transmission rate may be controlled by an AV/C command set"},
    {0x10, 0x17,    "Basic format for 24-bit*4 audio pack"},
    {0x18, 0x1f,    "Reserved"},
    {0x20, 0x27,    "Basic format for 32-bit floating-point data"},
    {0x28, 0x2f,    "Reserved"},
    {0x30, 0x37,    "Basic format for 32-bit generic data"},
    {0x38, 0x3f,    "Reserved"},
    {0x40, 0xfe,    "Reserved"},
    {0xff, 0xff,    "Packet for NO-DATA"},
    {0,    0,       NULL}
};

static const range_string syt_rvals [] = {
    {0x0000, 0x0bff,    "Timestamp"},
    {0x0c00, 0x0fff,    "Reserved"},
    {0x1000, 0x1bff,    "Timestamp"},
    {0x1c00, 0x1fff,    "Reserved"},
    {0x2000, 0x2bff,    "Timestamp"},
    {0x2c00, 0x2fff,    "Reserved"},
    {0x3000, 0x3bff,    "Timestamp"},
    {0x3c00, 0x3fff,    "Reserved"},
    {0x4000, 0x4bff,    "Timestamp"},
    {0x4c00, 0x4fff,    "Reserved"},
    {0x5000, 0x5bff,    "Timestamp"},
    {0x5c00, 0x5fff,    "Reserved"},
    {0x6000, 0x6bff,    "Timestamp"},
    {0x6c00, 0x6fff,    "Reserved"},
    {0x7000, 0x7bff,    "Timestamp"},
    {0x7c00, 0x7fff,    "Reserved"},
    {0x8000, 0x8bff,    "Timestamp"},
    {0x8c00, 0x8fff,    "Reserved"},
    {0x9000, 0x9bff,    "Timestamp"},
    {0x9c00, 0x9fff,    "Reserved"},
    {0xa000, 0xabff,    "Timestamp"},
    {0xac00, 0xafff,    "Reserved"},
    {0xb000, 0xbbff,    "Timestamp"},
    {0xbc00, 0xbfff,    "Reserved"},
    {0xc000, 0xcbff,    "Timestamp"},
    {0xcc00, 0xcfff,    "Reserved"},
    {0xd000, 0xdbff,    "Timestamp"},
    {0xdc00, 0xdfff,    "Reserved"},
    {0xe000, 0xebff,    "Timestamp"},
    {0xec00, 0xefff,    "Reserved"},
    {0xf000, 0xfbff,    "Timestamp"},
    {0xfc00, 0xfffe,    "Reserved"},
    {0xffff, 0xffff,    "No information"},
    {0,      0,         NULL}
};

/* Initialize the protocol and registered fields          */
static int proto_1722_61883;
static int hf_1722_61883_mrfield;
static int hf_1722_61883_gvfield;
static int hf_1722_61883_tvfield;
static int hf_1722_61883_seqnum;
static int hf_1722_61883_tufield;
static int hf_1722_61883_stream_id;
static int hf_1722_61883_avtp_timestamp;
static int hf_1722_61883_gateway_info;
static int hf_1722_61883_stream_data_length;
static int hf_1722_61883_tag;
static int hf_1722_61883_channel;
static int hf_1722_61883_tcode;
static int hf_1722_61883_sy;
static int hf_1722_61883_cip_qi1;
static int hf_1722_61883_cip_sid;
static int hf_1722_61883_cip_dbs;
static int hf_1722_61883_cip_fn;
static int hf_1722_61883_cip_qpc;
static int hf_1722_61883_cip_sph;
static int hf_1722_61883_cip_dbc;
static int hf_1722_61883_cip_qi2;
static int hf_1722_61883_cip_fmt;
static int hf_1722_61883_cip_fdf_no_syt;
static int hf_1722_61883_cip_fdf_tsf;
static int hf_1722_61883_cip_fdf;
static int hf_1722_61883_cip_syt;
static int hf_1722_61883_audio_data;
static int hf_1722_61883_label;
static int hf_1722_61883_sample;
static int hf_1722_61883_video_data;
static int hf_1722_61883_source_packet_header_timestamp;

/* Initialize the subtree pointers */
static int ett_1722_61883;
static int ett_1722_61883_audio;
static int ett_1722_61883_sample;
static int ett_1722_61883_video;

/* Initialize expert fields */
static expert_field ei_1722_61883_incorrect_tag;
static expert_field ei_1722_61883_incorrect_tcode;
static expert_field ei_1722_61883_incorrect_qi1;
static expert_field ei_1722_61883_incorrect_qpc;
static expert_field ei_1722_61883_incorrect_qi2;
static expert_field ei_1722_61883_unknown_format;
static expert_field ei_1722_61883_incorrect_channel_sid;
static expert_field ei_1722_61883_incorrect_datalen;
static expert_field ei_1722_61883_4_incorrect_cip_fn;
static expert_field ei_1722_61883_4_incorrect_cip_dbs;
static expert_field ei_1722_61883_4_incorrect_cip_sph;
static expert_field ei_1722_61883_6_incorrect_cip_fn;
static expert_field ei_1722_61883_6_incorrect_cip_sph;
static expert_field ei_1722_61883_incorrect_cip_fdf;

/**************************************************************************************************/
/* subtype AAF                                                                                    */
/*                                                                                                */
/**************************************************************************************************/
static const range_string aaf_format_range_rvals [] = {
    {0, 0,      "User specified"},
    {1, 1,      "32bit floating point"},
    {2, 2,      "32bit integer"},
    {3, 3,      "24bit integer"},
    {4, 4,      "16bit integer"},
    {5, 5,      "32bit AES3 format"},
    {6, 0xff,   "Reserved"},
    {0, 0,      NULL}
};

static const range_string aaf_nominal_sample_rate_range_rvals [] = {
    {0,    0,       "User specified"},
    {1,    1,       "8kHz"},
    {2,    2,       "16kHz"},
    {3,    3,       "32kHz"},
    {4,    4,       "44.1kHz"},
    {5,    5,       "48kHz"},
    {6,    6,       "88.2kHz"},
    {7,    7,       "96kHz"},
    {8,    8,       "176.4kHz"},
    {9,    9,       "192kHz"},
    {0xa, 0xa,      "24kHz"},
    {0xb, 0xf,      "Reserved"},
    {0,    0,       NULL}
};

static const value_string aaf_sparse_timestamp_vals [] = {
    {0,     "Normal operation, timestamp in every AAF AVTPDU"},
    {1,     "Sparse mode, timestamp in every eighth AAF AVTPDU"},
    {0,     NULL}
};

/* Initialize the protocol and registered fields          */
static int proto_1722_aaf;
static int hf_1722_aaf_mrfield;
static int hf_1722_aaf_tvfield;
static int hf_1722_aaf_seqnum;
static int hf_1722_aaf_tufield;
static int hf_1722_aaf_stream_id;
static int hf_1722_aaf_avtp_timestamp;
static int hf_1722_aaf_format;
static int hf_1722_aaf_nominal_sample_rate;
static int hf_1722_aaf_bit_depth;
static int hf_1722_aaf_stream_data_length;
static int hf_1722_aaf_sparse_timestamp;
static int hf_1722_aaf_evtfield;
static int hf_1722_aaf_reserved;
static int hf_1722_aaf_channels_per_frame;
static int hf_1722_aaf_data;
static int hf_1722_aaf_sample;

/* Initialize the subtree pointers */
static int ett_1722_aaf;
static int ett_1722_aaf_audio;
static int ett_1722_aaf_sample;

/* Initialize expert fields */
static expert_field ei_aaf_sample_width;
static expert_field ei_aaf_reserved_format;
static expert_field ei_aaf_aes3_format;
static expert_field ei_aaf_channels_per_frame;
static expert_field ei_aaf_incorrect_bit_depth;

/**************************************************************************************************/
/* subtype CRF                                                                                    */
/*                                                                                                */
/**************************************************************************************************/
static const range_string crf_pull_range_rvals [] = {
    {0, 0,  "[1.0]"},
    {1, 1,  "[1/1.001]"},
    {2, 2,  "[1.001]"},
    {3, 3,  "[24/25]"},
    {4, 4,  "[25/24]"},
    {5, 5,  "[1/8]"},
    {6, 7,  "Reserved"},
    {0, 0,  NULL}
};

static const range_string crf_type_range_rvals [] = {
    {0, 0,      "User Specified"},
    {1, 1,      "Audio Sample Timestamp"},
    {2, 2,      "Video Frame Sync Timestamp"},
    {3, 3,      "Video Line Sync Timestamp"},
    {4, 4,      "Machine Cycle Timestamp"},
    {5, 0xff,   "Reserved"},
    {0, 0,      NULL}
};

/* Initialize the protocol and registered fields          */
static int proto_1722_crf;
static int hf_1722_crf_mrfield;
static int hf_1722_crf_fsfield;
static int hf_1722_crf_tufield;
static int hf_1722_crf_seqnum;
static int hf_1722_crf_type;
static int hf_1722_crf_stream_id;
static int hf_1722_crf_pull;
static int hf_1722_crf_base_frequency;
static int hf_1722_crf_data_length;
static int hf_1722_crf_timestamp_interval;
static int hf_1722_crf_timestamp_data;
static int hf_1722_crf_timestamp;

/* Initialize the subtree pointers */
static int ett_1722_crf;
static int ett_1722_crf_timestamp;

/* Initialize expert fields */
static expert_field ei_crf_datalen;

/**************************************************************************************************/
/* subtype CVF                                                                                    */
/*                                                                                                */
/**************************************************************************************************/
static const range_string cvf_format_range_rvals [] = {
    {0, 1,      "Reserved"},
    {2, 2,      "RFC payload type"},
    {3, 0xff,   "Reserved"},
    {0, 0,      NULL}
};

static const range_string cvf_format_subtype_range_rvals [] = {
    {0, 0,      "MJPEG Format (RFC 2435)"},
    {1, 1,      "H.264 Format (RFC 6184)"},
    {2, 2,      "JPEG 2000 Video (RFC 5371)"},
    {3, 0xff,   "Reserved"},
    {0, 0,      NULL}
};

/* Initialize the protocol and registered fields          */

static int proto_1722_cvf;
static int hf_1722_cvf_mrfield;
static int hf_1722_cvf_tvfield;
static int hf_1722_cvf_seqnum;
static int hf_1722_cvf_tufield;
static int hf_1722_cvf_stream_id;
static int hf_1722_cvf_avtp_timestamp;
static int hf_1722_cvf_format;
static int hf_1722_cvf_format_subtype;
static int hf_1722_cvf_stream_data_length;
static int hf_1722_cvf_evtfield;
static int hf_1722_cvf_marker_bit;
static int hf_1722_cvf_h264_ptvfield;
static int hf_1722_cvf_h264_timestamp;

/* Initialize the subtree pointers */
static int ett_1722_cvf;

/* Initialize expert fields */
static expert_field ei_cvf_jpeg2000_format;
static expert_field ei_cvf_reserved_format;
static expert_field ei_cvf_invalid_data_length;

/**************************************************************************************************/
/* subtype NTSCF                                                                                  */
/*                                                                                                */
/**************************************************************************************************/

/* Initialize the protocol and registered fields          */
static int proto_1722_ntscf;
static int hf_1722_ntscf_rfield;
static int hf_1722_ntscf_data_length;
static int hf_1722_ntscf_seqnum;
static int hf_1722_ntscf_stream_id;

/* Initialize the subtree pointers */
static int ett_1722_ntscf;

/* Initialize expert fields */
static expert_field ei_1722_ntscf_no_space_for_header;
static expert_field ei_1722_ntscf_invalid_data_length;

/**************************************************************************************************/
/* subtype TSCF                                                                                   */
/*                                                                                                */
/**************************************************************************************************/

/* Initialize the protocol and registered fields          */
static int proto_1722_tscf;
static int hf_1722_tscf_mr;
static int hf_1722_tscf_rsv1;
static int hf_1722_tscf_tv;
static int hf_1722_tscf_seqnum;
static int hf_1722_tscf_rsv2;
static int hf_1722_tscf_tu;
static int hf_1722_tscf_stream_id;
static int hf_1722_tscf_avtp_timestamp;
static int hf_1722_tscf_rsv3;
static int hf_1722_tscf_data_length;
static int hf_1722_tscf_rsv4;

/* Initialize the subtree pointers */
static int ett_1722_tscf;
static int ett_1722_tscf_flags;
static int ett_1722_tscf_tu;

/* Initialize expert fields */
static expert_field ei_1722_tscf_no_space_for_header;
static expert_field ei_1722_tscf_invalid_data_length;


/**************************************************************************************************/
/* AVTP Control Format (ACF) Message Header                                                       */
/*                                                                                                */
/**************************************************************************************************/

static const range_string acf_msg_type_range_rvals [] = {
    {0x00, 0x00,    "FlexRay"},
    {0x01, 0x01,    "CAN"},
    {0x02, 0x02,    "CAN Brief"},
    {0x03, 0x03,    "LIN"},
    {0x04, 0x04,    "MOST"},
    {0x05, 0x05,    "General purpose control"},
    {0x06, 0x06,    "Serial port"},
    {0x07, 0x07,    "Parallel port"},
    {0x08, 0x08,    "Analog sensor"},
    {0x09, 0x09,    "Abbreviated sensor"},
    {0x0A, 0x0A,    "IEEE Std 1722.1 AECP"},
    {0x0B, 0x0B,    "Video ancillary data"},
    {0x0C, 0x77,    "Reserved"},
    {0x78, 0x7F,    "User-defined"},
    {0, 0,      NULL}
};

/* Initialize the protocol and registered fields          */
static int proto_1722_acf;
static int hf_1722_acf_msg_type;
static int hf_1722_acf_msg_length;

/* Initialize the subtree pointers */
static int ett_1722_acf;
static int ett_1722_acf_header;

/* Initialize expert fields */
static expert_field ei_1722_acf_invalid_msg_length;
static expert_field ei_1722_acf_message_is_cropped;

/* Dissector handles */
static dissector_handle_t  avb1722_acf_handle;
static dissector_table_t   avb1722_acf_dissector_table;

/**************************************************************************************************/
/* ACF CAN Message                                                                                */
/*                                                                                                */
/**************************************************************************************************/

typedef struct {
    uint32_t    id;
    uint32_t    bus_id;
    unsigned    datalen;
    bool        is_fd;
    bool        is_xtd;
    bool        is_rtr;
    bool        is_brs;
    bool        is_esi;
} acf_can_t;

/* Initialize the protocol and registered fields          */
static int proto_1722_acf_can;
static int hf_1722_can_flags;
static int hf_1722_can_pad;
static int hf_1722_can_len;
static int hf_1722_can_mtvfield;
static int hf_1722_can_rtrfield;
static int hf_1722_can_efffield;
static int hf_1722_can_brsfield;
static int hf_1722_can_fdffield;
static int hf_1722_can_esifield;
static int hf_1722_can_rsv1;
static int hf_1722_can_bus_id;
static int hf_1722_can_message_timestamp;
static int hf_1722_can_rsv2;
static int hf_1722_can_identifier;
static int hf_1722_can_padding;

/* Initialize the subtree pointers */
static int ett_can;
static int ett_1722_can;
static int ett_1722_can_flags;
static int ett_1722_can_bus_id;
static int ett_1722_can_msg_id;

/* Initialize expert fields */
static expert_field ei_1722_can_header_cropped;
static expert_field ei_1722_can_invalid_message_id;
static expert_field ei_1722_can_invalid_payload_length;
static expert_field ei_1722_canfd_invalid_payload_length;

/* Dissector handles */
static dissector_handle_t avb1722_can_brief_handle;
static dissector_handle_t avb1722_can_handle;

static int                      proto_can;
static int                      proto_canfd;
static bool                 can_heuristic_first;

/**************************************************************************************************/
/* ACF LIN Message                                                                                */
/*                                                                                                */
/**************************************************************************************************/

/* Initialize the protocol and registered fields          */
static int proto_1722_acf_lin;
static int hf_1722_lin_pad;
static int hf_1722_lin_mtv;
static int hf_1722_lin_bus_id;
static int hf_1722_lin_identifier;
static int hf_1722_lin_message_timestamp;
static int hf_1722_lin_padding;

/* Initialize the subtree pointers */
static int ett_1722_lin;
static int ett_1722_lin_flags;

/* Initialize expert fields */
static expert_field ei_1722_lin_header_cropped;
static expert_field ei_1722_lin_invalid_payload_length;

static dissector_table_t avb1722_acf_lin_dissector_table;

/**************************************************************************************************/
/* 1722 dissector implementation                                                                  */
/*                                                                                                */
/**************************************************************************************************/

static uint32_t
get_seqnum_exp_1722_udp(packet_info *pinfo, const uint32_t seqnum)
{
    conversation_t *conv;
    ieee1722_seq_data_t *conv_seq_data, *p_seq_data;

    if (!PINFO_FD_VISITED(pinfo)) {
        conv = find_or_create_conversation(pinfo);
        conv_seq_data = (ieee1722_seq_data_t *)conversation_get_proto_data(conv, proto_1722);
        if (conv_seq_data == NULL) {
            conv_seq_data = wmem_new(wmem_file_scope(), ieee1722_seq_data_t);
            conv_seq_data->seqnum_exp = seqnum;

            conversation_add_proto_data(conv, proto_1722, conv_seq_data);
        } else {
            conv_seq_data->seqnum_exp++;
        }
        p_seq_data = wmem_new(wmem_file_scope(), ieee1722_seq_data_t);
        p_seq_data->seqnum_exp = conv_seq_data->seqnum_exp;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_1722, 0, p_seq_data);

    } else {
        p_seq_data = (ieee1722_seq_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_1722, 0);
    }
    DISSECTOR_ASSERT(p_seq_data != NULL);
    return p_seq_data->seqnum_exp;
}

static int dissect_1722_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, enum IEEE_1722_TRANSPORT transport)
{
    tvbuff_t   *next_tvb;
    proto_item *ti;
    proto_tree *ieee1722_tree;
    uint32_t    encap_seqnum, encap_seqnum_exp;
    unsigned    subtype = 0;
    int         offset = 0;
    int         dissected_size;
    static int * const fields[] = {
        &hf_1722_svfield,
        &hf_1722_verfield,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE1722");
    col_set_str(pinfo->cinfo, COL_INFO, "Audio Video Transport Protocol");

    ti = proto_tree_add_item(tree, proto_1722, tvb, 0, -1, ENC_NA);
    ieee1722_tree = proto_item_add_subtree(ti, ett_1722);

    if (transport == IEEE_1722_TRANSPORT_UDP) {
        /* IEEE 1722-2016 Annex J IP Encapsulation */
        ti = proto_tree_add_item_ret_uint(ieee1722_tree, hf_1722_encap_seqnum, tvb, offset, 4, ENC_BIG_ENDIAN, &encap_seqnum);
        encap_seqnum_exp = get_seqnum_exp_1722_udp(pinfo, encap_seqnum);
        if (encap_seqnum != encap_seqnum_exp) {
            if ((encap_seqnum + 1) == encap_seqnum_exp) {
                expert_add_info(pinfo, ti, &ei_1722_encap_seqnum_dup);
            } else {
                expert_add_info(pinfo, ti, &ei_1722_encap_seqnum_ooo);
            }
        }
        offset += 4;
        next_tvb = tvb_new_subset_remaining(tvb, offset);
    } else {
        next_tvb = tvb;
    }

    proto_tree_add_item_ret_uint(ieee1722_tree, hf_1722_subtype, tvb, offset, 1, ENC_BIG_ENDIAN, &subtype);
    offset += 1;
    proto_tree_add_bitmask_list(ieee1722_tree, tvb, offset, 1, fields, ENC_NA);

    /* call any registered subtype dissectors which use only the common AVTPDU (e.g. 1722.1, MAAP, 61883, AAF, CRF or CVF) */
    dissected_size = dissector_try_uint(avb_dissector_table, subtype, next_tvb, pinfo, tree);
    if (dissected_size > 0) {
        return dissected_size;
    }

    call_data_dissector(next_tvb, pinfo, ieee1722_tree);
    return tvb_captured_length(tvb);
}

static int dissect_1722_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_1722_common(tvb, pinfo, tree, IEEE_1722_TRANSPORT_ETH);
}

static int dissect_1722_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_1722_common(tvb, pinfo, tree, IEEE_1722_TRANSPORT_UDP);
}

/* Register the protocol with Wireshark */
void proto_register_1722(void)
{
    static hf_register_info hf[] = {
        { &hf_1722_encap_seqnum,
            { "Encapsulation Sequence Number", "ieee1722.encapsulation_sequence_num",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              "Sequence number incremented for each AVTPDU on a 5-tuple", HFILL }
        },
        { &hf_1722_subtype,
            { "AVTP Subtype", "ieee1722.subtype",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(subtype_range_rvals), 0x0, NULL, HFILL }
        },
        { &hf_1722_svfield,
            { "AVTP Stream ID Valid", "ieee1722.svfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_SV_MASK, NULL, HFILL }
        },
        { &hf_1722_verfield,
            { "AVTP Version", "ieee1722.verfield",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_VER_MASK, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_1722_encap_seqnum_dup,          { "ieee1722.encapsulation_sequence_num.dup", PI_SEQUENCE, PI_NOTE, "Duplicate encapsulation_sequence_num (retransmission?)", EXPFILL }},
        { &ei_1722_encap_seqnum_ooo,          { "ieee1722.encapsulation_sequence_num.ooo", PI_SEQUENCE, PI_WARN, "Unexpected encapsulation_sequence_num (lost or out-of-order?)", EXPFILL }},
    };

    static int *ett[] = {
        &ett_1722
    };

    expert_module_t *expert_1722;

    /* Register the protocol name and description */
    proto_1722 = proto_register_protocol("IEEE 1722 Audio Video Transport Protocol (AVTP)", "IEEE1722", "ieee1722");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722 = expert_register_protocol(proto_1722);
    expert_register_field_array(expert_1722, ei, array_length(ei));

    /* Sub-dissector for 1722.1, 1722 AAF, 1722 CRF, 1722 61883, 1722 CVF */
    avb_dissector_table = register_dissector_table("ieee1722.subtype",
                          "IEEE1722 AVTP Subtype", proto_1722, FT_UINT8, BASE_HEX);

    avtp_handle_eth = register_dissector("ieee1722.eth", dissect_1722_eth, proto_1722);
    avtp_handle_udp = register_dissector("ieee1722.udp", dissect_1722_udp, proto_1722);
}

void proto_reg_handoff_1722(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_AVTP, avtp_handle_eth);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_IEEE_1722, avtp_handle_udp);
}

/**************************************************************************************************/
/* IEC 61883 dissector implementation                                                             */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722_61883(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *ti_61883_tree;
    proto_tree *ti_channel;
    proto_tree *ti_datalen;
    proto_tree *ti_cip_fn;
    proto_tree *ti_cip_dbs;
    proto_tree *ti_cip_sph;
    proto_tree *ti_cip_fmt;
    proto_tree *ti_cip_fdf;
    proto_tree *ti_audio_tree;
    proto_tree *ti_sample_tree;
    proto_tree *ti_video_tree;
    int         offset = 1;
    uint8_t     cip_dbs = 0;
    uint8_t     tag = 0;
    uint8_t     channel = 0;
    uint8_t     tcode = 0;
    uint8_t     cip_qi1 = 0;
    uint8_t     cip_sid = 0;
    uint8_t     cip_qpc = 0;
    uint8_t     cip_qi2 = 0;
    uint8_t     cip_fmt = 0;
    uint8_t     cip_sph = 0;
    uint8_t     cip_fn = 0;
    unsigned    datalen = 0;
    unsigned    db_size = 0;
    unsigned    numSourcePackets = 0;
    unsigned    i = 0;
    unsigned    j = 0;
    static int * const fields[] = {
        &hf_1722_61883_mrfield,
        &hf_1722_61883_gvfield,
        &hf_1722_61883_tvfield,
        NULL
    };

    ti = proto_tree_add_item(tree, proto_1722_61883, tvb, 0, -1, ENC_NA);
    ti_61883_tree = proto_item_add_subtree(ti, ett_1722_61883);

    proto_tree_add_bitmask_list(ti_61883_tree, tvb, offset, 1, fields, ENC_NA);
    offset += 1;
    proto_tree_add_item(ti_61883_tree, hf_1722_61883_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_61883_tree, hf_1722_61883_tufield, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_61883_tree, hf_1722_61883_stream_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(ti_61883_tree, hf_1722_61883_avtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ti_61883_tree, hf_1722_61883_gateway_info, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    ti_datalen = proto_tree_add_item_ret_uint(ti_61883_tree, hf_1722_61883_stream_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
    offset += 2;

    /* tag field defines if CIP header is included or not */
    ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_tag, tvb, offset, 1, ENC_BIG_ENDIAN);

    tag = tvb_get_uint8(tvb, offset) & IEEE_1722_TAG_MASK;
    if (tag > 0x40)
    {
        expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_tag);
    }

    ti_channel = proto_tree_add_item(ti_61883_tree, hf_1722_61883_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
    channel = tvb_get_uint8(tvb, offset) & IEEE_1722_CHANNEL_MASK;
    if (channel != IEEE_1722_61883_CHANNEL_AVTP)
    {
        proto_item_append_text(ti_channel, ": Originating Source ID from an IEEE 1394 serial bus");
    }
    else
    {
        proto_item_append_text(ti_channel, ": Originating source is on AVTP network (native AVTP)");
    }
    offset += 1;

    ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_tcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    tcode = tvb_get_uint8(tvb, offset) & IEEE_1722_TCODE_MASK;
    if (tcode != 0xa0)
    {
       expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_tcode);
    }

    proto_tree_add_item(ti_61883_tree, hf_1722_61883_sy, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (tag) {
    case IEEE_1722_61883_TAG_NO_CIP:
        proto_item_prepend_text(ti, "IIDC 1394 video payload:");
        break;
    case IEEE_1722_61883_TAG_CIP:
        ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_qi1, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_qi1 = tvb_get_uint8(tvb, offset) & IEEE_1722_QI1_MASK;
        if (cip_qi1 != 0)
        {
            expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_qi1);
        }

        ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_sid, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_sid = tvb_get_uint8(tvb, offset) & IEEE_1722_SID_MASK;
        if (cip_sid != IEEE_1722_61883_SID_AVTP)
        {
            proto_item_append_text(ti, ": Originating Source ID from an IEEE 1394 serial bus");
            if (channel == IEEE_1722_61883_CHANNEL_AVTP)
            {
                expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_channel_sid);
                expert_add_info(pinfo, ti_channel, &ei_1722_61883_incorrect_channel_sid);

            }
        }
        else
        {
            proto_item_append_text(ti, ": Originating source is on AVTP network");
            if (channel != IEEE_1722_61883_CHANNEL_AVTP)
            {
                expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_channel_sid);
                expert_add_info(pinfo, ti_channel, &ei_1722_61883_incorrect_channel_sid);
            }
        }
        offset += 1;

        ti_cip_dbs = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_dbs, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_dbs = tvb_get_uint8(tvb, offset);
        offset += 1;
        ti_cip_fn = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_fn, tvb, offset, 1, ENC_BIG_ENDIAN);

        switch (tvb_get_uint8(tvb, offset) & IEEE_1722_FN_MASK) {
        case 0:
            cip_fn = 0;
            break;
        case 0x40:
            cip_fn = 2;
            break;
        case 0x80:
            cip_fn = 4;
            break;
        case 0xc0:
            cip_fn = 8;
            break;
        default:
            break;
        }

        ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_qpc, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_qpc = tvb_get_uint8(tvb, offset) & IEEE_1722_QPC_MASK;
        if (cip_qpc != 0)
        {
            expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_qpc);
        }

        ti_cip_sph = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_sph, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_sph = tvb_get_uint8(tvb, offset) & IEEE_1722_SPH_MASK;
        offset += 1;
        proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_dbc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_qi2, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_qi2 = tvb_get_uint8(tvb, offset) & IEEE_1722_QI2_MASK;
        if (cip_qi2 != 0x80)
        {
            expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_qi2);
        }

        /* Check format field for 61883-4 MPEG-TS video or 61883-6 for audio */
        ti_cip_fmt = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_fmt, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_fmt = tvb_get_uint8(tvb, offset) & IEEE_1722_FMT_MASK;
        offset += 1;

        if ((cip_fmt & 0x20) == 0)
        {
            proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_fdf, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_syt, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        else
        {
            ti_cip_fdf = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_fdf_no_syt, tvb, offset, 3, ENC_BIG_ENDIAN);
            if (((tvb_get_ntoh24(tvb, offset) & 0x7fffff) != 0))
            {
                expert_add_info(pinfo, ti_cip_fdf, &ei_1722_61883_incorrect_cip_fdf);
            }

            proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_fdf_tsf, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
        }

        /* Calculate the remaining size by subtracting the CIP header size from the value in the packet data length field */
        datalen -= IEEE_1722_CIP_HEADER_SIZE;

        if (cip_dbs == 0) {
            db_size = 256;
        }
        else
        {
            db_size = cip_dbs;
        }

        switch (cip_fmt) {
        case IEEE_1722_61883_6:
            if (cip_fn != 0)
            {
                expert_add_info(pinfo, ti_cip_fn, &ei_1722_61883_6_incorrect_cip_fn);
            }
            if (cip_sph != 0)
            {
                expert_add_info(pinfo, ti_cip_sph, &ei_1722_61883_6_incorrect_cip_sph);
            }

            /* Make the Audio sample tree. */
            ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_audio_data, tvb, offset, datalen, ENC_NA);
            ti_audio_tree = proto_item_add_subtree(ti, ett_1722_61883_audio);
            if ((datalen % (db_size*4)) != 0)
            {
                expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_datalen);
                expert_add_info(pinfo, ti_datalen, &ei_1722_61883_incorrect_datalen);
            }
            numSourcePackets = datalen / (db_size*4);

            if (ti_audio_tree) {
                /* Loop through all samples and add them to the audio tree. */
                for (j = 0; j < numSourcePackets; j++) {
                    ti_sample_tree = proto_tree_add_subtree_format(ti_audio_tree, tvb, offset, 1, ett_1722_61883_sample, NULL, "Sample %d", j+1);
                    for (i = 0; i < db_size; i++) {
                        proto_tree_add_item(ti_sample_tree, hf_1722_61883_label, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(ti_sample_tree, hf_1722_61883_sample, tvb, offset, 3, ENC_NA);
                        offset += 3;
                    }
                }
            }
            break;
        case IEEE_1722_61883_4:
            if (db_size != 6)
            {
                expert_add_info(pinfo, ti_cip_dbs, &ei_1722_61883_4_incorrect_cip_dbs);
            }
            if (cip_fn != 8)
            {
                expert_add_info(pinfo, ti_cip_fn, &ei_1722_61883_4_incorrect_cip_fn);
            }
            if (cip_sph != 4)
            {
                expert_add_info(pinfo, ti_cip_sph, &ei_1722_61883_4_incorrect_cip_sph);
            }
            /* Make the video tree. */
            ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_video_data, tvb, offset, datalen, ENC_NA);
            ti_video_tree = proto_item_add_subtree(ti, ett_1722_61883_video);
            if ((datalen % IEEE_1722_61883_4_LEN_SOURCE_PACKET) != 0)
            {
                expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_datalen);
                expert_add_info(pinfo, ti_datalen, &ei_1722_61883_incorrect_datalen);
            }
            numSourcePackets = datalen / IEEE_1722_61883_4_LEN_SOURCE_PACKET;

            /* if (ti_video_tree) - MP2T needs to be called regardless
             * for fragmentation handling */
            for (j = 0; j < numSourcePackets; j++) {
                proto_tree_add_item(ti_video_tree, hf_1722_61883_source_packet_header_timestamp, tvb, offset, IEEE_1722_61883_4_LEN_SP_TIMESTAMP, ENC_BIG_ENDIAN);
                offset += IEEE_1722_61883_4_LEN_SP_TIMESTAMP;
                call_dissector(mp2t_handle, tvb_new_subset_length(tvb, offset, MP2T_PACKET_SIZE), pinfo, ti_video_tree);
                offset += MP2T_PACKET_SIZE;
            }
            break;
        default:
            expert_add_info(pinfo, ti_cip_fmt, &ei_1722_61883_unknown_format);
            break;
        }
        break;
    default:
        break;
    }
    return tvb_captured_length(tvb);
}

void proto_register_1722_61883(void)
{
    static hf_register_info hf[] = {
        { &hf_1722_61883_mrfield,
            { "Media Clock Restart", "iec61883.mrfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_MR_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_gvfield,
            { "Gateway Info Valid", "iec61883.gvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_GV_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_tvfield,
            { "Timestamp Valid", "iec61883.tvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TV_MASK, NULL, HFILL }
            },
        { &hf_1722_61883_seqnum,
            { "Sequence Number", "iec61883.seqnum",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_tufield,
            { "Timestamp Uncertain", "iec61883.tufield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TU_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_stream_id,
            { "Stream ID", "iec61883.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_avtp_timestamp,
            { "AVTP Timestamp", "iec61883.avtp_timestamp",
              FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_gateway_info,
            { "Gateway Info", "iec61883.gateway_info",
              FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_stream_data_length,
            { "1394 Stream Data Length", "iec61883.stream_data_len",
              FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_tag,
            { "1394 Packet Format Tag", "iec61883.tag",
              FT_UINT8, BASE_HEX, VALS(tag_vals), IEEE_1722_TAG_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_channel,
            { "1394 Packet Channel", "iec61883.channel",
                FT_UINT8, BASE_DEC, NULL, IEEE_1722_CHANNEL_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_tcode,
            { "1394 Packet Tcode", "iec61883.tcode",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_TCODE_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_sy,
            { "1394 App-specific Control", "iec61883.sy",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_SY_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_qi1,
            { "CIP Quadlet Indicator 1", "iec61883.qi1",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_QI1_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_sid,
            { "CIP Source ID", "iec61883.sid",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_SID_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_dbs,
            { "CIP Data Block Size", "iec61883.dbs",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fn,
            { "CIP Fraction Number", "iec61883.fn",
              FT_UINT8, BASE_HEX, VALS(fraction_number_vals), IEEE_1722_FN_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_qpc,
            { "CIP Quadlet Padding Count", "iec61883.qpc",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_QPC_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_sph,
            { "CIP Source Packet Header", "iec61883.sph",
              FT_BOOLEAN, 8, NULL, IEEE_1722_SPH_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_dbc,
            { "CIP Data Block Continuity", "iec61883.dbc",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_cip_qi2,
            { "CIP Quadlet Indicator 2", "iec61883.qi2",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_QI2_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fmt,
            { "CIP Format ID", "iec61883.fmt",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(format_rvals), IEEE_1722_FMT_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fdf_no_syt,
            { "CIP Format Dependent Field", "iec61883.fdf_no_syt",
              FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fdf_tsf,
            { "Time shift flag", "iec61883.fdf_tsf",
              FT_BOOLEAN, 8, NULL, IEEE_1722_FDF_TSF_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fdf,
            { "CIP Format Dependent Field", "iec61883.fdf",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(fdf_rvals), IEEE_1722_FDF_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_syt,
            { "CIP SYT", "iec61883.syt",
              FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(syt_rvals), 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_audio_data,
            { "Audio Data", "iec61883.audiodata",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_label,
            { "Label", "iec61883.audiodata.sample.label",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_sample,
            { "Sample", "iec61883.audiodata.sample.sampledata",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_video_data,
            { "Video Data", "iec61883.videodata",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_61883_source_packet_header_timestamp,
            { "Source Packet Header Timestamp", "iec61883.spht",
              FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_1722_61883,
        &ett_1722_61883_audio,
        &ett_1722_61883_sample,
        &ett_1722_61883_video
    };

    static ei_register_info ei[] = {
        { &ei_1722_61883_incorrect_tag,         { "iec61883.incorrect_tag", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect tag field, only 0x00 and 0x01 supported for AVTP", EXPFILL }},
        { &ei_1722_61883_incorrect_tcode,       { "iec61883.incorrect_tcode", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect tcode, talker shall set this field to 0x0A", EXPFILL }},
        { &ei_1722_61883_incorrect_qi1,         { "iec61883.incorrect_qi1", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect quadlet indicator 1 field, talker shall set this field to 0x00", EXPFILL }},
        { &ei_1722_61883_incorrect_qpc,         { "iec61883.incorrect_qpc", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect quadlet padding count field, shall be set to 0", EXPFILL }},
        { &ei_1722_61883_incorrect_qi2,         { "iec61883.incorrect_qi2", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect quadlet indicator 2 field, talker shall set this field to 0x02", EXPFILL }},
        { &ei_1722_61883_unknown_format,        { "iec61883.unknown_format", PI_PROTOCOL, PI_NOTE,
                                                  "IEC 61883 format not dissected yet", EXPFILL }},
        { &ei_1722_61883_incorrect_channel_sid, { "iec61883.incorrect_channel_sid", PI_PROTOCOL, PI_WARN,
                                                  "1394 Packet Channel and Source ID don`t match", EXPFILL }},
        { &ei_1722_61883_incorrect_datalen,     { "iec61883.incorrect_datalen", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect stream data length field, must be multiple of 192 plus 8 bytes CIP header", EXPFILL }},
        { &ei_1722_61883_4_incorrect_cip_fn,    { "iec61883.4_incorrect_cip_fn", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect fraction number, shall be 8 for IEC 61883-4", EXPFILL }},
        { &ei_1722_61883_4_incorrect_cip_dbs,   { "iec61883.4_incorrect_cip_dbs", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect data block size, shall be 6 for IEC 61883-4", EXPFILL }},
        { &ei_1722_61883_4_incorrect_cip_sph,   { "iec61883.4_incorrect_cip_sph", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect source packet header value, shall be 1 for IEC 61883-4", EXPFILL }},
        { &ei_1722_61883_6_incorrect_cip_fn,    { "iec61883.6_incorrect_cip_fn", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect fraction number, shall be 0 for IEC 61883-6", EXPFILL }},
        { &ei_1722_61883_6_incorrect_cip_sph,   { "iec61883.6_incorrect_cip_sph", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect source packet header value, shall be 0 for IEC 61883-6", EXPFILL }},
        { &ei_1722_61883_incorrect_cip_fdf,     { "iec61883.6_incorrect_cip_fdf", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect frame dependent field value, shall be 0", EXPFILL }}
    };

    expert_module_t* expert_1722_61883;

    /* Register the protocol name and description */
    proto_1722_61883 = proto_register_protocol("IEC 61883 Protocol", "IEC 61883", "iec61883");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_61883, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_1722_61883 = expert_register_protocol(proto_1722_61883);
    expert_register_field_array(expert_1722_61883, ei, array_length(ei));

    avb1722_61883_handle = register_dissector("iec61883", dissect_1722_61883, proto_1722_61883);
}

void proto_reg_handoff_1722_61883(void)
{
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_61883, avb1722_61883_handle);

    mp2t_handle = find_dissector_add_dependency("mp2t", proto_1722_61883);
}

/**************************************************************************************************/
/* 1722 AAF dissector implementation                                                              */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722_aaf (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *ti_aaf_tree;
    proto_tree *ti_channels_per_frame;
    proto_tree *ti_format;
    proto_tree *ti_audio_tree;
    proto_tree *ti_sample_tree;
    int         offset = 1;
    unsigned    datalen = 0;
    unsigned    channels_per_frame = 0;
    unsigned    bit_depth = 0;
    unsigned    sample_width = 0;
    unsigned    format = 0;
    unsigned    i = 0;
    unsigned    j = 0;
    static int * const fields[] = {
        &hf_1722_aaf_mrfield,
        &hf_1722_aaf_tvfield,
        NULL
    };
    static int * const fields_pcm[] = {
        &hf_1722_aaf_sparse_timestamp,
        &hf_1722_aaf_evtfield,
        NULL
    };

    ti = proto_tree_add_item(tree, proto_1722_aaf, tvb, 0, -1, ENC_NA);
    ti_aaf_tree = proto_item_add_subtree(ti, ett_1722_aaf);

    proto_tree_add_bitmask_list(ti_aaf_tree, tvb, offset, 1, fields, ENC_NA);
    offset += 1;
    proto_tree_add_item(ti_aaf_tree, hf_1722_aaf_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_aaf_tree, hf_1722_aaf_tufield, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_aaf_tree, hf_1722_aaf_stream_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(ti_aaf_tree, hf_1722_aaf_avtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    ti_format = proto_tree_add_item_ret_uint(ti_aaf_tree, hf_1722_aaf_format, tvb, offset, 1, ENC_BIG_ENDIAN, &format);
    offset += 1;
    switch (format)
    {
    case IEEE_1722_AAF_FORMAT_USER:
        break;
    case IEEE_1722_AAF_FORMAT_FLOAT_32_BIT:
        sample_width = 32;
        break;
    case IEEE_1722_AAF_FORMAT_INT_32_BIT:
        sample_width = 32;
        break;
    case IEEE_1722_AAF_FORMAT_INT_24_BIT:
        sample_width = 24;
        break;
    case IEEE_1722_AAF_FORMAT_INT_16_BIT:
        sample_width = 16;
        break;
    case IEEE_1722_AAF_FORMAT_AES3_32_BIT:
        sample_width = 32;
        break;
    default:
        break;
    }

    if (format < IEEE_1722_AAF_FORMAT_AES3_32_BIT)
    {
        /* PCM Format */
        proto_tree_add_item(ti_aaf_tree, hf_1722_aaf_nominal_sample_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
        ti_channels_per_frame = proto_tree_add_item_ret_uint(ti_aaf_tree, hf_1722_aaf_channels_per_frame, tvb, offset, 2, ENC_BIG_ENDIAN, &channels_per_frame);
        if (channels_per_frame == 0)
        {
            expert_add_info(pinfo, ti_channels_per_frame, &ei_aaf_channels_per_frame);
        }
        else
        {
            offset += 2;
            ti = proto_tree_add_item_ret_uint(ti_aaf_tree, hf_1722_aaf_bit_depth, tvb, offset, 1, ENC_BIG_ENDIAN, &bit_depth);
            if ((bit_depth == 0) || (bit_depth > sample_width))
            {
                expert_add_info(pinfo, ti, &ei_aaf_incorrect_bit_depth);
            }
            offset += 1;
            proto_tree_add_item_ret_uint(ti_aaf_tree, hf_1722_aaf_stream_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
            offset += 2;

            proto_tree_add_bitmask_list(ti_aaf_tree, tvb, offset, 1, fields_pcm, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(ti_aaf_tree, hf_1722_aaf_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Make the Audio sample tree. */
            ti            = proto_tree_add_item(ti_aaf_tree, hf_1722_aaf_data, tvb, offset, datalen, ENC_NA);
            ti_audio_tree = proto_item_add_subtree(ti, ett_1722_aaf_audio);

            if (sample_width == 0)
            {
                expert_add_info(pinfo, ti, &ei_aaf_sample_width);
            }
            else
            {
                /* Loop through all samples and add them to the audio tree. */
                for (j = 0; j < ((datalen * 8) / (channels_per_frame * sample_width)); j++)
                {
                    ti_sample_tree = proto_tree_add_subtree_format(ti_audio_tree, tvb, offset, 1,
                                         ett_1722_aaf_sample, NULL, "Sample Chunk %d", j);
                    for (i = 0; i < channels_per_frame; i++)
                    {
                        ti = proto_tree_add_item(ti_sample_tree, hf_1722_aaf_sample, tvb, offset, sample_width / 8, ENC_NA);
                        proto_item_prepend_text(ti, "Channel: %d ", i);
                        offset += (sample_width / 8);
                    }
                }
            }
        }
    }
    else if (format == IEEE_1722_AAF_FORMAT_AES3_32_BIT)
    {
        expert_add_info(pinfo, ti_format, &ei_aaf_aes3_format);
    }
    else
    {
        expert_add_info(pinfo, ti_format, &ei_aaf_reserved_format);
    }
    return tvb_captured_length(tvb);
}

void proto_register_1722_aaf (void)
{
    static hf_register_info hf[] =
    {
        { &hf_1722_aaf_mrfield,
            { "Media Clock Restart", "aaf.mrfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_MR_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_tvfield,
            { "Source Timestamp Valid", "aaf.tvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TV_MASK, NULL, HFILL }
            },
        { &hf_1722_aaf_seqnum,
            { "Sequence Number", "aaf.seqnum",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_SEQ_NUM_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_tufield,
            { "Timestamp Uncertain", "aaf.tufield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TU_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_stream_id,
            { "Stream ID", "aaf.stream_id",
              FT_UINT64, BASE_HEX, NULL, IEEE_1722_STREAM_ID_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_avtp_timestamp,
            { "AVTP Timestamp", "aaf.avtp_timestamp",
              FT_UINT32, BASE_DEC, NULL, IEEE_1722_TIMESTAMP_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_format,
            { "Format", "aaf.format_info",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(aaf_format_range_rvals), IEEE_1722_FORMAT_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_nominal_sample_rate,
            { "Nominal Sample Rate", "aaf.nominal_sample_rate",
              FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(aaf_nominal_sample_rate_range_rvals), IEEE_1722_NOM_SAMPLE_RATE_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_channels_per_frame,
            { "Channels per Frame", "aaf.channels_per_frame",
              FT_UINT16, BASE_DEC, NULL, IEEE_1722_CHANNEL_PER_FRAME_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_bit_depth,
            { "Bit Depth", "aaf.bit_depth",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_BIT_DEPTH_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_stream_data_length,
            { "Stream Data Length", "aaf.stream_data_len",
              FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, IEEE_1722_STREAM_DATA_LENGTH_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_sparse_timestamp,
            { "Sparse Timestamp Mode", "aaf.sparse_timestamp",
              FT_UINT8, BASE_DEC, VALS(aaf_sparse_timestamp_vals), IEEE_1722_SP_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_evtfield,
            { "EVT", "aaf.evtfield",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_EVT_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_reserved,
            { "Reserved", "aaf.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_aaf_data,
            { "Audio Data", "aaf.data",
              FT_BYTES, BASE_NONE, NULL, IEEE_1722_DATA_MASK, NULL, HFILL }
        },
        { &hf_1722_aaf_sample,
            { "Sample Data", "aaf.data.sample",
              FT_BYTES, BASE_NONE, NULL, IEEE_1722_SAMPLE_MASK, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_aaf_sample_width,          { "aaf.expert.sample_width_zero", PI_PROTOCOL, PI_WARN, "Sample_width of 0 can`t be dissected", EXPFILL }},
        { &ei_aaf_reserved_format,       { "aaf.expert.reserved_format", PI_PROTOCOL, PI_WARN, "Incorrect format, can`t be dissected", EXPFILL }},
        { &ei_aaf_aes3_format,           { "aaf.expert.aes3_format", PI_PROTOCOL, PI_WARN, "AES3 format is currently not supported", EXPFILL }},
        { &ei_aaf_channels_per_frame,    { "aaf.expert.channels_per_frame_zero", PI_PROTOCOL, PI_WARN, "Channels_per_frame value shall not be 0", EXPFILL }},
        { &ei_aaf_incorrect_bit_depth,   { "aaf.expert.incorrect_bit_depth", PI_PROTOCOL, PI_WARN, "Incorrect bit_depth value", EXPFILL }}
    };

    static int *ett[] =
    {
        &ett_1722_aaf,
        &ett_1722_aaf_audio,
        &ett_1722_aaf_sample,
    };

    expert_module_t *expert_1722_aaf;

    /* Register the protocol name and description */
    proto_1722_aaf = proto_register_protocol("AVTP Audio Format", "AAF", "aaf");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_aaf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722_aaf = expert_register_protocol(proto_1722_aaf);
    expert_register_field_array(expert_1722_aaf, ei, array_length(ei));

    avb1722_aaf_handle = register_dissector("aaf", dissect_1722_aaf, proto_1722_aaf);
}

void proto_reg_handoff_1722_aaf(void)
{
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_AAF, avb1722_aaf_handle);
}

/**************************************************************************************************/
/* 1722 CVF dissector implementation                                                              */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722_cvf (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *ti_cvf_tree;
    tvbuff_t   *next_tvb;
    int         offset = 1;
    unsigned    reported_len;
    uint32_t    datalen, format, format_subtype = 0;
    proto_tree *ti_format, *ti_datalen;

    static int * const fields[] = {
        &hf_1722_cvf_mrfield,
        &hf_1722_cvf_tvfield,
        NULL
    };

    static int * const fields_cvf[] = {
        &hf_1722_cvf_marker_bit,
        &hf_1722_cvf_evtfield,
        NULL
    };

    /* The PTV field is only defined for the H264 subtype,
     * reserved for others.
     */
    static int * const fields_h264[] = {
        &hf_1722_cvf_h264_ptvfield,
        &hf_1722_cvf_marker_bit,
        &hf_1722_cvf_evtfield,
        NULL
    };

    ti = proto_tree_add_item(tree, proto_1722_cvf, tvb, 0, 24, ENC_NA);
    ti_cvf_tree = proto_item_add_subtree(ti, ett_1722_cvf);

    proto_tree_add_bitmask_list(ti_cvf_tree, tvb, offset, 1, fields, ENC_NA);
    offset += 1;
    proto_tree_add_item(ti_cvf_tree, hf_1722_cvf_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_cvf_tree, hf_1722_cvf_tufield, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_cvf_tree, hf_1722_cvf_stream_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(ti_cvf_tree, hf_1722_cvf_avtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    ti_format = proto_tree_add_item_ret_uint(ti_cvf_tree, hf_1722_cvf_format, tvb, offset, 1, ENC_BIG_ENDIAN, &format);
    if (format == IEEE_1722_CVF_FORMAT_RFC) {
        offset += 1;
        ti_format = proto_tree_add_item_ret_uint(ti_cvf_tree, hf_1722_cvf_format_subtype, tvb, offset, 1, ENC_BIG_ENDIAN, &format_subtype);
        offset += 3;
    } else {
        expert_add_info(pinfo, ti_format, &ei_cvf_reserved_format);
        offset += 4;
    }
    ti_datalen = proto_tree_add_item_ret_uint(ti_cvf_tree, hf_1722_cvf_stream_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
    offset += 2;
    if (format == IEEE_1722_CVF_FORMAT_RFC &&
            format_subtype == IEEE_1722_CVF_FORMAT_SUBTYPE_H264) {
        proto_tree_add_bitmask_list(ti_cvf_tree, tvb, offset, 1, fields_h264, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_bitmask_list(ti_cvf_tree, tvb, offset, 1, fields_cvf, ENC_BIG_ENDIAN);
    }
    offset += 2;

    reported_len = tvb_reported_length_remaining(tvb, offset);
    if (reported_len < datalen) {
        expert_add_info(pinfo, ti_datalen, &ei_cvf_invalid_data_length);
        datalen = reported_len;
    }
    next_tvb = tvb_new_subset_length(tvb, offset, datalen);

    if (format == IEEE_1722_CVF_FORMAT_RFC) {
        switch(format_subtype) {
        case IEEE_1722_CVF_FORMAT_SUBTYPE_MJPEG:
            call_dissector(jpeg_handle, next_tvb, pinfo, tree);
            break;

        case IEEE_1722_CVF_FORMAT_SUBTYPE_H264:
            proto_tree_add_item(ti_cvf_tree, hf_1722_cvf_h264_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
            call_dissector(h264_handle, tvb_new_subset_remaining(next_tvb, 4), pinfo, tree);
            break;

        case IEEE_1722_CVF_FORMAT_SUBTYPE_JPEG2000:
            expert_add_info(pinfo, ti_format, &ei_cvf_jpeg2000_format);
            call_data_dissector(next_tvb, pinfo, tree);
            break;

        default:
            expert_add_info(pinfo, ti_format, &ei_cvf_reserved_format);
            call_data_dissector(next_tvb, pinfo, tree);
            break;
        }
    } else {
        call_data_dissector(next_tvb, pinfo, tree);
    }
    return offset + datalen;
}

void proto_register_1722_cvf (void)
{
    static hf_register_info hf[] =
    {
        { &hf_1722_cvf_mrfield,
            { "Media Clock Restart", "cvf.mrfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_MR_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_tvfield,
            { "Source Timestamp Valid", "cvf.tvfield",
              FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), IEEE_1722_TV_MASK,
              "Indicates whether avtp_timestamp contains a valid value", HFILL }
        },
        { &hf_1722_cvf_seqnum,
            { "Sequence Number", "cvf.seqnum",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_SEQ_NUM_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_tufield,
            { "Timestamp Uncertain", "cvf.tufield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TU_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_stream_id,
            { "Stream ID", "cvf.stream_id",
              FT_UINT64, BASE_HEX, NULL, IEEE_1722_STREAM_ID_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_avtp_timestamp,
            { "AVTP Timestamp", "cvf.avtp_timestamp",
              FT_UINT32, BASE_DEC, NULL, IEEE_1722_TIMESTAMP_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_format,
            { "Format", "cvf.format",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(cvf_format_range_rvals), IEEE_1722_FORMAT_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_format_subtype,
            { "CVF Format Subtype", "cvf.format_subtype",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(cvf_format_subtype_range_rvals), IEEE_1722_FORMAT_SUBTYPE_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_stream_data_length,
            { "Stream Data Length", "cvf.stream_data_len",
              FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_byte_bytes, IEEE_1722_STREAM_DATA_LENGTH_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_h264_ptvfield,
            { "H264 Payload Timestamp Valid", "cvf.h264_ptvfield",
              FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), IEEE_1722_H264_PTV_MASK,
              "Indicates whether h264_timestamp contains a valid value", HFILL }
        },
        { &hf_1722_cvf_marker_bit,
            { "Marker Bit", "cvf.marker_bit",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), IEEE_1722_MARKER_BIT_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_evtfield,
            { "EVT", "cvf.evtfield",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_EVT_MASK, NULL, HFILL }
        },
        { &hf_1722_cvf_h264_timestamp,
            { "H264 Timestamp", "cvf.h264_timestamp",
              FT_UINT32, BASE_DEC, NULL, IEEE_1722_CVF_H264_TIMESTAMP_MASK, NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_cvf_jpeg2000_format,          { "cvf.expert.jpeg2000_video", PI_UNDECODED, PI_WARN, "JPEG2000 format is currently not supported", EXPFILL }},
        { &ei_cvf_reserved_format,          { "cvf.expert.reserved_format", PI_PROTOCOL, PI_WARN, "Incorrect format, can't be dissected", EXPFILL }},
        { &ei_cvf_invalid_data_length,      { "cvf.expert.data_len", PI_PROTOCOL, PI_WARN, "data_length is too large or frame is incomplete", EXPFILL }}
    };

    static int *ett[] =
    {
        &ett_1722_cvf,
    };

    expert_module_t *expert_1722_cvf;

    /* Register the protocol name and description */
    proto_1722_cvf = proto_register_protocol("AVTP Compressed Video Format", "CVF", "cvf");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_cvf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722_cvf = expert_register_protocol(proto_1722_cvf);
    expert_register_field_array(expert_1722_cvf, ei, array_length(ei));

    avb1722_cvf_handle = register_dissector("cvf", dissect_1722_cvf, proto_1722_cvf);
}

void proto_reg_handoff_1722_cvf(void)
{
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_CVF, avb1722_cvf_handle);

    jpeg_handle = find_dissector_add_dependency("jpeg", proto_1722_cvf);
    h264_handle = find_dissector_add_dependency("h264", proto_1722_cvf);
}

/**************************************************************************************************/
/* 1722 CRF dissector implementation                                                              */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722_crf (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *ti_crf_tree;
    proto_tree *timestamp_tree;
    int         offset = 1;
    unsigned    datalen = 0;
    unsigned    j = 0;
    static int * const fields[] = {
        &hf_1722_crf_mrfield,
        &hf_1722_crf_fsfield,
        &hf_1722_crf_tufield,
        NULL
    };
    static int * const pull_frequency[] = {
        &hf_1722_crf_pull,
        &hf_1722_crf_base_frequency,
        NULL
    };

    ti = proto_tree_add_item(tree, proto_1722_crf, tvb, 0, -1, ENC_NA);
    ti_crf_tree = proto_item_add_subtree(ti, ett_1722_crf);

    proto_tree_add_bitmask_list(ti_crf_tree, tvb, offset, 1, fields, ENC_NA);
    offset += 1;
    proto_tree_add_item(ti_crf_tree, hf_1722_crf_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_crf_tree, hf_1722_crf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ti_crf_tree, hf_1722_crf_stream_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_bitmask_list(ti_crf_tree, tvb, offset, 4, pull_frequency, ENC_NA);
    offset += 4;
    proto_tree_add_item_ret_uint(ti_crf_tree, hf_1722_crf_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
    offset += 2;
    proto_tree_add_item(ti_crf_tree, hf_1722_crf_timestamp_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Make the Timestamp tree. */
    ti = proto_tree_add_item(ti_crf_tree, hf_1722_crf_timestamp_data, tvb, offset, datalen, ENC_NA);
    timestamp_tree = proto_item_add_subtree(ti, ett_1722_crf_timestamp);

    if (datalen%8)
    {
        expert_add_info(pinfo, ti, &ei_crf_datalen);
    }
    else
    {
        /* Loop through all timestamps and add them to the timestamp tree. */
        for (j = 0; j < (datalen / IEEE_1722_CRF_TIMESTAMP_SIZE); j++)
        {
            ti = proto_tree_add_item(timestamp_tree, hf_1722_crf_timestamp, tvb, offset, IEEE_1722_CRF_TIMESTAMP_SIZE, ENC_BIG_ENDIAN);
            proto_item_prepend_text(ti, "Timestamp %d ", j);
            offset += IEEE_1722_CRF_TIMESTAMP_SIZE;
        }
    }

    return tvb_captured_length(tvb);
}

void proto_register_1722_crf(void)
{
    static hf_register_info hf[] =
    {
        { &hf_1722_crf_mrfield,
          { "Media Clock Restart", "crf.mrfield",
            FT_BOOLEAN, 8, NULL, IEEE_1722_MR_MASK, NULL, HFILL }
        },
        { &hf_1722_crf_fsfield,
          { "Frame Sync", "crf.fsfield",
            FT_BOOLEAN, 8, NULL, IEEE_1722_FS_MASK, NULL, HFILL }
        },
        { &hf_1722_crf_tufield,
            { "Timestamp Uncertain", "crf.tufield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TU_MASK, NULL, HFILL }
        },
        { &hf_1722_crf_seqnum,
            { "Sequence Number", "crf.seqnum",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_crf_type,
            { "Type", "crf.type",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(crf_type_range_rvals), 0x0, NULL, HFILL }
        },
        { &hf_1722_crf_stream_id,
            { "Stream ID", "crf.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_crf_pull,
            { "Pull", "crf.pull",
              FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(crf_pull_range_rvals), IEEE_1722_PULL_MASK, NULL, HFILL }
        },
        { &hf_1722_crf_base_frequency,
            { "Base Frequency", "crf.base_frequency",
              FT_UINT32, BASE_DEC, NULL, IEEE_1722_BASE_FREQUENCY_MASK, NULL, HFILL }
        },
        { &hf_1722_crf_data_length,
            { "Data Length", "crf.data_len",
              FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL }
        },
        { &hf_1722_crf_timestamp_interval,
            { "Timestamp Interval", "crf.timestamp_interval",
              FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_crf_timestamp_data,
            { "Timestamp Data", "crf.timestamp_data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_crf_timestamp,
            { "Data", "crf.timestamp",
              FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_crf_datalen,              { "crf.expert.crf_datalen", PI_PROTOCOL, PI_WARN, "The CRF data length must be multiple of 8", EXPFILL }}
    };

    static int *ett[] =
    {
        &ett_1722_crf,
        &ett_1722_crf_timestamp
    };

    expert_module_t *expert_1722_crf;

    /* Register the protocol name and description */
    proto_1722_crf = proto_register_protocol("Clock Reference Format", "CRF", "crf");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_crf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_1722_crf = expert_register_protocol(proto_1722_crf);
    expert_register_field_array(expert_1722_crf, ei, array_length(ei));

    avb1722_crf_handle = register_dissector("crf", dissect_1722_crf, proto_1722_crf);
}

void proto_reg_handoff_1722_crf(void)
{
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_CRF, avb1722_crf_handle);
}

/**************************************************************************************************/
/* 1722 NTSCF dissector implementation                                                            */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722_ntscf (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti_ntscf;
    proto_item *ti_data_length;
    proto_tree *tree_ntscf;
    int         offset = 1;
    uint32_t    datalen = 0;
    unsigned    captured_length = tvb_captured_length(tvb);
    int         captured_payload_length;

    static int * const fields[] = {
        &hf_1722_ntscf_rfield,
        NULL,
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NTSCF");
    col_set_str(pinfo->cinfo, COL_INFO, "AVTP Non-Time-Synchronous Control Format");

    ti_ntscf = proto_tree_add_item(tree, proto_1722_ntscf, tvb, 0, -1, ENC_NA);
    tree_ntscf = proto_item_add_subtree(ti_ntscf, ett_1722_ntscf);

    if (captured_length < IEEE_1722_NTSCF_HEADER_SIZE) {
        expert_add_info(pinfo, ti_ntscf, &ei_1722_ntscf_no_space_for_header);
        return captured_length;
    }

    proto_tree_add_bitmask_list(tree_ntscf, tvb, offset, 2, fields, ENC_BIG_ENDIAN);
    ti_data_length = proto_tree_add_item_ret_uint(tree_ntscf, hf_1722_ntscf_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
    offset += 2;
    proto_tree_add_item(tree_ntscf, hf_1722_ntscf_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree_ntscf, hf_1722_ntscf_stream_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    captured_payload_length = tvb_captured_length_remaining(tvb, offset);
    if (captured_payload_length < 0 || (int)datalen > captured_payload_length) {
        expert_add_info(pinfo, ti_data_length, &ei_1722_ntscf_invalid_data_length);
    }

    if ((int)datalen > captured_payload_length) {
        datalen = captured_payload_length > 0
                ? captured_payload_length
                : 0;
    }

    while(datalen > 0) {
        unsigned    processed_bytes;
        tvbuff_t*   next_tvb;

        next_tvb = tvb_new_subset_length(tvb, offset, datalen);
        if (call_dissector(avb1722_acf_handle, next_tvb, pinfo, tree) <= 0) {
            break;
        }

        processed_bytes = tvb_reported_length(next_tvb);

        offset += processed_bytes;
        if (processed_bytes < datalen) {
            datalen -= processed_bytes;
        } else {
            datalen = 0;
        }
    }

    set_actual_length(tvb, offset);
    proto_item_set_len(ti_ntscf, offset);

    return tvb_captured_length(tvb);
}

void proto_register_1722_ntscf(void)
{
    static hf_register_info hf[] =
    {
        { &hf_1722_ntscf_rfield,
            { "Reserved bits", "ntscf.rfield",
              FT_UINT16, BASE_HEX, NULL, IEEE_1722_NTSCF_R_MASK, NULL, HFILL }
        },
        { &hf_1722_ntscf_data_length,
            { "Data Length", "ntscf.data_len",
              FT_UINT16, BASE_DEC, NULL, IEEE_1722_NTSCF_DATA_LENGTH_MASK, NULL, HFILL }
        },
        { &hf_1722_ntscf_seqnum,
            { "Sequence Number", "ntscf.seqnum",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_ntscf_stream_id,
            { "Stream ID", "ntscf.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        }
    };

    static int *ett[] =
    {
        &ett_1722_ntscf
    };

    static ei_register_info ei[] = {
        { &ei_1722_ntscf_no_space_for_header, { "ntscf.expert.no_space_for_header", PI_PROTOCOL, PI_WARN, "Frame is cropped: NTSCF header won't fit into captured data.", EXPFILL}},
        { &ei_1722_ntscf_invalid_data_length, { "ntscf.expert.data_len", PI_PROTOCOL, PI_WARN, "data_length is too large or frame is incomplete", EXPFILL }}
    };

    expert_module_t *expert_1722_ntscf;

    /* Register the protocol name and description */
    proto_1722_ntscf = proto_register_protocol("Non-Time-Synchronous Control Format", "NTSCF", "ntscf");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_ntscf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722_ntscf = expert_register_protocol(proto_1722_ntscf);
    expert_register_field_array(expert_1722_ntscf, ei, array_length(ei));

    avb1722_ntscf_handle = register_dissector("ntscf", dissect_1722_ntscf, proto_1722_ntscf);
}

void proto_reg_handoff_1722_ntscf(void)
{
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_NTSCF, avb1722_ntscf_handle);
}


/**************************************************************************************************/
/* 1722 TSCF dissector implementation                                                            */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722_tscf (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_item *ti_tscf;
    proto_tree *tree_tscf;
    proto_tree *tree_flags;
    proto_tree *tree_tu;
    int         offset = 1;
    uint32_t    mr;
    uint32_t    tv;
    uint32_t    tu;
    uint32_t    datalen = 0;
    unsigned    captured_length = tvb_captured_length(tvb);
    int         captured_payload_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TSCF");
    col_set_str(pinfo->cinfo, COL_INFO, "AVTP Time-Synchronous Control Format");

    ti_tscf = proto_tree_add_item(tree, proto_1722_tscf, tvb, 0, -1, ENC_NA);
    tree_tscf = proto_item_add_subtree(ti_tscf, ett_1722_tscf);

    if (captured_length < IEEE_1722_TSCF_HEADER_SIZE) {
        expert_add_info(pinfo, ti_tscf, &ei_1722_tscf_no_space_for_header);
        return captured_length;
    }

    tree_flags = proto_tree_add_subtree(tree_tscf, tvb, offset, 1, ett_1722_tscf_flags, &ti, "Flags");
    proto_tree_add_item_ret_uint(tree_flags, hf_1722_tscf_mr, tvb, offset, 1, ENC_BIG_ENDIAN, &mr);
    proto_tree_add_item(tree_flags, hf_1722_tscf_rsv1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree_flags, hf_1722_tscf_tv, tvb, offset, 1, ENC_BIG_ENDIAN, &tv);
    proto_item_append_text(ti, ": mr=%d, tv=%d", mr, tv);
    offset += 1;

    proto_tree_add_item(tree_tscf, hf_1722_tscf_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    tree_tu = proto_tree_add_subtree(tree_tscf, tvb, offset, 1, ett_1722_tscf_tu, &ti, "Timestamp Uncertain");
    proto_tree_add_item(tree_tu, hf_1722_tscf_rsv2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree_tu, hf_1722_tscf_tu, tvb, offset, 1, ENC_BIG_ENDIAN, &tu);
    proto_item_append_text(ti, ": %d", tu);
    offset += 1;

    proto_tree_add_item(tree_tscf, hf_1722_tscf_stream_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree_tscf, hf_1722_tscf_avtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree_tscf, hf_1722_tscf_rsv3, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    ti = proto_tree_add_item_ret_uint(tree_tscf, hf_1722_tscf_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
    captured_payload_length = tvb_captured_length_remaining(tvb, offset);
    if (captured_payload_length < 0 || (int)datalen > captured_payload_length) {
        expert_add_info(pinfo, ti, &ei_1722_tscf_invalid_data_length);
    }
    offset += 2;

    proto_tree_add_item(tree_tscf, hf_1722_tscf_rsv4, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if ((int)datalen > captured_payload_length) {
        datalen = captured_payload_length > 0
                ? captured_payload_length
                : 0;
    }

    while(datalen > 0) {
        unsigned    processed_bytes;
        tvbuff_t*   next_tvb = tvb_new_subset_length(tvb, offset, datalen);
        if (call_dissector(avb1722_acf_handle, next_tvb, pinfo, tree) <= 0) {
            break;
        }
        processed_bytes = tvb_reported_length(next_tvb);

        offset += processed_bytes;
        if (processed_bytes < datalen) {
            datalen -= processed_bytes;
        } else {
            datalen = 0;
        }
    }

    set_actual_length(tvb, offset);
    proto_item_set_len(ti_tscf, offset);

    return captured_length;
}

void proto_register_1722_tscf(void)
{
    static hf_register_info hf[] =
    {
        { &hf_1722_tscf_mr,
            { "Media Clock Restart", "tscf.flags.mr",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_TSCF_MR_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_rsv1,
            { "Reserved bits", "tscf.flags.rsv1",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_TSCF_RSV1_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_tv,
            { "Avtp Timestamp Valid", "tscf.flags.tv",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_TSCF_TV_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_seqnum,
            { "Sequence Number", "tscf.seqnum",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_TSCF_SEQNUM_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_rsv2,
            { "Reserved Bits", "tscf.rsv2",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_TSCF_RSV2_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_tu,
            { "Timestamp Uncertain", "tscf.flags.tu",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_TSCF_TU_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_stream_id,
            { "Stream ID", "tscf.stream_id",
              FT_UINT64, BASE_HEX, NULL, IEEE_1722_TSCF_STREAM_ID_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_avtp_timestamp,
            { "AVTP Timestamp", "tscf.avtp_timestamp",
              FT_UINT32, BASE_HEX, NULL, IEEE_1722_TSCF_AVTP_TIMESTAMP_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_rsv3,
            { "Reserved Bits", "tscf.rsv3",
              FT_UINT32, BASE_HEX, NULL, IEEE_1722_TSCF_RSV3_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_data_length,
            { "Data Length", "tscf.data_len",
              FT_UINT16, BASE_DEC, NULL, IEEE_1722_TSCF_DATA_LENGTH_MASK, NULL, HFILL }
        },

        { &hf_1722_tscf_rsv4,
            { "Reserved Bits", "tscf.rsv4",
              FT_UINT16, BASE_HEX, NULL, IEEE_1722_TSCF_RSV4_MASK, NULL, HFILL }
        },
    };

    static int *ett[] =
    {
        &ett_1722_tscf,
        &ett_1722_tscf_flags,
        &ett_1722_tscf_tu,
    };

    static ei_register_info ei[] = {
        { &ei_1722_tscf_no_space_for_header, { "tscf.expert.no_space_for_header", PI_PROTOCOL, PI_WARN, "Frame is cropped: TSCF header won't fit into captured data.", EXPFILL}},
        { &ei_1722_tscf_invalid_data_length, { "tscf.expert.data_len", PI_PROTOCOL, PI_WARN, "data_length is too large or frame is incomplete", EXPFILL }}
    };

    expert_module_t *expert_1722_tscf;

    /* Register the protocol name and description */
    proto_1722_tscf = proto_register_protocol("Time-Synchronous Control Format", "TSCF", "tscf");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_tscf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722_tscf = expert_register_protocol(proto_1722_tscf);
    expert_register_field_array(expert_1722_tscf, ei, array_length(ei));

    avb1722_tscf_handle = register_dissector("tscf", dissect_1722_tscf, proto_1722_tscf);
}

void proto_reg_handoff_1722_tscf(void)
{
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_TSCF, avb1722_tscf_handle);
}

/**************************************************************************************************/
/* AVTP Control Format (ACF) Message dissector implementation                                     */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722_acf (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item     *ti;
    proto_item     *ti_acf;
    proto_item     *ti_header;
    proto_tree     *tree_acf;
    proto_tree     *tree_header;
    uint32_t        msg_type;
    uint32_t        msg_length;
    uint32_t        payload_length;
    unsigned        captured_length = tvb_captured_length(tvb);
    const char     *msg_type_str;
    tvbuff_t       *next_tvb;

    if (captured_length < IEEE_1722_ACF_HEADER_SIZE) {
        return captured_length;
    }

    ti_acf = proto_tree_add_item(tree, proto_1722_acf, tvb, 0, -1, ENC_NA);
    tree_acf = proto_item_add_subtree(ti_acf, ett_1722_acf);

    tree_header = proto_tree_add_subtree(tree_acf, tvb, 0, 2, ett_1722_acf_header, &ti_header, "ACF Header");
    proto_tree_add_item_ret_uint(tree_header, hf_1722_acf_msg_type, tvb, 0, 2, ENC_BIG_ENDIAN, &msg_type);
    ti = proto_tree_add_item_ret_uint(tree_header, hf_1722_acf_msg_length, tvb, 0, 2, ENC_BIG_ENDIAN, &msg_length);
    msg_length = msg_length * 4; /* msg_length is stored as number of quadlets */

    if (msg_length < IEEE_1722_ACF_HEADER_SIZE) {
        expert_add_info(pinfo, ti, &ei_1722_acf_invalid_msg_length);
        return captured_length;
    }

    if (captured_length < msg_length) {
        expert_add_info_format(pinfo, ti, &ei_1722_acf_message_is_cropped,
                               "expected: %u bytes, available: %u bytes",
                               msg_length, tvb_captured_length(tvb));
        return captured_length;
    }

    set_actual_length(tvb, msg_length);
    proto_item_set_len(ti_acf, msg_length);
    msg_type_str = rval_to_str_const(msg_type, acf_msg_type_range_rvals, "Unknown");
    proto_item_append_text(ti_header, ": %s (0x%02X), %d bytes with header",
                           msg_type_str, msg_type, msg_length);
    proto_item_append_text(ti_acf, ": %s (0x%02X)", msg_type_str, msg_type);
    payload_length = msg_length - IEEE_1722_ACF_HEADER_SIZE;

    /* call any registered message dissectors */
    next_tvb = tvb_new_subset_length(tvb, IEEE_1722_ACF_HEADER_SIZE, payload_length);

    if (!dissector_try_uint(avb1722_acf_dissector_table, msg_type, next_tvb, pinfo, tree_acf)) {
        call_data_dissector(next_tvb, pinfo, tree_acf);
    }

    return captured_length;
}

void proto_register_1722_acf(void)
{
    static hf_register_info hf[] = {
        { &hf_1722_acf_msg_type,
            { "Message Type", "acf.msg_type",
              FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(acf_msg_type_range_rvals), IEEE_1722_ACF_MSG_TYPE_MASK, NULL, HFILL }
        },
        { &hf_1722_acf_msg_length,
            { "Message Length (Quadlets)", "acf.msg_length",
              FT_UINT16, BASE_DEC, NULL, IEEE_1722_ACF_MSG_LENGTH_MASK, NULL, HFILL }
        },
    };

    static int *ett[] =
    {
        &ett_1722_acf,
        &ett_1722_acf_header,
    };


    static ei_register_info ei[] = {
        { &ei_1722_acf_invalid_msg_length, { "acf.expert.msg_length", PI_PROTOCOL, PI_WARN, "msg_length shall be at least 1 quadlet", EXPFILL }},
        { &ei_1722_acf_message_is_cropped, { "acf.expert.msg_cropped", PI_PROTOCOL, PI_WARN, "Message is cropped or msg_length is invalid", EXPFILL }},
    };

    expert_module_t *expert_1722_acf;

    /* Register the protocol name and description */
    proto_1722_acf = proto_register_protocol("ACF Message", "ACF", "acf");
    avb1722_acf_handle = register_dissector("acf", dissect_1722_acf, proto_1722_acf);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_acf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Sub-dissector for ACF messages */
    avb1722_acf_dissector_table = register_dissector_table("acf.msg_type",
                          "IEEE1722 AVTP Control Message Type", proto_1722_acf,
                          FT_UINT8, BASE_HEX);

    expert_1722_acf = expert_register_protocol(proto_1722_acf);
    expert_register_field_array(expert_1722_acf, ei, array_length(ei));
}

void proto_reg_handoff_1722_acf(void)
{
    register_depend_dissector("ntscf", "acf");
    register_depend_dissector("tscf", "acf");
}

/**************************************************************************************************/
/* ACF CAN Message dissector implementation                                                       */
/*                                                                                                */
/**************************************************************************************************/
static void describe_can_message(proto_item* dst, unsigned bus_id, uint32_t can_id, uint8_t flags)
{
    /* Add text describing the CAN message to the parent item.
     * Example: ": bus_id=2, id=0x100, rtr=1, brs=1, esi=1" */
    const char* format_str = (flags & IEEE_1722_ACF_CAN_EFF_MASK) != 0
                           ? ": bus_id=%u, id=0x%08X"
                           : ": bus_id=%u, id=0x%03X";

    proto_item_append_text (dst, format_str, bus_id, can_id);
}

static void describe_can_flags(proto_item* dst, uint8_t pad, uint8_t flags)
{
    proto_item_append_text(dst, ": pad=%u, mtv=%d, rtr=%d, eff=%d, brs=%d, fdf=%d, esi=%d",
                           pad,
                           (flags & IEEE_1722_ACF_CAN_MTV_MASK) != 0,
                           (flags & IEEE_1722_ACF_CAN_RTR_MASK) != 0,
                           (flags & IEEE_1722_ACF_CAN_EFF_MASK) != 0,
                           (flags & IEEE_1722_ACF_CAN_BRS_MASK) != 0,
                           (flags & IEEE_1722_ACF_CAN_FDF_MASK) != 0,
                           (flags & IEEE_1722_ACF_CAN_ESI_MASK) != 0
    );
}

static int is_valid_can_payload_length(int len)
{
    return len >= 0 && len <= 8;
}

static int is_valid_canfd_payload_length(int len)
{
    return is_valid_can_payload_length(len) ||
           len == 12 ||
           len == 16 ||
           len == 20 ||
           len == 24 ||
           len == 32 ||
           len == 48 ||
           len == 64;
}

static int dissect_1722_acf_can_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_, const bool is_brief)
{
    acf_can_t           parsed;
    uint32_t            pad_length;
    int                 payload_length;
    uint8_t             flags;
    proto_item         *ti;

    proto_item         *ti_acf_can;
    proto_tree         *tree_acf_can;
    proto_tree         *tree_acf_can_flags;
    proto_tree         *tree_acf_can_bus_id;

    proto_item         *ti_can;
    proto_tree         *tree_can;
    proto_tree         *tree_can_id;
    int                 can_protocol;
    int                * const *can_flags;
    struct can_info     can_info;

    tvbuff_t*           next_tvb;
    int                 offset = 0;
    unsigned            captured_length = tvb_captured_length(tvb);
    unsigned            header_size = is_brief
                                    ? IEEE_1722_ACF_CAN_BRIEF_HEADER_SIZE
                                    : IEEE_1722_ACF_CAN_HEADER_SIZE;


    static int * const fields[] = {
        &hf_1722_can_mtvfield,
        &hf_1722_can_fdffield,
        NULL,
    };

    static int * const can_std_flags[] = {
        &hf_1722_can_rtrfield,
        &hf_1722_can_efffield,
        NULL
    };

    static int * const can_fd_flags[] = {
        &hf_1722_can_efffield,
        &hf_1722_can_brsfield,
        &hf_1722_can_esifield,
        NULL
    };

    memset(&parsed, 0, sizeof(parsed));

    /* create tree for ACF-CAN-specific fields */
    ti_acf_can = proto_tree_add_item(tree, proto_1722_acf_can, tvb, offset, -1, ENC_NA);
    tree_acf_can = proto_item_add_subtree(ti_acf_can, ett_1722_can);
    if (is_brief) {
        proto_item_append_text(ti_acf_can, " Brief");
    }

    /* parse flags */
    flags = tvb_get_uint8(tvb, offset);
    parsed.is_fd   = (flags & IEEE_1722_ACF_CAN_FDF_MASK) != 0;
    parsed.is_xtd  = (flags & IEEE_1722_ACF_CAN_EFF_MASK) != 0;
    parsed.is_rtr  = (flags & IEEE_1722_ACF_CAN_RTR_MASK) != 0;
    parsed.is_brs  = (flags & IEEE_1722_ACF_CAN_BRS_MASK) != 0;
    parsed.is_esi  = (flags & IEEE_1722_ACF_CAN_ESI_MASK) != 0;

    /* create the tree for CAN-specific fields */
    can_protocol = parsed.is_fd ? proto_canfd : proto_can;
    can_flags    = parsed.is_fd ? can_fd_flags : can_std_flags;
    ti_can = proto_tree_add_item(tree, can_protocol, tvb, offset, -1, ENC_NA);
    tree_can = proto_item_add_subtree(ti_can, ett_can);

    if (captured_length < header_size) {
        expert_add_info(pinfo, ti_acf_can, &ei_1722_can_header_cropped);
        return captured_length;
    }

    /* Add flags subtree to ACF_CAN message */
    ti = proto_tree_add_item(tree_acf_can, hf_1722_can_flags, tvb, offset, 1, ENC_NA);
    tree_acf_can_flags = proto_item_add_subtree(ti, ett_1722_can_flags);

    proto_tree_add_item_ret_uint(tree_acf_can_flags, hf_1722_can_pad, tvb, offset, 1, ENC_BIG_ENDIAN, &pad_length);
    proto_tree_add_bitmask_list(tree_acf_can_flags, tvb, offset, 1, fields, ENC_BIG_ENDIAN);
    describe_can_flags(ti, pad_length, flags);

    /* Add flags to CAN message */
    proto_tree_add_bitmask_list(tree_can, tvb, offset, 1, can_flags, ENC_BIG_ENDIAN);
    offset += 1;

    /* Add bus id subtree to ACF_CAN message */
    tree_acf_can_bus_id = proto_tree_add_subtree(tree_acf_can, tvb, offset, 1, ett_1722_can_bus_id, &ti, "Bus Identifier");
    proto_tree_add_item(tree_acf_can_bus_id, hf_1722_can_rsv1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree_acf_can_bus_id, hf_1722_can_bus_id, tvb, offset, 1, ENC_BIG_ENDIAN, &parsed.bus_id);
    proto_item_append_text(ti, ": %u", parsed.bus_id);
    offset += 1;

    /* Add message_timestamp to ACF_CAN if present */
    if (!is_brief) {
        proto_tree_add_item(tree_acf_can, hf_1722_can_message_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    /* Add message id subtree to CAN message */
    tree_can_id = proto_tree_add_subtree(tree_can, tvb, offset, 4, ett_1722_can_msg_id, &ti, "Message Identifier");
    proto_tree_add_item(tree_can_id, hf_1722_can_rsv2, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item *ti_id = proto_tree_add_item_ret_uint(tree_can_id, hf_1722_can_identifier, tvb, offset, 4, ENC_BIG_ENDIAN, &parsed.id);
    proto_item_append_text(ti, parsed.is_xtd ? ": 0x%08X" : ": 0x%03X", parsed.id);
    if (!parsed.is_xtd && (parsed.id & ~IEEE_1722_ACF_CAN_11BIT_ID_MASK) != 0) {
        expert_add_info(pinfo, ti_id, &ei_1722_can_invalid_message_id);
    }
    offset += 4;

    /* Add text description to tree items and info column*/
    describe_can_message(ti_acf_can, parsed.bus_id, parsed.id, flags);
    describe_can_message(proto_tree_get_parent(tree), parsed.bus_id, parsed.id, flags);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACF-CAN");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "ACF-CAN(%u): 0x%08x   ", parsed.bus_id, parsed.id);

    payload_length = tvb_reported_length_remaining(tvb, offset) - pad_length;
    if (payload_length < 0) {
        payload_length = 0;
    }
    parsed.datalen = (unsigned)payload_length;
    proto_tree_add_uint(tree_acf_can, hf_1722_can_len, tvb, offset, 1, parsed.datalen);

    if (payload_length > 0)
        col_append_str(pinfo->cinfo, COL_INFO, tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, payload_length, ' '));

    if (parsed.is_fd && !is_valid_canfd_payload_length(payload_length))
    {
        expert_add_info(pinfo, ti_acf_can, &ei_1722_canfd_invalid_payload_length);
    }
    else if (!parsed.is_fd && !is_valid_can_payload_length(payload_length))
    {
        expert_add_info(pinfo, ti_acf_can, &ei_1722_can_invalid_payload_length);
    }

    /* Add payload to parent tree */

    /*
    * CAN sub-dissectors expect several flags to be merged into ID that is passed
    * to dissector_try_payload_new. Add them
    */
    can_info.id = parsed.id;
    if (parsed.is_xtd)
    {
        can_info.id |= CAN_EFF_FLAG;
    }

    if (parsed.is_rtr)
    {
        can_info.id |= CAN_RTR_FLAG;
    }

    can_info.len = (uint32_t)parsed.datalen;
    can_info.fd = parsed.is_fd ? CAN_TYPE_CAN_FD : CAN_TYPE_CAN_CLASSIC;

    /* for practical reasons a remapping might be needed in the future */
    can_info.bus_id = (uint16_t)parsed.bus_id;

    next_tvb = tvb_new_subset_length(tvb, offset, parsed.datalen);

    if (!socketcan_call_subdissectors(next_tvb, pinfo, tree, &can_info, can_heuristic_first)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    /* Add padding bytes to ACF-CAN tree if any */
    if (pad_length > 0 && tvb_reported_length_remaining(tvb, offset) >= (int)pad_length)
    {
        proto_tree_add_item(tree_acf_can, hf_1722_can_padding, tvb, offset, pad_length, ENC_NA);
    }

    return captured_length;
}

static int dissect_1722_acf_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_1722_acf_can_common(tvb, pinfo, tree, data, false);
}

static int dissect_1722_acf_can_brief(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_1722_acf_can_common(tvb, pinfo, tree, data, true);
}

void proto_register_1722_acf_can(void)
{
    static hf_register_info hf[] = {
        /* ACF-CAN, ACF-CAN-BRIEF and CAN fields */
        { &hf_1722_can_flags,
            { "Flags", "acf-can.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_1722_can_pad,
            { "Padding Length", "acf-can.flags.pad",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_ACF_CAN_PAD_MASK, NULL, HFILL }
        },
        { &hf_1722_can_len,
            { "Frame-Length", "can.len",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_1722_can_mtvfield,
            { "Message Timestamp Valid", "acf-can.flags.mtv",
              FT_BOOLEAN, 8, NULL, IEEE_1722_ACF_CAN_MTV_MASK, NULL, HFILL }
        },
        { &hf_1722_can_fdffield,
            { "CAN Flexible Data-rate Format", "acf-can.flags.fdf",
              FT_BOOLEAN, 8, NULL, IEEE_1722_ACF_CAN_FDF_MASK, NULL, HFILL }
        },
        { &hf_1722_can_rtrfield,
            { "Remote Transmission Request Flag", "can.flags.rtr",
              FT_BOOLEAN, 8, NULL, IEEE_1722_ACF_CAN_RTR_MASK, NULL, HFILL }
        },
        { &hf_1722_can_efffield,
            { "Extended Flag", "can.flags.xtd",
              FT_BOOLEAN, 8, NULL, IEEE_1722_ACF_CAN_EFF_MASK, NULL, HFILL }
        },
        { &hf_1722_can_brsfield,
            { "Bit Rate Setting", "canfd.flags.brs",
              FT_BOOLEAN, 8, NULL, IEEE_1722_ACF_CAN_BRS_MASK, NULL, HFILL }
        },
        { &hf_1722_can_esifield,
            { "Error Message Flag", "canfd.flags.esi",
              FT_BOOLEAN, 8, NULL, IEEE_1722_ACF_CAN_ESI_MASK, NULL, HFILL }
        },
        { &hf_1722_can_rsv1,
            { "Reserved Bits", "acf-can.rsv1",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_ACF_CAN_RSV1_MASK, NULL, HFILL }
        },
        { &hf_1722_can_bus_id,
            { "CAN Bus Identifier", "acf-can.bus_id",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_ACF_CAN_BUS_ID_MASK, NULL, HFILL }
        },
        { &hf_1722_can_message_timestamp,
            { "Message Timestamp", "acf-can.message_timestamp",
              FT_UINT64, BASE_HEX, NULL, IEEE_1722_ACF_CAN_MSG_TIMESTAMP_MASK, NULL, HFILL }
        },
        { &hf_1722_can_rsv2,
            { "Reserved", "can.reserved",
              FT_UINT32, BASE_HEX, NULL, IEEE_1722_ACF_CAN_RSV2_MASK, NULL, HFILL }
        },
        { &hf_1722_can_identifier,
            { "CAN Message Identifier", "can.id",
              FT_UINT32, BASE_HEX, NULL, IEEE_1722_ACF_CAN_IDENTIFIER_MASK, NULL, HFILL }
        },
        { &hf_1722_can_padding,
            { "Padding", "can.padding",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] =
    {
        &ett_1722_can,
        &ett_1722_can_flags,
        &ett_1722_can_bus_id,
        &ett_1722_can_msg_id,
        &ett_can
    };

    static ei_register_info ei[] = {
        { &ei_1722_can_header_cropped,          { "acf-can.expert.header_cropped",  PI_PROTOCOL, PI_WARN,
                                                  "Message is cropped, no space for header", EXPFILL }},
        { &ei_1722_can_invalid_message_id,      { "acf-can.expert.incorrect_can_id", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect msg id, shall be 0..1FF when EFF flag is not set", EXPFILL }},
        { &ei_1722_can_invalid_payload_length,  { "acf-can.expert.incorrect_datalen", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect payload length, shall be [0..8] when FDF flag is not set", EXPFILL }},
        { &ei_1722_canfd_invalid_payload_length,{ "acf-can.expert.incorrect_fd_datalen", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect FD payload length, shall be [0..8, 12, 16, 20, 32, 48, 64] when FDF flag is set", EXPFILL }},
    };

    module_t*        module_acf_can;
    expert_module_t* expert_1722_acf_can;

    /* Register the protocol name and description */
    proto_1722_acf_can = proto_register_protocol("ACF CAN", "CAN over AVTP", "acf-can");
    avb1722_can_handle = register_dissector("acf-can", dissect_1722_acf_can, proto_1722_acf_can);
    avb1722_can_brief_handle = register_dissector("acf-can-brief", dissect_1722_acf_can_brief, proto_1722_acf_can);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_acf_can, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722_acf_can = expert_register_protocol(proto_1722_acf_can);
    expert_register_field_array(expert_1722_acf_can, ei, array_length(ei));

    /* register preferences */
    module_acf_can = prefs_register_protocol(proto_1722_acf_can, NULL);

    prefs_register_obsolete_preference(module_acf_can, "protocol");
    prefs_register_bool_preference(
        module_acf_can, "try_heuristic_first",
        "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector"
        " before using a sub-dissector registered to \"decode as\"",
        &can_heuristic_first
    );

}

void proto_reg_handoff_1722_acf_can(void)
{
    dissector_add_uint("acf.msg_type", IEEE_1722_ACF_TYPE_CAN, avb1722_can_handle);
    dissector_add_uint("acf.msg_type", IEEE_1722_ACF_TYPE_CAN_BRIEF, avb1722_can_brief_handle);

    register_depend_dissector("acf-can", "can");
    register_depend_dissector("acf-can", "canfd");

    proto_can = proto_get_id_by_filter_name("can");
    proto_canfd = proto_get_id_by_filter_name("canfd");
}

/**************************************************************************************************/
/* ACF LIN Message dissector implementation                                                       */
/*                                                                                                */
/**************************************************************************************************/
static void describe_lin_message(proto_item *dst, uint32_t bus_id, uint32_t lin_id)
{
    proto_item_append_text(dst, ": bus_id=%u, id=0x%02X", bus_id, lin_id);
}

static int dissect_1722_acf_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_item *ti_lin;
    proto_tree *tree_lin;
    proto_tree *tree_flags;
    unsigned    offset = 0;
    unsigned    captured_length = tvb_captured_length(tvb);
    uint32_t    pad_length;
    bool        mtv;
    uint32_t    bus_id;
    uint32_t    lin_id;
    int         payload_length;

    ti_lin = proto_tree_add_item(tree, proto_1722_acf_lin, tvb, offset, -1, ENC_NA);
    tree_lin = proto_item_add_subtree(ti_lin, ett_1722_lin);

    if (captured_length < IEEE_1722_ACF_LIN_HEADER_SIZE) {
        expert_add_info(pinfo, ti_lin, &ei_1722_lin_header_cropped);
        return captured_length;
    }

    tree_flags = proto_tree_add_subtree(tree_lin, tvb, offset, 1, ett_1722_lin_flags, &ti, "Flags and BusID");
    proto_tree_add_item_ret_uint(tree_flags, hf_1722_lin_pad, tvb, offset, 1, ENC_BIG_ENDIAN, &pad_length);
    proto_tree_add_item_ret_boolean(tree_flags, hf_1722_lin_mtv, tvb, offset, 1, ENC_BIG_ENDIAN, &mtv);
    proto_tree_add_item_ret_uint(tree_flags, hf_1722_lin_bus_id, tvb, offset, 1, ENC_BIG_ENDIAN, &bus_id);
    proto_item_append_text(ti, ": pad=%u, mtv=%u, bus_id=%u", pad_length, (unsigned)mtv, bus_id);
    offset += 1;

    proto_tree_add_item_ret_uint(tree_lin, hf_1722_lin_identifier, tvb, offset, 1, ENC_BIG_ENDIAN, &lin_id);
    offset += 1;

    proto_tree_add_item(tree_lin, hf_1722_lin_message_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    describe_lin_message(ti_lin, bus_id, lin_id);
    describe_lin_message(proto_tree_get_parent(tree), bus_id, lin_id);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACF-LIN");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "ACF-LIN(%u): 0x%02x   ", bus_id, lin_id);

    payload_length = tvb_reported_length_remaining(tvb, offset) - pad_length;

    if (payload_length < 0 || payload_length > 8)
    {
        expert_add_info(pinfo, ti_lin, &ei_1722_lin_invalid_payload_length);
    }
    else if (payload_length > 0)
    {
        tvbuff_t*   next_tvb = tvb_new_subset_length(tvb, offset, payload_length);

        col_append_str(pinfo->cinfo, COL_INFO, tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, payload_length, ' '));

        /* at the moment, there's no global LIN sub-protocols support. Use our own. */
        if (dissector_try_payload_new(avb1722_acf_lin_dissector_table, next_tvb, pinfo, tree, true, &lin_id) <= 0)
        {
            call_data_dissector(next_tvb, pinfo, tree);
        }

        offset += payload_length;
    }

    if (pad_length > 0 && tvb_reported_length_remaining(tvb, offset) >= (int)pad_length)
    {
        proto_tree_add_item(tree_lin, hf_1722_lin_padding, tvb, offset, pad_length, ENC_NA);
    }

    return captured_length;
}

void proto_register_1722_acf_lin(void)
{
    static hf_register_info hf[] = {
        { &hf_1722_lin_pad,
            { "Padding Length", "acf-lin.flags.pad",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_ACF_LIN_PAD_MASK, NULL, HFILL }
        },
        { &hf_1722_lin_mtv,
            { "Message Timestamp Valid", "acf-lin.flags.mtv",
              FT_BOOLEAN, 8, NULL, IEEE_1722_ACF_LIN_MTV_MASK, NULL, HFILL }
        },
        { &hf_1722_lin_bus_id,
            { "LIN Bus Identifier", "acf-lin.bus_id",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_ACF_LIN_BUS_ID_MASK, NULL, HFILL }
        },
        { &hf_1722_lin_identifier,
            { "LIN Message Identifier", "acf-lin.id",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_ACF_LIN_IDENTIFIER_MASK, NULL, HFILL }
        },
        { &hf_1722_lin_message_timestamp,
            { "Message Timestamp", "acf-lin.message_timestamp",
              FT_UINT64, BASE_HEX, NULL, IEEE_1722_ACF_LIN_MSG_TIMESTAMP_MASK, NULL, HFILL }
        },
        { &hf_1722_lin_padding,
            { "Padding", "acf-lin.padding",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] =
    {
        &ett_1722_lin,
        &ett_1722_lin_flags,
    };

    static ei_register_info ei[] = {
        { &ei_1722_lin_header_cropped,          { "acf-lin.expert.header_cropped",  PI_PROTOCOL, PI_WARN,
                                                  "Message is cropped, no space for header", EXPFILL }},
        { &ei_1722_lin_invalid_payload_length,  { "acf-lin.expert.incorrect_datalen", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect payload length, shall be [0..8]", EXPFILL }},
    };

    expert_module_t* expert_1722_acf_lin;

    /* Register the protocol name and description */
    proto_1722_acf_lin = proto_register_protocol("ACF LIN", "LIN over AVTP", "acf-lin");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_acf_lin, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722_acf_lin = expert_register_protocol(proto_1722_acf_lin);
    expert_register_field_array(expert_1722_acf_lin, ei, array_length(ei));

    avb1722_acf_lin_dissector_table = register_decode_as_next_proto(proto_1722_acf_lin, "acf-lin.subdissector", "ACF-LIN next level dissector", NULL);

    avb1722_acf_lin_handle = register_dissector("acf-lin", dissect_1722_acf_lin, proto_1722_acf_lin);
}

void proto_reg_handoff_1722_acf_lin(void)
{
    dissector_add_uint("acf.msg_type", IEEE_1722_ACF_TYPE_LIN, avb1722_acf_lin_handle);
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
