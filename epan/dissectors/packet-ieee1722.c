/* packet-ieee1722.c
 * Routines for AVB-TP (Audio Video Bridging - Transport Protocol) dissection
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
 *
 * The 1722 Protocol specification can be found at the following:
 * http://grouper.ieee.org/groups/1722/
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/etypes.h>

void proto_register_1722(void);
void proto_reg_handoff_1722(void);
void proto_register_1722_crf(void);
void proto_reg_handoff_1722_crf(void);
void proto_register_1722_aaf(void);
void proto_reg_handoff_1722_aaf(void);
void proto_register_1722_61883(void);
void proto_reg_handoff_1722_61883(void);

/**************************************************************************************************/
/* 1722                                                                                           */
/*                                                                                                */
/**************************************************************************************************/
#define IEEE_1722_SUBTYPE_61883             0x00
#define IEEE_1722_SUBTYPE_AAF               0x02
#define IEEE_1722_SUBTYPE_CRF               0x04

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
#define IEEE_1722_SEQ_NUM_MASK                          0x00
#define IEEE_1722_TU_MASK                               0x01
#define IEEE_1722_STREAM_ID_MASK                        0x00
#define IEEE_1722_TIMESTAMP_MASK                        0x00
#define IEEE_1722_FORMAT_MASK                           0x00
#define IEEE_1722_NOM_SAMPLE_RATE_MASK                  0xf000
#define IEEE_1722_CHANNEL_PER_FRAME_MASK                0x03ff
#define IEEE_1722_BIT_DEPTH_MASK                        0x00
#define IEEE_1722_AES3_DATA_TYPE_H_MASK                 0x00
#define IEEE_1722_STREAM_DATA_LENGTH_MASK               0x00
#define IEEE_1722_AES3_DATA_TYPE_REFERENCE_MASK         0xe0
#define IEEE_1722_SP_MASK                               0x10
#define IEEE_1722_EVT_MASK                              0x0f
#define IEEE_1722_AES3_DATA_TYPE_L_MASK                 0x00
#define IEEE_1722_DATA_MASK                             0x00
#define IEEE_1722_SAMPLE_MASK                           0x00

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
    { 0x83, 0xed,   "Reserved for future protocols" },
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
static int proto_1722 = -1;
static int hf_1722_subtype = -1;
static int hf_1722_svfield = -1;
static int hf_1722_verfield = -1;

/* Initialize the subtree pointers */
static int ett_1722 = -1;

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
static int proto_1722_61883 = -1;
static int hf_1722_61883_mrfield = -1;
static int hf_1722_61883_gvfield = -1;
static int hf_1722_61883_tvfield = -1;
static int hf_1722_61883_seqnum = -1;
static int hf_1722_61883_tufield = -1;
static int hf_1722_61883_stream_id = -1;
static int hf_1722_61883_avtp_timestamp = -1;
static int hf_1722_61883_gateway_info = -1;
static int hf_1722_61883_stream_data_length = -1;
static int hf_1722_61883_tag = -1;
static int hf_1722_61883_channel = -1;
static int hf_1722_61883_tcode = -1;
static int hf_1722_61883_sy = -1;
static int hf_1722_61883_cip_qi1 = -1;
static int hf_1722_61883_cip_sid = -1;
static int hf_1722_61883_cip_dbs = -1;
static int hf_1722_61883_cip_fn = -1;
static int hf_1722_61883_cip_qpc = -1;
static int hf_1722_61883_cip_sph = -1;
static int hf_1722_61883_cip_dbc = -1;
static int hf_1722_61883_cip_qi2 = -1;
static int hf_1722_61883_cip_fmt = -1;
static int hf_1722_61883_cip_fdf_no_syt = -1;
static int hf_1722_61883_cip_fdf_tsf = -1;
static int hf_1722_61883_cip_fdf = -1;
static int hf_1722_61883_cip_syt = -1;
static int hf_1722_61883_audio_data = -1;
static int hf_1722_61883_label = -1;
static int hf_1722_61883_sample = -1;
static int hf_1722_61883_video_data = -1;
static int hf_1722_61883_source_packet_header_timestamp = -1;

/* Initialize the subtree pointers */
static int ett_1722_61883 = -1;
static int ett_1722_61883_audio = -1;
static int ett_1722_61883_sample = -1;
static int ett_1722_61883_video = -1;

/* Initialize expert fields */
static expert_field ei_1722_61883_incorrect_tag = EI_INIT;
static expert_field ei_1722_61883_incorrect_tcode = EI_INIT;
static expert_field ei_1722_61883_incorrect_qi1 = EI_INIT;
static expert_field ei_1722_61883_incorrect_qpc = EI_INIT;
static expert_field ei_1722_61883_incorrect_qi2 = EI_INIT;
static expert_field ei_1722_61883_unknown_format = EI_INIT;
static expert_field ei_1722_61883_incorrect_channel_sid = EI_INIT;
static expert_field ei_1722_61883_incorrect_datalen = EI_INIT;
static expert_field ei_1722_61883_4_incorrect_cip_fn = EI_INIT;
static expert_field ei_1722_61883_4_incorrect_cip_dbs = EI_INIT;
static expert_field ei_1722_61883_4_incorrect_cip_sph = EI_INIT;
static expert_field ei_1722_61883_6_incorrect_cip_fn = EI_INIT;
static expert_field ei_1722_61883_6_incorrect_cip_sph = EI_INIT;
static expert_field ei_1722_61883_incorrect_cip_fdf = EI_INIT;

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
static int proto_1722_aaf = -1;
static int hf_1722_aaf_mrfield = -1;
static int hf_1722_aaf_tvfield = -1;
static int hf_1722_aaf_seqnum = -1;
static int hf_1722_aaf_tufield = -1;
static int hf_1722_aaf_stream_id = -1;
static int hf_1722_aaf_avtp_timestamp = -1;
static int hf_1722_aaf_format = -1;
static int hf_1722_aaf_nominal_sample_rate = -1;
static int hf_1722_aaf_bit_depth = -1;
static int hf_1722_aaf_stream_data_length = -1;
static int hf_1722_aaf_sparse_timestamp = -1;
static int hf_1722_aaf_evtfield = -1;
static int hf_1722_aaf_channels_per_frame = -1;
static int hf_1722_aaf_data = -1;
static int hf_1722_aaf_sample = -1;

/* Initialize the subtree pointers */
static int ett_1722_aaf = -1;
static int ett_1722_aaf_audio = -1;
static int ett_1722_aaf_sample = -1;

/* Initialize expert fields */
static expert_field ei_aaf_sample_width = EI_INIT;
static expert_field ei_aaf_reserved_format = EI_INIT;
static expert_field ei_aaf_aes3_format = EI_INIT;
static expert_field ei_aaf_channels_per_frame = EI_INIT;
static expert_field ei_aaf_incorrect_bit_depth = EI_INIT;

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
static int proto_1722_crf = -1;
static int hf_1722_crf_mrfield = -1;
static int hf_1722_crf_fsfield = -1;
static int hf_1722_crf_tufield = -1;
static int hf_1722_crf_seqnum = -1;
static int hf_1722_crf_type = -1;
static int hf_1722_crf_stream_id = -1;
static int hf_1722_crf_pull = -1;
static int hf_1722_crf_base_frequency = -1;
static int hf_1722_crf_data_length = -1;
static int hf_1722_crf_timestamp_interval = -1;
static int hf_1722_crf_timestamp_data = -1;
static int hf_1722_crf_timestamp = -1;

/* Initialize the subtree pointers */
static int ett_1722_crf = -1;
static int ett_1722_crf_timestamp = -1;

/* Initialize expert fields */
static expert_field ei_crf_datalen = EI_INIT;

/**************************************************************************************************/
/* 1722 dissector implementation                                                                  */
/*                                                                                                */
/**************************************************************************************************/
static int dissect_1722(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *ieee1722_tree;
    guint       subtype = 0;
    gint        offset = 0;
    const gint *fields[] = {
        &hf_1722_svfield,
        &hf_1722_verfield,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE1722");
    col_set_str(pinfo->cinfo, COL_INFO, "AVB Transportation Protocol");

    ti = proto_tree_add_item(tree, proto_1722, tvb, 0, -1, ENC_NA);
    ieee1722_tree = proto_item_add_subtree(ti, ett_1722);

    proto_tree_add_item_ret_uint(ieee1722_tree, hf_1722_subtype, tvb, offset, 1, ENC_BIG_ENDIAN, &subtype);
    offset += 1;
    proto_tree_add_bitmask_list(ieee1722_tree, tvb, offset, 1, fields, ENC_NA);

    /* call any registered subtype dissectors which use only the common AVTPDU (e.g. 1722.1, MAAP, 61883, AAF or CRF) */
    if (dissector_try_uint(avb_dissector_table, subtype, tvb, pinfo, tree))
        return tvb_captured_length(tvb);

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void proto_register_1722(void)
{
    static hf_register_info hf[] = {
        { &hf_1722_subtype,
            { "AVBTP Subtype", "ieee1722.subtype",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(subtype_range_rvals), 0x00, NULL, HFILL }
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

    static gint *ett[] = {
        &ett_1722
    };

    /* Register the protocol name and description */
    proto_1722 = proto_register_protocol("IEEE 1722 Protocol", "IEEE1722", "ieee1722");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Sub-dissector for 1772.1, 1722 AAF, 1722 CRF, 1722 61883 */
    avb_dissector_table = register_dissector_table("ieee1722.subtype",
                          "IEEE1722 AVBTP Subtype", proto_1722, FT_UINT8, BASE_HEX);
}

void proto_reg_handoff_1722(void)
{
    dissector_handle_t avbtp_handle;

    avbtp_handle = create_dissector_handle(dissect_1722, proto_1722);
    dissector_add_uint("ethertype", ETHERTYPE_AVBTP, avbtp_handle);
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
    gint        offset = 1;
    guint8      cip_dbs = 0;
    guint8      tag = 0;
    guint8      channel = 0;
    guint8      tcode = 0;
    guint8      cip_qi1 = 0;
    guint8      cip_sid = 0;
    guint8      cip_qpc = 0;
    guint8      cip_qi2 = 0;
    guint8      cip_fmt = 0;
    guint8      cip_sph = 0;
    guint8      cip_fn = 0;
    guint       datalen = 0;
    guint       db_size = 0;
    guint       numSourcePackets = 0;
    guint       i = 0;
    guint       j = 0;
    const gint *fields[] = {
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

    tag = tvb_get_guint8(tvb, offset) & IEEE_1722_TAG_MASK;
    if (tag > 0x40)
    {
        expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_tag);
    }

    ti_channel = proto_tree_add_item(ti_61883_tree, hf_1722_61883_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
    channel = tvb_get_guint8(tvb, offset) & IEEE_1722_CHANNEL_MASK;
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
    tcode = tvb_get_guint8(tvb, offset) & IEEE_1722_TCODE_MASK;
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
        cip_qi1 = tvb_get_guint8(tvb, offset) & IEEE_1722_QI1_MASK;
        if (cip_qi1 != 0)
        {
            expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_qi1);
        }

        ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_sid, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_sid = tvb_get_guint8(tvb, offset) & IEEE_1722_SID_MASK;
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
        cip_dbs = tvb_get_guint8(tvb, offset);
        offset += 1;
        ti_cip_fn = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_fn, tvb, offset, 1, ENC_BIG_ENDIAN);

        switch (tvb_get_guint8(tvb, offset) & IEEE_1722_FN_MASK) {
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
        cip_qpc = tvb_get_guint8(tvb, offset) & IEEE_1722_QPC_MASK;
        if (cip_qpc != 0)
        {
            expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_qpc);
        }

        ti_cip_sph = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_sph, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_sph = tvb_get_guint8(tvb, offset) & IEEE_1722_SPH_MASK;
        offset += 1;
        proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_dbc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        ti = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_qi2, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_qi2 = tvb_get_guint8(tvb, offset) & IEEE_1722_QI2_MASK;
        if (cip_qi2 != 0x80)
        {
            expert_add_info(pinfo, ti, &ei_1722_61883_incorrect_qi2);
        }

        /* Check format field for 61883-4 MPEG-TS video or 61883-6 for audio */
        ti_cip_fmt = proto_tree_add_item(ti_61883_tree, hf_1722_61883_cip_fmt, tvb, offset, 1, ENC_BIG_ENDIAN);
        cip_fmt = tvb_get_guint8(tvb, offset) & IEEE_1722_FMT_MASK;
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
            if (((tvb_get_guint8(tvb, offset) & 0x007fffff) != 0))
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

            if (ti_video_tree) {
                /* Loop through all packets and add them to the video tree. */
                for (j = 0; j < numSourcePackets; j++) {
                    proto_tree_add_item(ti_video_tree, hf_1722_61883_source_packet_header_timestamp, tvb, offset, IEEE_1722_61883_4_LEN_SP_TIMESTAMP, ENC_BIG_ENDIAN);
                    offset += IEEE_1722_61883_4_LEN_SP_TIMESTAMP;
                    proto_tree_add_item(ti_video_tree, hf_1722_61883_video_data, tvb, offset, (IEEE_1722_61883_4_LEN_SOURCE_PACKET - IEEE_1722_61883_4_LEN_SP_TIMESTAMP), ENC_NA);
                    offset += (IEEE_1722_61883_4_LEN_SOURCE_PACKET - IEEE_1722_61883_4_LEN_SP_TIMESTAMP);
                }
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
            { "Media Clock Restart", "61883.mrfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_MR_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_gvfield,
            { "Gateway Info Valid", "61883.gvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_GV_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_tvfield,
            { "Timestamp Valid", "61883.tvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TV_MASK, NULL, HFILL }
            },
        { &hf_1722_61883_seqnum,
            { "Sequence Number", "61883.seqnum",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_tufield,
            { "Timestamp Uncertain", "61883.tufield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TU_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_stream_id,
            { "Stream ID", "61883.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_avtp_timestamp,
            { "AVTP Timestamp", "61883.avtp_timestamp",
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_gateway_info,
            { "Gateway Info", "61883.gateway_info",
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_stream_data_length,
            { "1394 Stream Data Length", "61883.stream_data_len",
              FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_tag,
            { "1394 Packet Format Tag", "61883.tag",
              FT_UINT8, BASE_HEX, VALS(tag_vals), IEEE_1722_TAG_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_channel,
            { "1394 Packet Channel", "61883.channel",
                FT_UINT8, BASE_DEC, NULL, IEEE_1722_CHANNEL_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_tcode,
            { "1394 Packet Tcode", "61883.tcode",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_TCODE_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_sy,
            { "1394 App-specific Control", "61883.sy",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_SY_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_qi1,
            { "CIP Quadlet Indicator 1", "61883.qi1",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_QI1_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_sid,
            { "CIP Source ID", "61883.sid",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_SID_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_dbs,
            { "CIP Data Block Size", "61883.dbs",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fn,
            { "CIP Fraction Number", "61883.fn",
              FT_UINT8, BASE_HEX, VALS(fraction_number_vals), IEEE_1722_FN_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_qpc,
            { "CIP Quadlet Padding Count", "61883.qpc",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_QPC_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_sph,
            { "CIP Source Packet Header", "61883.sph",
              FT_BOOLEAN, 8, NULL, IEEE_1722_SPH_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_dbc,
            { "CIP Data Block Continuity", "61883.dbc",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_cip_qi2,
            { "CIP Quadlet Indicator 2", "61883.qi2",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_QI2_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fmt,
            { "CIP Format ID", "61883.fmt",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(format_rvals), IEEE_1722_FMT_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fdf_no_syt,
            { "CIP Format Dependent Field", "61883.fdf_no_syt",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fdf_tsf,
            { "Time shift flag", "61883.fdf_tsf",
              FT_BOOLEAN, 8, NULL, IEEE_1722_FDF_TSF_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_fdf,
            { "CIP Format Dependent Field", "61883.fdf",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(fdf_rvals), IEEE_1722_FDF_MASK, NULL, HFILL }
        },
        { &hf_1722_61883_cip_syt,
            { "CIP SYT", "61883.syt",
              FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(syt_rvals), 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_audio_data,
            { "Audio Data", "61883.audiodata",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_label,
            { "Label", "61883.audiodata.sample.label",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_sample,
            { "Sample", "61883.audiodata.sample.sampledata",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_video_data,
            { "Video Data", "61883.videodata",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_61883_source_packet_header_timestamp,
            { "Source Packet Header Timestamp", "61883.spht",
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_1722_61883,
        &ett_1722_61883_audio,
        &ett_1722_61883_sample,
        &ett_1722_61883_video
    };

    static ei_register_info ei[] = {
        { &ei_1722_61883_incorrect_tag,         { "61883.incorrect_tag", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect tag field, only 0x00 and 0x01 supported for AVTP", EXPFILL }},
        { &ei_1722_61883_incorrect_tcode,       { "61883.incorrect_tcode", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect tcode, talker shall set this field to 0x0A", EXPFILL }},
        { &ei_1722_61883_incorrect_qi1,         { "61883.incorrect_qi1", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect quadlet indicator 1 field, talker shall set this field to 0x00", EXPFILL }},
        { &ei_1722_61883_incorrect_qpc,         { "61883.incorrect_qpc", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect quadlet padding count field, shall be set to 0", EXPFILL }},
        { &ei_1722_61883_incorrect_qi2,         { "61883.incorrect_qi2", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect quadlet indicator 2 field, talker shall set this field to 0x02", EXPFILL }},
        { &ei_1722_61883_unknown_format,        { "61883.unknown_format", PI_PROTOCOL, PI_NOTE,
                                                  "IEC 61883 format not dissected yet", EXPFILL }},
        { &ei_1722_61883_incorrect_channel_sid, { "61883.incorrect_channel_sid", PI_PROTOCOL, PI_WARN,
                                                  "1394 Packet Channel and Source ID don`t match", EXPFILL }},
        { &ei_1722_61883_incorrect_datalen,     { "61883.incorrect_datalen", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect stream data length field, must be multiple of 192 plus 8 bytes CIP header", EXPFILL }},
        { &ei_1722_61883_4_incorrect_cip_fn,    { "61883.4_incorrect_cip_fn", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect fraction number, shall be 8 for IEC 61883-4", EXPFILL }},
        { &ei_1722_61883_4_incorrect_cip_dbs,   { "61883.4_incorrect_cip_dbs", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect data block size, shall be 6 for IEC 61883-4", EXPFILL }},
        { &ei_1722_61883_4_incorrect_cip_sph,   { "61883.4_incorrect_cip_sph", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect source packet header value, shall be 1 for IEC 61883-4", EXPFILL }},
        { &ei_1722_61883_6_incorrect_cip_fn,    { "61883.6_incorrect_cip_fn", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect fraction number, shall be 0 for IEC 61883-6", EXPFILL }},
        { &ei_1722_61883_6_incorrect_cip_sph,   { "61883.6_incorrect_cip_sph", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect source packet header value, shall be 0 for IEC 61883-6", EXPFILL }},
        { &ei_1722_61883_incorrect_cip_fdf,     { "61883.6_incorrect_cip_fdf", PI_PROTOCOL, PI_WARN,
                                                  "Incorrect frame dependent field value, shall be 0", EXPFILL }}
    };

    expert_module_t* expert_1722_61883;

    /* Register the protocol name and description */
    proto_1722_61883 = proto_register_protocol(
                "IEC 61883 Protocol",   /* name */
                "IEC 61883",            /* short name */
                "61883");               /* abbrev */

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722_61883, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_1722_61883 = expert_register_protocol(proto_1722_61883);
    expert_register_field_array(expert_1722_61883, ei, array_length(ei));
}

void proto_reg_handoff_1722_61883(void)
{
    dissector_handle_t avb1722_61883_handle;

    avb1722_61883_handle = create_dissector_handle(dissect_1722_61883, proto_1722_61883);
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_61883, avb1722_61883_handle);
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
    gint        offset = 1;
    guint       datalen = 0;
    guint       channels_per_frame = 0;
    guint       bit_depth = 0;
    guint       sample_width = 0;
    guint       format = 0;
    guint       i = 0;
    guint       j = 0;
    const gint *fields[] = {
        &hf_1722_aaf_mrfield,
        &hf_1722_aaf_tvfield,
        NULL
    };
    const gint *fields_pcm[] = {
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
            offset += 2;

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

    static gint *ett[] =
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
}

void proto_reg_handoff_1722_aaf(void)
{
    dissector_handle_t avb1722_aaf_handle;

    avb1722_aaf_handle = create_dissector_handle(dissect_1722_aaf, proto_1722_aaf);
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_AAF, avb1722_aaf_handle);
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
    gint        offset = 1;
    guint       datalen = 0;
    guint       j = 0;
    const gint *fields[] = {
        &hf_1722_crf_mrfield,
        &hf_1722_crf_fsfield,
        &hf_1722_crf_tufield,
        NULL
    };
    const gint *pull_frequency[] = {
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
              FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_crf_type,
            { "Type", "crf.type",
              FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(crf_type_range_rvals), 0x00, NULL, HFILL }
        },
        { &hf_1722_crf_stream_id,
            { "Stream ID", "crf.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
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
              FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x00, NULL, HFILL }
        },
        { &hf_1722_crf_timestamp_interval,
            { "Timestamp Interval", "crf.timestamp_interval",
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_crf_timestamp_data,
            { "Timestamp Data", "crf.timestamp_data",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_crf_timestamp,
            { "Data", "crf.timestamp",
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_crf_datalen,              { "crf.expert.crf_datalen", PI_PROTOCOL, PI_WARN, "The CRF data length must be multiple of 8", EXPFILL }}
    };

    static gint *ett[] =
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
}

void proto_reg_handoff_1722_crf(void)
{
    dissector_handle_t avb1722_crf_handle;

    avb1722_crf_handle = create_dissector_handle(dissect_1722_crf, proto_1722_crf);
    dissector_add_uint("ieee1722.subtype", IEEE_1722_SUBTYPE_CRF, avb1722_crf_handle);
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
