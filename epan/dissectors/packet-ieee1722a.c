/* packet-ieee1722a.c
 * Routines for AVB-TP (Audio Video Bridging - Transport Protocol) dissection
 * Copyright 2014, Andreas Leibold <andreas.leibold@harman.com>,
 *                 Patrick Martin <patrick.martin@harman.com>
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
 * The 1722a Protocol specification can be found here:
 * http://grouper.ieee.org/groups/1722/
 *
 * Dissector based on specification version: 1722a Draft 7
 *
 * Only 1722a "Audio" and "Clock Reference Stream Audio Timestamps"
 * are dissected.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_1722a(void);
void proto_reg_handoff_1722a(void);

/* 1722a Offsets */
/* 1722a audio */
#define IEEE_1722A_CD_OFFSET                             0
#define IEEE_1722A_VERSION_OFFSET                        1
#define IEEE_1722A_SEQ_NUM_OFFSET                        2
#define IEEE_1722A_TU_FIELD_OFFSET                       3
#define IEEE_1722A_STREAM_ID_OFFSET                      4
#define IEEE_1722A_TIMESTAMP_OFFSET                     12
#define IEEE_1722A_FORMAT_INFO_OFFSET                   16
#define IEEE_1722A_NOM_SAMPLE_RATE_OFFSET               17
#define IEEE_1722A_CHANNELS_PER_FRAME_OFFSET            17
#define IEEE_1722A_BIT_DEPTH_OFFSET                     19
#define IEEE_1722A_STREAM_DATA_LENGTH_OFFSET            20
#define IEEE_1722A_SPARSE_TIMESTAMP_OFFSET              22
#define IEEE_1722A_EVT_OFFSET                           22
#define IEEE_1722A_DATA_OFFSET                          24
/* CRF */
#define IEEE_1722A_CRF_TYPE_OFFSET                      22
#define IEEE_1722A_CRF_CLOCK_FREQUENCY_OFFSET           24
#define IEEE_1722A_CRF_CLOCK_MULTIPLIER_OFFSET          25
#define IEEE_1722A_CRF_TIMESTAMP_INTERVAL_OFFSET        26
#define IEEE_1722A_CRF_AUDIO_TIMESTAMP_OFFSET           28


/* Bit Field Masks */
/* 1722a audio */
#define IEEE_1722A_SUBTYPE_MASK                         0x7f
#define IEEE_1722A_MR_MASK                              0x08
#define IEEE_1722A_TV_MASK                              0x01
#define IEEE_1722A_TU_MASK                              0x01
#define IEEE_1722A_NOM_SAMPLE_RATE_MASK                 0xf0
#define IEEE_1722A_CHANNEL_PER_FRAME_MASK               0x03ff
#define IEEE_1722A_SP_MASK                              0x10
#define IEEE_1722A_EVT_MASK                             0x0f

#define IEEE_1722A_CRF_AUDIO_SAMPLE_TIMESTAMP           1
#define IEEE_1722A_CRF_TIMESTAMP_SIZE                   8 /* size of the CRF timestamp in bytes */


#define IEEE_1722A_SUBTYPE_AVTP_AUDIO                   0x02
#define IEEE_1722A_SUBTYPE_CRF                          0x05

#define FORMAT_INFO_USER_SPECIFIED       0
#define FORMAT_INFO_32FLOAT              1
#define FORMAT_INFO_32INTEGER            2
#define FORMAT_INFO_24INTEGER            3
#define FORMAT_INFO_16INTEGER            4

static const value_string format_info_vals [] = {
    {FORMAT_INFO_USER_SPECIFIED,        "User specified"},
    {FORMAT_INFO_32FLOAT,               "[32bit floating]"},
    {FORMAT_INFO_32INTEGER,             "[32bit integer]"},
    {FORMAT_INFO_24INTEGER,             "[24bit integer]"},
    {FORMAT_INFO_16INTEGER,             "[16bit integer]"},
    {0,                                 NULL}
};

#define SAMPLE_RATE_USER_SPECIFIED       0
#define SAMPLE_RATE_8K                   1
#define SAMPLE_RATE_16K                  2
#define SAMPLE_RATE_32K                  3
#define SAMPLE_RATE_44K1                 4
#define SAMPLE_RATE_48K                  5
#define SAMPLE_RATE_88K2                 6
#define SAMPLE_RATE_96K                  7
#define SAMPLE_RATE_176K4                8
#define SAMPLE_RATE_192K                 9
#define SAMPLE_RATE_16RPM               10
#define SAMPLE_RATE_33RPM3              11
#define SAMPLE_RATE_33RPM3_REV          12
#define SAMPLE_RATE_45RPM               13
#define SAMPLE_RATE_78RPM               14
#define SAMPLE_RATE_RESERVED            15

static const value_string sample_rate_type_vals [] = {
    {SAMPLE_RATE_USER_SPECIFIED,        "User specified"},
    {SAMPLE_RATE_8K,                    "[8kHz]"},
    {SAMPLE_RATE_16K,                   "[16kHz]"},
    {SAMPLE_RATE_32K,                   "[32kHz]"},
    {SAMPLE_RATE_44K1,                  "[44.1kHz]"},
    {SAMPLE_RATE_48K,                   "[48kHz]"},
    {SAMPLE_RATE_88K2,                  "[88.2kHz]"},
    {SAMPLE_RATE_96K,                   "[96kHz]"},
    {SAMPLE_RATE_176K4,                 "[176.4kHz]"},
    {SAMPLE_RATE_192K,                  "[192kHz]"},
    {SAMPLE_RATE_16RPM,                 "[16 RPM]"},
    {SAMPLE_RATE_33RPM3,                "[33 1/3 RPM]"},
    {SAMPLE_RATE_33RPM3_REV,            "[33 1/3 RPM In Reverse]"},
    {SAMPLE_RATE_45RPM,                 "[45RPM]"},
    {SAMPLE_RATE_78RPM,                 "[78RPM]"},
    {SAMPLE_RATE_RESERVED,              "Reserved"},
    {0,                                 NULL}
};

#define CLOCK_FREQUENCY_OTHER  0
#define CLOCK_FREQUENCY_8K     1
#define CLOCK_FREQUENCY_16K    2
#define CLOCK_FREQUENCY_32K    3
#define CLOCK_FREQUENCY_44K1   4
#define CLOCK_FREQUENCY_88K2   5
#define CLOCK_FREQUENCY_176K4  6
#define CLOCK_FREQUENCY_48K    7
#define CLOCK_FREQUENCY_96K    8
#define CLOCK_FREQUENCY_192K   9

static const value_string clock_frequency_type_vals [] = {
    {CLOCK_FREQUENCY_OTHER,    "Other Nominal Frequency"},
    {CLOCK_FREQUENCY_8K,       "[8kHz]"},
    {CLOCK_FREQUENCY_16K,      "[16kHz]"},
    {CLOCK_FREQUENCY_32K,      "[32kHz]"},
    {CLOCK_FREQUENCY_44K1,     "[44.1kHz]"},
    {CLOCK_FREQUENCY_88K2,     "[88.2kHz]"},
    {CLOCK_FREQUENCY_176K4,    "[176.4kHz]"},
    {CLOCK_FREQUENCY_48K,      "[48kHz]"},
    {CLOCK_FREQUENCY_96K,      "[96kHz]"},
    {CLOCK_FREQUENCY_192K,     "[192kHz]"},
    {0,                          NULL}
};

#define CLOCK_MULTIPLIER_0     0
#define CLOCK_MULTIPLIER_1     1
#define CLOCK_MULTIPLIER_2     2
#define CLOCK_MULTIPLIER_3     3
#define CLOCK_MULTIPLIER_4     4

static const value_string clock_multiplier_type_vals [] = {
    {CLOCK_MULTIPLIER_0,       "[1.0]"},
    {CLOCK_MULTIPLIER_1,       "[1/1.001]"},
    {CLOCK_MULTIPLIER_2,       "[1.001]"},
    {CLOCK_MULTIPLIER_3,       "[24/25]"},
    {CLOCK_MULTIPLIER_4,       "[25/24]"},
    {0,                          NULL}
};

#define CRF_TYPE_OTHER             0
#define CRF_TYPE_AUDIO             1
#define CRF_TYPE_VIDEO_FRAME_SYNC  2
#define CRF_TYPE_VIDEO_LINE_SYNC   3
#define CRF_TYPE_EXPERIMENTAL      0xffff

static const value_string clock_reference_format_type_vals [] = {
    {CRF_TYPE_OTHER,                 "Other"},
    {CRF_TYPE_AUDIO,                 "Audio Sample Timestamp"},
    {CRF_TYPE_VIDEO_FRAME_SYNC,      "Video Frame Sync Timestamp"},
    {CRF_TYPE_VIDEO_LINE_SYNC,       "Video Line Sync Timestamp"},
    {CRF_TYPE_EXPERIMENTAL,          "Experimental"},
    {0,                              NULL}
};

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/
/* 1722a audio */
static int proto_1722a = -1;
static int hf_1722a_mrfield = -1;
static int hf_1722a_tvfield = -1;
static int hf_1722a_seqnum = -1;
static int hf_1722a_tufield = -1;
static int hf_1722a_stream_id = -1;
static int hf_1722a_avbtp_timestamp = -1;
static int hf_1722a_format_info = -1;
static int hf_1722a_nominal_sample_rate = -1;
static int hf_1722a_bit_depth = -1;
static int hf_1722a_stream_data_length = -1;
static int hf_1722a_sparse_timestamp = -1;
static int hf_1722a_evtfield = -1;
static int hf_1722a_channels_per_frame = -1;
static int hf_1722a_data = -1;
static int hf_1722a_sample = -1;

/* CRF */
static int hf_1722a_crf_type = -1;
static int hf_1722a_clock_frequency = -1;
static int hf_1722a_clock_multiplier = -1;
static int hf_1722a_timestamp_interval = -1;
static int hf_1722a_crf_timestamp = -1;
static int hf_1722a_crf_timestamp_data = -1;

/* Initialize the subtree pointers */
static int ett_1722a = -1;
static int ett_1722a_audio = -1;
static int ett_1722a_sample = -1;
static int ett_1722a_crf_timestamp = -1;

static expert_field ei_sample_width         = EI_INIT;
static expert_field ei_channels_per_frame   = EI_INIT;
static expert_field ei_unknown_parameter    = EI_INIT;
static expert_field ei_format_info          = EI_INIT;
static expert_field ei_clock_reference_type = EI_INIT;


static void dissect_1722a (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti                 = NULL;
    proto_tree *ieee1722a_tree     = NULL;
    proto_tree *audio_tree         = NULL;
    proto_tree *sample_tree        = NULL;
    proto_tree *timestamp_tree     = NULL;
    gint        offset             = 0;
    guint16     datalen            = 0;
    guint16     channels_per_frame = 0;
    guint8      subtype            = 0;
    gint        sample_width       = 0;
    int         i, j;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE1722a");

    col_set_str(pinfo->cinfo, COL_INFO, "AVB Transportation Protocol");

    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_1722a, tvb, 0, -1, ENC_NA);
        ieee1722a_tree = proto_item_add_subtree(ti, ett_1722a);
    }

    /* Version field ends the common AVTPDU. Now parse the specfic packet type */
    subtype = tvb_get_guint8(tvb, IEEE_1722A_CD_OFFSET);
    subtype &= IEEE_1722A_SUBTYPE_MASK;

    switch (subtype)
    {
    case IEEE_1722A_SUBTYPE_AVTP_AUDIO:
        if (tree)
        {
            proto_tree_add_item(ieee1722a_tree, hf_1722a_mrfield,         tvb, IEEE_1722A_VERSION_OFFSET,     1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_tvfield,         tvb, IEEE_1722A_VERSION_OFFSET,     1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_seqnum,          tvb, IEEE_1722A_SEQ_NUM_OFFSET,     1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_tufield,         tvb, IEEE_1722A_TU_FIELD_OFFSET,    1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_stream_id,       tvb, IEEE_1722A_STREAM_ID_OFFSET,   8, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_avbtp_timestamp, tvb, IEEE_1722A_TIMESTAMP_OFFSET,   4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_format_info,     tvb, IEEE_1722A_FORMAT_INFO_OFFSET, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(ieee1722a_tree, hf_1722a_nominal_sample_rate, tvb, IEEE_1722A_NOM_SAMPLE_RATE_OFFSET,        1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_channels_per_frame,  tvb, IEEE_1722A_CHANNELS_PER_FRAME_OFFSET,     2, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_bit_depth,           tvb, IEEE_1722A_BIT_DEPTH_OFFSET,              1, ENC_BIG_ENDIAN);
            ti = proto_tree_add_item(ieee1722a_tree, hf_1722a_stream_data_length, tvb, IEEE_1722A_STREAM_DATA_LENGTH_OFFSET, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, " bytes");
            proto_tree_add_item(ieee1722a_tree, hf_1722a_sparse_timestamp, tvb, IEEE_1722A_SPARSE_TIMESTAMP_OFFSET, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ieee1722a_tree, hf_1722a_evtfield,         tvb, IEEE_1722A_EVT_OFFSET,              1, ENC_BIG_ENDIAN);
        }
        /* Make the Audio sample tree. */
        datalen    = tvb_get_ntohs(tvb, IEEE_1722A_STREAM_DATA_LENGTH_OFFSET); /* Length of audio data in bytes */
        ti         = proto_tree_add_item(ieee1722a_tree, hf_1722a_data, tvb, IEEE_1722A_DATA_OFFSET, datalen, ENC_NA);
        audio_tree = proto_item_add_subtree(ti, ett_1722a_audio);

        /* Need to get the offset of where the audio data starts */
        offset              = IEEE_1722A_DATA_OFFSET;
        channels_per_frame  = tvb_get_ntohs(tvb, IEEE_1722A_CHANNELS_PER_FRAME_OFFSET);
        channels_per_frame &= IEEE_1722A_CHANNEL_PER_FRAME_MASK;

        switch (tvb_get_guint8(tvb, IEEE_1722A_FORMAT_INFO_OFFSET))
        {
        case 0:
            break;
        case 1:
            sample_width = 32;
            break;
        case 2:
            sample_width = 32;
            break;
        case 3:
            sample_width = 24;
            break;
        case 4:
            sample_width = 16;
            break;
        default:
            expert_add_info(pinfo, ti, &ei_format_info);
            break;
        }

        if (sample_width == 0)
        {
            expert_add_info(pinfo, ti, &ei_sample_width);
        }
        else
        {
            if (channels_per_frame == 0)
            {
                expert_add_info(pinfo, ti, &ei_channels_per_frame);
            }
            else
            {
                if (tree)
                {
                    /* Loop through all samples and add them to the audio tree. */
                    for (j = 0; j < ((datalen * 8) / (channels_per_frame * sample_width)); j++)
                    {
                        ti = proto_tree_add_text(audio_tree, tvb, offset, 1, "Sample Chunk %d", j);
                        sample_tree = proto_item_add_subtree(ti, ett_1722a_sample);
                        for (i = 0; i < channels_per_frame; i++)
                        {
                            ti = proto_tree_add_item(sample_tree, hf_1722a_sample, tvb, offset, sample_width / 8, ENC_NA);
                            proto_item_prepend_text(ti, "Channel: %d ", i);
                            offset += (sample_width / 8);
                        }
                    }
                }
            }
        }
        break;
    case IEEE_1722A_SUBTYPE_CRF:
        proto_tree_add_item(ieee1722a_tree, hf_1722a_mrfield,   tvb, IEEE_1722A_VERSION_OFFSET,   1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ieee1722a_tree, hf_1722a_tvfield,   tvb, IEEE_1722A_VERSION_OFFSET,   1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ieee1722a_tree, hf_1722a_seqnum,    tvb, IEEE_1722A_SEQ_NUM_OFFSET,   1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ieee1722a_tree, hf_1722a_tufield,   tvb, IEEE_1722A_TU_FIELD_OFFSET,  1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ieee1722a_tree, hf_1722a_stream_id, tvb, IEEE_1722A_STREAM_ID_OFFSET, 8, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(ieee1722a_tree, hf_1722a_stream_data_length, tvb, IEEE_1722A_STREAM_DATA_LENGTH_OFFSET, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " bytes");
        proto_tree_add_item(ieee1722a_tree, hf_1722a_crf_type,  tvb, IEEE_1722A_CRF_TYPE_OFFSET,  2, ENC_BIG_ENDIAN);

        switch (tvb_get_ntohs(tvb, IEEE_1722A_CRF_TYPE_OFFSET))
        {
        /* Audio Timestamp Case */
        case IEEE_1722A_CRF_AUDIO_SAMPLE_TIMESTAMP:
            if (tree)
            {
                proto_tree_add_item(ieee1722a_tree, hf_1722a_clock_frequency,    tvb, IEEE_1722A_CRF_CLOCK_FREQUENCY_OFFSET,    1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ieee1722a_tree, hf_1722a_clock_multiplier,   tvb, IEEE_1722A_CRF_CLOCK_MULTIPLIER_OFFSET,   1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ieee1722a_tree, hf_1722a_timestamp_interval, tvb, IEEE_1722A_CRF_TIMESTAMP_INTERVAL_OFFSET, 2, ENC_BIG_ENDIAN);
                /* Make the Timestamp tree. */
                datalen = tvb_get_ntohs(tvb, IEEE_1722A_STREAM_DATA_LENGTH_OFFSET);
                datalen = datalen - 6; /* remove type field and type header */
                ti = proto_tree_add_item(ieee1722a_tree, hf_1722a_crf_timestamp, tvb, IEEE_1722A_CRF_AUDIO_TIMESTAMP_OFFSET, datalen, ENC_NA);
                timestamp_tree = proto_item_add_subtree(ti, ett_1722a_crf_timestamp);
                offset = IEEE_1722A_CRF_AUDIO_TIMESTAMP_OFFSET;
                /* Loop through all timestamps and add them to the timestamp tree. */
                for (j = 0; j < (datalen / IEEE_1722A_CRF_TIMESTAMP_SIZE); j++)
                {
                    proto_tree_add_item(timestamp_tree, hf_1722a_crf_timestamp_data, tvb, offset, IEEE_1722A_CRF_TIMESTAMP_SIZE, ENC_NA);
                    offset += IEEE_1722A_CRF_TIMESTAMP_SIZE;
                }
            }
            break;
        default:
            expert_add_info(pinfo, ti, &ei_clock_reference_type);
            break;
        }
        break;
    default:
        /* This dissector only registers for subtype 0x02 (AVTP Audio Format) and 0x05 (Clock Reference Format)
           which will be handled above. So we won`t enter the default path. */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }
}

/* Register the protocol with Wireshark */
void proto_register_1722a (void)
{
    expert_module_t *expert_1722a;

    static hf_register_info hf[] =
    {
        { &hf_1722a_mrfield,
            { "AVBTP Media Clock Restart", "ieee1722a.mrfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722A_MR_MASK, NULL, HFILL }
        },
        { &hf_1722a_tvfield,
            { "Source Timestamp Valid", "ieee1722a.tvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722A_TV_MASK, NULL, HFILL }
            },
        { &hf_1722a_seqnum,
            { "Sequence Number", "ieee1722a.seqnum",
              FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_tufield,
            { "AVBTP Timestamp Uncertain", "ieee1722a.tufield",
              FT_BOOLEAN, 8, NULL, IEEE_1722A_TU_MASK, NULL, HFILL }
        },
        { &hf_1722a_stream_id,
            { "Stream ID", "ieee1722a.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_avbtp_timestamp,
            { "AVBTP Timestamp", "ieee1722a.avbtp_timestamp",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_format_info,
            { "Format Info", "ieee1722a.format_info",
              FT_UINT8, BASE_HEX, VALS(format_info_vals), 0x00, NULL, HFILL }
        },
        { &hf_1722a_nominal_sample_rate,
            { "Nominal Sample Rate", "ieee1722a.nominal_sample_rate",
              FT_UINT8, BASE_HEX, VALS(sample_rate_type_vals), IEEE_1722A_NOM_SAMPLE_RATE_MASK, NULL, HFILL }
        },
        { &hf_1722a_bit_depth,
            { "Bit Depth", "ieee1722a.bit_depth",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_stream_data_length,
            { "Stream Data Length", "ieee1722a.stream_data_len",
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_sparse_timestamp,
            { "Sparse Timestamp Mode", "ieee1722a.sparse_timestamp",
              FT_BOOLEAN, 8, NULL, IEEE_1722A_SP_MASK, NULL, HFILL }
        },
        { &hf_1722a_evtfield,
            { "EVT", "ieee1722a.evtfield",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722A_EVT_MASK, NULL, HFILL }
        },
        { &hf_1722a_channels_per_frame,
            { "Channels per Frame", "ieee1722a.channels_per_frame",
              FT_UINT16, BASE_DEC, NULL, IEEE_1722A_CHANNEL_PER_FRAME_MASK, NULL, HFILL }
        },
        { &hf_1722a_data,
            { "Audio Data", "ieee1722a.data",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_sample,
            { "Sample Data", "ieee1722a.data.sample.sampledata",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_crf_type,
            { "Type", "ieee1722a.type",
              FT_UINT16, BASE_HEX, VALS(clock_reference_format_type_vals), 0x00, NULL, HFILL }
        },
        { &hf_1722a_clock_frequency,
            { "Clock Frequency", "ieee1722a.clock_frequency",
              FT_UINT8, BASE_HEX, VALS(clock_frequency_type_vals), 0x00, NULL, HFILL }
        },
        { &hf_1722a_clock_multiplier,
            { "Clock Multiplier", "ieee1722a.clock_multiplier",
              FT_UINT8, BASE_HEX, VALS(clock_multiplier_type_vals), 0x00, NULL, HFILL }
        },
        { &hf_1722a_timestamp_interval,
            { "Timestamp Interval", "ieee1722a.timestamp_interval",
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_crf_timestamp,
            { "Timestamps", "ieee1722a.crf_timestamps",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722a_crf_timestamp_data,
            { "Timestamp Data", "ieee1722a.crf_timestamp_data",
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_sample_width,                 { "1722a.expert.sample_width_zero", PI_PROTOCOL, PI_WARN, "Wrong value for Sample Width", EXPFILL }},
        { &ei_channels_per_frame,           { "1722a.expert.channels_per_frame_zero", PI_PROTOCOL, PI_WARN, "Wrong value for parameter Channels per Frame", EXPFILL }},
        { &ei_unknown_parameter,            { "1722a.expert.unknown_parameter", PI_PROTOCOL, PI_WARN, "Unknown parameter", EXPFILL }},
        { &ei_format_info,                  { "1722a.expert.format_info", PI_PROTOCOL, PI_WARN, "Format Info Value Reserved", EXPFILL }},
        { &ei_clock_reference_type,         { "1722a.expert.clock_reference_format_type", PI_PROTOCOL, PI_WARN, "The CRF type is not supported", EXPFILL }}
    };

    static gint *ett[] =
    {
        &ett_1722a,
        &ett_1722a_audio,
        &ett_1722a_sample,
        &ett_1722a_crf_timestamp
    };

    /* Register the protocol name and description */
    proto_1722a = proto_register_protocol(
        "IEEE 1722a Protocol", /* name */
        "1722A",               /* short name */
        "1722a"                /* abbrev */
        );

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722a, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_1722a = expert_register_protocol(proto_1722a);
    expert_register_field_array(expert_1722a, ei, array_length(ei));
}

void proto_reg_handoff_1722a(void)
{
    dissector_handle_t avb1722a_handle;

    avb1722a_handle = create_dissector_handle(dissect_1722a, proto_1722a);
    dissector_add_uint("ieee1722.subtype", IEEE_1722A_SUBTYPE_AVTP_AUDIO, avb1722a_handle);
    dissector_add_uint("ieee1722.subtype", IEEE_1722A_SUBTYPE_CRF,        avb1722a_handle);
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
