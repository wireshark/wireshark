/* packet-ieee1722.c
 * Routines for AVB-TP (Audio Video Bridging - Transport Protocol) dissection
 * Copyright 2010, Torrey Atcitty <tatcitty@harman.com>
 *                 Dave Olsen <dave.olsen@harman.com>
 *                 Levi Pearson <levi.pearson@harman.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * The 1722 Protocol specification can be found at the following:
 * http://grouper.ieee.org/groups/1722/
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/etypes.h>

/* 1722 Offsets */
#define IEEE_1722_CD_OFFSET                  0
#define IEEE_1722_VERSION_OFFSET             1
#define IEEE_1722_SEQ_NUM_OFFSET             2
#define IEEE_1722_TU_FIELD_OFFSET            3
#define IEEE_1722_STREAM_ID_OFFSET           4
#define IEEE_1722_TIMESTAMP_OFFSET          12
#define IEEE_1722_GW_INFO_OFFSET            16
#define IEEE_1722_PKT_DATA_LENGTH_OFFSET    20
#define IEEE_1722_TAG_OFFSET                22
#define IEEE_1722_TCODE_OFFSET              23
#define IEEE_1722_SID_OFFSET                24
#define IEEE_1722_DBS_OFFSET                25
#define IEEE_1722_FN_OFFSET                 26
#define IEEE_1722_DBC_OFFSET                27
#define IEEE_1722_FMT_OFFSET                28
#define IEEE_1722_FDF_OFFSET                29
#define IEEE_1722_SYT_OFFSET                30
#define IEEE_1722_DATA_OFFSET               32

#define IEEE_1722_CIP_HEADER_SIZE    8

/* Bit Field Masks */
#define IEEE_1722_CD_MASK       0x80
#define IEEE_1722_SUBTYPE_MASK  0x7f
#define IEEE_1722_SV_MASK       0x80
#define IEEE_1722_VER_MASK      0x70
#define IEEE_1722_MR_MASK       0x08
#define IEEE_1722_GV_MASK       0x02
#define IEEE_1722_TV_MASK       0x01
#define IEEE_1722_TU_MASK       0x01
#define IEEE_1722_TAG_MASK      0xc0
#define IEEE_1722_CHANNEL_MASK  0x3f
#define IEEE_1722_TCODE_MASK    0xf0
#define IEEE_1722_SY_MASK       0x0f
#define IEEE_1722_SID_MASK      0x3f
#define IEEE_1722_FN_MASK       0xc0
#define IEEE_1722_QPC_MASK      0x38
#define IEEE_1722_SPH_MASK      0x04
#define IEEE_1722_FMT_MASK      0x3f

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/
static int proto_1722 = -1;
static int hf_1722_cdfield = -1;
static int hf_1722_subtype = -1;
static int hf_1722_svfield = -1;
static int hf_1722_verfield = -1;
static int hf_1722_mrfield = -1;
static int hf_1722_gvfield = -1;
static int hf_1722_tvfield = -1;
static int hf_1722_seqnum = -1;
static int hf_1722_tufield = -1;
static int hf_1722_stream_id = -1;
static int hf_1722_avbtp_timestamp = -1;
static int hf_1722_gateway_info = -1;
static int hf_1722_packet_data_length = -1;
static int hf_1722_tag = -1;
static int hf_1722_channel = -1;
static int hf_1722_tcode = -1;
static int hf_1722_sy = -1;
static int hf_1722_sid = -1;
static int hf_1722_dbs = -1;
static int hf_1722_fn = -1;
static int hf_1722_qpc = -1;
static int hf_1722_sph = -1;
static int hf_1722_dbc = -1;
static int hf_1722_fmt = -1;
static int hf_1722_fdf = -1;
static int hf_1722_syt = -1;
static int hf_1722_data = -1;
static int hf_1722_label = -1;
static int hf_1722_sample = -1;

/* Initialize the subtree pointers */
static int ett_1722 = -1;
static int ett_1722_audio = -1;
static int ett_1722_sample = -1;

static void dissect_1722(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *ieee1722_tree = NULL;
    proto_tree *audio_tree = NULL;
    proto_tree *sample_tree = NULL;
    gint offset = 0;
    guint16 datalen = 0;
    guint8 dbs = 0;
    int i, j;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE1722");

    col_set_str(pinfo->cinfo, COL_INFO, "AVB Transportation Protocol");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_1722, tvb, 0, -1, FALSE);

        ieee1722_tree = proto_item_add_subtree(ti, ett_1722);

        /* Add the CD and Subtype fields 
         * CD field is 1 bit
         * Subtype field is 7 bits
         */
        proto_tree_add_item(ieee1722_tree, hf_1722_cdfield, tvb, IEEE_1722_CD_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_subtype, tvb, IEEE_1722_CD_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_svfield, tvb, IEEE_1722_VERSION_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_verfield, tvb, IEEE_1722_VERSION_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_mrfield, tvb, IEEE_1722_VERSION_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_gvfield, tvb, IEEE_1722_VERSION_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_tvfield, tvb, IEEE_1722_VERSION_OFFSET, 1, FALSE);

        /* Add the rest of the packet fields */
        proto_tree_add_item(ieee1722_tree, hf_1722_seqnum, tvb,
                            IEEE_1722_SEQ_NUM_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_tufield, tvb,
                            IEEE_1722_TU_FIELD_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_stream_id, tvb, 
                            IEEE_1722_STREAM_ID_OFFSET, 8, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_avbtp_timestamp, tvb,
                            IEEE_1722_TIMESTAMP_OFFSET, 4, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_gateway_info, tvb,
                            IEEE_1722_GW_INFO_OFFSET, 4, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_packet_data_length, tvb,
                            IEEE_1722_PKT_DATA_LENGTH_OFFSET, 2, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_tag, tvb,
                            IEEE_1722_TAG_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_channel, tvb, 
                            IEEE_1722_TAG_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_tcode, tvb, 
                            IEEE_1722_TCODE_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_sy, tvb,
                            IEEE_1722_TCODE_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_sid, tvb,
                            IEEE_1722_SID_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_dbs, tvb,
                            IEEE_1722_DBS_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_fn, tvb,
                            IEEE_1722_FN_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_qpc, tvb,
                            IEEE_1722_FN_OFFSET, 1, FALSE);
        proto_tree_add_item(ieee1722_tree, hf_1722_sph, tvb,
                            IEEE_1722_FN_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_dbc, tvb,
                            IEEE_1722_DBC_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_fmt, tvb,
                            IEEE_1722_FMT_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_fdf, tvb,
                            IEEE_1722_FDF_OFFSET, 1, FALSE);

        proto_tree_add_item(ieee1722_tree, hf_1722_syt, tvb,
                            IEEE_1722_SYT_OFFSET, 2, FALSE);

        /* Calculate the remaining size by subtracting the CIP header size 
           from the value in the packet data length field */
        datalen = tvb_get_ntohs(tvb, IEEE_1722_PKT_DATA_LENGTH_OFFSET);
        datalen -= IEEE_1722_CIP_HEADER_SIZE;

        /* Make the Audio sample tree. */
        ti = proto_tree_add_item(ieee1722_tree, hf_1722_data, tvb, 
                                 IEEE_1722_DATA_OFFSET, datalen, ENC_NA);

        audio_tree = proto_item_add_subtree(ti, ett_1722_audio);

        /* Need to get the offset of where the audio data starts */
        offset = IEEE_1722_DATA_OFFSET;
        dbs = tvb_get_guint8(tvb, IEEE_1722_DBS_OFFSET);

        /* If the DBS is ever 0 for whatever reason, then just add the rest of packet as unknown */
        if(dbs == 0)
            proto_tree_add_text(ieee1722_tree, tvb, IEEE_1722_DATA_OFFSET, datalen, "Incorrect DBS");

        else {
            /* Loop through all samples and add them to the audio tree. */
            for (j = 0; j < (datalen / (dbs*4)); j++) {
                ti = proto_tree_add_text(audio_tree, tvb, offset, 1, "Sample %d", j+1);
                sample_tree = proto_item_add_subtree(ti, ett_1722_sample);
                for (i = 0; i < dbs; i++) {
                    proto_tree_add_item(sample_tree, hf_1722_label, tvb, offset, 1, FALSE);
                    offset += 1;

                    proto_tree_add_item(sample_tree, hf_1722_sample, tvb, offset, 3, ENC_NA);
                    offset += 3;
                }
            }
        }
    }
}

/* Register the protocol with Wireshark */
void proto_register_1722(void) 
{
    static hf_register_info hf[] = {
        { &hf_1722_cdfield,
            { "Control/Data Indicator", "ieee1722.cdfield", 
              FT_BOOLEAN, 8, NULL, IEEE_1722_CD_MASK, NULL, HFILL } 
        },
        { &hf_1722_subtype,
            { "AVBTP Subtype", "ieee1722.subtype",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_SUBTYPE_MASK, NULL, HFILL } 
        },
        { &hf_1722_svfield,
            { "AVBTP Stream ID Valid", "ieee1722.svfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_SV_MASK, NULL, HFILL } 
        },
        { &hf_1722_verfield,
            { "AVBTP Version", "ieee1722.verfield",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_VER_MASK, NULL, HFILL } 
        },
        { &hf_1722_mrfield,
            { "AVBTP Media Reset", "ieee1722.mrfield",
              FT_UINT8, BASE_DEC, NULL, IEEE_1722_MR_MASK, NULL, HFILL } 
        },
        { &hf_1722_gvfield,
            { "AVBTP Gateway Info Valid", "ieee1722.gvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_GV_MASK, NULL, HFILL } 
        },
        { &hf_1722_tvfield,
            { "Source Timestamp Valid", "ieee1722.tvfield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TV_MASK, NULL, HFILL } 
            },
        { &hf_1722_seqnum,
            { "Sequence Number", "ieee1722.seqnum",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_tufield,
            { "AVBTP Timestamp Uncertain", "ieee1722.tufield",
              FT_BOOLEAN, 8, NULL, IEEE_1722_TU_MASK, NULL, HFILL }
        },
        { &hf_1722_stream_id,
            { "Stream ID", "ieee1722.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_avbtp_timestamp,
            { "AVBTP Timestamp", "ieee1722.avbtp_timestamp",
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_gateway_info,
            { "Gateway Info", "ieee1722.gateway_info",
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_packet_data_length,
            { "1394 Packet Data Length", "ieee1722.packet_data_len",
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_tag,
            { "1394 Packet Format Tag", "ieee1722.tag",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_TAG_MASK, NULL, HFILL }
        },
        { &hf_1722_channel,
            { "1394 Packet Channel", "ieee1722.channel",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_CHANNEL_MASK, NULL, HFILL }
        },
        { &hf_1722_tcode,
            { "1394 Packet Tcode", "ieee1722.tcode",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_TCODE_MASK, NULL, HFILL }
        },
        { &hf_1722_sy,
            { "1394 App-specific Control", "ieee1722.sy",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_SY_MASK, NULL, HFILL }
        },
        { &hf_1722_sid,
            { "Source ID", "ieee1722.sid",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_SID_MASK, NULL, HFILL }
        },
        { &hf_1722_dbs,
            { "Data Block Size", "ieee1722.dbs",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_fn,
            { "Fraction Number", "ieee1722.fn",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_FN_MASK, NULL, HFILL }
        },
        { &hf_1722_qpc,
            { "Quadlet Padding Count", "ieee1722.qpc",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_QPC_MASK, NULL, HFILL }
        },
        { &hf_1722_sph,
            { "Source Packet Header", "ieee1722.sph",
              FT_BOOLEAN, 8, NULL, IEEE_1722_SPH_MASK, NULL, HFILL }
        },
        { &hf_1722_dbc,
            { "Data Block Continuity", "ieee1722.dbc",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_fmt,
            { "Format ID", "ieee1722.fmt",
              FT_UINT8, BASE_HEX, NULL, IEEE_1722_FMT_MASK, NULL, HFILL }
        },
        { &hf_1722_fdf,
            { "Format Dependent Field", "ieee1722.fdf",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_syt,
            { "SYT", "ieee1722.syt",
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_data,
            { "Audio Data", "ieee1722.data",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_label,
            { "Label", "ieee1722.data.sample.label",
              FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_1722_sample,
            { "Sample", "ieee1722.data.sample.sampledata",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_1722,
        &ett_1722_audio,
        &ett_1722_sample
    };

    /* Register the protocol name and description */
    proto_1722 = proto_register_protocol("IEEE 1722 Protocol", "IEEE1722", "ieee1722");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_1722, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_1722(void) 
{
    dissector_handle_t avbtp_handle;

    avbtp_handle = create_dissector_handle(dissect_1722, proto_1722);
    dissector_add_uint("ethertype", ETHERTYPE_AVBTP, avbtp_handle);
}
