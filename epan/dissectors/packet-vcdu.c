/* packet-vcdu.c
 * Routines for VCDU dissection
 * Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
 * Enhanced 2008, Matt Dunkle Matthew.L.Dunkle@nasa.gov
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.com>
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
#include <epan/to_str.h>
#include <epan/uat.h>

void proto_register_vcdu(void);
void proto_reg_handoff_vcdu(void);

/* Initialize the protocol and registered fields */
static int proto_vcdu = -1;

static int hf_smex_gsc = -1;
/* static int hf_smex_unused = -1; */
static int hf_smex_version = -1;
static int hf_smex_framelen = -1;
static int hf_smex_rs_error = -1;
static int hf_smex_rs_enable = -1;
static int hf_smex_crc_enable = -1;
static int hf_smex_crc_error = -1;
static int hf_smex_mcs_enable = -1;
static int hf_smex_mcs_num_error = -1;
static int hf_smex_data_inv = -1;
static int hf_smex_frame_sync = -1;
static int hf_smex_data_dir = -1;
static int hf_smex_data_class = -1;
static int hf_smex_pb5 = -1;
static int hf_smex_jday = -1;
static int hf_smex_seconds = -1;
static int hf_smex_msec = -1;
/* static int hf_smex_spare = -1; */

static int hf_vcdu_version = -1;
static int hf_vcdu_sp_id = -1;
static int hf_vcdu_vc_id = -1;
static int hf_vcdu_seq = -1;
static int hf_vcdu_replay = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_vcdu_data = -1;
static int hf_vcdu_ground_receipt_time = -1;
static int hf_vcdu_ccsds_all_fill = -1;
static int hf_vcdu_bitream_all_fill = -1;
static int hf_vcdu_bitream_all_data = -1;
static int hf_vcdu_bitream_all_data_anomaly = -1;
static int hf_vcdu_ccsds_continuation_packet = -1;

/* although technically not part of the vcdu header, the
 * first header pointer (for ccsds), and the last bit
 * pointer (for bitstream), are more easily processed by
 * simply adding them to the tail end of the vcdu header
 * branch rather than creating a distinct branch for them
 */
static int hf_vcdu_fhp = -1;
static int hf_vcdu_lbp = -1;

static dissector_handle_t vcdu_handle;

static dissector_handle_t ccsds_handle;

/* Initialize the subtree pointers */
static gint ett_vcdu  = -1;
static gint ett_smex  = -1;
static gint ett_vcduh = -1;

static expert_field ei_vcdu_fhp_too_close_to_end_of_vcdu = EI_INIT;

/*
 * Bits in the first 16-bit header word
 */
#define SMEX_VERSION    0xc000
#define SMEX_FRAMELEN   0x3fff

/* some basic sizing parameters */
#define IP_HEADER_LENGTH              48
#define SMEX_HEADER_LENGTH            20
#define VCDU_HEADER_LENGTH             6
#define CCSDS_PRIMARY_HEADER_LENGTH    6
#define CCSDS_SECONDARY_HEADER_LENGTH 10

#define PB5_JULIAN_DAY_MASK   0x7ffe
#define PB5_SECONDS_MASK      0x01ffff
#define PB5_MILLISECONDS_MASK 0xffc0

#define LBP_ALL_DATA          0x3fff
#define LBP_ALL_DATA_ANOMALY  0x7ff
#define LBP_ALL_FILL          0x3ffe

#define FHP_ALL_FILL          0x7fe
#define FHP_CONTINUATION      0x7ff

#define LBP_MASK 0x3fff
#define FHP_MASK 0x7ff

/* leap year macro */
#ifndef Leap
#  define Leap(yr) ( ( 0 == (yr)%4  &&  0 != (yr)%100 )  ||  ( 0 == (yr)%400 ) )
#endif


static const value_string smex_data_inversion_type[] = {
    { 0, "Data True (not inverted)" },
    { 1, "Data Inverted (not corrected)" },
    { 2, "Data Inversion State UNDEFINED" },
    { 3, "Data Inverted (and corrected)" },
    { 0, NULL }
};

static const value_string smex_frame_sync_mode[] = {
    { 0, "Search" },
    { 1, "Check" },
    { 2, "Lock" },
    { 3, "Flywheel" },
    { 0, NULL }
};

static const value_string smex_data_direction[] = {
    { 0, "Forward" },
    { 1, "Reverse" },
    { 0, NULL }
};

static const value_string smex_data_class[] = {
    { 0, "Data Class UNDEFINED" },
    { 1, "CCSDS Frame" },
    { 2, "CCSDS Packet" },
    { 3, "TDM Frame" },
    { 4, "Stopped TDM Frame" },
    { 0, NULL }
};

/* default bitstream channel assignments:
* the audio channels 4-6 are designated as bitstream channels
* the standard bitstream channels are 12 through 19
* the video channels 28-30 are designated as bitstream channels
* the fill channel 63 is designated as bitstream
*/
static int bitstream_channels[] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 0-9 */
    0, 0, 1, 1, 1, 1, 1, 1, 1, 1,  /* channels 10-19 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 20-29 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 30-39 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 40-49 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 50-59 */
    0, 0, 0, 1                     /* channels 60-63 */
};

typedef struct {
    guint channel;
} uat_channel_t;

static uat_channel_t *uat_bitchannels  = NULL;
static uat_t         *vcdu_uat         = NULL;
static guint          num_channels_uat = 0;

UAT_DEC_CB_DEF(uat_bitchannels, channel, uat_channel_t)

static gboolean
vcdu_uat_data_update_cb(void *p, char **err) {
    uat_channel_t *ud = (uat_channel_t *)p;

    if (ud->channel >= 64) {
        *err = g_strdup("Channel must be between 0-63.");
        return FALSE;
    }
    return TRUE;
}

static void
vcdu_prefs_apply_cb(void)
{
    guint i;

    if (num_channels_uat > 0)
    {
        memset(bitstream_channels, 0, sizeof(bitstream_channels));

        for (i = 0; i < num_channels_uat; i++)
        {
            bitstream_channels[uat_bitchannels[i].channel] = 1;
        }
    }
}

/* convert smex PB5 header time to a human readable string - NOT THREAD SAFE
 *
 * note:  this is not true PB5 time either, but a tsi specific version, although it is similar
 */
static const char *
smex_time_to_string (int pb5_days_since_midnight_9_10_oct_1995, int pb5_seconds, int pb5_milliseconds)
{
    static int utcdiff = 0;
    nstime_t t;

    static int Days[2][13] =
        {
            { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
            { 0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
        };

    int yr;
    int ix, days, month;

    /* compute the static constant difference in seconds
     * between midnight 9-10 October 1995 (PB5 time) and
     * seconds since 1/1/1970 (UTC time) just this once
     */
    if (0 == utcdiff)
    {
        for (yr=1970; yr < 1995; ++yr)
        {
            utcdiff += (Leap(yr)  ?  366 : 365) * 24 * 60 * 60;
        }

        days = 0;
        ix = (Leap(1995)  ?  1 : 0);

        for (month=1; month < 10; ++month)
        {
            days += Days[ix][month];
        }

        days += 9;  /* this gets us up to midnight october 9-10 */

        utcdiff += days * 24 * 60 * 60;  /* add days in 1995 prior to October 10 */
    }

    t.secs = (pb5_days_since_midnight_9_10_oct_1995 * 86400) + pb5_seconds + utcdiff;
    t.nsecs = pb5_milliseconds*1000000; /* msecs to nsecs */

    return abs_time_to_str(wmem_packet_scope(), &t, ABSOLUTE_TIME_DOY_UTC, TRUE);
}


static int
dissect_vcdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset           = 0;
    gboolean ccsds_tree_added = FALSE;

    proto_item *smex_header;
    proto_tree *smex_tree;

    proto_tree *vcdu_tree;
    proto_item *vcdu_item;

    guint16 first_word;
    guint32 long_word;

    int vcid, pb5_days, pb5_seconds, pb5_milliseconds;
    const char *time_string;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VCDU");
    col_set_str(pinfo->cinfo, COL_INFO, "Virtual Channel Data Unit");

    /* build the smex header tree */
    smex_tree = proto_tree_add_subtree(tree, tvb, offset, SMEX_HEADER_LENGTH, ett_smex, &smex_header, "SMEX Header");

    proto_tree_add_item(smex_tree, hf_smex_gsc, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    /* proto_tree_add_item(smex_tree, hf_smex_unused, tvb, offset, 2, ENC_BIG_ENDIAN); */
    offset += 2;

    first_word = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(smex_tree, hf_smex_version,  tvb, offset, 2, first_word);
    proto_tree_add_uint(smex_tree, hf_smex_framelen, tvb, offset, 2, first_word);
    offset += 2;

    proto_tree_add_item(smex_tree, hf_smex_rs_enable,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_rs_error,      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_crc_enable,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_crc_error,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_mcs_enable,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_mcs_num_error, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_data_inv,      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(smex_tree, hf_smex_frame_sync, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_data_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_data_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* extract smex ground receipt time tag */
    long_word   = tvb_get_ntohl(tvb, offset);
    pb5_days    = (long_word >> 17) & PB5_JULIAN_DAY_MASK;
    pb5_seconds = (long_word & PB5_SECONDS_MASK);

    first_word = tvb_get_ntohs(tvb, offset+4);
    pb5_milliseconds = (first_word & PB5_MILLISECONDS_MASK) >> 6;

    proto_tree_add_item(smex_tree, hf_smex_pb5,     tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(smex_tree, hf_smex_jday,    tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(smex_tree, hf_smex_seconds, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(smex_tree, hf_smex_msec, tvb, offset, 2, ENC_BIG_ENDIAN);
    /* proto_tree_add_item(smex_tree, hf_smex_spare, tvb, offset, 2, ENC_BIG_ENDIAN); */
    offset += 2;

    /* format ground receipt time into human readable time format for display */
    time_string = smex_time_to_string(pb5_days, pb5_seconds, pb5_milliseconds);
    proto_tree_add_string(smex_tree, hf_vcdu_ground_receipt_time, tvb, offset-6, 6, time_string);

    proto_item_set_end(smex_header, tvb, offset);


    /* build the vcdu header tree */
    vcdu_tree = proto_tree_add_subtree(tree, tvb, offset, VCDU_HEADER_LENGTH, ett_vcdu, &vcdu_item, "VCDU Header");

    /* extract the virtual channel for use later on */
    first_word = tvb_get_ntohs(tvb, offset);
    vcid = first_word & 0x3f;

    proto_tree_add_item(vcdu_tree, hf_vcdu_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(vcdu_tree, hf_vcdu_sp_id,   tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(vcdu_tree, hf_vcdu_vc_id,   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(vcdu_tree, hf_vcdu_seq,     tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(vcdu_tree, hf_vcdu_replay,  tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* extract mpdu/bpdu header word */
    first_word = tvb_get_ntohs(tvb, offset);

    /* do bitstream channel processing */
    if (bitstream_channels[vcid])
    {
        guint16 new_ptr;

        /* extract last bit pointer for bitstream channels */
        new_ptr = first_word & LBP_MASK;

        /* add last bit pointer to display tree */
        proto_tree_add_item(vcdu_tree, hf_vcdu_lbp, tvb, offset, 2, ENC_BIG_ENDIAN);

        switch (new_ptr)
        {
        case LBP_ALL_DATA:
            proto_tree_add_item(vcdu_tree, hf_vcdu_bitream_all_data, tvb, 0, -1, ENC_NA);
            break;

        case LBP_ALL_DATA_ANOMALY:
            proto_tree_add_item(vcdu_tree, hf_vcdu_bitream_all_data_anomaly, tvb, 0, -1, ENC_NA);
            break;

        case LBP_ALL_FILL:
            proto_tree_add_item(vcdu_tree, hf_vcdu_bitream_all_fill, tvb, 0, -1, ENC_NA);
            break;

        default:
            break;
        }
    }  /* end of bitstream channel processing */

    /* do ccsds channel processing */
    else
    {
        guint16 new_ptr;

        /* extract first header pointer for ccsds channels */
        new_ptr = first_word & FHP_MASK;

        /* add first header pointer to display tree */
        proto_tree_add_item(vcdu_tree, hf_vcdu_fhp, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* process special cases of first header pointer */
        if (FHP_ALL_FILL == new_ptr)
        {
            proto_tree_add_item(vcdu_tree, hf_vcdu_ccsds_all_fill, tvb, 0, -1, ENC_NA);
        }

        else if (FHP_CONTINUATION == new_ptr)
        {
            proto_tree_add_item(vcdu_tree, hf_vcdu_ccsds_continuation_packet, tvb, 0, -1, ENC_NA);
        }

        /* process as many ccsds packet headers as we can using the ccsds packet dissector */
        else
        {
            int packet_boundary;
            int new_offset;

            /* compute offset and packet boundary lengths for ccsds dissector loop */
            new_offset = offset + 2 + new_ptr;

            packet_boundary =
                tvb_reported_length(tvb) - VCDU_HEADER_LENGTH
                - CCSDS_PRIMARY_HEADER_LENGTH - CCSDS_SECONDARY_HEADER_LENGTH;

            while ( ((new_offset-offset+2) < packet_boundary)  &&  ((new_offset-offset+2) >= 4) )
            {
                int ccsds_len;
                tvbuff_t *new_tvb;

                ccsds_tree_added = TRUE;
                ccsds_len = tvb_get_ntohs(tvb, new_offset+4);

                new_tvb = tvb_new_subset_remaining(tvb, new_offset);
                call_dissector(ccsds_handle, new_tvb, pinfo, vcdu_tree);

                new_offset = new_offset + ccsds_len + 7;
            }

            if (! ccsds_tree_added)
            {
                proto_tree_add_expert(vcdu_tree, pinfo, &ei_vcdu_fhp_too_close_to_end_of_vcdu, tvb, 0, -1);
            }
        }

    }  /* end of ccsds channel processing */

    /* don't include the mpdu/bpdu header in the vcdu header highlighting.
     * by skipping the offset bump the vcdu header highlighting will show
     * just 6 bytes as it really should, and the fhp/lbp will be included
     * in the data zone, which is technically more correct.
     */
    /* offset += 2; */
    proto_item_set_end(vcdu_item, tvb, offset);

    if (! ccsds_tree_added)
    {
        /* add "Data" section if ccsds parsing did not do so already */
        proto_tree_add_item(vcdu_tree, hf_vcdu_data, tvb, offset, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}


void
proto_register_vcdu(void)
{
    module_t *vcdu_module;

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_smex_gsc,
          { "Ground Sequence Counter",  "vcdu.smex.gsc",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "SMEX Ground Sequence Counter", HFILL }
        },
#if 0
        { &hf_smex_unused,
          { "Unused",  "vcdu.smex.unused",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "SMEX Unused", HFILL }
        },
#endif
        { &hf_smex_version,
          { "Version",           "vcdu.smex.version",
            FT_UINT16, BASE_DEC, NULL, SMEX_VERSION,
            "SMEX Version", HFILL }
        },
        { &hf_smex_framelen,
          { "Frame Length",           "vcdu.smex.frame_len",
            FT_UINT16, BASE_DEC, NULL, SMEX_FRAMELEN,
            "SMEX Frame Length", HFILL }
        },
        { &hf_smex_rs_enable,
          { "RS Enable",           "vcdu.smex.rs_enable",
            FT_BOOLEAN, 8, NULL, 0x80,
            "SMEX RS Enable", HFILL }
        },
        { &hf_smex_rs_error,
          { "RS Error",           "vcdu.smex.rs_error",
            FT_BOOLEAN, 8, NULL, 0x40,
            "SMEX RS Error", HFILL }
        },
        { &hf_smex_crc_enable,
          { "CRC Enable",           "vcdu.smex.crc_enable",
            FT_BOOLEAN, 8, NULL, 0x20,
            "SMEX CRC Enable", HFILL }
        },
        { &hf_smex_crc_error,
          { "CRC Error",           "vcdu.smex.crc_error",
            FT_BOOLEAN, 8, NULL, 0x10,
            "SMEX CRC Error", HFILL }
        },
        { &hf_smex_mcs_enable,
          { "MCS Enable",           "vcdu.smex.mcs_enable",
            FT_BOOLEAN, 8, NULL, 0x08,
            "SMEX MCS Enable", HFILL }
        },
        { &hf_smex_mcs_num_error,
          { "MCS Number Error",           "vcdu.smex.mcs_numerr",
            FT_BOOLEAN, 8, NULL, 0x04,
            "SMEX MCS Number Error", HFILL }
        },
        { &hf_smex_data_inv,
          { "Data Inversion",           "vcdu.smex.data_inv",
            FT_UINT16, BASE_DEC, VALS(smex_data_inversion_type), 0x03,
            "SMEX Data Inversion", HFILL }
        },
        { &hf_smex_frame_sync,
          { "Frame Sync",           "vcdu.smex.frame_sync",
            FT_UINT16, BASE_DEC, VALS(smex_frame_sync_mode), 0xc0,
            "SMEX Frame Sync Flag", HFILL }
        },
        { &hf_smex_data_dir,
          { "Data Direction",           "vcdu.smex.data_dir",
            FT_UINT16, BASE_DEC, VALS(smex_data_direction), 0x20,
            "SMEX Data Direction flag", HFILL }
        },
        { &hf_smex_data_class,
          { "Data Class",           "vcdu.smex.data_class",
            FT_UINT16, BASE_DEC, VALS(smex_data_class), 0x1f,
            "SMEX Data Class", HFILL }
        },
        { &hf_smex_pb5,
          { "PB5 Flag",           "vcdu.smex.pb5",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            "SMEX PB5 Flag", HFILL }
        },
        { &hf_smex_jday,
          { "Julian Day",           "vcdu.smex.jday",
            FT_UINT16, BASE_DEC, NULL, PB5_JULIAN_DAY_MASK,
            "SMEX Julian Day", HFILL }
        },
        { &hf_smex_seconds,
          { "Seconds",           "vcdu.smex.seconds",
            FT_UINT24, BASE_DEC, NULL, PB5_SECONDS_MASK,
            "SMEX Seconds", HFILL }
        },
        { &hf_smex_msec,
          { "Milliseconds",           "vcdu.smex.msec",
            FT_UINT16, BASE_DEC, NULL, PB5_MILLISECONDS_MASK,
            "SMEX Milliseconds", HFILL }
        },
#if 0
        { &hf_smex_spare,
          { "Spare",           "vcdu.smex.spare",
            FT_UINT16, BASE_DEC, NULL, 0x03f,
            "SMEX Spare", HFILL }
        },
#endif

        { &hf_vcdu_version,
          { "Version",           "vcdu.version",
            FT_UINT16, BASE_DEC, NULL, 0xc0,
            "VCDU Version", HFILL }
        },
        { &hf_vcdu_sp_id,
          { "Space Craft ID",           "vcdu.spid",
            FT_UINT16, BASE_DEC, NULL, 0x3fc0,
            "VCDU Space Craft ID", HFILL }
        },
        { &hf_vcdu_vc_id,
          { "Virtual Channel ID",           "vcdu.vcid",
            FT_UINT16, BASE_DEC, NULL, 0x3f,
            "VCDU Virtual Channel ID", HFILL }
        },
        { &hf_vcdu_seq,
          { "Sequence Count",           "vcdu.seq",
            FT_UINT16, BASE_DEC, NULL, 0xffffff,
            "VCDU Sequence Count", HFILL }
        },
        { &hf_vcdu_replay,
          { "Replay Flag",           "vcdu.replay",
            FT_BOOLEAN, 8, NULL, 0x80,
            "VCDU Replay Flag", HFILL }
        },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_vcdu_ground_receipt_time, { "Ground Receipt Time", "vcdu.ground_receipt_time", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vcdu_bitream_all_data, { "Bitream ALL Data", "vcdu.bitream.all_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vcdu_bitream_all_data_anomaly, { "Bitream ALL Data (Anomaly)", "vcdu.bitream.all_data_anomaly", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vcdu_bitream_all_fill, { "Bitream ALL Fill", "vcdu.bitream.all_fill", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vcdu_ccsds_all_fill, { "Ccsds ALL Fill", "vcdu.ccsds.all_fill", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vcdu_ccsds_continuation_packet, { "Ccsds Continuation Packet", "vcdu.ccsds_continuation_packet", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vcdu_data, { "Data", "vcdu.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* not really part of the vcdu header, but it's easier this way */
        { &hf_vcdu_fhp,
          { "First Header Pointer",  "vcdu.fhp",
            FT_UINT16, BASE_DEC, NULL, FHP_MASK,
            "VCDU/MPDU First Header Pointer", HFILL }
        },
        { &hf_vcdu_lbp,
          { "Last Bit Pointer",  "vcdu.lbp",
            FT_UINT16, BASE_DEC, NULL, LBP_MASK,
            "VCDU/BPDU Last Bit Pointer", HFILL }
        }
    };

    static uat_field_t vcdu_uat_flds[] = {
        UAT_FLD_DEC(uat_bitchannels, channel, "Bitstream Channel", "Bitstream Channel"),
        UAT_END_FIELDS
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_vcdu,
        &ett_smex,
        &ett_vcduh,
    };

    static ei_register_info ei[] = {
        { &ei_vcdu_fhp_too_close_to_end_of_vcdu, { "vcdu.fhp_too_close_to_end_of_vcdu", PI_PROTOCOL, PI_WARN, "FHP too close to end of VCDU. Incomplete Hdr Info Available - Unable to format CCSDS Hdr(s).", EXPFILL }},
    };

    expert_module_t* expert_vcdu;

    /* Register the protocol name and description */
    proto_vcdu = proto_register_protocol("VCDU", "VCDU", "vcdu");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_vcdu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_vcdu = expert_register_protocol(proto_vcdu);
    expert_register_field_array(expert_vcdu, ei, array_length(ei));

    /* XX: Does this dissector need to be publicly registered ?? */
    vcdu_handle = register_dissector("vcdu", dissect_vcdu, proto_vcdu);

    vcdu_module = prefs_register_protocol(proto_vcdu, vcdu_prefs_apply_cb);

    vcdu_uat = uat_new("Bitstream Channel Table",
        sizeof(uat_channel_t),
        "vcdu_bitstream_channels",
        TRUE,
        &uat_bitchannels,
        &num_channels_uat,
        UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
        NULL,
        NULL,
        vcdu_uat_data_update_cb,
        NULL,
        NULL,
        vcdu_uat_flds);

    prefs_register_uat_preference(vcdu_module,
        "bitstream_channels",
        "Bitstream Channel Table",
        "Bitstream Channel Table",
        vcdu_uat);

}


void
proto_reg_handoff_vcdu(void)
{
    dissector_add_for_decode_as("udp.port", vcdu_handle);
    ccsds_handle = find_dissector_add_dependency("ccsds", proto_vcdu);
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
