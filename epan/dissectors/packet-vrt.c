/* packet-vrt.c
 * Routines for VRT (VITA 49) packet disassembly
 * Copyright 2012 Ettus Research LLC - Nick Foster <nick@ettus.com>: original dissector
 * Copyright 2013 Alexander Chemeris <alexander.chemeris@gmail.com>: dissector improvement
 * Copyright 2013 Dario Lombardo (lomato@gmail.com): Official Wireshark port
 *
 * Original dissector repository: https://github.com/bistromath/vrt-dissector
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_vrt(void);

static gint dissector_port_pref = 4991;

static int proto_vrt = -1;

/* fields */
static int hf_vrt_header = -1; /* 32-bit header */
static int hf_vrt_type = -1; /* 4-bit pkt type */
static int hf_vrt_cidflag = -1; /* 1-bit class ID flag */
static int hf_vrt_tflag = -1; /* 1-bit trailer flag */
static int hf_vrt_tsmflag = -1; /* 1-bit timestamp mode */
static int hf_vrt_tsi = -1; /* 2-bit timestamp type */
static int hf_vrt_tsf = -1; /* 2-bit fractional timestamp type */
static int hf_vrt_seq = -1; /* 4-bit sequence number */
static int hf_vrt_len = -1; /* 16-bit length */
static int hf_vrt_sid = -1; /* 32-bit stream ID (opt.) */
static int hf_vrt_cid = -1; /* 64-bit class ID (opt.) */
static int hf_vrt_cid_oui = -1; /* 24-bit class ID OUI */
static int hf_vrt_cid_icc = -1; /* 16-bit class ID ICC */
static int hf_vrt_cid_pcc = -1; /* 16-bit class ID PCC */
static int hf_vrt_ts_int = -1; /* 32-bit integer timestamp (opt.) */
static int hf_vrt_ts_frac_picosecond = -1; /* 64-bit fractional timestamp (opt.) */
static int hf_vrt_ts_frac_sample = -1; /* 64-bit fractional timestamp (opt.) */
static int hf_vrt_data = -1; /* data */
static int hf_vrt_trailer = -1; /* 32-bit trailer (opt.) */
static int hf_vrt_trailer_enables = -1; /* trailer indicator enables */
static int hf_vrt_trailer_ind = -1; /* trailer indicators */
static int hf_vrt_trailer_e = -1; /* ass con pac cnt enable */
static int hf_vrt_trailer_acpc = -1; /* associated context packet count */
static int hf_vrt_trailer_en_caltime = -1; /* calibrated time indicator */
static int hf_vrt_trailer_en_valid = -1; /* valid data ind */
static int hf_vrt_trailer_en_reflock = -1; /* reference locked ind */
static int hf_vrt_trailer_en_agc = -1; /* AGC/MGC enabled ind */
static int hf_vrt_trailer_en_sig = -1; /* signal detected ind */
static int hf_vrt_trailer_en_inv = -1; /* spectral inversion ind */
static int hf_vrt_trailer_en_overrng = -1; /* overrange indicator */
static int hf_vrt_trailer_en_sampleloss = -1; /* sample loss indicator */
static int hf_vrt_trailer_en_user0 = -1; /* User indicator 0 */
static int hf_vrt_trailer_en_user1 = -1; /* User indicator 1 */
static int hf_vrt_trailer_en_user2 = -1; /* User indicator 2 */
static int hf_vrt_trailer_en_user3 = -1; /* User indicator 3 */
static int hf_vrt_trailer_ind_caltime = -1; /* calibrated time indicator */
static int hf_vrt_trailer_ind_valid = -1; /* valid data ind */
static int hf_vrt_trailer_ind_reflock = -1; /* reference locked ind */
static int hf_vrt_trailer_ind_agc = -1; /* AGC/MGC enabled ind */
static int hf_vrt_trailer_ind_sig = -1; /* signal detected ind */
static int hf_vrt_trailer_ind_inv = -1; /* spectral inversion ind */
static int hf_vrt_trailer_ind_overrng = -1; /* overrange indicator */
static int hf_vrt_trailer_ind_sampleloss = -1; /* sample loss indicator */
static int hf_vrt_trailer_ind_user0 = -1; /* User indicator 0 */
static int hf_vrt_trailer_ind_user1 = -1; /* User indicator 1 */
static int hf_vrt_trailer_ind_user2 = -1; /* User indicator 2 */
static int hf_vrt_trailer_ind_user3 = -1; /* User indicator 3 */

/* subtree state variables */
static gint ett_vrt = -1;
static gint ett_header = -1;
static gint ett_trailer = -1;
static gint ett_indicators = -1;
static gint ett_ind_enables = -1;
static gint ett_cid = -1;

static const value_string packet_types[] = {
    {0x00, "IF data packet without stream ID"},
    {0x01, "IF data packet with stream ID"},
    {0x02, "Extension data packet without stream ID"},
    {0x03, "Extension data packet with stream ID"},
    {0x04, "IF context packet"},
    {0x05, "Extension context packet"},
    {0, NULL}
};

static const value_string tsi_types[] = {
    {0x00, "No integer-seconds timestamp field included"},
    {0x01, "Coordinated Universal Time (UTC)"},
    {0x02, "GPS time"},
    {0x03, "Other"},
    {0, NULL}
};

static const value_string tsf_types[] = {
    {0x00, "No fractional-seconds timestamp field included"},
    {0x01, "Sample count timestamp"},
    {0x02, "Real time (picoseconds) timestamp"},
    {0x03, "Free running count timestamp"},
    {0, NULL}
};

static const value_string tsm_types[] = {
    {0x00, "Precise timestamp resolution"},
    {0x01, "General timestamp resolution"},
    {0, NULL}
};

static const int *enable_hfs[] = {
    &hf_vrt_trailer_en_user3,
    &hf_vrt_trailer_en_user2,
    &hf_vrt_trailer_en_user1,
    &hf_vrt_trailer_en_user0,
    &hf_vrt_trailer_en_sampleloss,
    &hf_vrt_trailer_en_overrng,
    &hf_vrt_trailer_en_inv,
    &hf_vrt_trailer_en_sig,
    &hf_vrt_trailer_en_agc,
    &hf_vrt_trailer_en_reflock,
    &hf_vrt_trailer_en_valid,
    &hf_vrt_trailer_en_caltime
};

static const int *ind_hfs[] = {
    &hf_vrt_trailer_ind_user3,
    &hf_vrt_trailer_ind_user2,
    &hf_vrt_trailer_ind_user1,
    &hf_vrt_trailer_ind_user0,
    &hf_vrt_trailer_ind_sampleloss,
    &hf_vrt_trailer_ind_overrng,
    &hf_vrt_trailer_ind_inv,
    &hf_vrt_trailer_ind_sig,
    &hf_vrt_trailer_ind_agc,
    &hf_vrt_trailer_ind_reflock,
    &hf_vrt_trailer_ind_valid,
    &hf_vrt_trailer_ind_caltime
};

void dissect_header(tvbuff_t *tvb, proto_tree *tree, int type, int offset);
void dissect_trailer(tvbuff_t *tvb, proto_tree *tree, int offset);
void dissect_cid(tvbuff_t *tvb, proto_tree *tree, int offset);
void proto_reg_handoff_vrt(void);

static int dissect_vrt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int     offset = 0;
    guint8  type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49");
    col_clear(pinfo->cinfo,COL_INFO);

    /* HACK to support UHD's weird header offset on data packets. */
    if (tvb_get_guint8(tvb, 0) == 0)
        offset += 4;

    /* get packet type */
    type = tvb_get_guint8(tvb, offset) >> 4;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, packet_types, "Reserved packet type (0x%02x)"));

    if (tree) { /* we're being asked for details */
        guint8  sidflag;
        guint8  cidflag;
        guint8  tflag;
        guint8  tsitype;
        guint8  tsftype;
        guint16 len;
        guint16 nsamps;

        proto_tree *vrt_tree;
        proto_item *ti;

        /* get SID, CID, T flags and TSI, TSF types */
        sidflag = (((type & 0x01) != 0) || (type == 4)) ? 1 : 0;
        cidflag = (tvb_get_guint8(tvb, offset) >> 3) & 0x01;
        /* tflag is in data packets but not context packets */
        tflag =   (tvb_get_guint8(tvb, offset) >> 2) & 0x01;
        if (type == 4)
            tflag = 0; /* this should be unnecessary but we do it just in case */
        /* tsmflag is in context packets but not data packets
           tsmflag = (tvb_get_guint8(tvb, offset) >> 0) & 0x01; */
        tsitype = (tvb_get_guint8(tvb, offset+1) >> 6) & 0x03;
        tsftype = (tvb_get_guint8(tvb, offset+1) >> 4) & 0x03;
        len     = tvb_get_ntohs(tvb, offset+2);

        nsamps  = len - 1;  /* (Before adjusting word count for optional fields) */

        ti = proto_tree_add_item(tree, proto_vrt, tvb, offset, -1, ENC_NA);
        vrt_tree = proto_item_add_subtree(ti, ett_vrt);

        dissect_header(tvb, vrt_tree, type, offset);
        offset += 4;

        /* header's done! if SID (last bit of type), put the stream ID here */
        if (sidflag) {
            proto_tree_add_item(vrt_tree, hf_vrt_sid, tvb, offset, 4, ENC_BIG_ENDIAN);
            nsamps -= 1;
            offset += 4;

        }

        /* if there's a class ID (cidflag), put the class ID here */
        if (cidflag) {
            dissect_cid(tvb, vrt_tree, offset);
            nsamps -= 2;
            offset += 8;
        }

        /* if TSI and/or TSF, populate those here */
        if (tsitype != 0) {
            proto_tree_add_item(vrt_tree, hf_vrt_ts_int, tvb, offset, 4, ENC_BIG_ENDIAN);
            nsamps -= 1;
            offset += 4;
        }
        if (tsftype != 0) {
            if (tsftype == 1 || tsftype == 3) {
                proto_tree_add_item(vrt_tree, hf_vrt_ts_frac_sample, tvb, offset, 8, ENC_BIG_ENDIAN);
            } else if (tsftype == 2) {
                proto_tree_add_item(vrt_tree, hf_vrt_ts_frac_picosecond, tvb, offset, 8, ENC_BIG_ENDIAN);
            }
            nsamps -= 2;
            offset += 8;
        }

        if (tflag) {
            nsamps -= 1;
        }

        /* now we've got either a context packet or a data packet
           TODO: parse context packet fully instead of just spewing data */

        /* we're into the data */
        if (nsamps != 0) {
            proto_tree_add_item(vrt_tree, hf_vrt_data, tvb, offset, nsamps*4, ENC_NA);
        }

        offset += nsamps*4;

        if (tflag) {
            dissect_trailer(tvb, vrt_tree, offset);
        }
    }
    return tvb_captured_length(tvb);
}

void dissect_header(tvbuff_t *tvb, proto_tree *tree, int type, int offset)
{
    proto_item *hdr_item;
    proto_tree *hdr_tree;

    hdr_item = proto_tree_add_item(tree, hf_vrt_header, tvb, offset, 4, ENC_BIG_ENDIAN);

    hdr_tree = proto_item_add_subtree(hdr_item, ett_header);
    proto_tree_add_item(hdr_tree, hf_vrt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_cidflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (type == 4) {
        proto_tree_add_item(hdr_tree, hf_vrt_tsmflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(hdr_tree, hf_vrt_tflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;
    proto_tree_add_item(hdr_tree, hf_vrt_tsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_tsf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hdr_tree, hf_vrt_len, tvb, offset, 2, ENC_BIG_ENDIAN);
}

void dissect_trailer(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *enable_item, *ind_item, *trailer_item;
    proto_tree *enable_tree;
    proto_tree *ind_tree;
    proto_tree *trailer_tree;
    guint16     en_bits;
    gint16      i;

    trailer_item = proto_tree_add_item(tree, hf_vrt_trailer, tvb, offset, 4, ENC_BIG_ENDIAN);
    trailer_tree = proto_item_add_subtree(trailer_item, ett_trailer);

    /* grab the indicator enables and the indicators;
       only display enables, indicators which are enabled */
    enable_item = proto_tree_add_item(trailer_tree, hf_vrt_trailer_enables, tvb, offset, 2, ENC_BIG_ENDIAN);
    ind_item = proto_tree_add_item(trailer_tree, hf_vrt_trailer_ind, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    /* grab enable bits */
    en_bits = (tvb_get_ntohs(tvb, offset) & 0xFFF0) >> 4;

    /* if there's any enables, start trees for enable bits and for indicators
       only enables and indicators which are enabled get printed. */
    if (en_bits) {
        enable_tree = proto_item_add_subtree(enable_item, ett_ind_enables);
        ind_tree = proto_item_add_subtree(ind_item, ett_indicators);
        for (i = 11; i >= 0; i--) {
            if (en_bits & (1<<i)) {
                /* XXX: Display needs to be improved ... */
                proto_tree_add_item(enable_tree, *enable_hfs[i], tvb, offset,   2, ENC_BIG_ENDIAN);
                proto_tree_add_item(ind_tree, *ind_hfs[i],       tvb, offset+1, 2, ENC_BIG_ENDIAN);
            }
        }
    }
    offset += 3;
    proto_tree_add_item(trailer_tree, hf_vrt_trailer_e,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(trailer_tree, hf_vrt_trailer_acpc, tvb, offset, 1, ENC_BIG_ENDIAN);
}

void dissect_cid(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *cid_item;
    proto_tree *cid_tree;

    cid_item = proto_tree_add_item(tree, hf_vrt_cid, tvb, offset, 8, ENC_BIG_ENDIAN);
    cid_tree = proto_item_add_subtree(cid_item, ett_cid);

    offset += 1;
    proto_tree_add_item(cid_tree, hf_vrt_cid_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(cid_tree, hf_vrt_cid_icc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(cid_tree, hf_vrt_cid_pcc, tvb, offset, 2, ENC_BIG_ENDIAN);
}

void
proto_register_vrt(void)
{
    static hf_register_info hf[] = {
        { &hf_vrt_header,
            { "VRT header", "vrt.hdr",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_type,
            { "Packet type", "vrt.type",
            FT_UINT8, BASE_DEC,
            VALS(packet_types), 0xF0,
            NULL, HFILL }
        },
        { &hf_vrt_cidflag,
            { "Class ID included", "vrt.cidflag",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_tflag,
            { "Trailer included", "vrt.tflag",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_tsmflag,
            { "Timestamp mode", "vrt.tsmflag",
            FT_UINT8, BASE_DEC,
            VALS(tsm_types), 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_tsi,
            { "Integer timestamp type", "vrt.tsi",
            FT_UINT8, BASE_DEC,
            VALS(tsi_types), 0xC0,
            NULL, HFILL }
        },
        { &hf_vrt_tsf,
            { "Fractional timestamp type", "vrt.tsf",
            FT_UINT8, BASE_DEC,
            VALS(tsf_types), 0x30,
            NULL, HFILL }
        },
        { &hf_vrt_seq,
            { "Sequence number", "vrt.seq",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_vrt_len,
            { "Length", "vrt.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_int,
            { "Integer timestamp", "vrt.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.ts_frac_sample",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.ts_frac_picosecond",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_sid,
            { "Stream ID", "vrt.sid",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid,
            { "Class ID", "vrt.cid",
            FT_UINT64, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_data,
            { "Data", "vrt.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_trailer,
            { "Trailer", "vrt.trailer",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_enables,
            { "Indicator enable bits", "vrt.enables",
            FT_UINT16, BASE_HEX,
            NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind,
            { "Indicator bits", "vrt.indicators",
            FT_UINT16, BASE_HEX,
            NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_e,
            { "Associated context packet count enabled", "vrt.e",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_acpc,
            { "Associated context packet count", "vrt.acpc",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_caltime,
            { "Calibrated time indicator", "vrt.caltime",
            FT_BOOLEAN, 16,
            NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_valid,
            { "Valid signal indicator", "vrt.valid",
            FT_BOOLEAN, 16,
            NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_reflock,
            { "Reference lock indicator", "vrt.reflock",
            FT_BOOLEAN, 16,
            NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_agc,
            { "AGC/MGC indicator", "vrt.agc",
            FT_BOOLEAN, 16,
            NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_sig,
            { "Signal detected indicator", "vrt.sig",
            FT_BOOLEAN, 16,
            NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_inv,
            { "Spectral inversion indicator", "vrt.inv",
            FT_BOOLEAN, 16,
            NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_overrng,
            { "Overrange indicator", "vrt.overrng",
            FT_BOOLEAN, 16,
            NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_sampleloss,
            { "Lost sample indicator", "vrt.sampleloss",
            FT_BOOLEAN, 16,
            NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user0,
            { "User indicator 0", "vrt.user0",
            FT_BOOLEAN, 16,
            NULL, 0x00008,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user1,
            { "User indicator 1", "vrt.user1",
            FT_BOOLEAN, 16,
            NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user2,
            { "User indicator 2", "vrt.user2",
            FT_BOOLEAN, 16,
            NULL, 0x00002,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user3,
            { "User indicator 3", "vrt.user3",
            FT_BOOLEAN, 16,
            NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_caltime,
            { "Calibrated time indicator enable", "vrt.caltime_en",
            FT_BOOLEAN, 16,
            NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_valid,
            { "Valid signal indicator enable", "vrt.valid_en",
            FT_BOOLEAN, 16,
            NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_reflock,
            { "Reference lock indicator enable", "vrt.reflock_en",
            FT_BOOLEAN, 16,
            NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_agc,
            { "AGC/MGC indicator enable", "vrt.agc_en",
            FT_BOOLEAN, 16,
            NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_sig,
            { "Signal detected indicator enable", "vrt.sig_en",
            FT_BOOLEAN, 16,
            NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_inv,
            { "Spectral inversion indicator enable", "vrt.inv_en",
            FT_BOOLEAN, 16,
            NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_overrng,
            { "Overrange indicator enable", "vrt.overrng_en",
            FT_BOOLEAN, 16,
            NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_sampleloss,
            { "Lost sample indicator enable", "vrt.sampleloss_en",
            FT_BOOLEAN, 16,
            NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user0,
            { "User indicator 0 enable", "vrt.user0_en",
            FT_BOOLEAN, 16,
            NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user1,
            { "User indicator 1 enable", "vrt.user1_en",
            FT_BOOLEAN, 16,
            NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user2,
            { "User indicator 2 enable", "vrt.user2_en",
            FT_BOOLEAN, 16,
            NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user3,
            { "User indicator 3 enable", "vrt.user3_en",
            FT_BOOLEAN, 16,
            NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_vrt_cid_oui,
            { "Class ID Organizationally Unique ID", "vrt.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid_icc,
            { "Class ID Information Class Code", "vrt.icc",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid_pcc,
            { "Class ID Packet Class Code", "vrt.pcc",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_vrt,
        &ett_header,
        &ett_trailer,
        &ett_indicators,
        &ett_ind_enables,
        &ett_cid
     };

    module_t *vrt_module;

    proto_vrt = proto_register_protocol (
        "VITA 49 radio transport protocol", /* name       */
        "VITA 49",      /* short name */
        "vrt"       /* abbrev     */
        );

    proto_register_field_array(proto_vrt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    vrt_module = prefs_register_protocol(proto_vrt, proto_reg_handoff_vrt);
    prefs_register_uint_preference(vrt_module,
        "dissector_port",
        "Dissector UDP port",
        "The UDP port used by this dissector",
        10, &dissector_port_pref);
}

void
proto_reg_handoff_vrt(void)
{
    static gboolean vrt_prefs_initialized = FALSE;
    static dissector_handle_t vrt_handle;
    static gint dissector_port;

    if (!vrt_prefs_initialized) {
        vrt_handle = create_dissector_handle(dissect_vrt, proto_vrt);
        vrt_prefs_initialized = TRUE;
    } else {
        dissector_delete_uint("udp.port", dissector_port, vrt_handle);
    }

    dissector_port = dissector_port_pref;

    dissector_add_uint("udp.port", dissector_port, vrt_handle);
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
