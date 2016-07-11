/* packet-dvb-s2-bb.c
 * Routines for DVB Dynamic Mode Adaption dissection
 *  refer to
 *    http://satlabs.org/pdf/sl_561_Mode_Adaptation_Input_and_Output_Interfaces_for_DVB-S2_Equipment_v1.3.pdf
 *
 * Standards:
 *  ETSI EN 302 307 - Digital Video Broadcasting (DVB) - Framing Structure
 *  ETSI TS 102 606 - Digital Video Broadcasting (DVB) - Generic Stream Encapsulation (GSE) Protocol
 *
 * Copyright 2012, Tobias Rutz <tobias.rutz@work-microwave.de>
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
#include <epan/prefs.h>
#include <epan/etypes.h>

#define BIT_IS_SET(var, bit) ((var) & (1 << (bit)))
#define BIT_IS_CLEAR(var, bit) !BIT_IS_SET(var, bit)

#define DVB_S2_MODEADAPT_MINSIZE        (DVB_S2_MODEADAPT_OUTSIZE  + DVB_S2_BB_OFFS_CRC + 1)
#define DVB_S2_MODEADAPT_INSIZE         2
#define DVB_S2_MODEADAPT_OUTSIZE        4

/* CRC table crc-8, poly=0xD5 */
static guint8 crc8_table[256] = {
    0x00, 0xD5, 0x7F, 0xAA, 0xFE, 0x2B, 0x81, 0x54, 0x29, 0xFC, 0x56, 0x83, 0xD7, 0x02, 0xA8, 0x7D,
    0x52, 0x87, 0x2D, 0xF8, 0xAC, 0x79, 0xD3, 0x06, 0x7B, 0xAE, 0x04, 0xD1, 0x85, 0x50, 0xFA, 0x2F,
    0xA4, 0x71, 0xDB, 0x0E, 0x5A, 0x8F, 0x25, 0xF0, 0x8D, 0x58, 0xF2, 0x27, 0x73, 0xA6, 0x0C, 0xD9,
    0xF6, 0x23, 0x89, 0x5C, 0x08, 0xDD, 0x77, 0xA2, 0xDF, 0x0A, 0xA0, 0x75, 0x21, 0xF4, 0x5E, 0x8B,
    0x9D, 0x48, 0xE2, 0x37, 0x63, 0xB6, 0x1C, 0xC9, 0xB4, 0x61, 0xCB, 0x1E, 0x4A, 0x9F, 0x35, 0xE0,
    0xCF, 0x1A, 0xB0, 0x65, 0x31, 0xE4, 0x4E, 0x9B, 0xE6, 0x33, 0x99, 0x4C, 0x18, 0xCD, 0x67, 0xB2,
    0x39, 0xEC, 0x46, 0x93, 0xC7, 0x12, 0xB8, 0x6D, 0x10, 0xC5, 0x6F, 0xBA, 0xEE, 0x3B, 0x91, 0x44,
    0x6B, 0xBE, 0x14, 0xC1, 0x95, 0x40, 0xEA, 0x3F, 0x42, 0x97, 0x3D, 0xE8, 0xBC, 0x69, 0xC3, 0x16,
    0xEF, 0x3A, 0x90, 0x45, 0x11, 0xC4, 0x6E, 0xBB, 0xC6, 0x13, 0xB9, 0x6C, 0x38, 0xED, 0x47, 0x92,
    0xBD, 0x68, 0xC2, 0x17, 0x43, 0x96, 0x3C, 0xE9, 0x94, 0x41, 0xEB, 0x3E, 0x6A, 0xBF, 0x15, 0xC0,
    0x4B, 0x9E, 0x34, 0xE1, 0xB5, 0x60, 0xCA, 0x1F, 0x62, 0xB7, 0x1D, 0xC8, 0x9C, 0x49, 0xE3, 0x36,
    0x19, 0xCC, 0x66, 0xB3, 0xE7, 0x32, 0x98, 0x4D, 0x30, 0xE5, 0x4F, 0x9A, 0xCE, 0x1B, 0xB1, 0x64,
    0x72, 0xA7, 0x0D, 0xD8, 0x8C, 0x59, 0xF3, 0x26, 0x5B, 0x8E, 0x24, 0xF1, 0xA5, 0x70, 0xDA, 0x0F,
    0x20, 0xF5, 0x5F, 0x8A, 0xDE, 0x0B, 0xA1, 0x74, 0x09, 0xDC, 0x76, 0xA3, 0xF7, 0x22, 0x88, 0x5D,
    0xD6, 0x03, 0xA9, 0x7C, 0x28, 0xFD, 0x57, 0x82, 0xFF, 0x2A, 0x80, 0x55, 0x01, 0xD4, 0x7E, 0xAB,
    0x84, 0x51, 0xFB, 0x2E, 0x7A, 0xAF, 0x05, 0xD0, 0xAD, 0x78, 0xD2, 0x07, 0x53, 0x86, 0x2C, 0xF9
};


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

void proto_register_dvb_s2_modeadapt(void);
void proto_reg_handoff_dvb_s2_modeadapt(void);

/* preferences */
static gboolean dvb_s2_full_dissection = FALSE;

/* Initialize the protocol and registered fields */
static int proto_dvb_s2_modeadapt = -1;
static int hf_dvb_s2_modeadapt_sync = -1;
static int hf_dvb_s2_modeadapt_acm = -1;
static int hf_dvb_s2_modeadapt_acm_fecframe = -1;
static int hf_dvb_s2_modeadapt_acm_pilot = -1;
static int hf_dvb_s2_modeadapt_acm_modcod = -1;
static int hf_dvb_s2_modeadapt_cni = -1;
static int hf_dvb_s2_modeadapt_frameno = -1;

static int proto_dvb_s2_bb = -1;
static int hf_dvb_s2_bb_matype1 = -1;
static int hf_dvb_s2_bb_matype1_gs = -1;
static int hf_dvb_s2_bb_matype1_mis = -1;
static int hf_dvb_s2_bb_matype1_acm = -1;
static int hf_dvb_s2_bb_matype1_issyi = -1;
static int hf_dvb_s2_bb_matype1_npd = -1;
static int hf_dvb_s2_bb_matype1_ro = -1;
static int hf_dvb_s2_bb_matype2 = -1;
static int hf_dvb_s2_bb_upl = -1;
static int hf_dvb_s2_bb_dfl = -1;
static int hf_dvb_s2_bb_sync = -1;
static int hf_dvb_s2_bb_syncd = -1;
static int hf_dvb_s2_bb_crc = -1;

static int proto_dvb_s2_gse = -1;
static int hf_dvb_s2_gse_hdr = -1;
static int hf_dvb_s2_gse_hdr_start = -1;
static int hf_dvb_s2_gse_hdr_stop = -1;
static int hf_dvb_s2_gse_hdr_labeltype = -1;
static int hf_dvb_s2_gse_hdr_length = -1;
static int hf_dvb_s2_gse_proto = -1;
static int hf_dvb_s2_gse_label6 = -1;
static int hf_dvb_s2_gse_label3 = -1;
static int hf_dvb_s2_gse_fragid = -1;
static int hf_dvb_s2_gse_totlength = -1;
static int hf_dvb_s2_gse_exthdr = -1;
static int hf_dvb_s2_gse_data = -1;
static int hf_dvb_s2_gse_crc32 = -1;

/* Initialize the subtree pointers */
static gint ett_dvb_s2_modeadapt = -1;
static gint ett_dvb_s2_modeadapt_acm = -1;

static gint ett_dvb_s2_bb = -1;
static gint ett_dvb_s2_bb_matype1 = -1;

static gint ett_dvb_s2_gse = -1;
static gint ett_dvb_s2_gse_hdr = -1;

/* *** DVB-S2 Modeadaption Header *** */

/* first byte */
#define DVB_S2_MODEADAPT_OFFS_SYNCBYTE          0
#define DVB_S2_MODEADAPT_SYNCBYTE               0xB8

/* second byte */
#define DVB_S2_MODEADAPT_OFFS_ACMBYTE         1
#define DVB_S2_MODEADAPT_MODCODS_MASK   0x1F
static const value_string modeadapt_modcods[] = {
    { 0, "DUMMY PLFRAME"},
    { 1, "QPSK 1/4"},
    { 2, "QPSK 1/3"},
    { 3, "QPSK 2/5"},
    { 4, "QPSK 1/2"},
    { 5, "QPSK 3/5"},
    { 6, "QPSK 2/3"},
    { 7, "QPSK 3/4"},
    { 8, "QPSK 4/5"},
    { 9, "QPSK 5/6"},
    {10, "QPSK 8/9"},
    {11, "QPSK 9/10"},
    {12, "8PSK 3/5"},
    {13, "8PSK 2/3"},
    {14, "8PSK 3/4"},
    {15, "8PSK 5/6"},
    {16, "8PSK 8/9"},
    {17, "8PSK 9/10"},
    {18, "16APSK 2/3"},
    {19, "16APSK 3/4"},
    {20, "16APSK 4/5"},
    {21, "16APSK 5/6"},
    {22, "16APSK 8/9"},
    {23, "16APSK 9/10"},
    {24, "32APSK 3/4"},
    {25, "32APSK 4/5"},
    {26, "32APSK 5/6"},
    {27, "32APSK 8/9"},
    {28, "32APSK 9/10"},
    {29, "reserved"},
    {30, "reserved"},
    {31, "reserved"},
    { 0, NULL}
};
static value_string_ext modeadapt_modcods_ext = VALUE_STRING_EXT_INIT(modeadapt_modcods);

#define DVB_S2_MODEADAPT_PILOTS_MASK    0x20
static const true_false_string tfs_modeadapt_pilots = {
    "pilots on",
    "pilots off"
};

#define DVB_S2_MODEADAPT_FECFRAME_MASK          0x40
static const true_false_string tfs_modeadapt_fecframe = {
    "short",
    "normal"
};

/* third byte */
#define DVB_S2_MODEADAPT_OFFS_CNI             2
static const value_string modeadapt_esno[] = {
    {  0, "modem unlocked, SNR not available"},
    {  1, "-1.000"},
    {  2, "-0.875"},
    {  3, "-0.750"},
    {  4, "-0.625"},
    {  5, "-0.500"},
    {  6, "-0.375"},
    {  7, "-0.250"},
    {  8, "-0.125"},
    {  9, "0.000"},
    { 10, "0.125"},
    { 11, "0.250"},
    { 12, "0.375"},
    { 13, "0.500"},
    { 14, "0.625"},
    { 15, "0.750"},
    { 16, "0.875"},
    { 17, "1.000"},
    { 18, "1.125"},
    { 19, "1.250"},
    { 20, "1.375"},
    { 21, "1.500"},
    { 22, "1.625"},
    { 23, "1.750"},
    { 24, "1.875"},
    { 25, "2.000"},
    { 26, "2.125"},
    { 27, "2.250"},
    { 28, "2.375"},
    { 29, "2.500"},
    { 30, "2.625"},
    { 31, "2.750"},
    { 32, "2.875"},
    { 33, "3.000"},
    { 34, "3.125"},
    { 35, "3.250"},
    { 36, "3.375"},
    { 37, "3.500"},
    { 38, "3.625"},
    { 39, "3.750"},
    { 40, "3.875"},
    { 41, "4.000"},
    { 42, "4.125"},
    { 43, "4.250"},
    { 44, "4.375"},
    { 45, "4.500"},
    { 46, "4.625"},
    { 47, "4.750"},
    { 48, "4.875"},
    { 49, "5.000"},
    { 50, "5.125"},
    { 51, "5.250"},
    { 52, "5.375"},
    { 53, "5.500"},
    { 54, "5.625"},
    { 55, "5.750"},
    { 56, "5.875"},
    { 57, "6.000"},
    { 58, "6.125"},
    { 59, "6.250"},
    { 60, "6.375"},
    { 61, "6.500"},
    { 62, "6.625"},
    { 63, "6.750"},
    { 64, "6.875"},
    { 65, "7.000"},
    { 66, "7.125"},
    { 67, "7.250"},
    { 68, "7.375"},
    { 69, "7.500"},
    { 70, "7.625"},
    { 71, "7.750"},
    { 72, "7.875"},
    { 73, "8.000"},
    { 74, "8.125"},
    { 75, "8.250"},
    { 76, "8.375"},
    { 77, "8.500"},
    { 78, "8.625"},
    { 79, "8.750"},
    { 80, "8.875"},
    { 81, "9.000"},
    { 82, "9.125"},
    { 83, "9.250"},
    { 84, "9.375"},
    { 85, "9.500"},
    { 86, "9.625"},
    { 87, "9.750"},
    { 88, "9.875"},
    { 89, "10.000"},
    { 90, "10.125"},
    { 91, "10.250"},
    { 92, "10.375"},
    { 93, "10.500"},
    { 94, "10.625"},
    { 95, "10.750"},
    { 96, "10.875"},
    { 97, "11.000"},
    { 98, "11.125"},
    { 99, "11.250"},
    {100, "11.375"},
    {101, "11.500"},
    {102, "11.625"},
    {103, "11.750"},
    {104, "11.875"},
    {105, "12.000"},
    {106, "12.125"},
    {107, "12.250"},
    {108, "12.375"},
    {109, "12.500"},
    {110, "12.625"},
    {111, "12.750"},
    {112, "12.875"},
    {113, "13.000"},
    {114, "13.125"},
    {115, "13.250"},
    {116, "13.375"},
    {117, "13.500"},
    {118, "13.625"},
    {119, "13.750"},
    {120, "13.875"},
    {121, "14.000"},
    {122, "14.125"},
    {123, "14.250"},
    {124, "14.375"},
    {125, "14.500"},
    {126, "14.625"},
    {127, "14.750"},
    {128, "14.875"},
    {129, "15.000"},
    {130, "15.125"},
    {131, "15.250"},
    {132, "15.375"},
    {133, "15.500"},
    {134, "15.625"},
    {135, "15.750"},
    {136, "15.875"},
    {137, "16.000"},
    {138, "16.125"},
    {139, "16.250"},
    {140, "16.375"},
    {141, "16.500"},
    {142, "16.625"},
    {143, "16.750"},
    {144, "16.875"},
    {145, "17.000"},
    {146, "17.125"},
    {147, "17.250"},
    {148, "17.375"},
    {149, "17.500"},
    {150, "17.625"},
    {151, "17.750"},
    {152, "17.875"},
    {153, "18.000"},
    {154, "18.125"},
    {155, "18.250"},
    {156, "18.375"},
    {157, "18.500"},
    {158, "18.625"},
    {159, "18.750"},
    {160, "18.875"},
    {161, "19.000"},
    {162, "19.125"},
    {163, "19.250"},
    {164, "19.375"},
    {165, "19.500"},
    {166, "19.625"},
    {167, "19.750"},
    {168, "19.875"},
    {169, "20.000"},
    {170, "20.125"},
    {171, "20.250"},
    {172, "20.375"},
    {173, "20.500"},
    {174, "20.625"},
    {175, "20.750"},
    {176, "20.875"},
    {177, "21.000"},
    {178, "21.125"},
    {179, "21.250"},
    {180, "21.375"},
    {181, "21.500"},
    {182, "21.625"},
    {183, "21.750"},
    {184, "21.875"},
    {185, "22.000"},
    {186, "22.125"},
    {187, "22.250"},
    {188, "22.375"},
    {189, "22.500"},
    {190, "22.625"},
    {191, "22.750"},
    {192, "22.875"},
    {193, "23.000"},
    {194, "23.125"},
    {195, "23.250"},
    {196, "23.375"},
    {197, "23.500"},
    {198, "23.625"},
    {199, "23.750"},
    {200, "23.875"},
    {201, "24.000"},
    {202, "24.125"},
    {203, "24.250"},
    {204, "24.375"},
    {205, "24.500"},
    {206, "24.625"},
    {207, "24.750"},
    {208, "24.875"},
    {209, "25.000"},
    {210, "25.125"},
    {211, "25.250"},
    {212, "25.375"},
    {213, "25.500"},
    {214, "25.625"},
    {215, "25.750"},
    {216, "25.875"},
    {217, "26.000"},
    {218, "26.125"},
    {219, "26.250"},
    {220, "26.375"},
    {221, "26.500"},
    {222, "26.625"},
    {223, "26.750"},
    {224, "26.875"},
    {225, "27.000"},
    {226, "27.125"},
    {227, "27.250"},
    {228, "27.375"},
    {229, "27.500"},
    {230, "27.625"},
    {231, "27.750"},
    {232, "27.875"},
    {233, "28.000"},
    {234, "28.125"},
    {235, "28.250"},
    {236, "28.375"},
    {237, "28.500"},
    {238, "28.625"},
    {239, "28.750"},
    {240, "28.875"},
    {241, "29.000"},
    {242, "29.125"},
    {243, "29.250"},
    {244, "29.375"},
    {245, "29.500"},
    {246, "29.625"},
    {247, "29.750"},
    {248, "29.875"},
    {249, "30.000"},
    {250, "30.125"},
    {251, "30.250"},
    {252, "30.375"},
    {253, "30.500"},
    {254, "30.625"},
    {255, ">30.750"},
    {  0, NULL}
};
static value_string_ext modeadapt_esno_ext = VALUE_STRING_EXT_INIT(modeadapt_esno);

/* fourth byte */
#define DVB_S2_MODEADAPT_OFFS_FNO                  3

/* *** DVB-S2 Base-Band Frame *** */

#define DVB_S2_BB_HEADER_LEN    10

#define DVB_S2_BB_OFFS_MATYPE1          0
#define DVB_S2_BB_GS_MASK               0xC0
static const value_string bb_gs[] = {
    {0, "Generic Packetized (GSE)"},
    {1, "Generic continuous (GSE)"},
    {2, "reserved"},
    {3, "Transport (TS)"},
    {0, NULL}
};

#define DVB_S2_BB_MIS_POS          5
#define DVB_S2_BB_MIS_MASK      0x20
static const true_false_string tfs_bb_mis = {
    "single (SIS)",
    "multiple (MIS)"
};

#define DVB_S2_BB_ACM_MASK      0x10
static const true_false_string tfs_bb_acm = {
    "constant (CCM)",
    "adaptive (ACM)"
};

#define DVB_S2_BB_ISSYI_MASK    0x08
static const true_false_string tfs_bb_issyi = {
    "active",
    "not-active"
};

#define DVB_S2_BB_NPD_MASK      0x04
static const true_false_string tfs_bb_npd = {
    "active",
    "not-active"
};

#define DVB_S2_BB_RO_MASK       0x03
static const value_string bb_ro[] = {
    {0, "0,35"},
    {1, "0,25"},
    {2, "0,20"},
    {3, "<0,20 / reserved"},
    {0, NULL}
};

#define DVB_S2_BB_OFFS_MATYPE2          1
#define DVB_S2_BB_OFFS_UPL              2
#define DVB_S2_BB_OFFS_DFL              4
#define DVB_S2_BB_OFFS_SYNC             6
#define DVB_S2_BB_OFFS_SYNCD            7
#define DVB_S2_BB_OFFS_CRC              9

/* *** DVB-S2 GSE Frame *** */

#define DVB_S2_GSE_MINSIZE              2

#define DVB_S2_GSE_OFFS_HDR             0
#define DVB_S2_GSE_HDR_START_MASK       0x8000
#define DVB_S2_GSE_HDR_START_POS        15
#define DVB_S2_GSE_HDR_STOP_MASK        0x4000
#define DVB_S2_GSE_HDR_STOP_POS         14
static const true_false_string tfs_gse_ss = {
    "enabled",
    "disabled"
};

#define DVB_S2_GSE_HDR_LABELTYPE_MASK   0x3000
#define DVB_S2_GSE_HDR_LABELTYPE_POS1   13
#define DVB_S2_GSE_HDR_LABELTYPE_POS2   12
static const value_string gse_labeltype[] = {
    {0, "6 byte"},
    {1, "3 byte"},
    {2, "0 byte (Broadcast)"},
    {3, "re-use last label"},
    {0, NULL}
};

#define DVB_S2_GSE_HDR_LENGTH_MASK      0x0FFF

static const range_string gse_proto_str[] = {
    {0x0000        , 0x00FF        , "not implemented"},
    {0x0100        , 0x05FF        , "not implemented"},
    {0x0600        , 0x07FF        , "not implemented"},
    {ETHERTYPE_IP  , ETHERTYPE_IP  , "IPv4 Payload"   },
    {0x0801        , 0x86DC        , "not implemented"},
    {ETHERTYPE_IPv6, ETHERTYPE_IPv6, "IPv6 Payload"   },
    {0x86DE        , 0xFFFF        , "not implemented"},
    {0             , 0             , NULL             }
};

#define DVB_S2_GSE_CRC32_LEN            4

/* *** helper functions *** */
static gboolean check_crc8(tvbuff_t *p, guint8 len, guint8 offset, guint8 received_fcs)
{
    int    i;
    guint8 crc = 0, tmp;

    for (i = 0; i < len; i++) {
        tmp = tvb_get_guint8(p, offset++);
        crc = crc8_table[crc ^ tmp];
    }
    if (received_fcs == crc)
        return TRUE;
    else
        return FALSE;
}

/* *** Code to actually dissect the packets *** */
static int dissect_dvb_s2_gse(tvbuff_t *tvb, int cur_off, proto_tree *tree, packet_info *pinfo)
{
    int         new_off                      = 0;
    int         frag_len;
    guint16     gse_hdr, data_len, gse_proto = 0;

    proto_item *ti, *tf;
    proto_tree *dvb_s2_gse_tree, *dvb_s2_gse_hdr_tree;

    tvbuff_t   *next_tvb;

    col_append_str(pinfo->cinfo, COL_INFO, "GSE");

    /* get header and determine length */
    gse_hdr = tvb_get_ntohs(tvb, cur_off + DVB_S2_GSE_OFFS_HDR);
    new_off += 2;
    frag_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK)+2;

    ti = proto_tree_add_item(tree, proto_dvb_s2_gse, tvb, cur_off, frag_len, ENC_NA);
    dvb_s2_gse_tree = proto_item_add_subtree(ti, ett_dvb_s2_gse);

    tf = proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_hdr, tvb, cur_off + DVB_S2_GSE_OFFS_HDR, 2, gse_hdr);

    dvb_s2_gse_hdr_tree = proto_item_add_subtree(tf, ett_dvb_s2_gse_hdr);
    proto_tree_add_item(dvb_s2_gse_hdr_tree, hf_dvb_s2_gse_hdr_start, tvb, cur_off + DVB_S2_GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_gse_hdr_tree, hf_dvb_s2_gse_hdr_stop, tvb, cur_off + DVB_S2_GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_gse_hdr_tree, hf_dvb_s2_gse_hdr_labeltype, tvb,
                        cur_off + DVB_S2_GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_gse_hdr_tree, hf_dvb_s2_gse_hdr_length, tvb, cur_off + DVB_S2_GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);

    if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) &&
        BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS) &&
        BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS1) && BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS2)) {
        col_append_str(pinfo->cinfo, COL_INFO, " ");
        return new_off;
    } else {
        if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) || BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {

            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_fragid, tvb, cur_off + new_off, 1, ENC_BIG_ENDIAN);

            new_off += 1;
        }
        if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS) && BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {

            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_totlength, tvb, cur_off + new_off, 2, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, "(frag) ");

            new_off += 2;
        }
        if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS)) {
            gse_proto = tvb_get_ntohs(tvb, cur_off + new_off);

            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_proto, tvb, cur_off + new_off, 2, ENC_BIG_ENDIAN);

            new_off += 2;

            if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS1) && BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS2)) {
                /* 6 byte label */
                if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS))
                    col_append_str(pinfo->cinfo, COL_INFO, "6 ");

                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_label6, tvb, cur_off + new_off, 6, ENC_NA);

                new_off += 6;
            } else if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS1) &&
                       BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS2)) {
                /* 3 byte label */
                if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS))
                    col_append_str(pinfo->cinfo, COL_INFO, "3 ");

                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_label3, tvb, cur_off + new_off, 3, ENC_BIG_ENDIAN);

                new_off += 3;
            } else {
                /* 0 byte label */
                if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS))
                    col_append_str(pinfo->cinfo, COL_INFO, "0 ");
            }
            if (gse_proto < 0x0600 && gse_proto >= 0x100) {
                /* Only display optional extension headers */
                /* TODO: needs to be tested */

                /* TODO: implementation needs to be checked (len of ext-header??) */
                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_exthdr, tvb, cur_off + new_off, 1, ENC_BIG_ENDIAN);

                new_off += 1;
            }
        }
        else
        {
            /* correct cinfo */
            col_append_str(pinfo->cinfo, COL_INFO, "(frag) ");
        }

        next_tvb = tvb_new_subset_remaining(tvb, cur_off + new_off);

        if (dvb_s2_full_dissection)
        {
            switch (gse_proto) {
            case ETHERTYPE_IP:
                new_off += call_dissector(ip_handle, next_tvb, pinfo, tree);
                break;
            case ETHERTYPE_IPv6:
                new_off += call_dissector(ipv6_handle, next_tvb, pinfo, tree);
                break;
            default:
                if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
                    data_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK) - (new_off - DVB_S2_GSE_MINSIZE) - DVB_S2_GSE_CRC32_LEN;
                } else
                    data_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK) - (new_off - DVB_S2_GSE_MINSIZE);

                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_data, tvb, cur_off + new_off, data_len, ENC_NA);
                new_off += data_len;
                break;
            }
        }
        else
        {
            if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
                data_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK) - (new_off - DVB_S2_GSE_MINSIZE) - DVB_S2_GSE_CRC32_LEN;
            } else
                data_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK) - (new_off - DVB_S2_GSE_MINSIZE);

            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_data, tvb, cur_off + new_off, data_len, ENC_NA);
            new_off += data_len;
        }

        /* add crc32 if last fragment */
        if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_crc32, tvb, cur_off + new_off, DVB_S2_GSE_CRC32_LEN, ENC_BIG_ENDIAN);
            new_off += DVB_S2_GSE_CRC32_LEN;
        }
    }

    return new_off;
}

static gboolean test_dvb_s2_crc(tvbuff_t *tvb, guint offset) {

    guint8 input8;

    /* only check BB Header and return */
    if (tvb_captured_length(tvb) < (offset + DVB_S2_BB_HEADER_LEN))
        return FALSE;

    input8 = tvb_get_guint8(tvb, offset + DVB_S2_BB_OFFS_CRC);

    if (!check_crc8(tvb, DVB_S2_BB_HEADER_LEN - 1, offset, input8))
        return FALSE;
    else
        return TRUE;
}




static int dissect_dvb_s2_bb(tvbuff_t *tvb, int cur_off, proto_tree *tree, packet_info *pinfo)
{
    proto_item *ti, *tf;
    proto_tree *dvb_s2_bb_tree, *dvb_s2_bb_matype1_tree;

    guint8      input8;
    guint16     input16, bb_data_len = 0;

    int         sub_dissected        = 0, flag_is_ms = 0, new_off = 0;

    col_append_str(pinfo->cinfo, COL_PROTOCOL, "BB ");
    col_append_str(pinfo->cinfo, COL_INFO, "Baseband ");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dvb_s2_bb, tvb, cur_off, DVB_S2_BB_HEADER_LEN, ENC_NA);
    dvb_s2_bb_tree = proto_item_add_subtree(ti, ett_dvb_s2_bb);

    input8 = tvb_get_guint8(tvb, cur_off + DVB_S2_BB_OFFS_MATYPE1);
    new_off += 1;

    if (BIT_IS_CLEAR(input8, DVB_S2_BB_MIS_POS))
        flag_is_ms = 1;

    tf = proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_matype1, tvb, cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, input8);
    dvb_s2_bb_matype1_tree = proto_item_add_subtree(tf, ett_dvb_s2_bb_matype1);
    proto_tree_add_item(dvb_s2_bb_matype1_tree, hf_dvb_s2_bb_matype1_gs, tvb,
                        cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_bb_matype1_tree, hf_dvb_s2_bb_matype1_mis, tvb,
                        cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_bb_matype1_tree, hf_dvb_s2_bb_matype1_acm, tvb,
                        cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_bb_matype1_tree, hf_dvb_s2_bb_matype1_issyi, tvb,
                        cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_bb_matype1_tree, hf_dvb_s2_bb_matype1_npd, tvb,
                        cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_bb_matype1_tree, hf_dvb_s2_bb_matype1_ro, tvb,
                        cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);

    input8 = tvb_get_guint8(tvb, cur_off + DVB_S2_BB_OFFS_MATYPE2);
    new_off += 1;
    if (flag_is_ms) {
        proto_tree_add_uint_format_value(dvb_s2_bb_tree, hf_dvb_s2_bb_matype2, tvb,
                                   cur_off + DVB_S2_BB_OFFS_MATYPE2, 1, input8, "Input Stream Identifier (ISI): %d",
                                   input8);
    } else {
        proto_tree_add_uint_format_value(dvb_s2_bb_tree, hf_dvb_s2_bb_matype2, tvb,
                                   cur_off + DVB_S2_BB_OFFS_MATYPE2, 1, input8, "reserved");
    }

    input16 = tvb_get_ntohs(tvb, cur_off + DVB_S2_BB_OFFS_UPL);
    new_off += 2;

    proto_tree_add_uint_format(dvb_s2_bb_tree, hf_dvb_s2_bb_upl, tvb,
                               cur_off + DVB_S2_BB_OFFS_UPL, 2, input16, "User Packet Length: %d bits (%d bytes)",
                               (guint16) input16, (guint16) input16 / 8);

    bb_data_len = input16 = tvb_get_ntohs(tvb, cur_off + DVB_S2_BB_OFFS_DFL);
    bb_data_len /= 8;
    new_off += 2;

    proto_tree_add_uint_format_value(dvb_s2_bb_tree, hf_dvb_s2_bb_dfl, tvb,
                               cur_off + DVB_S2_BB_OFFS_DFL, 2, input16, "%d bits (%d bytes)", input16, input16 / 8);

    new_off += 1;
    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_sync, tvb, cur_off + DVB_S2_BB_OFFS_SYNC, 1, ENC_BIG_ENDIAN);

    new_off += 2;
    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_syncd, tvb, cur_off + DVB_S2_BB_OFFS_SYNCD, 2, ENC_BIG_ENDIAN);

    input8 = tvb_get_guint8(tvb, cur_off + DVB_S2_BB_OFFS_CRC);
    new_off += 1;

    proto_tree_add_checksum(dvb_s2_bb_tree, tvb, cur_off + DVB_S2_BB_OFFS_CRC, hf_dvb_s2_bb_crc, -1, NULL, pinfo,
        check_crc8(tvb, DVB_S2_BB_HEADER_LEN - 1, cur_off, input8), ENC_NA, PROTO_CHECKSUM_VERIFY);

    while (bb_data_len) {
        /* start DVB-GSE dissector */
        sub_dissected = dissect_dvb_s2_gse(tvb, cur_off + new_off, tree, pinfo);
        new_off += sub_dissected;

        if ((sub_dissected <= bb_data_len) && (sub_dissected >= DVB_S2_GSE_MINSIZE)) {
            bb_data_len -= sub_dissected;
            if (bb_data_len < DVB_S2_GSE_MINSIZE)
                bb_data_len = 0;
        } else
            bb_data_len = 0;
    }

    return new_off;
}

static int dissect_dvb_s2_modeadapt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int         cur_off = 0, dvb_s2_modeadapt_len = -1;

    proto_item *ti, *tf;
    proto_tree *dvb_s2_modeadapt_tree;
    proto_tree *dvb_s2_modeadapt_acm_tree;

    guint8      byte;

    /* Check that there's enough data */
    if (tvb_captured_length(tvb) < 1)
        return 0;

    /* Check if first byte is valid for this dissector */
    byte = tvb_get_guint8(tvb, DVB_S2_MODEADAPT_OFFS_SYNCBYTE);
    cur_off++;
    if (byte != DVB_S2_MODEADAPT_SYNCBYTE)
        return 0;

    /* Check if BB-Header CRC is valid and determine input or output */

    if (test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_INSIZE)) {
        dvb_s2_modeadapt_len = 2;
    } else if (test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_OUTSIZE)) {
        dvb_s2_modeadapt_len = 4;
    } else {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVB-S2 ");
    col_set_str(pinfo->cinfo, COL_INFO,     "DVB-S2 ");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dvb_s2_modeadapt, tvb, 0, dvb_s2_modeadapt_len, ENC_NA);
    dvb_s2_modeadapt_tree = proto_item_add_subtree(ti, ett_dvb_s2_modeadapt);

    proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_sync, tvb, DVB_S2_MODEADAPT_OFFS_SYNCBYTE, 1, ENC_BIG_ENDIAN);

    cur_off++;
    tf = proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_acm, tvb,
                             DVB_S2_MODEADAPT_OFFS_ACMBYTE, 1, ENC_BIG_ENDIAN);

    dvb_s2_modeadapt_acm_tree = proto_item_add_subtree(tf, ett_dvb_s2_modeadapt_acm);

    proto_tree_add_item(dvb_s2_modeadapt_acm_tree, hf_dvb_s2_modeadapt_acm_fecframe, tvb,
                        DVB_S2_MODEADAPT_OFFS_ACMBYTE, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_modeadapt_acm_tree, hf_dvb_s2_modeadapt_acm_pilot, tvb,
                        DVB_S2_MODEADAPT_OFFS_ACMBYTE, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_s2_modeadapt_acm_tree, hf_dvb_s2_modeadapt_acm_modcod, tvb,
                        DVB_S2_MODEADAPT_OFFS_ACMBYTE, 1, ENC_BIG_ENDIAN);

    if (dvb_s2_modeadapt_len > 2) {
        cur_off++;
        proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_cni, tvb, DVB_S2_MODEADAPT_OFFS_CNI, 1, ENC_BIG_ENDIAN);

        cur_off++;
        proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_frameno, tvb, DVB_S2_MODEADAPT_OFFS_FNO, 1, ENC_BIG_ENDIAN);
    }

    /* start DVB-BB dissector */
    cur_off = dissect_dvb_s2_bb(tvb, cur_off, tree, pinfo);


    return cur_off;
}


/* Register the protocol with Wireshark */
void proto_register_dvb_s2_modeadapt(void)
{
    module_t *dvb_s2_modeadapt_module;

    static hf_register_info hf_modeadapt[] = {
        {&hf_dvb_s2_modeadapt_sync, {
                "Sync Byte", "dvb-s2_modeadapt.sync",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Das Sync Byte", HFILL}
        },
        {&hf_dvb_s2_modeadapt_acm, {
                "ACM command", "dvb-s2_modeadapt.acmcmd",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_dvb_s2_modeadapt_acm_fecframe, {
                "FEC frame size", "dvb-s2_modeadapt.acmcmd.fecframe",
                FT_BOOLEAN, 8, TFS(&tfs_modeadapt_fecframe), DVB_S2_MODEADAPT_FECFRAME_MASK,
                "FEC", HFILL}
        },
        {&hf_dvb_s2_modeadapt_acm_pilot, {
                "Pilots configuration", "dvb-s2_modeadapt.acmcmd.pilots",
                FT_BOOLEAN, 8, TFS(&tfs_modeadapt_pilots), DVB_S2_MODEADAPT_PILOTS_MASK,
                "Pilots", HFILL}
        },
        {&hf_dvb_s2_modeadapt_acm_modcod, {
                "Modcod indicator", "dvb-s2_modeadapt.acmcmd.modcod",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, &modeadapt_modcods_ext, DVB_S2_MODEADAPT_MODCODS_MASK,
                "Modcod", HFILL}
        },
        {&hf_dvb_s2_modeadapt_cni, {
                "Carrier to Noise [dB]", "dvb-s2_modeadapt.cni",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, &modeadapt_esno_ext, 0x0,
                "CNI", HFILL}
        },
        {&hf_dvb_s2_modeadapt_frameno, {
                "Frame number", "dvb-s2_modeadapt.frameno",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "fno", HFILL}
        }
    };

/* Setup protocol subtree array */
    static gint *ett_modeadapt[] = {
        &ett_dvb_s2_modeadapt,
        &ett_dvb_s2_modeadapt_acm
    };

    static hf_register_info hf_bb[] = {
        {&hf_dvb_s2_bb_matype1, {
                "MATYPE1", "dvb-s2_bb.matype1",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "MATYPE1 Header Field", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_gs, {
                "Stream Input", "dvb-s2_bb.matype1.gs",
                FT_UINT8, BASE_DEC, VALS(bb_gs), DVB_S2_BB_GS_MASK,
                "Transport Stream Input or Generic Stream Input", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_mis, {
                "Input Stream", "dvb-s2_bb.matype1.mis",
                FT_BOOLEAN, 8, TFS(&tfs_bb_mis), DVB_S2_BB_MIS_MASK,
                "Single Input Stream or Multiple Input Stream", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_acm, {
                "Coding and Modulation", "dvb-s2_bb.matype1.acm",
                FT_BOOLEAN, 8, TFS(&tfs_bb_acm), DVB_S2_BB_ACM_MASK,
                "Constant Coding and Modulation or Adaptive Coding and Modulation", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_issyi, {
                "ISSYI", "dvb-s2_bb.matype1.issyi",
                FT_BOOLEAN, 8, TFS(&tfs_bb_issyi), DVB_S2_BB_ISSYI_MASK,
                "Input Stream Synchronization Indicator", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_npd, {
                "NPD", "dvb-s2_bb.matype1.npd",
                FT_BOOLEAN, 8, TFS(&tfs_bb_npd), DVB_S2_BB_NPD_MASK,
                "Null-packet deletion enabled", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_ro, {
                "RO", "dvb-s2_bb.matype1.ro",
                FT_UINT8, BASE_DEC, VALS(bb_ro), DVB_S2_BB_RO_MASK,
                "Transmission Roll-off factor", HFILL}
        },
        {&hf_dvb_s2_bb_matype2, {
                "MATYPE2", "dvb-s2_bb.matype2",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "MATYPE2 Header Field", HFILL}
        },
        {&hf_dvb_s2_bb_upl, {
                "UPL", "dvb-s2_bb.upl",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "User Packet Length", HFILL}
        },
        {&hf_dvb_s2_bb_dfl, {
                "DFL", "dvb-s2_bb.dfl",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Data Field Length", HFILL}
        },
        {&hf_dvb_s2_bb_sync, {
                "SYNC", "dvb-s2_bb.sync",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Copy of the User Packet Sync-byte", HFILL}
        },
        {&hf_dvb_s2_bb_syncd, {
                "SYNCD", "dvb-s2_bb.syncd",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Distance to first user packet", HFILL}
        },
        {&hf_dvb_s2_bb_crc, {
                "Checksum", "dvb-s2_bb.crc",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "CRC-8", HFILL}
        }
    };

    static gint *ett_bb[] = {
        &ett_dvb_s2_bb,
        &ett_dvb_s2_bb_matype1
    };

    /* DVB-S2 GSE Frame */
    static hf_register_info hf_gse[] = {
        {&hf_dvb_s2_gse_hdr, {
                "GSE header", "dvb-s2_gse.hdr",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "GSE Header (start/stop/length)", HFILL}
        },
        {&hf_dvb_s2_gse_hdr_start, {
                "Start", "dvb-s2_gse.hdr.start",
                FT_BOOLEAN, 16, TFS(&tfs_gse_ss), DVB_S2_GSE_HDR_START_MASK,
                "Start Indicator", HFILL}
        },
        {&hf_dvb_s2_gse_hdr_stop, {
                "Stop", "dvb-s2_gse.hdr.stop",
                FT_BOOLEAN, 16, TFS(&tfs_gse_ss), DVB_S2_GSE_HDR_STOP_MASK,
                "Stop Indicator", HFILL}
        },
        {&hf_dvb_s2_gse_hdr_labeltype, {
                "Label Type", "dvb-s2_gse.hdr.labeltype",
                FT_UINT16, BASE_HEX, VALS(gse_labeltype), DVB_S2_GSE_HDR_LABELTYPE_MASK,
                "Label Type Indicator", HFILL}
        },
        {&hf_dvb_s2_gse_hdr_length, {
                "Length", "dvb-s2_gse.hdr.length",
                FT_UINT16, BASE_DEC, NULL, DVB_S2_GSE_HDR_LENGTH_MASK,
                "GSE Length", HFILL}
        },
        {&hf_dvb_s2_gse_proto, {
                "Protocol", "dvb-s2_gse.proto",
                FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(gse_proto_str), 0x0,
                "Protocol Type", HFILL}
        },
        {&hf_dvb_s2_gse_label6, {
                "Label", "dvb-s2_gse.label_ether",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                "Label Field", HFILL}
        },
        {&hf_dvb_s2_gse_label3, {
                "Label", "dvb-s2_gse.label",
                FT_UINT24, BASE_HEX, NULL, 0x0,
                "Label Field", HFILL}
        },
        {&hf_dvb_s2_gse_fragid, {
                "Frag ID", "dvb-s2_gse.fragid",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Fragment ID", HFILL}
        },
        {&hf_dvb_s2_gse_totlength, {
                "Total Length", "dvb-s2_gse.totlength",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "GSE Total Frame Length", HFILL}
        },
        {&hf_dvb_s2_gse_exthdr, {
                "Extension Header", "dvb-s2_gse.exthdr",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "optional Extension Header", HFILL}
        },
        {&hf_dvb_s2_gse_data, {
                "PDU Data", "dvb-s2_gse.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "GSE Frame User Data", HFILL}
        },
        {&hf_dvb_s2_gse_crc32, {
                "CRC", "dvb-s2_gse.crc",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                "CRC-32", HFILL}
        }
    };

    static gint *ett_gse[] = {
        &ett_dvb_s2_gse,
        &ett_dvb_s2_gse_hdr
    };

    proto_dvb_s2_modeadapt = proto_register_protocol("DVB-S2 Modeadaption Header", "DVB-S2", "dvb-s2_modeadapt");

    proto_dvb_s2_bb = proto_register_protocol("DVB-S2 Baseband Frame", "DVB-S2-BB", "dvb-s2_bb");

    proto_dvb_s2_gse = proto_register_protocol("DVB-S2 GSE Packet", "DVB-S2-GSE", "dvb-s2_gse");

    proto_register_field_array(proto_dvb_s2_modeadapt, hf_modeadapt, array_length(hf_modeadapt));
    proto_register_subtree_array(ett_modeadapt, array_length(ett_modeadapt));

    proto_register_field_array(proto_dvb_s2_bb, hf_bb, array_length(hf_bb));
    proto_register_subtree_array(ett_bb, array_length(ett_bb));

    proto_register_field_array(proto_dvb_s2_gse, hf_gse, array_length(hf_gse));
    proto_register_subtree_array(ett_gse, array_length(ett_gse));

    dvb_s2_modeadapt_module = prefs_register_protocol(proto_dvb_s2_modeadapt, proto_reg_handoff_dvb_s2_modeadapt);

    prefs_register_obsolete_preference(dvb_s2_modeadapt_module, "enable");

    prefs_register_bool_preference(dvb_s2_modeadapt_module, "full_decode",
        "Enable dissection of GSE data",
        "Check this to enable full protocol dissection of data above GSE Layer",
        &dvb_s2_full_dissection);
}

void proto_reg_handoff_dvb_s2_modeadapt(void)
{
    static gboolean prefs_initialized = FALSE;

    if (!prefs_initialized) {
        heur_dissector_add("udp", dissect_dvb_s2_modeadapt, "DVB-S2 over UDP", "dvb_s2_udp", proto_dvb_s2_modeadapt, HEURISTIC_DISABLE);
        ip_handle   = find_dissector_add_dependency("ip", proto_dvb_s2_bb);
        ipv6_handle = find_dissector_add_dependency("ipv6", proto_dvb_s2_bb);
        prefs_initialized = TRUE;
    }
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
