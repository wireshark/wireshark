/* packet-dvb-s2-bb.c
 * Routines for DVB Dynamic Mode Adaptation dissection
 *  refer to
 *    https://web.archive.org/web/20170226064346/http://satlabs.org/pdf/sl_561_Mode_Adaptation_Input_and_Output_Interfaces_for_DVB-S2_Equipment_v1.3.pdf
 *
 *    (http://satlabs.org/pdf/sl_561_Mode_Adaptation_Input_and_Output_Interfaces_for_DVB-S2_Equipment_v1.3.pdf
 *    is no longer available)
 *
 * Standards:
 *  ETSI EN 302 307 - Digital Video Broadcasting (DVB) - Framing Structure
 *  ETSI TS 102 606-1 - Digital Video Broadcasting (DVB) - Generic Stream Encapsulation (GSE) Part 1: Protocol
 *  ETSI TS 102 771 - Digital Video Broadcasting (DVB) - GSE implementation guidelines
 *  SatLabs sl_561 - Mode Adaptation Interfaces for DVB-S2 equipment
 *  ETSI EN 301 545 - Digital Video Broadcasting (DVB) - Second Generation DVB Interactive Satellite System (DVB-RCS2)
 *  RFC 4326 - Unidirectional Lightweight Encapsulation (ULE) for Transmission of IP Datagrams over an MPEG-2 Transport Stream (TS)
 *  IANA registries:
 *
 *    Mandatory Extension Headers (or link-dependent type fields) for ULE (Range 0-255 decimal):
 *
 *      https://www.iana.org/assignments/ule-next-headers/ule-next-headers.xhtml#ule-next-headers-1
 *
 *  and
 *
 *    Optional Extension Headers for ULE (Range 256-511 decimal):
 *
 *      https://www.iana.org/assignments/ule-next-headers/ule-next-headers.xhtml#ule-next-headers-2
 *
 * Copyright 2012, Tobias Rutz <tobias.rutz@work-microwave.de>
 * Copyright 2013-2020, Thales Alenia Space
 * Copyright 2013-2020, Viveris Technologies <adrien.destugues@opensource.viveris.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

#define BIT_IS_SET(var, bit) ((var) & (1 << (bit)))
#define BIT_IS_CLEAR(var, bit) !BIT_IS_SET(var, bit)

#define DVB_S2_MODEADAPT_MINSIZE        (DVB_S2_BB_OFFS_CRC + 1)

/* Types of mode adaptation headers supported. */
#define DVB_S2_MODEADAPT_TYPE_L1        1
#define DVB_S2_MODEADAPT_TYPE_L2        2
#define DVB_S2_MODEADAPT_TYPE_L3        3
#define DVB_S2_MODEADAPT_TYPE_L4        4

#define DVB_S2_MODEADAPT_L1SIZE         0
#define DVB_S2_MODEADAPT_L2SIZE         2
#define DVB_S2_MODEADAPT_L3SIZE         4
#define DVB_S2_MODEADAPT_L4SIZE         3


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
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t dvb_s2_table_handle;
static dissector_handle_t data_handle;

void proto_register_dvb_s2_modeadapt(void);
void proto_reg_handoff_dvb_s2_modeadapt(void);

/* preferences */
#define DVB_S2_RCS_TABLE_DECODING      0
#define DVB_S2_RCS2_TABLE_DECODING     1

static gboolean dvb_s2_full_dissection = FALSE;
static gboolean dvb_s2_df_dissection = FALSE;

/* Initialize the protocol and registered fields */
static int proto_dvb_s2_modeadapt = -1;
static int hf_dvb_s2_modeadapt_sync = -1;
static int hf_dvb_s2_modeadapt_acm = -1;
static int hf_dvb_s2_modeadapt_acm_fecframe = -1;
static int hf_dvb_s2_modeadapt_acm_pilot = -1;
static int hf_dvb_s2_modeadapt_acm_modcod = -1;
static int hf_dvb_s2_modeadapt_acm_modcod_s2x = -1;
static int hf_dvb_s2_modeadapt_cni = -1;
static int hf_dvb_s2_modeadapt_frameno = -1;

static int proto_dvb_s2_bb = -1;
static int hf_dvb_s2_bb_matype1 = -1;
static int hf_dvb_s2_bb_matype1_gs = -1;
static int hf_dvb_s2_bb_matype1_mis = -1;
static int hf_dvb_s2_bb_matype1_acm = -1;
static int hf_dvb_s2_bb_matype1_issyi = -1;
static int hf_dvb_s2_bb_matype1_npd = -1;
static int hf_dvb_s2_bb_matype1_high_ro = -1;
static int hf_dvb_s2_bb_matype1_low_ro = -1;
static int hf_dvb_s2_bb_matype2 = -1;
static int hf_dvb_s2_bb_upl = -1;
static int hf_dvb_s2_bb_dfl = -1;
static int hf_dvb_s2_bb_sync = -1;
static int hf_dvb_s2_bb_syncd = -1;
static int hf_dvb_s2_bb_crc = -1;
static int hf_dvb_s2_bb_crc_status = -1;
static int hf_dvb_s2_bb_df = -1;
static int hf_dvb_s2_bb_eip_crc32 = -1;

static int hf_dvb_s2_bb_packetized = -1;
static int hf_dvb_s2_bb_transport = -1;
static int hf_dvb_s2_bb_reserved = -1;

static int proto_dvb_s2_gse = -1;
static int hf_dvb_s2_gse_hdr = -1;
static int hf_dvb_s2_gse_hdr_start = -1;
static int hf_dvb_s2_gse_hdr_stop = -1;
static int hf_dvb_s2_gse_hdr_labeltype = -1;
static int hf_dvb_s2_gse_hdr_length = -1;
static int hf_dvb_s2_gse_padding = -1;
static int hf_dvb_s2_gse_proto_next_header = -1;
static int hf_dvb_s2_gse_proto_ethertype = -1;
static int hf_dvb_s2_gse_label6 = -1;
static int hf_dvb_s2_gse_label3 = -1;
static int hf_dvb_s2_gse_fragid = -1;
static int hf_dvb_s2_gse_totlength = -1;
static int hf_dvb_s2_gse_exthdr = -1;
static int hf_dvb_s2_gse_ncr = -1;
static int hf_dvb_s2_gse_data = -1;
static int hf_dvb_s2_gse_crc32 = -1;

/* Initialize the subtree pointers */
static gint ett_dvb_s2_modeadapt = -1;
static gint ett_dvb_s2_modeadapt_acm = -1;

static gint ett_dvb_s2_bb = -1;
static gint ett_dvb_s2_bb_matype1 = -1;

static gint ett_dvb_s2_gse = -1;
static gint ett_dvb_s2_gse_hdr = -1;
static gint ett_dvb_s2_gse_ncr = -1;

static expert_field ei_dvb_s2_bb_crc = EI_INIT;
static expert_field ei_dvb_s2_bb_header_ambiguous = EI_INIT;
static expert_field ei_dvb_s2_bb_issy_invalid = EI_INIT;
static expert_field ei_dvb_s2_bb_npd_invalid = EI_INIT;
static expert_field ei_dvb_s2_bb_upl_invalid = EI_INIT;
static expert_field ei_dvb_s2_bb_reserved = EI_INIT;

/* Reassembly support */

static reassembly_table dvbs2_reassembly_table;

static void
dvbs2_defragment_init(void)
{
  reassembly_table_init(&dvbs2_reassembly_table,
                        &addresses_reassembly_table_functions);
}

static gint ett_dvbs2_fragments = -1;
static gint ett_dvbs2_fragment  = -1;
static int hf_dvbs2_fragments = -1;
static int hf_dvbs2_fragment = -1;
static int hf_dvbs2_fragment_overlap = -1;
static int hf_dvbs2_fragment_overlap_conflict = -1;
static int hf_dvbs2_fragment_multiple_tails = -1;
static int hf_dvbs2_fragment_too_long_fragment = -1;
static int hf_dvbs2_fragment_error = -1;
static int hf_dvbs2_fragment_count = -1;
static int hf_dvbs2_reassembled_in = -1;
static int hf_dvbs2_reassembled_length = -1;
static int hf_dvbs2_reassembled_data = -1;

static const fragment_items dvbs2_frag_items = {
  &ett_dvbs2_fragment,
  &ett_dvbs2_fragments,
  &hf_dvbs2_fragments,
  &hf_dvbs2_fragment,
  &hf_dvbs2_fragment_overlap,
  &hf_dvbs2_fragment_overlap_conflict,
  &hf_dvbs2_fragment_multiple_tails,
  &hf_dvbs2_fragment_too_long_fragment,
  &hf_dvbs2_fragment_error,
  &hf_dvbs2_fragment_count,
  &hf_dvbs2_reassembled_in,
  &hf_dvbs2_reassembled_length,
  &hf_dvbs2_reassembled_data,
  "DVB-S2 fragments"
};


static unsigned char _use_low_rolloff_value = 0;

/* Offset in SYNC MARKER */
#define DVB_S2_OFFS_SYNCBYTE 0

/* *** DVB-S2 Modeadaption Header *** */

/* first byte */
#define DVB_S2_MODEADAPT_OFFS_SYNCBYTE          0
#define DVB_S2_MODEADAPT_SYNCBYTE               0xB8

/* second byte */
#define DVB_S2_MODEADAPT_OFFS_ACMBYTE         1
#define DVB_S2_MODEADAPT_MODCODS_MASK   0x1F
#define DVB_S2_MODEADAPT_MODCODS_S2X_MASK   0xDF
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
    {32, "QPSK 1/3 SF48"},
    {33, "QPSK 1/2 SF48"},
    {34, "QPSK 1/4 SF12"},
    {35, "QPSK 1/3 SF12"},
    {36, "QPSK 1/2 SF12"},
    {37, "QPSK 1/3 SF6"},
    {38, "QPSK 1/2 SF6"},
    {39, "QPSK 1/3 SF3"},
    {40, "QPSK 2/5 SF3"},
    {41, "QPSK 1/3 SF2"},
    {42, "QPSK 2/5 SF2"},
    {43, "QPSK 1/2 SF2"},
    {44, "QPSK 1/3 SF1"},
    {45, "QPSK 2/5 SF1"},
    {46, "QPSK 1/2 SF1"},
    {47, "reserved"},
    {48, "reserved"},
    {49, "reserved"},
    {50, "reserved"},
    {51, "reserved"},
    {52, "reserved"},
    {53, "reserved"},
    {54, "reserved"},
    {55, "reserved"},
    {56, "reserved"},
    {57, "reserved"},
    {58, "reserved"},
    {59, "reserved"},
    {60, "reserved"},
    {61, "reserved"},
    {62, "reserved"},
    {63, "reserved"},
    {64, "reserved"},
    {65, "reserved"},
    {66, "reserved"},
    {67, "reserved"},
    {68, "reserved"},
    {69, "reserved"},
    {70, "reserved"},
    {71, "reserved"},
    {72, "reserved"},
    {73, "reserved"},
    {74, "reserved"},
    {75, "reserved"},
    {76, "reserved"},
    {77, "reserved"},
    {78, "reserved"},
    {79, "reserved"},
    {80, "reserved"},
    {81, "reserved"},
    {82, "reserved"},
    {83, "reserved"},
    {84, "reserved"},
    {85, "reserved"},
    {86, "reserved"},
    {87, "reserved"},
    {88, "reserved"},
    {89, "reserved"},
    {90, "reserved"},
    {91, "reserved"},
    {92, "reserved"},
    {93, "reserved"},
    {94, "reserved"},
    {95, "reserved"},
    {96, "reserved"},
    {97, "reserved"},
    {98, "reserved"},
    {99, "reserved"},
    {100, "reserved"},
    {101, "reserved"},
    {102, "reserved"},
    {103, "reserved"},
    {104, "reserved"},
    {105, "reserved"},
    {106, "reserved"},
    {107, "reserved"},
    {108, "reserved"},
    {109, "reserved"},
    {110, "reserved"},
    {111, "reserved"},
    {112, "reserved"},
    {113, "reserved"},
    {114, "reserved"},
    {115, "reserved"},
    {116, "reserved"},
    {117, "reserved"},
    {118, "reserved"},
    {119, "reserved"},
    {120, "reserved"},
    {121, "reserved"},
    {122, "reserved"},
    {123, "reserved"},
    {124, "reserved"},
    {125, "reserved"},
    {126, "reserved"},
    {127, "reserved"},
    {128, "reserved"},
    {129, "reserved"},
    {130, "reserved"},
    {131, "reserved"},
    {132, "QPSK 13/45"},
    {133, "reserved"},
    {134, "QPSK 9/20"},
    {135, "reserved"},
    {136, "QPSK 11/20"},
    {137, "reserved"},
    {138, "8PSK 5/9-L"},
    {139, "reserved"},
    {140, "8PSK 26/45-L"},
    {141, "reserved"},
    {142, "8PSK 23/36"},
    {143, "reserved"},
    {144, "8PSK 25/36"},
    {145, "reserved"},
    {146, "8PSK 13/18"},
    {147, "reserved"},
    {148, "16APSK 1/2-L"},
    {149, "reserved"},
    {150, "16APSK 8/15-L"},
    {151, "reserved"},
    {152, "16APSK 5/9-L"},
    {153, "reserved"},
    {154, "16APSK 26/45"},
    {155, "reserved"},
    {156, "16APSK 3/5"},
    {157, "reserved"},
    {158, "16APSK 3/5-L"},
    {159, "reserved"},
    {160, "16APSK 28/45"},
    {161, "reserved"},
    {162, "16APSK 23/36"},
    {163, "reserved"},
    {164, "16APSK 2/3-L"},
    {165, "reserved"},
    {166, "16APSK 25/36"},
    {167, "reserved"},
    {168, "16APSK 13/18"},
    {169, "reserved"},
    {170, "16APSK 7/9"},
    {171, "reserved"},
    {172, "16APSK 77/90"},
    {173, "reserved"},
    {174, "32APSK 2/3-L"},
    {175, "reserved"},
    {176, "reserved"},
    {177, "reserved"},
    {178, "32APSK 32/45"},
    {179, "reserved"},
    {180, "32APSK 11/15"},
    {181, "reserved"},
    {182, "32APSK 7/9"},
    {183, "reserved"},
    {184, "64APSK 32/45-L"},
    {185, "reserved"},
    {186, "64APSK 11/15"},
    {187, "reserved"},
    {188, "reserved"},
    {189, "reserved"},
    {190, "64APSK 7/9"},
    {191, "reserved"},
    {192, "reserved"},
    {193, "reserved"},
    {194, "64APSK 4/5"},
    {195, "reserved"},
    {196, "reserved"},
    {197, "reserved"},
    {198, "64APSK 5/6"},
    {199, "reserved"},
    {200, "128APSK 3/4"},
    {201, "reserved"},
    {202, "128APSK 7/9"},
    {203, "reserved"},
    {204, "256APSK 29/45-L"},
    {205, "reserved"},
    {206, "256APSK 2/3-L"},
    {207, "reserved"},
    {208, "256APSK 31/45-L"},
    {209, "reserved"},
    {210, "256APSK 32/45"},
    {211, "reserved"},
    {212, "256APSK 11/15-L"},
    {213, "reserved"},
    {214, "256APSK 3/4"},
    {215, "reserved"},
    {216, "QPSK 11/45"},
    {217, "reserved"},
    {218, "QPSK 4/15"},
    {219, "reserved"},
    {220, "QPSK 14/45"},
    {221, "reserved"},
    {222, "QPSK 7/15"},
    {223, "reserved"},
    {224, "QPSK 8/15"},
    {225, "reserved"},
    {226, "QPSK 32/45"},
    {227, "reserved"},
    {228, "8PSK 7/15"},
    {229, "reserved"},
    {230, "8PSK 8/15"},
    {231, "reserved"},
    {232, "8PSK 26/45"},
    {233, "reserved"},
    {234, "8PSK 32/45"},
    {235, "reserved"},
    {236, "16APSK 7/15"},
    {237, "reserved"},
    {238, "16APSK 8/15"},
    {239, "reserved"},
    {240, "16APSK 26/45"},
    {241, "reserved"},
    {242, "16APSK 3/5"},
    {243, "reserved"},
    {244, "16APSK 32/45"},
    {245, "reserved"},
    {246, "32APSK 2/3"},
    {247, "reserved"},
    {248, "32APSK 32/45"},
    {249, "reserved"},
    {250, "reserved"},
    {251, "reserved"},
    {252, "reserved"},
    {253, "reserved"},
    {254, "reserved"},
    {255, "reserved"},
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
#define DVB_S2_BB_TSGS_MASK               0xC0
#define DVB_S2_BB_TSGS_GENERIC_PACKETIZED 0x00
#define DVB_S2_BB_TSGS_GENERIC_CONTINUOUS 0x40
#define DVB_S2_BB_TSGS_TRANSPORT_STREAM   0xC0
#define DVB_S2_BB_TSGS_RESERVED           0x80
static const value_string bb_tsgs[] = {
    {0, "Generic Packetized (not GSE)"},
    {1, "Generic Continuous (GSE)"},
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

#define DVB_S2_BB_ISSYI_POS        3
#define DVB_S2_BB_ISSYI_MASK    0x08
static const true_false_string tfs_bb_issyi = {
    "active",
    "not-active"
};

#define DVB_S2_BB_NPD_POS          2
#define DVB_S2_BB_NPD_MASK      0x04
static const true_false_string tfs_bb_npd = {
    "active",
    "not-active"
};

#define DVB_S2_BB_RO_MASK       0x03
static const value_string bb_high_ro[] = {
    {0, "0,35"},
    {1, "0,25"},
    {2, "0,20"},
    {3, "Low rolloff flag"},
    {0, NULL}
};

static const value_string bb_low_ro[] = {
    {0, "0,15"},
    {1, "0,10"},
    {2, "0,05"},
    {3, "Low rolloff flag"},
    {0, NULL}
};


#define DVB_S2_BB_OFFS_MATYPE2          1
#define DVB_S2_BB_OFFS_UPL              2
#define DVB_S2_BB_OFFS_DFL              4
#define DVB_S2_BB_OFFS_SYNC             6
#define DVB_S2_BB_OFFS_SYNCD            7
#define DVB_S2_BB_OFFS_CRC              9
#define DVB_S2_BB_EIP_CRC32_LEN         4
#define DVB_S2_BB_SYNC_EIP_CRC32        1

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

#define DVB_RCS2_NCR 0x0081
#define DVB_RCS2_SIGNAL_TABLE 0x0082

static const value_string gse_proto_next_header_str[] = {
    /* Mandatory Extension Headers (or link-dependent type fields) for ULE (Range 0-255 decimal) */
    {0x0000,                "Test SNDU"           },
    {0x0001,                "Bridged Frame"       },
    {0x0002,                "TS-Concat"           },
    {0x0003,                "PDU-Concat"          },
    {DVB_RCS2_NCR,          "NCR"                 },
    {DVB_RCS2_SIGNAL_TABLE, "Signaling Table"     },
    {131,                   "LL_RCS_DCP"          },
    {132,                   "LL_RCS_1"            },
    {133,                   "LL_RCS_TRANSEC_SYS"  },
    {134,                   "LL_RCS_TRANSEC_PAY"  },
    {135,                   "DVB-GSE_LLC"         },
    /* Unassigned, private, unassigned ranges */
    {200,                   "LL_RCS_FEC_EDT"      },
    /* Unassigned */

    /* Optional Extension Headers for ULE (Range 256-511 decimal) */
    {256,                   "Extension-Padding"   },
    {257,                   "Timestamp"   },
    /* Unassigned */
    {450,                   "LL_RCS_FEC_ADT"      },
    {451,                   "LL_CRC32"            },
    /* Unassigned */

    {0, NULL}
};

#define DVB_S2_GSE_CRC32_LEN            4

/* *** helper functions *** */
static guint8 compute_crc8(tvbuff_t *p, guint8 len, guint8 offset)
{
    int    i;
    guint8 crc = 0, tmp;

    for (i = 0; i < len; i++) {
        tmp = tvb_get_guint8(p, offset++);
        crc = crc8_table[crc ^ tmp];
    }
    return crc;
}

/* *** Code to actually dissect the packets *** */
static int dissect_dvb_s2_gse(tvbuff_t *tvb, int cur_off, proto_tree *tree, packet_info *pinfo, int bytes_available)
{
    int         new_off                      = 0;
    int         frag_len;
    guint16     gse_hdr, data_len, padding_len, gse_proto = 0;

    proto_item *ti;
    proto_item *ttf;
    proto_tree *dvb_s2_gse_tree, *dvb_s2_gse_ncr_tree;

    tvbuff_t   *next_tvb, *data_tvb;
    gboolean   dissected = FALSE;
    gboolean   update_col_info = TRUE;

    static int * const gse_header_bitfields[] = {
        &hf_dvb_s2_gse_hdr_start,
        &hf_dvb_s2_gse_hdr_stop,
        &hf_dvb_s2_gse_hdr_labeltype,
        &hf_dvb_s2_gse_hdr_length,
        NULL
    };

    col_append_str(pinfo->cinfo, COL_INFO, " GSE");

    /* get the GSE header */
    gse_hdr = tvb_get_ntohs(tvb, cur_off + DVB_S2_GSE_OFFS_HDR);

    /* check if this is just padding, which takes up the rest of the frame */
    if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) &&
        BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS) &&
        BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS1) && BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_LABELTYPE_POS2)) {

        padding_len = bytes_available;
        proto_tree_add_uint_format(tree, hf_dvb_s2_gse_padding, tvb, cur_off + new_off, padding_len, padding_len,
                                   "DVB-S2 GSE Padding, Length: %d", padding_len);
        col_append_str(pinfo->cinfo, COL_INFO, " pad");
        new_off += padding_len;

        return new_off;
    } else {
        /* Not padding, parse as a GSE Header */
        new_off += 2;
        frag_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK)+2;
        ti = proto_tree_add_item(tree, proto_dvb_s2_gse, tvb, cur_off, frag_len, ENC_NA);
        dvb_s2_gse_tree = proto_item_add_subtree(ti, ett_dvb_s2_gse);

        proto_tree_add_bitmask_with_flags(dvb_s2_gse_tree, tvb, cur_off + DVB_S2_GSE_OFFS_HDR, hf_dvb_s2_gse_hdr,
            ett_dvb_s2_gse_hdr, gse_header_bitfields, ENC_BIG_ENDIAN, BMT_NO_TFS);

        /* Get the fragment ID for reassembly */
        guint8 fragid = tvb_get_guint8(tvb, cur_off + new_off);
        if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) || BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
            /* Not a start or end packet, add only the fragid */
            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_fragid, tvb, cur_off + new_off, 1, ENC_BIG_ENDIAN);

            new_off += 1;
        }
        if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS) && BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
            /* Start packet, add the fragment size */
            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_totlength, tvb, cur_off + new_off, 2, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, "(frag) ");

            new_off += 2;
        }
        if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS)) {
            /* Start packet, decode the header */
            gse_proto = tvb_get_ntohs(tvb, cur_off + new_off);

            /* Protocol Type */
            if (gse_proto <= 1535) {
                /* Type 1 (Next-Header Type field) */
                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_proto_next_header, tvb, cur_off + new_off, 2, ENC_BIG_ENDIAN);
            }
            else {
                /* Type 2 (EtherType compatible Type Fields) */
                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_proto_ethertype, tvb, cur_off + new_off, 2, ENC_BIG_ENDIAN);
            }
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

        if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
            data_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK) - (new_off - DVB_S2_GSE_MINSIZE) - DVB_S2_GSE_CRC32_LEN;
        } else {
            data_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK) - (new_off - DVB_S2_GSE_MINSIZE);
        }

        data_tvb = NULL;
        if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) || BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
            fragment_head *dvbs2_frag_head = NULL;
            int offset = cur_off + new_off;
            if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS)) {
                offset -= 2; /* re-include GSE type in reassembled data */
                data_len += 2;
            }
            dvbs2_frag_head = fragment_add_seq_next(&dvbs2_reassembly_table, tvb, offset,
                pinfo, fragid, NULL, data_len, BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS));

            if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS))
                dvbs2_frag_head = fragment_end_seq_next(&dvbs2_reassembly_table, pinfo, fragid, NULL);

            data_tvb = process_reassembled_data(tvb, cur_off + new_off, pinfo, "Reassembled DVB-S2",
                dvbs2_frag_head, &dvbs2_frag_items, &update_col_info, tree);
        }

        if (data_tvb != NULL) {
            /* We have a reassembled packet. Extract the gse_proto from it. */
            gse_proto = tvb_get_ntohs(data_tvb, 0);
            /* And then remove it from the reassembled data */
            data_tvb = tvb_new_subset_remaining(data_tvb, 2);
        } else {
            data_tvb = tvb_new_subset_length(tvb, cur_off + new_off, data_len);
        }

        switch (gse_proto) {
            case ETHERTYPE_IP:
                if (dvb_s2_full_dissection)
                {
                    new_off += call_dissector(ip_handle, next_tvb, pinfo, tree);
                    dissected = TRUE;
                }
                break;

            case ETHERTYPE_IPv6:
                if (dvb_s2_full_dissection)
                {
                    new_off += call_dissector(ipv6_handle, next_tvb, pinfo, tree);
                    dissected = TRUE;
                }
                break;

            case ETHERTYPE_VLAN:
                if (dvb_s2_full_dissection)
                {
                    new_off += call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
                    dissected = TRUE;
                }
                break;

            case DVB_RCS2_SIGNAL_TABLE:
                call_dissector(dvb_s2_table_handle, data_tvb, pinfo, tree);
                new_off += data_len;
                dissected = TRUE;
                break;

            case DVB_RCS2_NCR:
                ttf = proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_ncr, tvb, cur_off + new_off, data_len, ENC_NA);
                dvb_s2_gse_ncr_tree = proto_item_add_subtree(ttf, ett_dvb_s2_gse_ncr);
                proto_tree_add_item(dvb_s2_gse_ncr_tree, hf_dvb_s2_gse_data, tvb, cur_off + new_off, data_len, ENC_NA);
                new_off += data_len;
                dissected = TRUE;
                break;

            default:
                /* Not handled! TODO: expert info? */
                break;
        }

        if (!dissected) {
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

    if (compute_crc8(tvb, DVB_S2_BB_HEADER_LEN - 1, offset) != input8)
        return FALSE;
    else
        return TRUE;
}




static int dissect_dvb_s2_bb(tvbuff_t *tvb, int cur_off, proto_tree *tree, packet_info *pinfo)
{
    proto_item *ti;
    proto_tree *dvb_s2_bb_tree;

    guint8      input8, matype1;
    guint8      sync_flag = 0;
    guint16     input16, bb_data_len = 0, user_packet_length;

    int         sub_dissected        = 0, flag_is_ms = 0, new_off = 0;

    static int * const bb_header_bitfields[] = {
        &hf_dvb_s2_bb_matype1_gs,
        &hf_dvb_s2_bb_matype1_mis,
        &hf_dvb_s2_bb_matype1_acm,
        &hf_dvb_s2_bb_matype1_issyi,
        &hf_dvb_s2_bb_matype1_npd,
        &hf_dvb_s2_bb_matype1_low_ro,
        NULL
    };

    col_append_str(pinfo->cinfo, COL_PROTOCOL, "BB ");
    col_append_str(pinfo->cinfo, COL_INFO, "Baseband ");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dvb_s2_bb, tvb, cur_off, DVB_S2_BB_HEADER_LEN, ENC_NA);
    dvb_s2_bb_tree = proto_item_add_subtree(ti, ett_dvb_s2_bb);

    matype1 = tvb_get_guint8(tvb, cur_off + DVB_S2_BB_OFFS_MATYPE1);
    new_off += 1;

    if (BIT_IS_CLEAR(matype1, DVB_S2_BB_MIS_POS))
        flag_is_ms = 1;

    proto_tree_add_bitmask_with_flags(dvb_s2_bb_tree, tvb, cur_off + DVB_S2_BB_OFFS_MATYPE1, hf_dvb_s2_bb_matype1,
        ett_dvb_s2_bb_matype1, bb_header_bitfields, ENC_BIG_ENDIAN, BMT_NO_FLAGS);

    input8 = tvb_get_guint8(tvb, cur_off + DVB_S2_BB_OFFS_MATYPE1);

    if ((pinfo->fd->num == 1) && (_use_low_rolloff_value != 0)) {
        _use_low_rolloff_value = 0;
    }
    if (((input8 & 0x03) == 3) && !_use_low_rolloff_value) {
      _use_low_rolloff_value = 1;
    }
    if (_use_low_rolloff_value) {
       proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_matype1_low_ro, tvb,
                           cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);
    } else {
       proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_matype1_high_ro, tvb,
                           cur_off + DVB_S2_BB_OFFS_MATYPE1, 1, ENC_BIG_ENDIAN);
    }

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

    user_packet_length = input16 = tvb_get_ntohs(tvb, cur_off + DVB_S2_BB_OFFS_UPL);
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
    sync_flag = tvb_get_guint8(tvb, cur_off + DVB_S2_BB_OFFS_SYNC);
    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_sync, tvb, cur_off + DVB_S2_BB_OFFS_SYNC, 1, ENC_BIG_ENDIAN);

    new_off += 2;
    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_syncd, tvb, cur_off + DVB_S2_BB_OFFS_SYNCD, 2, ENC_BIG_ENDIAN);

    new_off += 1;
    proto_tree_add_checksum(dvb_s2_bb_tree, tvb, cur_off + DVB_S2_BB_OFFS_CRC, hf_dvb_s2_bb_crc, hf_dvb_s2_bb_crc_status, &ei_dvb_s2_bb_crc, pinfo,
        compute_crc8(tvb, DVB_S2_BB_HEADER_LEN - 1, cur_off), ENC_NA, PROTO_CHECKSUM_VERIFY);

    switch (matype1 & DVB_S2_BB_TSGS_MASK) {
    case DVB_S2_BB_TSGS_GENERIC_CONTINUOUS:
        /* Check GSE constraints on the BB header per 9.2.1 of ETSI TS 102 771 */
        if (BIT_IS_SET(matype1, DVB_S2_BB_ISSYI_POS)) {
            expert_add_info(pinfo, ti, &ei_dvb_s2_bb_issy_invalid);
        }
        if (BIT_IS_SET(matype1, DVB_S2_BB_NPD_POS)) {
            expert_add_info(pinfo, ti, &ei_dvb_s2_bb_npd_invalid);
        }
        if (user_packet_length != 0x0000) {
            expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_upl_invalid,
                "UPL is 0x%04x. It must be 0x0000 for GSE packets.", user_packet_length);
        }


        if (dvb_s2_df_dissection) {
            while (bb_data_len) {
                if (sync_flag == DVB_S2_BB_SYNC_EIP_CRC32 && bb_data_len == DVB_S2_BB_EIP_CRC32_LEN) {
                    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_eip_crc32, tvb, cur_off + new_off, bb_data_len, ENC_NA);
                    bb_data_len = 0;
                    new_off += DVB_S2_BB_EIP_CRC32_LEN;
                } else {
                    /* start DVB-GSE dissector */
                    sub_dissected = dissect_dvb_s2_gse(tvb, cur_off + new_off, tree, pinfo, bb_data_len);
                    new_off += sub_dissected;

                    if ((sub_dissected <= bb_data_len) && (sub_dissected >= DVB_S2_GSE_MINSIZE)) {
                        bb_data_len -= sub_dissected;
                        if (bb_data_len < DVB_S2_GSE_MINSIZE)
                            bb_data_len = 0;
                    }
                }
            }
        } else {
            proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_df, tvb, cur_off + new_off, bb_data_len, ENC_NA);
            new_off += bb_data_len;
        }
        break;

    case DVB_S2_BB_TSGS_GENERIC_PACKETIZED:
        proto_tree_add_item(tree, hf_dvb_s2_bb_packetized, tvb, cur_off + new_off, bb_data_len, ENC_NA);
        new_off += bb_data_len;
        break;

    case DVB_S2_BB_TSGS_TRANSPORT_STREAM:
        proto_tree_add_item(tree, hf_dvb_s2_bb_transport, tvb, cur_off + new_off, bb_data_len, ENC_NA);
        new_off += bb_data_len;
        break;

    default:
        proto_tree_add_item(tree, hf_dvb_s2_bb_reserved, tvb, cur_off + new_off,bb_data_len, ENC_NA);
        new_off += bb_data_len;
        expert_add_info(pinfo, ti, &ei_dvb_s2_bb_reserved);
        break;
    }

    return new_off;
}

static int dissect_dvb_s2_modeadapt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int         cur_off = 0, modeadapt_len, modeadapt_type, matched_headers = 0;

    proto_item *ti, *tf;
    proto_tree *dvb_s2_modeadapt_tree;
    proto_tree *dvb_s2_modeadapt_acm_tree;

    unsigned int modcod, mc;
    static int * const modeadapt_acm_bitfields[] = {
        &hf_dvb_s2_modeadapt_acm_fecframe,
        &hf_dvb_s2_modeadapt_acm_pilot,
        &hf_dvb_s2_modeadapt_acm_modcod,
        NULL
    };

    /* Check that there's enough data */
    if (tvb_captured_length(tvb) < DVB_S2_MODEADAPT_MINSIZE)
        return 0;

    /* There are four different mode adaptation formats, with different
       length headers. Two of them have a sync byte at the beginning, but
       the other two do not. In every case, the mode adaptation header is
       followed by the baseband header, which is protected by a CRC-8.
       The CRC-8 is weak protection, so it can match by accident, leading
       to an ambiguity in identifying which format is in use. We will
       check for ambiguity and report it. */
    /* Try L.1 format: no header. */
    if (test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_L1SIZE)) {
        matched_headers++;
        modeadapt_type = DVB_S2_MODEADAPT_TYPE_L1;
        modeadapt_len = DVB_S2_MODEADAPT_L1SIZE;
    }

    /* Try L.2 format: header includes sync byte */
    if ((tvb_get_guint8(tvb, DVB_S2_MODEADAPT_OFFS_SYNCBYTE) == DVB_S2_MODEADAPT_SYNCBYTE) &&
        test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_L2SIZE)) {
        matched_headers++;
        modeadapt_type = DVB_S2_MODEADAPT_TYPE_L2;
        modeadapt_len = DVB_S2_MODEADAPT_L2SIZE;
    }

    /* Try L.3 format: header includes sync byte */
    if ((tvb_get_guint8(tvb, DVB_S2_MODEADAPT_OFFS_SYNCBYTE) == DVB_S2_MODEADAPT_SYNCBYTE) &&
        test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_L3SIZE)) {
        matched_headers++;
        modeadapt_type = DVB_S2_MODEADAPT_TYPE_L3;
        modeadapt_len = DVB_S2_MODEADAPT_L3SIZE;
    }

    /* Try L.4 format: header does not include sync byte */
    if (test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_L4SIZE)) {
        matched_headers++;
        modeadapt_type = DVB_S2_MODEADAPT_TYPE_L4;
        modeadapt_len = DVB_S2_MODEADAPT_L4SIZE;
    }

    if (matched_headers == 0) {
        /* This does not look like a DVB-S2-BB frame at all. We are a
           heuristic dissector, so we should just punt and let another
           dissector have a try at this one. */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVB-S2 ");
    col_set_str(pinfo->cinfo, COL_INFO,     "DVB-S2 ");

    /* If there's a mode adaptation header, create display subtree for it */
    if (modeadapt_len > 0) {
        /* ti = proto_tree_add_item(tree, proto_dvb_s2_modeadapt, tvb, 0, modeadapt_len, ENC_NA); */
        ti = proto_tree_add_protocol_format(tree, proto_dvb_s2_modeadapt, tvb, 0, modeadapt_len,
            "DVB-S2 Mode Adaptation Header L.%d", modeadapt_type);
        dvb_s2_modeadapt_tree = proto_item_add_subtree(ti, ett_dvb_s2_modeadapt);

        if (matched_headers > 1) {
            expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_header_ambiguous,
                "Mode adaptation header format is ambiguous. Assuming L.%d", modeadapt_type);
        }

        /* SYNC byte if used in this header format; value has already been checked */
        if (modeadapt_type == DVB_S2_MODEADAPT_TYPE_L2 ||
            modeadapt_type == DVB_S2_MODEADAPT_TYPE_L3) {
            proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_sync, tvb, cur_off, 1, ENC_BIG_ENDIAN);
            cur_off++;
        }

        /* ACM byte and subfields if used in this header format */
        if (modeadapt_type == DVB_S2_MODEADAPT_TYPE_L2 ||
            modeadapt_type == DVB_S2_MODEADAPT_TYPE_L3 ||
            modeadapt_type == DVB_S2_MODEADAPT_TYPE_L4) {
            mc = tvb_get_guint8(tvb, 1);
            //mc = tvb_get_letohs(tvb, 0);
            if (mc & 0x80) {
                modcod = 0x80;
                modcod |= ((mc & 0x1F) << 2);
                modcod |= ((mc & 0x40) >> 5);
                tf = proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_acm, tvb,
                        DVB_S2_MODEADAPT_OFFS_ACMBYTE, 1, ENC_BIG_ENDIAN);

                dvb_s2_modeadapt_acm_tree = proto_item_add_subtree(tf, ett_dvb_s2_modeadapt_acm);

                proto_tree_add_item(dvb_s2_modeadapt_acm_tree, hf_dvb_s2_modeadapt_acm_pilot, tvb,
                        DVB_S2_MODEADAPT_OFFS_ACMBYTE, 1, ENC_BIG_ENDIAN);
                proto_tree_add_uint_format_value(dvb_s2_modeadapt_acm_tree, hf_dvb_s2_modeadapt_acm_modcod_s2x, tvb,
                        DVB_S2_MODEADAPT_OFFS_ACMBYTE, 1, mc, "DVBS2X %s(%d)", modeadapt_modcods[modcod].strptr, modcod);
            } else {
                proto_tree_add_bitmask_with_flags(dvb_s2_modeadapt_tree, tvb, DVB_S2_MODEADAPT_OFFS_ACMBYTE, hf_dvb_s2_modeadapt_acm,
                        ett_dvb_s2_modeadapt_acm, modeadapt_acm_bitfields, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
            }
            cur_off++;
        }

        /* CNI and Frame No if used in this header format */
        if (modeadapt_type == DVB_S2_MODEADAPT_TYPE_L3 ||
            modeadapt_type == DVB_S2_MODEADAPT_TYPE_L4) {
            proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_cni, tvb, cur_off, 1, ENC_BIG_ENDIAN);
            cur_off++;

            proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_frameno, tvb, cur_off, 1, ENC_BIG_ENDIAN);
            cur_off++;
        }
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
        {&hf_dvb_s2_modeadapt_acm_modcod_s2x, {
                "Modcod indicator", "dvb-s2_modeadapt.acmcmd.modcod",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, &modeadapt_modcods_ext, DVB_S2_MODEADAPT_MODCODS_S2X_MASK,
                "Modcod S2X", HFILL}
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
                "TS/GS Stream Input", "dvb-s2_bb.matype1.tsgs",
                FT_UINT8, BASE_DEC, VALS(bb_tsgs), DVB_S2_BB_TSGS_MASK,
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
        {&hf_dvb_s2_bb_matype1_high_ro, {
                "RO", "dvb-s2_bb.matype1.ro",
                FT_UINT8, BASE_DEC, VALS(bb_high_ro), DVB_S2_BB_RO_MASK,
                "Transmission Roll-off factor", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_low_ro, {
                "RO", "dvb-s2_bb.matype1.ro",
                FT_UINT8, BASE_DEC, VALS(bb_low_ro), DVB_S2_BB_RO_MASK,
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
                "BB Header CRC-8", HFILL}
        },
        {&hf_dvb_s2_bb_crc_status, {
                "Checksum Status", "dvb-s2_bb.crc.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL}
        },
        {&hf_dvb_s2_bb_packetized, {
                "Packetized Generic Stream Data", "dvb-s2_bb.packetized",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Packetized Generic Stream (non-TS) Data", HFILL}
        },
        {&hf_dvb_s2_bb_transport, {
                "Transport Stream Data", "dvb-s2_bb.transport",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Transport Stream (TS) Data", HFILL}
        },
        {&hf_dvb_s2_bb_reserved, {
                "Reserved Stream Type Data", "dvb-s2_bb.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Stream of an unknown reserved type", HFILL}
        },
        {&hf_dvb_s2_bb_df, {
                "BBFrame user data", "dvb-s2_bb.df",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_dvb_s2_bb_eip_crc32, {
                "EIP CRC32", "dvb-s2_bb.eip_crc32",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                "Explicit Integrity Protection CRC32", HFILL}
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
        {&hf_dvb_s2_gse_padding, {
                "GSE Padding", "dvb-s2_gse.padding",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "GSE Padding Bytes", HFILL}
        },
        {&hf_dvb_s2_gse_proto_next_header, {
                "Protocol", "dvb-s2_gse.proto",
                FT_UINT16, BASE_HEX, VALS(gse_proto_next_header_str), 0x0,
                "Protocol Type", HFILL}
        },
        {&hf_dvb_s2_gse_proto_ethertype, {
                "Protocol", "dvb-s2_gse.proto",
                FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
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
        {&hf_dvb_s2_gse_ncr, {
                "NCR Packet", "dvb-s2_gse.ncr",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "GSE NCR PAcket", HFILL}
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
        },
        { &hf_dvbs2_fragment_overlap,
            { "Fragment overlap", "dvb-s2_gse.fragment.overlap", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

        { &hf_dvbs2_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "dvb-s2_gse.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }},

        { &hf_dvbs2_fragment_multiple_tails,
            { "Multiple tail fragments found", "dvb-s2_gse.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }},

        { &hf_dvbs2_fragment_too_long_fragment,
            { "Fragment too long", "dvb-s2_gse.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }},

        { &hf_dvbs2_fragment_error,
            { "Defragmentation error", "dvb-s2_gse.fragment.error", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},

        { &hf_dvbs2_fragment_count,
            { "Fragment count", "dvb-s2_gse.fragment.count", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_dvbs2_fragment,
            { "DVB-S2 GSE Fragment", "dvb-s2_gse.fragment", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

        { &hf_dvbs2_fragments,
            { "DVB-S2 GSE Fragments", "dvb-s2_gse.fragments", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

        { &hf_dvbs2_reassembled_in,
            { "Reassembled DVB-S2 GSE in frame", "dvb-s2_gse.reassembled_in", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, "This GSE packet is reassembled in this frame", HFILL }},

        { &hf_dvbs2_reassembled_length,
            { "Reassembled DVB-S2 GSE length", "dvb-s2_gse.reassembled.length", FT_UINT32, BASE_DEC,
                NULL, 0x0, "The total length of the reassembled payload", HFILL }},

        { &hf_dvbs2_reassembled_data,
            { "Reassembled DVB-S2 GSE data", "dvb-s2_gse.reassembled.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, "The reassembled payload", HFILL }}
    };

    static gint *ett_gse[] = {
        &ett_dvb_s2_gse,
        &ett_dvb_s2_gse_hdr,
        &ett_dvb_s2_gse_ncr,
        &ett_dvbs2_fragments,
        &ett_dvbs2_fragment,
    };

    static ei_register_info ei[] = {
        { &ei_dvb_s2_bb_crc, { "dvb-s2_bb.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_dvb_s2_bb_issy_invalid, {"dvb-s2_bb.issy_invalid", PI_PROTOCOL, PI_WARN, "ISSY is active, which is not allowed for GSE packets", EXPFILL }},
        { &ei_dvb_s2_bb_npd_invalid, {"dvb-s2_bb.npd_invalid", PI_PROTOCOL, PI_WARN, "NPD is active, which is not allowed for GSE packets", EXPFILL }},
        { &ei_dvb_s2_bb_upl_invalid, {"dvb-s2_bb.upl_invalid", PI_PROTOCOL, PI_WARN, "User Packet Length non-zero, which is not allowed for GSE packets", EXPFILL }},
        { &ei_dvb_s2_bb_reserved, {"dvb-s2_bb.reserved_frame_format", PI_PROTOCOL, PI_WARN, "Reserved frame format in TS/GS is not defined", EXPFILL }},
        { &ei_dvb_s2_bb_header_ambiguous, { "dvb-s2_bb.header_ambiguous", PI_ASSUMPTION, PI_WARN, "Mode Adaptation header ambiguous", EXPFILL }},
    };

    expert_module_t* expert_dvb_s2_bb;

    proto_dvb_s2_modeadapt = proto_register_protocol("DVB-S2 Mode Adaptation Header", "DVB-S2", "dvb-s2_modeadapt");

    proto_dvb_s2_bb = proto_register_protocol("DVB-S2 Baseband Frame", "DVB-S2-BB", "dvb-s2_bb");

    proto_dvb_s2_gse = proto_register_protocol("DVB-S2 GSE Packet", "DVB-S2-GSE", "dvb-s2_gse");

    proto_register_field_array(proto_dvb_s2_modeadapt, hf_modeadapt, array_length(hf_modeadapt));
    proto_register_subtree_array(ett_modeadapt, array_length(ett_modeadapt));

    proto_register_field_array(proto_dvb_s2_bb, hf_bb, array_length(hf_bb));
    proto_register_subtree_array(ett_bb, array_length(ett_bb));
    expert_dvb_s2_bb = expert_register_protocol(proto_dvb_s2_bb);
    expert_register_field_array(expert_dvb_s2_bb, ei, array_length(ei));

    proto_register_field_array(proto_dvb_s2_gse, hf_gse, array_length(hf_gse));
    proto_register_subtree_array(ett_gse, array_length(ett_gse));

    dvb_s2_modeadapt_module = prefs_register_protocol(proto_dvb_s2_modeadapt, proto_reg_handoff_dvb_s2_modeadapt);

    prefs_register_obsolete_preference(dvb_s2_modeadapt_module, "enable");

    prefs_register_bool_preference(dvb_s2_modeadapt_module, "decode_df",
        "Enable dissection of DATA FIELD",
        "Check this to enable full protocol dissection of data above BBHeader",
        &dvb_s2_df_dissection);

    prefs_register_bool_preference(dvb_s2_modeadapt_module, "full_decode",
        "Enable dissection of GSE data",
        "Check this to enable full protocol dissection of data above GSE Layer",
        &dvb_s2_full_dissection);

    register_init_routine(dvbs2_defragment_init);
}

void proto_reg_handoff_dvb_s2_modeadapt(void)
{
    static gboolean prefs_initialized = FALSE;

    if (!prefs_initialized) {
        heur_dissector_add("udp", dissect_dvb_s2_modeadapt, "DVB-S2 over UDP", "dvb_s2_udp", proto_dvb_s2_modeadapt, HEURISTIC_DISABLE);
        ip_handle   = find_dissector_add_dependency("ip", proto_dvb_s2_bb);
        ipv6_handle = find_dissector_add_dependency("ipv6", proto_dvb_s2_bb);
        dvb_s2_table_handle = find_dissector("dvb-s2_table");
        eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
        data_handle = find_dissector("data");
        prefs_initialized = TRUE;
    }
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
