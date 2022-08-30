/* packet-dvb-s2-bb.c
 * Routines for DVB Dynamic Mode Adaptation dissection
 *  refer to
 *    https://web.archive.org/web/20170226064346/http://satlabs.org/pdf/sl_561_Mode_Adaptation_Input_and_Output_Interfaces_for_DVB-S2_Equipment_v1.3.pdf
 *
 *    (http://satlabs.org/pdf/sl_561_Mode_Adaptation_Input_and_Output_Interfaces_for_DVB-S2_Equipment_v1.3.pdf
 *    is no longer available)
 *
 * Standards:
 *  ETSI EN 302 307-1 - Digital Video Broadcasting (DVB) - Framing Structure Part 1: DVB-S2
 *  ETSI EN 302 307-2 - Digital Video Broadcasting (DVB) - Framing Structure Part 2: DVB-S2X
 *  ETSI TS 102 606-1 - Digital Video Broadcasting (DVB) - Generic Stream Encapsulation (GSE) Part 1: Protocol
 *  ETSI TS 102 771 - Digital Video Broadcasting (DVB) - GSE implementation guidelines
 *  SatLabs sl_561 - Mode Adaptation Interfaces for DVB-S2 equipment
 *  ETSI EN 302 769 - Digital Video Broadcasting (DVB) - Framing Structure DVB-C2
 *  ETSI EN 302 755 - Digital Video Broadcasting (DVB) - Framing Structure DVB-T2
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
 * Copyright 2013-2021, Viveris Technologies <adrien.destugues@opensource.viveris.fr>
 * Copyright 2021, John Thacker <johnthacker@gmail.com>
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
#include <epan/crc32-tvb.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/stream.h>
#include <wsutil/bits_count_ones.h>
#include <wsutil/str_util.h>

#include "packet-mp2t.h"

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

static const int dvb_s2_modeadapt_sizes[] = {
    [DVB_S2_MODEADAPT_TYPE_L1] = DVB_S2_MODEADAPT_L1SIZE,
    [DVB_S2_MODEADAPT_TYPE_L2] = DVB_S2_MODEADAPT_L2SIZE,
    [DVB_S2_MODEADAPT_TYPE_L3] = DVB_S2_MODEADAPT_L3SIZE,
    [DVB_S2_MODEADAPT_TYPE_L4] = DVB_S2_MODEADAPT_L4SIZE,
};


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
static dissector_handle_t mp2t_handle;
static dissector_handle_t dvb_s2_modeadapt_handle;

void proto_register_dvb_s2_modeadapt(void);
void proto_reg_handoff_dvb_s2_modeadapt(void);

/* preferences */
#define DVB_S2_RCS_TABLE_DECODING      0
#define DVB_S2_RCS2_TABLE_DECODING     1

static const enum_val_t dvb_s2_modeadapt_enum[] = {
    {"l1", "L.1 (0 bytes)", DVB_S2_MODEADAPT_TYPE_L1},
    {"l2", "L.2 (2 bytes including sync)", DVB_S2_MODEADAPT_TYPE_L2},
    {"l3", "L.3 (4 bytes including sync)", DVB_S2_MODEADAPT_TYPE_L3},
    {"l4", "L.4 (3 bytes)", DVB_S2_MODEADAPT_TYPE_L4},
    {NULL, NULL, -1}
};

static gboolean dvb_s2_full_dissection = FALSE;
static gboolean dvb_s2_df_dissection = FALSE;
static gint dvb_s2_default_modeadapt = DVB_S2_MODEADAPT_TYPE_L3;
static gboolean dvb_s2_try_all_modeadapt = TRUE;

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
static int hf_dvb_s2_bb_eip_crc32_status = -1;
static int hf_dvb_s2_bb_up_crc = -1;
static int hf_dvb_s2_bb_up_crc_status = -1;
static int hf_dvb_s2_bb_issy_short = -1;
static int hf_dvb_s2_bb_issy_long = -1;
static int hf_dvb_s2_bb_dnp = -1;

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
static int hf_dvb_s2_gse_crc32_status = -1;

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
static expert_field ei_dvb_s2_bb_dfl_invalid = EI_INIT;
static expert_field ei_dvb_s2_bb_sync_invalid = EI_INIT;
static expert_field ei_dvb_s2_bb_syncd_invalid = EI_INIT;
static expert_field ei_dvb_s2_bb_up_reassembly_invalid = EI_INIT;
static expert_field ei_dvb_s2_bb_reserved = EI_INIT;

static expert_field ei_dvb_s2_gse_length_invalid = EI_INIT;
static expert_field ei_dvb_s2_gse_totlength_invalid = EI_INIT;
static expert_field ei_dvb_s2_gse_crc32 = EI_INIT;

/* Reassembly support */

/* ETSI TS 102 606-1 3.1 distinguishes "slicing", the splitting of a User
 * Packet over consecutive Base Band Frames of the same stream, and
 * "fragmentation", the splitting of a PDU (& optionally Extension Header)
 * over multiple GSE packets.
 *
 * Slicing does not occur with GSE as carried in DVB-S2 according to the
 * original method in ETSI EN 302 307-1 (TS/GS bits 01), but it does occur
 * with Transport Streams, Generic Packetized Streams (non-GSE, deprecated),
 * and with the GSE High Efficiency Mode used in DVB-C2, DVB-T2, and DVB-S2X
 * (TS/GS bits 10, originally reserved.)
 *
 * According to ETSI TS 102 606-1 D.2.2 "Fragmention", for simplicity when
 * GSE-HEM and thus slicing is used, PDU fragmentation is not performed
 * on the GSE layer (but note it's possible to mix stream types in one
 * capture.)
 *
 * We have two sets of fragment items, one for slicing of User Packets at the
 * BBF level, and one for GSE fragmentation. We only have one reassembly table,
 * however, as the slicing of User Packets is handled through the stream.h
 * API.
 */

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
  "DVB-S2 UP fragments"
};

static reassembly_table dvb_s2_gse_reassembly_table;

static void
dvb_s2_gse_defragment_init(void)
{
  reassembly_table_init(&dvb_s2_gse_reassembly_table,
                        &addresses_reassembly_table_functions);
}

static gint ett_dvb_s2_gse_fragments = -1;
static gint ett_dvb_s2_gse_fragment  = -1;
static int hf_dvb_s2_gse_fragments = -1;
static int hf_dvb_s2_gse_fragment = -1;
static int hf_dvb_s2_gse_fragment_overlap = -1;
static int hf_dvb_s2_gse_fragment_overlap_conflict = -1;
static int hf_dvb_s2_gse_fragment_multiple_tails = -1;
static int hf_dvb_s2_gse_fragment_too_long_fragment = -1;
static int hf_dvb_s2_gse_fragment_error = -1;
static int hf_dvb_s2_gse_fragment_count = -1;
static int hf_dvb_s2_gse_reassembled_in = -1;
static int hf_dvb_s2_gse_reassembled_length = -1;
static int hf_dvb_s2_gse_reassembled_data = -1;

static const fragment_items dvb_s2_gse_frag_items = {
  &ett_dvb_s2_gse_fragment,
  &ett_dvb_s2_gse_fragments,
  &hf_dvb_s2_gse_fragments,
  &hf_dvb_s2_gse_fragment,
  &hf_dvb_s2_gse_fragment_overlap,
  &hf_dvb_s2_gse_fragment_overlap_conflict,
  &hf_dvb_s2_gse_fragment_multiple_tails,
  &hf_dvb_s2_gse_fragment_too_long_fragment,
  &hf_dvb_s2_gse_fragment_error,
  &hf_dvb_s2_gse_fragment_count,
  &hf_dvb_s2_gse_reassembled_in,
  &hf_dvb_s2_gse_reassembled_length,
  &hf_dvb_s2_gse_reassembled_data,
  "DVB-S2 GSE fragments"
};

/* Offset in SYNC MARKER */
#define DVB_S2_OFFS_SYNCBYTE 0

/* *** DVB-S2 Modeadaption Header *** */

/* first byte */
#define DVB_S2_MODEADAPT_OFFS_SYNCBYTE          0
#define DVB_S2_MODEADAPT_SYNCBYTE               0xB8

/* second byte */
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

#define DVB_S2_BB_HEADER_LEN    ((guint)10)

#define DVB_S2_BB_OFFS_MATYPE1          0
#define DVB_S2_BB_TSGS_MASK               0xC0
#define DVB_S2_BB_TSGS_GENERIC_PACKETIZED 0x00
#define DVB_S2_BB_TSGS_GENERIC_CONTINUOUS 0x40
#define DVB_S2_BB_TSGS_TRANSPORT_STREAM   0xC0
#define DVB_S2_BB_TSGS_RESERVED           0x80
static const value_string bb_tsgs[] = {
    {0, "Generic Packetized (not GSE)"},
    {1, "Generic Continuous (GSE)"},
    {2, "GSE High Efficiency Mode (GSE-HEM)"},
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

#define DVB_S2_BB_NPD_POS          2
#define DVB_S2_BB_NPD_MASK      0x04

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


#define DVB_S2_GSE_HDR_LABELTYPE_MASK   0x3000
#define DVB_S2_GSE_HDR_LABELTYPE_SHIFT  12
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

/* Virtual circuit handling
 *
 * BBFrames have an Input Stream Identifier (equivalently PLP_ID in -T2, -C2),
 * but (cf. H.223), we are likely to encounter Base Band Frames over UDP or RTP.
 * In those situations, the ISI might be reused on different conversations
 * (or unused/0 on all of them). So we have a hash table that maps the
 * conversation and the ISI to a unique virtual stream identifier.
 */

typedef struct {
    const conversation_t* conv;
    guint32 isi;
} virtual_stream_key;

static wmem_map_t *virtual_stream_hashtable = NULL;
static guint virtual_stream_count = 1;

/* Hash functions */
static gint
virtual_stream_equal(gconstpointer v, gconstpointer w)
{
    const virtual_stream_key *v1 = (const virtual_stream_key *)v;
    const virtual_stream_key *v2 = (const virtual_stream_key *)w;
    gint result;
    result = (v1->conv == v2->conv && v1->isi == v2->isi);
    return result;
}

static guint
virtual_stream_hash(gconstpointer v)
{
    const virtual_stream_key *key = (const virtual_stream_key *)v;
    guint hash_val = (GPOINTER_TO_UINT(key->conv)) ^ (key->isi << 16);
    return hash_val;
}

static guint32
virtual_stream_lookup(const conversation_t* conv, guint32 isi)
{
    virtual_stream_key key, *new_key;
    guint32 virtual_isi;
    key.conv = conv;
    key.isi = isi;
    virtual_isi = GPOINTER_TO_UINT(wmem_map_lookup(virtual_stream_hashtable, &key));
    if (virtual_isi == 0) {
        new_key = wmem_new(wmem_file_scope(), virtual_stream_key);
        *new_key = key;
        virtual_isi = virtual_stream_count++;
        wmem_map_insert(virtual_stream_hashtable, new_key, GUINT_TO_POINTER(virtual_isi));
    }
    return virtual_isi;
}

static void
virtual_stream_init(void)
{
    virtual_stream_count = 1;
}

/* Data that is associated with a receiver at the BBFrame level, stored
 * at the conversation level. The Transmission Roll-off factor applies
 * for all ISI in a Multiple Input Stream Configuration (see ETSI EN
 * 302 307-2, clause 5.1.6 "Base-Band Header insertion".) Upon first
 * detection of '11' for the RO value, receiver will switch to low
 * roll-off range for the entire conversation.
 */
typedef struct {
    guint32 use_low_ro;
} dvbs2_bb_conv_data;

static dvbs2_bb_conv_data *
get_dvbs2_bb_conv_data(conversation_t *conv)
{
    dvbs2_bb_conv_data *bb_data;

    bb_data = (dvbs2_bb_conv_data *)conversation_get_proto_data(conv, proto_dvb_s2_bb);
    if (!bb_data) {
        bb_data = wmem_new0(wmem_file_scope(), dvbs2_bb_conv_data);
        conversation_add_proto_data(conv, proto_dvb_s2_bb, bb_data);
    }

    return bb_data;
}

/* Data that is associated with one BBFrame, used by GSE or TS packets
 * contained within it. Lifetime of the packet.
 */
typedef struct {
    address src;
    address dst;
    port_type ptype;
    guint32 srcport;
    guint32 destport;
    guint8  isi;
} dvbs2_bb_data;

/* GSE defragmentation related data, one set of data per conversation.
 * Two tables are used. One is for the first pass, and contains the most
 * recent information for each Frag ID for that conversation. The other is
 * for later random access, indexed by both packet number and Frag ID.
 * (It seems very unlikely according to the spec that the same Frag ID would
 * be reused on the same BBFrame that it was completed. If that does happen,
 * then we would have to index by something else, say, subpacket number in the
 * BBFrame (which we would have to track ourselves.)
 */
typedef struct {
    wmem_tree_t *fragid_table;
    wmem_tree_t *subpacket_table;
} gse_analysis_data;

typedef struct {
    guint8 labeltype;
} gse_frag_data;

static gse_analysis_data *
init_gse_analysis_data(void)
{
    gse_analysis_data *gse_data;

    gse_data = wmem_new0(wmem_file_scope(), gse_analysis_data);
    gse_data->fragid_table = wmem_tree_new(wmem_file_scope());
    gse_data->subpacket_table = wmem_tree_new(wmem_file_scope());

    return gse_data;
}

static gse_analysis_data *
get_gse_analysis_data(conversation_t *conv)
{
    gse_analysis_data *gse_data;

    gse_data = (gse_analysis_data *)conversation_get_proto_data(conv, proto_dvb_s2_gse);
    if (!gse_data) {
        gse_data = init_gse_analysis_data();
        conversation_add_proto_data(conv, proto_dvb_s2_gse, gse_data);
    }

    return gse_data;
}

static gse_frag_data *
get_gse_frag_data(gse_analysis_data *dvbs2_data, guint32 fragid, gboolean create)
{
    gse_frag_data  *frag_data;

    frag_data = (gse_frag_data *)wmem_tree_lookup32(dvbs2_data->fragid_table, fragid);
    if (!frag_data && create) {
        frag_data         = wmem_new0(wmem_file_scope(), gse_frag_data);
        wmem_tree_insert32(dvbs2_data->fragid_table, fragid, (void *)frag_data);
    }
    return frag_data;
}

static gse_frag_data *
get_gse_subpacket_data(gse_analysis_data *dvbs2_data, guint32 num, guint32 fragid, gboolean create)
{
    gse_frag_data  *subpacket_data;
    wmem_tree_key_t subpacket_key[3];

    subpacket_key[0].length = 1;
    subpacket_key[0].key = &num;
    subpacket_key[1].length = 1;
    subpacket_key[1].key = &fragid;
    subpacket_key[2].length = 0;
    subpacket_key[2].key = NULL;

    subpacket_data = (gse_frag_data *)wmem_tree_lookup32_array(dvbs2_data->subpacket_table, subpacket_key);
    if (!subpacket_data && create) {
        subpacket_data       = wmem_new0(wmem_file_scope(), gse_frag_data);
        wmem_tree_insert32_array(dvbs2_data->subpacket_table, subpacket_key, (void *)subpacket_data);
    }
    return subpacket_data;
}

/* *** helper functions *** */
static guint8 compute_crc8(tvbuff_t *p, guint8 len, guint offset)
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
static int dissect_dvb_s2_gse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int         new_off                      = 0;
    guint8      labeltype, isi = 0;
    guint16     gse_hdr, data_len, packet_len, gse_proto = 0;
    guint32     fragid, totlength, crc32_calc = 0;

    proto_item *ti;
    proto_item *ttf;
    proto_tree *dvb_s2_gse_tree, *dvb_s2_gse_ncr_tree;

    tvbuff_t   *next_tvb, *data_tvb;
    gboolean   dissected = FALSE;
    gboolean   update_col_info = TRUE;
    gboolean   complete = FALSE;

    dvbs2_bb_data     *pdata;
    conversation_t    *conv;
    gse_analysis_data *gse_data;

    address save_src, save_dst;
    port_type save_ptype;
    guint32 save_srcport, save_destport;

    static int * const gse_header_bitfields[] = {
        &hf_dvb_s2_gse_hdr_start,
        &hf_dvb_s2_gse_hdr_stop,
        &hf_dvb_s2_gse_hdr_labeltype,
        &hf_dvb_s2_gse_hdr_length,
        NULL
    };

    col_append_str(pinfo->cinfo, COL_INFO, " GSE");

    /* get the GSE header */
    gse_hdr = tvb_get_ntohs(tvb, DVB_S2_GSE_OFFS_HDR);
    labeltype = (gse_hdr & DVB_S2_GSE_HDR_LABELTYPE_MASK) >> DVB_S2_GSE_HDR_LABELTYPE_SHIFT;

    /* check if this is just padding, which takes up the rest of the frame */
    if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) &&
        BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS) &&
        labeltype == 0) {

        packet_len = tvb_reported_length(tvb);
        proto_tree_add_uint_format(tree, hf_dvb_s2_gse_padding, tvb, new_off, packet_len, packet_len,
                                   "DVB-S2 GSE Padding, Length: %d", packet_len);
        col_append_str(pinfo->cinfo, COL_INFO, " pad");
    } else {
        /* Not padding, parse as a GSE Header */

        copy_address_shallow(&save_src, &pinfo->src);
        copy_address_shallow(&save_dst, &pinfo->dst);
        save_ptype = pinfo->ptype;
        save_srcport = pinfo->srcport;
        save_destport = pinfo->destport;

        /* We restore the original addresses and ports before each
         * GSE packet so reassembly works. We do it here, because
         * we don't want to restore them after calling a subdissector
         * (so that the final values are that from the last protocol
         * in the last PDU), but we also don't want to restore them
         * if the remainder is just padding either, for the same reason.
         * So we restore them here after the test for padding.
         */
        if (data) { // Called from the BBFrame dissector
            pdata = (dvbs2_bb_data *)data;
            isi = pdata->isi;
            copy_address_shallow(&pinfo->src, &pdata->src);
            copy_address_shallow(&pinfo->dst, &pdata->dst);
            pinfo->ptype = pdata->ptype;
            pinfo->srcport = pdata->srcport;
            pinfo->destport = pdata->destport;
        }

        conv = find_or_create_conversation(pinfo);
        gse_data = get_gse_analysis_data(conv);

        /* Length in header does not include header itself */
        packet_len = (gse_hdr & DVB_S2_GSE_HDR_LENGTH_MASK) + 2;
        ti = proto_tree_add_item(tree, proto_dvb_s2_gse, tvb, 0, packet_len, ENC_NA);
        dvb_s2_gse_tree = proto_item_add_subtree(ti, ett_dvb_s2_gse);
        new_off += 2;
        ti = proto_tree_add_bitmask_with_flags(dvb_s2_gse_tree, tvb, DVB_S2_GSE_OFFS_HDR, hf_dvb_s2_gse_hdr,
            ett_dvb_s2_gse_hdr, gse_header_bitfields, ENC_BIG_ENDIAN, BMT_NO_TFS);
        if (packet_len > tvb_reported_length(tvb)) {
            expert_add_info(pinfo, ti, &ei_dvb_s2_gse_length_invalid);
            packet_len = tvb_reported_length(tvb);
        }

        /* If not both a start and an end packet, then it's a fragment */
        if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) || BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
            proto_tree_add_item_ret_uint(dvb_s2_gse_tree, hf_dvb_s2_gse_fragid, tvb, new_off, 1, ENC_BIG_ENDIAN, &fragid);
            col_append_str(pinfo->cinfo, COL_INFO, "(frag) ");
            /* Differentiate between the same frag id on different ISI */
            fragid ^= (isi << 8);
            new_off += 1;

            gse_frag_data *subpacket_data = NULL;
            if (!PINFO_FD_VISITED(pinfo)) {
                gse_frag_data *frag_data;
                if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS)) {
                    frag_data = get_gse_frag_data(gse_data, fragid, TRUE);
                    frag_data->labeltype = labeltype;
                    /* Delete any previous in-progress reassembly if
                     * we get a new start packet. */
                    data_tvb = fragment_delete(&dvb_s2_gse_reassembly_table,
                        pinfo, fragid, NULL);
                    /* Since we use fragment_add_seq_next, which (as part of
                     * the fragment_*_check family) moves completed assemblies
                     * to a new table (and only checks the completed table
                     * after a packet is visited once), this will never return
                     * non-NULL nor cause problems later.
                     * If it does, something changed in the API.
                     */
                    if (data_tvb != NULL) {
                        DISSECTOR_ASSERT_NOT_REACHED();
                    }
                    subpacket_data = get_gse_subpacket_data(gse_data, pinfo->num, fragid, TRUE);
                    subpacket_data->labeltype = frag_data->labeltype;
                } else {
                    frag_data = get_gse_frag_data(gse_data, fragid, FALSE);
                    /* ETSI TS 102 601-1 A.2 Reassembly
                     * Discard the packet if no buffer is in the re-assembly
                     * state for the Frag ID (check with fragment_get).
                     */
                    if (frag_data && fragment_get(&dvb_s2_gse_reassembly_table, pinfo, fragid, NULL)) {
                        subpacket_data = get_gse_subpacket_data(gse_data, pinfo->num, fragid, TRUE);
                        subpacket_data->labeltype = frag_data->labeltype;
                    }
                }
            } else {
                subpacket_data = get_gse_subpacket_data(gse_data, pinfo->num, fragid, FALSE);
            }
            fragment_head *dvbs2_frag_head = NULL;
            if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
                data_len = packet_len - new_off - DVB_S2_GSE_CRC32_LEN;
            } else {
                data_len = packet_len - new_off;
            }
            if (subpacket_data) {
                dvbs2_frag_head = fragment_add_seq_next(&dvb_s2_gse_reassembly_table, tvb, new_off,
                    pinfo, fragid, NULL, data_len, BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_STOP_POS));
            }
            next_tvb = process_reassembled_data(tvb, new_off, pinfo, "Reassembled GSE",
                dvbs2_frag_head, &dvb_s2_gse_frag_items, &update_col_info, tree);

            if (next_tvb != NULL) {
                /* We have a reassembled packet. */
                complete = TRUE;
                labeltype = subpacket_data->labeltype;
                crc32_calc = crc32_mpeg2_tvb_offset(next_tvb, 0, tvb_reported_length(next_tvb));
                new_off = 0;
                ti = proto_tree_add_item_ret_uint(dvb_s2_gse_tree, hf_dvb_s2_gse_totlength, next_tvb, new_off, 2, ENC_BIG_ENDIAN, &totlength);
                new_off += 2;
                /* Value of totlength field does not include itself or the
                 * CRC32.
                 */
                if (totlength != (guint32)tvb_reported_length_remaining(next_tvb, new_off)) {
                    expert_add_info(pinfo, ti, &ei_dvb_s2_gse_totlength_invalid);
                }
            } else {
                next_tvb = tvb_new_subset_length(tvb, new_off, data_len);
                new_off = 0;
                if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS)) {
                    /* Start packet, add the total length */
                    proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_totlength, next_tvb, new_off, 2, ENC_BIG_ENDIAN);
                    new_off += 2;
                }
            }
        } else {
            complete = TRUE;
            next_tvb = tvb_new_subset_length(tvb, 0, packet_len);
        }

        if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_START_POS) || complete) {
            /* Start packet, decode the header */
            gse_proto = tvb_get_ntohs(next_tvb, new_off);

            /* Protocol Type */
            if (gse_proto <= 1535) {
                /* Type 1 (Next-Header Type field) */
                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_proto_next_header, next_tvb, new_off, 2, ENC_BIG_ENDIAN);
            }
            else {
                /* Type 2 (EtherType compatible Type Fields) */
                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_proto_ethertype, next_tvb, new_off, 2, ENC_BIG_ENDIAN);
            }
            new_off += 2;

            switch (labeltype) {
                case 0:
                    if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS))
                        col_append_str(pinfo->cinfo, COL_INFO, "6 ");
                    proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_label6, next_tvb, new_off, 6, ENC_NA);
                    new_off += 6;
                    break;
                case 1:
                    if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS))
                        col_append_str(pinfo->cinfo, COL_INFO, "3 ");
                    proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_label3, next_tvb, new_off, 3, ENC_BIG_ENDIAN);
                    new_off += 3;
                    break;
                case 2:
                case 3:
                    /* TODO: Case 3 means "same as previous in the BBF."
                     * We can treat it as no label length because nothing
                     * is in the packet.
                     * In the future we could save the values in packet data
                     * and include them here as generated values. Then we
                     * could also set expert_info if no previous packet in
                     * the BBF had a label, or if the previous label was
                     * zero length, both illegal according to ETSI TS
                     * 102 606-1 A.1 "Filtering".
                     */
                    if (BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS))
                        col_append_str(pinfo->cinfo, COL_INFO, "0 ");
                    break;
            }
            if (gse_proto < 0x0600 && gse_proto >= 0x100) {
                /* Only display optional extension headers */
                /* TODO: needs to be tested */

                /* TODO: implementation needs to be checked (len of ext-header??) */
                proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_exthdr, next_tvb, new_off, 1, ENC_BIG_ENDIAN);

                new_off += 1;
            }
        }

        data_tvb = tvb_new_subset_remaining(next_tvb, new_off);

        copy_address_shallow(&pinfo->src, &save_src);
        copy_address_shallow(&pinfo->dst, &save_dst);
        pinfo->ptype = save_ptype;
        pinfo->srcport = save_srcport;
        pinfo->destport = save_destport;

        if (complete) {
            switch (gse_proto) {
                case ETHERTYPE_IP:
                    if (dvb_s2_full_dissection)
                    {
                        call_dissector(ip_handle, data_tvb, pinfo, tree);
                        dissected = TRUE;
                    }
                    break;

                case ETHERTYPE_IPv6:
                    if (dvb_s2_full_dissection)
                    {
                        call_dissector(ipv6_handle, data_tvb, pinfo, tree);
                        dissected = TRUE;
                    }
                    break;

                case ETHERTYPE_VLAN:
                    if (dvb_s2_full_dissection)
                    {
                        call_dissector(eth_withoutfcs_handle, data_tvb, pinfo, tree);
                        dissected = TRUE;
                    }
                    break;

                case DVB_RCS2_SIGNAL_TABLE:
                    call_dissector(dvb_s2_table_handle, data_tvb, pinfo, tree);
                    dissected = TRUE;
                    break;

                case DVB_RCS2_NCR:
                    ttf = proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_ncr, data_tvb, 0, -1, ENC_NA);
                    dvb_s2_gse_ncr_tree = proto_item_add_subtree(ttf, ett_dvb_s2_gse_ncr);
                    proto_tree_add_item(dvb_s2_gse_ncr_tree, hf_dvb_s2_gse_data, data_tvb, 0, -1, ENC_NA);
                    dissected = TRUE;
                    break;

                default:
                    /* Not handled! TODO: expert info? */
                    break;
            }
        }

        if (!dissected) {
            proto_tree_add_item(dvb_s2_gse_tree, hf_dvb_s2_gse_data, data_tvb, 0, -1, ENC_NA);
        }

        /* add crc32 if last fragment */
        if (BIT_IS_CLEAR(gse_hdr, DVB_S2_GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, DVB_S2_GSE_HDR_STOP_POS)) {
            guint flags = PROTO_CHECKSUM_NO_FLAGS;
            if (complete) {
                flags = PROTO_CHECKSUM_VERIFY;
            }
            proto_tree_add_checksum(dvb_s2_gse_tree, tvb, packet_len - DVB_S2_GSE_CRC32_LEN, hf_dvb_s2_gse_crc32, hf_dvb_s2_gse_crc32_status, &ei_dvb_s2_gse_crc32, pinfo, crc32_calc, ENC_BIG_ENDIAN, flags);
        }
    }

    return packet_len;
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




static int dissect_dvb_s2_bb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *dvb_s2_bb_tree;

    tvbuff_t   *sync_tvb = NULL, *tsp_tvb = NULL, *next_tvb = NULL;

    conversation_t *conv, *subcircuit;
    stream_t *ts_stream;
    stream_pdu_fragment_t *ts_frag;
    fragment_head *fd_head;
    dvbs2_bb_conv_data *conv_data;
    dvbs2_bb_data *pdata;

    gboolean    npd, composite_init = FALSE;
    guint8      input8, matype1, crc8, isi = 0, issyi;
    guint8      sync_flag = 0;
    guint16     input16, bb_data_len = 0, user_packet_length, syncd;
    guint32     virtual_id;
    guint       flags;

    int         sub_dissected        = 0, flag_is_ms = 0, new_off = 0;

    static int * const bb_header_bitfields_low_ro[] = {
        &hf_dvb_s2_bb_matype1_gs,
        &hf_dvb_s2_bb_matype1_mis,
        &hf_dvb_s2_bb_matype1_acm,
        &hf_dvb_s2_bb_matype1_issyi,
        &hf_dvb_s2_bb_matype1_npd,
        &hf_dvb_s2_bb_matype1_low_ro,
        NULL
    };

    static int * const bb_header_bitfields_high_ro[] = {
        &hf_dvb_s2_bb_matype1_gs,
        &hf_dvb_s2_bb_matype1_mis,
        &hf_dvb_s2_bb_matype1_acm,
        &hf_dvb_s2_bb_matype1_issyi,
        &hf_dvb_s2_bb_matype1_npd,
        &hf_dvb_s2_bb_matype1_high_ro,
        NULL
    };

    conv = find_or_create_conversation(pinfo);

    col_append_str(pinfo->cinfo, COL_PROTOCOL, "BB ");
    col_append_str(pinfo->cinfo, COL_INFO, "Baseband ");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dvb_s2_bb, tvb, 0, DVB_S2_BB_HEADER_LEN, ENC_NA);
    dvb_s2_bb_tree = proto_item_add_subtree(ti, ett_dvb_s2_bb);

    matype1 = tvb_get_guint8(tvb, DVB_S2_BB_OFFS_MATYPE1);
    new_off += 1;

    if (BIT_IS_CLEAR(matype1, DVB_S2_BB_MIS_POS))
        flag_is_ms = 1;

    issyi = (matype1 & DVB_S2_BB_ISSYI_MASK) >> DVB_S2_BB_ISSYI_POS;
    npd = (matype1 & DVB_S2_BB_NPD_MASK) >> DVB_S2_BB_NPD_POS;

    conv_data = get_dvbs2_bb_conv_data(conv);

    if (((matype1 & DVB_S2_BB_RO_MASK) == 3) && !conv_data->use_low_ro) {
        conv_data->use_low_ro = pinfo->num;
    }
    if (conv_data->use_low_ro && pinfo->num >= conv_data->use_low_ro) {
        proto_tree_add_bitmask_with_flags(dvb_s2_bb_tree, tvb, DVB_S2_BB_OFFS_MATYPE1, hf_dvb_s2_bb_matype1,
        ett_dvb_s2_bb_matype1, bb_header_bitfields_low_ro, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
    } else {
        proto_tree_add_bitmask_with_flags(dvb_s2_bb_tree, tvb, DVB_S2_BB_OFFS_MATYPE1, hf_dvb_s2_bb_matype1,
        ett_dvb_s2_bb_matype1, bb_header_bitfields_high_ro, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
    }

    input8 = tvb_get_guint8(tvb, DVB_S2_BB_OFFS_MATYPE2);
    new_off += 1;
    if (flag_is_ms) {
        proto_tree_add_uint_format_value(dvb_s2_bb_tree, hf_dvb_s2_bb_matype2, tvb,
                                   DVB_S2_BB_OFFS_MATYPE2, 1, input8, "Input Stream Identifier (ISI): %d",
                                   input8);
        isi = input8;
    } else {
        proto_tree_add_uint_format_value(dvb_s2_bb_tree, hf_dvb_s2_bb_matype2, tvb,
                                   DVB_S2_BB_OFFS_MATYPE2, 1, input8, "reserved");
    }

    user_packet_length = input16 = tvb_get_ntohs(tvb, DVB_S2_BB_OFFS_UPL);
    new_off += 2;

    proto_tree_add_uint_format(dvb_s2_bb_tree, hf_dvb_s2_bb_upl, tvb,
                               DVB_S2_BB_OFFS_UPL, 2, input16, "User Packet Length: %d bits (%d bytes)",
                               (guint16) input16, (guint16) input16 / 8);

    new_off += 2;
    bb_data_len = input16 = tvb_get_ntohs(tvb, DVB_S2_BB_OFFS_DFL);
    bb_data_len /= 8;
    if (bb_data_len + DVB_S2_BB_HEADER_LEN > tvb_reported_length(tvb)) {
        /* DFL can be less than the length of the BBFrame (zero padding is
         * applied, see ETSI EN 302 307-1 5.2.1), but cannot be greater
         * than the frame length (minus 10 bytes of header).
         */
        expert_add_info(pinfo, ti, &ei_dvb_s2_bb_dfl_invalid);
        bb_data_len = tvb_reported_length_remaining(tvb, DVB_S2_BB_HEADER_LEN);
    }

    proto_tree_add_uint_format_value(dvb_s2_bb_tree, hf_dvb_s2_bb_dfl, tvb,
                               DVB_S2_BB_OFFS_DFL, 2, input16, "%d bits (%d bytes)", input16, input16 / 8);

    new_off += 1;
    sync_flag = tvb_get_guint8(tvb, DVB_S2_BB_OFFS_SYNC);
    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_sync, tvb, DVB_S2_BB_OFFS_SYNC, 1, ENC_BIG_ENDIAN);

    new_off += 2;
    syncd = tvb_get_ntohs(tvb, DVB_S2_BB_OFFS_SYNCD);
    proto_tree_add_uint_format_value(dvb_s2_bb_tree, hf_dvb_s2_bb_syncd, tvb,
        DVB_S2_BB_OFFS_SYNCD, 2, syncd, "%d bits (%d bytes)", syncd, syncd >> 3);

    new_off += 1;
    proto_tree_add_checksum(dvb_s2_bb_tree, tvb, DVB_S2_BB_OFFS_CRC, hf_dvb_s2_bb_crc, hf_dvb_s2_bb_crc_status, &ei_dvb_s2_bb_crc, pinfo,
        compute_crc8(tvb, DVB_S2_BB_HEADER_LEN - 1, 0), ENC_NA, PROTO_CHECKSUM_VERIFY);

    /* The Base-Band Frame can have multiple GSE (or TS, which can have ULE
     * or MPE) packets that are concatenated, can be fragmented, and can call
     * subdissectors including IP (which itself can be fragmented) that
     * overwrite the pinfo addresses & ports, which are used as keys for
     * reassembly tables, conversations, and other purposes.
     *
     * Thus, we need to save the current values before any subdissectors
     * are run, and restore them each time before each subpacket.
     *
     * When BBFrames are carried over UDP or RTP we can't necessarily rely on
     * the ISI being unique - a capture might include different streams sent
     * as single input streams or with the same ISI over different UDP
     * endpoints and we don't want to mix data when defragmenting. So we
     * create a virtual ISI.
     */

    /* UDP and RTP both always create conversations. If we later have
     * support for DVB Base Band Frames as the link-layer of a capture file,
     * we'll need to handle it differently. In that case just use the
     * ISI directly in conversation_new_by_id() instead of creating a
     * virtual stream identifier.
     */

    if (conv) {
        virtual_id = virtual_stream_lookup(conv, isi);
        /* DVB Base Band streams are unidirectional. Differentiate by direction
         * for the unlikely case of two streams between the same endpointss in
         * the opposite direction.
         */
        if (addresses_equal(&pinfo->src, conversation_key_addr1(conv->key_ptr))) {
            pinfo->p2p_dir = P2P_DIR_SENT;
        } else {
            pinfo->p2p_dir = P2P_DIR_RECV;
        }

    } else {
        virtual_id = isi;
        pinfo->p2p_dir = P2P_DIR_SENT;
    }
    subcircuit = find_conversation_by_id(pinfo->num, CONVERSATION_DVBBBF, virtual_id);
    if (subcircuit == NULL) {
        subcircuit = conversation_new_by_id(pinfo->num, CONVERSATION_DVBBBF, virtual_id);
    }

    /* conversation_set_conv_addr_port_endpoints() could be useful for the subdissectors
     * this calls (whether GSE or TS, and replace passing the packet data
     * below), but it could cause problems when the subdissectors of those
     * subdissectors try and call find_or_create_conversation().
     * pinfo->use_conv_addr_port_endpoints doesn't affect reassembly tables
     * in the default reassembly functions, either. So maybe the eventual
     * approach is to create a conversation key but set
     * pinfo->use_conv_addr_port_endpoints back to FALSE, and also make the
     * GSE and MP2T dissectors more (DVB BBF) conversation key aware,
     * including in their reassembly functions.
     */

    pdata = wmem_new0(pinfo->pool, dvbs2_bb_data);
    copy_address_shallow(&pdata->src, &pinfo->src);
    copy_address_shallow(&pdata->dst, &pinfo->dst);
    pdata->ptype = pinfo->ptype;
    pdata->srcport = pinfo->srcport;
    pdata->destport = pinfo->destport;
    pdata->isi = isi;

    switch (matype1 & DVB_S2_BB_TSGS_MASK) {
    case DVB_S2_BB_TSGS_GENERIC_CONTINUOUS:
        /* Check GSE constraints on the BB header per 9.2.1 of ETSI TS 102 771 */
        if (issyi) {
            expert_add_info(pinfo, ti, &ei_dvb_s2_bb_issy_invalid);
        }
        if (npd) {
            expert_add_info(pinfo, ti, &ei_dvb_s2_bb_npd_invalid);
        }
        if (user_packet_length != 0x0000) {
            expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_upl_invalid,
                "UPL is 0x%04x. It must be 0x0000 for GSE packets.", user_packet_length);
        }


        if (dvb_s2_df_dissection) {
            while (bb_data_len) {
                if (sync_flag == DVB_S2_BB_SYNC_EIP_CRC32 && bb_data_len == DVB_S2_BB_EIP_CRC32_LEN) {
                    proto_tree_add_checksum(dvb_s2_bb_tree, tvb, new_off, hf_dvb_s2_bb_eip_crc32, hf_dvb_s2_bb_eip_crc32_status, &ei_dvb_s2_bb_crc, pinfo, crc32_mpeg2_tvb_offset(tvb, DVB_S2_BB_HEADER_LEN, new_off - DVB_S2_BB_HEADER_LEN), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
                    bb_data_len = 0;
                    new_off += DVB_S2_BB_EIP_CRC32_LEN;
                } else {
                    /* start DVB-GSE dissector */
                    sub_dissected = dissect_dvb_s2_gse(tvb_new_subset_length(tvb, new_off, bb_data_len), pinfo, tree, pdata);
                    new_off += sub_dissected;

                    if ((sub_dissected <= bb_data_len) && (sub_dissected >= DVB_S2_GSE_MINSIZE)) {
                        bb_data_len -= sub_dissected;
                        if (bb_data_len < DVB_S2_GSE_MINSIZE)
                            bb_data_len = 0;
                    } else {
                        bb_data_len = 0;
                    }
                }
            }
        } else {
            proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_df, tvb, new_off, bb_data_len, ENC_NA);
            new_off += bb_data_len;
        }
        break;

    case DVB_S2_BB_TSGS_GENERIC_PACKETIZED:
        proto_tree_add_item(tree, hf_dvb_s2_bb_packetized, tvb, new_off, bb_data_len, ENC_NA);
        new_off += bb_data_len;
        break;

    case DVB_S2_BB_TSGS_TRANSPORT_STREAM:
        crc8 = 0;
        // TODO: Save from frame to frame to test the first TSP when syncd == 0?
        flags = PROTO_CHECKSUM_NO_FLAGS;
        /* Check TS constraints on the BB header per 5.1 of ETSI EN 302 307 */
        if (sync_flag != MP2T_SYNC_BYTE) {
            expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_sync_invalid,
                "Copy of User Packet Sync is 0x%02x. It must be 0x%02x for TS packets.", sync_flag, MP2T_SYNC_BYTE);
        }
        /* ETSI 302 307-1 5.1.6: SYNCD == 0xFFFF -> "no UP starts in the
         * DATA FIELD"; otherwise it should not point past the UPL.
         */
        if (syncd != 0xFFFF && (syncd >> 3) >= bb_data_len) {
            expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_syncd_invalid,
                "SYNCD >= DFL (points past the end of the Data Field)");
            syncd = 0xFFFF;
        }
        /* Assume byte aligned. */
        user_packet_length >>= 3;
        /* UPL should be *at least* MP2T_PACKET_SIZE, depending on npd (1 byte)
         * and issy (2 or 3 bytes). The fields are overdetermined (something
         * addressed in -C2 and -T2's High Efficency Mode for TS), so how to
         * process in the case of inconsistency is a judgment call. The
         * approach here is to disable anything for which there is insufficent
         * room, but not to enable anything marked as inactive.
         */
        switch (user_packet_length) {
        case MP2T_PACKET_SIZE:
            if (issyi) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_issy_invalid,
                        "ISSYI is active on TS but UPL is only %d bytes",
                        user_packet_length);
                issyi = 0;
            }
            if (npd) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_npd_invalid,
                        "NPD is active on TS but UPL is only %d bytes",
                        user_packet_length);
                npd = FALSE;
            }
            break;
        case MP2T_PACKET_SIZE + 1:
            if (issyi) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_issy_invalid,
                        "ISSYI is active on TS but UPL is only %d bytes",
                        user_packet_length);
                issyi = 0;
            }
            if (!npd) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_npd_invalid,
                        "NPD is inactive on TS but UPL is %d bytes",
                        user_packet_length);
            }
            break;
        case MP2T_PACKET_SIZE + 2:
            if (!issyi) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_issy_invalid,
                        "ISSYI is inactive on TS but UPL is %d bytes",
                        user_packet_length);
            } else {
                issyi = 2;
            }
            if (npd) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_npd_invalid,
                        "NPD is active on TS but UPL is %d bytes",
                        user_packet_length);
                npd = FALSE;
            }
            break;
        case MP2T_PACKET_SIZE + 3:
            if (npd) {
                if (!issyi) {
                    expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_issy_invalid,
                            "ISSYI is inactive on TS with NPD active but UPL is %d bytes",
                            user_packet_length);
                } else {
                    issyi = 2;
                }
            } else {
                if (!issyi) {
                    expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_issy_invalid,
                            "ISSYI is inactive on TS with NPD inactive but UPL is %d bytes",
                            user_packet_length);
                } else {
                    issyi = 3;
                }
            }
            break;
        case MP2T_PACKET_SIZE + 4:
            if (!issyi) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_issy_invalid,
                        "ISSYI is inactive on TS but UPL is %d bytes",
                        user_packet_length);
            } else {
                issyi = 3;
            }
            if (!npd) {
                expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_npd_invalid,
                        "NPD is inactive on TS but UPL is %d bytes",
                        user_packet_length);
            }
            break;
        default:
            expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_upl_invalid,
                    "UPL is %d byte%s. It must be between %d and %d bytes for TS packets.",
                    user_packet_length, plurality(user_packet_length, "", "s"),
                    MP2T_PACKET_SIZE, MP2T_PACKET_SIZE+4);
            if (user_packet_length < MP2T_PACKET_SIZE) {
                user_packet_length = 0;
            }
            break;
        }
        if (dvb_s2_df_dissection && user_packet_length) {
            sync_tvb = tvb_new_subset_length(tvb, DVB_S2_BB_OFFS_SYNC, 1);
            ts_stream = find_stream(subcircuit, pinfo->p2p_dir);
            if (ts_stream == NULL) {
                ts_stream = stream_new(subcircuit, pinfo->p2p_dir);
            }
            if (syncd == 0xFFFF) {
                /* Largely theoretical for TS (cf. Generic Packetized, GSE-HEM)
                 * due to the small size of TSPs versus transmitted BBFrames.
                 */
                next_tvb = tvb_new_subset_length(tvb, new_off, bb_data_len);
                ts_frag = stream_find_frag(ts_stream, pinfo->num, new_off);
                if (ts_frag == NULL) {
                    ts_frag = stream_add_frag(ts_stream, pinfo->num, new_off,
                            next_tvb, pinfo, TRUE);
                }
                stream_process_reassembled(next_tvb, 0, pinfo,
                    "Reassembled TSP", ts_frag, &dvbs2_frag_items, NULL,
                    tree);
                new_off += bb_data_len;
            } else {
                syncd >>= 3;
                /* Do this even if syncd is zero just to clear out a partial
                 * fragment from before in the case of drops or out of order. */
                next_tvb = tvb_new_subset_length(tvb, new_off, syncd);
                ts_frag = stream_find_frag(ts_stream, pinfo->num, new_off);
                if (ts_frag == NULL) {
                    ts_frag = stream_add_frag(ts_stream, pinfo->num, new_off,
                            next_tvb, pinfo, FALSE);
                }
                fd_head = stream_get_frag_data(ts_frag);
                /* Don't put anything in the tree when SYNCD is 0 and there was
                 * no earlier fragment (i.e., zero length reassembly)
                 */
                if (syncd || (fd_head && fd_head->datalen)) {
                    next_tvb = stream_process_reassembled(next_tvb, 0, pinfo,
                            "Reassembled TSP", ts_frag, &dvbs2_frag_items, NULL,
                            tree);
                    if (next_tvb && tvb_reported_length(next_tvb) == user_packet_length) {
                        tsp_tvb = tvb_new_composite();
                        composite_init = TRUE;
                        tvb_composite_append(tsp_tvb, sync_tvb);
                        proto_tree_add_checksum(dvb_s2_bb_tree, next_tvb, 0,
                                hf_dvb_s2_bb_up_crc, hf_dvb_s2_bb_up_crc_status,
                                &ei_dvb_s2_bb_crc, pinfo, crc8, ENC_NA, flags);
                        crc8 = compute_crc8(next_tvb, user_packet_length - 1, 1);
                        flags = PROTO_CHECKSUM_VERIFY;
                        tvb_composite_append(tsp_tvb, tvb_new_subset_length(next_tvb, 1, MP2T_PACKET_SIZE - 1));
                        /* XXX: ISSY is not fully dissected */
                        if (issyi == 2) {
                            proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_issy_short,
                                    next_tvb, MP2T_PACKET_SIZE, issyi, ENC_BIG_ENDIAN);
                        } else if (issyi == 3) {
                            proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_issy_short,
                                    next_tvb, MP2T_PACKET_SIZE, issyi, ENC_BIG_ENDIAN);
                        }
                        if (npd) {
                            proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_dnp,
                                    next_tvb, MP2T_PACKET_SIZE + issyi, 1, ENC_NA);
                        }
                    } else if (pinfo->num != subcircuit->setup_frame) {
                        /* Bad reassembly due to a dropped or out of order
                         * packet, or maybe the previous packet cut short.
                         */
                        expert_add_info(pinfo, ti, &ei_dvb_s2_bb_up_reassembly_invalid);
                    }
                    new_off += syncd;
                }
            }
            while ((bb_data_len + DVB_S2_BB_HEADER_LEN - new_off) >= user_packet_length) {
                proto_tree_add_checksum(dvb_s2_bb_tree, tvb, new_off,
                        hf_dvb_s2_bb_up_crc, hf_dvb_s2_bb_up_crc_status,
                        &ei_dvb_s2_bb_crc, pinfo, crc8, ENC_NA, flags);
                if (!composite_init) {
                    tsp_tvb = tvb_new_composite();
                    composite_init = TRUE;
                }
                tvb_composite_append(tsp_tvb, sync_tvb);
                new_off++;
                crc8 = compute_crc8(tvb, user_packet_length - 1, new_off);
                flags = PROTO_CHECKSUM_VERIFY;
                tvb_composite_append(tsp_tvb, tvb_new_subset_length(tvb, new_off, MP2T_PACKET_SIZE - 1));
                new_off += MP2T_PACKET_SIZE - 1;
                /* XXX: ISSY is not fully dissected */
                if (issyi == 2) {
                    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_issy_short,
                            tvb, new_off, issyi, ENC_BIG_ENDIAN);
                } else if (issyi == 3) {
                    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_issy_long,
                            tvb, new_off, issyi, ENC_BIG_ENDIAN);
                }
                if (npd) {
                    proto_tree_add_item(dvb_s2_bb_tree, hf_dvb_s2_bb_dnp,
                            tvb, new_off + issyi, 1, ENC_NA);
                }
                new_off += user_packet_length - MP2T_PACKET_SIZE;
            }
            if (bb_data_len + DVB_S2_BB_HEADER_LEN - new_off) {
                next_tvb = tvb_new_subset_length(tvb, new_off, bb_data_len + DVB_S2_BB_HEADER_LEN - new_off);
                ts_frag = stream_find_frag(ts_stream, pinfo->num, new_off);
                if (ts_frag == NULL) {
                    ts_frag = stream_add_frag(ts_stream, pinfo->num, new_off,
                            next_tvb, pinfo, TRUE);
                }
                stream_process_reassembled(next_tvb, 0, pinfo,
                        "Reassembled TSP", ts_frag, &dvbs2_frag_items, NULL, tree);
            }
            if (composite_init) {
                tvb_composite_finalize(tsp_tvb);
                add_new_data_source(pinfo, tsp_tvb, "Sync-swapped TS");
                /* The way the MP2T dissector handles reassembly (using the
                 * offsets into the TVB to store per-packet information), it
                 * needs the entire composite TVB at once rather than be passed
                 * one TSP at a time. That's why bb_data_len is limited to the
                 * reported frame length, to avoid throwing an exception running
                 * off the end before processing the TSPs that are present.
                 */
                call_dissector(mp2t_handle, tsp_tvb, pinfo, tree);
            }
        } else {
            proto_tree_add_item(tree, hf_dvb_s2_bb_transport, tvb, new_off, bb_data_len, ENC_NA);
            new_off += bb_data_len;
        }
        break;

    default:
        proto_tree_add_item(tree, hf_dvb_s2_bb_reserved, tvb, new_off, bb_data_len, ENC_NA);
        new_off += bb_data_len;
        expert_add_info(pinfo, ti, &ei_dvb_s2_bb_reserved);
        break;
    }

    return new_off;
}

static int detect_dvb_s2_modeadapt(tvbuff_t *tvb)
{
    int matched_headers = 0;

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
        matched_headers |= (1 << DVB_S2_MODEADAPT_TYPE_L1);
    }

    /* Try L.2 format: header includes sync byte */
    if ((tvb_get_guint8(tvb, DVB_S2_MODEADAPT_OFFS_SYNCBYTE) == DVB_S2_MODEADAPT_SYNCBYTE) &&
        test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_L2SIZE)) {
        matched_headers |= (1 << DVB_S2_MODEADAPT_TYPE_L2);
    }

    /* Try L.4 format: header does not include sync byte */
    if (test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_L4SIZE)) {
        matched_headers |= (1 << DVB_S2_MODEADAPT_TYPE_L4);
    }

    /* Try L.3 format: header includes sync byte */
    if ((tvb_get_guint8(tvb, DVB_S2_MODEADAPT_OFFS_SYNCBYTE) == DVB_S2_MODEADAPT_SYNCBYTE) &&
        test_dvb_s2_crc(tvb, DVB_S2_MODEADAPT_L3SIZE)) {
        matched_headers |= (1 << DVB_S2_MODEADAPT_TYPE_L3);
    }

    return matched_headers;
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

    if (dvb_s2_try_all_modeadapt) {
        matched_headers = detect_dvb_s2_modeadapt(tvb);
        if (matched_headers & (1 << dvb_s2_default_modeadapt)) {
            /* If the default value from preferences matches, use it first */
            modeadapt_type = dvb_s2_default_modeadapt;
        } else if (matched_headers & (1 << DVB_S2_MODEADAPT_TYPE_L3)) {
            /* In my experience and in product data sheets, L.3 format is the
             * most common for outputting over UDP or RTP, so try it next.
             */
            modeadapt_type = DVB_S2_MODEADAPT_TYPE_L3;
        } else if (matched_headers & (1 << DVB_S2_MODEADAPT_TYPE_L4)) {
            modeadapt_type = DVB_S2_MODEADAPT_TYPE_L4;
        } else if (matched_headers & (1 << DVB_S2_MODEADAPT_TYPE_L2)) {
            modeadapt_type = DVB_S2_MODEADAPT_TYPE_L2;
        } else if (matched_headers & (1 << DVB_S2_MODEADAPT_TYPE_L1)) {
            modeadapt_type = DVB_S2_MODEADAPT_TYPE_L1;
        } else {
            /* If nothing matches, use the default value from preferences.
             */
            modeadapt_type = dvb_s2_default_modeadapt;
        }
    } else {
        /* Assume it's the preferred type */
        modeadapt_type = dvb_s2_default_modeadapt;
    }
    modeadapt_len = dvb_s2_modeadapt_sizes[modeadapt_type];

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVB-S2 ");
    col_set_str(pinfo->cinfo, COL_INFO,     "DVB-S2 ");

    /* Add the protocol even if no length (L.1) so we get access to prefs. */
    ti = proto_tree_add_protocol_format(tree, proto_dvb_s2_modeadapt, tvb, 0, modeadapt_len,
        "DVB-S2 Mode Adaptation Header L.%d", modeadapt_type);
    if (ws_count_ones(matched_headers) > 1) {
        expert_add_info_format(pinfo, ti, &ei_dvb_s2_bb_header_ambiguous,
            "Mode adaptation header format is ambiguous. Assuming L.%d", modeadapt_type);
    }
    /* If there's a mode adaptation header, create display subtree for it */
    if (modeadapt_len > 0) {
        dvb_s2_modeadapt_tree = proto_item_add_subtree(ti, ett_dvb_s2_modeadapt);

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
            mc = tvb_get_guint8(tvb, cur_off);
            if (mc & 0x80) {
                modcod = 0x80;
                modcod |= ((mc & 0x1F) << 2);
                modcod |= ((mc & 0x40) >> 5);
                tf = proto_tree_add_item(dvb_s2_modeadapt_tree, hf_dvb_s2_modeadapt_acm, tvb,
                        cur_off, 1, ENC_BIG_ENDIAN);

                dvb_s2_modeadapt_acm_tree = proto_item_add_subtree(tf, ett_dvb_s2_modeadapt_acm);

                proto_tree_add_item(dvb_s2_modeadapt_acm_tree, hf_dvb_s2_modeadapt_acm_pilot, tvb,
                        cur_off, 1, ENC_BIG_ENDIAN);
                proto_tree_add_uint_format_value(dvb_s2_modeadapt_acm_tree, hf_dvb_s2_modeadapt_acm_modcod_s2x, tvb,
                        cur_off, 1, mc, "DVBS2X %s(%d)", modeadapt_modcods[modcod].strptr, modcod);
            } else {
                proto_tree_add_bitmask_with_flags(dvb_s2_modeadapt_tree, tvb, cur_off, hf_dvb_s2_modeadapt_acm,
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
    cur_off += dissect_dvb_s2_bb(tvb_new_subset_remaining(tvb, cur_off), pinfo, tree, NULL);

    return cur_off;
}

static gboolean dissect_dvb_s2_modeadapt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int matched_headers = detect_dvb_s2_modeadapt(tvb);
    if (dvb_s2_try_all_modeadapt) {
        if (matched_headers == 0) {
            /* This does not look like a DVB-S2-BB frame at all. We are a
               heuristic dissector, so we should just punt and let another
               dissector have a try at this one. */
            return FALSE;
        }
    } else if (! (matched_headers & (1 << dvb_s2_default_modeadapt))) {
        return FALSE;
    }

    int dissected_bytes;
    dissected_bytes = dissect_dvb_s2_modeadapt(tvb, pinfo, tree, data);
    if (dissected_bytes > 0) {
        return TRUE;
    } else {
        return FALSE;
    }
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
                FT_BOOLEAN, 8, TFS(&tfs_on_off), DVB_S2_MODEADAPT_PILOTS_MASK,
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
                FT_BOOLEAN, 8, TFS(&tfs_active_inactive), DVB_S2_BB_ISSYI_MASK,
                "Input Stream Synchronization Indicator", HFILL}
        },
        {&hf_dvb_s2_bb_matype1_npd, {
                "NPD", "dvb-s2_bb.matype1.npd",
                FT_BOOLEAN, 8, TFS(&tfs_active_inactive), DVB_S2_BB_NPD_MASK,
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
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "User Packet Length", HFILL}
        },
        {&hf_dvb_s2_bb_dfl, {
                "DFL", "dvb-s2_bb.dfl",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Data Field Length", HFILL}
        },
        {&hf_dvb_s2_bb_sync, {
                "SYNC", "dvb-s2_bb.sync",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Copy of the User Packet Sync-byte", HFILL}
        },
        {&hf_dvb_s2_bb_syncd, {
                "SYNCD", "dvb-s2_bb.syncd",
                FT_UINT16, BASE_DEC, NULL, 0x0,
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
                "GSE High Efficiency Mode Data", "dvb-s2_bb.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "GSE High Efficiency Mode (GSE-HEM) Data", HFILL}
        },
        {&hf_dvb_s2_bb_df, {
                "BBFrame user data", "dvb-s2_bb.df",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_dvb_s2_bb_issy_short, {
                "ISSY (short)", "dvb-s2_bb.issy.short",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Input stream synchronizer (2 octet version)", HFILL}
        },
        {&hf_dvb_s2_bb_issy_long, {
                "ISSY (long)", "dvb-s2_bb.issy.long",
                FT_UINT24, BASE_HEX, NULL, 0x0,
                "Input stream synchronizer (3 octet version)", HFILL}
        },
        {&hf_dvb_s2_bb_dnp, {
                "DNP", "dvb-s2_bb.dnp",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Deleted Null-Packets counter", HFILL}
        },
        {&hf_dvb_s2_bb_eip_crc32, {
                "EIP CRC32", "dvb-s2_bb.eip_crc32",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                "Explicit Integrity Protection CRC32", HFILL}
        },
        {&hf_dvb_s2_bb_eip_crc32_status, {
                "EIP CRC32 Status", "dvb-s2_bb.eip_crc32.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL}
        },
        {&hf_dvb_s2_bb_up_crc, {
                "UP Checksum", "dvb-s2_bb.up.crc",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "User Packet CRC-8", HFILL}
        },
        {&hf_dvb_s2_bb_up_crc_status, {
                "UP Checksum Status", "dvb-s2_bb.up.crc.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL}
        },
        { &hf_dvbs2_fragment_overlap,
            { "Fragment overlap", "dvb-s2_bb.fragment.overlap", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
        { &hf_dvbs2_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "dvb-s2_bb.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_dvbs2_fragment_multiple_tails,
            { "Multiple tail fragments found", "dvb-s2_bb.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_dvbs2_fragment_too_long_fragment,
            { "Fragment too long", "dvb-s2_bb.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }},
        { &hf_dvbs2_fragment_error,
            { "Defragmentation error", "dvb-s2_bb.fragment.error", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_dvbs2_fragment_count,
            { "Fragment count", "dvb-s2_bb.fragment.count", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_dvbs2_fragment,
            { "DVB-S2 UP Fragment", "dvb-s2_bb.fragment", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_dvbs2_fragments,
            { "DVB-S2 UP Fragments", "dvb-s2_bb.fragments", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_dvbs2_reassembled_in,
            { "Reassembled DVB-S2 UP in frame", "dvb-s2_bb.reassembled_in", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, "This User Packet is reassembled in this frame", HFILL }},

        { &hf_dvbs2_reassembled_length,
            { "Reassembled DVB-S2 UP length", "dvb-s2_bb.reassembled.length", FT_UINT32, BASE_DEC,
                NULL, 0x0, "The total length of the reassembled payload", HFILL }},

        { &hf_dvbs2_reassembled_data,
            { "Reassembled DVB-S2 UP data", "dvb-s2_bb.reassembled.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, "The reassembled payload", HFILL }}
    };

    static gint *ett_bb[] = {
        &ett_dvb_s2_bb,
        &ett_dvb_s2_bb_matype1,
        &ett_dvbs2_fragments,
        &ett_dvbs2_fragment,
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
                FT_BOOLEAN, 16, TFS(&tfs_enabled_disabled), DVB_S2_GSE_HDR_START_MASK,
                "Start Indicator", HFILL}
        },
        {&hf_dvb_s2_gse_hdr_stop, {
                "Stop", "dvb-s2_gse.hdr.stop",
                FT_BOOLEAN, 16, TFS(&tfs_enabled_disabled), DVB_S2_GSE_HDR_STOP_MASK,
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
        {&hf_dvb_s2_gse_crc32_status, {
                "CRC Status", "dvb-s2_gse.crc.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL}
        },
        { &hf_dvb_s2_gse_fragment_overlap,
            { "Fragment overlap", "dvb-s2_gse.fragment.overlap", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

        { &hf_dvb_s2_gse_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "dvb-s2_gse.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }},

        { &hf_dvb_s2_gse_fragment_multiple_tails,
            { "Multiple tail fragments found", "dvb-s2_gse.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }},

        { &hf_dvb_s2_gse_fragment_too_long_fragment,
            { "Fragment too long", "dvb-s2_gse.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }},

        { &hf_dvb_s2_gse_fragment_error,
            { "Defragmentation error", "dvb-s2_gse.fragment.error", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},

        { &hf_dvb_s2_gse_fragment_count,
            { "Fragment count", "dvb-s2_gse.fragment.count", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_dvb_s2_gse_fragment,
            { "DVB-S2 GSE Fragment", "dvb-s2_gse.fragment", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

        { &hf_dvb_s2_gse_fragments,
            { "DVB-S2 GSE Fragments", "dvb-s2_gse.fragments", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

        { &hf_dvb_s2_gse_reassembled_in,
            { "Reassembled DVB-S2 GSE in frame", "dvb-s2_gse.reassembled_in", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, "This GSE packet is reassembled in this frame", HFILL }},

        { &hf_dvb_s2_gse_reassembled_length,
            { "Reassembled DVB-S2 GSE length", "dvb-s2_gse.reassembled.length", FT_UINT32, BASE_DEC,
                NULL, 0x0, "The total length of the reassembled payload", HFILL }},

        { &hf_dvb_s2_gse_reassembled_data,
            { "Reassembled DVB-S2 GSE data", "dvb-s2_gse.reassembled.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, "The reassembled payload", HFILL }}
    };

    static gint *ett_gse[] = {
        &ett_dvb_s2_gse,
        &ett_dvb_s2_gse_hdr,
        &ett_dvb_s2_gse_ncr,
        &ett_dvb_s2_gse_fragments,
        &ett_dvb_s2_gse_fragment,
    };

    static ei_register_info ei[] = {
        { &ei_dvb_s2_bb_crc, { "dvb-s2_bb.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_dvb_s2_bb_issy_invalid, {"dvb-s2_bb.issy_invalid", PI_PROTOCOL, PI_WARN, "ISSY is active, which is not allowed for GSE packets", EXPFILL }},
        { &ei_dvb_s2_bb_npd_invalid, {"dvb-s2_bb.npd_invalid", PI_PROTOCOL, PI_WARN, "NPD is active, which is not allowed for GSE packets", EXPFILL }},
        { &ei_dvb_s2_bb_upl_invalid, {"dvb-s2_bb.upl_invalid", PI_PROTOCOL, PI_WARN, "User Packet Length non-zero, which is not allowed for GSE packets", EXPFILL }},
        { &ei_dvb_s2_bb_dfl_invalid, {"dvb-s2_bb.dfl_invalid", PI_PROTOCOL, PI_WARN, "Data Field Length greater than reported frame length", EXPFILL }},
        { &ei_dvb_s2_bb_sync_invalid, {"dvb-s2_bb.sync_invalid", PI_PROTOCOL, PI_WARN, "User Packet Sync-byte not 0x47, which is not allowed for TS packets", EXPFILL }},
        { &ei_dvb_s2_bb_syncd_invalid, {"dvb-s2_bb.syncd_invalid", PI_PROTOCOL, PI_WARN, "Sync Distance is invalid", EXPFILL }},
        { &ei_dvb_s2_bb_up_reassembly_invalid, {"dvb-s2_bb.up_reassembly_invalid", PI_REASSEMBLE, PI_ERROR, "Reassembled User Packet has invalid length (dropped or out of order frames)", EXPFILL }},
        { &ei_dvb_s2_bb_reserved, {"dvb-s2_bb.reserved_frame_format", PI_UNDECODED, PI_WARN, "Dissection of GSE-HEM is not (yet) supported", EXPFILL }},
        { &ei_dvb_s2_bb_header_ambiguous, { "dvb-s2_bb.header_ambiguous", PI_ASSUMPTION, PI_WARN, "Mode Adaptation header ambiguous", EXPFILL }},
    };

    expert_module_t* expert_dvb_s2_bb;

    static ei_register_info ei_gse[] = {
        { &ei_dvb_s2_gse_length_invalid, {"dvb-s2_gse.hdr.length_invalid", PI_PROTOCOL, PI_ERROR, "Length field in header exceeds available bytes in frame", EXPFILL }},
        { &ei_dvb_s2_gse_totlength_invalid, {"dvb-s2_gse.totlength_invalid", PI_REASSEMBLE, PI_ERROR, "Length of reassembled packet does not equal total length field (missing fragments?)", EXPFILL }},
        { &ei_dvb_s2_gse_crc32, { "dvb-s2_gse.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    expert_module_t* expert_dvb_s2_gse;

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
    expert_dvb_s2_gse = expert_register_protocol(proto_dvb_s2_gse);
    expert_register_field_array(expert_dvb_s2_gse, ei_gse, array_length(ei_gse));

    dvb_s2_modeadapt_module = prefs_register_protocol(proto_dvb_s2_modeadapt, NULL);

    prefs_register_obsolete_preference(dvb_s2_modeadapt_module, "enable");

    prefs_register_bool_preference(dvb_s2_modeadapt_module, "decode_df",
        "Enable dissection of DATA FIELD",
        "Check this to enable full protocol dissection of data above BBHeader",
        &dvb_s2_df_dissection);

    prefs_register_bool_preference(dvb_s2_modeadapt_module, "full_decode",
        "Enable dissection of GSE data",
        "Check this to enable full protocol dissection of data above GSE Layer",
        &dvb_s2_full_dissection);

    prefs_register_enum_preference(dvb_s2_modeadapt_module, "default_modeadapt",
        "Preferred Mode Adaptation Interface",
        "The preferred Mode Adaptation Interface",
        &dvb_s2_default_modeadapt, dvb_s2_modeadapt_enum, FALSE);

    prefs_register_bool_preference(dvb_s2_modeadapt_module, "try_all_modeadapt",
        "Try all Mode Adaptation Interface Types",
        "Try all supported Mode Adaptation Interface Types, using the preferred"
        " value in the case of ambiguity; if unset, only look for Base Band"
        " Frames with the preferred type",
        &dvb_s2_try_all_modeadapt);

    prefs_register_obsolete_preference(dvb_s2_modeadapt_module, "dynamic.payload.type");

    register_init_routine(dvb_s2_gse_defragment_init);
    register_init_routine(&virtual_stream_init);

    virtual_stream_hashtable = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), virtual_stream_hash, virtual_stream_equal);

    dvb_s2_modeadapt_handle = register_dissector("DVB-S2 Mode adaptation header", dissect_dvb_s2_modeadapt, proto_dvb_s2_modeadapt);
}

void proto_reg_handoff_dvb_s2_modeadapt(void)
{
    heur_dissector_add("udp", dissect_dvb_s2_modeadapt_heur, "DVB-S2 over UDP", "dvb_s2_udp", proto_dvb_s2_modeadapt, HEURISTIC_DISABLE);
    dissector_add_for_decode_as("udp.port", dvb_s2_modeadapt_handle);
    ip_handle   = find_dissector_add_dependency("ip", proto_dvb_s2_bb);
    ipv6_handle = find_dissector_add_dependency("ipv6", proto_dvb_s2_bb);
    dvb_s2_table_handle = find_dissector("dvb-s2_table");
    eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
    data_handle = find_dissector("data");
    mp2t_handle = find_dissector_add_dependency("mp2t", proto_dvb_s2_bb);

    dissector_add_string("rtp_dyn_payload_type","DVB-S2", dvb_s2_modeadapt_handle);
    dissector_add_uint_range_with_preference("rtp.pt", "", dvb_s2_modeadapt_handle);
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
