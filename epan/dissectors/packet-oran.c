/* packet-oran.c
 * Routines for O-RAN fronthaul UC-plane dissection
 * Copyright 2020, Jan Schiefer, Keysight Technologies, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
   * Dissector for the O-RAN Fronthaul CUS protocol specification.
   * The current implementation is based on the
   * ORAN-WG4.CUS.0-v10.00 specification, dated 2022/07/23 (plus some enums from v13)
   *
   */
#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

/* TODO:
 * - sequence analysis based on sequence Id.  N.B. separate counts per antenna for spatial stream (eAxC Id), plane, direction
 * - tap stats by flow?
 * - for U-Plane, track back to last C-Plane frame for that eAxC
 *     - use upCompHdr values from C-Plane if not overridden by U-Plane?
 *     N.B. this matching is tricky see 7.8.1 Coupling of C-Plane and U-Plane
 * - Radio transport layer (eCPRI) fragmentation / reassembly
 * - Detect/indicate signs of application layer fragmentation?
 * - Not handling M-plane setting for "little endian byte order" as applied to IQ samples and beam weights
 * - Really long long text in some items will not be displayed.  Try to summarise/truncate
 * - Register for UDP port(s)
 * - for section extensions, check constraints (section type, which other extension types appear with them, order)
 * - when section extensions are present, some section header fields are effectively ignored
 * - re-order items (decl and hf definitions) to match spec order
 */

/* Prototypes */
void proto_reg_handoff_oran(void);
void proto_register_oran(void);

/* Initialize the protocol and registered fields */
static int proto_oran;

static int hf_oran_du_port_id;
static int hf_oran_bandsector_id;
static int hf_oran_cc_id;
static int hf_oran_ru_port_id;
static int hf_oran_sequence_id;
static int hf_oran_e_bit;
static int hf_oran_subsequence_id;

static int hf_oran_data_direction;
static int hf_oran_payload_version;
static int hf_oran_filter_index;
static int hf_oran_frame_id;
static int hf_oran_subframe_id;
static int hf_oran_slot_id;
static int hf_oran_slot_within_frame;
static int hf_oran_start_symbol_id;
static int hf_oran_numberOfSections;
static int hf_oran_sectionType;

static int hf_oran_udCompHdr;
static int hf_oran_udCompHdrIqWidth;
static int hf_oran_udCompHdrIqWidth_pref;
static int hf_oran_udCompHdrMeth;
static int hf_oran_udCompHdrMeth_pref;
static int hf_oran_numberOfUEs;
static int hf_oran_timeOffset;
static int hf_oran_frameStructure_fft;
static int hf_oran_frameStructure_subcarrier_spacing;
static int hf_oran_cpLength;
static int hf_oran_section_id;
static int hf_oran_rb;
static int hf_oran_symInc;
static int hf_oran_startPrbc;
static int hf_oran_reMask;
static int hf_oran_numPrbc;
static int hf_oran_numSymbol;
static int hf_oran_ef;
static int hf_oran_beamId;

static int hf_oran_ciCompHdr;
static int hf_oran_ciCompHdrIqWidth;
static int hf_oran_ciCompHdrMeth;
static int hf_oran_ciCompOpt;

static int hf_oran_extension;
static int hf_oran_exttype;
static int hf_oran_extlen;

static int hf_oran_bfw_bundle;
static int hf_oran_bfw_bundle_id;
static int hf_oran_bfw;
static int hf_oran_bfw_i;
static int hf_oran_bfw_q;

static int hf_oran_ueId;
static int hf_oran_freqOffset;
static int hf_oran_regularizationFactor;
static int hf_oran_laaMsgType;
static int hf_oran_laaMsgLen;
static int hf_oran_lbtHandle;
static int hf_oran_lbtDeferFactor;
static int hf_oran_lbtBackoffCounter;
static int hf_oran_lbtOffset;
static int hf_oran_MCOT;
static int hf_oran_lbtMode;
static int hf_oran_sfnSfEnd;
static int hf_oran_lbtPdschRes;
static int hf_oran_sfStatus;
static int hf_oran_initialPartialSF;
static int hf_oran_lbtDrsRes;
static int hf_oran_lbtBufErr;
static int hf_oran_lbtTrafficClass;
static int hf_oran_lbtCWConfig_H;
static int hf_oran_lbtCWConfig_T;
static int hf_oran_lbtCWR_Rst;

static int hf_oran_reserved;
static int hf_oran_reserved_1bit;
static int hf_oran_reserved_2bits;
static int hf_oran_reserved_4bits;
static int hf_oran_reserved_6bits;

static int hf_oran_ext11_reserved;

static int hf_oran_bfwCompHdr;
static int hf_oran_bfwCompHdr_iqWidth;
static int hf_oran_bfwCompHdr_compMeth;
static int hf_oran_symbolId;
static int hf_oran_startPrbu;
static int hf_oran_numPrbu;
/* static int hf_oran_udCompParam; */

static int hf_oran_bfwCompParam;

static int hf_oran_iSample;
static int hf_oran_qSample;

static int hf_oran_ciCompParam;

static int hf_oran_blockScaler;
static int hf_oran_compBitWidth;
static int hf_oran_compShift;

static int hf_oran_repetition;
static int hf_oran_rbgSize;
static int hf_oran_rbgMask;
static int hf_oran_noncontig_priority;
static int hf_oran_symbolMask;

static int hf_oran_rsvd8;
static int hf_oran_rsvd16;
static int hf_oran_exponent;
static int hf_oran_iq_user_data;

static int hf_oran_disable_bfws;
static int hf_oran_rad;
static int hf_oran_num_bund_prbs;
static int hf_oran_beam_id;
static int hf_oran_num_weights_per_bundle;

static int hf_oran_ack_nack_req_id;

static int hf_oran_off_start_prb_num_prb_pair;
static int hf_oran_off_start_prb;
static int hf_oran_num_prb;

static int hf_oran_samples_prb;
static int hf_oran_ciSample;
static int hf_oran_ciIsample;
static int hf_oran_ciQsample;

static int hf_oran_beamGroupType;
static int hf_oran_numPortc;

static int hf_oran_csf;
static int hf_oran_modcompscaler;

static int hf_oran_modcomp_param_set;
static int hf_oran_mc_scale_re_mask;
static int hf_oran_mc_scale_offset;

static int hf_oran_eAxC_mask;
static int hf_oran_technology;
static int hf_oran_nullLayerInd;

static int hf_oran_portReMask;
static int hf_oran_portSymbolMask;

static int hf_oran_ext19_port;

static int hf_oran_prb_allocation;
static int hf_oran_nextSymbolId;
static int hf_oran_nextStartPrbc;

static int hf_oran_puncPattern;
static int hf_oran_numPuncPatterns;
static int hf_oran_symbolMask_ext20;
static int hf_oran_startPuncPrb;
static int hf_oran_numPuncPrb;
static int hf_oran_puncReMask;
static int hf_oran_RbgIncl;

static int hf_oran_ci_prb_group_size;

static int hf_oran_num_ueid;

static int hf_oran_antMask;

static int hf_oran_transmissionWindowOffset;
static int hf_oran_transmissionWindowSize;
static int hf_oran_toT;

static int hf_oran_bfaCompHdr;
static int hf_oran_bfAzPtWidth;
static int hf_oran_bfZePtWidth;
static int hf_oran_bfAz3ddWidth;
static int hf_oran_bfZe3ddWidth;
static int hf_oran_bfAzPt;
static int hf_oran_bfZePt;
static int hf_oran_bfAz3dd;
static int hf_oran_bfZe3dd;
static int hf_oran_bfAzSl;
static int hf_oran_bfZeSl;


/* Computed fields */
static int hf_oran_c_eAxC_ID;
static int hf_oran_refa;

/* Initialize the subtree pointers */
static int ett_oran;
static int ett_oran_ecpri_rtcid;
static int ett_oran_ecpri_pcid;
static int ett_oran_ecpri_seqid;
static int ett_oran_section;
static int ett_oran_section_type;
static int ett_oran_u_timing;
static int ett_oran_u_section;
static int ett_oran_u_prb;
static int ett_oran_iq;
static int ett_oran_c_section_extension;
static int ett_oran_bfw_bundle;
static int ett_oran_bfw;
static int ett_oran_offset_start_prb_num_prb;
static int ett_oran_prb_cisamples;
static int ett_oran_cisample;
static int ett_oran_udcomphdr;
static int ett_oran_cicomphdr;
static int ett_oran_cicompparam;
static int ett_oran_bfwcomphdr;
static int ett_oran_bfwcompparam;
static int ett_oran_ext19_port;
static int ett_oran_prb_allocation;
static int ett_oran_punc_pattern;
static int ett_oran_bfacomphdr;
static int ett_oran_modcomp_param_set;


/* Expert info */
static expert_field ei_oran_unsupported_bfw_compression_method;
static expert_field ei_oran_invalid_sample_bit_width;
static expert_field ei_oran_reserved_numBundPrb;
static expert_field ei_oran_extlen_wrong;
static expert_field ei_oran_invalid_eaxc_bit_width;
static expert_field ei_oran_extlen_zero;
static expert_field ei_oran_rbg_size_reserved;
static expert_field ei_oran_frame_length;
static expert_field ei_oran_numprbc_ext21_zero;
static expert_field ei_oran_ci_prb_group_size_reserved;



/* These are the message types handled by this dissector */
#define ECPRI_MT_IQ_DATA            0
#define ECPRI_MT_RT_CTRL_DATA       2


/* Preference settings. */
static unsigned pref_du_port_id_bits = 2;
static unsigned pref_bandsector_id_bits = 6;
static unsigned pref_cc_id_bits = 4;
static unsigned pref_ru_port_id_bits = 4;

static unsigned pref_sample_bit_width_uplink = 14;
static unsigned pref_sample_bit_width_downlink = 14;

/* Compression schemes */
#define COMP_NONE                             0
#define COMP_BLOCK_FP                         1
#define COMP_BLOCK_SCALE                      2
#define COMP_U_LAW                            3
#define COMP_MODULATION                       4
#define BFP_AND_SELECTIVE_RE                  5
#define MOD_COMPR_AND_SELECTIVE_RE            6
#define BFP_AND_SELECTIVE_RE_WITH_MASKS       7
#define MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS 8

static int pref_iqCompressionUplink = COMP_BLOCK_FP;
static int pref_iqCompressionDownlink = COMP_BLOCK_FP;
static bool pref_includeUdCompHeaderUplink;
static bool pref_includeUdCompHeaderDownlink;

static unsigned pref_data_plane_section_total_rbs = 273;
static unsigned pref_num_weights_per_bundle = 32;
static unsigned pref_num_bf_antennas = 32;
static bool pref_showIQSampleValues = true;


static const enum_val_t compression_options[] = {
    { "COMP_NONE",                             "No Compression",                   COMP_NONE },
    { "COMP_BLOCK_FP",                         "Block Floating Point Compression", COMP_BLOCK_FP },
    { "COMP_BLOCK_SCALE",                      "Block Scaling Compression",        COMP_BLOCK_SCALE },
    { "COMP_U_LAW",                            "u-Law Compression",                COMP_U_LAW },
    { "COMP_MODULATION",                       "Modulation Compression",           COMP_MODULATION },
    { "BFP_AND_SELECTIVE_RE",                  "BFP + selective RE sending",       BFP_AND_SELECTIVE_RE },
    { "MOD_COMPR_AND_SELECTIVE_RE",            "mod-compr + selective RE sending", MOD_COMPR_AND_SELECTIVE_RE },
    { "BFP_AND_SELECTIVE_RE_WITH_MASKS",       "BFP + selective RE sending with masks in section header",       BFP_AND_SELECTIVE_RE_WITH_MASKS },
    { "MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS", "mod-compr + selective RE sending with masks in section header", MOD_COMPR_AND_SELECTIVE_RE },
    { NULL, NULL, 0 }
};

static const value_string e_bit[] = {
    { 0, "More fragments follow" },
    { 1, "Last fragment" },
    { 0, NULL}
};

#define DIR_UPLINK      0
#define DIR_DOWNLINK    1

static const value_string data_direction_vals[] = {
    { DIR_UPLINK,   "Uplink" },
    { DIR_DOWNLINK, "Downlink" },
    { 0, NULL}
};

static const value_string rb_vals[] = {
    { 0, "Every RB used" },
    { 1, "Every other RB used" },
    { 0, NULL}
};

static const value_string sym_inc_vals[] = {
    { 0, "Use the current symbol number" },
    { 1, "Increment the current symbol number" },
    { 0, NULL}
};

static const value_string lbtMode_vals[] = {
    { 0,  "Full LBT (regular LBT, sending reservation signal until the beginning of the SF/slot)" },
    { 1,  "Partial LBT (looking back 25 usec prior to transmission" },
    { 2,  "Partial LBT (looking back 34 usec prior to transmission" },
    { 3,  "Full LBT and stop (regular LBT, without sending reservation signal" },
    { 0, NULL}
};

static const range_string filter_indices[] = {
    {0, 0,  "standard channel filter"},
    {1, 1,  "UL filter for PRACH preamble formats 0, 1, 2; min. passband 839 x 1.25kHz = 1048.75 kHz"},
    {2, 2,  "UL filter for PRACH preamble format 3, min. passband 839 x 5 kHz = 4195 kHz"},
    {3, 3,  "UL filter for PRACH preamble formats A1, A2, A3, B1, B2, B3, B4, C0, C2; min. passband 139 x \u0394fRA"},
    {4, 4,  "UL filter for NPRACH 0, 1; min. passband 48 x 3.75KHz = 180 KHz"},
    {5, 5,  "UL filter for PRACH preamble formats"},
    {8, 8,  "UL filter NPUSCH"},
    {9, 15, "Reserved"},
    {0, 0, NULL}
};

/* Section types from Table 7.3.1-1 */
enum section_c_types {
    SEC_C_UNUSED_RB = 0,
    SEC_C_NORMAL = 1,
    SEC_C_RSVD2 = 2,
    SEC_C_PRACH = 3,
    SEC_C_RSVD4 = 4,
    SEC_C_UE_SCHED = 5,
    SEC_C_CH_INFO = 6,
    SEC_C_LAA = 7,
    SEC_C_ACK_NACK_FEEDBACK = 8
};

static const range_string section_types[] = {
    { SEC_C_UNUSED_RB,         SEC_C_UNUSED_RB,         "Unused Resource Blocks or symbols in Downlink or Uplink" },
    { SEC_C_NORMAL,            SEC_C_NORMAL,            "Most DL/UL radio channels" },
    { SEC_C_RSVD2,             SEC_C_RSVD2,             "Reserved for future use" },
    { SEC_C_PRACH,             SEC_C_PRACH,             "PRACH and mixed-numerology channels" },
    { SEC_C_RSVD4,             SEC_C_RSVD4,             "Reserved for future use" },
    { SEC_C_UE_SCHED,          SEC_C_UE_SCHED,          "UE scheduling information (UE-ID assignment to section)" },
    { SEC_C_CH_INFO,           SEC_C_CH_INFO,           "Channel information" },
    { SEC_C_LAA,               SEC_C_LAA,               "LAA" },
    { SEC_C_ACK_NACK_FEEDBACK, SEC_C_ACK_NACK_FEEDBACK, "ACK/NACK Feedback" },
    { 9,                       255,                     "Reserved for future use" },
    { 0, 0, NULL} };

static const range_string section_types_short[] = {
    { SEC_C_UNUSED_RB,         SEC_C_UNUSED_RB,         "(Unused RBs)" },
    { SEC_C_NORMAL,            SEC_C_NORMAL,            "(Most channels)" },
    { SEC_C_RSVD2,             SEC_C_RSVD2,             "(reserved)" },
    { SEC_C_PRACH,             SEC_C_PRACH,             "(PRACH/mixed-\u03bc)" },
    { SEC_C_RSVD4,             SEC_C_RSVD4,             "(reserved)" },
    { SEC_C_UE_SCHED,          SEC_C_UE_SCHED,          "(UE scheduling info)" },
    { SEC_C_CH_INFO,           SEC_C_CH_INFO,           "(Channel info)" },
    { SEC_C_LAA,               SEC_C_LAA,               "(LAA)" },
    { SEC_C_ACK_NACK_FEEDBACK, SEC_C_ACK_NACK_FEEDBACK, "(ACK/NACK)" },
    { 9,                       255,                     "Reserved for future use" },
    { 0, 0, NULL }
};

static const range_string ud_comp_header_width[] = {
    {0, 0,  "I and Q are each 16 bits wide"},
    {1, 15, "Bit width of I and Q"},
    {0, 0, NULL} };

/* Table 8.3.3.13-3 */
static const range_string ud_comp_header_meth[] = {
    {COMP_NONE,                             COMP_NONE,                             "No compression" },
    {COMP_BLOCK_FP,                         COMP_BLOCK_FP,                         "Block floating point compression" },
    {COMP_BLOCK_SCALE,                      COMP_BLOCK_SCALE,                      "Block scaling" },
    {COMP_U_LAW,                            COMP_U_LAW,                            "Mu - law" },
    {COMP_MODULATION,                       COMP_MODULATION,                       "Modulation compression" },
    {BFP_AND_SELECTIVE_RE,                  BFP_AND_SELECTIVE_RE,                  "BFP + selective RE sending" },
    {MOD_COMPR_AND_SELECTIVE_RE,            MOD_COMPR_AND_SELECTIVE_RE,            "mod-compr + selective RE sending" },
    {BFP_AND_SELECTIVE_RE_WITH_MASKS,       BFP_AND_SELECTIVE_RE_WITH_MASKS,       "BFP + selective RE sending with masks in section header" },
    {MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS, MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS, "mod-compr + selective RE sending with masks in section header"},
    {9, 15, "Reserved"},
    {0, 0, NULL}
};

/* Table 7.5.2.13-2 */
static const range_string frame_structure_fft[] = {
    {0,  0,  "Reserved (no FFT / iFFT processing)"},
    {1,  3,  "Reserved"},
    {4,  4,  "FFT size 16"},
    {5,  5,  "FFT size 32"},
    {6,  6,  "FFT size 64"},
    {7,  7,  "FFT size 128"},
    {8,  8,  "FFT size 256"},
    {9,  9,  "FFT size 512"},
    {10, 10, "FFT size 1024"},
    {11, 11, "FFT size 2048"},
    {12, 12, "FFT size 4096"},
    {13, 13, "FFT size 1536"},
    {14, 14, "FFT size 3072"},
    {15, 15, "Reserved"},
    {0, 0, NULL}
};

/* Table 7.5.2.13-3 */
static const range_string subcarrier_spacings[] = {
    { 0,  0,  "SCS 15 kHz, 1 slot/subframe, slot length 1 ms" },
    { 1,  1,  "SCS 30 kHz, 2 slots/subframe, slot length 500 \u03bcs" },
    { 2,  2,  "SCS 60 kHz, 4 slots/subframe, slot length 250 \u03bcs" },
    { 3,  3,  "SCS 120 kHz, 8 slots/subframe, slot length 125 \u03bcs" },
    { 4,  4,  "SCS 240 kHz, 16 slots/subframe, slot length 62.5 \u03bcs" },
    { 5,  5,  "SCS 480 kHz, 32 slots/subframe, slot length 31.25 \u03bcs" }, /* TODO: not in v13.0 */
    { 6,  11, "Reserved" },
    { 12, 12, "SCS 1.25 kHz, 1 slot/subframe, slot length 1 ms" },
    { 13, 13, "SCS 3.75 kHz(LTE - specific), 1 slot/subframe, slot length 1 ms" },
    { 14, 14, "SCS 5 kHz, 1 slot/subframe, slot length 1 ms" },
    { 15, 15, "SCS 7.5 kHz(LTE - specific), 1 slot/subframe, slot length 1 ms" },
    { 0, 0, NULL }
};

static const range_string laaMsgTypes[] = {
    {0, 0,  "LBT_PDSCH_REQ - lls - O-DU to O-RU request to obtain a PDSCH channel"},
    {1, 1,  "LBT_DRS_REQ - lls - O-DU to O-RU request to obtain the channel and send DRS"},
    {2, 2,  "LBT_PDSCH_RSP - O-RU to O-DU response, channel acq success or failure"},
    {3, 3,  "LBT_DRS_RSP - O-RU to O-DU response, DRS sending success or failure"},
    {4, 4,  "LBT_Buffer_Error - O-RU to O-DU response, reporting buffer overflow"},
    {5, 5,  "LBT_CWCONFIG_REQ - O-DU to O-RU request, congestion window configuration"},
    {6, 6,  "LBT_CWCONFIG_REQ - O-RU to O-DU request, congestion window config"},
    {8, 15, "reserved for future methods"},
    {0, 0, NULL}
};

/* Table 7.6.1-1 */
static const value_string exttype_vals[] = {
    {0,     "Reserved"},
    {1,     "Beamforming weights"},
    {2,     "Beamforming attributes"},
    {3,     "DL Precoding configuration parameters and indications"},
    {4,     "Modulation compr. params"},
    {5,     "Modulation compression additional scaling parameters"},
    {6,     "Non-contiguous PRB allocation"},
    {7,     "Multiple-eAxC designation"},
    {8,     "Regularization factor"},
    {9,     "Dynamic Spectrum Sharing parameters"},
    {10,    "Multiple ports grouping"},
    {11,    "Flexible BF weights"},
    {12,    "Non-Contiguous PRB Allocation with Frequency Ranges"},
    {13,    "PRB Allocation with Frequency Hopping"},
    {14,    "Nulling-layer Info. for ueId-based beamforming"},
    {15,    "Mixed-numerology Info. for ueId-based beamforming"},
    {16,    "Section description for antenna mapping in UE channel information based UL beamforming"},
    {17,    "Section description for indication of user port group"},
    {18,    "Section description for Uplink Transmission Management"},
    {19,    "Compact beamforming information for multiple port"},
    {20,    "Puncturing extension"},
    {21,    "Variable PRB group size for channel information"},
    {22,    "ACK/NACK request"},
    {23,    "Multiple symbol modulation compression parameters"},
    {0, NULL}
};

static const value_string bfw_comp_headers_iq_width[] = {
    {0,     "I and Q are 16 bits wide"},
    {1,     "I and Q are 1 bit wide"},
    {2,     "I and Q are 2 bits wide"},
    {3,     "I and Q are 3 bits wide"},
    {4,     "I and Q are 4 bits wide"},
    {5,     "I and Q are 5 bits wide"},
    {6,     "I and Q are 6 bits wide"},
    {7,     "I and Q are 7 bits wide"},
    {8,     "I and Q are 8 bits wide"},
    {9,     "I and Q are 9 bits wide"},
    {10,    "I and Q are 10 bits wide"},
    {11,    "I and Q are 11 bits wide"},
    {12,    "I and Q are 12 bits wide"},
    {13,    "I and Q are 13 bits wide"},
    {14,    "I and Q are 14 bits wide"},
    {15,    "I and Q are 15 bits wide"},
    {0, NULL}
};

/* Table 7.7.1.2-3 */
static const value_string bfw_comp_headers_comp_meth[] = {
    {COMP_NONE,         "no compression"},
    {COMP_BLOCK_FP,     "block floating point"},
    {COMP_BLOCK_SCALE,  "block scaling"},
    {COMP_U_LAW,        "u-law"},
    {4,                 "beamspace compression type I"},
    {5,                 "beamspace compression type II"},
    {0, NULL}
};

/* 7.7.6.2 */
static const value_string rbg_size_vals[] = {
    {0,     "reserved"},
    {1,     "1"},
    {2,     "2"},
    {3,     "3"},
    {4,     "4"},
    {5,     "6"},
    {6,     "8"},
    {7,     "16"},
    {0, NULL}
};

/* 7.7.6.5 */
static const value_string priority_vals[] = {
    {0,     "0"},
    {1,     "+1"},
    {2,     "-2 (reserved, should not be used)"},
    {3,     "-1"},
    {0, NULL}
};

/* 7.7.10.2  beamGroupType */
static const value_string beam_group_type_vals[] = {
    {0x0, "common beam"},
    {0x1, "beam matrix indication"},
    {0x2, "beam vector listing"},
    {0x3, "reserved"},
    {0, NULL}
};

/* 7.7.9.2 technology (interface name) */
static const value_string interface_name_vals[] = {
    {0x0, "LTE"},
    {0x1, "NR"},
    {0, NULL}
};

/* 7.7.18.4 toT (type of transmission) */
static const value_string type_of_transmission_vals[] = {
    {0x0, "normal transmission mode, data can be distributed in any way the O-RU is implemented to transmit data"},
    {0x1, "uniformly distributed over the transmission window"},
    {0x2, "Reserved"},
    {0x3, "Reserved"},
    {0, NULL}
};

/* 7.7.2.2 (width of bfa parameters) */
static const value_string bfa_bw_vals[] = {
    {0,   "no bits, the field is not applicable (e.g., O-RU does not support it) or the default value shall be used"},
    {1,   "2-bit bitwidth"},
    {2,   "3-bit bitwidth"},
    {3,   "4-bit bitwidth"},
    {4,   "5-bit bitwidth"},
    {5,   "6-bit bitwidth"},
    {6,   "7-bit bitwidth"},
    {7,   "8-bit bitwidth"},
    {0,   NULL}
};

/* 7.7.2.7 & 7.7.2.8 */
static const value_string sidelobe_suppression_vals[] = {
    {0,   "10 dB"},
    {1,   "15 dB"},
    {2,   "20 dB"},
    {3,   "25 dB"},
    {4,   "30 dB"},
    {5,   "35 dB"},
    {6,   "40 dB"},
    {7,   ">= 45 dB"},
    {0,   NULL}
};

static const value_string lbtTrafficClass_vals[] = {
    {1,   "Priority 1"},
    {2,   "Priority 2"},
    {3,   "Priority 3"},
    {4,   "Priority 4"},
    {0,   NULL}
};

static const value_string lbtPdschRes_vals[] = {
    {0, "not sensing – indicates that the O-RU is transmitting data"},
    {1, "currently sensing – indicates the O-RU has not yet acquired the channel"},
    {2, "success – indicates that the channel was successfully acquired"},
    {3, "Failure – indicates expiration of the LBT timer. The LBT process should be reset"},
    {0,   NULL}
};

static const value_string ci_comp_opt_vals[] = {
    {0, "compression per UE, one ciCompParam exists before the I/Q value of each UE"},
    {1, "compression per PRB, one ciCompParam exists before the I/Q value of each PRB"},
    {0,   NULL}
};


static const true_false_string tfs_sfStatus =
{
    "subframe was transmitted",
    "subframe was dropped"
};

static const true_false_string tfs_lbtBufErr =
{
    "buffer overflow – data received at O-RU is larger than the available buffer size",
    "reserved"
};

static const true_false_string tfs_partial_full_sf = {
  "partial SF",
  "full SF"
};

/* Config for (and later, worked-out allocations) bundles for ext11 (dynamic BFW) */
typedef struct {
    /* Ext 6 config */
    bool     ext6_set;
    uint8_t  ext6_rbg_size;      /* number of PRBs allocated by bitmask */

    uint8_t  ext6_num_bits_set;
    uint8_t  ext6_bits_set[28];  /* Which bit position this entry has */

    /* Ext 12 config */
    bool     ext12_set;
    unsigned ext12_num_pairs;
#define MAX_BFW_EXT12_PAIRS 128
    struct {
        uint8_t off_start_prb;
        uint8_t num_prb;
    } ext12_pairs[MAX_BFW_EXT12_PAIRS];

    /* Ext 13 config */
    bool     ext13_set;
    unsigned ext13_num_start_prbs;
#define MAX_BFW_EXT13_ALLOCATIONS 128
    unsigned ext13_start_prbs[MAX_BFW_EXT13_ALLOCATIONS];
    /* TODO: store nextSymbolId here too? */

    /* Ext 21 config */
    bool     ext21_set;
    uint8_t  ext21_ci_prb_group_size;

    /* Results (after calling ext11_work_out_bundles()) */
    uint32_t num_bundles;
#define MAX_BFW_BUNDLES 512
    struct {
        uint32_t start;      /* first prb of bundle */
        uint32_t end;        /* last prb of bundle*/
        bool     is_orphan;  /* true if not complete (i.e., < numBundPrb) */
    } bundles[MAX_BFW_BUNDLES];
} ext11_settings_t;


/* Work out bundle allocation for ext 11.  Take into account ext6/ext21, ext12 or ext13 in this section before ext 11. */
/* Won't be called with numBundPrb=0 */
static void ext11_work_out_bundles(unsigned startPrbc,
                                   unsigned numPrbc,
                                   unsigned numBundPrb,             /* number of PRBs pre (full) bundle */
                                   ext11_settings_t *settings)
{
    /* Allocation configured by ext 6 */
    if (settings->ext6_set) {
        unsigned bundles_per_entry = (settings->ext6_rbg_size / numBundPrb);

        /* Maybe also be affected by ext 21 */
        if (settings->ext21_set) {
            /* N.B., have already checked that numPrbc is not 0 */

            /* ciPrbGroupSize overrides number of contiguous PRBs in group */
            bundles_per_entry = (settings->ext6_rbg_size / settings->ext21_ci_prb_group_size);

            /* numPrbc is the number of PRB groups per antenna - handled in call to dissect_bfw_bundle() */
        }

        unsigned bundles_set = 0;
        for (uint8_t n=0; n < settings->ext6_num_bits_set; n++) {
            /* For each bit set in the mask */
            uint32_t prb_start = (settings->ext6_bits_set[n] * settings->ext6_rbg_size);

            /* For each bundle within identified rbgSize block */
            for (unsigned m=0; m < bundles_per_entry; m++) {
                settings->bundles[bundles_set].start = startPrbc+prb_start+(m*numBundPrb);
                /* Start already beyond end, so doesn't count. */
                if (settings->bundles[bundles_set].start > (startPrbc+numPrbc-1)) {
                    break;
                }
                /* Bundle consists of numBundPrb bundles */
                settings->bundles[bundles_set].end = startPrbc+prb_start+((m+1)*numBundPrb)-1;
                if (settings->bundles[bundles_set].end > (startPrbc+numPrbc-1)) {
                    /* Extends beyond end, so counts but is an orphan bundle */
                    settings->bundles[bundles_set].end = numPrbc;
                    settings->bundles[bundles_set].is_orphan = true;
                }

                /* Get out if have reached array bound */
                if (++bundles_set == MAX_BFW_BUNDLES) {
                    return;
                }
            }
        }
        settings->num_bundles = bundles_set;
    }

    /* Allocation configured by ext 12 */
    else if (settings->ext12_set) {
        /* First, allocate normally from startPrbc, numPrbc */
        settings->num_bundles = (numPrbc+numBundPrb-1) / numBundPrb;

        /* Don't overflow settings->bundles[] ! */
        settings->num_bundles = MIN(MAX_BFW_BUNDLES, settings->num_bundles);

        for (uint32_t n=0; n < settings->num_bundles; n++) {
            settings->bundles[n].start = startPrbc + n*numBundPrb;
            settings->bundles[n].end =   settings->bundles[n].start + numBundPrb-1;
            /* Does it go beyond the end? */
            if (settings->bundles[n].end > startPrbc+numPrbc) {
                settings->bundles[n].end = numPrbc+numPrbc;
                settings->bundles[n].is_orphan = true;
            }
        }
        if (settings->num_bundles == MAX_BFW_BUNDLES) {
            return;
        }

        unsigned prb_offset = startPrbc + numPrbc;

        /* Loop over pairs, adding bundles for each */
        for (unsigned p=0; p < settings->ext12_num_pairs; p++) {
            prb_offset += settings->ext12_pairs[p].off_start_prb;
            unsigned pair_bundles = (settings->ext12_pairs[p].num_prb+numBundPrb-1) / numBundPrb;

            for (uint32_t n=0; n < pair_bundles; n++) {
                unsigned idx = settings->num_bundles;

                settings->bundles[idx].start = prb_offset + n*numBundPrb;
                settings->bundles[idx].end =   settings->bundles[idx].start + numBundPrb-1;
                /* Does it go beyond the end? */
                if (settings->bundles[idx].end > prb_offset + settings->ext12_pairs[p].num_prb) {
                    settings->bundles[idx].end = prb_offset + settings->ext12_pairs[p].num_prb;
                    settings->bundles[idx].is_orphan = true;
                }
                /* Range check / return */
                settings->num_bundles++;
                if (settings->num_bundles == MAX_BFW_BUNDLES) {
                    return;
                }
            }

            prb_offset += settings->ext12_pairs[p].num_prb;
        }
    }

    /* Allocation configured by ext 13 */
    else if (settings->ext13_set) {
        unsigned alloc_size = (numPrbc+numBundPrb-1) / numBundPrb;
        settings->num_bundles = alloc_size * settings->ext13_num_start_prbs;

        /* Don't overflow settings->bundles[] ! */
        settings->num_bundles = MIN(MAX_BFW_BUNDLES, settings->num_bundles);

        for (unsigned alloc=0; alloc < settings->ext13_num_start_prbs; alloc++) {
            unsigned alloc_start = alloc * alloc_size;
            for (uint32_t n=0; n < alloc_size; n++) {
                if ((alloc_start+n) >= MAX_BFW_BUNDLES) {
                    /* ERROR */
                    return;
                }
                settings->bundles[alloc_start+n].start = settings->ext13_start_prbs[alloc] + startPrbc + n*numBundPrb;
                settings->bundles[alloc_start+n].end =   settings->bundles[alloc_start+n].start + numBundPrb-1;
                if (settings->bundles[alloc_start+n].end > settings->ext13_start_prbs[alloc] + numPrbc) {
                    settings->bundles[alloc_start+n].end = settings->ext13_start_prbs[alloc] + numPrbc;
                    settings->bundles[alloc_start+n].is_orphan = true;
                }
            }
        }
    }

    /* Bundles not controlled by other extensions - just divide up range into bundles we have */
    else {
        settings->num_bundles = (numPrbc+numBundPrb-1) / numBundPrb;

        /* Don't overflow settings->bundles[] ! */
        settings->num_bundles = MIN(MAX_BFW_BUNDLES, settings->num_bundles);

        for (uint32_t n=0; n < settings->num_bundles; n++) {
            settings->bundles[n].start = startPrbc + n*numBundPrb;
            settings->bundles[n].end =   settings->bundles[n].start + numBundPrb-1;
            /* Does it go beyond the end? */
            if (settings->bundles[n].end > startPrbc+numPrbc) {
                settings->bundles[n].end = numPrbc+numPrbc;
                settings->bundles[n].is_orphan = true;
            }
        }
    }
}



/*******************************************************/
/* Overall state of a flow (eAxC)                      */
typedef struct {
    uint32_t last_cplane_frame;
    nstime_t last_cplane_frame_ts;
    /* TODO: add udCompHdr info for subsequence U-Plane frames? */

    /* First U-PLane frame following 'last_cplane' frame */
    uint32_t first_uplane_frame;
    nstime_t first_uplane_frame_ts;
} flow_state_t;

/* Table maintained on first pass from eAxC (uint16_t) -> flow_state_t* */
static wmem_tree_t *flow_states_table;



static void write_pdu_label_and_info(proto_item *ti1, proto_item *ti2,
    packet_info *pinfo, const char *format, ...) G_GNUC_PRINTF(4, 5);

 /* Write the given formatted text to:
    - the info column (if pinfo != NULL)
    - 1 or 2 other labels (optional)
 */
static void write_pdu_label_and_info(proto_item *ti1, proto_item *ti2,
    packet_info *pinfo, const char *format, ...)
{
#define MAX_INFO_BUFFER 256
    char info_buffer[MAX_INFO_BUFFER];
    va_list ap;

    if ((ti1 == NULL) && (ti2 == NULL) && (pinfo == NULL)) {
        return;
    }

    va_start(ap, format);
    vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    if (pinfo != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    }
    if (ti1 != NULL) {
        proto_item_append_text(ti1, "%s", info_buffer);
    }
    if (ti2 != NULL) {
        proto_item_append_text(ti2, "%s", info_buffer);
    }
}

/* Add section (type + PRB range) for C-Plane, U-Plane */
static void
write_section_info(proto_item *section_heading, packet_info *pinfo, proto_item *protocol_item,
                   uint32_t section_id, uint32_t start_prbx, uint32_t num_prbx, uint32_t rb)
{
    switch (num_prbx) {
    case 0:
        write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %d (all PRBs)", section_id);
        break;
    case 1:
        write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %d (PRB: %3u)", section_id, start_prbx);
        break;
    default:
        write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %d (PRB: %3u-%3u%s)", section_id, start_prbx,
                                 start_prbx + (num_prbx-1)*(1+rb), rb ? " (every-other)" : "");
    }
}

/* 5.1.3.2.7 (real time control data / IQ data transfer message series identifier */
static void
addPcOrRtcid(tvbuff_t *tvb, proto_tree *tree, int *offset, const char *name, uint16_t *eAxC)
{
    /* Subtree */
    proto_item *item;
    proto_tree *oran_pcid_tree = proto_tree_add_subtree(tree, tvb, *offset, 2, ett_oran_ecpri_pcid, &item, name);
    uint64_t duPortId, bandSectorId, ccId, ruPortId = 0;
    int id_offset = *offset;

    /* All parts of eAxC should be above 0, and should total 16 bits (breakdown controlled by preferences) */
    if (!((pref_du_port_id_bits > 0) && (pref_bandsector_id_bits > 0) && (pref_cc_id_bits > 0) && (pref_ru_port_id_bits > 0) &&
         ((pref_du_port_id_bits + pref_bandsector_id_bits + pref_cc_id_bits + pref_ru_port_id_bits) == 16))) {
        expert_add_info(NULL, tree, &ei_oran_invalid_eaxc_bit_width);
        *offset += 2;
        return;
    }

    unsigned bit_offset = *offset * 8;

    /* N.B. For sequence analysis / tapping, just interpret these 2 bytes as eAxC ID... */
    *eAxC = tvb_get_uint16(tvb, *offset, ENC_BIG_ENDIAN);

    /* DU Port ID */
    proto_tree_add_bits_ret_val(oran_pcid_tree, hf_oran_du_port_id, tvb, bit_offset, pref_du_port_id_bits, &duPortId, ENC_BIG_ENDIAN);
    bit_offset += pref_du_port_id_bits;
    /* BandSector ID */
    proto_tree_add_bits_ret_val(oran_pcid_tree, hf_oran_bandsector_id, tvb, bit_offset, pref_bandsector_id_bits, &bandSectorId, ENC_BIG_ENDIAN);
    bit_offset += pref_bandsector_id_bits;
    /* CC ID */
    proto_tree_add_bits_ret_val(oran_pcid_tree, hf_oran_cc_id, tvb, bit_offset, pref_cc_id_bits, &ccId, ENC_BIG_ENDIAN);
    bit_offset += pref_cc_id_bits;
    /* RU Port ID */
    proto_tree_add_bits_ret_val(oran_pcid_tree, hf_oran_ru_port_id, tvb, bit_offset, pref_ru_port_id_bits, &ruPortId, ENC_BIG_ENDIAN);
    *offset += 2;

    proto_item_append_text(item, " (DU_Port_ID: %d, BandSector_ID: %d, CC_ID: %d, RU_Port_ID: %d)", (int)duPortId, (int)bandSectorId, (int)ccId, (int)ruPortId);
    char id[16];
    snprintf(id, 16, "%x:%x:%x:%x", (int)duPortId, (int)bandSectorId, (int)ccId, (int)ruPortId);
    proto_item *pi = proto_tree_add_string(oran_pcid_tree, hf_oran_c_eAxC_ID, tvb, id_offset, 2, id);
    proto_item_set_generated(pi);
}

/* 5.1.3.2.8 (message identifier) */
static void
addSeqid(tvbuff_t *tvb, proto_tree *oran_tree, int *offset)
{
    /* Subtree */
    proto_item *seqIdItem;
    proto_tree *oran_seqid_tree = proto_tree_add_subtree(oran_tree, tvb, *offset, 2, ett_oran_ecpri_seqid, &seqIdItem, "ecpriSeqid");
    uint32_t seqId, subSeqId, e = 0;
    /* Sequence ID */
    proto_tree_add_item_ret_uint(oran_seqid_tree, hf_oran_sequence_id, tvb, *offset, 1, ENC_NA, &seqId);
    *offset += 1;
    /* E bit */
    proto_tree_add_item_ret_uint(oran_seqid_tree, hf_oran_e_bit, tvb, *offset, 1, ENC_NA, &e);
    /* Subsequence ID */
    proto_tree_add_item_ret_uint(oran_seqid_tree, hf_oran_subsequence_id, tvb, *offset, 1, ENC_NA, &subSeqId);
    *offset += 1;
    proto_item_append_text(seqIdItem, ", SeqId: %d, SubSeqId: %d, E: %d", seqId, subSeqId, e);
}

/* Special case for uncompressed/16-bit value */
static float uncompressed_to_float(uint32_t h)
{
    int16_t i16 = h & 0x0000ffff;
    return ((float)i16) / 0x7fff;
}

/* 7.7.1.2 bfwCompHdr (beamforming weight compression header) */
static int dissect_bfwCompHdr(tvbuff_t *tvb, proto_tree *tree, int offset,
                              uint32_t *iq_width, uint32_t *comp_meth, proto_item **comp_meth_ti)
{
    /* Subtree */
    proto_item *bfwcomphdr_ti = proto_tree_add_string_format(tree, hf_oran_bfwCompHdr,
                                                            tvb, offset, 1, "",
                                                            "bfwCompHdr");
    proto_tree *bfwcomphdr_tree = proto_item_add_subtree(bfwcomphdr_ti, ett_oran_bfwcomphdr);

    /* Width and method */
    proto_tree_add_item_ret_uint(bfwcomphdr_tree, hf_oran_bfwCompHdr_iqWidth,
                                 tvb, offset, 1, ENC_BIG_ENDIAN,  iq_width);
    *comp_meth_ti = proto_tree_add_item_ret_uint(bfwcomphdr_tree, hf_oran_bfwCompHdr_compMeth,
                                                 tvb, offset, 1, ENC_BIG_ENDIAN, comp_meth);
    offset++;

    /* Summary */
    proto_item_append_text(bfwcomphdr_ti, " (IqWidth=%u, compMeth=%s)",
                           *iq_width,
                           val_to_str_const(*comp_meth, bfw_comp_headers_comp_meth, "reserved"));

    return offset;
}

/* 7.7.1.3 bfwCompParam (beamforming weight compression parameter).
 * Depends upon passed-in bfwCompMeth (field may be empty) */
static int dissect_bfwCompParam(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset,
                                proto_item *ti, uint32_t bfw_comp_method,
                                uint32_t *exponent, bool *supported)
{
    /* Subtree */
    proto_item *bfwcompparam_ti = proto_tree_add_string_format(tree, hf_oran_bfwCompParam,
                                                               tvb, offset, 1, "",
                                                              "bfwCompParam");
    proto_tree *bfwcompparam_tree = proto_item_add_subtree(bfwcompparam_ti, ett_oran_bfwcompparam);

    proto_item_append_text(bfwcompparam_ti,
                           " (meth=%s)", val_to_str_const(bfw_comp_method, bfw_comp_headers_comp_meth, "reserved"));


    *supported = false;
    switch (bfw_comp_method) {
        case COMP_NONE:         /* no compression */
            /* In this case, bfwCompParam is absent! */
            *supported = true;
            break;
        case COMP_BLOCK_FP:     /* block floating point */
            /* 4 reserved bits +  exponent */
            proto_tree_add_item_ret_uint(bfwcompparam_tree, hf_oran_exponent,
                                         tvb, offset, 1, ENC_BIG_ENDIAN, exponent);
            proto_item_append_text(bfwcompparam_ti, " exponent=%u", *exponent);
            *supported = true;
            offset++;
            break;
        case COMP_BLOCK_SCALE:  /* block scaling */
            proto_tree_add_item(bfwcompparam_tree, hf_oran_blockScaler,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case COMP_U_LAW:        /* u-law */
            /* compBitWidth, compShift */
            proto_tree_add_item(bfwcompparam_tree, hf_oran_compBitWidth,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bfwcompparam_tree, hf_oran_compShift,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case 4:                 /* beamspace I */
            /* TODO: activeBeamspaceCoefficientMask - ceil(K/8) octets */
            /* proto_tree_add_item(extension_tree, hf_oran_blockScaler,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++; */
            break;
        case 5:                 /* beamspace II */
            /* TODO: activeBeamspaceCoefficientMask - ceil(K/8) octets */
            /* reserved (4 bits) + exponent (4 bits)
            proto_tree_add_item(bfwcompparam_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(bfwcompparam_tree, hf_oran_exponent, tvb, offset, 1, ENC_BIG_ENDIAN, exponent);
            offset += 1;
            */
            break;

        default:
            /* Not handled */
             break;
    }

    /* Can't go on if compression scheme not supported */
    if (!*supported) {
        expert_add_info_format(pinfo, ti, &ei_oran_unsupported_bfw_compression_method,
                               "BFW Compression method %u (%s) not supported by dissector",
                               bfw_comp_method,
                               val_to_str_const(bfw_comp_method, bfw_comp_headers_comp_meth, "reserved"));
    }
    return offset;
}


static float decompress_value(uint32_t bits, uint32_t comp_method, uint8_t iq_width, uint32_t exponent)
{
    switch (comp_method) {
        case COMP_NONE: /* no compression */
            return uncompressed_to_float(bits);

        case COMP_BLOCK_FP: /* block floating point */
        {
            /* A.1.2 Block Floating Point Decompression Algorithm */
            int32_t cPRB = bits;
            uint32_t scaler = 1 << exponent;  /* i.e. 2^exponent */

            /* Check last bit, in case we need to flip to -ve */
            if (cPRB >= (1<<(iq_width-1))) {
                cPRB -= (1<<iq_width);
            }

            const uint8_t mantissa_bits = iq_width-1;
            return (cPRB / (float)(1 << (mantissa_bits))) * scaler;
        }

        case COMP_BLOCK_SCALE:
        case COMP_U_LAW:
        case COMP_MODULATION:
        case BFP_AND_SELECTIVE_RE:
        case MOD_COMPR_AND_SELECTIVE_RE:
        default:
            /* TODO: Not supported! */
            return 0.0;
    }
}

/* Out-of-range value used for special case */
#define ORPHAN_BUNDLE_NUMBER 999

/* Bundle of PRBs/TRX I/Q samples (ext 11) */
static uint32_t dissect_bfw_bundle(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, unsigned offset,
                                  proto_item *comp_meth_ti, uint32_t bfwcomphdr_comp_meth,
                                  uint32_t num_weights_per_bundle,
                                  uint8_t iq_width,
                                  unsigned bundle_number,
                                  unsigned first_prb, unsigned last_prb, bool is_orphan)
{
    /* Set bundle name */
    char bundle_name[32];
    if (!is_orphan) {
        snprintf(bundle_name, 32, "Bundle %3u", bundle_number);
    }
    else {
        g_strlcpy(bundle_name, "Orphaned  ", 32);
    }

    /* Create Bundle root */
    proto_item *bundle_ti;
    if (first_prb != last_prb) {
        bundle_ti = proto_tree_add_string_format(tree, hf_oran_bfw_bundle,
                                                 tvb, offset, 0, "",
                                                 "%s: (PRBs %3u-%3u)",
                                                 bundle_name,
                                                 first_prb, last_prb);
    }
    else {
        bundle_ti = proto_tree_add_string_format(tree, hf_oran_bfw_bundle,
                                                 tvb, offset, 0, "",
                                                 "%s: (PRB %3u)",
                                                 bundle_name,
                                                 first_prb);
    }
    proto_tree *bundle_tree = proto_item_add_subtree(bundle_ti, ett_oran_bfw_bundle);

    /* Generated bundle id */
    proto_item *bundleid_ti = proto_tree_add_uint(bundle_tree, hf_oran_bfw_bundle_id, tvb, 0, 0,
                                                  bundle_number);
    proto_item_set_generated(bundleid_ti);
    proto_item_set_hidden(bundleid_ti);

    /* bfwCompParam */
    bool compression_method_supported = false;
    unsigned exponent;
    offset = dissect_bfwCompParam(tvb, bundle_tree, pinfo, offset, comp_meth_ti,
                                  bfwcomphdr_comp_meth, &exponent, &compression_method_supported);

    /* Can't show details of unsupported compression method */
    if (!compression_method_supported) {
        /* Don't know how to show, so give up */
        return offset;
    }

    /* Create Bundle subtree */
    int bit_offset = offset*8;
    int bfw_offset;
    int prb_offset = offset;

    /* beamId */
    uint32_t beam_id;
    proto_tree_add_item_ret_uint(bundle_tree, hf_oran_beam_id, tvb, offset, 2, ENC_BIG_ENDIAN, &beam_id);
    proto_item_append_text(bundle_ti, " (beamId:%u) ", beam_id);
    bit_offset += 16;

    /* Number of weights per bundle (from preference) */
    proto_item *wpb_ti = proto_tree_add_uint(bundle_tree, hf_oran_num_weights_per_bundle, tvb, 0, 0,
                                             num_weights_per_bundle);
    proto_item_set_generated(wpb_ti);

    /* Add the weights for this bundle */
    for (unsigned m=0; m < num_weights_per_bundle; m++) {

        /* Create subtree */
        bfw_offset = bit_offset / 8;
        uint8_t bfw_extent = ((bit_offset + (iq_width*2)) / 8) - bfw_offset;
        proto_item *bfw_ti = proto_tree_add_string_format(bundle_tree, hf_oran_bfw,
                                                          tvb, bfw_offset, bfw_extent,
                                                          "", "TRX %3u: (", m);
        proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

        /* I */
        /* Get bits, and convert to float. */
        uint32_t bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
        float value = decompress_value(bits, bfwcomphdr_comp_meth, iq_width, exponent);
        /* Add to tree. */
        proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_i, tvb, bit_offset/8, (iq_width+7)/8, value, "#%u=%f", m, value);
        bit_offset += iq_width;
        proto_item_append_text(bfw_ti, "I%u=%f ", m, value);

        /* Q */
        /* Get bits, and convert to float. */
        bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
        value = decompress_value(bits, bfwcomphdr_comp_meth, iq_width, exponent);
        /* Add to tree. */
        proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_q, tvb, bit_offset/8, (iq_width+7)/8, value, "#%u=%f", m, value);
        bit_offset += iq_width;
        proto_item_append_text(bfw_ti, "Q%u=%f)", m, value);
    }

    /* Set extent of bundle */
    proto_item_set_len(bundle_ti, (bit_offset+7)/8 - prb_offset);

    return (bit_offset+7)/8;
}

/* Return new bit offset.  in/out will always be byte-aligned.. */
static int dissect_ciCompParam(tvbuff_t *tvb _U_, proto_tree *tree _U_, packet_info *pinfo _U_, unsigned bit_offset,
                               unsigned comp_meth, uint8_t *exponent)
{
    /* Subtree */
    proto_item *cicompparam_ti = proto_tree_add_string_format(tree, hf_oran_ciCompParam,
                                                            tvb, bit_offset/8, 1, "",
                                                            "ciCompParam");
    proto_tree *cicompparam_tree = proto_item_add_subtree(cicompparam_ti, ett_oran_cicompparam);
    uint32_t ci_exponent;

    /* Contents differ by compression method */
    switch (comp_meth) {
        case COMP_NONE:
            break;
        case COMP_BLOCK_FP:
            proto_tree_add_item(cicompparam_tree, hf_oran_reserved_4bits, tvb, bit_offset/8, 1, ENC_NA);
            proto_tree_add_item_ret_uint(cicompparam_tree, hf_oran_exponent,
                                         tvb, bit_offset/8, 1, ENC_BIG_ENDIAN, &ci_exponent);
            *exponent = ci_exponent;
            proto_item_append_text(cicompparam_ti, " (Exponent=%u)", ci_exponent);
            bit_offset += 8; /* one byte */
            break;

        case COMP_BLOCK_SCALE:
        case COMP_U_LAW:
            /* TODO: handle (separate) details) */
            bit_offset += 8;
            break;
        default:
            /* reserved, ? bytes of zeros.. */
            break;
    }

    return bit_offset;
}

/* Section 7.
 * N.B. these are the green parts of the tables showing Section Types, differing by section Type */
static int dissect_oran_c_section(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                                  uint32_t sectionType, proto_item *protocol_item,
                                  uint8_t ci_iq_width, uint8_t ci_comp_meth, unsigned ci_comp_opt)
{
    unsigned offset = 0;
    proto_tree *c_section_tree = NULL;
    proto_item *sectionHeading = NULL;

    c_section_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_oran_section, &sectionHeading, "Section");
    uint32_t sectionId = 0;

    uint32_t startPrbc;
    uint32_t numPrbc;
    uint32_t ueId = 0;
    uint32_t beamId = 0;
    proto_item *beamId_ti = NULL;
    bool beamId_ignored = false;

    proto_item *numprbc_ti = NULL;

    /* Config affecting ext11 bundles (initially unset) */
    ext11_settings_t ext11_settings;
    memset(&ext11_settings, 0, sizeof(ext11_settings));

    bool extension_flag = false;

    /* These sections are similar, so handle as common with per-type differences */
    if (sectionType <= SEC_C_UE_SCHED) {
        /* sectionID */
        proto_item *ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_section_id, tvb, offset, 2, ENC_BIG_ENDIAN, &sectionId);
        if (sectionId == 4095) {
            proto_item_append_text(ti, " (not default coupling C/U planes using sectionId)");
        }
        offset++;

        /* rb */
        uint32_t rb;
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_rb, tvb, offset, 1, ENC_NA, &rb);
        /* symInc */
        proto_tree_add_item(c_section_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA);
        /* startPrbc */
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_startPrbc, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbc);
        offset += 2;
        /* numPrbc */
        numprbc_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_numPrbc, tvb, offset, 1, ENC_NA, &numPrbc);
        if (numPrbc == 0) {
            proto_item_append_text(numprbc_ti, " (all PRBs - configured as %u)", pref_data_plane_section_total_rbs);
        }
        offset += 1;
        /* reMask */
        proto_tree_add_item(c_section_tree, hf_oran_reMask, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset++;
        /* numSymbol */
        uint32_t numSymbol;
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_numSymbol, tvb, offset, 1, ENC_NA, &numSymbol);
        offset++;

        /* [ef] (extension flag) */
        switch (sectionType) {
            case SEC_C_NORMAL:            /* Section Type 1 */
            case SEC_C_PRACH:             /* Section Type 3 */
            case SEC_C_UE_SCHED:          /* Section Type 5 */
                proto_tree_add_item_ret_boolean(c_section_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);
                break;
            default:
                break;
        }

        write_section_info(sectionHeading, pinfo, protocol_item, sectionId, startPrbc, numPrbc, rb);
        proto_item_append_text(sectionHeading, ", Symbols: %d", numSymbol);

        if (numPrbc == 0) {
            /* Special case for all PRBs */
            numPrbc = pref_data_plane_section_total_rbs;
            startPrbc = 0;  /* may already be 0... */
        }

        /* Section type specific fields (after 'numSymbol') */
        switch (sectionType) {
            case SEC_C_UNUSED_RB:    /* Section Type 0 - Table 5.4 */
                /* reserved */
                proto_tree_add_item(c_section_tree, hf_oran_rsvd16, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;

            case SEC_C_NORMAL:       /* Section Type 1 - Table 5.5 */
                /* beamId */
                beamId_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN, &beamId);
                offset += 2;

                proto_item_append_text(sectionHeading, ", BeamId: %d", beamId);
                break;

            case SEC_C_PRACH:       /* Section Type 3 - Table 5.6 */
            {
                /* beamId */
                beamId_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN, &beamId);
                offset += 2;

                /* freqOffset */
                int32_t freqOffset;          /* Yes, this is signed, so the implicit cast is intentional. */
                proto_item *freq_offset_item = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_freqOffset, tvb, offset, 3, ENC_BIG_ENDIAN, &freqOffset);
                freqOffset |= 0xff000000;   /* Must sign-extend */
                proto_item_set_text(freq_offset_item, "Frequency offset: %d \u0394f", freqOffset);
                offset += 3;

                /* reserved */
                proto_tree_add_item(c_section_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_item_append_text(sectionHeading, ", BeamId: %d, FreqOffset: %d \u0394f", beamId, freqOffset);
                break;
            }

            case SEC_C_UE_SCHED:   /* Section Type 5 - Table 5.7 */
                /* ueId */
                proto_tree_add_item_ret_uint(c_section_tree, hf_oran_ueId, tvb, offset, 2, ENC_NA, &ueId);
                offset += 2;

                proto_item_append_text(sectionHeading, ", UEId: %d", ueId);
                break;

            default:
                break;
        }
    }
    else if (sectionType == SEC_C_CH_INFO) {  /* Section Type 6 */
        /* ef */
        proto_tree_add_item_ret_boolean(c_section_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);
        /* ueId */
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_ueId, tvb, offset, 2, ENC_NA, &ueId);
        offset += 2;
        /* regularizationFactor */
        proto_tree_add_item(c_section_tree, hf_oran_regularizationFactor, tvb, offset, 2, ENC_NA);
        offset += 2;
        /* reserved */
        proto_tree_add_item(c_section_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
        /* rb */
        proto_tree_add_item(c_section_tree, hf_oran_rb, tvb, offset, 1, ENC_NA);
        /* symInc */
        proto_tree_add_item(c_section_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA);
        /* startPrbc */
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_startPrbc, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbc);
        offset += 2;
        /* numPrbc */
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_numPrbc, tvb, offset, 1, ENC_NA, &numPrbc);
        offset += 1;

        /* ciIsample,ciQsample pairs */
        unsigned m;
        unsigned prb;
        uint32_t bit_offset = offset*8;

        /* Antenna count from preference */
        unsigned num_trx = pref_num_bf_antennas;
        if (numPrbc > 1) {
            proto_item_append_text(sectionHeading, " (UEId=%u  PRBs %u-%u, %u antennas", ueId, startPrbc, startPrbc+numPrbc-1, num_trx);
        }
        else {
            proto_item_append_text(sectionHeading, " (UEId=%u  PRB %u, %u antennas", ueId, startPrbc, num_trx);
        }

        bool first_prb = true;
        uint8_t exponent = 0;
        for (prb=startPrbc; prb < startPrbc+numPrbc; prb++) {

            /* PRB subtree */
            unsigned prb_start_offset = bit_offset;
            proto_item *prb_ti = proto_tree_add_string_format(c_section_tree, hf_oran_samples_prb,
                                                                 tvb, bit_offset/8, 0,
                                                                 "", "PRB=%u", prb);
            proto_tree *prb_tree = proto_item_add_subtree(prb_ti, ett_oran_prb_cisamples);

            /* There may be a ciCompParam here.. */
            if (first_prb || ci_comp_opt==1) {
                bit_offset = dissect_ciCompParam(tvb, prb_tree, pinfo, bit_offset, ci_comp_meth, &exponent);
            }
            first_prb = false;

            /* Antennas */
            for (m=0; m < num_trx; m++) {

                unsigned sample_offset = bit_offset / 8;
                uint8_t sample_extent = ((bit_offset + (ci_iq_width*2)) / 8) - sample_offset;

                /* Create subtree for antenna */
                proto_item *sample_ti = proto_tree_add_string_format(prb_tree, hf_oran_ciSample,
                                                                     tvb, sample_offset, sample_extent,
                                                                     "", "TRX=%u:  ", m);
                proto_tree *sample_tree = proto_item_add_subtree(sample_ti, ett_oran_cisample);

                /* I */
                /* Get bits, and convert to float. */
                uint32_t bits = tvb_get_bits(tvb, bit_offset, ci_iq_width, ENC_BIG_ENDIAN);
                float value = decompress_value(bits, ci_comp_meth, ci_iq_width, exponent);

                /* Add to tree. */
                proto_tree_add_float_format_value(sample_tree, hf_oran_ciIsample, tvb, bit_offset/8, (16+7)/8, value, "#%u=%f", m, value);
                bit_offset += ci_iq_width;
                proto_item_append_text(sample_ti, "I%u=%f ", m, value);

                /* Q */
                /* Get bits, and convert to float. */
                bits = tvb_get_bits(tvb, bit_offset, ci_iq_width, ENC_BIG_ENDIAN);
                value = decompress_value(bits, ci_comp_meth, ci_iq_width, exponent);

                /* Add to tree. */
                proto_tree_add_float_format_value(sample_tree, hf_oran_ciQsample, tvb, bit_offset/8, (16+7)/8, value, "#%u=%f", m, value);
                bit_offset += ci_iq_width;
                proto_item_append_text(sample_ti, "Q%u=%f ", m, value);
            }
            proto_item_set_len(prb_ti, (bit_offset-prb_start_offset)/8);
        }
        offset = (bit_offset/8);
    }
    else if (sectionType == SEC_C_LAA) {   /* Section Type 7 */
        /* 7.2.5 Table 6.4-6 */

        /* laaMsgType */
        uint32_t laa_msg_type;
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_laaMsgType, tvb, offset, 1, ENC_NA, &laa_msg_type);
        /* laaMsgLen */
        uint32_t laa_msg_len;
        proto_item *len_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_laaMsgLen, tvb, offset, 1, ENC_NA, &laa_msg_len);
        proto_item_append_text(len_ti, " (%u bytes)", 4*(laa_msg_len+1));
        offset += 1;

        int payload_offset = offset;

        /* Payload */
        switch (laa_msg_type) {
            case 0:
                /* LBT_PDSCH_REQ */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtOffset (10 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtMode  (2 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_lbtMode, tvb, offset*8, 2, ENC_BIG_ENDIAN);
                /* reserved (1 bit) */
                /* lbtDeferFactor (3 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtDeferFactor, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtBackoffCounter (10 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtBackoffCounter, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 1;
                /* MCOT (4 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_MCOT, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (10 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_reserved, tvb, (offset*8)+6, 10, ENC_BIG_ENDIAN);
                break;
            case 1:
                /* LBT_DRS_REQ */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtOffset (10 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtMode  (2 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_lbtMode, tvb, offset*8, 2, ENC_BIG_ENDIAN);
                /* reserved (28 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_reserved, tvb, (offset*8)+4, 28, ENC_BIG_ENDIAN);
                break;
            case 2:
                /* LBT_PDSCH_RSP */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtPdschRes (2 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtPdschRes, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* inParSF (1 bit) */
                proto_tree_add_item(c_section_tree, hf_oran_initialPartialSF, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* sfStatus (1 bit) */
                proto_tree_add_item(c_section_tree, hf_oran_sfStatus, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* sfnSf (12 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_sfnSfEnd, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* reserved (24 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_reserved, tvb, (offset*8), 24, ENC_BIG_ENDIAN);
                break;
            case 3:
                /* LBT_DRS_RSP */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtDrsRes (1 bit) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtDrsRes, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (7 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_reserved, tvb, (offset*8)+1, 7, ENC_BIG_ENDIAN);
                break;
            case 4:
                /* LBT_Buffer_Error */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtBufErr (1 bit) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtBufErr, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (7 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_reserved, tvb, (offset*8)+1, 7, ENC_BIG_ENDIAN);
                break;
            case 5:
                /* LBT_CWCONFIG_REQ */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtCWConfig_H (8 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtCWConfig_H, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtCWConfig_T (8 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtCWConfig_T, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtMode  (2 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_lbtMode, tvb, offset*8, 2, ENC_BIG_ENDIAN);
                /* lbtTrafficClass (3 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtTrafficClass, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (19 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_reserved, tvb, (offset*8)+5, 19, ENC_BIG_ENDIAN);
                break;
            case 6:
                /* LBT_CWCONFIG_RSP */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtCWR_Rst (1 bit) */
                proto_tree_add_item(c_section_tree, hf_oran_lbtCWR_Rst, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (7 bits) */
                proto_tree_add_bits_item(c_section_tree, hf_oran_reserved, tvb, (offset*8)+1, 7, ENC_BIG_ENDIAN);
                break;

            default:
                /* Unhandled! */
                break;
        }
        /* For now just skip indicated length of bytes */
        offset = payload_offset + 4*(laa_msg_len+1);
    }

    /* Section extension commands */
    while (extension_flag) {

        int extension_start_offset = offset;

        /* Create subtree for each extension (with summary) */
        proto_item *extension_ti = proto_tree_add_string_format(c_section_tree, hf_oran_extension,
                                                                tvb, offset, 0, "", "Extension");
        proto_tree *extension_tree = proto_item_add_subtree(extension_ti, ett_oran_c_section_extension);

        /* ef (i.e. another extension after this one?) */
        proto_tree_add_item_ret_boolean(extension_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);

        /* extType */
        uint32_t exttype;
        proto_tree_add_item_ret_uint(extension_tree, hf_oran_exttype, tvb, offset, 1, ENC_BIG_ENDIAN, &exttype);
        offset++;
        proto_item_append_text(sectionHeading, " (ext-%u)", exttype);

        proto_item_append_text(extension_ti, " (ext-%u: %s)", exttype, val_to_str_const(exttype, exttype_vals, "Reserved"));

        /* extLen (number of 32-bit words) */
        uint32_t extlen_len = ((exttype==11)||(exttype==19)||(exttype==20)) ? 2 : 1;  /* Extensions 11/19/20 are special */
        uint32_t extlen;
        proto_item *extlen_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_extlen, tvb,
                                                             offset, extlen_len, ENC_BIG_ENDIAN, &extlen);
        proto_item_append_text(extlen_ti, " (%u bytes)", extlen*4);
        offset += extlen_len;
        if (extlen == 0) {
            expert_add_info_format(pinfo, extlen_ti, &ei_oran_extlen_zero,
                                   "extlen value of 0 is reserved");
            /* Break out to avoid infinitely looping! */
            break;
        }

        switch (exttype) {

            case 1:  /* Beamforming Weights Extension type */
            {
                uint32_t bfwcomphdr_iq_width, bfwcomphdr_comp_meth;
                proto_item *comp_meth_ti = NULL;

                /* bfwCompHdr (2 subheaders - bfwIqWidth and bfwCompMeth)*/
                offset = dissect_bfwCompHdr(tvb, extension_tree, offset,
                                            &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);

                /* Look up width of samples. */
                uint8_t iq_width = !bfwcomphdr_iq_width ? 16 : bfwcomphdr_iq_width;

                /* bfwCompParam */
                uint32_t exponent = 0;
                bool compression_method_supported = false;
                offset = dissect_bfwCompParam(tvb, extension_tree, pinfo, offset, comp_meth_ti,
                                              bfwcomphdr_comp_meth, &exponent, &compression_method_supported);

                /* Can't show details of unsupported compression method */
                if (!compression_method_supported) {
                    break;
                }

                /* We know:
                   - iq_width (above)
                   - numBfWeights (taken from preference)
                   - remaining bytes in extension
                   We can therefore derive TRX (number of antennas).
                 */

                /* I & Q samples
                   Don't know how many there will be, so just fill available bytes...
                 */
                unsigned weights_bytes = (extlen*4)-3;
                unsigned num_weights_pairs = (weights_bytes*8) / (iq_width*2);
                unsigned num_trx = num_weights_pairs;
                int bit_offset = offset*8;

                for (unsigned n=0; n < num_trx; n++) {
                    /* Create antenna subtree */
                    int bfw_offset = bit_offset / 8;
                    proto_item *bfw_ti = proto_tree_add_string_format(extension_tree, hf_oran_bfw,
                                                                      tvb, bfw_offset, 0, "", "TRX %3u: (", n);
                    proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

                    /* I value */
                    /* Get bits, and convert to float. */
                    uint32_t bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
                    float value = decompress_value(bits, COMP_BLOCK_FP, iq_width, exponent);
                    /* Add to tree. */
                    proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_i, tvb, bit_offset/8, (iq_width+7)/8, value, "%f", value);
                    bit_offset += iq_width;
                    proto_item_append_text(bfw_ti, "I=%f ", value);

                    /* Leave a gap between I and Q values */
                    proto_item_append_text(bfw_ti, "  ");

                    /* Q value */
                    /* Get bits, and convert to float. */
                    bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
                    value = decompress_value(bits, COMP_BLOCK_FP, iq_width, exponent);
                    /* Add to tree. */
                    proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_q, tvb, bit_offset/8, (iq_width+7)/8, value, "%f", value);
                    bit_offset += iq_width;
                    proto_item_append_text(bfw_ti, "Q=%f", value);

                    proto_item_append_text(bfw_ti, ")");
                    proto_item_set_len(bfw_ti, (bit_offset+7)/8  - bfw_offset);
                }
                /* Need to round to next byte */
                offset = (bit_offset+7)/8;

                break;
            }

            case 2: /* Beamforming attributes */
            {
                /* bfaCompHdr (get widths of fields to follow) */
                uint32_t bfAzPtWidth, bfZePtWidth, bfAz3ddWidth, bfZe3ddWidth;
                /* subtree */
                proto_item *bfa_ti = proto_tree_add_string_format(extension_tree, hf_oran_bfaCompHdr,
                                                                  tvb, offset, 2, "", "bfaCompHdr");
                proto_tree *bfa_tree = proto_item_add_subtree(bfa_ti, ett_oran_bfacomphdr);

                /* reserved (2 bits) */
                proto_tree_add_item(bfa_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* bfAzPtWidth (3 bits) */
                proto_tree_add_item_ret_uint(bfa_tree, hf_oran_bfAzPtWidth, tvb, offset, 1, ENC_BIG_ENDIAN, &bfAzPtWidth);
                /* bfZePtWidth (3 bits) */
                proto_tree_add_item_ret_uint(bfa_tree, hf_oran_bfZePtWidth, tvb, offset, 1, ENC_BIG_ENDIAN, &bfZePtWidth);
                offset += 1;

                /* reserved (2 bits) */
                proto_tree_add_item(bfa_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* bfAz3ddWidth (3 bits) */
                proto_tree_add_item_ret_uint(bfa_tree, hf_oran_bfAz3ddWidth, tvb, offset, 1, ENC_BIG_ENDIAN, &bfAz3ddWidth);
                /* bfZe3ddWidth (3 bits) */
                proto_tree_add_item_ret_uint(bfa_tree, hf_oran_bfZe3ddWidth, tvb, offset, 1, ENC_BIG_ENDIAN, &bfZe3ddWidth);
                offset += 1;

                unsigned bit_offset = offset*8;

                /* bfAzPt */
                if (bfAzPtWidth > 0) {
                    proto_tree_add_bits_item(extension_tree, hf_oran_bfAzPt, tvb, bit_offset, bfAzPtWidth+1, ENC_BIG_ENDIAN);
                    bit_offset += (bfAzPtWidth+1);
                }
                /* bfZePt */
                if (bfZePtWidth > 0) {
                    proto_tree_add_bits_item(extension_tree, hf_oran_bfZePt, tvb, bit_offset, bfZePtWidth+1, ENC_BIG_ENDIAN);
                    bit_offset += (bfZePtWidth+1);
                }
                /* bfAz3dd */
                if (bfAz3ddWidth > 0) {
                    proto_tree_add_bits_item(extension_tree, hf_oran_bfAz3dd, tvb, bit_offset, bfAz3ddWidth+1, ENC_BIG_ENDIAN);
                    bit_offset += (bfAz3ddWidth+1);
                }
                /* bfZe3dd */
                if (bfZe3ddWidth > 0) {
                    proto_tree_add_bits_item(extension_tree, hf_oran_bfZe3dd, tvb, bit_offset, bfZe3ddWidth+1, ENC_BIG_ENDIAN);
                    bit_offset += (bfZe3ddWidth+1);
                }

                /* go to next byte (zero-padding.. - a little confusing..) */
                offset = (bit_offset+7) / 8;

                /* 2 reserved/padding bits */
                /* bfAzSl (3 bits) */
                proto_tree_add_item(extension_tree, hf_oran_bfAzSl, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* bfZeSl (3 bits) */
                proto_tree_add_item(extension_tree, hf_oran_bfZeSl, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            }

            case 4: /* Modulation compression params (5.4.7.4) */
            {
                /* csf */
                proto_tree_add_bits_item(extension_tree, hf_oran_csf, tvb, offset*8, 1, ENC_BIG_ENDIAN);
                /* modCompScaler */
                uint32_t modCompScaler;
                proto_item *ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_modcompscaler,
                                                              tvb, offset, 2, ENC_BIG_ENDIAN, &modCompScaler);
                /* Work out and show floating point value too. */
                uint16_t exponent = (modCompScaler >> 11) & 0x000f; /* m.s. 4 bits */
                uint16_t mantissa = modCompScaler & 0x07ff;         /* l.s. 11 bits */
                double value = (double)mantissa * (1.0 / (1 << exponent));
                proto_item_append_text(ti, " (%f)", value);

                offset += 2;
                break;
            }

            case 5: /* Modulation Compression Additional Parameters Extension Type (7.7.5) */
            {
                /* Applies only to section types 1,3 and 5 */

                /* There may be one or 2 entries, depending upon extlen */
                int sets = 1, reserved_bits = 0;
                switch (extlen) {
                    case 2:
                        sets = 1;
                        reserved_bits = 20;
                        break;
                    case 3:
                        sets = 2;
                        reserved_bits = 24;
                        break;
                    case 4:
                        /* sets can be 3 or 4, depending upon whether last 28 bits are 0.. */
                        if ((tvb_get_ntohl(tvb, offset+10) & 0x0fffffff) == 0) {
                            sets = 3;
                            reserved_bits = 28;
                        }
                        else {
                            sets = 4;
                            reserved_bits = 0;
                        }
                        break;

                    default:
                        /* Malformed error!!! */
                        expert_add_info_format(pinfo, extlen_ti, &ei_oran_extlen_wrong,
                                               "For section 5, extlen must be 2, 3 or 4, but %u was dissected",
                                               extlen);
                        break;
                }

                unsigned bit_offset = offset*8;

                for (int n=0; n < sets; n++) {
                    /* Subtree for each set */
                    unsigned set_start_offset = bit_offset/8;
                    proto_item *set_ti = proto_tree_add_string(extension_tree, hf_oran_modcomp_param_set,
                                                                tvb, set_start_offset, 0, "");
                    proto_tree *set_tree = proto_item_add_subtree(set_ti, ett_oran_modcomp_param_set);

                    uint64_t mcScaleReMask, csf, mcScaleOffset;

                    /* mcScaleReMask (12 bits) */
                    proto_tree_add_bits_ret_val(set_tree, hf_oran_mc_scale_re_mask, tvb, bit_offset, 12, &mcScaleReMask, ENC_BIG_ENDIAN);
                    bit_offset += 12;
                    /* csf (1 bit) */
                    proto_tree_add_bits_ret_val(set_tree, hf_oran_csf, tvb, bit_offset, 1, &csf, ENC_BIG_ENDIAN);
                    bit_offset += 1;
                    /* mcScaleOffset (15 bits) */
                    proto_tree_add_bits_ret_val(set_tree, hf_oran_mc_scale_offset, tvb, bit_offset, 15, &mcScaleOffset, ENC_BIG_ENDIAN);
                    bit_offset += 15;

                    /* Summary */
                    proto_item_set_len(set_ti, (bit_offset+7)/8 - set_start_offset);
                    proto_item_append_text(set_ti, " (mcScaleReMask=%u  csf=%s  mcScaleOffset=%u)",
                                           (unsigned)mcScaleReMask, tfs_get_true_false((bool)csf), (unsigned)mcScaleOffset);
                }

                proto_item_append_text(extension_ti, " (%u sets)", sets);

                /* Reserved */
                if (reserved_bits) {
                    proto_tree_add_bits_item(extension_tree, hf_oran_reserved, tvb, bit_offset, reserved_bits, ENC_BIG_ENDIAN);
                    bit_offset += reserved_bits;
                }

                offset = bit_offset/8;
                break;
            }

            case 6: /* Non-contiguous PRB allocation in time and frequency domain */
            {
                /* Update ext6 recorded info */
                ext11_settings.ext6_set = true;

                /* repetition */
                proto_tree_add_bits_item(extension_tree, hf_oran_repetition, tvb, offset*8, 1, ENC_BIG_ENDIAN);
                /* rbgSize */
                uint32_t rbgSize;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_rbgSize, tvb, offset, 1, ENC_BIG_ENDIAN, &rbgSize);
                if (rbgSize == 0) {
                    expert_add_info_format(pinfo, extlen_ti, &ei_oran_rbg_size_reserved,
                                           "rbgSize value of 0 is reserved");
                }
                /* rbgMask (28 bits) */
                uint32_t rbgMask;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_rbgMask, tvb, offset, 4, ENC_BIG_ENDIAN, &rbgMask);
                offset += 4;
                /* priority */
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* symbolMask */
                proto_tree_add_item(extension_tree, hf_oran_symbolMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Look up rbg_size enum -> value */
                switch (rbgSize) {
                    case 0:
                        /* N.B. reserved, but covered above with expert info (would remain 0) */
                        break;
                    case 1:
                        ext11_settings.ext6_rbg_size = 1; break;
                    case 2:
                        ext11_settings.ext6_rbg_size = 2; break;
                    case 3:
                        ext11_settings.ext6_rbg_size = 3; break;
                    case 4:
                        ext11_settings.ext6_rbg_size = 4; break;
                    case 5:
                        ext11_settings.ext6_rbg_size = 6; break;
                    case 6:
                        ext11_settings.ext6_rbg_size = 8; break;
                    case 7:
                        ext11_settings.ext6_rbg_size = 16; break;
                    /* N.B., encoded in 3 bits, so no other values are possible */
                }
                /* Record which bits (and count) are set in rbgMask */
                for (unsigned n=0; n < 28 && ext11_settings.ext6_num_bits_set < 28; n++) {
                    if ((rbgMask >> n) & 0x01) {
                        ext11_settings.ext6_bits_set[ext11_settings.ext6_num_bits_set++] = n;
                    }
                }
                break;
            }

            case 7: /* eAxC mask */
                proto_tree_add_item(extension_tree, hf_oran_eAxC_mask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case 8: /* Regularization factor */
                proto_tree_add_item(extension_tree, hf_oran_regularizationFactor, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case 9: /* Dynamic Spectrum Sharing parameters */
                proto_tree_add_item(extension_tree, hf_oran_technology, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_bits_item(extension_tree, hf_oran_reserved, tvb, offset*8, 8, ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case 10: /* Section description for group configuration of multiple ports */
            {
                /* beamGroupType */
                uint32_t beam_group_type = 0;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_beamGroupType,
                                             tvb, offset, 1, ENC_BIG_ENDIAN, &beam_group_type);
                proto_item_append_text(extension_ti, " (%s)", val_to_str_const(beam_group_type, beam_group_type_vals, "Unknown"));

                /* numPortc */
                uint32_t numPortc;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_numPortc,
                                             tvb, offset, 1, ENC_BIG_ENDIAN, &numPortc);
                offset++;

                /* TODO: any generated fields or expert info should be added, due to entries in table 5-35 ? */

                /* Will append all beamId values to extension_ti, regardless of beamGroupType */
                proto_item_append_text(extension_ti, "(");
                unsigned n;

                switch (beam_group_type) {
                    case 0x0: /* common beam */
                        /* Reserved byte */
                        proto_tree_add_item(extension_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
                        offset++;

                        /* All entries are beamId... */
                        for (n=0; n < numPortc; n++) {
                            proto_item_append_text(extension_ti, "%u ", beamId);
                        }
                        break;

                    case 0x1: /* beam matrix indication */
                        /* Reserved byte */
                        proto_tree_add_item(extension_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
                        offset++;

                        /* Entries inc from beamId... */
                        for (n=0; n < numPortc; n++) {
                            proto_item_append_text(extension_ti, "%u ", beamId+n);
                        }
                        break;

                    case 0x2: /* beam vector listing */
                    {
                        /* Beam listing vector case */
                        /* Work out how many port beam entries there is room for */
                        /* Using numPortC as visible in issue 18116 */
                        proto_item_append_text(extension_ti, " (%u entries) ", numPortc);
                        for (n=0; n < numPortc; n++) {
                            /* TODO: Single reserved bit */

                            /* port beam ID (or UEID) */
                            uint32_t id;
                            proto_item *beamid_or_ueid_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_beamId,
                                                                                         tvb, offset, 2, ENC_BIG_ENDIAN, &id);
                            proto_item_append_text(beamid_or_ueid_ti, " port #%u beam ID (or UEId) %u", n, id);
                            offset += 2;

                            proto_item_append_text(extension_ti, "%u ", id);
                        }
                        break;
                    }

                    default:
                        /* TODO: warning for unsupported/reserved value */
                        break;
                }
                proto_item_append_text(extension_ti, ")");
                break;
            }

            case 11: /* Flexible Weights Extension Type */
            {
                bool disableBFWs;
                uint32_t numBundPrb;

                /* disableBFWs */
                proto_tree_add_item_ret_boolean(extension_tree, hf_oran_disable_bfws,
                                                tvb, offset, 1, ENC_BIG_ENDIAN, &disableBFWs);
                if (disableBFWs) {
                    proto_item_append_text(extension_ti, " (disableBFWs)");
                }
                /* RAD */
                proto_tree_add_item(extension_tree, hf_oran_rad,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                /* 6 reserved bits */
                proto_tree_add_item(extension_tree, hf_oran_ext11_reserved, tvb,
                                    offset, 1, ENC_BIG_ENDIAN);
                offset++;

                /* numBundPrb (number of prbs in each bundle) */
                proto_item *num_bund_prb_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_num_bund_prbs,
                                                                           tvb, offset, 1, ENC_BIG_ENDIAN, &numBundPrb);
                offset++;
                /* value zero is reserved.. */
                if (numBundPrb == 0) {
                    expert_add_info_format(pinfo, num_bund_prb_ti, &ei_oran_reserved_numBundPrb,
                                           "Reserved value 0 for numBundPrb seen - not valid");
                }

                uint32_t num_bundles;
                bool orphaned_prbs = false;

                if (!disableBFWs) {
                    /********************************************/
                    /* Table 7.7.1.1-1 */
                    /********************************************/

                    uint32_t bfwcomphdr_iq_width, bfwcomphdr_comp_meth;
                    proto_item *comp_meth_ti = NULL;

                    /* bfwCompHdr (2 subheaders - bfwIqWidth and bfwCompMeth)*/
                    offset = dissect_bfwCompHdr(tvb, extension_tree, offset,
                                                &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);

                    /* Look up width of samples. */
                    uint8_t iq_width = !bfwcomphdr_iq_width ? 16 : bfwcomphdr_iq_width;


                    /* Work out number of bundles, but take care not to divide by zero. */
                    if (numBundPrb == 0) {
                        break;
                    }

                    /* Work out bundles! */
                    ext11_work_out_bundles(startPrbc, numPrbc, numBundPrb, &ext11_settings);
                    num_bundles = ext11_settings.num_bundles;

                    /* Add (complete) bundles */
                    for (unsigned b=0; b < num_bundles; b++) {

                        offset = dissect_bfw_bundle(tvb, extension_tree, pinfo, offset,
                                                    comp_meth_ti, bfwcomphdr_comp_meth,
                                                    (ext11_settings.ext21_set) ?
                                                        numPrbc :
                                                        pref_num_weights_per_bundle,
                                                    iq_width,
                                                    b,                                 /* bundle number */
                                                    ext11_settings.bundles[b].start,
                                                    ext11_settings.bundles[b].end,
                                                    ext11_settings.bundles[b].is_orphan);
                        if (!offset) {
                            break;
                        }
                    }
                    if (num_bundles > 0) {
                        /* Set flag from last bundle entry */
                        orphaned_prbs = ext11_settings.bundles[num_bundles-1].is_orphan;
                    }
                }
                else {
                    /********************************************/
                    /* Table 7.7.1.1-2 */
                    /* No weights in this case */
                    /********************************************/

                    /* Work out number of bundles, but take care not to divide by zero. */
                    if (numBundPrb == 0) {
                        break;
                    }

                    ext11_work_out_bundles(startPrbc, numPrbc, numBundPrb, &ext11_settings);
                    num_bundles = ext11_settings.num_bundles;

                    for (unsigned n=0; n < num_bundles; n++) {
                        /* beamId */
                        proto_item *ti = proto_tree_add_item(extension_tree, hf_oran_beam_id,
                                                             tvb, offset, 2, ENC_BIG_ENDIAN);
                        if (!ext11_settings.bundles[n].is_orphan) {
                            proto_item_append_text(ti, " (Bundle %u)", n);
                        }
                        else {
                            orphaned_prbs = true;
                            proto_item_append_text(ti, " (Orphaned PRBs)");
                        }
                        offset += 2;
                    }
                }

                /* Add summary to extension root */
                if (orphaned_prbs) {
                    proto_item_append_text(extension_ti, " (%u bundles + orphaned)", num_bundles);
                }
                else {
                    proto_item_append_text(extension_ti, " (%u bundles)", num_bundles);
                }
            }

                break;

            case 12: /* Non-Contiguous PRB Allocation with Frequency Ranges */
            {
                ext11_settings.ext12_set = true;

                /* priority */
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);

                /* symbolMask */
                proto_tree_add_item(extension_tree, hf_oran_symbolMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* There are now 'R' pairs of (offStartPrb, numPrb) values. Fill extlen bytes with values.  If last one is not set,
                   should be populated with 0s. */
                uint32_t extlen_remaining_bytes = (extlen*4) - 4;
                uint8_t prb_index;

                for (prb_index = 1; extlen_remaining_bytes > 0; prb_index++)
                {
                    /* Create a subtree for each pair */
                    proto_item *pair_ti = proto_tree_add_string(extension_tree, hf_oran_off_start_prb_num_prb_pair,
                                                                tvb, offset, 2, "");
                    proto_tree *pair_tree = proto_item_add_subtree(pair_ti, ett_oran_offset_start_prb_num_prb);

                    /* offStartPrb */
                    uint32_t off_start_prb;
                    proto_tree_add_item_ret_uint(pair_tree, hf_oran_off_start_prb, tvb, offset, 1, ENC_BIG_ENDIAN, &off_start_prb);
                    offset++;

                    /* numPrb */
                    uint32_t num_prb;
                    proto_tree_add_item_ret_uint(pair_tree, hf_oran_num_prb, tvb, offset, 1, ENC_BIG_ENDIAN, &num_prb);
                    offset++;

                    extlen_remaining_bytes -= 2;

                    /* Last pair may be 0,0 if not used. Check for this */
                    if ((extlen_remaining_bytes == 0) && (off_start_prb == 0) && (num_prb == 0)) {
                        proto_item_append_text(pair_ti, " (not used)");
                    }
                    /* Add summary to pair root item, and configure details in ext11_settings */
                    else {
                        proto_item_append_text(pair_ti, "(%u) offStartPrb=%3u, numPrb=%u",
                                              prb_index, off_start_prb, num_prb);
                        if (ext11_settings.ext12_num_pairs < MAX_BFW_EXT12_PAIRS) {
                            ext11_settings.ext12_pairs[ext11_settings.ext12_num_pairs].off_start_prb = off_start_prb;
                            ext11_settings.ext12_pairs[ext11_settings.ext12_num_pairs++].num_prb = num_prb;
                        }
                    }
                }
                break;
            }

            case 13:  /* PRB Allocation with Frequency Hopping */
            {
                /* Will update settings for ext11 */
                ext11_settings.ext13_set = true;

                uint32_t extlen_remaining_bytes = (extlen*4) - 2;
                uint8_t allocation_index;

                unsigned prev_next_symbol_id = 0, prev_next_start_prbc = 0;

                for (allocation_index = 1; extlen_remaining_bytes > 0; allocation_index++)
                {
                    /* Subtree for allocation */
                    proto_item *allocation_ti = proto_tree_add_string(extension_tree, hf_oran_prb_allocation,
                                                                tvb, offset, 2, "");
                    proto_tree *allocation_tree = proto_item_add_subtree(allocation_ti, ett_oran_prb_allocation);

                    /* Reserved (2 bits) */
                    proto_tree_add_item(allocation_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);

                    /* nextSymbolId (4 bits) */
                    uint32_t next_symbol_id;
                    proto_tree_add_item_ret_uint(allocation_tree, hf_oran_nextSymbolId, tvb, offset, 1, ENC_BIG_ENDIAN, &next_symbol_id);

                    /* nextStartPrbc (10 bits) */
                    uint32_t next_start_prbc;
                    proto_tree_add_item_ret_uint(allocation_tree, hf_oran_nextStartPrbc, tvb, offset, 2, ENC_BIG_ENDIAN, &next_start_prbc);
                    offset += 2;

                    /* Add summary to allocation root item */
                    proto_item_append_text(allocation_ti, "(%u) nextSymbolId=%3u, nextStartPrbc=%u",
                                           allocation_index, next_symbol_id, next_start_prbc);

                    /* Checking for duplicates (expected if e.g. had only 2 entries but extlen bytes still to fill */
                    if ((allocation_index > 1) && (next_symbol_id == prev_next_symbol_id) && (next_start_prbc == prev_next_start_prbc)) {
                        proto_item_append_text(allocation_ti, " (repeated - to fill up extlen)");
                    }
                    else {
                        /* Add entry for configuring ext11. don't store out of range */
                        if (ext11_settings.ext13_num_start_prbs < MAX_BFW_EXT13_ALLOCATIONS) {
                            ext11_settings.ext13_start_prbs[ext11_settings.ext13_num_start_prbs++] = next_start_prbc;
                        }
                    }
                    prev_next_symbol_id = next_symbol_id;
                    prev_next_start_prbc = next_start_prbc;

                    extlen_remaining_bytes -= 2;
                }
                break;
            }

            case 14:  /* Nulling-layer Info. for ueId-based beamforming */
                proto_tree_add_item(extension_tree, hf_oran_nullLayerInd, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_bits_item(extension_tree, hf_oran_reserved, tvb, offset*8, 8, ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case 15:  /* Mixed-numerology Info. for ueId-based beamforming */
                /* frameStructure */
                proto_tree_add_item(extension_tree, hf_oran_frameStructure_fft, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(extension_tree, hf_oran_frameStructure_subcarrier_spacing, tvb, offset, 1, ENC_NA);
                offset += 1;
                /* freqOffset */
                proto_tree_add_item(extension_tree, hf_oran_freqOffset, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
                /* cpLength */
                proto_tree_add_item(extension_tree, hf_oran_cpLength, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case 16:  /* Section description for antenna mapping in UE channel information based UL beamforming */
            {
                uint32_t extlen_remaining_bytes = (extlen*4) - 2;
                unsigned num_ant_masks = extlen_remaining_bytes / 8;
                for (unsigned n=0; n < num_ant_masks; n++) {
                    proto_item *ti = proto_tree_add_item(extension_tree, hf_oran_antMask, tvb, offset, 8, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (RX eAxC #%u)", n+1);
                    offset += 8;
                }
                break;
            }

            case 17:  /* Section description for indication of user port group */
            {
                uint32_t extlen_remaining_bytes = (extlen*4) - 2;
                uint32_t end_bit = (offset+extlen_remaining_bytes) * 8;
                uint32_t ueid_index = 1;
                /* TODO: just filling up all available bytes - some may actually be padding.. */
                for (uint32_t bit_offset=offset*8; bit_offset < end_bit; bit_offset+=4, ueid_index++) {
                    proto_item *ti = proto_tree_add_bits_item(extension_tree, hf_oran_num_ueid, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (user #%u)", ueid_index);
                }
                break;
            }

            case 18:  /* Section description for Uplink Transmission Management */
                /* transmissionWindowOffset */
                proto_tree_add_item(extension_tree, hf_oran_transmissionWindowOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* reserved (2 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* transmissionWindowSize (14 bits) */
                proto_tree_add_item(extension_tree, hf_oran_transmissionWindowSize, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* reserved (6 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_6bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* toT (2 bits) */
                proto_tree_add_item(extension_tree, hf_oran_toT, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case 19:  /* Compact beamforming information for multiple port */
            {
                /* beamId in section header should be ignored */
                if (beamId_ti && !beamId_ignored) {
                    proto_item_append_text(beamId_ti, " (ignored)");
                    beamId_ignored = true;
                }

                /* disableBFWs */
                bool disableBFWs;
                proto_tree_add_item_ret_boolean(extension_tree, hf_oran_disable_bfws,
                                                tvb, offset, 1, ENC_BIG_ENDIAN, &disableBFWs);
                if (disableBFWs) {
                    proto_item_append_text(extension_ti, " (disableBFWs)");
                }
                /* Repetition */
                proto_tree_add_bits_item(extension_tree, hf_oran_repetition, tvb, (offset*8)+1, 1, ENC_BIG_ENDIAN);
                /* numPortc */
                uint32_t numPortc;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_numPortc,
                                             tvb, offset, 1, ENC_BIG_ENDIAN, &numPortc);
                offset++;

                /* priority */
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* symbolMask */
                proto_tree_add_item(extension_tree, hf_oran_symbolMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* bfwCompHdr */
                uint32_t bfwcomphdr_iq_width, bfwcomphdr_comp_meth;
                proto_item *comp_meth_ti = NULL;
                offset = dissect_bfwCompHdr(tvb, extension_tree, offset,
                                            &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);

                /* Add entries for each port */
                for (unsigned port=0; port < numPortc; port++) {

                    /* Create subtree for port entry*/
                    int port_start_offset = offset;
                    proto_item *port_ti = proto_tree_add_string_format(extension_tree, hf_oran_ext19_port,
                                                                       tvb, offset, 0,
                                                                      "", "Port %u: ", port);
                    proto_tree *port_tree = proto_item_add_subtree(port_ti, ett_oran_ext19_port);



                    /* Reserved (4 bits) */
                    proto_tree_add_item(port_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* portReMask (12 bits) */
                    proto_tree_add_item(port_tree, hf_oran_portReMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* Reserved (2 bits) */
                    proto_tree_add_item(port_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* portSymbolMask (14 bits) */
                    proto_tree_add_item(port_tree, hf_oran_portSymbolMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* Reserved (1 bit) */
                    proto_tree_add_item(port_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* beamID (15 bits) */
                    proto_tree_add_item_ret_uint(port_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN, &beamId);
                    proto_item_append_text(port_ti, " (beamId=%u)", beamId);
                    offset += 2;

                    /* bfwCompParam (TODO: present in disableBFWs case?) */
                    bool compression_method_supported = false;
                    uint32_t exponent = 0;
                    offset = dissect_bfwCompParam(tvb, port_tree, pinfo, offset, comp_meth_ti,
                                                  bfwcomphdr_comp_meth, &exponent, &compression_method_supported);


                    if (!disableBFWs) {
                        /*****************************************************************/
                        /* Table 7.7.19.1-1 (there is no part 2 for disableBFWs case...) */
                        /*****************************************************************/

                        /* Look up width of samples. */
                        uint8_t iq_width = !bfwcomphdr_iq_width ? 16 : bfwcomphdr_iq_width;

                        int bit_offset = offset*8;
                        int bfw_offset;

                        /* Add weights for each TRX */
                        for (unsigned b=0; b < pref_num_bf_antennas; b++) {

                            /* Create BFW subtree */
                            bfw_offset = bit_offset / 8;
                            uint8_t bfw_extent = ((bit_offset + (iq_width*2)) / 8) - bfw_offset;
                            proto_item *bfw_ti = proto_tree_add_string_format(port_tree, hf_oran_bfw,
                                                                              tvb, bfw_offset, bfw_extent,
                                                                              "", "TRX %u: (", b);
                            proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

                            /* I */
                            /* Get bits, and convert to float. */
                            uint32_t bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
                            float value = decompress_value(bits, bfwcomphdr_comp_meth, iq_width, exponent);
                            /* Add to tree. */
                            proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_i, tvb, bit_offset/8, (iq_width+7)/8, value, "#%u=%f", b, value);
                            bit_offset += iq_width;
                            proto_item_append_text(bfw_ti, "I%u=%f ", b, value);

                            /* Q */
                            /* Get bits, and convert to float. */
                            bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
                            value = decompress_value(bits, bfwcomphdr_comp_meth, iq_width, exponent);
                            /* Add to tree. */
                            proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_q, tvb, bit_offset/8, (iq_width+7)/8, value, "#%u=%f", b, value);
                            bit_offset += iq_width;
                            proto_item_append_text(bfw_ti, "Q%u=%f)", b, value);
                        }

                        offset = (bit_offset+7)/8;
                    }
                    else {
                        /* No weights... */

                        /* Reserved (1 bit) */
                        proto_tree_add_bits_item(extension_tree, hf_oran_reserved, tvb, offset*8, 1, ENC_BIG_ENDIAN);
                        /* beamID (15 bits) */
                        proto_tree_add_item_ret_uint(extension_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN, &beamId);
                        proto_item_append_text(port_ti, " (beamId=%u)", beamId);
                        offset += 2;
                    }

                    /* Set length of this port entry */
                    proto_item_set_len(port_ti, offset-port_start_offset);
                }
                break;
            }

            case 20:  /* Puncturing extension */
            {
                /* numPuncPatterns */
                uint32_t numPuncPatterns;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_numPuncPatterns, tvb, offset, 1, ENC_BIG_ENDIAN, &numPuncPatterns);
                offset += 1;

                /* Add each puncturing pattern */
                for (uint32_t n=0; n < numPuncPatterns; n++) {
                    unsigned pattern_start_offset = offset;

                    /* Subtree for this puncturing pattern */
                    proto_item *pattern_ti = proto_tree_add_string_format(extension_tree, hf_oran_puncPattern,
                                                                         tvb, offset, 0,
                                                                         "", "Puncturing Pattern: %u/%u", n+1, hf_oran_numPuncPatterns);
                    proto_tree *pattern_tree = proto_item_add_subtree(pattern_ti, ett_oran_punc_pattern);

                    /* SymbolMask (14 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_symbolMask_ext20, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 1;
                    /* startPuncPrb (10 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_startPuncPrb, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 2;
                    /* numPuncPrb (8 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_numPuncPrb, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    /* puncReMask (12 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_puncReMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 1;
                    /* rb (1 bit) */
                    proto_tree_add_item(pattern_tree, hf_oran_rb, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* reserved (2 bits? - spec says 1) */
                    proto_tree_add_bits_item(pattern_tree, hf_oran_reserved, tvb, offset*8, 2, ENC_BIG_ENDIAN);
                    /* rbgIncl */
                    bool rbgIncl;
                    proto_tree_add_item_ret_boolean(pattern_tree, hf_oran_RbgIncl, tvb, offset, 1, ENC_BIG_ENDIAN, &rbgIncl);
                    offset += 1;

                    if (rbgIncl) {
                        /* reserved (1 bit) */
                        proto_tree_add_item(pattern_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                        /* rbgSize(3 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_rbgSize, tvb, offset, 1, ENC_BIG_ENDIAN);
                        /* rbgMask (28 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_rbgMask, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                    }

                    proto_item_set_len(pattern_ti, offset-pattern_start_offset);
                }

                break;
            }
            case 21:  /* Variable PRB group size for channel information */
            {
                /* ciPrbGroupSize */
                uint32_t ci_prb_group_size;
                proto_item *prb_group_size_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_ci_prb_group_size, tvb, offset, 1, ENC_BIG_ENDIAN, &ci_prb_group_size);
                switch (ci_prb_group_size) {
                    case 0:
                    case 1:
                    case 255:
                        /* Reserved value */
                        expert_add_info_format(pinfo, prb_group_size_ti, &ei_oran_ci_prb_group_size_reserved,
                                               "SE 11 ciPrbGroupSize is reserved value %u - must be 2-254",
                                               ci_prb_group_size);

                        break;
                    default:
                        ext11_settings.ext21_set = true;
                        ext11_settings.ext21_ci_prb_group_size = ci_prb_group_size;

                        if (numPrbc ==0) {
                            expert_add_info(pinfo, numprbc_ti, &ei_oran_numprbc_ext21_zero);
                        }
                        break;
                }

                offset += 1;
                /* reserved (8 bits) */
                proto_tree_add_bits_item(extension_tree, hf_oran_reserved, tvb, offset*8, 8, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            }

            case 22:  /* ACK/NACK request */
                proto_tree_add_item(extension_tree, hf_oran_ack_nack_req_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            default:
                /* Other/unexpected extension types. */
                break;
        }

        /* Check offset compared with extlen.  There should be 0-3 bytes of padding */
        int num_padding_bytes = (extension_start_offset + (extlen*4) - offset);
        if ((num_padding_bytes<0) || (num_padding_bytes>3)) {
            expert_add_info_format(pinfo, extlen_ti, &ei_oran_extlen_wrong,
                                   "extlen signalled %u bytes (+ 0-3 bytes padding), but %u were dissected",
                                   extlen*4, offset-extension_start_offset);
        }

        /* Move offset to beyond signalled length of extension */
        offset = extension_start_offset + (extlen*4);

        /* Set length of extension header. */
        proto_item_set_len(extension_ti, extlen*4);
    }

    /* Set extent of overall section */
    proto_item_set_len(sectionHeading, offset);

    return offset;
}

/* Dissect udCompHdr (user data compression header, 7.5.2.10) */
/* bit_width and comp_meth are out params */
static int dissect_udcomphdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset,
                             unsigned *bit_width, unsigned *comp_meth)
{
    /* Subtree */
    proto_item *udcomphdr_ti = proto_tree_add_string_format(tree, hf_oran_udCompHdr,
                                                         tvb, offset, 1, "",
                                                         "udCompHdr");
    proto_tree *udcomphdr_tree = proto_item_add_subtree(udcomphdr_ti, ett_oran_udcomphdr);

    /* udIqWidth */
    uint32_t hdr_iq_width;
    proto_item *iq_width_item = proto_tree_add_item_ret_uint(udcomphdr_tree, hf_oran_udCompHdrIqWidth , tvb, offset, 1, ENC_NA, &hdr_iq_width);
    *bit_width = (hdr_iq_width) ? hdr_iq_width : 16;
    proto_item_append_text(iq_width_item, " (%u bits)", *bit_width);

    /* udCompMeth */
    uint32_t ud_comp_meth;
    proto_tree_add_item_ret_uint(udcomphdr_tree, hf_oran_udCompHdrMeth, tvb, offset, 1, ENC_NA, &ud_comp_meth);
    if (comp_meth) {
        *comp_meth = ud_comp_meth;
    }
    offset += 1;

    /* Summary */
    proto_item_append_text(udcomphdr_ti, " (IqWidth=%u, udCompMeth=%s)",
                           *bit_width, rval_to_str_const(ud_comp_meth, ud_comp_header_meth, "Unknown"));
    return offset;
}

/* Dissect ciCompHdr (channel information compression header, 7.5.2.15) */
/* bit_width and comp_meth are out params */
static int dissect_cicomphdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset,
                             unsigned *bit_width, unsigned *comp_meth, uint8_t *comp_opt)
{
    /* Subtree */
    proto_item *cicomphdr_ti = proto_tree_add_string_format(tree, hf_oran_ciCompHdr,
                                                         tvb, offset, 1, "",
                                                         "ciCompHdr");
    proto_tree *cicomphdr_tree = proto_item_add_subtree(cicomphdr_ti, ett_oran_cicomphdr);

    /* ciIqWidth */
    uint32_t hdr_iq_width;
    proto_item *iq_width_item = proto_tree_add_item_ret_uint(cicomphdr_tree, hf_oran_ciCompHdrIqWidth , tvb, offset, 1, ENC_NA, &hdr_iq_width);
    hdr_iq_width = (hdr_iq_width) ? hdr_iq_width : 16;
    if (bit_width) {
        *bit_width = hdr_iq_width;
    }
    proto_item_append_text(iq_width_item, " (%u bits)", hdr_iq_width);

    /* ciCompMeth */
    uint32_t ci_comp_meth;
    proto_tree_add_item_ret_uint(cicomphdr_tree, hf_oran_ciCompHdrMeth, tvb, offset, 1, ENC_NA, &ci_comp_meth);
    if (comp_meth) {
        *comp_meth = ci_comp_meth;
    }

    /* ciCompOpt */
    uint32_t opt;
    proto_tree_add_item_ret_uint(cicomphdr_tree, hf_oran_ciCompOpt, tvb, offset, 1, ENC_NA, &opt);
    *comp_opt = opt;
    offset += 1;

    /* Summary */
    proto_item_append_text(cicomphdr_ti, " (IqWidth=%u, ciCompMeth=%s, ciCompOpt=%s)",
                           hdr_iq_width,
                           rval_to_str_const(ci_comp_meth, ud_comp_header_meth, "Unknown"),
                           (*comp_opt) ?  "compression per PRB" : "compression per UE");
    return offset;
}


/* Control plane dissector (section 7). */
static int dissect_oran_c(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    unsigned offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "O-RAN-FH-C");
    col_set_str(pinfo->cinfo, COL_INFO, "C-Plane");

    /* Create display subtree for the protocol */
    proto_item *protocol_item = proto_tree_add_item(tree, proto_oran, tvb, 0, -1, ENC_NA);
    proto_item_append_text(protocol_item, "-C");
    proto_tree *oran_tree = proto_item_add_subtree(protocol_item, ett_oran);

    uint16_t eAxC;
    addPcOrRtcid(tvb, oran_tree, &offset, "ecpriRtcid", &eAxC);

    if (!PINFO_FD_VISITED(pinfo)) {
        /* TODO: create or update conversation for stream eAxC */
    }
    else {
        /* TODO: show stored state for this stream */
    }

    /* Message identifier */
    addSeqid(tvb, oran_tree, &offset);

    proto_item *sectionHeading;

    /* Section subtree */
    int section_tree_offset = offset;
    proto_tree *section_tree = proto_tree_add_subtree(oran_tree, tvb, offset, 2, ett_oran_section_type, &sectionHeading, "C-Plane Section Type ");

    /* dataDirection */
    uint32_t direction = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_data_direction, tvb, offset, 1, ENC_NA, &direction);
    /* payloadVersion */
    proto_tree_add_item(section_tree, hf_oran_payload_version, tvb, offset, 1, ENC_NA);
    /* payloadVersion */
    proto_tree_add_item(section_tree, hf_oran_filter_index, tvb, offset, 1, ENC_NA);
    offset += 1;

    unsigned ref_a_offset = offset;
    /* frameId */
    uint32_t frameId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_frame_id, tvb, offset, 1, ENC_NA, &frameId);
    offset += 1;

    /* subframeId */
    uint32_t subframeId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_subframe_id, tvb, offset, 1, ENC_NA, &subframeId);
    /* slotId */
    uint32_t slotId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN, &slotId);
    offset++;
    /* startSymbolId */
    uint32_t startSymbolId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_start_symbol_id, tvb, offset, 1, ENC_NA, &startSymbolId);
    offset++;

    char id[16];
    snprintf(id, 16, "%d-%d-%d", frameId, subframeId, slotId);
    proto_item *pi = proto_tree_add_string(section_tree, hf_oran_refa, tvb, ref_a_offset, 3, id);
    proto_item_set_generated(pi);

    /* numberOfSections */
    uint32_t nSections = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_numberOfSections, tvb, offset, 1, ENC_NA, &nSections);
    offset += 1;

    /* sectionType */
    uint32_t sectionType = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_sectionType, tvb, offset, 1, ENC_NA, &sectionType);
    offset += 1;

    /* Section-specific fields (white entries in Section Type diagrams) */
    unsigned bit_width = 0;
    unsigned ci_comp_method = 0;
    uint8_t ci_comp_opt = 0;

    uint32_t scs, slots_per_subframe;
    uint32_t num_ues = 0;
    proto_item *ti;

    switch (sectionType) {
        case SEC_C_UNUSED_RB:   /* Section Type 0 */
            /* timeOffset */
            proto_tree_add_item(section_tree, hf_oran_timeOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* frameStructure */
            proto_tree_add_item(section_tree, hf_oran_frameStructure_fft, tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(section_tree, hf_oran_frameStructure_subcarrier_spacing, tvb, offset, 1, ENC_NA, &scs);
            /* slots_per_subframe = 1 << scs; */
            offset += 1;

            /* cpLength */
            proto_tree_add_item(section_tree, hf_oran_cpLength, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* reserved */
            proto_tree_add_item(section_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case SEC_C_NORMAL:      /* Section Type 1 */
        case SEC_C_UE_SCHED:    /* Section Type 5 */
            /* udCompHdr */
            offset = dissect_udcomphdr(tvb, pinfo, section_tree, offset, &bit_width, NULL);
            /* reserved */
            proto_tree_add_item(section_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case SEC_C_PRACH:       /* Section Type 3 */
            /* timeOffset */
            proto_tree_add_item(section_tree, hf_oran_timeOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* frameStructure */
            proto_tree_add_item(section_tree, hf_oran_frameStructure_fft, tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(section_tree, hf_oran_frameStructure_subcarrier_spacing, tvb, offset, 1, ENC_NA, &scs);
            slots_per_subframe = 1 << scs;
            ti = proto_tree_add_uint(section_tree, hf_oran_slot_within_frame, tvb, 0, 0, (slots_per_subframe*subframeId) + slotId);
            proto_item_set_generated(ti);
            offset += 1;
            /* cpLength */
            proto_tree_add_item(section_tree, hf_oran_cpLength, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* udCompHdr */
            offset = dissect_udcomphdr(tvb, pinfo, section_tree, offset, &bit_width, NULL);
            break;

        case SEC_C_CH_INFO:
            /* numberOfUEs */
            proto_tree_add_item_ret_uint(section_tree, hf_oran_numberOfUEs, tvb, offset, 1, ENC_NA, &num_ues);
            offset += 1;
            /* ciCompHdr (was reserved) */
            offset = dissect_cicomphdr(tvb, pinfo, section_tree, offset, &bit_width, &ci_comp_method, &ci_comp_opt);

            /* Number of sections may not be filled in, so set to the number of UEs */
            if (nSections == 0) {
                nSections = num_ues;
            }
            break;

        case SEC_C_RSVD2:
        case SEC_C_LAA:
            /* TODO: */
            break;
    };

    proto_item_append_text(sectionHeading, "%d, %s, Frame: %d, Subframe: %d, Slot: %d, StartSymbol: %d",
                           sectionType, val_to_str_const(direction, data_direction_vals, "Unknown"),
                           frameId, subframeId, slotId, startSymbolId);
    write_pdu_label_and_info(protocol_item, NULL, pinfo, ", Type: %d %s", sectionType,
                             rval_to_str_const(sectionType, section_types_short, "Unknown"));

    /* Set actual length of C-Plane section. */
    proto_item_set_len(section_tree, offset - section_tree_offset);


    /* Dissect each C section */
    for (uint32_t i = 0; i < nSections; ++i) {
        tvbuff_t *section_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);
        offset += dissect_oran_c_section(section_tvb, oran_tree, pinfo, sectionType, protocol_item,
                                         bit_width, ci_comp_method, ci_comp_opt);
    }

    /* Expert error if we are short of tvb by > 3 bytes */
    if (tvb_reported_length_remaining(tvb, offset) > 3) {
        expert_add_info_format(pinfo, protocol_item, &ei_oran_frame_length,
                               "%u bytes remain at end of frame - should be 0-3",
                               tvb_reported_length_remaining(tvb, offset));
    }

    return tvb_captured_length(tvb);
}

/* User plane dissector (section 8) */
static int
dissect_oran_u(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "O-RAN-FH-U");
    col_set_str(pinfo->cinfo, COL_INFO, "U-Plane");

    /* Create display subtree for the protocol */
    proto_item *protocol_item = proto_tree_add_item(tree, proto_oran, tvb, 0, -1, ENC_NA);
    proto_item_append_text(protocol_item, "-U");
    proto_tree *oran_tree = proto_item_add_subtree(protocol_item, ett_oran);

    /* Transport header */
    /* Real-time control data / IQ data transfer message series identifier */
    uint16_t eAxC;
    addPcOrRtcid(tvb, oran_tree, &offset, "ecpriPcid", &eAxC);

    if (!PINFO_FD_VISITED(pinfo)) {
        /* TODO: create or update conversation for stream eAxC */
    }
    else {
        /* TODO: show stored state for this stream */
    }

    /* Message identifier */
    addSeqid(tvb, oran_tree, &offset);

    /* Common header for time reference */
    proto_item *timingHeader;
    proto_tree *timing_header_tree = proto_tree_add_subtree(oran_tree, tvb, offset, 4, ett_oran_u_timing, &timingHeader, "Timing header");

    /* dataDirection */
    uint32_t direction;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_data_direction, tvb, offset, 1, ENC_NA, &direction);
    /* payloadVersion */
    proto_tree_add_item(timing_header_tree, hf_oran_payload_version, tvb, offset, 1, ENC_NA);
    /* filterIndex */
    proto_tree_add_item(timing_header_tree, hf_oran_filter_index, tvb, offset, 1, ENC_NA);
    offset += 1;

    int ref_a_offset = offset;

    /* frameId */
    uint32_t frameId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_frame_id, tvb, offset, 1, ENC_NA, &frameId);
    offset += 1;

    /* subframeId */
    uint32_t subframeId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_subframe_id, tvb, offset, 1, ENC_NA, &subframeId);
    /* slotId */
    uint32_t slotId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN, &slotId);
    offset++;
    /* symbolId */
    uint32_t symbolId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_symbolId, tvb, offset, 1, ENC_NA, &symbolId);
    offset++;

    char id[16];
    snprintf(id, 16, "%d-%d-%d", frameId, subframeId, slotId);
    proto_item *pi = proto_tree_add_string(timing_header_tree, hf_oran_refa, tvb, ref_a_offset, 3, id);
    proto_item_set_generated(pi);

    proto_item_append_text(timingHeader, " %s, Frame: %d, Subframe: %d, Slot: %d, Symbol: %d",
        val_to_str_const(direction, data_direction_vals, "Unknown"), frameId, subframeId, slotId, symbolId);

    unsigned sample_bit_width;
    int compression;
    bool includeUdCompHeader;

    if (direction == DIR_UPLINK) {
        sample_bit_width = pref_sample_bit_width_uplink;
        compression = pref_iqCompressionUplink;
        includeUdCompHeader = pref_includeUdCompHeaderUplink;
    } else {
        sample_bit_width = pref_sample_bit_width_downlink;
        compression = pref_iqCompressionDownlink;
        includeUdCompHeader = pref_includeUdCompHeaderDownlink;
    }

    /* Need a valid value (e.g. 9, 14).  0 definitely won't work, as won't progress around loop! */
    if (sample_bit_width == 0) {
        expert_add_info_format(pinfo, protocol_item, &ei_oran_invalid_sample_bit_width,
                               "%cL Sample bit width from preference (%u) not valid, so can't decode sections",
                               (direction == DIR_UPLINK) ? 'U' : 'D', sample_bit_width);
        return offset;
    }

    unsigned bytesLeft;

    unsigned number_of_sections = 0;
    unsigned nBytesPerPrb;

    do {
        unsigned section_start_offet = offset;
        proto_item *sectionHeading;
        proto_tree *section_tree = proto_tree_add_subtree(oran_tree, tvb, offset, 0, ett_oran_u_section, &sectionHeading, "Section");

        /* Section Header fields (darker green part) */

        /* sectionId */
        uint32_t sectionId = 0;
        proto_item *ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_section_id, tvb, offset, 2, ENC_BIG_ENDIAN, &sectionId);
        if (sectionId == 4095) {
            proto_item_append_text(ti, " (not default coupling C/U planes using sectionId)");
        }
        offset++;
        /* rb */
        uint32_t rb;
        proto_tree_add_item_ret_uint(section_tree, hf_oran_rb, tvb, offset, 1, ENC_NA, &rb);
        /* symInc */
        proto_tree_add_item(section_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA);
        /* startPrbu */
        uint32_t startPrbu = 0;
        proto_tree_add_item_ret_uint(section_tree, hf_oran_startPrbu, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbu);
        offset += 2;

        /* numPrbu */
        uint32_t numPrbu = 0;
        proto_tree_add_item_ret_uint(section_tree, hf_oran_numPrbu, tvb, offset, 1, ENC_NA, &numPrbu);
        offset += 1;

        if (includeUdCompHeader) {
            /* 7.5.2.10 */
            /* Extract these values to inform how wide IQ samples in each PRB will be. */
            offset = dissect_udcomphdr(tvb, pinfo, section_tree, offset, &sample_bit_width, &compression);

            /* Not part of udCompHdr */
            proto_tree_add_item(section_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else {
            /* Showing comp values from prefs */
            /* iqWidth */
            proto_item *iq_width_item = proto_tree_add_uint(section_tree, hf_oran_udCompHdrIqWidth_pref, tvb, 0, 0, sample_bit_width);
            proto_item_append_text(iq_width_item, " (from preferences)");
            proto_item_set_generated(iq_width_item);

            /* udCompMethod */
            proto_item *ud_comp_meth_item = proto_tree_add_uint(section_tree, hf_oran_udCompHdrMeth_pref, tvb, 0, 0, compression);
            proto_item_append_text(ud_comp_meth_item, " (from preferences)");
            proto_item_set_generated(ud_comp_meth_item);
        }

        /* Work this out each time, as udCompHdr may have changed things */
        unsigned nBytesForSamples = (sample_bit_width * 12 * 2) / 8;
        nBytesPerPrb = nBytesForSamples;
        if ((compression != COMP_NONE) && (compression != COMP_MODULATION)) {
            nBytesPerPrb++;         /* 1 extra byte reserved/exponent */
        }


        write_section_info(sectionHeading, pinfo, protocol_item, sectionId, startPrbu, numPrbu, rb);

        /* TODO: should this use the same pref as c-plane? */
        if (numPrbu == 0) {
            /* Special case for all PRBs (NR: the total number of PRBs may be > 255) */
            numPrbu = pref_data_plane_section_total_rbs;
            startPrbu = 0;  /* may already be 0... */
        }

        for (unsigned i = 0; i < numPrbu; i++) {
            /* Create subtree */
            proto_item *prbHeading = proto_tree_add_string_format(section_tree, hf_oran_samples_prb,
                                                                  tvb, offset, nBytesPerPrb,
                                                                  "", "PRB");
            proto_tree *rb_tree = proto_item_add_subtree(prbHeading, ett_oran_u_prb);
            uint32_t exponent = 0;
            if ((compression != COMP_NONE) && (compression != COMP_MODULATION)) {
                proto_tree_add_item(rb_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
                proto_tree_add_item_ret_uint(rb_tree, hf_oran_exponent, tvb, offset, 1, ENC_BIG_ENDIAN, &exponent);
                offset += 1;
            }
            /* Show PRB number in root */
            proto_item_append_text(prbHeading, " %u", startPrbu + i*(1+rb));


            proto_tree_add_item(rb_tree, hf_oran_iq_user_data, tvb, offset, nBytesForSamples, ENC_NA);

            if (pref_showIQSampleValues) {
                /* Individual values */
                unsigned samples_offset = offset*8;
                unsigned sample_number = 0;
                for (unsigned n = 0; n<12; n++) {
                    /* I */
                    unsigned i_bits = tvb_get_bits(tvb, samples_offset, sample_bit_width, ENC_BIG_ENDIAN);
                    float i_value = decompress_value(i_bits, COMP_BLOCK_FP, sample_bit_width, exponent);
                    unsigned sample_len_in_bytes = ((samples_offset%8)+sample_bit_width+7)/8;
                    proto_item *i_ti = proto_tree_add_float(rb_tree, hf_oran_iSample, tvb, samples_offset/8, sample_len_in_bytes, i_value);
                    proto_item_set_text(i_ti, "iSample: %0.12f  0x%04x (iSample-%u in the PRB)", i_value, i_bits, sample_number);
                    samples_offset += sample_bit_width;
                    /* Q */
                    unsigned q_bits = tvb_get_bits(tvb, samples_offset, sample_bit_width, ENC_BIG_ENDIAN);
                    float q_value = decompress_value(q_bits, COMP_BLOCK_FP, sample_bit_width, exponent);
                    sample_len_in_bytes = ((samples_offset%8)+sample_bit_width+7)/8;
                    proto_item *q_ti = proto_tree_add_float(rb_tree, hf_oran_qSample, tvb, samples_offset/8, sample_len_in_bytes, q_value);
                    proto_item_set_text(q_ti, "qSample: %0.12f  0x%04x (qSample-%u in the PRB)", q_value, q_bits, sample_number);
                    samples_offset += sample_bit_width;

                    sample_number++;
                }
                proto_item_append_text(prbHeading, " (%u samples)", sample_number);
            }

            offset += nBytesForSamples;

            /* Set length of overall section */
            proto_item_set_len(sectionHeading, offset-section_start_offet);
        }
        bytesLeft = tvb_captured_length(tvb) - offset;
        number_of_sections++;
    } while (bytesLeft >= (4 + nBytesPerPrb));     /* FIXME: bad heuristic */

    /* Show number of sections found */
    proto_item *ti = proto_tree_add_uint(oran_tree, hf_oran_numberOfSections, tvb, 0, 0, number_of_sections);
    proto_item_set_generated(ti);

    /* Expert error if we are short of tvb by > 3 bytes */
    if (tvb_reported_length_remaining(tvb, offset) > 3) {
        expert_add_info_format(pinfo, protocol_item, &ei_oran_frame_length,
                               "%u bytes remain at end of frame - should be 0-3",
                               tvb_reported_length_remaining(tvb, offset));
    }

    return tvb_captured_length(tvb);
}


/*****************************/
/* Main dissection function. */
/* N.B. ecpri message type passed in as 'data' arg by eCPRI dissector */
static int
dissect_oran(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t ecpri_message_type = *(uint32_t *)data;

    switch (ecpri_message_type) {
        case ECPRI_MT_IQ_DATA:
            return dissect_oran_u(tvb, pinfo, tree, data);
        case ECPRI_MT_RT_CTRL_DATA:
            return dissect_oran_c(tvb, pinfo, tree, data);

        default:
            /* Not dissecting other types - assume these are handled by eCPRI dissector */
            return 0;
    }
}


/* Register the protocol with Wireshark. */
void
proto_register_oran(void)
{
    static hf_register_info hf[] = {

       /* Section 3.1.3.1.6 */
       { &hf_oran_du_port_id,
         { "DU Port ID", "oran_fh_cus.du_port_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           "Width set in dissector preference", HFILL }
       },

       /* Section 3.1.3.1.6 */
       { &hf_oran_bandsector_id,
         { "BandSector ID", "oran_fh_cus.bandsector_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           "Width set in dissector preference", HFILL }
       },

       /* Section 3.1.3.1.6 */
       { &hf_oran_cc_id,
         { "CC ID", "oran_fh_cus.cc_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           "Width set in dissector preference", HFILL }
       },

        /* Section 3.1.3.1.6 */
        { &hf_oran_ru_port_id,
          { "RU Port ID", "oran_fh_cus.ru_port_id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Width set in dissector preference", HFILL }
        },

        /* Section 3.1.3.1.7 */
        { &hf_oran_sequence_id,
          { "Sequence ID", "oran_fh_cus.sequence_id",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "The Sequence ID wraps around individually per c_eAxC",
            HFILL }
        },

        /* Section 3.1.3.1.7 */
        { &hf_oran_e_bit,
          { "E Bit", "oran_fh_cus.e_bit",
            FT_UINT8, BASE_DEC,
            VALS(e_bit), 0x80,
            "One bit (the \"E-bit\") is reserved to indicate the last message of a subsequence",
            HFILL }
        },

        /* Section 3.1.3.1.7 */
        { &hf_oran_subsequence_id,
          { "Subsequence ID", "oran_fh_cus.subsequence_id",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            "The subsequence identifier",
            HFILL }
        },

        /* Section 7.5.2.1 */
        { &hf_oran_data_direction,
          { "Data Direction", "oran_fh_cus.data_direction",
            FT_UINT8, BASE_DEC,
            VALS(data_direction_vals), 0x80,
            "gNB data direction",
            HFILL }
        },

        /* Section 7.5.2.2 */
        { &hf_oran_payload_version,
         {"Payload Version", "oran_fh_cus.payloadVersion",
          FT_UINT8, BASE_DEC,
          NULL, 0x70,
          "Payload protocol version the following IEs",
          HFILL}
        },

        /* Section 7.5.2.2 */
        {&hf_oran_filter_index,
         {"Filter Index", "oran_fh_cus.filterIndex",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(filter_indices), 0x0f,
          "used between IQ data and air interface, both in DL and UL",
          HFILL}
        },

        /* Section 7.5.2.4 */
        {&hf_oran_frame_id,
         {"Frame ID", "oran_fh_cus.frameId",
          FT_UINT8, BASE_DEC,
          NULL, 0x00,
          "A counter for 10 ms frames (wrapping period 2.56 seconds)",
          HFILL}
        },

        /* Section 7.5.2.5 */
        {&hf_oran_subframe_id,
         {"Subframe ID", "oran_fh_cus.subframe_id",
          FT_UINT8, BASE_DEC,
          NULL, 0xf0,
          "A counter for 1 ms sub-frames within 10ms frame",
          HFILL}
        },

        /* Section 7.5.2.6 */
        {&hf_oran_slot_id,
         {"Slot ID", "oran_fh_cus.slotId",
          FT_UINT16, BASE_DEC,
          NULL, 0x0fc0,
          "Slot number within a 1ms sub-frame",
          HFILL}
        },

        /* Generated for convenience */
        {&hf_oran_slot_within_frame,
         {"Slot within frame", "oran_fh_cus.slot-within-frame",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
         "Slot within frame, to match DCT logs",
         HFILL}
        },

        /* Section 7.5.2.7 */
        {&hf_oran_start_symbol_id,
         {"Start Symbol ID", "oran_fh_cus.startSymbolId",
          FT_UINT8, BASE_DEC,
          NULL, 0x3f,
          "The first symbol number within slot, to "
          "which the information of this message is applies",
          HFILL}
        },

        /* Section 7.5.2.8 */
        {&hf_oran_numberOfSections,
         {"Number of Sections", "oran_fh_cus.numberOfSections",
          FT_UINT8, BASE_DEC,
          NULL, 0x00,
          "The number of section IDs included in this C-Plane message",
          HFILL}
        },

        /* Section 7.5.2.9 */
        {&hf_oran_sectionType,
         {"Section Type", "oran_fh_cus.sectionType",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(section_types), 0x00,
          "Determines the characteristics of U-plane data",
          HFILL}
        },

        /* Section 7.5.2.10 */
        {&hf_oran_udCompHdr,
         {"udCompHdr", "oran_fh_cus.udCompHdr",
          FT_STRING, BASE_NONE,
          NULL, 0x00,
          NULL,
          HFILL}
        },

        /* Section 7.5.2.11 */
        {&hf_oran_numberOfUEs,
         {"Number Of UEs", "oran_fh_cus.numberOfUEs",
          FT_UINT8, BASE_DEC,
          NULL, 0x00,
          "Applies to section type 6 messages",
          HFILL}
        },

        /* Section 7.5.2.12 */
        {&hf_oran_timeOffset,
         {"Time Offset", "oran_fh_cus.timeOffset",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          "from start of the slot to CP",
          HFILL}
        },

        /* Section 7.5.2.13 */
        { &hf_oran_frameStructure_fft,
          { "FFT Size", "oran_fh_cus.frameStructure.fft",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(frame_structure_fft), 0xf0,
            "The FFT/iFFT size being used for all IQ data processing related "
            "to this message",
            HFILL }
        },

        /* Section 7.5.2.13 */
        { &hf_oran_frameStructure_subcarrier_spacing,
          { "Subcarrier Spacing", "oran_fh_cus.frameStructure.spacing",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(subcarrier_spacings), 0x0f,
            "The sub carrier spacing "
            "as well as the number of slots per 1ms sub-frame according "
            "to 3GPP TS 38.211, taking for completeness also 3GPP TS 36.211 "
            "into account. The parameter \u03bc=0...5 from 3GPP TS 38.211 is "
            "extended to apply for PRACH processing",
            HFILL }
        },

        /* Section 7.5.2.14 */
        {&hf_oran_cpLength,
         {"cpLength", "oran_fh_cus.cpLength",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          "cyclic prefix length",
          HFILL}
        },

        /* Section 7.5.3.1 */
        {&hf_oran_section_id,
         {"sectionId", "oran_fh_cus.sectionId",
          FT_UINT16, BASE_DEC,
          NULL, 0xfff0,
          "section identifier of data",
          HFILL}
        },

        /* Section 7.5.3.2 */
        {&hf_oran_rb,
         {"rb", "oran_fh_cus.rb",
          FT_UINT8, BASE_DEC,
          VALS(rb_vals), 0x08,
          "resource block indicator",
          HFILL}
        },

        /* Section 7.5.5.3 */
        {&hf_oran_symInc,
         {"symInc", "oran_fh_cus.symInc",
          FT_UINT8, BASE_DEC,
          VALS(sym_inc_vals), 0x04,
          "Symbol Number Increment Command",
          HFILL}
        },

        /* Section 7.5.3.4 */
        {&hf_oran_startPrbc,
         {"startPrbc", "oran_fh_cus.startPrbc",
          FT_UINT16, BASE_DEC,
          NULL, 0x03ff,
          "Starting PRB of Control Plane Section",
          HFILL}
        },

        /* Section 7.5.3.5 */
        {&hf_oran_reMask,
         {"RE Mask", "oran_fh_cus.reMask",
          FT_UINT16, BASE_HEX,
          NULL, 0xfff0,
          "The Resource Element (RE) mask within a "
          "PRB. Each bit setting in the reMask indicates if the section control "
          "is applicable to the RE sent in U-Plane messages (0=not applicable; "
          "1=applicable)",
          HFILL}
        },

        /* Section 7.5.3.6 */
        {&hf_oran_numPrbc,
         {"numPrbc", "oran_fh_cus.numPrbc",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "Number of contiguous PRBs per data section description",
          HFILL}
        },

        /* Section 7.5.3.7 */
        {&hf_oran_numSymbol,
         {"Number of Symbols", "oran_fh_cus.numSymbol",
          FT_UINT8, BASE_DEC,
          NULL, 0x0f,
          "Defines number of symbols to which the section "
          "control is applicable. At minimum, the section control shall be "
          "applicable to at least one symbol. However, possible optimizations "
          "could allow for several (up to 14) symbols, if e.g., all 14 "
          "symbols use the same beam ID",
          HFILL}
        },

        /* Section 7.5.3.8 */
        {&hf_oran_ef,
         {"Extension Flag", "oran_fh_cus.ef",
          FT_BOOLEAN, 8,
          NULL, 0x80,
         "Indicates if more section extensions follow",
          HFILL}
        },

        /* Section 7.5.3.9 */
        {&hf_oran_beamId,
         {"Beam ID", "oran_fh_cus.beamId",
          FT_UINT16, BASE_DEC,
          NULL, 0x7fff,
          "Defines the beam pattern to be applied to the U-Plane data",
          HFILL}
        },

        /* Section 7.5.3.8 */
        {&hf_oran_extension,
         {"Extension", "oran_fh_cus.extension",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "Section extension type (ef)",
          HFILL}
        },

        /* Section 7.6.2.1 */
        {&hf_oran_exttype,
         {"extType", "oran_fh_cus.extType",
          FT_UINT8, BASE_DEC,
          VALS(exttype_vals), 0x7f,
          "The extension type, which provides additional parameters specific to subject data extension",
          HFILL}
        },

        /* Section 7.6.2.3 */
        {&hf_oran_extlen,
         {"extLen", "oran_fh_cus.extLen",
         FT_UINT16, BASE_DEC,
         NULL, 0x0,
         "Extension length in 32-bit words",
         HFILL}
        },

        /* Section 7.7.1 */
        {&hf_oran_bfw,
         {"bfw", "oran_fh_cus.bfw",
         FT_STRING, BASE_NONE,
         NULL, 0x0,
         "Set of weights for a particular antenna",
         HFILL}
        },
        {&hf_oran_bfw_bundle,
         {"Bundle", "oran_fh_cus.bfw.bundle",
         FT_STRING, BASE_NONE,
         NULL, 0x0,
         "Bundle of BFWs",
         HFILL}
        },
        {&hf_oran_bfw_bundle_id,
         {"Bundle Id", "oran_fh_cus.bfw.bundleId",
         FT_UINT32, BASE_DEC,
         NULL, 0x0,
         NULL,
         HFILL}
        },
        /* Section 7.7.1.4 */
        {&hf_oran_bfw_i,
         {"bfwI", "oran_fh_cus.bfwI",
         FT_FLOAT, BASE_NONE,
         NULL, 0x0,
         "In-phase",
         HFILL}
        },
        /* Section 7.7.1.5 */
        {&hf_oran_bfw_q,
         {"bfwQ", "oran_fh_cus.bfwQ",
         FT_FLOAT, BASE_NONE,
         NULL, 0x0,
         "Quadrature",
         HFILL}
        },

        /* Section 7.5.3.10 */
        {&hf_oran_ueId,
         {"UE ID", "oran_fh_cus.ueId",
          FT_UINT16, BASE_HEX_DEC,
          NULL, 0x7fff,
          "applies to section contents",
          HFILL}
        },

        /* Section 7.5.3.11 */
        {&hf_oran_freqOffset,
         {"Frequency Offset", "oran_fh_cus.freqOffset",
          FT_UINT24, BASE_DEC,
          NULL, 0x0,
          "with respect to the "
          "carrier center frequency before additional filtering",
          HFILL}
        },

        /* Section 7.5.3.12 */
        {&hf_oran_regularizationFactor,
         {"Regularization Factor", "oran_fh_cus.regularizationFactor",
          FT_INT16, BASE_DEC,
          NULL, 0x0,
          "related to section type 6",
          HFILL}
        },

        /* Section 7.5.3.14 */
        {&hf_oran_laaMsgType,
         {"LAA Message Type", "oran_fh_cus.laaMsgType",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(laaMsgTypes), 0xf0,
          NULL,
          HFILL}
        },

        /* Section 7.5.3.15 */
        {&hf_oran_laaMsgLen,
         {"LAA Message Length", "oran_fh_cus.laaMsgLen",
          FT_UINT8, BASE_DEC,
          NULL, 0x0f,
          "number of 32-bit words in the LAA section",
          HFILL}
        },

        /* Section 7.5.3.16 */
        {&hf_oran_lbtHandle,
         {"LBT Handle", "oran_fh_cus.lbtHandle",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          "included in the configuration request message",
          HFILL}
         },

        /* Section 7.5.3.17 */
        {&hf_oran_lbtDeferFactor,
         {"Defer Factor", "oran_fh_cus.lbtDeferFactor",
          FT_UINT8, BASE_DEC,
          NULL, 0x1c,
          "Defer factor in sensing slots as described in 3GPP TS 36.213 "
          "Section 15.1.1. This parameter is used for LBT CAT 4 and can take "
          "one of three values: {1, 3, 7} based on the priority class. Four "
          "priority classes are defined in 3GPP TS 36.213",
          HFILL}
        },

        /* Section 7.5.3.18 */
        {&hf_oran_lbtBackoffCounter,
         {"Backoff Counter", "oran_fh_cus.lbtBackoffCounter",
          FT_UINT16, BASE_DEC,
          NULL, 0x03ff,
          "LBT backoff counter in sensing slots as described in 3GPP TS 36.213 "
          "Section 15.1.1. This parameter is used for LBT CAT 4 and can "
          "take one of nine values: {3, 7, 15, 31, 63, 127, 255, 511, 1023} "
          "based on the priority class. Four priority classes are defined "
          "in 3GPP TS 36.213",
          HFILL}
        },

        /* Section 7.5.3.19 */
        {&hf_oran_lbtOffset,
         {"LBT Offset", "oran_fh_cus.lbtOffset",
          FT_UINT16, BASE_DEC,
          NULL, 0xff80,
          "LBT start time in microseconds from the beginning of the subframe "
          "scheduled by this message",
          HFILL}
        },

        /* Section 7.5.3.20 */
        {&hf_oran_MCOT,
         {"Maximum Channel Occupancy Time", "oran_fh_cus.MCOT",
          FT_UINT8, BASE_DEC,
          NULL, 0xf0,
          "LTE TXOP duration in subframes as described in 3GPP TS 36.213 "
          "Section 15.1.1. The maximum values for this parameter are {2, 3, 8, "
          "10} based on the priority class. Four priority classes are "
          "defined in 3GPP TS 36.213",
          HFILL}
        },

        /* Section 7.5.3.21 */
        {&hf_oran_lbtMode,
         {"LBT Mode", "oran_fh_cus.lbtMode",
          FT_UINT8, BASE_DEC,
          VALS(lbtMode_vals), 0x0,
          NULL,
          HFILL}
        },

        /* Section 7.5.3.22 */
        {&hf_oran_lbtPdschRes,
         {"lbtPdschRes", "oran_fh_cus.lbtPdschRes",
          FT_UINT8, BASE_DEC,
          VALS(lbtPdschRes_vals), 0xc0,
          "LBT result of SFN/SF",
          HFILL}
        },

        /* Section 7.5.3.23 */
        {&hf_oran_sfStatus,
         {"sfStatus", "oran_fh_cus.sfStatus",
          FT_BOOLEAN, 8,
          TFS(&tfs_sfStatus), 0x10,
          "Indicates whether the subframe was dropped or transmitted",
          HFILL}
        },

        /* Section 7.5.3.22 */
        {&hf_oran_lbtDrsRes,
         {"lbtDrsRes", "oran_fh_cus.lbtDrsRes",
          FT_BOOLEAN, 8,
          TFS(&tfs_fail_success), 0x80,
          "Indicates whether the subframe was dropped or transmitted",
          HFILL}
        },

        /* Section 7.5.3.25 */
        {&hf_oran_initialPartialSF,
         {"Initial partial SF", "oran_fh_cus.initialPartialSF",
          FT_BOOLEAN, 8,
          TFS(&tfs_partial_full_sf), 0x40,
          "Indicates whether the initial SF in the LBT process is full or partial",
          HFILL}
        },

        /* Section 7.5.3.26. */
        {&hf_oran_lbtBufErr,
         {"lbtBufErr", "oran_fh_cus.lbtBufErr",
          FT_BOOLEAN, 8,
          TFS(&tfs_lbtBufErr), 0x80,
          "LBT buffer error",
          HFILL}
        },

        /* Section 7.5.3.27 */
        {&hf_oran_sfnSfEnd,
         {"SFN/SF End", "oran_fh_cus.sfnSfEnd",
          FT_UINT16, BASE_DEC,
          NULL, 0x0fff,
          "SFN/SF by which the DRS window must end",
          HFILL}
        },

        /* Section 7.5.3.28 */
        {&hf_oran_lbtCWConfig_H,
         {"lbtCWConfig_H", "oran_fh_cus.lbtCWConfig_H",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "HARQ parameters for congestion window management",
          HFILL}
        },

        /* Section 7.5.3.29 */
        {&hf_oran_lbtCWConfig_T,
         {"lbtCWConfig_T", "oran_fh_cus.lbtCWConfig_T",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "TB parameters for congestion window management",
          HFILL}
        },

        /* Section 7.5.3.30 */
        {&hf_oran_lbtTrafficClass,
         {"lbtTrafficClass", "oran_fh_cus.lbtTrafficClass",
          FT_UINT8, BASE_DEC,
          VALS(lbtTrafficClass_vals), 0x38,
          "Traffic class priority for congestion window management",
          HFILL}
        },

        /* Section 7.5.3.31 */
        {&hf_oran_lbtCWR_Rst,
         {"lbtCWR_Rst", "oran_fh_cus.lbtCWR_Rst",
          FT_BOOLEAN, 8,
          TFS(&tfs_fail_success), 0x80,
          "notification about packet reception successful or not",
          HFILL}
        },

        {&hf_oran_reserved,
         {"reserved", "oran_fh_cus.reserved",
          FT_UINT64, BASE_HEX,
          NULL, 0x0,
          NULL,
          HFILL}
        },

        {&hf_oran_reserved_1bit,
         {"reserved", "oran_fh_cus.reserved",
          FT_UINT8, BASE_HEX,
          NULL, 0x80,
          NULL,
          HFILL}
        },
        {&hf_oran_reserved_2bits,
         {"reserved", "oran_fh_cus.reserved",
          FT_UINT8, BASE_HEX,
          NULL, 0xc0,
          NULL,
          HFILL}
        },
        {&hf_oran_reserved_4bits,
         {"reserved", "oran_fh_cus.reserved",
          FT_UINT8, BASE_HEX,
          NULL, 0xf0,
          NULL,
          HFILL}
        },
        {&hf_oran_reserved_6bits,
         {"reserved", "oran_fh_cus.reserved",
          FT_UINT8, BASE_HEX,
          NULL, 0xfc,
          NULL,
          HFILL}
        },

        /* 7.7.11 */
        {&hf_oran_ext11_reserved,
         {"Reserved", "oran_fh_cus.reserved",
          FT_UINT8, BASE_HEX,
          NULL, 0x3f,
          NULL,
          HFILL}
        },

        /* 7.7.1.2 bfwCompHdr (beamforming weight compression header) */
        {&hf_oran_bfwCompHdr,
         {"bfwCompHdr", "oran_fh_cus.bfwCompHdr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "Compression method and IQ bit width for beamforming weights",
          HFILL}
        },
        {&hf_oran_bfwCompHdr_iqWidth,
         {"IQ Bit Width", "oran_fh_cus.bfwCompHdr_iqWidth",
          FT_UINT8, BASE_HEX,
          VALS(bfw_comp_headers_iq_width), 0xf0,
          "IQ bit width for the beamforming weights",
          HFILL}
        },
        {&hf_oran_bfwCompHdr_compMeth,
         {"Compression Method", "oran_fh_cus.bfwCompHdr_compMeth",
          FT_UINT8, BASE_HEX,
          VALS(bfw_comp_headers_comp_meth), 0x0f,
          "compression method for the beamforming weights",
          HFILL}
        },

        /* 7.5.3.32 */
        {&hf_oran_ciCompParam,
         {"ciCompParam", "oran_fh_cus.ciCompParam",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "channel information compression parameter",
          HFILL}
        },



        /* Table 7.5.3.32-1 */
        {&hf_oran_blockScaler,
         {"blockScaler", "oran_fh_cus.blockScaler",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          "unsigned, 1 integer bit, 7 fractional bits",
          HFILL}
        },
        {&hf_oran_compBitWidth,
         {"compBitWidth", "oran_fh_cus.compBitWidth",
          FT_UINT8, BASE_DEC,
          NULL, 0xf0,
          "Length of I bits and length of Q bits after compression over entire PRB",
          HFILL}
        },
        {&hf_oran_compShift,
         {"compShift", "oran_fh_cus.compShift",
          FT_UINT8, BASE_DEC,
          NULL, 0x0f,
          "The shift applied to the entire PRB",
          HFILL}
        },

        /* Section 7.7.6.6 */
        {&hf_oran_repetition,
         {"repetition", "oran_fh_cus.repetition",
          FT_BOOLEAN, BASE_NONE,
          NULL, 0x0,
          "Repetition of a highest priority data section for C-Plane",
          HFILL}
        },
        /* 7.7.20.9 */
        {&hf_oran_rbgSize,
         {"rbgSize", "oran_fh_cus.rbgSize",
          FT_UINT8, BASE_HEX,
          VALS(rbg_size_vals), 0x70,
          "Number of PRBs of the resource block groups allocated by the bit mask",
          HFILL}
        },
        /* 7.7.20.10 */
        {&hf_oran_rbgMask,
         {"rbgMask", "oran_fh_cus.rbgMask",
          FT_UINT32, BASE_HEX,
          NULL, 0x0fffffff,
          "Each bit indicates whether a corresponding resource block group is present",
          HFILL}
        },
        /* 7.7.6.5 */
        {&hf_oran_noncontig_priority,
         {"priority", "oran_fh_cus.priority",
          FT_UINT8, BASE_HEX,
          VALS(priority_vals), 0xc0,
          NULL,
          HFILL}
        },
        /* 7.7.6.4 */
        {&hf_oran_symbolMask,
         {"symbolMask", "oran_fh_cus.symbolMask",
          FT_UINT16, BASE_HEX,
          NULL, 0x3fff,
          "Each bit indicates whether the rbgMask applies to a given symbol in the slot",
          HFILL}
        },

        /* 7.7.22.1 */
        {&hf_oran_ack_nack_req_id,
         {"ackNackReqId", "oran_fh_cus.ackNackReqId",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          "Indicates the ACK/NACK request ID of a section description",
          HFILL}
        },

        /* Subtree for next 2 items */
        {&hf_oran_off_start_prb_num_prb_pair,
         {"Pair", "oran_fh_cus.offStartPrb_numPrb",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "Pair of offStartPrb and numPrb",
          HFILL}
        },

        /* 7.7.12.4 */
        {&hf_oran_off_start_prb,
         {"offStartPrb", "oran_fh_cus.offStartPrb",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "Offset of PRB range start",
          HFILL}
        },
        /* 7.7.12.5 */
        {&hf_oran_num_prb,
         {"numPrb", "oran_fh_cus.numPrb",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "Number of PRBs in PRB range",
          HFILL}
        },

        /* symbolId 8.3.3.7 */
        {&hf_oran_symbolId,
         {"Symbol Identifier", "oran_fh_cus.symbolId",
          FT_UINT8, BASE_HEX,
          NULL, 0x3f,
          "Identifies a symbol number within a slot",
          HFILL}
        },

        /* startPrbu 8.3.3.11 */
        {&hf_oran_startPrbu,
         {"startPrbu", "oran_fh_cus.startPrbu",
          FT_UINT16, BASE_DEC,
          NULL, 0x03ff,
          "starting PRB of user plane section",
          HFILL}
        },

        /* numPrbu 8.3.3.12 */
        { &hf_oran_numPrbu,
         {"numPrbu", "oran_fh_cus.numPrbu",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "number of PRBs per user plane section",
          HFILL}
        },

        /* 7.7.1.3 */
        {&hf_oran_bfwCompParam,
         {"bfwCompParam", "oran_fh_cus.bfwCompParam",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "Beamforming weight compression parameter",
          HFILL}
        },

        /* 6.3.3.13 */
        { &hf_oran_udCompHdrMeth,
         {"User Data Compression Method", "oran_fh_cus.udCompHdrMeth",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_meth), 0x0f,
          "Defines the compression method for "
          "the user data in every section in the C-Plane message",
          HFILL}
         },
        { &hf_oran_udCompHdrMeth_pref,
         {"User Data Compression Method", "oran_fh_cus.udCompHdrMeth",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_meth), 0x0,
          "Defines the compression method for "
          "the user data in every section in the C-Plane message",
          HFILL}
         },

        /* 6.3.3.13 */
        { &hf_oran_udCompHdrIqWidth,
         {"User Data IQ width", "oran_fh_cus.udCompHdrWidth",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_width), 0xf0,
          "Defines the IQ bit width "
          "for the user data in every section in the C-Plane message",
          HFILL}
        },
        { &hf_oran_udCompHdrIqWidth_pref,
         {"User Data IQ width", "oran_fh_cus.udCompHdrWidth",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "Defines the IQ bit width "
          "for the user data in every section in the C-Plane message",
          HFILL}
        },

#if 0
        /* Section 8.3.3.15 (not always present?) */
        {&hf_oran_udCompParam,
         {"User Data Compression Parameter", "oran_fh_cus.udCompParam",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(udCompParams), 0x0,
          "Applies to whatever compression method is specified "
          "by the associated sectionID's compMeth value",
          HFILL}
        },
#endif

        /* Section 6.3.3.15 */
        {&hf_oran_iSample,
         {"iSample", "oran_fh_cus.iSample",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          "In-phase Sample value", HFILL}
        },

        /* Section 6.3.3.16 */
        {&hf_oran_qSample,
         {"qSample", "oran_fh_cus.qSample",
          FT_FLOAT, BASE_NONE,
          NULL, 0x0,
          "Quadrature Sample value", HFILL}
        },

        { &hf_oran_rsvd8,
          { "Reserved", "oran_fh_cus.reserved8",
            FT_UINT8, BASE_HEX,
            NULL, 0x00,
            "Reserved for future use", HFILL }
        },

        { &hf_oran_rsvd16,
          { "Reserved", "oran_fh_cus.reserved16",
            FT_UINT16, BASE_HEX,
            NULL, 0x00,
            "Reserved for future use", HFILL }
        },

        { &hf_oran_exponent,
          { "Exponent", "oran_fh_cus.exponent",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "Exponent applicable to the I & Q mantissas",
            HFILL }
        },

        { &hf_oran_iq_user_data,
          { "IQ User Data", "oran_fh_cus.iq_user_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "Used for the In-phase and Quadrature sample mantissa",
            HFILL }
        },

        { &hf_oran_c_eAxC_ID,
          { "c_eAxC_ID", "oran_fh_cus.c_eaxc_id",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "This is a calculated field for the c_eAxC ID, which identifies the message stream",
            HFILL } },

        { &hf_oran_refa,
          { "RefA", "oran_fh_cus.refa",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "This is a calculated field for the RefA ID, which provides a reference in time",
            HFILL }
        },


        /* Section 7.5.2.15 */
        {&hf_oran_ciCompHdr,
         {"ciCompHdr", "oran_fh_cus.ciCompHdr",
          FT_STRING, BASE_NONE,
          NULL, 0x00,
          NULL,
          HFILL}
        },
        { &hf_oran_ciCompHdrMeth,
         {"User Data Compression Method", "oran_fh_cus.ciCompHdrMeth",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_meth), 0x0e,
          "Defines the compression method for "
          "the user data in every section in the C-Plane message",
          HFILL}
         },
        { &hf_oran_ciCompHdrIqWidth,
         {"User Data IQ width", "oran_fh_cus.udCompHdrWidth",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_width), 0xf0,
          "Defines the IQ bit width "
          "for the user data in every section in the C-Plane message",
          HFILL}
        },
        { &hf_oran_ciCompOpt,
         {"ciCompOpt", "oran_fh_cus.ciCompOpt",
          FT_UINT8, BASE_DEC,
          VALS(ci_comp_opt_vals), 0x01,
          NULL,
          HFILL}
        },

        /* 7.7.11.7 */
        { &hf_oran_disable_bfws,
          { "disableBFWs", "oran_fh_cus.disableBFWs",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            "Indicate if BFWs under section extension are disabled",
            HFILL }
        },
        /* 7.7.11.8 */
        { &hf_oran_rad,
          { "RAD", "oran_fh_cus.rad",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            "Reset After PRB Discontinuity",
            HFILL }
        },
        /* 7.7.11.4 */
        { &hf_oran_num_bund_prbs,
          { "numBundPrb", "oran_fh_cus.numBundPrb",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Number of bundled PRBs per BFWs",
            HFILL }
        },
        { &hf_oran_beam_id,
          { "beamId", "oran_fh_cus.beamId",
            FT_UINT16, BASE_DEC,
            NULL, 0x7fff,
            NULL,
            HFILL }
        },
        { &hf_oran_num_weights_per_bundle,
          { "Num weights per bundle", "oran_fh_cus.num_weights_per_bundle",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "From dissector preference",
            HFILL }
        },


        { &hf_oran_samples_prb,
          {"PRB", "oran_fh_cus.prb",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Grouping of samples for a particular Physical Resource Block",
            HFILL}
         },

        /* 7.5.3.13 */
        {&hf_oran_ciSample,
         {"ciSample", "oran_fh_cus.ciSample",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Sample (I and Q values)",
            HFILL}
        },
        {&hf_oran_ciIsample,
         {"ciIsample", "oran_fh_cus.ciISample",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "Channel information complex value - I part",
            HFILL}
        },
        {&hf_oran_ciQsample,
          { "ciQsample", "oran_fh_cus.ciQSample",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "Channel information complex value - Q part",
            HFILL}
        },

        /* 7.7.10.2 */
        { &hf_oran_beamGroupType,
          { "beamGroupType", "oran_fh_cus.beamGroupType",
            FT_UINT8, BASE_DEC,
            VALS(beam_group_type_vals), 0xc0,
            "The type of beam grouping",
            HFILL }
        },
        /* 7.7.10.3 */
        { &hf_oran_numPortc,
          { "numPortc", "oran_fh_cus.numPortc",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            "The number of eAxC ports",
            HFILL }
        },

        /* 7.7.4.2 (1 bit) */
        { &hf_oran_csf,
          { "csf", "oran_fh_cus.csf",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            "constellation shift flag",
            HFILL }
        },
        /* 7.7.4.3 */
        { &hf_oran_modcompscaler,
          { "modCompScaler", "oran_fh_cus.modcompscaler",
            FT_UINT16, BASE_DEC,
            NULL, 0x7fff,
            "modulation compression scaler value",
            HFILL }
        },

        /* 7.7.5.1 */
        { &hf_oran_modcomp_param_set,
          { "Set", "oran_fh_cus.modcomp-param-set",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL,
            HFILL }
        },

        /* mcScaleReMask 7.7.5.2 (12 bits) */
        { &hf_oran_mc_scale_re_mask,
          { "mcScaleReMask", "oran_fh_cus.mcscaleremask",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            "modulation compression power scale RE mask",
            HFILL }
        },
        /* mcScaleOffset 7.7.5.4 (15 bits) */
        { &hf_oran_mc_scale_offset,
          { "mcScaleOffset", "oran_fh_cus.mcscaleoffset",
            FT_UINT24, BASE_DEC,
            NULL, 0x0,
            "scaling value for modulation compression",
            HFILL }
        },
        /* eAxCmask (7.7.7.2) */
        { &hf_oran_eAxC_mask,
          { "eAxC Mask", "oran_fh_cus.eaxcmask",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Which eAxC_ID values the C-Plane message applies to",
            HFILL }
        },
        /* technology (interface name) 7.7.9.2 */
        { &hf_oran_technology,
          { "Technology", "oran_fh_cus.technology",
            FT_UINT8, BASE_DEC,
            VALS(interface_name_vals), 0x0,
            "Interface name (that C-PLane section applies to)",
            HFILL }
        },
        /* Exttype 14 (7.7.14.2) */
        { &hf_oran_nullLayerInd,
          { "nullLayerInd", "oran_fh_cus.nulllayerind",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            "Whether corresponding layer is nulling-layer or not",
            HFILL }
        },

        /* Exttype 19 (7.7.19.8) */
        { &hf_oran_portReMask,
          { "portReMask", "oran_fh_cus.portReMask",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), 0x0fff,
            "RE bitmask per port",
            HFILL }
        },
        /* 7.7.19.9 */
        { &hf_oran_portSymbolMask,
          { "portSymbolMask", "oran_fh_cus.portSymbolMask",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), 0x3fff,
            "Symbol bitmask port port",
            HFILL }
        },

        { &hf_oran_ext19_port,
          {"Port", "oran_fh_cus.ext19.port",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Entry for a given port in ext19",
            HFILL}
         },

        /* Ext 13 */
        { &hf_oran_prb_allocation,
          {"PRB allocation", "oran_fh_cus.prb-allocation",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL,
            HFILL}
         },
        /* 7.7.13.2 */
        { &hf_oran_nextSymbolId,
          { "nextSymbolId", "oran_fh_cus.nextSymbolId",
            FT_UINT8, BASE_DEC,
            NULL, 0x3c,
            "offset of PRB range start",
            HFILL }
        },
        /* 7.7.13.3 */
        { &hf_oran_nextStartPrbc,
          { "nextStartPrbc", "oran_fh_cus.nextStartPrbc",
            FT_UINT16, BASE_DEC,
            NULL, 0x03ff,
            "number of PRBs in PRB range",
            HFILL }
        },

        /* Puncturing patters as appears in SE 20 */
        {&hf_oran_puncPattern,
         {"puncPattern", "oran_fh_cus.puncPattern",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL,
          HFILL}
        },

        /* 7.7.20.2 numPuncPatterns */
        { &hf_oran_numPuncPatterns,
          { "numPuncPatterns", "oran_fh_cus.numPuncPatterns",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "number of puncturing patterns",
            HFILL }
        },
        /* 7.7.20.3 symbolMask */
        {&hf_oran_symbolMask_ext20,
         {"symbolMask", "oran_fh_cus.symbolMask",
          FT_UINT16, BASE_HEX,
          NULL, 0xfffc,
          "Bitmask where each bit indicates the symbols associated with the puncturing pattern",
          HFILL}
        },
        /* 7.7.20.4 startPuncPrb */
        {&hf_oran_startPuncPrb,
         {"startPuncPrb", "oran_fh_cus.startPuncPrb",
          FT_UINT16, BASE_DEC,
          NULL, 0x03ff,
          "starting PRB to which one puncturing pattern applies",
          HFILL}
        },
        /* 7.7.20.5 numPuncPrb */
        {&hf_oran_numPuncPrb,
         {"numPuncPrb", "oran_fh_cus.numPuncPrb",
          FT_UINT24, BASE_DEC,
          NULL, 0x03ffff,
          "the number of PRBs of the puncturing pattern",
          HFILL}
        },
        /* 7.7.20.6 puncReMask */
        {&hf_oran_puncReMask,
         {"puncReMask", "oran_fh_cus.puncReMask",
          FT_UINT16, BASE_DEC,
          NULL, 0xffc0,
          "puncturing pattern RE mask",
          HFILL}
        },
        /* 7.7.20.4 rbgIncl */
        {&hf_oran_RbgIncl,
         {"rbgIncl", "oran_fh_cus.rbgIncl",
          FT_BOOLEAN, 8,
          NULL, 0x01,
          "rbg included flag",
          HFILL}
        },

        /* 7.7.21.2 ciPrbGroupSize */
        {&hf_oran_ci_prb_group_size,
         {"ciPrbGroupSize", "oran_fh_cus.ciPrbGroupSize",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "channel information PRB group size",
          HFILL}
        },

        /* 7.7.17.2 numUeID */
        {&hf_oran_num_ueid,
         {"numUeID", "oran_fh_cus.numUeID",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "number of ueIDs per user",
          HFILL}
        },

        /* 7.7.16.2 antMask */
        {&hf_oran_antMask,
         {"antMask", "oran_fh_cus.antMask",
          FT_UINT64, BASE_HEX,
          NULL, 0xffffffffffffffff,
          "indices of antennas to be pre-combined per RX endpoint",
          HFILL}
        },

        /* 7.7.18.2 transmissionWindowOffset */
        {&hf_oran_transmissionWindowOffset,
         {"transmissionWindowOffset", "oran_fh_cus.transmissionWindowOffset",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          "start of the transmission window as an offset to when the transmission window would have been without this parameter, i.e. (Ta3_max - Ta3_min)",
          HFILL}
        },
        /* 7.7.18.3 transmissionWindowSize */
        {&hf_oran_transmissionWindowSize,
         {"transmissionWindowSize", "oran_fh_cus.transmissionWindowSize",
          FT_UINT16, BASE_DEC,
          NULL, 0x3fff,
          "size of the transmission window in resolution µs",
          HFILL}
        },
        /* 7.7.18.4 toT */
        {&hf_oran_toT,
         {"toT", "oran_fh_cus.toT",
          FT_UINT8, BASE_DEC,
          VALS(type_of_transmission_vals), 0x03,
          "type of transmission",
          HFILL}
        },

        /* 7.7.2.2 bfaCompHdr */
        {&hf_oran_bfaCompHdr,
         {"bfaCompHdr", "oran_fh_cus.bfaCompHdr",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "beamforming attributes compression header",
          HFILL}
        },
        /* 7.7.2.2-2: bfAzPtWidth */
        {&hf_oran_bfAzPtWidth,
         {"bfAzPtWidth", "oran_fh_cus.bfAzPtWidth",
          FT_UINT8, BASE_DEC,
          VALS(bfa_bw_vals), 0x38,
          NULL,
          HFILL}
        },
        /* 7.7.2.2-3: bfZePtWidth */
        {&hf_oran_bfZePtWidth,
         {"bfZePtWidth", "oran_fh_cus.bfZePtWidth",
          FT_UINT8, BASE_DEC,
          VALS(bfa_bw_vals), 0x07,
          NULL,
          HFILL}
        },
        /* 7.7.2.2-4: bfAz3ddWidth */
        {&hf_oran_bfAz3ddWidth,
         {"bfAz3ddWidth", "oran_fh_cus.bfAz3ddWidth",
          FT_UINT8, BASE_DEC,
          VALS(bfa_bw_vals), 0x38,
          NULL,
          HFILL}
        },
        /* 7.7.2.2-5: bfZe3ddWidth */
        {&hf_oran_bfZe3ddWidth,
         {"bfZe3ddWidth", "oran_fh_cus.bfZe3ddWidth",
          FT_UINT8, BASE_DEC,
          VALS(bfa_bw_vals), 0x07,
          NULL,
          HFILL}
        },

        /* 7.7.2.3 bfAzPt */
        {&hf_oran_bfAzPt,
         {"bfAzPt", "oran_fh_cus.bfAzPt",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "beamforming azimuth pointing parameter",
          HFILL}
        },
        /* 7.7.2.4 bfZePt */
        {&hf_oran_bfZePt,
         {"bfZePt", "oran_fh_cus.bfZePt",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "beamforming zenith pointing parameter",
          HFILL}
        },
        /* 7.7.2.5 bfAz3dd */
        {&hf_oran_bfAz3dd,
         {"bfAz3dd", "oran_fh_cus.bfAz3dd",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "beamforming azimuth beamwidth parameter",
          HFILL}
        },
        /* 7.7.2.6 bfZe3dd */
        {&hf_oran_bfZe3dd,
         {"bfZe3dd", "oran_fh_cus.bfZe3dd",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "beamforming zenith beamwidth parameter",
          HFILL}
        },

        /* 7.7.2.7 bfAzSl */
        {&hf_oran_bfAzSl,
         {"bfAzSl", "oran_fh_cus.bfAzSl",
          FT_UINT8, BASE_DEC,
          VALS(sidelobe_suppression_vals), 0x38,
          "beamforming azimuth sidelobe parameter",
          HFILL}
        },
        /* 7.7.2.8 bfZeSl */
        {&hf_oran_bfZeSl,
         {"bfZeSl", "oran_fh_cus.bfZeSl",
          FT_UINT8, BASE_DEC,
          VALS(sidelobe_suppression_vals), 0x38,
          "beamforming zenith sidelobe parameter",
          HFILL}
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_oran,
        &ett_oran_ecpri_pcid,
        &ett_oran_ecpri_rtcid,
        &ett_oran_ecpri_seqid,
        &ett_oran_section_type,
        &ett_oran_u_timing,
        &ett_oran_u_section,
        &ett_oran_u_prb,
        &ett_oran_section,
        &ett_oran_iq,
        &ett_oran_c_section_extension,
        &ett_oran_bfw_bundle,
        &ett_oran_bfw,
        &ett_oran_offset_start_prb_num_prb,
        &ett_oran_prb_cisamples,
        &ett_oran_cisample,
        &ett_oran_udcomphdr,
        &ett_oran_cicomphdr,
        &ett_oran_cicompparam,
        &ett_oran_bfwcomphdr,
        &ett_oran_bfwcompparam,
        &ett_oran_ext19_port,
        &ett_oran_prb_allocation,
        &ett_oran_punc_pattern,
        &ett_oran_bfacomphdr,
        &ett_oran_modcomp_param_set
    };

    expert_module_t* expert_oran;

    static ei_register_info ei[] = {
        { &ei_oran_unsupported_bfw_compression_method, { "oran_fh_cus.unsupported_bfw_compression_method", PI_UNDECODED, PI_WARN, "Unsupported BFW Compression Method", EXPFILL }},
        { &ei_oran_invalid_sample_bit_width, { "oran_fh_cus.invalid_sample_bit_width", PI_UNDECODED, PI_ERROR, "Unsupported sample bit width", EXPFILL }},
        { &ei_oran_reserved_numBundPrb, { "oran_fh_cus.reserved_numBundPrb", PI_MALFORMED, PI_ERROR, "Reserved value of numBundPrb", EXPFILL }},
        { &ei_oran_extlen_wrong, { "oran_fh_cus.extlen_wrong", PI_MALFORMED, PI_ERROR, "extlen doesn't match number of dissected bytes", EXPFILL }},
        { &ei_oran_invalid_eaxc_bit_width, { "oran_fh_cus.invalid_exac_bit_width", PI_UNDECODED, PI_ERROR, "Inconsistent eAxC bit width", EXPFILL }},
        { &ei_oran_extlen_zero, { "oran_fh_cus.extlen_zero", PI_MALFORMED, PI_ERROR, "extlen - zero is reserved value", EXPFILL }},
        { &ei_oran_rbg_size_reserved, { "oran_fh_cus.rbg_size_reserved", PI_MALFORMED, PI_ERROR, "rbgSize - zero is reserved value", EXPFILL }},
        { &ei_oran_frame_length, { "oran_fh_cus.frame_length", PI_MALFORMED, PI_ERROR, "there should be 0-3 bytes remaining after PDU in frame", EXPFILL }},
        { &ei_oran_numprbc_ext21_zero, { "oran_fh_cus.numprbc-ext21-zero", PI_MALFORMED, PI_ERROR, "numPrbc shall not be set to 0 when ciPrbGroupSize is configured", EXPFILL }},
        { &ei_oran_ci_prb_group_size_reserved, { "oran_fh_cus.ci_prb_group_size_reserved", PI_MALFORMED, PI_WARN, "ciPrbGroupSize should be 2-254", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_oran = proto_register_protocol("O-RAN Fronthaul CUS", "O-RAN FH CUS", "oran_fh_cus");

    /* Allow dissector to find be found by name. */
    register_dissector("oran_fh_cus", dissect_oran, proto_oran);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_oran, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_oran = expert_register_protocol(proto_oran);
    expert_register_field_array(expert_oran, ei, array_length(ei));

    module_t * oran_module = prefs_register_protocol(proto_oran, NULL);

    /* Register bit width/compression preferences separately by direction. */
    prefs_register_uint_preference(oran_module, "oran.du_port_id_bits", "DU Port ID bits [a]",
        "The bit width of DU Port ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_du_port_id_bits);
    prefs_register_uint_preference(oran_module, "oran.bandsector_id_bits", "BandSector ID bits [b]",
        "The bit width of BandSector ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_bandsector_id_bits);
    prefs_register_uint_preference(oran_module, "oran.cc_id_bits", "CC ID bits [c]",
        "The bit width of CC ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_cc_id_bits);
    prefs_register_uint_preference(oran_module, "oran.ru_port_id_bits", "RU Port ID bits [d]",
        "The bit width of RU Port ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_ru_port_id_bits);

    prefs_register_uint_preference(oran_module, "oran.iq_bitwidth_up", "IQ Bitwidth Uplink",
        "The bit width of a sample in the Uplink (if no udcompHdr)", 10, &pref_sample_bit_width_uplink);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_up", "Uplink User Data Compression",
        "Uplink User Data Compression", &pref_iqCompressionUplink, compression_options, true);
    prefs_register_bool_preference(oran_module, "oran.ud_comp_hdr_up", "udCompHdr field is present for uplink",
        "The udCompHdr field in U-Plane messages may or may not be present, depending on the "
        "configuration of the O-RU. This preference instructs the dissector to expect "
        "this field to be present in uplink messages", &pref_includeUdCompHeaderUplink);

    prefs_register_uint_preference(oran_module, "oran.iq_bitwidth_down", "IQ Bitwidth Downlink",
        "The bit width of a sample in the Downlink (if no udcompHdr)", 10, &pref_sample_bit_width_downlink);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_down", "Downlink User Data Compression",
        "Downlink User Data Compression", &pref_iqCompressionDownlink, compression_options, true);
    prefs_register_bool_preference(oran_module, "oran.ud_comp_hdr_down", "udCompHdr field is present for downlink",
        "The udCompHdr field in U-Plane messages may or may not be present, depending on the "
        "configuration of the O-RU. This preference instructs the dissector to expect "
        "this field to be present in downlink messages", &pref_includeUdCompHeaderDownlink);

    prefs_register_uint_preference(oran_module, "oran.rbs_in_uplane_section", "Total RBs in User-Plane data section",
        "This is used if numPrbu is signalled as 0", 10, &pref_data_plane_section_total_rbs);

    prefs_register_uint_preference(oran_module, "oran.num_weights_per_bundle", "Number of weights per bundle",
        "Used in decoding of section extension type 11 (Flexible BF weights)", 10, &pref_num_weights_per_bundle);

    prefs_register_uint_preference(oran_module, "oran.num_bf_antennas", "Number of BF Antennas",
        "Number of BF Antennas (used for C section type 6)", 10, &pref_num_bf_antennas);

    prefs_register_bool_preference(oran_module, "oran.show_iq_samples", "Show IQ Sample values",
        "When enabled, for U-Plane frames show each I and Q value in PRB", &pref_showIQSampleValues);

    prefs_register_obsolete_preference(oran_module, "oran.num_bf_weights");

    flow_states_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

/* Simpler form of proto_reg_handoff_oran which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_oran(void)
{
}

/*
* Editor modelines  -  http://www.wireshark.org/tools/modelines.html
*
* Local Variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
