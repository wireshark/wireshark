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
   * ORAN-WG4.CUS.0-v01.00 specification, dated 2019/01/31.
   */
#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto.h>

/* Prototypes */
void proto_reg_handoff_oran(void);
void proto_register_oran(void);

/* Initialize the protocol and registered fields */
static int proto_oran = -1;

static int hf_oran_du_port_id = -1;
static int hf_oran_bandsector_id = -1;
static int hf_oran_cc_id = -1;
static int hf_oran_ru_port_id = -1;
static int hf_oran_sequence_id = -1;
static int hf_oran_e_bit = -1;
static int hf_oran_subsequence_id = -1;

static int hf_oran_data_direction = -1;
static int hf_oran_payload_version = -1;
static int hf_oran_filter_index = -1;
static int hf_oran_frame_id = -1;
static int hf_oran_subframe_id = -1;
static int hf_oran_slot_id = -1;
static int hf_oran_slot_within_frame = -1;
static int hf_oran_start_symbol_id = -1;
static int hf_oran_numberOfSections = -1;
static int hf_oran_sectionType = -1;
static int hf_oran_udCompHdrIqWidth = -1;
static int hf_oran_udCompHdrMeth = -1;
static int hf_oran_numberOfUEs = -1;
static int hf_oran_timeOffset = -1;
static int hf_oran_frameStructure_fft = -1;
static int hf_oran_frameStructure_subcarrier_spacing = -1;
/* static int hf_oran_frameStructure_u = -1; */
static int hf_oran_cpLength = -1;
static int hf_oran_section_id = -1;
static int hf_oran_rb = -1;
static int hf_oran_symInc = -1;
static int hf_oran_startPrbc = -1;
static int hf_oran_reMask = -1;
static int hf_oran_numPrbc = -1;
static int hf_oran_numSymbol = -1;
static int hf_oran_ef = -1;
static int hf_oran_beamId = -1;

static int hf_oran_extension = -1;
static int hf_oran_exttype = -1;
static int hf_oran_extlen = -1;

static int hf_oran_bfw = -1;
static int hf_oran_bfw_i = -1;
static int hf_oran_bfw_q = -1;

static int hf_oran_ueId = -1;
static int hf_oran_freqOffset = -1;
static int hf_oran_regularizationFactor = -1;
static int hf_oran_laaMsgType = -1;
static int hf_oran_laaMsgLen = -1;
static int hf_oran_lbtHandle = -1;
static int hf_oran_lbtDeferFactor = -1;
static int hf_oran_lbtBackoffCounter = -1;
static int hf_oran_lbtOffset = -1;
static int hf_oran_MCOT = -1;
static int hf_oran_txopSfnSfEnd = -1;
static int hf_oran_lbtMode = -1;
static int hf_oran_sfnSfEnd = -1;
static int hf_oran_lbtResult = -1;
static int hf_oran_lteTxopSymbols = -1;
static int hf_oran_initialPartialSF = -1;
static int hf_oran_reserved = -1;
/* static int hf_oran_bfwCompParam = -1; */
static int hf_oran_bfwCompHdr_iqWidth = -1;
static int hf_oran_bfwCompHdr_compMeth = -1;
static int hf_oran_num_bf_weights = -1;
static int hf_oran_symbolId = -1;
static int hf_oran_startPrbu = -1;
static int hf_oran_numPrbu = -1;
/* static int hf_oran_udCompParam = -1; */

static int hf_oran_iSample = -1;
static int hf_oran_qSample = -1;

static int hf_oran_blockScaler = -1;
static int hf_oran_compBitWidth = -1;
static int hf_oran_compShift = -1;

static int hf_oran_repetition = -1;
static int hf_oran_rbgSize = -1;
static int hf_oran_rbgMask = -1;
static int hf_oran_noncontig_priority = -1;
static int hf_oran_symbolMask = -1;

static int hf_oran_rsvd4 = -1;
static int hf_oran_rsvd8 = -1;
static int hf_oran_rsvd16 = -1;
static int hf_oran_exponent = -1;
static int hf_oran_iq_user_data = -1;

static int hf_oran_disable_bfws = -1;
static int hf_oran_rad = -1;
static int hf_oran_num_bund_prbs = -1;
static int hf_oran_beam_id = -1;
static int hf_oran_num_weights_per_bundle = -1;

static int hf_oran_off_start_prb_num_prb_pair = -1;
static int hf_oran_off_start_prb = -1;
static int hf_oran_num_prb = -1;

static int hf_oran_samples_prb = -1;
static int hf_oran_ciSample = -1;
static int hf_oran_ciIsample = -1;
static int hf_oran_ciQsample = -1;

static int hf_oran_beamGroupType = -1;
static int hf_oran_numPortc = -1;

static int hf_oran_csf = -1;
static int hf_oran_modcompscaler = -1;

/* Computed fields */
static int hf_oran_c_eAxC_ID = -1;
static int hf_oran_refa = -1;

/* Initialize the subtree pointers */
static gint ett_oran = -1;
static gint ett_oran_ecpri_rtcid = -1;
static gint ett_oran_ecpri_pcid = -1;
static gint ett_oran_ecpri_seqid = -1;
static gint ett_oran_section = -1;
static gint ett_oran_section_type = -1;
static gint ett_oran_u_timing = -1;
static gint ett_oran_u_section = -1;
static gint ett_oran_u_prb = -1;
static gint ett_oran_iq = -1;
static gint ett_oran_c_section_extension = -1;
static gint ett_oran_bfw = -1;
static gint ett_oran_offset_start_prb_num_prb = -1;
static gint ett_oran_prb_cisamples = -1;
static gint ett_oran_cisample = -1;

/* Expert info */
static expert_field ei_oran_invalid_bfw_iqwidth = EI_INIT;
static expert_field ei_oran_invalid_num_bfw_weights = EI_INIT;
static expert_field ei_oran_unsupported_bfw_compression_method = EI_INIT;
static expert_field ei_oran_invalid_sample_bit_width = EI_INIT;
static expert_field ei_oran_reserved_numBundPrb = EI_INIT;
static expert_field ei_oran_extlen_wrong = EI_INIT;
static expert_field ei_oran_extlen_zero = EI_INIT;
static expert_field ei_oran_invalid_eaxc_bit_width = EI_INIT;


/* These are the message types handled by this dissector */
#define ECPRI_MT_IQ_DATA            0
#define ECPRI_MT_RT_CTRL_DATA       2


/* Preference settings. */
static guint pref_du_port_id_bits = 2;
static guint pref_bandsector_id_bits = 6;
static guint pref_cc_id_bits = 4;
static guint pref_ru_port_id_bits = 4;

static guint pref_sample_bit_width_uplink = 14;
static guint pref_sample_bit_width_downlink = 14;


#define COMP_NONE                  0
#define COMP_BLOCK_FP              1
#define COMP_BLOCK_SCALE           2
#define COMP_U_LAW                 3
#define COMP_MODULATION            4
#define BFP_AND_SELECTIVE_RE       5
#define MOD_COMPR_AND_SELECTIVE_RE 6

static gint pref_iqCompressionUplink = COMP_BLOCK_FP;
static gint pref_iqCompressionDownlink = COMP_BLOCK_FP;
static gboolean pref_includeUdCompHeaderUplink = FALSE;
static gboolean pref_includeUdCompHeaderDownlink = FALSE;

static guint pref_data_plane_section_total_rbs = 273;
static guint pref_num_weights_per_bundle = 32;
static guint pref_num_bf_antennas = 32;
static gboolean pref_showIQSampleValues = TRUE;


static const enum_val_t compression_options[] = {
    { "COMP_NONE",                  "No Compression",                   COMP_NONE },
    { "COMP_BLOCK_FP",              "Block Floating Point Compression", COMP_BLOCK_FP },
    { "COMP_BLOCK_SCALE",           "Block Scaling Compression",        COMP_BLOCK_SCALE },
    { "COMP_U_LAW",                 "u-Law Compression",                COMP_U_LAW },
    { "COMP_MODULATION",            "Modulation Compression",           COMP_MODULATION },
    { "BFP_AND_SELECTIVE_RE",       "BFP + selective RE sending",       BFP_AND_SELECTIVE_RE },
    { "MOD_COMPR_AND_SELECTIVE_RE", "mod-compr + selective RE sending", MOD_COMPR_AND_SELECTIVE_RE },
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

static const range_string filter_indices[] = {
    {0, 0,  "standard channel filter"},
    {1, 1,  "UL filter for PRACH preamble formats 0, 1, 2; min. passband 839 x 1.25kHz = 1048.75 kHz"},
    {2, 2,  "UL filter for PRACH preamble format 3, min. passband 839 x 5 kHz = 4195 kHz"},
    {3, 3,  "UL filter for PRACH preamble formats A1, A2, A3, B1, B2, B3, B4, C0, C2; min. passband 139 x \u0394fRA"},
    {4, 4,  "UL filter for NPRACH 0, 1; min. passband 48 x 3.75KHz = 180 KHz"},
    {5, 15, "Reserved"},
    {0, 0, NULL}
};

enum section_c_types {
    SEC_C_UNUSED_RB = 0,
    SEC_C_NORMAL = 1,
    SEC_C_RSVD2 = 2,
    SEC_C_PRACH = 3,
    SEC_C_RSVD4 = 4,
    SEC_C_UE_SCHED = 5,
    SEC_C_CH_INFO = 6,
    SEC_C_LAA = 7
};

static const range_string section_types[] = {
    {SEC_C_UNUSED_RB,   SEC_C_UNUSED_RB, "Unused Resource Blocks or symbols in Downlink or Uplink"},
    {SEC_C_NORMAL,      SEC_C_NORMAL,    "Most DL/UL radio channels"},
    {SEC_C_RSVD2,       SEC_C_RSVD2,     "Reserved for future use"},
    {SEC_C_PRACH,       SEC_C_PRACH,     "PRACH and mixed-numerology channels"},
    {SEC_C_RSVD4,       SEC_C_RSVD4,     "Reserved for future use"},
    {SEC_C_UE_SCHED,    SEC_C_UE_SCHED,  "UE scheduling information(UE-ID assignment to section)"},
    {SEC_C_CH_INFO,     SEC_C_CH_INFO,   "Channel information"},
    {SEC_C_LAA,         SEC_C_LAA,       "LAA"},
    {8,                 255,             "Reserved for future use"},
    {0, 0, NULL} };

static const range_string section_types_short[] = {
    { SEC_C_UNUSED_RB,  SEC_C_UNUSED_RB,    "(Unused RBs)" },
    { SEC_C_NORMAL,     SEC_C_NORMAL,       "(Most channels)" },
    { SEC_C_RSVD2,      SEC_C_RSVD2,        "(reserved)" },
    { SEC_C_PRACH,      SEC_C_PRACH,        "(PRACH/mixed-\u03bc)" },
    { SEC_C_RSVD4,      SEC_C_RSVD4,        "(reserved)" },
    { SEC_C_UE_SCHED,   SEC_C_UE_SCHED,     "(UE scheduling info)" },
    { SEC_C_CH_INFO,    SEC_C_CH_INFO,      "(Channel info)" },
    { SEC_C_LAA,        SEC_C_LAA,          "(LAA)" },
    { 8,                255,                "Reserved for future use" },
    { 0, 0, NULL }
};

static const range_string ud_comp_header_width[] = {
    {0, 0, "I and Q are each 16 bits wide"},
    {1, 15, "Bit width of I and Q"},
    {0, 0, NULL} };

static const range_string ud_comp_header_meth[] = {
    {0, 0, "No compression" },
    {1, 1, "Block floating point compression" },
    {2, 2, "Block scaling" },
    {3, 3, "Mu - law" },
    {4, 4, "Modulation compression" },
    {5, 5, "BFP + selective RE sending" },
    {6, 6, "mod-compr + selective RE sending" },
    {7, 15, "Reserved"},
    {0, 0, NULL}
};

static const range_string frame_structure_fft[] = {
    {0,  0,  "Reserved(no FFT / iFFT processing)"},
    {1,  7,  "Reserved"},
    {8,  8,  "FFT size 256"},
    {9,  9,  "FFT size 512"},
    {10, 10, "FFT size 1024"},
    {11, 11, "FFT size 2048"},
    {12, 12, "FFT size 4096"},
    {13, 13, "FFT size 1536"},
    {14, 14, "FFT size 128"},
    {15, 15, "Reserved"},
    {0, 0, NULL}
};

static const range_string subcarrier_spacings[] = {
    { 0,  0,  "SCS 15 kHz, 1 slot/subframe, slot length 1 ms" },
    { 1,  1,  "SCS 30 kHz, 2 slots/subframe, slot length 500 \u03bcs" },
    { 2,  2,  "SCS 60 kHz, 4 slots/subframe, slot length 250 \u03bcs" },
    { 3,  3,  "SCS 120 kHz, 8 slots/subframe, slot length 125 \u03bcs" },
    { 4,  4,  "SCS 240 kHz, 16 slots/subframe, slot length 62.5 \u03bcs" },
    { 5,  5,  "SCS 480 kHz, 32 slots/subframe, slot length 31.25 \u03bcs" },
    { 6,  11, "Reserved" },
    { 12, 12, "SCS 1.25 kHz, 1 slot/subframe, slot length 1 ms" },
    { 13, 13, "SCS 3.75 kHz(LTE - specific), 1 slot/subframe, slot length 1 ms" },
    { 14, 14, "SCS 5 kHz, 1 slot/subframe, slot length 1 ms" },
    { 15, 15, "SCS 7.5 kHz(LTE - specific), 1 slot/subframe, slot length 1 ms" },
    { 0, 0, NULL }
};

static const range_string laaMsgTypes[] = {
    {0, 0,  "LBT_PDSCH_REQ - lls - CU to RU request to obtain a PDSCH channel"},
    {1, 1,  "LBT_DRS_REQ - lls - CU to RU request to obtain the channel and send DRS"},
    {2, 2,  "LBT_PDSCH_RSP - RU to lls - CU response, channel acq success or failure"},
    {3, 3,  "LBT_DRS_RSP - RU to lls - CU response, DRS sending success or failure"},
    {4, 15, "reserved for future methods"},
    {0, 0, NULL}
};


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

static const value_string bfw_comp_headers_comp_meth[] = {
    {0,     "no compression"},
    {1,     "block floating point"},
    {2,     "block scaling"},
    {3,     "u-law"},
    {4,     "beamspace compression"},
    {0, NULL}
};

/* 5.4.7.6.1 */
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

/* 5.4.7.6.4 */
static const value_string priority_vals[] = {
    {0,     "0"},
    {1,     "+1"},
    {2,     "-2 (reserved, should not be used)"},
    {3,     "-1"},
    {0, NULL}
};

/* 5.4.7.10.1  beamGroupType */
static const value_string beam_group_type_vals[] = {
    {0x0, "common beam"},
    {0x1, "beam matrix indication"},
    {0x2, "beam vector listing"},
    {0x3, "reserved"},
    {0, NULL}
};

#if 0
static const range_string bfw_comp_parms[] = {
    {0, 0, NULL}
};
static const range_string udCompParams[] = {
    {0, 0, NULL}
};
#endif

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

static void
write_section_info(proto_item *section_heading, packet_info *pinfo, proto_item *protocol_item, guint32 section_id, guint32 start_prbx, guint32 num_prbx)
{
    switch (num_prbx) {
    case 0:
        write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %d (all PRBs)", section_id);
        break;
    case 1:
        write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %d (PRB: %d)", section_id, start_prbx);
        break;
    default:
        write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %d (PRB: %d-%d)", section_id, start_prbx, start_prbx + num_prbx - 1);
    }
}

/* 3.1.3.1.6 (real time control data / IQ data transfer message series identifier */
static void
addPcOrRtcid(tvbuff_t *tvb, proto_tree *tree, gint *offset, const char *name)
{
    /* Subtree */
    proto_item *item;
    proto_tree *oran_pcid_tree = proto_tree_add_subtree(tree, tvb, *offset, 2, ett_oran_ecpri_pcid, &item, name);
    guint64 duPortId, bandSectorId, ccId, ruPortId = 0;
    gint id_offset = *offset;

    if (!((pref_du_port_id_bits > 0) && (pref_bandsector_id_bits > 0) && (pref_cc_id_bits > 0) && (pref_ru_port_id_bits > 0) && ((pref_du_port_id_bits + pref_bandsector_id_bits + pref_cc_id_bits + pref_ru_port_id_bits) == 16))) {
        expert_add_info(NULL, tree, &ei_oran_invalid_eaxc_bit_width);
        *offset += 2;
        return;
    }

    guint bit_offset = *offset * 8;

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
    bit_offset += pref_ru_port_id_bits;
    *offset += 2;

    proto_item_append_text(item, " (DU_Port_ID: %d, BandSector_ID: %d, CC_ID: %d, RU_Port_ID: %d)", (int)duPortId, (int)bandSectorId, (int)ccId, (int)ruPortId);
    char id[16];
    snprintf(id, 16, "%x:%x:%x:%x", (int)duPortId, (int)bandSectorId, (int)ccId, (int)ruPortId);
    proto_item *pi = proto_tree_add_string(oran_pcid_tree, hf_oran_c_eAxC_ID, tvb, id_offset, 2, id);
    proto_item_set_generated(pi);
}

/* 3.1.3.1.6 (message identfier) */
static void
addSeqid(tvbuff_t *tvb, proto_tree *oran_tree, gint *offset)
{
    /* Subtree */
    proto_item *seqIdItem;
    proto_tree *oran_seqid_tree = proto_tree_add_subtree(oran_tree, tvb, *offset, 2, ett_oran_ecpri_seqid, &seqIdItem, "ecpriSeqid");
    guint32 seqId, subSeqId, e = 0;
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
static float uncompressed_to_float(guint32 h)
{
    gint16 i16 = h & 0x0000ffff;
    return ((float)i16) / 0x7fff;
}

static gfloat digital_power_scaling(gfloat f)
{
    return f / (1 << 15);
}

static int dissect_bfwCompHdr(tvbuff_t *tvb, proto_tree *tree, gint offset,
                              guint32 *iq_width, guint32 *comp_meth, proto_item **comp_meth_ti)
{
    proto_tree_add_item_ret_uint(tree, hf_oran_bfwCompHdr_iqWidth,
                                 tvb, offset, 1, ENC_BIG_ENDIAN,  iq_width);
    *comp_meth_ti = proto_tree_add_item_ret_uint(tree, hf_oran_bfwCompHdr_compMeth,
                                                 tvb, offset, 1, ENC_BIG_ENDIAN, comp_meth);
    offset++;
    return offset;
}

/* Fields present (if any) depend upon passed-in bfwCompMeth */
static int dissect_bfwCompParam(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint offset,
                                proto_item *ti, guint32 bfwcomphdr_comp_method,
                                guint32 *exponent, gboolean *supported)
{
    *supported = FALSE;
    switch (bfwcomphdr_comp_method) {
        case COMP_NONE:
            /* In this case, bfwCompParam is absent */
            *supported = TRUE;
            break;
        case COMP_BLOCK_FP:
            /* 4 reserved bits +  exponent */
            proto_tree_add_item_ret_uint(tree, hf_oran_exponent,
                                         tvb, offset, 1, ENC_BIG_ENDIAN, exponent);
            *supported = TRUE;
            offset++;
            break;
        case COMP_BLOCK_SCALE:
            proto_tree_add_item(tree, hf_oran_blockScaler,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case COMP_U_LAW:
            /* compBitWidth, compShift */
            proto_tree_add_item(tree, hf_oran_compBitWidth,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_oran_compShift,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case COMP_MODULATION: /* beamspace */
            /* TODO: activeBeamspaceCoefficientMask - ceil(K/8) octets */
            /* proto_tree_add_item(extension_tree, hf_oran_blockScaler,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++; */
            break;

        case BFP_AND_SELECTIVE_RE:
        case MOD_COMPR_AND_SELECTIVE_RE:
        default:
            /* Not handled */
             break;
    }

    /* Can't go on if compression scheme not supported */
    if (!*supported) {
        expert_add_info_format(pinfo, ti, &ei_oran_unsupported_bfw_compression_method,
                               "BFW Compression method %u (%s) not supported by dissector",
                               bfwcomphdr_comp_method,
                               val_to_str_const(bfwcomphdr_comp_method, bfw_comp_headers_comp_meth, "Unknown"));
    }
    return offset;
}


static gfloat decompress_value(guint32 bits, guint32 comp_method, guint8 iq_width, guint32 exponent)
{
    switch (comp_method) {
        case COMP_NONE: /* no compression */
            return uncompressed_to_float(bits);

        case COMP_BLOCK_FP: /* block floating point */
        {
            /* A.1.2 Block Floating Point Decompression Algorithm */
            gint32 cPRB = bits;
            guint32 scaler = 1 << exponent;  /* i.e. 2^exponent */

            /* Check last bit, in case we need to flip to -ve */
            if (cPRB >= (1<<(iq_width-1))) {
                cPRB -= (1<<iq_width);
            }

            const guint8 mantissa_bits = iq_width-1;
            return (cPRB / (gfloat)(1 << (mantissa_bits))) * scaler;
        }

        case COMP_BLOCK_SCALE:
        case COMP_U_LAW:
        case COMP_MODULATION:
        case BFP_AND_SELECTIVE_RE:
        case MOD_COMPR_AND_SELECTIVE_RE:
        default:
            /* Not supported! */
            return 0.0;
    }
}

/* Out-of-range value used for special case */
#define ORPHAN_BUNDLE_NUMBER 999

static guint32 dissect_bfw_bundle(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint offset,
                                  proto_item *comp_meth_ti, guint32 bfwcomphdr_comp_meth,
                                  guint8 iq_width,
                                  guint bundle_number, guint first_prb, guint last_prb)
{
    /* bfwCompParam */
    gboolean compression_method_supported = FALSE;
    guint32  exponent = 0;
    offset = dissect_bfwCompParam(tvb, tree, pinfo, offset, comp_meth_ti,
                                  bfwcomphdr_comp_meth, &exponent, &compression_method_supported);

    /* Can't show details of unsupported compression method */
    if (!compression_method_supported) {
        /* Don't know how to show, so give up */
        return 0;
    }

    /* Create Bundle subtree */
    gint bit_offset = offset*8;
    gint bfw_offset = bit_offset / 8;
    gint prb_offset = offset;

    /* Set bundle name */
    char bundle_name[32];
    if (bundle_number != ORPHAN_BUNDLE_NUMBER) {
        snprintf(bundle_name, 32, "Bundle %u", bundle_number);
    }
    else {
        g_strlcpy(bundle_name, "Orphaned", 32);
    }

    /* Create Bundle root */
    proto_item *bundle_ti = proto_tree_add_string_format(tree, hf_oran_bfw,
                                                         tvb, bfw_offset, 0, "",
                                                         "%s: (PRBs %u-%u)",
                                                         bundle_name,
                                                         first_prb, last_prb);
    proto_tree *bundle_tree = proto_item_add_subtree(bundle_ti, ett_oran_bfw);

    /* beamId */
    guint32 beam_id;
    proto_tree_add_item_ret_uint(bundle_tree, hf_oran_beam_id, tvb, offset, 2, ENC_BIG_ENDIAN, &beam_id);
    proto_item_append_text(bundle_ti, " (beamId:%u) ", beam_id);
    bit_offset += 16;

    /* Number of weights per bundle (from preference) */
    proto_item *wpb_ti = proto_tree_add_uint(bundle_tree, hf_oran_num_weights_per_bundle, tvb, 0, 0,
                                             pref_num_weights_per_bundle);
    proto_item_set_generated(wpb_ti);

    /* Add the weights for this bundle */
    for (guint m=0; m < pref_num_weights_per_bundle; m++) {

        /* Create subtree */
        bfw_offset = bit_offset / 8;
        guint8 bfw_extent = ((bit_offset + (iq_width*2)) / 8) - bfw_offset;
        proto_item *bfw_ti = proto_tree_add_string_format(bundle_tree, hf_oran_bfw,
                                                          tvb, bfw_offset, bfw_extent,
                                                          "", "TRX %u: (", m);
        proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

        /* I */
        /* Get bits, and convert to float. */
        guint32 bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
        gfloat value = decompress_value(bits, bfwcomphdr_comp_meth, iq_width, exponent);

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

    proto_item_set_len(bundle_ti, bit_offset/8 - prb_offset);

    return bit_offset/8;
}

/* N.B. these are the green parts of the tables showing Section Types, differing by section Type */
static int dissect_oran_c_section(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                                  guint32 sectionType, proto_item *protocol_item)
{
    guint offset = 0;
    proto_tree *oran_tree = NULL;
    proto_item *sectionHeading = NULL;

    oran_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_oran_section, &sectionHeading, "Section");
    guint32 sectionId = 0;

    guint32 startPrbc;
    guint32 numPrbc;
    guint32 ueId = 0;
    guint32 beamId = 0;

    gboolean extension_flag = FALSE;

    /* These sections are similar, so handle as common with per-type differences */
    if (sectionType <= SEC_C_UE_SCHED) {
        /* sectionID */
        proto_tree_add_item_ret_uint(oran_tree, hf_oran_section_id, tvb, offset, 2, ENC_BIG_ENDIAN, &sectionId);
        offset++;

        /* rb */
        proto_tree_add_item(oran_tree, hf_oran_rb, tvb, offset, 1, ENC_NA);
        /* symInc */
        proto_tree_add_item(oran_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA);
        /* startPrbc */
        proto_tree_add_item_ret_uint(oran_tree, hf_oran_startPrbc, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbc);
        offset += 2;
        /* numPrbc */
        proto_tree_add_item_ret_uint(oran_tree, hf_oran_numPrbc, tvb, offset, 1, ENC_NA, &numPrbc);
        offset += 1;
        /* reMask */
        proto_tree_add_item(oran_tree, hf_oran_reMask, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset++;
        /* numSymbol */
        guint32 numSymbol;
        proto_tree_add_item_ret_uint(oran_tree, hf_oran_numSymbol, tvb, offset, 1, ENC_NA, &numSymbol);
        offset++;

        /* ef (extension flag) */
        switch (sectionType) {
            case SEC_C_NORMAL:            /* Section Type "1" */
            case SEC_C_PRACH:             /* Section Type "3" */
            case SEC_C_UE_SCHED:          /* Section Type "5" */
                proto_tree_add_item_ret_boolean(oran_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);
                break;
            default:
                break;
        }

        write_section_info(sectionHeading, pinfo, protocol_item, sectionId, startPrbc, numPrbc);
        proto_item_append_text(sectionHeading, ", Symbols: %d", numSymbol);

        if (numPrbc == 0) {
            /* Special case for all PRBs */
            numPrbc = pref_data_plane_section_total_rbs;
            startPrbc = 0;  /* may already be 0... */
        }

        /* Section type specific fields (after 'numSymbol') */
        switch (sectionType) {
            case SEC_C_UNUSED_RB:    /* Section Type "0" - Table 5.4 */
                /* reserved */
                proto_tree_add_item(oran_tree, hf_oran_rsvd16, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;

            case SEC_C_NORMAL:       /* Section Type "1" - Table 5.5 */
                /* beamId */
                proto_tree_add_item_ret_uint(oran_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN, &beamId);
                offset += 2;

                proto_item_append_text(sectionHeading, ", BeamId: %d", beamId);
                break;

            case SEC_C_PRACH:       /* Section Type "3" - Table 5.6 */
            {
                /* beamId */
                proto_tree_add_item_ret_uint(oran_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN, &beamId);
                offset += 2;

                /* freqOffset */
                gint32 freqOffset;          /* Yes, this is signed, so the implicit cast is intentional. */
                proto_item *freq_offset_item = proto_tree_add_item_ret_uint(oran_tree, hf_oran_freqOffset, tvb, offset, 3, ENC_BIG_ENDIAN, &freqOffset);
                freqOffset |= 0xff000000;   /* Must sign-extend */
                proto_item_set_text(freq_offset_item, "Frequency offset: %d \u0394f", freqOffset);
                offset += 3;

                /* reserved */
                proto_tree_add_item(oran_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_item_append_text(sectionHeading, ", BeamId: %d, FreqOffset: %d \u0394f", beamId, freqOffset);
                break;
            }

            case SEC_C_UE_SCHED:   /* Section Type "5" - Table 5.7 */
                /* ueId */
                proto_tree_add_item_ret_uint(oran_tree, hf_oran_ueId, tvb, offset, 2, ENC_NA, &ueId);
                offset += 2;

                proto_item_append_text(sectionHeading, ", UEId: %d", ueId);
                break;

            default:
                break;
        }
    }
    else if (sectionType == SEC_C_CH_INFO) {  /* Section Type "6" */
        /* ef */
        proto_tree_add_item_ret_boolean(oran_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);
        /* ueId */
        proto_tree_add_item_ret_uint(oran_tree, hf_oran_ueId, tvb, offset, 2, ENC_NA, &ueId);
        offset += 2;
        /* regularizationFactor */
        proto_tree_add_item(oran_tree, hf_oran_regularizationFactor, tvb, offset, 2, ENC_NA);
        offset += 2;
        /* reserved */
        proto_tree_add_item(oran_tree, hf_oran_rsvd4, tvb, offset, 1, ENC_NA);
        /* rb */
        proto_tree_add_item(oran_tree, hf_oran_rb, tvb, offset, 1, ENC_NA);
        /* symInc */
        proto_tree_add_item(oran_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA);
        /* startPrbc */
        proto_tree_add_item_ret_uint(oran_tree, hf_oran_startPrbc, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbc);
        offset += 2;
        /* numPrbc */
        proto_tree_add_item_ret_uint(oran_tree, hf_oran_numPrbc, tvb, offset, 1, ENC_NA, &numPrbc);
        offset += 1;

        /* ciIsample,ciQsample pairs */
        guint m;
        guint prb;
        guint32 bit_offset = offset*8;

        /* Antenna count from preference */
        guint num_trx = pref_num_bf_antennas;
        if (numPrbc > 1) {
            proto_item_append_text(sectionHeading, " (UEId=%u  PRBs %u-%u, %u antennas", ueId, startPrbc, startPrbc+numPrbc-1, num_trx);
        }
        else {
            proto_item_append_text(sectionHeading, " (UEId=%u  PRB %u, %u antennas", ueId, startPrbc, num_trx);
        }

        for (prb=startPrbc; prb < startPrbc+numPrbc; prb++) {

            /* PRB subtree */
            guint prb_start_offset = bit_offset;
            proto_item *prb_ti = proto_tree_add_string_format(oran_tree, hf_oran_samples_prb,
                                                                 tvb, bit_offset/8, 0,
                                                                 "", "PRB=%u", prb);
            proto_tree *prb_tree = proto_item_add_subtree(prb_ti, ett_oran_prb_cisamples);

            /* Antennas */
            for (m=0; m < num_trx; m++) {

                guint sample_offset = bit_offset / 8;
                guint8 sample_extent = ((bit_offset + (16*2)) / 8) - sample_offset;

                /* Create subtree for antenna */
                proto_item *sample_ti = proto_tree_add_string_format(prb_tree, hf_oran_ciSample,
                                                                     tvb, sample_offset, sample_extent,
                                                                     "", "TRX=%u:  ", m);
                proto_tree *sample_tree = proto_item_add_subtree(sample_ti, ett_oran_cisample);

                /* I */
                /* Get bits, and convert to float. */
                guint32 bits = tvb_get_bits(tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                gfloat value = uncompressed_to_float(bits);

                /* Add to tree. */
                proto_tree_add_float_format_value(sample_tree, hf_oran_ciIsample, tvb, bit_offset/8, (16+7)/8, value, "#%u=%f", m, value);
                bit_offset += 16;
                proto_item_append_text(sample_ti, "I%u=%f ", m, value);

                /* Q */
                /* Get bits, and convert to float. */
                bits = tvb_get_bits(tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                value = uncompressed_to_float(bits);

                /* Add to tree. */
                proto_tree_add_float_format_value(sample_tree, hf_oran_ciQsample, tvb, bit_offset/8, (16+7)/8, value, "#%u=%f", m, value);
                bit_offset += 16;
                proto_item_append_text(sample_ti, "Q%u=%f ", m, value);
            }
            proto_item_set_len(prb_ti, (bit_offset-prb_start_offset)/8);
        }
        offset = (bit_offset/8);
    }
    else if (sectionType == SEC_C_LAA) {   /* Section Type "7" */
        /* TODO: */
    }


    /* Section extension commands */
    while (extension_flag) {

        gint extension_start_offset = offset;

        /* Create subtree for each extension (with summary) */
        proto_item *extension_ti = proto_tree_add_string_format(oran_tree, hf_oran_extension,
                                                                tvb, offset, 0, "", "Extension");
        proto_tree *extension_tree = proto_item_add_subtree(extension_ti, ett_oran_c_section_extension);

        /* ef (i.e. another extension after this one?) */
        proto_tree_add_item_ret_boolean(extension_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);

        /* extType */
        guint32 exttype;
        proto_tree_add_item_ret_uint(extension_tree, hf_oran_exttype, tvb, offset, 1, ENC_BIG_ENDIAN, &exttype);
        offset++;

        proto_item_append_text(extension_ti, " (%s)", val_to_str_const(exttype, exttype_vals, "Unknown"));

        /* extLen (number of 32-bit words) */
        guint32 extlen_len = (exttype==11) ? 2 : 1;  /* Extension 11 is special */
        guint32 extlen;
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
                guint32 bfwcomphdr_iq_width, bfwcomphdr_comp_meth;
                proto_item *comp_meth_ti = NULL;

                /* bfwCompHdr (2 subheaders - bfwIqWidth and bfwCompMeth)*/
                offset = dissect_bfwCompHdr(tvb, extension_tree, offset,
                                            &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);

                /* Look up width of samples. */
                guint8 iq_width = !bfwcomphdr_iq_width ? 16 : bfwcomphdr_iq_width;

                /* bfwCompParam */
                guint32 exponent = 0;
                gboolean compression_method_supported = FALSE;
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
                guint weights_bytes = (extlen*4)-3;
                guint num_weights_pairs = (weights_bytes*8) / (iq_width*2);
                guint num_trx = num_weights_pairs;
                gint bit_offset = offset*8;

                for (guint n=0; n < num_trx; n++) {
                    /* Create antenna subtree */
                    gint bfw_offset = bit_offset / 8;
                    proto_item *bfw_ti = proto_tree_add_string_format(extension_tree, hf_oran_bfw,
                                                                      tvb, bfw_offset, 0, "", "TRX %2u: (", n);
                    proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

                    /* I value */
                    /* Get bits, and convert to float. */
                    guint32 bits = tvb_get_bits(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
                    gfloat value = decompress_value(bits, COMP_BLOCK_FP, iq_width, exponent);
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
                offset = bit_offset/8;

                break;
            }

            case 4: /* Modulation compression params */
                /* csf */
                proto_tree_add_item(extension_tree, hf_oran_csf, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* modCompScaler */
                proto_tree_add_item(extension_tree, hf_oran_modcompscaler, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case 6: /* Non-contiguous PRB allocation in time and frequency domain */
                proto_tree_add_item(extension_tree, hf_oran_repetition, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(extension_tree, hf_oran_rbgSize, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(extension_tree, hf_oran_rbgMask, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(extension_tree, hf_oran_symbolMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case 10: /* Section description for group configuration of multiple ports */
            {
                /* beamGroupType */
                guint32 beam_group_type = 0;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_beamGroupType,
                                             tvb, offset, 1, ENC_BIG_ENDIAN, &beam_group_type);
                proto_item_append_text(extension_ti, " (%s)", val_to_str_const(beam_group_type, beam_group_type_vals, "Unknown"));

                /* numPortc */
                guint32 numPortc;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_numPortc,
                                             tvb, offset, 1, ENC_BIG_ENDIAN, &numPortc);
                offset++;

                /* TODO: any generated fields or expert info should be added, due to enties in table 5-35 ? */

                /* Will append all beamId values to extension_ti, regardless of beamGroupType */
                proto_item_append_text(extension_ti, "(");
                guint n;

                switch (beam_group_type) {
                    case 0x0: /* common beam */
                        /* Reserved byte */
                        proto_tree_add_item(oran_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
                        offset++;

                        /* All entries are beamId... */
                        for (n=0; n < numPortc; n++) {
                            proto_item_append_text(extension_ti, "%u ", beamId);
                        }
                        break;

                    case 0x1: /* beam matrix indication */
                        /* Reserved byte */
                        proto_tree_add_item(oran_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
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
                            guint32 id;
                            proto_item *beamid_or_ueid_ti = proto_tree_add_item_ret_uint(oran_tree, hf_oran_beamId,
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
                gboolean disableBFWs;
                guint32  numBundPrb;

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
                offset++;

                /* numBundPrb */
                proto_item *num_bund_prb_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_num_bund_prbs,
                                                                           tvb, offset, 1, ENC_BIG_ENDIAN, &numBundPrb);
                offset++;
                /* value zero is reserved.. */
                if (numBundPrb == 0) {
                    expert_add_info_format(pinfo, num_bund_prb_ti, &ei_oran_reserved_numBundPrb,
                                           "Reserved value of numBundPrb seen - not valid for use");
                }

                guint32 num_bundles;
                guint32 orphaned_prbs;

                if (!disableBFWs) {
                    /********************************************/
                    /* Table 5-36 */
                    /********************************************/

                    guint32 bfwcomphdr_iq_width, bfwcomphdr_comp_meth;
                    proto_item *comp_meth_ti = NULL;

                    /* bfwCompHdr (2 subheaders - bfwIqWidth and bfwCompMeth)*/
                    offset = dissect_bfwCompHdr(tvb, extension_tree, offset,
                                                &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);

                    /* Look up width of samples. */
                    guint8 iq_width = !bfwcomphdr_iq_width ? 16 : bfwcomphdr_iq_width;


                    /* Work out number of bundles, but take care not to divide by zero. */
                    if (numBundPrb == 0) {
                        break;
                    }
                    num_bundles = numPrbc / numBundPrb;

                    /* Add (complete) bundles */
                    for (guint b=0; b < num_bundles; b++) {

                        offset = dissect_bfw_bundle(tvb, extension_tree, pinfo, offset,
                                                    comp_meth_ti, bfwcomphdr_comp_meth,
                                                    iq_width,
                                                    b,
                                                    startPrbc + b*numBundPrb,
                                                    startPrbc + (b+1)*numBundPrb - 1);
                        if (!offset) {
                            break;
                        }
                    }


                    /* Any remaining BFWs will be added into an 'orphan bundle'. */
                    orphaned_prbs = numPrbc % numBundPrb;
                    if (orphaned_prbs) {
                        offset = dissect_bfw_bundle(tvb, extension_tree, pinfo, offset,
                                                    comp_meth_ti, bfwcomphdr_comp_meth,
                                                    iq_width, ORPHAN_BUNDLE_NUMBER,
                                                    startPrbc + num_bundles*numBundPrb,
                                                    startPrbc + num_bundles*numBundPrb + orphaned_prbs-1);
                    }
                }
                else {
                    /********************************************/
                    /* Table 5.37 */
                    /* No weights in this case */
                    /********************************************/

                    /* Work out number of bundles, but take care not to divide by zero. */
                    if (numBundPrb == 0) {
                        break;
                    }
                    num_bundles = numPrbc / numBundPrb;

                    for (guint n=0; n < num_bundles; n++) {
                        /* beamId */
                        proto_item *ti = proto_tree_add_item(extension_tree, hf_oran_beam_id,
                                                             tvb, offset, 2, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti, " (Bundle %u)", n);
                        offset += 2;
                    }

                    /* Any remaining BFWs would be added into an 'orphan bundle', so beamId would be here. */
                    orphaned_prbs = numPrbc % numBundPrb;
                    if (orphaned_prbs) {
                        proto_item *ti = proto_tree_add_item(extension_tree, hf_oran_beam_id,
                                                             tvb, offset, 2, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti, " (Orphaned PRBs)");
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
                /* priority */
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);

                /* symbolMask */
                proto_tree_add_item(extension_tree, hf_oran_symbolMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* There are now 'R' pairs of (offStartPrb, numPrb) values.  Not sure where R comes from,
                   but for now assume that entire space in extLen should be filled with pairs.
                   N.B. this suggests that 'R' would always be an even number.. */
                guint32 extlen_remaining_byte = (extlen*4) - 4;
                guint8 prb_index;

                for (prb_index = 1; extlen_remaining_byte > 0; prb_index++)
                {
                    /* Create a subtree for each pair */
                    proto_item *pair_ti = proto_tree_add_string(extension_tree, hf_oran_off_start_prb_num_prb_pair,
                                                                tvb, offset, 2, "");
                    proto_tree *pair_tree = proto_item_add_subtree(pair_ti, ett_oran_offset_start_prb_num_prb);

                    /* offStartPrb */
                    guint32 off_start_prb;
                    proto_tree_add_item_ret_uint(pair_tree, hf_oran_off_start_prb, tvb, offset, 1, ENC_BIG_ENDIAN, &off_start_prb);
                    offset++;

                    /* numPrb */
                    guint32 num_prb;
                    proto_tree_add_item_ret_uint(pair_tree, hf_oran_num_prb, tvb, offset, 1, ENC_BIG_ENDIAN, &num_prb);
                    offset++;

                    /* Add summary to pair root item */
                    proto_item_append_text(pair_ti, "(%u) offStartPrb=%3u, numPrb=%u",
                                           prb_index, off_start_prb, num_prb);

                    extlen_remaining_byte -= 2;
                }
                break;
            }

            default:
                /* TODO: Support remaining extension types. */
                break;
        }

        /* Check offset compared with extlen.  There should be 0-3 bytes of padding */
        gint num_padding_bytes = (extension_start_offset + (extlen*4) - offset);
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
    proto_item_append_text(sectionHeading, ")");

    return offset;
}


/* Control plane dissector. */
static int dissect_oran_c(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    guint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "O-RAN-FH-C");
    col_set_str(pinfo->cinfo, COL_INFO, "C-Plane");

    /* Create display subtree for the protocol */
    proto_item *protocol_item = proto_tree_add_item(tree, proto_oran, tvb, 0, -1, ENC_NA);
    proto_item_append_text(protocol_item, "-C");
    proto_tree *oran_tree = proto_item_add_subtree(protocol_item, ett_oran);

    addPcOrRtcid(tvb, oran_tree, &offset, "ecpriRtcid");
    addSeqid(tvb, oran_tree, &offset);

    proto_item *sectionHeading;

    /* section subtree */
    gint section_tree_offset = offset;
    proto_tree *section_tree = proto_tree_add_subtree(oran_tree, tvb, offset, 2, ett_oran_section_type, &sectionHeading, "C-Plane Section Type ");

    /* dataDirection */
    guint32 direction = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_data_direction, tvb, offset, 1, ENC_NA, &direction);
    /* payloadVersion */
    proto_tree_add_item(section_tree, hf_oran_payload_version, tvb, offset, 1, ENC_NA);
    /* payloadVersion */
    proto_tree_add_item(section_tree, hf_oran_filter_index, tvb, offset, 1, ENC_NA);
    offset += 1;

    guint ref_a_offset = 0;
    /* frameId */
    guint32 frameId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_frame_id, tvb, offset, 1, ENC_NA, &frameId);
    offset += 1;

    /* subframeId */
    guint32 subframeId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_subframe_id, tvb, offset, 1, ENC_NA, &subframeId);
    /* slotId */
    guint32 slotId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN, &slotId);
    offset++;
    /* startSymbolId */
    guint32 startSymbolId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_start_symbol_id, tvb, offset, 1, ENC_NA, &startSymbolId);
    offset++;

    char id[16];
    snprintf(id, 16, "%d-%d-%d", frameId, subframeId, slotId);
    proto_item *pi = proto_tree_add_string(section_tree, hf_oran_refa, tvb, ref_a_offset, 3, id);
    proto_item_set_generated(pi);

    /* numberOfSections */
    guint32 nSections = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_numberOfSections, tvb, offset, 1, ENC_NA, &nSections);
    offset += 1;

    /* sectionType */
    guint32 sectionType = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_sectionType, tvb, offset, 1, ENC_NA, &sectionType);
    offset += 1;

    /* Section-specific fields (white entries in Section Type diagrams) */
    proto_item *iq_width_item = NULL;
    guint bit_width = 0;

    guint32 scs, slots_per_subframe;
    guint32 num_ues = 0;
    proto_item *ti;

    switch (sectionType) {
        case SEC_C_UNUSED_RB:   /* Section Type "0" */
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

        case SEC_C_NORMAL:      /* Section Type "1" */
        case SEC_C_UE_SCHED:    /* Section Type "5" */
            /* udCompHdr */
            iq_width_item = proto_tree_add_item_ret_uint(section_tree, hf_oran_udCompHdrIqWidth , tvb, offset, 1, ENC_NA, &bit_width);
            proto_item_append_text(iq_width_item, " (%d bits)", bit_width == 0 ? 16 : bit_width);
            proto_tree_add_item(section_tree, hf_oran_udCompHdrMeth, tvb, offset, 1, ENC_NA);
            offset += 1;
            /* reserved */
            proto_tree_add_item(section_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case SEC_C_PRACH:       /* Section Type "3" */
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
            /* udpCompHdr */
            iq_width_item = proto_tree_add_item_ret_uint(section_tree, hf_oran_udCompHdrIqWidth, tvb, offset, 1, ENC_NA, &bit_width);
            proto_item_append_text(iq_width_item, " (%d bits)", bit_width + 1);
            proto_tree_add_item(section_tree, hf_oran_udCompHdrMeth, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case SEC_C_CH_INFO:
            /* numberOfUEs */
            proto_tree_add_item_ret_uint(section_tree, hf_oran_numberOfUEs, tvb, offset, 1, ENC_NA, &num_ues);
            offset += 1;
            /* reserved */
            proto_tree_add_item(section_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
            offset += 1;

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

    /* Set actual length of section. */
    proto_item_set_len(section_tree, offset - section_tree_offset);

    proto_item_append_text(sectionHeading, "%d, %s, Frame: %d, Subframe: %d, Slot: %d, StartSymbol: %d",
                           sectionType, val_to_str(direction, data_direction_vals, "Unknown"),
                           frameId, subframeId, slotId, startSymbolId);
    write_pdu_label_and_info(protocol_item, NULL, pinfo, ", Type: %d %s", sectionType, rval_to_str(sectionType, section_types_short, "Unknown"));

    /* Dissect each C section */
    for (guint32 i = 0; i < nSections; ++i) {
        tvbuff_t *section_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);
        offset += dissect_oran_c_section(section_tvb, oran_tree, pinfo, sectionType, protocol_item);
    }

    return tvb_captured_length(tvb);
}

/* User plane dissector */
static int
dissect_oran_u(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "O-RAN-FH-U");
    col_set_str(pinfo->cinfo, COL_INFO, "U-Plane");

    /* create display subtree for the protocol */
    proto_item *protocol_item = proto_tree_add_item(tree, proto_oran, tvb, 0, -1, ENC_NA);
    proto_item_append_text(protocol_item, "-U");
    proto_tree *oran_tree = proto_item_add_subtree(protocol_item, ett_oran);

    /* Transport header */
    /* Real-time control data / IQ data transfer message series identifier */
    addPcOrRtcid(tvb, oran_tree, &offset, "ecpriPcid");
    /* Message identifier */
    addSeqid(tvb, oran_tree, &offset);

    /* Common header for time reference */
    proto_item *timingHeader;
    proto_tree *timing_header_tree = proto_tree_add_subtree(oran_tree, tvb, offset, 4, ett_oran_u_timing, &timingHeader, "Timing header");

    guint32 direction;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_data_direction, tvb, offset, 1, ENC_NA, &direction);
    proto_tree_add_item(timing_header_tree, hf_oran_payload_version, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(timing_header_tree, hf_oran_filter_index, tvb, offset, 1, ENC_NA);
    offset += 1;

    gint ref_a_offset = offset;
    guint32 frameId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_frame_id, tvb, offset, 1, ENC_NA, &frameId);
    offset += 1;

    guint32 subframeId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_subframe_id, tvb, offset, 1, ENC_NA, &subframeId);
    guint32 slotId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN, &slotId);
    guint32 startSymbolId = 0;
    offset++;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_start_symbol_id, tvb, offset, 1, ENC_NA, &startSymbolId);
    offset++;

    char id[16];
    snprintf(id, 16, "%d-%d-%d", frameId, subframeId, slotId);
    proto_item *pi = proto_tree_add_string(timing_header_tree, hf_oran_refa, tvb, ref_a_offset, 3, id);
    proto_item_set_generated(pi);

    proto_item_append_text(timingHeader, " %s, Frame: %d, Subframe: %d, Slot: %d, StartSymbol: %d",
        val_to_str(direction, data_direction_vals, "Unknown"), frameId, subframeId, slotId, startSymbolId);

    guint sample_bit_width;
    gint compression;
    gboolean includeUdCompHeader;

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

    guint nBytesForSamples = (sample_bit_width * 12 * 2) / 8;
    guint nBytesPerPrb = nBytesForSamples;
    if (compression != COMP_NONE)
        nBytesPerPrb++;         /* 1 extra byte reserved/exponent */
    guint bytesLeft;

    guint number_of_sections = 0;
    do {
        proto_item *sectionHeading;
        proto_tree *section_tree = proto_tree_add_subtree(oran_tree, tvb, offset, 2, ett_oran_u_section, &sectionHeading, "Section");

        /* Section Header fields */

        /* sectionId */
        guint32 sectionId = 0;
        proto_tree_add_item_ret_uint(section_tree, hf_oran_section_id, tvb, offset, 2, ENC_BIG_ENDIAN, &sectionId);
        offset++;
        /* rb */
        proto_tree_add_item(section_tree, hf_oran_rb, tvb, offset, 1, ENC_NA);
        /* symInc */
        proto_tree_add_item(section_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA);
        /* startPrbu */
        guint32 startPrbu = 0;
        proto_tree_add_item_ret_uint(section_tree, hf_oran_startPrbu, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbu);
        offset += 2;

        /* numPrbu */
        guint32 numPrbu = 0;
        proto_tree_add_item_ret_uint(section_tree, hf_oran_numPrbu, tvb, offset, 1, ENC_NA, &numPrbu);
        offset += 1;

        if (includeUdCompHeader) {
            /* 5.4.4.10.  Described in 6.3.3.13 */
            /* TODO: break out into function with subheader and good summary? */
            /* TODO: extract these values to inform how wide IQ samples in each PRB will be? */
            proto_tree_add_item(section_tree, hf_oran_udCompHdrMeth, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(section_tree, hf_oran_udCompHdrIqWidth, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Not part of udCompHdr */
            proto_tree_add_item(section_tree, hf_oran_rsvd8, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        write_section_info(sectionHeading, pinfo, protocol_item, sectionId, startPrbu, numPrbu);

        /* TODO: should this use the same pref as c-plane? */
        if (numPrbu == 0) {
            /* Special case for all PRBs (NR: the total number of PRBs may be > 255) */
            numPrbu = pref_data_plane_section_total_rbs;
            startPrbu = 0;  /* may already be 0... */
        }

        for (guint i = 0; i < numPrbu; ++i) {
            proto_item *prbHeading;
            proto_tree *rb_tree = proto_tree_add_subtree(section_tree, tvb, offset, nBytesPerPrb, ett_oran_u_prb, &prbHeading, "PRB");
            guint32 exponent = 0;
            if (compression != COMP_NONE) {
                proto_tree_add_item(rb_tree, hf_oran_rsvd4, tvb, offset, 1, ENC_NA);
                proto_tree_add_item_ret_uint(rb_tree, hf_oran_exponent, tvb, offset, 1, ENC_BIG_ENDIAN, &exponent);
                offset += 1;
            }

            /* FIXME - add udCompParam for COMP_NONE or COMP_MODULATION, figure out correct length
               Maybe even decode the samples themselves.
             */

            proto_tree_add_item(rb_tree, hf_oran_iq_user_data, tvb, offset, nBytesForSamples, ENC_NA);

            if (pref_showIQSampleValues) {
                /* Individual values */
                guint samples_offset = offset*8;
                guint sample_number = 0;
                for (guint n = 0; n<12; n++) {
                    /* I */
                    guint i_bits = tvb_get_bits(tvb, samples_offset, sample_bit_width, ENC_BIG_ENDIAN);
                    gfloat i_value = decompress_value(i_bits, COMP_BLOCK_FP, sample_bit_width, exponent);
                    i_value = digital_power_scaling(i_value);
                    guint sample_len_in_bytes = ((samples_offset%8)+sample_bit_width+7)/8;
                    proto_item *i_ti = proto_tree_add_float(rb_tree, hf_oran_iSample, tvb, samples_offset/8, sample_len_in_bytes, i_value);
                    proto_item_set_text(i_ti, "iSample: %0.12f  0x%04x (iSample-%u in the PRB)", i_value, i_bits, sample_number);
                    samples_offset += sample_bit_width;
                    /* Q */
                    guint q_bits = tvb_get_bits(tvb, samples_offset, sample_bit_width, ENC_BIG_ENDIAN);
                    gfloat q_value = decompress_value(q_bits, COMP_BLOCK_FP, sample_bit_width, exponent);
                    q_value = digital_power_scaling(q_value);
                    sample_len_in_bytes = ((samples_offset%8)+sample_bit_width+7)/8;
                    proto_item *q_ti = proto_tree_add_float(rb_tree, hf_oran_qSample, tvb, samples_offset/8, sample_len_in_bytes, q_value);
                    proto_item_set_text(q_ti, "qSample: %0.12f  0x%04x (qSample-%u in the PRB)", q_value, q_bits, sample_number);
                    samples_offset += sample_bit_width;

                    sample_number++;
                }
            }

            offset += nBytesForSamples;

            proto_item_set_len(sectionHeading, nBytesPerPrb * numPrbu + 4);  /* 4 bytes for section header */
            proto_item_append_text(prbHeading, " %d", startPrbu + i);
        }
        bytesLeft = tvb_captured_length(tvb) - offset;
        number_of_sections++;
    } while (bytesLeft >= (4 + nBytesPerPrb));     /* FIXME: bad heuristic */

    /* Show number of sections found */
    proto_item *ti = proto_tree_add_uint(oran_tree, hf_oran_numberOfSections, tvb, 0, 0, number_of_sections);
    proto_item_set_generated(ti);

    return tvb_captured_length(tvb);
}


/*****************************/
/* Main dissection function. */
static int
dissect_oran(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint32 ecpri_message_type = *(guint32 *)data;

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
           NULL, HFILL }
       },

       /* Section 3.1.3.1.6 */
       { &hf_oran_bandsector_id,
         { "BandSector ID", "oran_fh_cus.bandsector_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           NULL, HFILL }
       },

       /* Section 3.1.3.1.6 */
       { &hf_oran_cc_id,
         { "CC ID", "oran_fh_cus.cc_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           NULL, HFILL }
       },

        /* Section 3.1.3.1.6 */
        { &hf_oran_ru_port_id,
          { "RU Port ID", "oran_fh_cus.ru_port_id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
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
            "One bit (the \"E-bit\") is reserved to indicate the last message of a subsequence.",
            HFILL }
        },

        /* Section 3.1.3.1.7 */
        { &hf_oran_subsequence_id,
          { "Subsequence ID", "oran_fh_cus.subsequence_id",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            "The subsequence identifier.",
            HFILL }
        },

        /* Section 5.4.4.1 */
        { &hf_oran_data_direction,
          { "Data Direction", "oran_fh_cus.data_direction",
            FT_UINT8, BASE_DEC,
            VALS(data_direction_vals), 0x80,
            "This parameter indicates the gNB data direction.",
            HFILL }
        },

        /* Section 5.4.4.2 */
        { &hf_oran_payload_version,
         {"Payload Version", "oran_fh_cus.payloadVersion",
          FT_UINT8, BASE_DEC,
          NULL, 0x70,
          "This parameter defines the payload protocol version valid for the "
          "following IEs in the application layer. In this version of the "
          "specification payloadVersion=001b shall be used.",
          HFILL}
        },

        /* Section 5.4.4.3 */
        {&hf_oran_filter_index,
         {"Filter Index", "oran_fh_cus.filterIndex",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(filter_indices), 0x0f,
          "This parameter defines an index to the channel filter to be used "
          "between IQ data and air interface, both in DL and UL. For most "
          "physical channels filterIndex =0000b is used which indexes the "
          "standard channel filter, e.g. 100MHz channel filter for 100MHz "
          "nominal carrier bandwidth. Another use case is PRACH in UL, where "
          "different filter indices can be used for different PRACH formats, "
          "assuming that before FFT processing of PRACH data there is a "
          "separate PRACH filter or PRACH filter in addition to the standard "
          "channel filter in UL. Please note that for PRACH there is typically "
          "also a frequency offset (see freqOffset) applied before the "
          "PRACH filter.  NOTE: Filter index is commanded from lls-CU to RU. "
          "Likewise, it is not mandatory to command special filters, and "
          "filter index = 0000b is also allowed for PRACH.",
          HFILL}
        },

        /* Section 5.4.4.4 */
        {&hf_oran_frame_id,
         {"Frame ID", "oran_fh_cus.frameId",
          FT_UINT8, BASE_DEC,
          NULL, 0x00,
          "This parameter is a counter for 10 ms frames (wrapping period 2.56 seconds)",
          HFILL}
        },

        /* Section 5.4.4.5 */
        {&hf_oran_subframe_id,
         {"Subframe ID", "oran_fh_cus.subframe_id",
          FT_UINT8, BASE_DEC,
          NULL, 0xf0,
          "This parameter is a counter for 1 ms sub-frames within 10ms frame.",
          HFILL}
        },

        /* Section 5.4.4.6 */
        {&hf_oran_slot_id,
         {"Slot ID", "oran_fh_cus.slotId",
          FT_UINT16, BASE_DEC,
          NULL, 0x0fc0,
          "This parameter is the slot number within a 1ms sub-frame. All slots "
          "in one sub-frame are counted by this parameter, slotId running "
          "from 0 to Nslot-1. In this version of the specification the "
          "maximum Nslot=16, All other values of the 6 bits are reserved for "
          "future use.",
          HFILL}
        },

        /* Section 5.4.4.6 */
        {&hf_oran_slot_within_frame,
         {"Slot within frame", "oran_fh_cus.slot-within-frame",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
         "Slot within frame, to match DT logs",
         HFILL}
        },

        /* Section 5.4.4.7 */
        {&hf_oran_start_symbol_id,
         {"Start Symbol ID", "oran_fh_cus.startSymbolId",
          FT_UINT8, BASE_DEC,
          NULL, 0x3f,
          "This parameter identifies the first symbol number within slot, to "
          "which the information of this message is applies.",
          HFILL}
        },

        /* Section 5.4.4.8 */
        {&hf_oran_numberOfSections,
         {"Number of Sections", "oran_fh_cus.numberOfSections",
          FT_UINT8, BASE_DEC,
          NULL, 0x00,
          "This parameter indicates the number of section IDs included in "
          "this C-Plane message.",
          HFILL}
        },

        /* Section 5.4.4.9 */
        {&hf_oran_sectionType,
         {"Section Type", "oran_fh_cus.sectionType",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(section_types), 0x00,
          "This parameter determines the characteristics of U-plane data to "
          "be transferred or received from a beam with one pattern id.",
          HFILL}
        },

        /* Section 5.4.4.11 */
        {&hf_oran_numberOfUEs,
         {"Number Of UEs", "oran_fh_cus.numberOfUEs",
          FT_UINT8, BASE_DEC,
          NULL, 0x00,
          "This parameter applies to section type 6 messages and indicates "
          "the number of UEs (for which channel information is provided) are "
          "included in the message.  This allows the parser to determine "
          "when the last UE's data has been parsed.",
          HFILL}
        },

        /* Section 5.4.4.12 */
        {&hf_oran_timeOffset,
         {"Time Offset", "oran_fh_cus.timeOffset",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          "This parameter defines the time_offset from the start of the slot "
          "to the start of the Cyclic Prefix (CP) in number of samples tsample "
          "(=1/30.72MHz as specified in 3GPP TS38.211 section 4.1). "
          "Because this is denominated in \"samples\" there is no fixed "
          "microsecond unit for this parameter; time_offset = \"n\" may be longer "
          "or shorter in time depending on the sampling interval (which is "
          "a NR capability only, not applicable to LTE). time_offset = time"
          "Offset * tsample",
          HFILL}
        },

        /* Section 5.4.4.13 */
        { &hf_oran_frameStructure_fft,
          { "FFT Size", "oran_fh_cus.frameStructure.fft",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(frame_structure_fft), 0xf0,
            "The FFT/iFFT size being used for all IQ data processing related "
            "to this message.",
            HFILL }
        },

        /* Section 5.4.4.13 */
        { &hf_oran_frameStructure_subcarrier_spacing,
          { "Subcarrier Spacing", "oran_fh_cus.frameStructure.spacing",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(subcarrier_spacings), 0x0f,
            "The sub carrier spacing "
            "as well as the number of slots per 1ms sub-frame according "
            "to 3GPP TS 38.211, taking for completeness also 3GPP TS 36.211 "
            "into account. The parameter \u03bc=0...5 from 3GPP TS 38.211 is "
            "extended to apply for PRACH processing.",
            HFILL }
        },

        /* Section 5.4.4.14 */
        {&hf_oran_cpLength,
         {"CP Length", "oran_fh_cus.cpLength",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          "This parameter defines the length CP_length of the Cyclic Prefix "
          "(CP) as follows, based on Ts (=1/30.72MHz as specified in 3GPP "
          "TS38.211 section 4.1) and \u03bc as defined inTable 16. (\"NA\" for \u03bc "
          "shall be replaced by \"0\" in the following:) CP_length = cpLength "
          "* Ts  * 2-\u03bc",
          HFILL}
        },

        /* Section 5.4.5.1 */
        {&hf_oran_section_id,
         {"Section ID", "oran_fh_cus.sectionId",
          FT_UINT16, BASE_DEC,
          NULL, 0xfff0,
          "This parameter identifies individual sections within the C-Plane "
          "message. The purpose of section ID is mapping of U-Plane messages "
          "to the corresponding C-Plane message (and Section Type) associated "
          "with the data.  Two C-Plane sections with same Section ID "
          "may be combined and mapped to a common section in a corresponding "
          "U-Plane message containing a combined payload for both sections "
          "(e.g., for supporting mixed CSI RS and PDSCH). This case is "
          "applicable when usage of reMask is complimentary (or orthogonal) "
          "and different beam directions (i.e. beamIds) are given the resource "
          "elements.  NOTE: In case of two sections with same Section ID "
          "are combined, both sections shall have same rb, startPrbc, numPrbc "
          "and numSymbol IE fields' content.",
          HFILL}
        },

        /* Section 5.4.5.2 */
        {&hf_oran_rb,
         {"RB Indicator", "oran_fh_cus.rb",
          FT_UINT8, BASE_DEC,
          VALS(rb_vals), 0x08,
          "This parameter is used to indicate if every RB is used or every "
          "other RB is used. The starting RB is defined by startPrbc and "
          "total number of used RBs is defined by numPrbc.  Example: RB=1, "
          "startPrb=1, numPrb=3, then the PRBs used are 1, 3, and 5.",
          HFILL}
        },

        /* Section 5.4.5.3 */
        {&hf_oran_symInc,
         {"Symbol Number Increment Command", "oran_fh_cus.symInc",
          FT_UINT8, BASE_DEC,
          VALS(sym_inc_vals), 0x04,
          "This parameter is used to indicate which symbol number is relevant "
          "to the given sectionId.  It is expected that for each C-Plane "
          "message a symbol number is maintained and starts with the value "
          "of startSymbolid.  The same value is used for each section in "
          "the message as long as symInc is zero.  When symInc is one, the "
          "maintained symbol number should be incremented by one, and that "
          "new symbol number should be used for that section and each subsequent "
          "section until the symInc bit is again detected to be one. "
          "In this manner, multiple symbols may be handled by a single C-Plane "
          "message.",
          HFILL}
        },

        /* Section 5.4.5.4 */
        {&hf_oran_startPrbc,
         {"Starting PRB of Control Plane Section", "oran_fh_cus.startPrbc",
          FT_UINT16, BASE_DEC,
          NULL, 0x03ff,
          "This parameter is the starting PRB of a control section. For one "
          "C-Plane message, there may be multiple U-Plane messages associated "
          "with it and requiring defining from which PRB the control "
          "commands are applicable.",
          HFILL}
        },

        /* Section 5.4.5.5 */
        {&hf_oran_reMask,
         {"RE Mask", "oran_fh_cus.reMask",
          FT_UINT16, BASE_HEX,
          NULL, 0xfff0,
          "This parameter defines the Resource Element (RE) mask within a "
          "PRB. Each bit setting in the reMask indicates if the section control "
          "is applicable to the RE sent in U-Plane messages (0=not applicable; "
          "1=applicable).",
          HFILL}
        },

        /* Section 5.4.5.6 */
        {&hf_oran_numPrbc,
         {"Number of Contiguous PRBs per Control Section", "oran_fh_cus.numPrbc",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "This parameter defines the PRBs where the control section is valid.",
          HFILL}
        },

        /* Section 5.4.5.7 */
        {&hf_oran_numSymbol,
         {"Number of Symbols", "oran_fh_cus.numSymbol",
          FT_UINT8, BASE_DEC,
          NULL, 0x0f,
          "This parameter defines number of symbols to which the section "
          "control is applicable. At minimum, the section control shall be "
          "applicable to at least one symbol. However, possible optimizations "
          "could allow for several (up to 14) symbols, if e.g., all 14 "
          "symbols use the same beam ID.",
          HFILL}
        },

        /* Section 5.4.5.8 */
        {&hf_oran_ef,
         {"Extension Flag", "oran_fh_cus.ef",
          FT_BOOLEAN, 8,
          NULL, 0x80,
          "This parameter is used to indicate if this section will contain "
          "both beamforming index and any ex(tension information (ef=1) or "
          "just a beamforming index (ewf=0)",
          HFILL}
        },

        /* Section 5.4.5.9 */
        {&hf_oran_beamId,
         {"Beam ID", "oran_fh_cus.beamId",
          FT_UINT16, BASE_DEC,
          NULL, 0x7fff,
          "This parameter defines the beam pattern to be applied to the U-Plane "
          "data. beamId = 0 means no beamforming operation will be "
          "performed.  Note that the beamId encodes the beamforming to be done "
          "on the RU.  This beamforming may be digital, analog or both "
          "(\"hybrid beamforming\") and the beamId provides all the information "
          "necessary for the RU to select the correct beam (or weight table "
          "from which to create a beam).  The specific mapping of beamId "
          "to e.g. weight table, directionality, beam adjacency or any other "
          "beam attributes is specific to the RU design and must be conveyed "
          "via M-Plane from the RU to lls-CU upon startup.",
          HFILL}
        },

        /* Section 5.4.6.2 */
        {&hf_oran_extension,
         {"Extension", "oran_fh_cus.extension",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "Section extension",
          HFILL}
        },

        /* Section 5.4.6.1 */
        {&hf_oran_exttype,
         {"extType", "oran_fh_cus.extType",
          FT_UINT8, BASE_DEC,
          VALS(exttype_vals), 0x7f,
          "The extension type, which provides additional parameters specific to subject data extension",
          HFILL}
        },

        /* Section 5.4.6.3 */
        {&hf_oran_extlen,
         {"extLen", "oran_fh_cus.extLen",
         FT_UINT16, BASE_DEC,
         NULL, 0x0,
         "Extension length in 32-bit words",
         HFILL}
        },

        /* Section 5.4.7.1 */
        {&hf_oran_bfw,
         {"bfw", "oran_fh_cus.bfw",
         FT_STRING, BASE_NONE,
         NULL, 0x0,
         "Set of weights for a particular antenna",
         HFILL}
        },

        /* Section 5.4.7.1.3 */
        {&hf_oran_bfw_i,
         {"bfwI", "oran_fh_cus.bfwI",
         FT_FLOAT, BASE_NONE,
         NULL, 0x0,
         "This parameter is the In-phase beamforming weight value. The total "
         "number of weights in the section is RU-specific and is conveyed "
         "from the RU to the lls-CU as part of the initialization procedure "
         "via the M-Plane.",
         HFILL}
        },

        /* Section 5.4.7.1.4 */
        {&hf_oran_bfw_q,
         {"bfwQ", "oran_fh_cus.bfwQ",
         FT_FLOAT, BASE_NONE,
         NULL, 0x0,
         "This parameter is the Quadrature beamforming weight value. The "
         "total number of weights in the section is RU-specific and is "
         "conveyed from the RU to the lls-CU as part of the initialization "
         "procedure via the M-Plane.",
         HFILL}
        },

        /* Section 5.4.5.10 */
        {&hf_oran_ueId,
         {"UE ID", "oran_fh_cus.ueId",
          FT_UINT16, BASE_HEX_DEC,
          NULL, 0x7fff,
          "This parameter provides a label for the UE for which the section "
          "contents apply.  This is used to support channel information "
          "sending from the lls-CU to the RU.  This is just a label and the "
          "specific value has no meaning regarding types of UEs that may be "
          "supported within the system.",
          HFILL}
        },

        /* Section 5.4.5.11 */
        {&hf_oran_freqOffset,
         {"Frequency Offset", "oran_fh_cus.freqOffset",
          FT_UINT24, BASE_DEC,
          NULL, 0x0,
          "This parameter defines the frequency offset with respect to the "
          "carrier center frequency before additional filtering (e.g. for "
          "PRACH) and FFT processing (in UL) in steps of subcarrier spacings"
          " ?f. The frequency offset shall be individual per control section. "
          "frequency_offset = freqOffset * ?f Note: It may be studied "
          "whether this IEs should be individual per control section to allow "
          "scheduling of several simultaneous PRACH opportunities with "
          "different individual frequency offsets",
          HFILL}
        },

        /* Section 5.4.5.12 */
        {&hf_oran_regularizationFactor,
         {"Regularization Factor", "oran_fh_cus.regularizationFactor",
          FT_INT16, BASE_DEC,
          NULL, 0x0,
          "This parameter provides a signed value to support MMSE operation "
          "within the RU when beamforming weights are supported in the RU, "
          "so related to section type 6.",
          HFILL}
        },

        /* Section 5.4.5.14 */
        {&hf_oran_laaMsgType,
         {"LAA Message Type", "oran_fh_cus.laaMsgType",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(laaMsgTypes), 0xf0,
          "This parameter defines number of symbols to which the section "
          "control is applicable. At minimum, the section control shall be "
          "applicable to at least one symbol. However, possible optimizations "
          "could allow for several (up to 14) symbols, if e.g., all 14 "
          "symbols use the same beam ID.",
          HFILL}
        },

        /* Section 5.4.5.15 */
        {&hf_oran_laaMsgLen,
         {"LAA Message Length", "oran_fh_cus.laaMsgLen",
          FT_UINT8, BASE_DEC,
          NULL, 0x0f,
          "This parameter defines number of 32-bit words in the LAA section, "
          "where \"0\" means one 32-bit word, \"1\" means 2 32-bit words, etc. "
          "- including the byte containing the lssMsgLen parameter.",
          HFILL}
        },

        /* Section 5.4.5.16 */
        {&hf_oran_lbtHandle,
         {"LBT Handle", "oran_fh_cus.lbtHandle",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          "This parameter provides a label that is included in the configuration "
          "request message (e.g., LBT_PDSCH_REQ, LBT_DRS_REQ) transmitted "
          "from the lls-CU to the RU and returned in the corresponding "
          "response message (e.g., LBT_PDSCH_RSP, LBT_DRS_RSP).",
          HFILL}
         },

        /* Section 5.4.5.17 */
        {&hf_oran_lbtDeferFactor,
         {"Defer Factor", "oran_fh_cus.lbtDeferFactor",
          FT_UINT8, BASE_DEC,
          NULL, 0x1c,
          "Defer factor in sensing slots as described in 3GPP TS 36.213 "
          "Section 15.1.1. This parameter is used for LBT CAT 4 and can take "
          "one of three values: {1,3, 7} based on the priority class. Four "
          "priority classes are defined in 3GPP TS 36.213.",
          HFILL}
        },

        /* Section 5.4.5.18 */
        {&hf_oran_lbtBackoffCounter,
         {"Backoff Counter", "oran_fh_cus.lbtBackoffCounter",
          FT_UINT16, BASE_DEC,
          NULL, 0x03ff,
          "LBT backoff counter in sensing slots as described in 3GPP TS 36.213 "
          "Section 15.1.1. This parameter is used for LBT CAT 4 and can "
          "take one of nine values: {3, 7, 15, 31, 63, 127, 255, 511, 1023} "
          "based on the priority class. Four priority classes are defined "
          "in 3GPP TS 36.213.",
          HFILL}
        },

        /* Section 5.4.5.19 */
        {&hf_oran_lbtOffset,
         {"LBT Offset", "oran_fh_cus.lbtOffset",
          FT_UINT16, BASE_DEC,
          NULL, 0xff80,
          "LBT start time in microseconds from the beginning of the subframe "
          "scheduled by this message",
          HFILL}
        },

        /* Section 5.4.5.20 */
        {&hf_oran_MCOT,
         {"Maximum Channel Occupancy Time", "oran_fh_cus.MCOT",
          FT_UINT8, BASE_DEC,
          NULL, 0xf0,
          "LTE TXOP duration in subframes as described in 3GPP TS 36.213 "
          "Section 15.1.1. The maximum values for this parameter are {2, 3, 8, "
          "10} based on the priority class. Four priority classes are "
          "defined in 3GPP TS 36.213.",
          HFILL}
        },

        /* Section 5.4.5.21 */
        {&hf_oran_txopSfnSfEnd,
         {"TXOP SFN/SF End", "oran_fh_cus.txopSfnSfEnd",
          FT_UINT16, BASE_DEC,
          NULL, 0x0fff,
          "SFN/SF by which the TXOP must end",
          HFILL}
        },

        /* Section 5.4.5.22 */
        {&hf_oran_lbtMode,
         {"LBT Mode", "oran_fh_cus.lbtMode",
          FT_UINT8, BASE_DEC,
          NULL, 0x20,
          "Part of multi-carrier support. Indicates whether full LBT process "
          "is carried or partial LBT process is carried (multi carrier mode "
          "B according to 3GPP TS 36.213 Section 15.1.5.2). 0 - full LBT "
          "(regular LBT). 1 - Partial LBT (looking back 25usec prior to "
          "transmission as indicated in 3GPP TS 36.213 section 15.1.5.2)",
          HFILL}
        },

        /* Section 5.4.5.23 */
        {&hf_oran_sfnSfEnd,
         {"SFN/SF End", "oran_fh_cus.sfnSfEnd",
          FT_UINT16, BASE_DEC,
          NULL, 0x0fff,
          "SFN/SF by which the DRS window must end",
          HFILL}
        },

        /* Section 5.4.5.24 */
        {&hf_oran_lbtResult,
         {"LBT Result", "oran_fh_cus.lbtResult",
          FT_UINT8, BASE_DEC,
          NULL, 0x80,
          "LBT result of SFN/SF. 0 - SUCCESS - indicates that the channel was "
          "successfully acquired. 1 - FAILURE - indicates failure to "
          "acquire the channel by the end of SFN/SF",
          HFILL}
        },

        /* Section 5.4.5.25 */
        {&hf_oran_lteTxopSymbols,
         {"LTE TXOP Symbols", "oran_fh_cus.lteTxopSymbols",
          FT_UINT16, BASE_DEC,
          NULL, 0x3fff,
          "Actual LTE TXOP in symbols. Valid when LBT result = SUCCESS.",
          HFILL}
        },

        /* Section 5.4.5.26 */
        {&hf_oran_initialPartialSF,
         {"Initial partial SF", "oran_fh_cus.initialPartialSF",
          FT_UINT8, BASE_DEC,
          NULL, 0x40,
          "Indicates whether the initial SF in the LBT process is full or "
          "partial. 0 - full SF (two slots, 14 symbols). 1 - partial SF (only "
          "second slot, last 7 symbols)",
          HFILL}
        },

        /* Section 5.4.5.27 */
        {&hf_oran_reserved,
         {"reserved for future use", "oran_fh_cus.reserved",
          FT_UINT16, BASE_HEX,
          NULL, 0x7fff,
          "This parameter is reserved for future use. Transmitter shall send "
          "value \"0\", while receiver shall ignore the value received.",
          HFILL}
        },

        /* Section 5.4.7.1.1 */
        {&hf_oran_bfwCompHdr_iqWidth,
         {"IQ Bit Width", "oran_fh_cus.bfwCompHdr_iqWidth",
          FT_UINT8, BASE_HEX,
          VALS(bfw_comp_headers_iq_width), 0xf0,
          "This parameter defines the compression method and IQ bit width "
          "for the beamforming weights in the specific section in the C-Plane "
          "message.  In this way each set of weights may employ a separate "
          "compression method. Note that for the block compression methods, "
          "the block size is the entire vector of beamforming weights, not "
          "some subset of them.",
          HFILL}
        },

        /* Section 5.4.7.1.1 */
        {&hf_oran_bfwCompHdr_compMeth,
         {"Compression Method", "oran_fh_cus.bfwCompHdr_compMeth",
          FT_UINT8, BASE_HEX,
          VALS(bfw_comp_headers_comp_meth), 0x0f,
          "This parameter defines the compression method and IQ bit width for "
          "the beamforming weights in the specific section in the C-Plane "
          "message.  In this way each set of weights may employ a separate "
          "compression method. Note that for the block compression methods, "
          "the block size is the entire vector of beamforming weights, "
          "not some subset of them.",
          HFILL}
        },

        {&hf_oran_num_bf_weights,
         {"Number of BF weights", "oran_fh_cus.num_bf_weights",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          "This is the number of BF weights per antenna - currently set in a preference",
          HFILL}
        },

#if 0
    /* FIXME  Section 5.4.7.1.2 */
    { &hf_oran_bfwCompParam.
     { "beamforming weight compression parameter", "oran_fh_cus.bfwCompParam",
        various, | BASE_RANGE_STRING,
        RVALS(bfw_comp_parms), 0x0,
        "This parameter applies to the compression method specified by th"
        "e associated sectionID's bfwCompMeth value.",
        HFILL }
    },
#endif

        /* Section 5.4.7.1.2 */
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
          "Length of I bits and length of Q bits after compression over entire PRB.",
          HFILL}
        },
        {&hf_oran_compShift,
         {"compShift", "oran_fh_cus.compShift",
          FT_UINT8, BASE_DEC,
          NULL, 0x0f,
          "The shift applied to the entire PRB.",
          HFILL}
        },

        /* Section 5.4.7.6 */
        {&hf_oran_repetition,
         {"repetition", "oran_fh_cus.repetition",
          FT_UINT8, BASE_HEX,
          NULL, 0x80,
          "Repetition of a highest priority data section inside a C-Plane message",
          HFILL}
        },
        {&hf_oran_rbgSize,
         {"rbgSize", "oran_fh_cus.rbgSize",
          FT_UINT8, BASE_HEX,
          VALS(rbg_size_vals), 0x70,
          "Number of PRBs of the resource block groups allocated by the bit mask",
          HFILL}
        },
        {&hf_oran_rbgMask,
         {"rbgMask", "oran_fh_cus.rbgMask",
          FT_UINT32, BASE_HEX,
          NULL, 0x0fffffff,
          "Each bit indicates whether a corresponding resource block group is present",
          HFILL}
        },
        {&hf_oran_noncontig_priority,
         {"priority", "oran_fh_cus.priority",
          FT_UINT8, BASE_HEX,
          VALS(priority_vals), 0xc0,
          NULL,
          HFILL}
        },
        {&hf_oran_symbolMask,
         {"symbolMask", "oran_fh_cus.symbolMask",
          FT_UINT16, BASE_HEX,
          NULL, 0x3fff,
          "Each bit indicates whether the rbgMask applies to a given symbol in the slot",
          HFILL}
        },

        /* Section 5.4.7.12 */
        {&hf_oran_off_start_prb_num_prb_pair,
         {"Pair", "oran_fh_cus.offStartPrb_numPrb",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          "Pair of offStartPrb and numPrb.",
          HFILL}
        },

        {&hf_oran_off_start_prb,
         {"offStartPrb", "oran_fh_cus.offStartPrb",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "Offset of PRB range start.",
          HFILL}
        },
        {&hf_oran_num_prb,
         {"numPrb", "oran_fh_cus.numPrb",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "Number of PRBs in PRB range.",
          HFILL}
        },

        /* Section 6.3.3.7 */
        {&hf_oran_symbolId,
         {"Symbol Identifier", "oran_fh_cus.symbolId",
          FT_UINT8, BASE_HEX,
          NULL, 0x3f,
          "This parameter identifies a symbol number within a slot",
          HFILL}
        },

        /* Section 6.3.3.11 */
        {&hf_oran_startPrbu,
         {"Starting PRB of User Plane Section", "oran_fh_cus.startPrbu",
          FT_UINT16, BASE_DEC,
          NULL, 0x03ff,
          "This parameter is the starting PRB of a user plane section. For "
          "one C-Plane message, there may be multiple U-Plane messages "
          "associated with it and requiring defining from which PRB the contained "
          "IQ data are applicable.",
          HFILL}
        },

        /* Section 6.3.3.12 */
        {&hf_oran_numPrbu,
         {"Number of PRBs per User Plane Section", "oran_fh_cus.numPrbu",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          "This parameter defines the PRBs where the user plane section is "
          "valid.",
          HFILL}
        },

        /* Section 6.3.3.13 */
        {&hf_oran_udCompHdrMeth,
         {"User Data Compression Method", "oran_fh_cus.udCompHdrMeth",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_meth), 0x0f,
          "This parameter defines the compression method for "
          "the user data in every section in the C-Plane message.",
          HFILL}
         },

        /* Section 6.3.3.13 */
        {&hf_oran_udCompHdrIqWidth,
         {"User Data IQ width", "oran_fh_cus.udCompHdrWidth",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_width), 0xf0,
          "This parameter defines the IQ bit width "
          "for the user data in every section in the C-Plane message.",
          HFILL}
        },

#if 0
        /* Section 6.3.3.14 */
        {&hf_oran_udCompParam,
         {"User Data Compression Parameter", "oran_fh_cus.udCompParam",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(udCompParams), 0x0,
          "This parameter applies to whatever compression method is specified "
          "by the associated sectionID's compMeth value.",
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

        { &hf_oran_rsvd4,
          { "Reserved", "oran_fh_cus.reserved4",
            FT_UINT8, BASE_DEC,
            NULL, 0xf0,
            "Reserved for future use", HFILL }
        },

        { &hf_oran_rsvd8,
          { "Reserved", "oran_fh_cus.reserved8",
            FT_UINT8, BASE_DEC,
            NULL, 0x00,
            "Reserved for future use", HFILL }
        },

        { &hf_oran_rsvd16,
          { "Reserved", "oran_fh_cus.reserved16",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            "Reserved for future use", HFILL }
        },

        { &hf_oran_exponent,
          { "Exponent", "oran_fh_cus.exponent",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "This parameter exponent applicable to the I & Q mantissas. "
            "NOTE : Exponent is used for all mantissa sample sizes(i.e. 6bit "
            "- 16bit). Likewise, a native \"uncompressed\" format is not supported "
            "within this specification.",
            HFILL }
        },

        { &hf_oran_iq_user_data,
          { "IQ User Data", "oran_fh_cus.iq_user_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "This parameter is used for the In-phase and Quadrature sample "
            "mantissa. Twelve I/Q Samples are included per resource block. The width "
            "of the mantissa can be between 6 and 16 bits",
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
            "This is a calculated field for the RefA ID, which provides a "
            "reference in time.",
            HFILL }
        },

        { &hf_oran_disable_bfws,
          { "disableBFWs", "oran_fh_cus.disableBFWs",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            "Indicate if BFWs under section extension are disabled.",
            HFILL }
        },
        { &hf_oran_rad,
          { "RAD", "oran_fh_cus.rad",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            "Reset After PRB Discontinuity.",
            HFILL }
        },
        { &hf_oran_num_bund_prbs,
          { "numBundPrb", "oran_fh_cus.numBundPrbs",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Number of bundled PRBs per BFWs.",
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
            "From preference",
            HFILL }
        },


        { &hf_oran_samples_prb,
          {"PRB", "oran_fh_cus.prb",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Grouping of samples for a particular PRB",
            HFILL}
         },

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

        /* 5.4.7.10.1 */
        { &hf_oran_beamGroupType,
          { "beamGroupType", "oran_fh_cus.beamGroupType",
            FT_UINT8, BASE_DEC,
            VALS(beam_group_type_vals), 0xc0,
            "The type of beam grouping",
            HFILL }
        },
        /* 5.4.7.10.2 */
        { &hf_oran_numPortc,
          { "numPortc", "oran_fh_cus.numPortc",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            "The number of eAxC ports",
            HFILL }
        },

        /* 5.4.7.4.1 */
        { &hf_oran_csf,
          { "csf", "oran_fh_cus.csf",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            "constellation shift flag",
            HFILL }
        },
        /* 5.4.7.4.2 */
        { &hf_oran_modcompscaler,
          { "modCompScaler", "oran_fh_cus.modcompscaler",
            FT_UINT16, BASE_DEC,
            NULL, 0x7fff,
            "modulation compression scaler value",
            HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
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
        &ett_oran_bfw,
        &ett_oran_offset_start_prb_num_prb,
        &ett_oran_prb_cisamples,
        &ett_oran_cisample
    };

    expert_module_t* expert_oran;

    static ei_register_info ei[] = {
        { &ei_oran_invalid_bfw_iqwidth, { "oran_fh_cus.bfw_iqwidth_invalid", PI_MALFORMED, PI_ERROR, "Invalid IQ Width", EXPFILL }},
        { &ei_oran_invalid_num_bfw_weights, { "oran_fh_cus.num_bf_weights_invalid", PI_MALFORMED, PI_ERROR, "Invalid number of BF Weights", EXPFILL }},
        { &ei_oran_unsupported_bfw_compression_method, { "oran_fh_cus.unsupported_bfw_compression_method", PI_UNDECODED, PI_WARN, "Unsupported BFW Compression Method", EXPFILL }},
        { &ei_oran_invalid_sample_bit_width, { "oran_fh_cus.invalid_sample_bit_width", PI_UNDECODED, PI_ERROR, "Unsupported sample bit width", EXPFILL }},
        { &ei_oran_reserved_numBundPrb, { "oran_fh_cus.reserved_numBundPrb", PI_MALFORMED, PI_ERROR, "Reserved value of numBundPrb", EXPFILL }},
        { &ei_oran_extlen_wrong, { "oran_fh_cus.extlen_wrong", PI_MALFORMED, PI_ERROR, "extlen doesn't match number of dissected bytes", EXPFILL }},
        { &ei_oran_invalid_eaxc_bit_width, { "oran_fh_cus.invalid_exac_bit_width", PI_UNDECODED, PI_ERROR, "Inconsistent eAxC bit width", EXPFILL }},
        { &ei_oran_extlen_zero, { "oran_fh_cus.extlen_zero", PI_MALFORMED, PI_ERROR, "extlen - zero is reserved value", EXPFILL }}
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
        "The bit width of DU Port ID, sum of a,b,c&d must be 16", 10, &pref_du_port_id_bits);
    prefs_register_uint_preference(oran_module, "oran.bandsector_id_bits", "BandSector ID bits [b]",
        "The bit width of BandSector ID, sum of a,b,c&d must be 16", 10, &pref_bandsector_id_bits);
    prefs_register_uint_preference(oran_module, "oran.cc_id_bits", "CC ID bits [c]",
        "The bit width of CC ID, sum of a,b,c&d must be 16", 10, &pref_cc_id_bits);
    prefs_register_uint_preference(oran_module, "oran.ru_port_id_bits", "RU Port ID bits [d]",
        "The bit width of RU Port ID, sum of a,b,c&d must be 16", 10, &pref_ru_port_id_bits);

    prefs_register_uint_preference(oran_module, "oran.iq_bitwidth_up", "IQ Bitwidth Uplink",
        "The bit width of a sample in the Uplink", 10, &pref_sample_bit_width_uplink);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_up", "Uplink User Data Compression",
        "Uplink User Data Compression", &pref_iqCompressionUplink, compression_options, TRUE);
    prefs_register_bool_preference(oran_module, "oran.ud_comp_hdr_up", "udCompHdr field is present for uplink",
        "The udCompHdr field in U-Plane messages may or may not be present, depending on the "
        "configuration of the O-RU. This preference instructs the dissector to expect "
        "this field to be present in uplink messages.", &pref_includeUdCompHeaderUplink);

    prefs_register_uint_preference(oran_module, "oran.iq_bitwidth_down", "IQ Bitwidth Downlink",
        "The bit width of a sample in the Downlink", 10, &pref_sample_bit_width_downlink);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_down", "Downlink User Data Compression",
        "Downlink User Data Compression", &pref_iqCompressionDownlink, compression_options, TRUE);
    prefs_register_bool_preference(oran_module, "oran.ud_comp_hdr_down", "udCompHdr field is present for downlink",
        "The udCompHdr field in U-Plane messages may or may not be present, depending on the "
        "configuration of the O-RU. This preference instructs the dissector to expect "
        "this field to be present in downlink messages.", &pref_includeUdCompHeaderDownlink);

    prefs_register_uint_preference(oran_module, "oran.rbs_in_uplane_section", "Total RBs in User-Plane data section",
        "This is used if numPrbu is signalled as 0", 10, &pref_data_plane_section_total_rbs);

    prefs_register_uint_preference(oran_module, "oran.num_weights_per_bundle", "Number of weights per bundle",
        "Used in decoding of section extension type 11 (Flexible BF weights)", 10, &pref_num_weights_per_bundle);

    prefs_register_uint_preference(oran_module, "oran.num_bf_antennas", "Number of BF Antennas",
        "Number of BF Antennas (used for C section type 6)", 10, &pref_num_bf_antennas);

    prefs_register_bool_preference(oran_module, "oran.show_iq_samples", "Show IQ Sample values",
        "When enabled, for U-Plane frames show each I and Q value in PRB.", &pref_showIQSampleValues);

    prefs_register_obsolete_preference(oran_module, "oran.num_bf_weights");
}

/* Simpler form of proto_reg_handoff_oran which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_oran(void)
{
    create_dissector_handle(dissect_oran, proto_oran);
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
