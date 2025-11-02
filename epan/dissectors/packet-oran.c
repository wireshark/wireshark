/* packet-oran.c
 * Routines for O-RAN fronthaul UC-plane dissection
 * Copyright 2020, Jan Schiefer, Keysight Technologies, Inc.
 * Copyright 2020- Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * Dissector for the O-RAN Fronthaul CUS protocol specification.
  * See https://specifications.o-ran.org/specifications, WG4, Fronthaul Interfaces Workgroup
  * The current implementation is based on the ORAN-WG4.CUS.0-v17.01 specification.
  *   - haven't spotted any differences in v18.00
  * Note that other eCPRI message types are handled in packet-ecpri.c
  */

#include <config.h>

#include <math.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#include <epan/tfs.h>

#include <wsutil/ws_roundup.h>
#include <wsutil/ws_padding_to.h>

#include "epan/dissectors/packet-oran.h"

/* N.B. dissector preferences are taking the place of (some) M-plane parameters, so unfortunately it can be
 * fiddly to get the preferences into a good state to decode a given capture..
 * TODO:
 * - for U-Plane, track back to last C-Plane frame for that eAxC
 *     - use udCompHdr values from C-Plane if not overridden by U-Plane?
 *     N.B. this matching is tricky see 7.8.1 Coupling of C-Plane and U-Plane
 * - Radio transport layer (eCPRI) fragmentation / reassembly
 * - Detect/indicate signs of application layer fragmentation?
 * - Not handling M-plane setting for "little endian byte order" as applied to IQ samples and beam weights
 * - for section extensions, check more constraints (which other extension types appear with them, order)
 * - when some section extensions are present, some section header fields are effectively ignored - flag any remaining ("ignored, "shall")?
 * - re-order items (decl and hf definitions) to match spec order?
 * - track energy-saving status, and identify TRX or ASM commands as 'Sleep extension'
 */

/* Prototypes */
void proto_reg_handoff_oran(void);
void proto_register_oran(void);

/* Initialize the protocol and registered fields */
static int proto_oran;

static int oran_tap = -1;

static int hf_oran_du_port_id;
static int hf_oran_bandsector_id;
static int hf_oran_cc_id;
static int hf_oran_ru_port_id;
static int hf_oran_sequence_id;
static int hf_oran_e_bit;
static int hf_oran_subsequence_id;
static int hf_oran_previous_frame;


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
static int hf_oran_udCompLen;
static int hf_oran_numberOfUEs;
static int hf_oran_timeOffset;
static int hf_oran_frameStructure_fft;
static int hf_oran_frameStructure_subcarrier_spacing;
static int hf_oran_cpLength;
static int hf_oran_timing_header;
static int hf_oran_section_id;
static int hf_oran_rb;
static int hf_oran_symInc;
static int hf_oran_startPrbc;
static int hf_oran_reMask_re1;
static int hf_oran_reMask_re2;
static int hf_oran_reMask_re3;
static int hf_oran_reMask_re4;
static int hf_oran_reMask_re5;
static int hf_oran_reMask_re6;
static int hf_oran_reMask_re7;
static int hf_oran_reMask_re8;
static int hf_oran_reMask_re9;
static int hf_oran_reMask_re10;
static int hf_oran_reMask_re11;
static int hf_oran_reMask_re12;
static int hf_oran_reMask;
static int hf_oran_numPrbc;
static int hf_oran_numSymbol;
static int hf_oran_ef;
static int hf_oran_beamId;

static int hf_oran_sinrCompHdrIqWidth_pref;
static int hf_oran_sinrCompHdrMeth_pref;

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
static int hf_oran_reserved_3bits;
static int hf_oran_reserved_4bits;
static int hf_oran_reserved_last_4bits;
static int hf_oran_reserved_last_5bits;
static int hf_oran_reserved_6bits;
static int hf_oran_reserved_last_6bits;
static int hf_oran_reserved_7bits;
static int hf_oran_reserved_last_7bits;
static int hf_oran_reserved_8bits;
static int hf_oran_reserved_16bits;
static int hf_oran_reserved_15bits;
static int hf_oran_reserved_bit1;
static int hf_oran_reserved_bit2;
static int hf_oran_reserved_bit4;
static int hf_oran_reserved_bit5;
static int hf_oran_reserved_bits123;
static int hf_oran_reserved_bits456;

static int hf_oran_bundle_offset;
static int hf_oran_cont_ind;

static int hf_oran_bfwCompHdr;
static int hf_oran_bfwCompHdr_iqWidth;
static int hf_oran_bfwCompHdr_compMeth;
static int hf_oran_symbolId;
static int hf_oran_startPrbu;
static int hf_oran_numPrbu;

static int hf_oran_udCompParam;
static int hf_oran_sReSMask;
static int hf_oran_sReSMask_re12;
static int hf_oran_sReSMask_re11;
static int hf_oran_sReSMask_re10;
static int hf_oran_sReSMask_re9;
static int hf_oran_sReSMask_re8;
static int hf_oran_sReSMask_re7;
static int hf_oran_sReSMask_re6;
static int hf_oran_sReSMask_re5;
static int hf_oran_sReSMask_re4;
static int hf_oran_sReSMask_re3;
static int hf_oran_sReSMask_re2;
static int hf_oran_sReSMask_re1;

static int hf_oran_sReSMask1;
static int hf_oran_sReSMask2;
static int hf_oran_sReSMask1_2_re12;
static int hf_oran_sReSMask1_2_re11;
static int hf_oran_sReSMask1_2_re10;
static int hf_oran_sReSMask1_2_re9;

static int hf_oran_bfwCompParam;

static int hf_oran_iSample;
static int hf_oran_qSample;

static int hf_oran_ciCompParam;

static int hf_oran_blockScaler;
static int hf_oran_compBitWidth;
static int hf_oran_compShift;

static int hf_oran_active_beamspace_coefficient_n1;
static int hf_oran_active_beamspace_coefficient_n2;
static int hf_oran_active_beamspace_coefficient_n3;
static int hf_oran_active_beamspace_coefficient_n4;
static int hf_oran_active_beamspace_coefficient_n5;
static int hf_oran_active_beamspace_coefficient_n6;
static int hf_oran_active_beamspace_coefficient_n7;
static int hf_oran_active_beamspace_coefficient_n8;
static int hf_oran_activeBeamspaceCoefficientMask;
static int hf_oran_activeBeamspaceCoefficientMask_bits_set;

static int hf_oran_se6_repetition;

static int hf_oran_rbgSize;
static int hf_oran_rbgMask;
static int hf_oran_noncontig_priority;

static int hf_oran_symbol_mask;
static int hf_oran_symbol_mask_s13;
static int hf_oran_symbol_mask_s12;
static int hf_oran_symbol_mask_s11;
static int hf_oran_symbol_mask_s10;
static int hf_oran_symbol_mask_s9;
static int hf_oran_symbol_mask_s8;
static int hf_oran_symbol_mask_s7;
static int hf_oran_symbol_mask_s6;
static int hf_oran_symbol_mask_s5;
static int hf_oran_symbol_mask_s4;
static int hf_oran_symbol_mask_s3;
static int hf_oran_symbol_mask_s2;
static int hf_oran_symbol_mask_s1;
static int hf_oran_symbol_mask_s0;

static int hf_oran_exponent;
static int hf_oran_iq_user_data;

static int hf_oran_disable_bfws;
static int hf_oran_rad;
static int hf_oran_num_bund_prbs;
static int hf_oran_beam_id;
static int hf_oran_num_weights_per_bundle;

static int hf_oran_ack_nack_req_id;

static int hf_oran_frequency_range;
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
static int hf_oran_mc_scale_re_mask_re1;
static int hf_oran_mc_scale_re_mask_re2;
static int hf_oran_mc_scale_re_mask_re3;
static int hf_oran_mc_scale_re_mask_re4;
static int hf_oran_mc_scale_re_mask_re5;
static int hf_oran_mc_scale_re_mask_re6;
static int hf_oran_mc_scale_re_mask_re7;
static int hf_oran_mc_scale_re_mask_re8;
static int hf_oran_mc_scale_re_mask_re9;
static int hf_oran_mc_scale_re_mask_re10;
static int hf_oran_mc_scale_re_mask_re11;
static int hf_oran_mc_scale_re_mask_re12;
static int hf_oran_mc_scale_re_mask_re1_even;
static int hf_oran_mc_scale_re_mask_re2_even;
static int hf_oran_mc_scale_re_mask_re3_even;
static int hf_oran_mc_scale_re_mask_re4_even;
static int hf_oran_mc_scale_re_mask_re5_even;
static int hf_oran_mc_scale_re_mask_re6_even;
static int hf_oran_mc_scale_re_mask_re7_even;
static int hf_oran_mc_scale_re_mask_re8_even;
static int hf_oran_mc_scale_re_mask_re9_even;
static int hf_oran_mc_scale_re_mask_re10_even;
static int hf_oran_mc_scale_re_mask_re11_even;
static int hf_oran_mc_scale_re_mask_re12_even;

static int hf_oran_mc_scale_re_mask;
static int hf_oran_mc_scale_re_mask_even;

static int hf_oran_mc_scale_offset;

static int hf_oran_eAxC_mask;
static int hf_oran_technology;
static int hf_oran_nullLayerInd;

static int hf_oran_se19_repetition;
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
static int hf_oran_multiSDScope;
static int hf_oran_RbgIncl;

static int hf_oran_ci_prb_group_size;
static int hf_oran_prg_size_st5;
static int hf_oran_prg_size_st6;

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

static int hf_oran_cmd_scope;
static int hf_oran_number_of_st4_cmds;

static int hf_oran_st4_cmd_header;
static int hf_oran_st4_cmd_type;
static int hf_oran_st4_cmd_len;
static int hf_oran_st4_cmd_num_slots;
static int hf_oran_st4_cmd_ack_nack_req_id;

static int hf_oran_st4_cmd;

static int hf_oran_sleepmode_trx;
static int hf_oran_sleepmode_asm;
static int hf_oran_log2maskbits;
static int hf_oran_num_slots_ext;
static int hf_oran_antMask_trx_control;

static int hf_oran_ready;
static int hf_oran_number_of_acks;
static int hf_oran_number_of_nacks;
static int hf_oran_ackid;
static int hf_oran_nackid;

static int hf_oran_acknack_request_frame;
static int hf_oran_acknack_request_time;
static int hf_oran_acknack_request_type;
static int hf_oran_acknack_response_frame;
static int hf_oran_acknack_response_time;

static int hf_oran_disable_tdbfns;
static int hf_oran_td_beam_group;
static int hf_oran_disable_tdbfws;
static int hf_oran_td_beam_num;

static int hf_oran_dir_pattern;
static int hf_oran_guard_pattern;

static int hf_oran_ecpri_pcid;
static int hf_oran_ecpri_rtcid;
static int hf_oran_ecpri_seqid;

static int hf_oran_num_sym_prb_pattern;
static int hf_oran_prb_mode;
static int hf_oran_sym_prb_pattern;
static int hf_oran_sym_mask;
static int hf_oran_num_mc_scale_offset;
static int hf_oran_prb_pattern;
static int hf_oran_prb_block_offset;
static int hf_oran_prb_block_size;

static int hf_oran_codebook_index;
static int hf_oran_layerid;
static int hf_oran_numlayers;
static int hf_oran_txscheme;
static int hf_oran_crs_remask;
static int hf_oran_crs_shift;
static int hf_oran_crs_symnum;
static int hf_oran_beamid_ap1;
static int hf_oran_beamid_ap2;
static int hf_oran_beamid_ap3;

static int hf_oran_port_list_index;
static int hf_oran_alpn_per_sym;
static int hf_oran_ant_dmrs_snr;
static int hf_oran_user_group_size;
static int hf_oran_user_group_id;
static int hf_oran_entry_type;
static int hf_oran_dmrs_port_number;
static int hf_oran_ueid_reset;

static int hf_oran_dmrs_symbol_mask;
static int hf_oran_dmrs_symbol_mask_s13;
static int hf_oran_dmrs_symbol_mask_s12;
static int hf_oran_dmrs_symbol_mask_s11;
static int hf_oran_dmrs_symbol_mask_s10;
static int hf_oran_dmrs_symbol_mask_s9;
static int hf_oran_dmrs_symbol_mask_s8;
static int hf_oran_dmrs_symbol_mask_s7;
static int hf_oran_dmrs_symbol_mask_s6;
static int hf_oran_dmrs_symbol_mask_s5;
static int hf_oran_dmrs_symbol_mask_s4;
static int hf_oran_dmrs_symbol_mask_s3;
static int hf_oran_dmrs_symbol_mask_s2;
static int hf_oran_dmrs_symbol_mask_s1;
static int hf_oran_dmrs_symbol_mask_s0;

static int hf_oran_scrambling;
static int hf_oran_nscid;
static int hf_oran_dtype;
static int hf_oran_cmd_without_data;
static int hf_oran_lambda;
static int hf_oran_first_prb;
static int hf_oran_last_prb;
static int hf_oran_low_papr_type;
static int hf_oran_hopping_mode;

static int hf_oran_tx_win_for_on_air_symbol_l;
static int hf_oran_tx_win_for_on_air_symbol_r;

static int hf_oran_num_fo_fb;
static int hf_oran_freq_offset_fb;

static int hf_oran_num_ue_sinr_rpt;
static int hf_oran_num_sinr_per_prb;
static int hf_oran_num_sinr_per_prb_right;

static int hf_oran_sinr_value;

static int hf_oran_measurement_report;
static int hf_oran_mf;
static int hf_oran_meas_data_size;
static int hf_oran_meas_type_id;
static int hf_oran_ipn_power;
static int hf_oran_ue_tae;
static int hf_oran_ue_layer_power;
static int hf_oran_num_elements;
static int hf_oran_ant_dmrs_snr_val;
static int hf_oran_ue_freq_offset;

static int hf_oran_measurement_command;

static int hf_oran_beam_type;
static int hf_oran_meas_cmd_size;

static int hf_oran_symbol_reordering_layer;
static int hf_oran_dmrs_entry;

static int hf_oran_c_section_common;
static int hf_oran_c_section;
static int hf_oran_u_section;

static int hf_oran_u_section_ul_symbol_time;
static int hf_oran_u_section_ul_symbol_frames;
static int hf_oran_u_section_ul_symbol_first_frame;
static int hf_oran_u_section_ul_symbol_last_frame;

static int hf_oran_cd_scg_size;
static int hf_oran_cd_scg_phase_step;

/* Computed fields */
static int hf_oran_c_eAxC_ID;
static int hf_oran_refa;

/* Convenient fields for filtering, mostly shown as hidden */
static int hf_oran_cplane;
static int hf_oran_uplane;
static int hf_oran_bf;      /* to match frames that configure beamforming in any way */
static int hf_oran_zero_prb;

static int hf_oran_ul_cplane_ud_comp_hdr_frame;

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
static int ett_oran_bfw_bundle;
static int ett_oran_bfw;
static int ett_oran_frequency_range;
static int ett_oran_prb_cisamples;
static int ett_oran_cisample;
static int ett_oran_udcomphdr;
static int ett_oran_udcompparam;
static int ett_oran_cicomphdr;
static int ett_oran_cicompparam;
static int ett_oran_bfwcomphdr;
static int ett_oran_bfwcompparam;
static int ett_oran_ext19_port;
static int ett_oran_prb_allocation;
static int ett_oran_punc_pattern;
static int ett_oran_bfacomphdr;
static int ett_oran_modcomp_param_set;
static int ett_oran_st4_cmd_header;
static int ett_oran_st4_cmd;
static int ett_oran_sym_prb_pattern;
static int ett_oran_measurement_report;
static int ett_oran_measurement_command;
static int ett_oran_sresmask;
static int ett_oran_c_section_common;
static int ett_oran_c_section;
static int ett_oran_remask;
static int ett_oran_mc_scale_remask;
static int ett_oran_symbol_reordering_layer;
static int ett_oran_dmrs_entry;
static int ett_oran_dmrs_symbol_mask;
static int ett_oran_symbol_mask;
static int ett_active_beamspace_coefficient_mask;


/* Don't want all extensions to open and close together. Use extType-1 entry */
static int ett_oran_c_section_extension[HIGHEST_EXTTYPE];

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
static expert_field ei_oran_st8_nackid;
static expert_field ei_oran_st4_no_cmds;
static expert_field ei_oran_st4_zero_len_cmd;
static expert_field ei_oran_st4_wrong_len_cmd;
static expert_field ei_oran_st4_unknown_cmd;
static expert_field ei_oran_mcot_out_of_range;
static expert_field ei_oran_se10_unknown_beamgrouptype;
static expert_field ei_oran_se10_not_allowed;
static expert_field ei_oran_start_symbol_id_not_zero;
static expert_field ei_oran_trx_control_cmd_scope;
static expert_field ei_oran_unhandled_se;
static expert_field ei_oran_bad_symbolmask;
static expert_field ei_oran_numslots_not_zero;
static expert_field ei_oran_version_unsupported;
static expert_field ei_oran_laa_msg_type_unsupported;
static expert_field ei_oran_se_on_unsupported_st;
static expert_field ei_oran_cplane_unexpected_sequence_number_ul;
static expert_field ei_oran_cplane_unexpected_sequence_number_dl;
static expert_field ei_oran_uplane_unexpected_sequence_number_ul;
static expert_field ei_oran_uplane_unexpected_sequence_number_dl;
static expert_field ei_oran_acknack_no_request;
static expert_field ei_oran_udpcomphdr_should_be_zero;
static expert_field ei_oran_radio_fragmentation_c_plane;
static expert_field ei_oran_radio_fragmentation_u_plane;
static expert_field ei_oran_lastRbdid_out_of_range;
static expert_field ei_oran_rbgMask_beyond_last_rbdid;
static expert_field ei_oran_unexpected_measTypeId;
static expert_field ei_oran_unsupported_compression_method;
static expert_field ei_oran_ud_comp_len_wrong_size;
static expert_field ei_oran_sresmask2_not_zero_with_rb;
static expert_field ei_oran_st6_rb_shall_be_0;
static expert_field ei_oran_st9_not_ul;
static expert_field ei_oran_st10_numsymbol_not_14;
static expert_field ei_oran_st10_startsymbolid_not_0;
static expert_field ei_oran_st10_not_ul;
static expert_field ei_oran_se24_nothing_to_inherit;
static expert_field ei_oran_num_sinr_per_prb_unknown;
static expert_field ei_oran_start_symbol_id_bits_ignored;
static expert_field ei_oran_user_group_id_reserved_value;
static expert_field ei_oran_port_list_index_zero;
static expert_field ei_oran_ul_uplane_symbol_too_long;


/* These are the message types handled by this dissector */
#define ECPRI_MT_IQ_DATA            0
#define ECPRI_MT_RT_CTRL_DATA       2


/* Preference settings - try to set reasonable defaults */
static unsigned pref_du_port_id_bits    = 4;
static unsigned pref_bandsector_id_bits = 4;
static unsigned pref_cc_id_bits         = 4;
static unsigned pref_ru_port_id_bits    = 4;

/* TODO: ideally should be per-flow */
static unsigned pref_sample_bit_width_uplink   = 14;
static unsigned pref_sample_bit_width_downlink = 14;
static unsigned pref_sample_bit_width_sinr   = 14;

/* 8.3.3.15 Compression schemes */
#define COMP_NONE                             0
#define COMP_BLOCK_FP                         1
#define COMP_BLOCK_SCALE                      2
#define COMP_U_LAW                            3
#define COMP_MODULATION                       4
#define BFP_AND_SELECTIVE_RE                  5
#define MOD_COMPR_AND_SELECTIVE_RE            6
#define BFP_AND_SELECTIVE_RE_WITH_MASKS       7
#define MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS 8

/* TODO: these ideally should be per-flow too */
static int pref_iqCompressionUplink = COMP_BLOCK_FP;
static int pref_iqCompressionDownlink = COMP_BLOCK_FP;

static int pref_iqCompressionSINR = COMP_BLOCK_FP;


/* Is udCompHeader present (both directions) */
static int pref_includeUdCompHeaderUplink = 2;     /* start heuristic */
static int pref_includeUdCompHeaderDownlink = 2;   /* start heuristic */

static unsigned pref_data_plane_section_total_rbs = 273;
static unsigned pref_num_bf_antennas = 32;
static bool pref_showIQSampleValues = true;

/* Based upon m-plane param, so will be system-wide */
static int  pref_support_udcompLen = 2;            /* start heuristic, can force other settings if necessary */
static bool udcomplen_heuristic_result_set = false;
static bool udcomplen_heuristic_result = false;

/* st6-4byte-alignment-required */
static bool st6_4byte_alignment = false;

/* Requested, allows I/Q to be stored as integers.. */
static bool show_unscaled_values = false;

/* Initialized off. Timing is in microseconds. */
static unsigned us_allowed_for_ul_in_symbol = 0;

static const enum_val_t dl_compression_options[] = {
    { "COMP_NONE",                             "No Compression",                                                             COMP_NONE },
    { "COMP_BLOCK_FP",                         "Block Floating Point Compression",                                           COMP_BLOCK_FP },
    { "COMP_BLOCK_SCALE",                      "Block Scaling Compression",                                                  COMP_BLOCK_SCALE },
    { "COMP_U_LAW",                            "u-Law Compression",                                                          COMP_U_LAW },
    { "COMP_MODULATION",                       "Modulation Compression",                                                     COMP_MODULATION },
    { "BFP_AND_SELECTIVE_RE",                  "Block Floating Point + selective RE sending",                                BFP_AND_SELECTIVE_RE },
    { "MOD_COMPR_AND_SELECTIVE_RE",            "Modulation Compression + selective RE sending",                              MOD_COMPR_AND_SELECTIVE_RE },
    { "BFP_AND_SELECTIVE_RE_WITH_MASKS",       "Block Floating Point + selective RE sending with masks in section header",   BFP_AND_SELECTIVE_RE_WITH_MASKS },
    { "MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS", "Modulation Compression + selective RE sending with masks in section header", MOD_COMPR_AND_SELECTIVE_RE },
    { NULL, NULL, 0 }
};

static const enum_val_t ul_compression_options[] = {
    { "COMP_NONE",                             "No Compression",                                                           COMP_NONE },
    { "COMP_BLOCK_FP",                         "Block Floating Point Compression",                                         COMP_BLOCK_FP },
    { "COMP_BLOCK_SCALE",                      "Block Scaling Compression",                                                COMP_BLOCK_SCALE },
    { "COMP_U_LAW",                            "u-Law Compression",                                                        COMP_U_LAW },
    { "BFP_AND_SELECTIVE_RE",                  "Block Floating Point + selective RE sending",                              BFP_AND_SELECTIVE_RE },
    { "BFP_AND_SELECTIVE_RE_WITH_MASKS",       "Block Floating Point + selective RE sending with masks in section header", BFP_AND_SELECTIVE_RE_WITH_MASKS },
    { NULL, NULL, 0 }
};

static const enum_val_t udcomplen_support_options[] = {
    { "NOT_SUPPORTED",              "Not Supported",     0 },
    { "SUPPORTED",                  "Supported",         1 },
    { "HEURISTIC",                  "Attempt Heuristic", 2 },
    { NULL, NULL, 0 }
};

static const enum_val_t udcomphdr_present_options[] = {
    { "NOT_PRESENT",               "Not Present",       0 },
    { "PRESENT",                   "Present",           1 },
    { "HEURISTIC",                 "Attempt Heuristic", 2 },
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
    { DIR_UPLINK,   "Uplink" },   /* gNB Rx */
    { DIR_DOWNLINK, "Downlink" }, /* gNB Tx */
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
    {9, 9,  "Mixed numerology and other channels except PRACH and NB-IoT"},
    {9, 15, "Reserved"},
    {0, 0, NULL}
};

static const range_string section_types[] = {
    { SEC_C_UNUSED_RB,         SEC_C_UNUSED_RB,         "Unused Resource Blocks or symbols in Downlink or Uplink" },
    { SEC_C_NORMAL,            SEC_C_NORMAL,            "Most DL/UL radio channels" },
    { SEC_C_RSVD2,             SEC_C_RSVD2,             "Reserved for future use" },
    { SEC_C_PRACH,             SEC_C_PRACH,             "PRACH and mixed-numerology channels" },
    { SEC_C_SLOT_CONTROL,      SEC_C_SLOT_CONTROL,      "Slot Configuration Control" },
    { SEC_C_UE_SCHED,          SEC_C_UE_SCHED,          "UE scheduling information (UE-ID assignment to section)" },
    { SEC_C_CH_INFO,           SEC_C_CH_INFO,           "Channel information" },
    { SEC_C_LAA,               SEC_C_LAA,               "LAA (License Assisted Access)" },
    { SEC_C_ACK_NACK_FEEDBACK, SEC_C_ACK_NACK_FEEDBACK, "ACK/NACK Feedback" },
    { SEC_C_SINR_REPORTING,    SEC_C_SINR_REPORTING,    "SINR Reporting" },
    { SEC_C_RRM_MEAS_REPORTS,  SEC_C_RRM_MEAS_REPORTS,  "RRM Measurement Reports" },
    { SEC_C_REQUEST_RRM_MEAS,  SEC_C_REQUEST_RRM_MEAS,  "Request RRM Measurements" },
    { 12,                      255,                     "Reserved for future use" },
    { 0, 0, NULL} };

static const range_string section_types_short[] = {
    { SEC_C_UNUSED_RB,         SEC_C_UNUSED_RB,         "(Unused RBs)        " },
    { SEC_C_NORMAL,            SEC_C_NORMAL,            "(Most channels)     " },
    { SEC_C_RSVD2,             SEC_C_RSVD2,             "(reserved)          " },
    { SEC_C_PRACH,             SEC_C_PRACH,             "(PRACH/mixed-\u03bc)" },
    { SEC_C_SLOT_CONTROL,      SEC_C_SLOT_CONTROL,      "(Slot info)         " },
    { SEC_C_UE_SCHED,          SEC_C_UE_SCHED,          "(UE scheduling info)" },
    { SEC_C_CH_INFO,           SEC_C_CH_INFO,           "(Channel info)      " },
    { SEC_C_LAA,               SEC_C_LAA,               "(LAA)               " },
    { SEC_C_ACK_NACK_FEEDBACK, SEC_C_ACK_NACK_FEEDBACK, "(ACK/NACK)          " },
    { SEC_C_SINR_REPORTING,    SEC_C_SINR_REPORTING,    "(SINR Reporting)    " },
    { SEC_C_RRM_MEAS_REPORTS,  SEC_C_RRM_MEAS_REPORTS,  "(RRM Meas Reports)  " },
    { SEC_C_REQUEST_RRM_MEAS,  SEC_C_REQUEST_RRM_MEAS,  "(Req RRM Meas)      " },
    { 12,                      255,                     "Reserved for future use" },
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
    {0,  0,  "Reserved (no FFT/iFFT processing)"},
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
    { 5,  11, "Reserved" }, /* N.B., 5 was 480kHz in early spec versions */
    { 12, 12, "SCS 1.25 kHz, 1 slot/subframe, slot length 1 ms" },
    { 13, 13, "SCS 3.75 kHz(LTE - specific), 1 slot/subframe, slot length 1 ms" },
    { 14, 14, "SCS 5 kHz, 1 slot/subframe, slot length 1 ms" },
    { 15, 15, "SCS 7.5 kHz(LTE - specific), 1 slot/subframe, slot length 1 ms" },
    { 0, 0, NULL }
};

/* Table 7.5.3.14-1 laaMsgType definition */
static const range_string laaMsgTypes[] = {
    {0, 0,  "LBT_PDSCH_REQ - lls - O-DU to O-RU request to obtain a PDSCH channel"},
    {1, 1,  "LBT_DRS_REQ - lls - O-DU to O-RU request to obtain the channel and send DRS"},
    {2, 2,  "LBT_PDSCH_RSP - O-RU to O-DU response, channel acq success or failure"},
    {3, 3,  "LBT_DRS_RSP - O-RU to O-DU response, DRS sending success or failure"},
    {4, 4,  "LBT_Buffer_Error - O-RU to O-DU response, reporting buffer overflow"},
    {5, 5,  "LBT_CWCONFIG_REQ - O-DU to O-RU request, congestion window configuration"},
    {6, 6,  "LBT_CWCONFIG_RST - O-RU to O-DU request, congestion window config, response"},
    {7, 15, "reserved for future methods"},
    {0, 0, NULL}
};

static const range_string freq_offset_fb_values[] = {
    {0,      0,        "no frequency offset"},
    {8000,   8000,     "value not provided"},
    {1,      30000,    "positive frequency offset, (0, +0.5] subcarrier"},
    {0x8ad0, 0xffff,   "negative frequency offset, [-0.5, 0) subcarrier"},
    {0x0,    0xffff,   "reserved"},
    {0, 0, NULL}
};

static const value_string num_sinr_per_prb_vals[] = {
    { 0,  "1" },
    { 1,  "2" },
    { 2,  "3" },
    { 3,  "4" },
    { 4,  "6" },
    { 5,  "12" },
    { 6,  "reserved" },
    { 7,  "reserved" },
    { 0, NULL}
};

static const value_string meas_type_id_vals[] = {
    { 1,  "UE Timing Advance Error" },
    { 2,  "UE Layer power" },
    { 3,  "UE frequency offset" },
    { 4,  "Interference plus Noise for allocated PRBs" },
    { 5,  "Interference plus Noise for unallocated PRBs" },
    { 6,  "DMRS SNR per antenna" },
    { 0, NULL}
};

static const value_string beam_type_vals[] = {
    { 0,  "List of beamId values" },
    { 1,  "Range of beamId values" },
    { 0, NULL}
};

/* 7.7.24.3 */
static const value_string entry_type_vals[] = {
    { 0,  "inherit config from preceding entry (2 or 3) ueIdReset=0" },
    { 1,  "inherit config from preceding entry (2 or 3) ueIdReset=1" },
    { 2,  "related parameters if have transform precoding disabled " },
    { 3,  "related parameters if have transform precoding enabled  " },
    { 0, NULL}
};

/* Table 7.7.29.3-1 */
static const range_string cd_scg_size_vals[] = {
    { 0, 0,  "1 subcarrier" },
    { 1, 1,  "1 RB x N subcarriers" },
    { 2, 2,  "2 RB x N subcarriers" },
    { 3, 3,  "4 RB x N subcarriers" },
    { 4, 4,  "8 RB x N subcarriers" },
    { 5, 5,  "16 RB x N subcarriers" },
    { 6, 6,  "32 RB x N subcarriers" },
    { 7, 15, "reserved"},
    { 0, 0, NULL}
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
    {24,    "PUSCH DMRS configuration"},
    {25,    "Symbol reordering for DMRS-BF"},
    {26,    "Frequency offset feedback"},
    {27,    "O-DU controlled dimensionality reduction"},
    {28,    "O-DU controlled frequency resolution for SINR reporting"},
    {29,    "Cyclic delay adjustment"},
    {0, NULL}
};

/**************************************************************************************/
/* Keep track for each Section Extension, which section types are allowed to carry it */
typedef struct {
    bool ST0;
    bool ST1;
    bool ST3;
    bool ST5;
    bool ST6;
    bool ST10;
    bool ST11;
} AllowedCTs_t;


static AllowedCTs_t ext_cts[HIGHEST_EXTTYPE] = {
    /* ST0    ST1    ST3    ST5    ST6   ST10    ST11 */
    { false, true,  true,  false, false, false, false},   // SE 1      (1,3)
    { false, true,  true,  false, false, false, false},   // SE 2      (1,3)
    { false, true,  true,  false, false, false, false},   // SE 3      (1,3)
    { false, true,  true,  true,  false, false, false},   // SE 4      (1,3,5)
    { false, true,  true,  true,  false, false, false},   // SE 5      (1,3,5)
    { false, true,  true,  true,  false, true,  true },   // SE 6      (1,3,5,10,11)
    { true,  false, false, false, false, false, false},   // SE 7      (0)
    { false, false, false, true,  false, false, false},   // SE 8      (5)
    { true,  true,  true,  true,  true,  true,  true },   // SE 9      (all)
    { false, true,  true,  true,  false, false, false},   // SE 10     (1,3,5)
    { false, true,  true,  false, false, false, false},   // SE 11     (1,3)
    { false, true,  true,  true,  false, true,  true },   // SE 12     (1,3,5,10,11)
    { false, true,  true,  true,  false, false, false},   // SE 13     (1,3,5)
    { false, false, false, true,  false, false, false},   // SE 14     (5)
    { false, false, false, true,  true,  false, false},   // SE 15     (5,6)
    { false, false, false, true,  false, false, false},   // SE 16     (5)
    { false, false, false, true,  false, false, false},   // SE 17     (5)
    { false, true,  true,  true,  false, false, false},   // SE 18     (1,3,5)
    { false, true,  true,  false, false, false, false},   // SE 19     (1,3)
    { true,  true,  true,  true,  true,  true,  true },   // SE 20     (0,1,3,5,10,11)
    { false, false, false, true,  true,  false, false},   // SE 21     (5,6)
    { true,  true,  true,  true,  true,  true,  true },   // SE 22     (all)
    { false, true,  true,  true,  false, false, false},   // SE 23     (1,3,5)
    { false, false, false, true,  false, false, false},   // SE 24     (5)
    { false, false, false, true,  false, false, false},   // SE 25     (5)
    { false, false, false, true,  false, false, false},   // SE 26     (5)
    { false, false, false, true,  false, false, false},   // SE 27     (5)
    { false, false, false, true,  false, false, false},   // SE 28     (5)
    { false, true,  true,  true,  false, false, false},   // SE 29     (1,3,5)
};

static bool se_allowed_in_st(unsigned se, unsigned ct)
{
    if (se==0 || se>HIGHEST_EXTTYPE) {
        /* Don't know about new SE, so don't complain.. */
        return true;
    }

    switch (ct) {
        case 1:
            return ext_cts[se-1].ST1;
        case 3:
            return ext_cts[se-1].ST3;
        case 5:
            return ext_cts[se-1].ST5;
        case 6:
            return ext_cts[se-1].ST6;
        case 10:
            return ext_cts[se-1].ST10;
        case 11:
            return ext_cts[se-1].ST11;
        default:
            /* New/unknown section type that includes 'ef'.. assume ok */
            return true;
    }
}

/************************************************************************************/

/* Table 7.7.1.2-2 */
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

/* 7.7.6.2 rbgSize (resource block group size) */
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
    {0x3, "beamId/ueId listing with associated port-list index"},
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

/* 7.5.3.22 */
static const value_string lbtPdschRes_vals[] = {
    {0,   "not sensing – indicates that the O-RU is transmitting data"},
    {1,   "currently sensing – indicates the O-RU has not yet acquired the channel"},
    {2,   "success – indicates that the channel was successfully acquired"},
    {3,   "Failure – indicates expiration of the LBT timer. The LBT process should be reset"},
    {0,   NULL}
};

/* Table 7.5.2.15-3 */
static const value_string ci_comp_opt_vals[] = {
    {0,   "compression per UE, one ciCompParam exists before the I/Q value of each UE"},
    {1,   "compression per PRB, one ciCompParam exists before the I/Q value of each PRB"},
    {0,   NULL}
};

/* 7.5.2.17 */
static const range_string cmd_scope_vals[] = {
    {0, 0,  "ARRAY-COMMAND"},
    {1, 1,  "CARRIER-COMMAND"},
    {2, 2,  "O-RU-COMMAND"},
    {3, 15, "reserved"},
    {0, 0,  NULL}
};

/* N.B., table in 7.5.3.38 is truncated.. */
static const range_string st4_cmd_type_vals[] = {
    {0, 0,   "reserved for future command types"},
    {1, 1,   "TIME_DOMAIN_BEAM_CONFIG"},
    {2, 2,   "TDD_CONFIG_PATTERN"},
    {3, 3,   "TRX_CONTROL"},
    {4, 4,   "ASM"},
    {5, 255, "reserved for future command types"},
    {0, 0,   NULL}
};

/* Table 7.5.3.51-1 */
static const value_string log2maskbits_vals[] = {
    {0,  "reserved"},
    {1,  "min antMask size is 16 bits.."},
    {2,  "min antMask size is 16 bits.."},
    {3,  "min antMask size is 16 bits.."},
    {4,  "16 bits"},
    {5,  "32 bits"},
    {6,  "64 bits"},
    {7,  "128 bits"},
    {8,  "256 bits"},
    {9,  "512 bits"},
    {10, "1024 bits"},
    {11, "2048 bits"},
    {12, "4096 bits"},
    {13, "8192 bits"},
    {14, "16384 bits"},
    {15, "reserved"},
    {0,  NULL}
};

/* Table 16.1-1 Sleep modes */
static const value_string sleep_mode_trx_vals[] = {
    { 0, "TRXC-mode0-wake-up-duration (symbol)"},
    { 1, "TRXC-mode1-wake-up-duration (L)"},
    { 2, "TRXC-mode2-wake-up-duration (M)"},
    { 3, "TRXC-mode3-wake-up-duration (N)"},
    { 0, NULL}
};

static const value_string sleep_mode_asm_vals[] = {
    { 0, "ASM-mode0-wake-up-duration (symbol)"},
    { 1, "ASM-mode1-wake-up-duration (L)"},
    { 2, "ASM-mode2-wake-up-duration (M)"},
    { 3, "ASM-mode3-wake-up-duration (N)"},
    { 0, NULL}
};

/* 7.7.21.3.1 */
static const value_string prg_size_st5_vals[] = {
    { 0, "reserved"},
    { 1, "Precoding resource block group size as WIDEBAND"},
    { 2, "Precoding resource block group size 2"},
    { 3, "Precoding resource block group size 4"},
    { 0, NULL}
};

/* 7.7.21.3.2 */
static const value_string prg_size_st6_vals[] = {
    { 0, "if ciPrbGroupSize is 2 or 4, then ciPrbGroupSize, else WIDEBAND"},
    { 1, "Precoding resource block group size as WIDEBAND"},
    { 2, "Precoding resource block group size 2"},
    { 3, "Precoding resource block group size 4"},
    { 0, NULL}
};

/* 7.7.24.4 */
static const value_string alpn_per_sym_vals[] = {
    { 0, "report one allocated IPN value per all allocated symbols with DMRS"},
    { 1, "report one allocated IPN value per group of consecutive DMRS symbols"},
    { 0, NULL}
};

/* 7.7.24.5 */
static const value_string ant_dmrs_snr_vals[] = {
    { 0, "O-RU shall not report the MEAS_ANT_DMRS_SNR"},
    { 1, "O-RU shall report the MEAS_ANT_DMRS_SNR"},
    { 0, NULL}
};

/* 7.7.24.14 */
static const value_string dtype_vals[] = {
    { 0, "assume DMRS configuration type 1"},
    { 1, "assume DMRS configuration type 2"},
    { 0, NULL}
};

/* 7.7.24.17 */
static const value_string papr_type_vals[] = {
    { 0, "sequence generator type 1 for short sequence lengths"},
    { 1, "sequence generator type 1 for long sequence lengths"},
    { 2, "sequence generator type 2 for short sequence lengths"},
    { 3, "sequence generator type 2 for long sequence lengths"},
    { 0, NULL}
};

/* 7.7.24.18 */
static const value_string hopping_mode_vals[] = {
    { 0, "neither group, nor sequence hopping is enabled"},
    { 1, "group hopping is enabled and sequence hopping is disabled"},
    { 2, "sequence hopping is enabled and group hopping is disabled"},
    { 3, "reserved"},
    { 0, NULL}
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

static const true_false_string disable_tdbfns_tfs = {
  "beam numbers excluded",
  "beam numbers included"
};

static const true_false_string continuity_indication_tfs = {
  "continuity between current and next bundle",
  "discontinuity between current and next bundle"
};

static const true_false_string prb_mode_tfs = {
  "PRB-BLOCK mode",
  "PRB-MASK mode"
};

static const true_false_string symbol_direction_tfs = {
  "DL symbol",
  "UL symbol"
};

static const true_false_string symbol_guard_tfs = {
  "guard symbol",
  "non-guard symbol"
};

static const true_false_string beam_numbers_included_tfs = {
  "time-domain beam numbers excluded in this command",
  "time-domain beam numbers included in this command"
};

static const true_false_string measurement_flag_tfs = {
  "at least one additional measurement report or command after the current one",
  "no additional measurement report or command"
};

static const true_false_string repetition_se6_tfs = {
  "repeated highest priority data section in the C-Plane message",
  "no repetition"
};

static const true_false_string repetition_se19_tfs = {
  "per port information not present in the extension",
  "per port info present in the extension"
};



/* Forward declaration */
static int dissect_udcompparam(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset,
                               unsigned comp_meth,
                               uint32_t *exponent, uint16_t *sReSMask, bool for_sinr);


static const true_false_string ready_tfs = {
  "message is a \"ready\" message",
  "message is a ACK message"
};

static const true_false_string multi_sd_scope_tfs = {
  "Puncturing pattern applies to current and following sections",
  "Puncturing pattern applies to current section"
};

static const true_false_string tfs_ueid_reset = {
  "cannot assume same UE as in preceding slot",
  "can assume same UE as in preceding slot"
};


/* Config for (and later, worked-out allocations) bundles for ext11 (dynamic BFW) */
typedef struct {
    /* Ext 6 config */
    bool     ext6_set;
    uint8_t  ext6_rbg_size;      /* number of PRBs allocated by bitmask */

    uint8_t  ext6_num_bits_set;
    uint8_t  ext6_bits_set[28];  /* Which bit position this entry has */
    /* TODO: store an f value for each bit position? */

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

    /* Results/settings (after calling ext11_work_out_bundles()) */
    uint32_t num_bundles;
#define MAX_BFW_BUNDLES 512
    struct {
        uint32_t start;      /* first prb of bundle */
        uint32_t end;        /* last prb of bundle*/
        bool     is_orphan;  /* true if not complete (i.e., end-start < numBundPrb) */
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

        /* Need to cope with these not dividing exactly, or even having more PRbs in a bundle that
           rbg size.  i.e. each bundle gets the correct number of PRBs until
           all rbg entries are consumed... */

        /* TODO: need to check 7.9.4.2.  Different cases depending upon value of RAD */

        if (bundles_per_entry == 0) {
            bundles_per_entry = 1;
        }

        /* Maybe also be affected by ext 21 */
        if (settings->ext21_set) {
            /* N.B., have already checked that numPrbc is not 0 */

            /* ciPrbGroupSize overrides number of contiguous PRBs in group */
            bundles_per_entry = (settings->ext6_rbg_size / settings->ext21_ci_prb_group_size);

            /* numPrbc is the number of PRB groups per antenna - handled in call to dissect_bfw_bundle() */
        }

        unsigned bundles_set = 0;
        for (unsigned n=0;
             n < (settings->ext6_num_bits_set * settings->ext6_rbg_size) / numBundPrb;
             n++) {

            /* Watch out for array bound */
            if (n >= 28) {
                break;
            }

            /* For each bundle... */

            /* TODO: Work out where first PRB is */
            /* May not be the start of an rbg block... */
            uint32_t prb_start = (settings->ext6_bits_set[n] * settings->ext6_rbg_size);

            /* For each bundle within identified rbgSize block */
            for (unsigned m=0; m < bundles_per_entry; m++) {
                settings->bundles[bundles_set].start = startPrbc+prb_start+(m*numBundPrb);
                /* Start already beyond end, so doesn't count. */
                if (settings->bundles[bundles_set].start > (startPrbc+numPrbc-1)) {
                    break;
                }
                /* Bundle consists of numBundPrb bundles */
                /* TODO: may involve PRBs from >1 rbg blocks.. */
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

    /* Case where bundles are not controlled by other extensions - just divide up range into bundles we have */
    else {
        settings->num_bundles = (numPrbc+numBundPrb-1) / numBundPrb;   /* rounded up */

        /* Don't overflow settings->bundles[] */
        settings->num_bundles = MIN(MAX_BFW_BUNDLES, settings->num_bundles);

        /* For each bundle.. */
        for (uint32_t n=0; n < settings->num_bundles; n++) {
            /* Allocate start and end */
            settings->bundles[n].start = startPrbc + n*numBundPrb;
            settings->bundles[n].end =   settings->bundles[n].start + numBundPrb - 1;
            /* If would go beyond end of PRBs, limit and identify as orphan */
            if (settings->bundles[n].end > startPrbc+numPrbc) {
                settings->bundles[n].end = startPrbc+numPrbc;
                settings->bundles[n].is_orphan = true;
            }
        }
    }
}


/* Modulation Compression configuration */
typedef struct  {
    /* Application of each entry is filtered by RE.
     * TODO: should also be filtered by PRB + symbol... */
    uint16_t section_id;
    uint16_t mod_compr_re_mask;

    /* Settings to apply */
    bool     mod_compr_csf;
    float    mod_compr_scaler;
} mod_compr_config_t;

/* Multiple configs with a section */
typedef struct {
    uint16_t section_id;
    uint32_t num_configs;

    #define MAX_MOD_COMPR_CONFIGS 12
    mod_compr_config_t configs[MAX_MOD_COMPR_CONFIGS];
} section_mod_compr_config_t;

/* Flow has separate configs for each section */
typedef struct {
    uint16_t num_sections;

    /* Separate config for each section */
    section_mod_compr_config_t sections[MAX_SECTION_IDs];
} mod_compr_params_t;



/*******************************************************/
/* Overall state of a flow (eAxC/plane)                */
typedef struct {
    /* State for sequence analysis [each direction] */
    bool     last_frame_seen[2];
    uint32_t last_frame[2];
    uint8_t  next_expected_sequence_number[2];

    /* Table recording ackNack requests (ackNackId -> ack_nack_request_t*)
       Note that this assumes that the same ackNackId will not be reused within a state,
       which may well not be valid */
    wmem_tree_t *ack_nack_requests;

    /* Store udCompHdr seen in C-Plane for UL - can be looked up and used by U-PLane.
       Note that this appears in the common section header parts of ST1, ST3, ST5,
       so can still be over-written per sectionId in the U-Plane */
    unsigned ul_ud_comp_hdr_frame;
    bool     ul_ud_comp_hdr_set;
    unsigned ul_ud_comp_hdr_bit_width;
    int      ul_ud_comp_hdr_compression;

    bool udcomphdrDownlink_heuristic_result_set;
    bool udcomphdrDownlink_heuristic_result;
    bool udcomphdrUplink_heuristic_result_set;
    bool udcomphdrUplink_heuristic_result;

    /* Modulation compression params */
    /* This probably needs to be per section!? */
    mod_compr_params_t mod_comp_params;
} flow_state_t;

static section_mod_compr_config_t* get_mod_compr_section_to_write(flow_state_t *flow,
                                                           unsigned sectionId)
{
    if (flow == NULL) {
        return NULL;
    }

    /* Look for this section among existing entries */
    for (unsigned s=0; s < flow->mod_comp_params.num_sections; s++) {
        if (flow->mod_comp_params.sections[s].section_id == sectionId) {
            return &flow->mod_comp_params.sections[s];
        }
    }

    /* Not found, so try to add a new one */
    if (flow->mod_comp_params.num_sections >= MAX_SECTION_IDs) {
        /* Can't allocate one! */
        return NULL;
    }
    else {
        flow->mod_comp_params.sections[flow->mod_comp_params.num_sections].section_id = sectionId;
        return &flow->mod_comp_params.sections[flow->mod_comp_params.num_sections++];
    }
}

static section_mod_compr_config_t* get_mod_compr_section_to_read(flow_state_t *flow,
                                                           unsigned sectionId)
{
    if (flow == NULL) {
        return NULL;
    }

    /* Look for this section among existing entries */
    for (unsigned s=0; s < flow->mod_comp_params.num_sections; s++) {
        if (flow->mod_comp_params.sections[s].section_id == sectionId) {
            return &flow->mod_comp_params.sections[s];
        }
    }

    /* Not found */
    return NULL;
}



typedef struct {
    uint32_t request_frame_number;
    nstime_t request_frame_time;
    enum {
        SE22,
        ST4Cmd1,
        ST4Cmd2,
        ST4Cmd3,
        ST4Cmd4
    } requestType;

    uint32_t response_frame_number;
    nstime_t response_frame_time;
} ack_nack_request_t;

static const value_string acknack_type_vals[] = {
    { SE22,    "SE 22" },
    { ST4Cmd1, "ST4 (TIME_DOMAIN_BEAM_CONFIG)" },
    { ST4Cmd2, "ST4 (TDD_CONFIG_PATTERN)" },
    { ST4Cmd3, "ST4 (TRX_CONTROL)" },
    { ST4Cmd4, "ST4 (ASM)" },
    { 0, NULL}
};

#define ORAN_C_PLANE 0
#define ORAN_U_PLANE 1

/* Using parts of src/dst MAC address, so don't confuse UL messages with DL messages configuring UL.. */
static uint32_t make_flow_key(packet_info *pinfo, uint16_t eaxc_id, uint8_t plane, bool opposite_dir)
{
    uint16_t eth_bits = 0;
    if (pinfo->dl_src.len == 6 && pinfo->dl_dst.len == 6) {
        /* Only using (most of) 2 bytes from addresses for now, but reluctant to make key longer.. */
        uint8_t *src_eth = (uint8_t*)pinfo->dl_src.data;
        uint8_t *dst_eth = (uint8_t*)pinfo->dl_dst.data;
        if (!opposite_dir) {
            eth_bits = (src_eth[0]<<8) | dst_eth[5];
        }
        else {
            eth_bits = (dst_eth[0]<<8) | src_eth[5];
        }
    }
    return eaxc_id | (plane << 16) | (eth_bits << 17);
}


/* Table maintained on first pass from flow_key(uint32_t) -> flow_state_t* */
static wmem_tree_t *flow_states_table;

/* Table consulted on subsequent passes: frame_num -> flow_result_t* */
static wmem_tree_t *flow_results_table;

typedef struct {
    /* Sequence analysis */
    bool     unexpected_seq_number;
    uint8_t  expected_sequence_number;
    uint32_t previous_frame;
} flow_result_t;


/* Uplink timing */
/* For a given symbol, track first to last UL frame to find out first-last time */
/* frameId (8) + subframeId (4) + slotId (6) + symbolId (6) = 24 bits */
/* N.B. if a capture lasts > 2.5s, may see same timing come around again... */
static uint32_t get_timing_key(uint8_t frameId, uint8_t subframeId, uint8_t slotId, uint8_t symbolId)
{
    return symbolId + (slotId<<8) + (subframeId<<14) + (frameId<<18);
}

typedef struct {
    uint32_t first_frame;
    nstime_t first_frame_time;
    uint32_t frames_seen_in_symbol;
    uint32_t last_frame_in_symbol;
} ul_timing_for_slot;

/* Set during first pass.  timing_key -> ul_timing_for_slot*  */
static wmem_tree_t *ul_symbol_timing;


static void show_link_to_acknack_response(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                                          ack_nack_request_t *response);




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

/* Add section labels (type + PRB range) for C-Plane, U-Plane */
static void
write_section_info(proto_item *section_heading, packet_info *pinfo, proto_item *protocol_item,
                   uint32_t section_id, uint32_t start_prbx, uint32_t num_prbx, uint32_t rb)
{
    switch (num_prbx) {
        case 0:
            /* None -> all */
            write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %4d     (all PRBs)", section_id);
            break;
        case 1:
            /* Single PRB */
            write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %4d (PRB: %7u)", section_id, start_prbx);
            break;
        default:
            /* Range */
            write_pdu_label_and_info(section_heading, protocol_item, pinfo, ", Id: %4d (PRB: %3u-%3u%s)", section_id, start_prbx,
                                     start_prbx + (num_prbx-1)*(1+rb), rb ? " (every-other)" : "");
    }
}

static void
write_channel_section_info(proto_item *section_heading, packet_info *pinfo,
                           uint32_t section_id, uint32_t ueId, uint32_t start_prbx, uint32_t num_prbx,
                           uint32_t num_trx)
{
    switch (num_prbx) {
        case 0:
            /* TODO: ?? */
            break;
        case 1:
            /* Single PRB */
            write_pdu_label_and_info(section_heading, NULL, pinfo,
                                     ", Id: %4d (UEId=%5u  PRB %7u, %2u antennas)",
                                     section_id, ueId, start_prbx, num_trx);
            break;
        default:
            /* Range */
            write_pdu_label_and_info(section_heading, NULL, pinfo,
                                     ", Id: %4d (UEId=%5u  PRBs %3u-%3u, %2u antennas)",
                                     section_id, ueId, start_prbx, start_prbx+num_prbx-1, num_trx);
    }
}


/* 5.1.3.2.7 (real time control data / IQ data transfer message series identifier) */
static void
addPcOrRtcid(tvbuff_t *tvb, proto_tree *tree, int *offset, int hf, uint16_t *eAxC)
{
    /* Subtree */
    proto_item *oran_pcid_ti = proto_tree_add_item(tree, hf,
                                                   tvb, *offset, 2, ENC_NA);
    proto_tree *oran_pcid_tree = proto_item_add_subtree(oran_pcid_ti, ett_oran_ecpri_pcid);

    uint64_t duPortId, bandSectorId, ccId, ruPortId = 0;
    int id_offset = *offset;

    /* All parts of eAxC should be above 0, and should total 16 bits (breakdown controlled by preferences) */
    if (!((pref_du_port_id_bits > 0) && (pref_bandsector_id_bits > 0) && (pref_cc_id_bits > 0) && (pref_ru_port_id_bits > 0) &&
         ((pref_du_port_id_bits + pref_bandsector_id_bits + pref_cc_id_bits + pref_ru_port_id_bits) == 16))) {
        expert_add_info(NULL, tree, &ei_oran_invalid_eaxc_bit_width);
        *eAxC = 0;
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

    proto_item_append_text(oran_pcid_ti, " (DU_Port_ID: %d, BandSector_ID: %d, CC_ID: %d, RU_Port_ID: %d)",
                           (int)duPortId, (int)bandSectorId, (int)ccId, (int)ruPortId);
    char id[16];
    snprintf(id, 16, "%x:%x:%x:%x", (int)duPortId, (int)bandSectorId, (int)ccId, (int)ruPortId);
    proto_item *pi = proto_tree_add_string(oran_pcid_tree, hf_oran_c_eAxC_ID, tvb, id_offset, 2, id);
    proto_item_set_generated(pi);
}

/* 5.1.3.2.8  ecpriSeqid (message identifier) */
static int
addSeqid(tvbuff_t *tvb, proto_tree *oran_tree, int offset, int plane, uint8_t *seq_id, proto_item **seq_id_ti, packet_info *pinfo)
{
    /* Subtree */
    proto_item *seqIdItem = proto_tree_add_item(oran_tree, hf_oran_ecpri_seqid, tvb, offset, 2, ENC_NA);
    proto_tree *oran_seqid_tree = proto_item_add_subtree(seqIdItem, ett_oran_ecpri_seqid);
    uint32_t seqId, subSeqId, e = 0;

    /* Sequence ID (8 bits) */
    *seq_id_ti = proto_tree_add_item_ret_uint(oran_seqid_tree, hf_oran_sequence_id, tvb, offset, 1, ENC_NA, &seqId);
    *seq_id = seqId;
    offset += 1;

    /* Show link back to previous sequence ID, if set */
    flow_result_t *result = wmem_tree_lookup32(flow_results_table, pinfo->num);
    if (result) {
        proto_item *prev_ti = proto_tree_add_uint(oran_seqid_tree, hf_oran_previous_frame, tvb, 0, 0, result->previous_frame);
        proto_item_set_generated(prev_ti);
    }

    /* E bit */
    proto_tree_add_item_ret_uint(oran_seqid_tree, hf_oran_e_bit, tvb, offset, 1, ENC_NA, &e);
    /* Subsequence ID (7 bits) */
    proto_tree_add_item_ret_uint(oran_seqid_tree, hf_oran_subsequence_id, tvb, offset, 1, ENC_NA, &subSeqId);
    offset += 1;

    /* radio-transport fragmentation not allowed for C-Plane messages */
    if (plane == ORAN_C_PLANE) {
        if (e !=1 || subSeqId != 0) {
            expert_add_info(NULL, seqIdItem, &ei_oran_radio_fragmentation_c_plane);
        }
    }
    else {
        if (e !=1 || subSeqId != 0) {
            /* TODO: Re-assembly of any radio-fragmentation on U-Plane */
            expert_add_info(NULL, seqIdItem, &ei_oran_radio_fragmentation_u_plane);
        }
    }

    /* Summary */
    proto_item_append_text(seqIdItem, " (SeqId: %3d, E: %d, SubSeqId: %d)", seqId, e, subSeqId);
    return offset;
}

static int dissect_symbolmask(tvbuff_t *tvb, proto_tree *tree, int offset, uint32_t *symbol_mask, proto_item **ti)
{
    uint64_t temp_val;

    static int * const  symbol_mask_flags[] = {
        &hf_oran_symbol_mask_s13,
        &hf_oran_symbol_mask_s12,
        &hf_oran_symbol_mask_s11,
        &hf_oran_symbol_mask_s10,
        &hf_oran_symbol_mask_s9,
        &hf_oran_symbol_mask_s8,
        &hf_oran_symbol_mask_s7,
        &hf_oran_symbol_mask_s6,
        &hf_oran_symbol_mask_s5,
        &hf_oran_symbol_mask_s4,
        &hf_oran_symbol_mask_s3,
        &hf_oran_symbol_mask_s2,
        &hf_oran_symbol_mask_s1,
        &hf_oran_symbol_mask_s0,
        NULL
    };

    proto_item *temp_ti = proto_tree_add_bitmask_ret_uint64(tree, tvb, offset,
                                                            hf_oran_symbol_mask,
                                                            ett_oran_symbol_mask, symbol_mask_flags,
                                                            ENC_BIG_ENDIAN, &temp_val);
    /* Set out parameters */
    if (symbol_mask) {
        *symbol_mask = (uint32_t)temp_val;
    }
    if (ti) {
        *ti = temp_ti;
    }
    return offset+2;
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
    /* Special case: 0 -> 16 */
    *iq_width = (*iq_width==0) ? 16 : *iq_width;
    *comp_meth_ti = proto_tree_add_item_ret_uint(bfwcomphdr_tree, hf_oran_bfwCompHdr_compMeth,
                                                 tvb, offset, 1, ENC_BIG_ENDIAN, comp_meth);
    offset++;

    /* Summary */
    proto_item_append_text(bfwcomphdr_ti, " (IqWidth=%u, compMeth=%s)",
                           *iq_width,
                           val_to_str_const(*comp_meth, bfw_comp_headers_comp_meth, "reserved"));

    return offset;
}

/* Return offset */
/* Returning number of entries set - would be good to also return an array of set TRX# so could show which array element
   each BFW is actually for.. */
static int dissect_active_beamspace_coefficient_mask(tvbuff_t *tvb, proto_tree *tree, int offset, unsigned *num_trx_entries, uint16_t **trx_entries)
{
    /* activeBeamspaceCoefficientMask - ceil(K/8) octets */
    /* K is the number of elements in uncompressed beamforming weight vector.
     * Calculated from parameters describing tx-array or tx-array */
    unsigned k_octets = (pref_data_plane_section_total_rbs + 7) / 8;

    static uint16_t trx_enabled[1024];

    /* TODO: could use a bigger bitmask array, but for now just uses this bytes-worth for each byte */
    static int * const mask_bits[] = {
        &hf_oran_active_beamspace_coefficient_n1,
        &hf_oran_active_beamspace_coefficient_n2,
        &hf_oran_active_beamspace_coefficient_n3,
        &hf_oran_active_beamspace_coefficient_n4,
        &hf_oran_active_beamspace_coefficient_n5,
        &hf_oran_active_beamspace_coefficient_n6,
        &hf_oran_active_beamspace_coefficient_n7,
        &hf_oran_active_beamspace_coefficient_n8,
        NULL
    };

    *num_trx_entries = 0;
    uint64_t val;
    for (unsigned n=0; n < k_octets; n++) {
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset,
                                          hf_oran_activeBeamspaceCoefficientMask,
                                          ett_active_beamspace_coefficient_mask, mask_bits,
                                          ENC_BIG_ENDIAN, &val);
        offset++;
        /* Add up the set bits for this byte (but be careful not to count beyond last real K bit..) */
        for (unsigned b=0; b < 8; b++) {
            if ((1 << b) & (unsigned)val) {
                if (((n*8)+b) < pref_data_plane_section_total_rbs) {
                    if (*num_trx_entries < 1024-1) {   /* Don't write beyond array (which should be plenty big) */
                        trx_enabled[(*num_trx_entries)++] = (n*8) + b + 1;
                    }
                }
            }
        }
    }
    /* Set pointer to static array */
    *trx_entries = trx_enabled;

    /* Show how many bits set */
    proto_item *ti = proto_tree_add_uint(tree, hf_oran_activeBeamspaceCoefficientMask_bits_set, tvb,
                                         offset-k_octets, k_octets, *num_trx_entries);
    proto_item_set_generated(ti);

    return offset;
}

/* 7.7.1.3 bfwCompParam (beamforming weight compression parameter).
 * Depends upon passed-in bfwCompMeth (field may be empty) */
static int dissect_bfwCompParam(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset,
                                proto_item *meth_ti, uint32_t *bfw_comp_method,
                                uint32_t *exponent, bool *supported, unsigned *num_trx_entries, uint16_t **trx_entries)
{
    if (*bfw_comp_method == COMP_NONE) {
        /* Absent! */
        *num_trx_entries = 0;
        *supported = true;
        return offset;
    }

    /* Subtree */
    proto_item *bfwcompparam_ti = proto_tree_add_string_format(tree, hf_oran_bfwCompParam,
                                                               tvb, offset, 1, "",
                                                              "bfwCompParam");
    proto_tree *bfwcompparam_tree = proto_item_add_subtree(bfwcompparam_ti, ett_oran_bfwcompparam);

    proto_item_append_text(bfwcompparam_ti,
                           " (meth=%s)", val_to_str_const(*bfw_comp_method, bfw_comp_headers_comp_meth, "reserved"));

    *num_trx_entries = 0;
    *supported = false;
    switch (*bfw_comp_method) {
        case COMP_BLOCK_FP:     /* block floating point */
            /* 4 reserved bits +  exponent */
            proto_tree_add_item_ret_uint(bfwcompparam_tree, hf_oran_exponent,
                                         tvb, offset, 1, ENC_BIG_ENDIAN, exponent);
            proto_item_append_text(bfwcompparam_ti, " exponent=%u", *exponent);
            *supported = true;
            offset++;
            break;
        case COMP_BLOCK_SCALE:  /* block scaling */
            /* Separate into integer and fractional bits? */
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
        case 4:                 /* beamspace I (BLOCK SCALING) */
            /* activeBeamspaceCoefficientMask */
            offset = dissect_active_beamspace_coefficient_mask(tvb, bfwcompparam_tree, offset, num_trx_entries, trx_entries);
            *bfw_comp_method = COMP_BLOCK_SCALE;
            *supported = false;                  /* TODO: true once BLOCK SCALE is supported */
            break;
        case 5:                 /* beamspace II (BLOCK FLOATING POINT) */
            /* activeBeamspaceCoefficientMask */
            offset = dissect_active_beamspace_coefficient_mask(tvb, bfwcompparam_tree, offset, num_trx_entries, trx_entries);
            /* reserved (4 bits) + exponent (4 bits) */
            proto_tree_add_item(bfwcompparam_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(bfwcompparam_tree, hf_oran_exponent, tvb, offset, 1, ENC_BIG_ENDIAN, exponent);
            offset += 1;
            *bfw_comp_method = COMP_BLOCK_FP;
            *supported = true;
            break;

        default:
            /* Not handled */
             break;
    }

    /* Can't go on if compression scheme not supported */
    if (!(*supported) && meth_ti) {
        expert_add_info_format(pinfo, meth_ti, &ei_oran_unsupported_bfw_compression_method,
                               "BFW Compression method %u (%s) not decompressed by dissector",
                               *bfw_comp_method,
                               val_to_str_const(*bfw_comp_method, bfw_comp_headers_comp_meth, "reserved"));
    }
    return offset;
}


/* Special case for uncompressed/16-bit value */
static float uncompressed_to_float(uint32_t h)
{
    int16_t i16 = h & 0x0000ffff;
    if (show_unscaled_values) {
        return (float)i16;
    }
    return ((float)i16) / 0x7fff;
}

/* Decompress I/Q value, taking into account method, width, exponent, other input-specific methods */
static float decompress_value(uint32_t bits, uint32_t comp_method, uint8_t iq_width,
                              uint32_t exponent,
                              /* Modulation compression settings. N.B. should also pass in PRB + symbol? */
                              section_mod_compr_config_t *m_c_p, uint8_t re)
{
    switch (comp_method) {
        case COMP_NONE: /* no compression */
            return uncompressed_to_float(bits);

        case COMP_BLOCK_FP:         /* block floating point */
        case BFP_AND_SELECTIVE_RE:
        {
            /* A.1.3 Block Floating Point Decompression Algorithm */
            int32_t cPRB = bits;
            uint32_t scaler = 1 << exponent;  /* i.e. 2^exponent */

            /* Check last bit, in case we need to flip to -ve */
            if (cPRB >= (1<<(iq_width-1))) {
                cPRB -= (1<<iq_width);
            }

            /* Unscale (8.1.3.1) */
            cPRB *= scaler;
            if (show_unscaled_values) {
                return (float)cPRB;
            }

            uint32_t mantissa_scale_factor = 1 << (iq_width-1); /* 2^(mantissabits-1) */
            uint32_t exp_scale_factor = 1 << 15;  /* 2^(2^exponentbits - 1 ) The exponent bit width is fixed to 4, so the maximum exponent is 15 */

            float ret = cPRB / ((float)(mantissa_scale_factor*exp_scale_factor));
            return ret;
        }

        case COMP_BLOCK_SCALE:
        case COMP_U_LAW:
            /* Not supported! But will be reported as expert info outside of this function! */
            return 0.0;

        case COMP_MODULATION:
        case MOD_COMPR_AND_SELECTIVE_RE:
        {
            /* Described in A.5 (with pseudo code) */
            /* N.B., Applies to downlink data only - is not used for BFW */

            /* Defaults if not overridden. TODO: what should these be? */
            bool csf = false;
            float mcScaler = (float)(1 << 11);

            /* Find csf + mcScaler to use. Non-default configs gleaned from SE 4,5,23 */
            /* TODO: should ideally be filtering by symbol and PRB too (at least from SE23) */
            if (re > 0 && m_c_p && m_c_p->num_configs > 0) {
                for (unsigned c=0; c<m_c_p->num_configs; c++) {
                    if (m_c_p->configs[c].mod_compr_re_mask & (1 << (12-re))) {
                        /* Return first (should be only) found */
                        csf = m_c_p->configs[c].mod_compr_csf;
                        mcScaler = m_c_p->configs[c].mod_compr_scaler;
                        break;
                    }
                }
            }

            int32_t cPRB = bits;

            /* 2) Map iqSample to iqSampleFx */
            /* Check last bit, in case we need to flip to -ve */
            if (cPRB >= (1<<(iq_width-1))) {
                cPRB -= (1<<iq_width);
            }
            float iqSampleFx = (float)cPRB / (1 << (iq_width-1));


            /* 3) or 4) (b) - add unshifted value if csf set */
            float csf_to_add = 0.0;
            if (csf) {
                /* Unshift the constellation point */
                csf_to_add = (float)2.0 / (1 << (iq_width));
            }
            iqSampleFx += csf_to_add;

            /* 3) or 4) (c) - unscaling */
            float iqSampleScaled = mcScaler * iqSampleFx * (float)sqrt(2);
            return iqSampleScaled;
        }

        default:
            /* Not supported! But will be reported as expert info outside of this function! */
            return 0.0;
    }
}

/* Out-of-range value used for special case */
#define ORPHAN_BUNDLE_NUMBER 999

/* Bundle of PRBs/TRX I/Q samples (ext 11) */
static uint32_t dissect_bfw_bundle(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, unsigned offset,
                                  proto_item *comp_meth_ti, uint32_t bfwcomphdr_comp_meth,
                                  section_mod_compr_config_t *mod_compr_params,
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
    unsigned exponent = 0;
    unsigned num_trx_entries = 0;
    uint16_t *trx_entries;
    offset = dissect_bfwCompParam(tvb, bundle_tree, pinfo, offset, comp_meth_ti,
                                  &bfwcomphdr_comp_meth, &exponent, &compression_method_supported,
                                  &num_trx_entries, &trx_entries);

    /* Can't show details of unsupported compression method */
    if (!compression_method_supported) {
        /* Don't know how to show, so give up */
        return offset;
    }

    /* Create Bundle subtree */
    int bit_offset = offset*8;
    int bfw_offset;
    int prb_offset = offset;

    /* contInd */
    proto_tree_add_item(bundle_tree, hf_oran_cont_ind,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    /* beamId */
    uint32_t beam_id;
    proto_tree_add_item_ret_uint(bundle_tree, hf_oran_beam_id, tvb, offset, 2, ENC_BIG_ENDIAN, &beam_id);
    proto_item_append_text(bundle_ti, " (beamId:%u) ", beam_id);
    bit_offset += 16;

    /* Number of weights per bundle (from preference) */
    proto_item *wpb_ti = proto_tree_add_uint(bundle_tree, hf_oran_num_weights_per_bundle, tvb, 0, 0,
                                             num_weights_per_bundle);
    proto_item_set_generated(wpb_ti);

    /* Add the weights for this bundle. Overwrite with what was seen in bfwCompParam if beamspace */
    if (num_trx_entries != 0) {
        num_weights_per_bundle = num_trx_entries;
    }

    for (unsigned w=0; w < num_weights_per_bundle; w++) {

        uint16_t trx_index = (num_trx_entries) ? trx_entries[w] : w+1;

        /* Create subtree */
        bfw_offset = bit_offset / 8;
        uint8_t bfw_extent = ((bit_offset + (iq_width*2)) / 8) - bfw_offset;
        proto_item *bfw_ti = proto_tree_add_string_format(bundle_tree, hf_oran_bfw,
                                                          tvb, bfw_offset, bfw_extent,
                                                          "", "TRX %3u: (", trx_index);
        proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

        /* I */
        /* Get bits, and convert to float. */
        uint32_t bits = tvb_get_bits32(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
        float value = decompress_value(bits, bfwcomphdr_comp_meth, iq_width,
                                       exponent, mod_compr_params, 0 /* RE */);
        /* Add to tree. */
        proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_i, tvb, bit_offset/8, (iq_width+7)/8, value, "#%u=%f", w, value);
        bit_offset += iq_width;
        proto_item_append_text(bfw_ti, "I%u=%f ", w, value);

        /* Q */
        /* Get bits, and convert to float. */
        bits = tvb_get_bits32(tvb, bit_offset, iq_width, ENC_BIG_ENDIAN);
        value = decompress_value(bits, bfwcomphdr_comp_meth, iq_width,
                                 exponent, mod_compr_params, 0 /* RE */);
        /* Add to tree. */
        proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_q, tvb, bit_offset/8, (iq_width+7)/8, value, "#%u=%f", w, value);
        bit_offset += iq_width;
        proto_item_append_text(bfw_ti, "Q%u=%f)", w, value);
    }

    /* Set extent of bundle */
    proto_item_set_len(bundle_ti, (bit_offset+7)/8 - prb_offset);

    return (bit_offset+7)/8;
}

/* Return new bit offset.  in/out will always be byte-aligned.. */
static int dissect_ciCompParam(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, unsigned bit_offset,
                               unsigned comp_meth, uint8_t *exponent)
{
    if (comp_meth == COMP_NONE) {
        /* Nothing in frame so don't even create subtree */
        return bit_offset;
    }

    /* Subtree */
    proto_item *cicompparam_ti = proto_tree_add_string_format(tree, hf_oran_ciCompParam,
                                                            tvb, bit_offset/8, 1, "",
                                                            "ciCompParam");
    proto_tree *cicompparam_tree = proto_item_add_subtree(cicompparam_ti, ett_oran_cicompparam);
    uint32_t ci_exponent;

    /* Contents differ by compression method */
    switch (comp_meth) {
        case COMP_BLOCK_FP:
            proto_tree_add_item(cicompparam_tree, hf_oran_reserved_4bits, tvb, bit_offset/8, 1, ENC_NA);
            proto_tree_add_item_ret_uint(cicompparam_tree, hf_oran_exponent,
                                         tvb, bit_offset/8, 1, ENC_BIG_ENDIAN, &ci_exponent);
            *exponent = ci_exponent;
            proto_item_append_text(cicompparam_ti, " (Exponent=%u)", ci_exponent);
            bit_offset += 8; /* one byte */
            break;
        case COMP_BLOCK_SCALE:
            /* Separate into integer (1) and fractional (7) bits? */
            proto_tree_add_item(cicompparam_tree, hf_oran_blockScaler,
                                tvb, bit_offset/8, 1, ENC_BIG_ENDIAN);
            bit_offset += 8;
            break;
        case COMP_U_LAW:
            /* compBitWidth, compShift (4 bits each) */
            proto_tree_add_item(cicompparam_tree, hf_oran_compBitWidth,
                                tvb, bit_offset/8, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cicompparam_tree, hf_oran_compShift,
                                tvb, bit_offset/8, 1, ENC_BIG_ENDIAN);
            bit_offset += 8;
            break;

        default:
            /* reserved, ? bytes of zeros.. */
            break;
    }

    return bit_offset;
}

/* frameStructure (7.5.2.13) */
static unsigned dissect_frame_structure(proto_item *tree, tvbuff_t *tvb, unsigned offset,
                                        uint32_t subframeId, uint32_t slotId)
{
    uint32_t scs;
    /* FFT Size (4 bits) */
    proto_tree_add_item(tree, hf_oran_frameStructure_fft, tvb, offset, 1, ENC_NA);
    /* Subcarrier spacing (SCS) */
    proto_tree_add_item_ret_uint(tree, hf_oran_frameStructure_subcarrier_spacing, tvb, offset, 1, ENC_NA, &scs);

    /* Show slot within frame as a generated field. See table 7.5.13-3 */
    uint32_t slots_per_subframe = 1;
    if (scs <= 4) {
        slots_per_subframe = 1 << scs;
    }
    if (scs <= 4 || scs >= 12) {
        proto_item *ti = proto_tree_add_uint(tree, hf_oran_slot_within_frame, tvb, 0, 0,
                                             (slots_per_subframe*subframeId) + slotId);
        proto_item_set_generated(ti);
    }
    return offset + 1;
}

static unsigned dissect_csf(proto_item *tree, tvbuff_t *tvb, unsigned bit_offset,
                            unsigned iq_width, bool *p_csf)
{
    proto_item *csf_ti;
    uint64_t csf;
    csf_ti = proto_tree_add_bits_ret_val(tree, hf_oran_csf, tvb, bit_offset, 1, &csf, ENC_BIG_ENDIAN);
    if (csf) {
        /* Table 7.7.4.2-1 Constellation shift definition (index is udIqWidth) */
        const char* shift_value[] = { "n/a", "1/2", "1/4", "1/8", "1/16", "1/32" };
        if (iq_width >=1 && iq_width <= 5) {
            proto_item_append_text(csf_ti, " (Shift Value is %s)", shift_value[iq_width]);
        }
    }

    /* Set out parameter */
    if (p_csf != NULL) {
        *p_csf = (csf!=0);
    }
    return bit_offset+1;
}


/* Section 7.
 * N.B. these are the green parts of the tables showing Section Types, differing by section Type */
static int dissect_oran_c_section(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                                  flow_state_t* state,
                                  uint32_t sectionType, oran_tap_info *tap_info, proto_item *protocol_item,
                                  uint32_t subframeId, uint32_t slotId,
                                  uint8_t ci_iq_width, uint8_t ci_comp_meth, unsigned ci_comp_opt,
                                  unsigned num_sinr_per_prb)
{
    unsigned offset = 0;
    proto_tree *c_section_tree = NULL;
    proto_item *sectionHeading = NULL;

    /* Section subtree */
    sectionHeading = proto_tree_add_string_format(tree, hf_oran_c_section,
                                                  tvb, offset, 0, "", "Section");
    c_section_tree = proto_item_add_subtree(sectionHeading, ett_oran_c_section);

    uint32_t sectionId = 0;

    uint32_t startPrbc=0, startPrbu=0;
    uint32_t numPrbc=0, numPrbu=0;
    uint32_t ueId = 0;
    proto_item *ueId_ti = NULL;
    uint32_t beamId = 0;
    proto_item *beamId_ti = NULL;
    bool beamId_ignored = false;

    proto_item *numsymbol_ti = NULL;
    bool numsymbol_ignored = false;

    proto_item *numprbc_ti = NULL;

    /* Config affecting ext11 bundles (initially unset) */
    ext11_settings_t ext11_settings;
    memset(&ext11_settings, 0, sizeof(ext11_settings));

    /* Section Type 10 needs to keep track of PRB range that should be reported
       for msgTypeId=5 (Interference plus Noise for unallocated PRBs) */
    /* All PRBs start as false */
#define MAX_PRBS 273
    bool prbs_for_st10_type5[MAX_PRBS];
    memset(&prbs_for_st10_type5, 0, sizeof(prbs_for_st10_type5));


#define MAX_UEIDS 16
    uint32_t ueids[MAX_UEIDS];
    uint32_t number_of_ueids = 0;

    bool extension_flag = false;

    /* These sections (ST0, ST1, ST2, ST3, ST5, ST9, ST10, ST11) are similar, so handle as common with per-type differences */
    if (((sectionType <= SEC_C_UE_SCHED) || (sectionType >= SEC_C_SINR_REPORTING)) &&
         (sectionType != SEC_C_SLOT_CONTROL)) {

        /* sectionID */
        proto_item *ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_section_id, tvb, offset, 2, ENC_BIG_ENDIAN, &sectionId);
        if (sectionId == 4095) {
            proto_item_append_text(ti, " (not default coupling C/U planes using sectionId)");
        }
        offset++;

        if (tap_info->num_section_ids < MAX_SECTION_IDs) {
            tap_info->section_ids[tap_info->num_section_ids++] = sectionId;
        }

        /* rb */
        uint32_t rb;
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_rb, tvb, offset, 1, ENC_NA, &rb);
        /* symInc (1 bit) */
        if (sectionType != SEC_C_RRM_MEAS_REPORTS &&     /* Section Type 10 */
            sectionType != SEC_C_REQUEST_RRM_MEAS) {     /* Section Type 11 */
            unsigned int sym_inc;
            proto_item *sym_inc_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA, &sym_inc);
            if (sym_inc !=0 && (sectionType == SEC_C_SINR_REPORTING)) {  /* Section Type 9 */
                /* "0 shall be used" */
                proto_item_append_text(sym_inc_ti, " (should be 0)");
            }
        }
        else {
            /* reserved (1 bit) */
            proto_tree_add_item(c_section_tree, hf_oran_reserved_bit5, tvb, offset, 1, ENC_BIG_ENDIAN);
        }

        /* startPrbx and numPrbx */
        if (sectionType == SEC_C_SINR_REPORTING) {
            /* startPrbu (10 bits) */
            proto_tree_add_item_ret_uint(c_section_tree, hf_oran_startPrbu, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbu);
            offset += 2;
            /* numPrbu */
            numprbc_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_numPrbu, tvb, offset, 1, ENC_NA, &numPrbu);
            if (numPrbu == 0) {
                proto_item_append_text(numprbc_ti, " (all PRBs - configured as %u)", pref_data_plane_section_total_rbs);
                numPrbu = pref_data_plane_section_total_rbs;
            }
            offset += 1;
        }
        else {
            /* startPrbc (10 bits) */
            proto_tree_add_item_ret_uint(c_section_tree, hf_oran_startPrbc, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbc);
            offset += 2;
            /* numPrbc */
            numprbc_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_numPrbc, tvb, offset, 1, ENC_NA, &numPrbc);
            if (numPrbc == 0) {
                proto_item_append_text(numprbc_ti, " (all PRBs - configured as %u)", pref_data_plane_section_total_rbs);
                /* TODO: should probably set to pref_data_plane_section_total_rbs, and define MAX_PRBS to > 273 ? */
                numPrbc = MAX_PRBS;
            }
            offset += 1;
        }

        /* Start with range from section.  May get changed by SE6, SE12, SE20 */
        for (unsigned n=startPrbc; n < startPrbc+numPrbc; n++) {
            if (n < MAX_PRBS) {
                prbs_for_st10_type5[n] = true;
            }
        }

        if (sectionType != SEC_C_SINR_REPORTING) {  /* Section Type 9 */
            static int * const  remask_flags[] = {
                &hf_oran_reMask_re1,
                &hf_oran_reMask_re2,
                &hf_oran_reMask_re3,
                &hf_oran_reMask_re4,
                &hf_oran_reMask_re5,
                &hf_oran_reMask_re6,
                &hf_oran_reMask_re7,
                &hf_oran_reMask_re8,
                &hf_oran_reMask_re9,
                &hf_oran_reMask_re10,
                &hf_oran_reMask_re11,
                &hf_oran_reMask_re12,
                NULL
            };

            /* reMask */
            uint64_t remask;
            proto_tree_add_bitmask_ret_uint64(c_section_tree, tvb, offset,
                                              hf_oran_reMask, ett_oran_remask, remask_flags, ENC_BIG_ENDIAN, &remask);
            offset++;
            /* numSymbol */
            /* TODO: should warn if startSymbol + numSymbol would be > 14? */
            uint32_t numSymbol;
            numsymbol_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_numSymbol, tvb, offset, 1, ENC_NA, &numSymbol);
            if ((sectionType == SEC_C_RRM_MEAS_REPORTS) && (numSymbol != 14)) {     /* Section type 10 */
                proto_item_append_text(numsymbol_ti, " (for ST10, should be 14!)");
                expert_add_info_format(pinfo, numsymbol_ti, &ei_oran_st10_numsymbol_not_14,
                                       "numSymbol should be 14 for ST10 - found %u", numSymbol);
            }
            offset++;

            /* [ef] (extension flag) */
            switch (sectionType) {
                case SEC_C_UNUSED_RB:         /* Section Type 0 */
                case SEC_C_NORMAL:            /* Section Type 1 */
                case SEC_C_PRACH:             /* Section Type 3 */
                case SEC_C_UE_SCHED:          /* Section Type 5 */
                case SEC_C_RRM_MEAS_REPORTS:  /* Section Type 10 */
                case SEC_C_REQUEST_RRM_MEAS:  /* Section Type 11 */
                    proto_tree_add_item_ret_boolean(c_section_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);
                    break;
                default:
                    /* Other section types don't support extensions */
                    break;
            }

            write_section_info(sectionHeading, pinfo, protocol_item, sectionId, startPrbc, numPrbc, rb);
            proto_item_append_text(sectionHeading, ", Symbols: %2u", numSymbol);

            if (numPrbc == 0) {
                /* Special case for all PRBs */
                numPrbc = pref_data_plane_section_total_rbs;
                startPrbc = 0;  /* may already be 0... */
            }
        }
        else {
            /* Section Type 9 */
            write_section_info(sectionHeading, pinfo, protocol_item, sectionId, startPrbu, numPrbu, rb);
            proto_item_append_text(sectionHeading, ", numSinrPerPrb: %2u", num_sinr_per_prb);
        }

        /* Section type specific fields (after 'numSymbol') */
        switch (sectionType) {
            case SEC_C_UNUSED_RB:    /* Section Type 0 - Table 7.4.2-1 */
                /* reserved (15 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_reserved_15bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case SEC_C_NORMAL:       /* Section Type 1 - Table 7.4.3-1 */
                /* beamId */
                beamId_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN, &beamId);
                offset += 2;

                proto_item_append_text(sectionHeading, ", BeamId: %d", beamId);
                break;

            case SEC_C_PRACH:       /* Section Type 3 - Table 7.4.5-1 */
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
                proto_tree_add_item(c_section_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_item_append_text(sectionHeading, ", BeamId: %d, FreqOffset: %d \u0394f", beamId, freqOffset);
                break;
            }

            case SEC_C_UE_SCHED:          /* Section Type 5  - Table 7.4.7-1 */
            case SEC_C_RRM_MEAS_REPORTS:  /* Section Type 10 - Table 7.4.12-1 */
                /* ueId */
                ueId_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_ueId, tvb, offset, 2, ENC_BIG_ENDIAN, &ueId);
                offset += 2;
                if (ueId == 0x7fff) {
                    proto_item_append_text(ueId_ti, " (PRBs not scheduled for eAxC ID in transport header)");
                }
                else {
                    ueids[number_of_ueids++] = ueId;
                }

                proto_item_append_text(sectionHeading, ", UEId: %d", ueId);
                break;

            case SEC_C_SINR_REPORTING:   /* Section Type 9 - SINR Reporting */
            {
                /* Hidden filter for bf (DMFS-BF) */
                proto_item *bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_HIDDEN(bf_ti);

                unsigned bit_offset = offset*8;

                /* sinr iqWidth */
                proto_item *iq_width_item = proto_tree_add_uint(c_section_tree, hf_oran_sinrCompHdrIqWidth_pref, tvb, 0, 0, pref_sample_bit_width_sinr);
                proto_item_append_text(iq_width_item, " (from preferences)");
                proto_item_set_generated(iq_width_item);

                /* sinr compMethod */
                proto_item *sinr_comp_meth_item = proto_tree_add_uint(c_section_tree, hf_oran_sinrCompHdrMeth_pref, tvb, 0, 0, pref_iqCompressionSINR);
                proto_item_append_text(sinr_comp_meth_item, " (from preferences)");
                proto_item_set_generated(sinr_comp_meth_item);

                /* Add SINR entries for each PRB */
                for (unsigned prb=0; prb < numPrbu; prb++) {
                    /* TODO: create a subtree for each PRB entry with good summary? */

                    /* Each prb starts byte-aligned */
                    bit_offset = ((bit_offset+7)/8) * 8;

                    /* N.B., using width/method from UL U-plane preferences, not certain that this is correct.. */

                    /* sinrCompParam (udCompParam format, may be empty) */
                    uint32_t exponent = 0;  /* N.B. init to silence warnings, but will always be set if read in COMP_BLOCK_FP case */
                    uint16_t sReSMask;
                    bit_offset = dissect_udcompparam(tvb, pinfo, c_section_tree, bit_offset/8,
                                                     pref_iqCompressionSINR, &exponent, &sReSMask,
                                                     true) * 8; /* last param is for_sinr */

                    /* sinrValues for this PRB. */
                    /* TODO: not sure how numSinrPerPrb interacts with rb==1... */
                    for (unsigned n=0; n < num_sinr_per_prb; n++) {
                        unsigned sinr_bits = tvb_get_bits32(tvb, bit_offset, pref_sample_bit_width_sinr, ENC_BIG_ENDIAN);

                        /* Using SINR compression settings from preferences */
                        float value = decompress_value(sinr_bits,
                                                       pref_iqCompressionSINR, pref_sample_bit_width_sinr,
                                                       exponent,
                                                       NULL /* no ModCompr for SINR */, 0 /* RE */);
                        unsigned sample_len_in_bytes = ((bit_offset%8)+pref_sample_bit_width_sinr+7)/8;
                        proto_item *val_ti = proto_tree_add_float(c_section_tree, hf_oran_sinr_value, tvb,
                                                                   bit_offset/8, sample_len_in_bytes, value);

                        /* Show here which subcarriers share which values (they all divide 12..) */
                        if (num_sinr_per_prb == 12) {
                            proto_item_append_text(val_ti, " (PRB=%u, subcarrier %u)",
                                               startPrbu+(prb*(rb+1)),
                                               n*(12/num_sinr_per_prb));
                        }
                        else {
                            proto_item_append_text(val_ti, " (PRB=%u, subcarriers %u-%u)",
                                               startPrbu+(prb*(rb+1)),
                                               n*(12/num_sinr_per_prb), (n+1)*(12/num_sinr_per_prb)-1);
                        }
                        bit_offset += pref_sample_bit_width_sinr;
                    }

                    /* 1-byte alignment per PRB (7.2.11) */
                    offset = (bit_offset+7)/8;
                    bit_offset = offset*8;
                }
                break;
            }
            case SEC_C_REQUEST_RRM_MEAS:   /* Section Type 11 - Request RRM Measurements */
                /* Reserved (15 bits) */
                proto_tree_add_item(c_section_tree, hf_oran_reserved_15bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            default:
                break;
        }
    }
    else if (sectionType == SEC_C_CH_INFO) {   /* Section Type 6 */
        /* ef */
        proto_tree_add_item_ret_boolean(c_section_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);
        /* ueId */
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_ueId, tvb, offset, 2, ENC_BIG_ENDIAN, &ueId);
        offset += 2;
        /* regularizationFactor */
        proto_tree_add_item(c_section_tree, hf_oran_regularizationFactor, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        /* reserved (4 bits) */
        proto_tree_add_item(c_section_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
        /* rb ("Value=0 shall be set") */
        uint32_t rb;
        proto_item *rb_ti = proto_tree_add_item_ret_uint(c_section_tree, hf_oran_rb, tvb, offset, 1, ENC_NA, &rb);
        if (rb != 0) {
            proto_item_append_text(rb_ti, " (should be set to 0)");
            expert_add_info(pinfo, rb_ti, &ei_oran_st6_rb_shall_be_0);
        }
        /* symInc */
        proto_tree_add_item(c_section_tree, hf_oran_symInc, tvb, offset, 1, ENC_NA);
        /* startPrbc */
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_startPrbc, tvb, offset, 2, ENC_BIG_ENDIAN, &startPrbc);
        offset += 2;
        /* numPrbc */
        proto_tree_add_item_ret_uint(c_section_tree, hf_oran_numPrbc, tvb, offset, 1, ENC_NA, &numPrbc);
        offset += 1;

        /* Hidden filter for bf */
        proto_item *bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(bf_ti);

        /* ciIsample,ciQsample pairs */
        unsigned m;
        unsigned prb;
        uint32_t bit_offset = offset*8;

        /* Antenna count from preference */
        unsigned num_trx = pref_num_bf_antennas;

        write_channel_section_info(sectionHeading, pinfo,
                                   sectionId, ueId, startPrbc, numPrbc, num_trx);

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
                                                                     "", "TRX=%2u:  ", m);
                proto_tree *sample_tree = proto_item_add_subtree(sample_ti, ett_oran_cisample);

                /* I */
                /* Get bits, and convert to float. */
                uint32_t bits = tvb_get_bits32(tvb, bit_offset, ci_iq_width, ENC_BIG_ENDIAN);
                float value = decompress_value(bits, ci_comp_meth, ci_iq_width, exponent, NULL /* no ModCompr for ST6 */, 0 /* RE */);

                /* Add to tree. */
                proto_tree_add_float_format_value(sample_tree, hf_oran_ciIsample, tvb, bit_offset/8, (ci_iq_width+7)/8, value, "#%u=%f", m, value);
                bit_offset += ci_iq_width;
                proto_item_append_text(sample_ti, "I%u=%f ", m, value);

                /* Q */
                /* Get bits, and convert to float. */
                bits = tvb_get_bits32(tvb, bit_offset, ci_iq_width, ENC_BIG_ENDIAN);
                value = decompress_value(bits, ci_comp_meth, ci_iq_width, exponent, NULL /* no ModCompr for ST6 */, 0 /* RE */);

                /* Add to tree. */
                proto_tree_add_float_format_value(sample_tree, hf_oran_ciQsample, tvb, bit_offset/8, (ci_iq_width+7)/8, value, "#%u=%f", m, value);
                bit_offset += ci_iq_width;
                proto_item_append_text(sample_ti, "Q%u=%f ", m, value);
            }
            proto_item_set_len(prb_ti, (bit_offset-prb_start_offset+7)/8);
        }

        /* Pad out by 1 or 4 bytes, according to preference */
        if (!st6_4byte_alignment) {
            offset = (bit_offset + 7) / 8;
        }
        else {
            int mode = bit_offset % 32;
            if (mode != 0) {
                offset = (bit_offset + (32-mode))/8;
            }
            else {
                offset = bit_offset/8;
            }
        }
        proto_item_set_end(c_section_tree, tvb, offset);
    }

    bool seen_se10 = false;
    uint32_t numPortc = 0;
    proto_item *bf_ti = NULL;

    /* Section extension commands */
    while (extension_flag) {
        int extension_start_offset = offset;

        /* Prefetch extType so can use specific extension type ett */
        uint32_t exttype = tvb_get_uint8(tvb, offset) & 0x7f;
        uint32_t exttype_ett_index = exttype;
        if (exttype == 0 || exttype > HIGHEST_EXTTYPE) {
            /* Just use first one if out of range */
            exttype_ett_index = 1;
        }

        /* Create subtree for each extension (with summary) */
        proto_item *extension_ti = proto_tree_add_string_format(c_section_tree, hf_oran_extension,
                                                                tvb, offset, 0, "", "Extension");
        proto_tree *extension_tree = proto_item_add_subtree(extension_ti, ett_oran_c_section_extension[exttype_ett_index-1]);

        /* ef (i.e. another extension after this one?) */
        proto_tree_add_item_ret_boolean(extension_tree, hf_oran_ef, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);

        /* extType */
        proto_item *exttype_ti;
        exttype_ti = proto_tree_add_item(extension_tree, hf_oran_exttype, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_item_append_text(sectionHeading, " (ext-%u)", exttype);

        proto_item_append_text(extension_ti, " (ext-%u: %s)", exttype, val_to_str_const(exttype, exttype_vals, "Reserved"));

        /* Don't tap if out of range. */
        if (exttype > 0 && exttype <= HIGHEST_EXTTYPE) {
            tap_info->extensions[exttype] = true;
        }

        /* Is this SE allowed for this section type? */
        if (!se_allowed_in_st(exttype, sectionType)) {
            expert_add_info_format(pinfo, extension_tree, &ei_oran_se_on_unsupported_st,
                                   "SE %u (%s) should not appear in ST %u (%s)!",
                                   exttype, val_to_str_const(exttype, exttype_vals, "Reserved"),
                                   sectionType, rval_to_str_const(sectionType, section_types, "Unknown"));
        }


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

        bool ext_unhandled = false;

        switch (exttype) {

            case 1:  /* SE 1: Beamforming Weights */
            {
                uint32_t bfwcomphdr_iq_width, bfwcomphdr_comp_meth;
                proto_item *comp_meth_ti = NULL;

                /* Hidden filter for bf */
                bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_HIDDEN(bf_ti);

                /* bfwCompHdr (2 subheaders - bfwIqWidth and bfwCompMeth)*/
                offset = dissect_bfwCompHdr(tvb, extension_tree, offset,
                                            &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);

                /* bfwCompParam */
                uint32_t exponent = 0;
                bool compression_method_supported = false;
                unsigned num_trx = 0;
                uint16_t *trx;        /* ptr to array */
                offset = dissect_bfwCompParam(tvb, extension_tree, pinfo, offset, comp_meth_ti,
                                              &bfwcomphdr_comp_meth, &exponent, &compression_method_supported,
                                              &num_trx, &trx);

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

                bool using_array = false;

                /* I & Q samples
                   May know how many entries from activeBeamspaceCoefficientMask. */
                if (num_trx == 0) {
                    /* Don't know how many there will be, so just fill available bytes... */
                    unsigned weights_bytes = (extlen*4)-3;
                    unsigned num_weights_pairs = (weights_bytes*8) / (bfwcomphdr_iq_width*2);
                    num_trx = num_weights_pairs;
                }
                else {
                    using_array = true;
                    num_trx = pref_num_bf_antennas;
                }

                int bit_offset = offset*8;

                for (unsigned n=0; n < num_trx; n++) {
                    /* Create antenna subtree */
                    int bfw_offset = bit_offset / 8;

                    uint16_t trx_index = (using_array) ? trx[n] : n+1;

                    proto_item *bfw_ti = proto_tree_add_string_format(extension_tree, hf_oran_bfw,
                                                                      tvb, bfw_offset, 0, "", "TRX %3u: (", trx_index);
                    proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

                    /* I value */
                    /* Get bits, and convert to float. */
                    uint32_t bits = tvb_get_bits32(tvb, bit_offset, bfwcomphdr_iq_width, ENC_BIG_ENDIAN);
                    float value = decompress_value(bits, bfwcomphdr_comp_meth, bfwcomphdr_iq_width, exponent,
                                                   NULL /* no ModCompr */, 0 /* RE */);
                    /* Add to tree. */
                    proto_tree_add_float(bfw_tree, hf_oran_bfw_i, tvb, bit_offset/8,
                                         (bfwcomphdr_iq_width+7)/8, value);
                    bit_offset += bfwcomphdr_iq_width;
                    proto_item_append_text(bfw_ti, "I=%f ", value);

                    /* Leave a gap between I and Q values */
                    proto_item_append_text(bfw_ti, "  ");

                    /* Q value */
                    /* Get bits, and convert to float. */
                    bits = tvb_get_bits32(tvb, bit_offset, bfwcomphdr_iq_width, ENC_BIG_ENDIAN);
                    value = decompress_value(bits, bfwcomphdr_comp_meth, bfwcomphdr_iq_width, exponent,
                                             NULL /* no ModCompr */, 0 /* RE */);
                    /* Add to tree. */
                    proto_tree_add_float(bfw_tree, hf_oran_bfw_q, tvb, bit_offset/8,
                                         (bfwcomphdr_iq_width+7)/8, value);
                    bit_offset += bfwcomphdr_iq_width;
                    proto_item_append_text(bfw_ti, "Q=%f", value);

                    proto_item_append_text(bfw_ti, ")");
                    proto_item_set_len(bfw_ti, (bit_offset+7)/8  - bfw_offset);
                }
                /* Need to round to next byte */
                offset = (bit_offset+7)/8;

                break;
            }

            case 2: /* SE 2: Beamforming attributes */
            {
                /* Hidden filter for bf */
                bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_HIDDEN(bf_ti);

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

                /* Pad to next byte (unless last 2 fields already fit in this one) */
                if ((bit_offset % 8) > 2) {
                    offset = (bit_offset+7) / 8;
                }
                else {
                    offset = bit_offset / 8;
                }

                /* bfAzSl (3 bits) */
                proto_tree_add_item(extension_tree, hf_oran_bfAzSl, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* bfZeSl (3 bits) */
                proto_tree_add_item(extension_tree, hf_oran_bfZeSl, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            }

            case 3: /* SE 3: DL precoding parameters */
            {
                /* codebookindex (8 bits) */
                /* "This parameter is not used and shall be set to zero." */
                proto_tree_add_item(extension_tree, hf_oran_codebook_index, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* layerid */
                uint32_t layerid;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_layerid, tvb, offset, 1, ENC_BIG_ENDIAN, &layerid);
                /* numLayers */
                proto_tree_add_item(extension_tree, hf_oran_numlayers, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Stop here for non-first data layer */
                if (layerid != 0 && layerid != 0xf) {
                    break;
                }

                /* First data layer case */
                /* txScheme */
                proto_tree_add_item(extension_tree, hf_oran_txscheme, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* crsReMask */
                proto_tree_add_item(extension_tree, hf_oran_crs_remask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* crsShift (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_crs_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (3 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_bits123, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* crsSymNum (4 bits) */
                proto_tree_add_item(extension_tree, hf_oran_crs_symnum, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* reserved */
                proto_tree_add_item(extension_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* reserved (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* beamIdAP1 (15 bits) */
                proto_tree_add_item(extension_tree, hf_oran_beamid_ap1, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* reserved (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* beamIdAP2 (15 bits) */
                proto_tree_add_item(extension_tree, hf_oran_beamid_ap2, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* reserved (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* beamIdAP3 (15 bits) */
                proto_tree_add_item(extension_tree, hf_oran_beamid_ap3, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            }

            case 4: /* SE 4: Modulation compression params (5.4.7.4) (single sets) */
            {
                /* csf */
                bool csf;
                dissect_csf(extension_tree, tvb, offset*8, ci_iq_width, &csf);

                /* modCompScaler */
                uint32_t modCompScaler;
                proto_item *ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_modcompscaler,
                                                              tvb, offset, 2, ENC_BIG_ENDIAN, &modCompScaler);
                offset += 2;

                /* Work out and show floating point value too. exponent and mantissa are both unsigned */
                uint16_t exponent = (modCompScaler >> 11) & 0x000f; /* m.s. 4 bits */
                uint16_t mantissa = modCompScaler & 0x07ff;         /* l.s. 11 bits */
                float value = ((float)mantissa/(1<<11)) * ((float)1.0 / (1 << exponent));
                proto_item_append_text(ti, " (%f)", value);

                section_mod_compr_config_t* sect_config = get_mod_compr_section_to_write(state, sectionId);

                /* Store these params in this flow's state */
                if (sect_config && sect_config->num_configs < MAX_MOD_COMPR_CONFIGS) {
                    unsigned i = sect_config->num_configs;
                    sect_config->configs[i].mod_compr_re_mask = 0xfff;   /* Covers all REs */
                    sect_config->configs[i].mod_compr_csf = csf;
                    sect_config->configs[i].mod_compr_scaler = value;
                    sect_config->num_configs++;
                }
                break;
            }

            case 5: /* SE 5: Modulation Compression Additional Parameters (7.7.5) (multiple sets) */
            {
                /* Applies only to section types 1,3 and 5 */
                /* N.B. there may be multiple instances of this SE in the same frame */

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
                /* Dissect each set */
                for (int n=0; n < sets; n++) {
                    /* Subtree for each set */
                    unsigned set_start_offset = bit_offset/8;
                    proto_item *set_ti = proto_tree_add_string(extension_tree, hf_oran_modcomp_param_set,
                                                                tvb, set_start_offset, 0, "");
                    proto_tree *set_tree = proto_item_add_subtree(set_ti, ett_oran_modcomp_param_set);

                    uint64_t mcScaleReMask, mcScaleOffset;
                    bool csf;

                    /* mcScaleReMask (12 bits). Defines which REs the following csf and mcScaleOffset apply to */
                    static int * const  remask_flags[] = {
                        &hf_oran_mc_scale_re_mask_re1,
                        &hf_oran_mc_scale_re_mask_re2,
                        &hf_oran_mc_scale_re_mask_re3,
                        &hf_oran_mc_scale_re_mask_re4,
                        &hf_oran_mc_scale_re_mask_re5,
                        &hf_oran_mc_scale_re_mask_re6,
                        &hf_oran_mc_scale_re_mask_re7,
                        &hf_oran_mc_scale_re_mask_re8,
                        &hf_oran_mc_scale_re_mask_re9,
                        &hf_oran_mc_scale_re_mask_re10,
                        &hf_oran_mc_scale_re_mask_re11,
                        &hf_oran_mc_scale_re_mask_re12,
                        NULL
                    };
                    /* Same as above, but offset by 4 bits */
                    static int * const  remask_flags_even[] = {
                        &hf_oran_mc_scale_re_mask_re1_even,
                        &hf_oran_mc_scale_re_mask_re2_even,
                        &hf_oran_mc_scale_re_mask_re3_even,
                        &hf_oran_mc_scale_re_mask_re4_even,
                        &hf_oran_mc_scale_re_mask_re5_even,
                        &hf_oran_mc_scale_re_mask_re6_even,
                        &hf_oran_mc_scale_re_mask_re7_even,
                        &hf_oran_mc_scale_re_mask_re8_even,
                        &hf_oran_mc_scale_re_mask_re9_even,
                        &hf_oran_mc_scale_re_mask_re10_even,
                        &hf_oran_mc_scale_re_mask_re11_even,
                        &hf_oran_mc_scale_re_mask_re12_even,
                        NULL
                    };

                    /* RE Mask (12 bits) */
                    proto_tree_add_bitmask_ret_uint64(set_tree, tvb, bit_offset / 8,
                                                      (n % 2) ? hf_oran_mc_scale_re_mask_even : hf_oran_mc_scale_re_mask,
                                                      ett_oran_mc_scale_remask,
                                                      (n % 2) ? remask_flags_even : remask_flags, ENC_BIG_ENDIAN, &mcScaleReMask);
                    bit_offset += 12;

                    /* csf (1 bit) */
                    bit_offset = dissect_csf(set_tree, tvb, bit_offset, ci_iq_width, &csf);
                    /* mcScaleOffset (15 bits) */
                    proto_item *ti = proto_tree_add_bits_ret_val(set_tree, hf_oran_mc_scale_offset, tvb, bit_offset, 15, &mcScaleOffset, ENC_BIG_ENDIAN);
                    uint16_t exponent = (mcScaleOffset >> 11) & 0x000f; /* m.s. 4 bits */
                    uint16_t mantissa = mcScaleOffset & 0x07ff;         /* l.s. 11 bits */
                    float mcScaleOffset_value = ((float)mantissa/(1<<11)) * ((float)1.0 / (1 << exponent));
                    proto_item_append_text(ti, " (%f)", mcScaleOffset_value);
                    bit_offset += 15;

                    section_mod_compr_config_t* sect_config = get_mod_compr_section_to_write(state, sectionId);

                    /* Record this config */
                    if (sect_config && sect_config->num_configs < MAX_MOD_COMPR_CONFIGS) {
                        unsigned i = sect_config->num_configs;
                        sect_config->configs[i].mod_compr_re_mask = (uint16_t)mcScaleReMask;
                        sect_config->configs[i].mod_compr_csf = csf;
                        sect_config->configs[i].mod_compr_scaler = mcScaleOffset_value;
                        sect_config->num_configs++;
                    }

                    /* Summary */
                    proto_item_set_len(set_ti, (bit_offset+7)/8 - set_start_offset);
                    proto_item_append_text(set_ti, " (mcScaleReMask=0x%03x  csf=%5s  mcScaleOffset=%f)",
                                           (unsigned)mcScaleReMask, tfs_get_true_false(csf), mcScaleOffset_value);
                }

                proto_item_append_text(extension_ti, " (%u sets)", sets);

                /* Reserved (variable-length) */
                if (reserved_bits) {
                    proto_tree_add_bits_item(extension_tree, hf_oran_reserved, tvb, bit_offset, reserved_bits, ENC_BIG_ENDIAN);
                    bit_offset += reserved_bits;
                }

                offset = bit_offset/8;
                break;
            }

            case 6: /* SE 6: Non-contiguous PRB allocation in time and frequency domain */
            {
                /* numSymbol not used in this case */
                if (numsymbol_ti && !numsymbol_ignored) {
                    proto_item_append_text(numsymbol_ti, " (ignored)");
                    numsymbol_ignored = true;
                }

                /* Will update ext6 recorded info */
                ext11_settings.ext6_set = true;

                /* repetition */
                proto_tree_add_bits_item(extension_tree, hf_oran_se6_repetition, tvb, offset*8, 1, ENC_BIG_ENDIAN);
                /* rbgSize (PRBs per bit set in rbgMask) */
                uint32_t rbgSize;
                proto_item *rbg_size_ti;
                rbg_size_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_rbgSize, tvb, offset, 1, ENC_BIG_ENDIAN, &rbgSize);
                if (rbgSize == 0) {
                    /* N.B. this is only true if "se6-rb-bit-supported" is set... */
                    expert_add_info_format(pinfo, rbg_size_ti, &ei_oran_rbg_size_reserved,
                                           "rbgSize value of 0 is reserved");
                }
                /* rbgMask (28 bits) */
                uint32_t rbgMask;
                proto_item *rbgmask_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_rbgMask, tvb, offset, 4, ENC_BIG_ENDIAN, &rbgMask);
                if (rbgSize == 0) {
                    proto_item_append_text(rbgmask_ti, " (value ignored since rbgSize is 0)");
                }

                /* TODO: if receiver detects non-zero bits outside the valid range, those shall be ignored. */
                offset += 4;
                /* priority */
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* symbolMask */
                offset = dissect_symbolmask(tvb, extension_tree, offset, NULL, NULL);

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

                /* Set to looked-up value */
                rbgSize = ext11_settings.ext6_rbg_size;

                uint32_t lastRbgid = 0;
                if (rbgSize != 0) {
                    /* The O-DU shall not use combinations of startPrbc, numPrbc and rbgSize leading to a value of lastRbgid larger than 27 */
                    /* i.e., leftmost bit used should not need to go off left end of rbgMask! */
                    lastRbgid = (uint32_t)ceil((numPrbc + (startPrbc % rbgSize)) / (float)rbgSize) - 1;
                    if (lastRbgid > 27) {
                        expert_add_info_format(pinfo, rbg_size_ti, &ei_oran_lastRbdid_out_of_range,
                                               "SE6: rbgSize (%u) not compatible with startPrbc(%u) and numPrbc(%u)",
                                               rbgSize, startPrbc, numPrbc);
                        break;
                    }
                }

                /* Record (and count) which bits are set in rbgMask */
                bool first_seen = false;
                unsigned first_seen_pos=0, last_seen_pos=0;
                for (unsigned n=0; n < 28 && ext11_settings.ext6_num_bits_set < 28; n++) {
                    if ((rbgMask >> n) & 0x01) {
                        ext11_settings.ext6_bits_set[ext11_settings.ext6_num_bits_set++] = n;
                        if (!first_seen) {
                            first_seen = true;
                            first_seen_pos = n;
                        }
                        last_seen_pos = n;
                    }
                }

                /* Show how many bits were set in rbgMask */
                proto_item_append_text(rbgmask_ti, " (%u bits set)", ext11_settings.ext6_num_bits_set);
                /* Also, that is the range of bits */
                if (first_seen) {
                    proto_item_append_text(rbgmask_ti, " (%u bits spread)", last_seen_pos-first_seen_pos+1);
                }

                /* Complain if last set bit is beyond lastRbgid */
                if (first_seen) {
                    if (last_seen_pos > lastRbgid) {
                        expert_add_info_format(pinfo, rbgmask_ti, &ei_oran_rbgMask_beyond_last_rbdid,
                                               "SE6: rbgMask (0x%07x) has bit %u set, but lastRbgId is %u",
                                               rbgMask, last_seen_pos, lastRbgid);
                    }
                }

                /* Also update prbs_for_st10_type5[] */
                if (sectionType == 10 && rbgSize != 0) {
                    /* Unset all entries */
                    memset(&prbs_for_st10_type5, 0, sizeof(prbs_for_st10_type5));

                    /* Work out which PRB first bit corresponds to */
                    unsigned firstPrbStart = (startPrbc/rbgSize) * rbgSize;

                    /* Add PRBs corresponding to each bit set */
                    for (unsigned n=0; n < 28 ; n++) {
                        if ((rbgMask >> n) & 0x01) {
                            /* Lazy way to clip any values that lie outside of range for section */
                            for (unsigned p=0; p < rbgSize; p++) {
                                unsigned start = firstPrbStart + (n*rbgSize);
                                if ((start+p < MAX_PRBS) && (start+p >= startPrbc) && (start+p <= startPrbc+numPrbc-1)) {
                                    prbs_for_st10_type5[start+p] = true;
                                }
                            }
                        }
                    }
                }

                break;
            }

            case 7: /* SE 7: eAxC mask */
                /* Allow ST0 to address multiple eAxC_ID values for transmission blanking */
                proto_tree_add_item(extension_tree, hf_oran_eAxC_mask, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case 8: /* SE 8: Regularization factor */
                proto_tree_add_item(extension_tree, hf_oran_regularizationFactor, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;

            case 9: /* SE 9: Dynamic Spectrum Sharing parameters */
                proto_tree_add_item(extension_tree, hf_oran_technology, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(extension_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case 10: /* SE 10: Group configuration of multiple ports */
            {
                seen_se10 = true;

                /* beamGroupType */
                uint32_t beam_group_type = 0;
                proto_item *bgt_ti;
                bgt_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_beamGroupType,
                                                      tvb, offset, 1, ENC_BIG_ENDIAN, &beam_group_type);
                proto_item_append_text(extension_ti, " (%s)", val_to_str_const(beam_group_type, beam_group_type_vals, "Unknown"));

                /* numPortc */
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_numPortc,
                                             tvb, offset, 1, ENC_BIG_ENDIAN, &numPortc);
                offset++;

                /* Will append all beamId values to extension_ti, regardless of beamGroupType */
                unsigned n;

                switch (beam_group_type) {
                    case 0x0: /* common beam */
                    case 0x1: /* beam matrix indication */
                        /* Reserved byte */
                        proto_tree_add_item(extension_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_NA);
                        offset++;

                        /* Explain how entries are allocated */
                        if (beam_group_type == 0x0) {
                            proto_item_append_text(extension_ti, " (all %u ueid/Beam entries are %u)", numPortc, ueId);
                        }
                        else {
                            /* 'numPortc' consecutive BeamIds from section header */
                            proto_item_append_text(extension_ti, " (ueId/beam entries are %u -> %u)", ueId, ueId+numPortc);
                        }

                        if (sectionType == 5) {
                            /* These types are not allowed */
                            expert_add_info_format(pinfo, bgt_ti, &ei_oran_se10_not_allowed,
                                                   "SE10: beamGroupType %u is not allowed for section type 5", beam_group_type);
                        }
                        break;

                    case 0x2: /* beam vector listing */
                    {
                        proto_item_append_text(extension_ti, " [ ");

                        /* Beam listing vector case */
                        /* Work out how many port beam entries there is room for */
                        /* Using numPortC as visible in issue 18116 */
                        for (n=0; n < numPortc; n++) {
                            /* 1 reserved bit */
                            proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);

                            /* port beam ID (or UEID) (15 bits) */
                            uint32_t id;
                            proto_item *beamid_or_ueid_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_beamId,
                                                                                         tvb, offset, 2, ENC_BIG_ENDIAN, &id);
                            proto_item_append_text(beamid_or_ueid_ti, " port #%u beam ID (or UEId) %u", n, id);
                            offset += 2;

                            if (id != 0x7fff) {
                                if (number_of_ueids < MAX_UEIDS) {
                                    ueids[number_of_ueids++] = id;
                                }
                            }

                            proto_item_append_text(extension_ti, "%u ", id);
                        }

                        proto_item_append_text(extension_ti, "]");
                        break;
                    }
                    case 0x3: /* beamId/ueId listing with associated port-list index */
                    {
                        proto_item_append_text(extension_ti, " [ ");

                        if (numPortc > 0) {
                            /* first portListIndex is outside loop */
                            uint32_t port_list_index;
                            proto_item *pli_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_port_list_index, tvb,
                                                         offset, 1, ENC_BIG_ENDIAN, &port_list_index);
                            if (port_list_index == 0) {
                                /* Value 0 is reserved */
                                expert_add_info(pinfo, pli_ti, &ei_oran_port_list_index_zero);
                            }
                            offset += 1;

                            for (n=0; n < numPortc-1; n++) {
                                /* 1 reserved bit */
                                proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);

                                /* port beam ID (or UEID) */
                                uint32_t id;
                                proto_item *beamid_or_ueid_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_beamId,
                                                                                             tvb, offset, 2, ENC_BIG_ENDIAN, &id);
                                proto_item_append_text(beamid_or_ueid_ti, " port #%u beam ID (or UEId) %u", n, id);
                                offset += 2;

                                if (id != 0x7fff) {
                                    if (number_of_ueids < MAX_UEIDS) {
                                        ueids[number_of_ueids++] = id;
                                    }
                                }

                                /* subsequent portListIndex */
                                pli_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_port_list_index, tvb,
                                                             offset, 1, ENC_BIG_ENDIAN, &port_list_index);
                                if (port_list_index == 0) {
                                    /* Value 0 is reserved */
                                    expert_add_info(pinfo, pli_ti, &ei_oran_port_list_index_zero);
                                }
                                offset += 1;

                                proto_item_append_text(extension_ti, "%u:%u ", port_list_index, id);
                            }
                        }

                        proto_item_append_text(extension_ti, "]");
                        break;
                    }


                    default:
                        /* Warning for unsupported/reserved value */
                        expert_add_info(NULL, bgt_ti, &ei_oran_se10_unknown_beamgrouptype);
                        break;
                }
                break;
            }

            case 11: /* SE 11: Flexible Weights Extension Type */
            {
                /* Hidden filter for bf */
                bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_HIDDEN(bf_ti);

                /* beamId in section header should be ignored. Guard against appending multiple times.. */
                if (beamId_ti && !beamId_ignored) {
                    proto_item_append_text(beamId_ti, " (ignored)");
                    beamId_ignored = true;
                }

                bool disableBFWs;
                uint32_t numBundPrb;
                bool rad;

                /* disableBFWs */
                proto_tree_add_item_ret_boolean(extension_tree, hf_oran_disable_bfws,
                                                tvb, offset, 1, ENC_BIG_ENDIAN, &disableBFWs);
                if (disableBFWs) {
                    proto_item_append_text(extension_ti, " (disableBFWs)");
                }

                /* RAD */
                proto_tree_add_item_ret_boolean(extension_tree, hf_oran_rad,
                                    tvb, offset, 1, ENC_BIG_ENDIAN, &rad);
                /* bundleOffset (6 bits) */
                proto_tree_add_item(extension_tree, hf_oran_bundle_offset, tvb,
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
                                                    NULL /* no ModCompr */,
                                                    (ext11_settings.ext21_set) ?
                                                        numPrbc :
                                                        pref_num_bf_antennas,
                                                    bfwcomphdr_iq_width,
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
                        /* contInd */
                        proto_tree_add_item(extension_tree, hf_oran_cont_ind,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        /* beamId */
                        proto_item *ti = proto_tree_add_item(extension_tree, hf_oran_beam_id,
                                                             tvb, offset, 2, ENC_BIG_ENDIAN);
                        if (!ext11_settings.bundles[n].is_orphan) {
                            proto_item_append_text(ti, "    (PRBs %3u-%3u)  (Bundle %2u)",
                                                   ext11_settings.bundles[n].start,
                                                   ext11_settings.bundles[n].end,
                                                   n);
                        }
                        else {
                            orphaned_prbs = true;
                            proto_item_append_text(ti, "    (PRBs %3u-%3u)  (Orphaned PRBs)",
                                                   ext11_settings.bundles[n].start,
                                                   ext11_settings.bundles[n].end);
                        }
                        offset += 2;
                    }
                }

                /* Add summary to extension root */
                if (orphaned_prbs) {
                    proto_item_append_text(extension_ti, " (%u full bundles + orphaned)", num_bundles-1);
                }
                else {
                    proto_item_append_text(extension_ti, " (%u bundles)", num_bundles);
                }
            }

                break;

            case 12: /* SE 12: Non-Contiguous PRB Allocation with Frequency Ranges */
            {
                /* numSymbol not used in this case */
                if (numsymbol_ti && !numsymbol_ignored) {
                    proto_item_append_text(numsymbol_ti, " (ignored)");
                    numsymbol_ignored = true;
                }

                ext11_settings.ext12_set = true;

                /* priority */
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);

                /* symbolMask */
                offset = dissect_symbolmask(tvb, extension_tree, offset, NULL, NULL);

                /* There are now 'R' pairs of (offStartPrb, numPrb) values. Fill extlen bytes with values.  If last one is not set,
                   should be populated with 0s. */
                uint32_t extlen_remaining_bytes = (extlen*4) - 4;
                uint8_t prb_index;

                /* This is for ST10/ST11.  First pair starts after frames signalled there */
                uint16_t st10_st11_offset = startPrbc + numPrbc;

                for (prb_index = 1; extlen_remaining_bytes > 0; prb_index++)
                {
                    /* Create a subtree for each pair */
                    proto_item *pair_ti = proto_tree_add_string(extension_tree, hf_oran_frequency_range,
                                                                tvb, offset, 2, "");
                    proto_tree *pair_tree = proto_item_add_subtree(pair_ti, ett_oran_frequency_range);

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
                        proto_item_append_text(pair_ti, "(%u) [%u : %u]",
                                              prb_index, off_start_prb, num_prb);
                        proto_item_append_text(extension_ti, "[%u : %u]",
                                              off_start_prb, num_prb);
                        if (ext11_settings.ext12_num_pairs < MAX_BFW_EXT12_PAIRS) {
                            ext11_settings.ext12_pairs[ext11_settings.ext12_num_pairs].off_start_prb = off_start_prb;
                            ext11_settings.ext12_pairs[ext11_settings.ext12_num_pairs++].num_prb = num_prb;
                        }

                        /* Also update PRBs to be covered for ST10 type 5 */
                        /* Original range from section is added to.. */
                        /* TODO: I don't think this is quite right.. */
                        for (unsigned prb=st10_st11_offset+off_start_prb; prb < st10_st11_offset+off_start_prb+num_prb; prb++) {
                            if (prb < MAX_PRBS) {
                                prbs_for_st10_type5[prb] = true;
                            }
                        }

                        /* Any next pair will begin after this one */
                        st10_st11_offset += (off_start_prb + num_prb);
                    }
                }
                break;
            }

            case 13:  /* SE 13: PRB Allocation with Frequency Hopping */
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

            case 14:  /* SE 14: Nulling-layer Info. for ueId-based beamforming */
                /* Hidden filter for bf (DMRS BF) */
                bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_HIDDEN(bf_ti);

                if (!seen_se10) {
                    proto_tree_add_item(extension_tree, hf_oran_nullLayerInd, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(extension_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }
                else {
                    /* Loop over numPortc++1 (from SE 10) nullLayerInd fields  */
                    for (unsigned port=0; port < numPortc+1; port++) {
                        proto_tree_add_item(extension_tree, hf_oran_nullLayerInd, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                }
                break;

            case 15:  /* SE 15: Mixed-numerology Info. for ueId-based beamforming */
            {
                /* frameStructure */
                offset = dissect_frame_structure(extension_tree, tvb, offset,
                                                 subframeId, slotId);
                /* freqOffset */
                proto_tree_add_item(extension_tree, hf_oran_freqOffset, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
                /* cpLength */
                proto_item *cplength_ti = proto_tree_add_item(extension_tree, hf_oran_cpLength, tvb, offset, 2, ENC_BIG_ENDIAN);
                if (sectionType != 0 && sectionType != 3) {
                    proto_item_append_text(cplength_ti, "  (ignored - used only with ST0 and ST3)");
                }
                offset += 2;
                break;
            }

            case 16:  /* SE 16: Antenna mapping in UE channel information based UL beamforming */
            {
                /* Just filling available bytes with antMask entries.
                   N.B., if SE 10 also used, could associate each antMask with (beamId or UEId) RX eAxC */
                uint32_t extlen_remaining_bytes = (extlen*4) - 2;
                unsigned num_ant_masks = extlen_remaining_bytes / 8;
                for (unsigned n=0; n < num_ant_masks; n++) {
                    proto_item *ti = proto_tree_add_item(extension_tree, hf_oran_antMask, tvb, offset, 8, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (RX eAxC #%u)", n+1);
                    offset += 8;
                }
                break;
            }

            case 17:  /* SE 17: Indication of user port group */
            {
                uint32_t extlen_remaining_bytes = (extlen*4) - 2;
                uint32_t end_bit = (offset+extlen_remaining_bytes) * 8;
                uint32_t ueid_index = 1;
                /* TODO: just filling up all available bytes - some may actually be padding.. */
                /* "the preceding Section Type and extension messages implicitly provide the number of scheduled users" */
                for (uint32_t bit_offset=offset*8; bit_offset < end_bit; bit_offset+=4, ueid_index++) {
                    proto_item *ti = proto_tree_add_bits_item(extension_tree, hf_oran_num_ueid, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (user #%u)", ueid_index);
                }
                break;
            }

            case 18:  /* SE 18: Uplink transmission management */
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

            case 19:  /* SE 19: Compact beamforming information for multiple port */
            {
                /* beamId in section header should be ignored. Guard against appending multiple times.. */
                if (beamId_ti && !beamId_ignored) {
                    proto_item_append_text(beamId_ti, " (ignored)");
                    beamId_ignored = true;
                }

                /* numSymbol not used in this case */
                if (numsymbol_ti && !numsymbol_ignored) {
                    proto_item_append_text(numsymbol_ti, " (ignored)");
                    numsymbol_ignored = true;
                }

                /* disableBFWs */
                bool disableBFWs;
                proto_tree_add_item_ret_boolean(extension_tree, hf_oran_disable_bfws,
                                                tvb, offset, 1, ENC_BIG_ENDIAN, &disableBFWs);
                if (disableBFWs) {
                    proto_item_append_text(extension_ti, " (disableBFWs)");
                }
                /* repetition (1 bit) */
                uint64_t repetition;
                proto_tree_add_bits_ret_val(extension_tree, hf_oran_se19_repetition, tvb, (offset*8)+1, 1, &repetition, ENC_BIG_ENDIAN);
                /* numPortc (6 bits) */
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_numPortc,
                                             tvb, offset, 1, ENC_BIG_ENDIAN, &numPortc);
                offset++;

                /* priority (2 bits) */
                proto_tree_add_item(extension_tree, hf_oran_noncontig_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* symbolMask (14 bits) */
                offset = dissect_symbolmask(tvb, extension_tree, offset, NULL, NULL);

                uint32_t bfwcomphdr_iq_width, bfwcomphdr_comp_meth;
                proto_item *comp_meth_ti = NULL;

                if (!repetition) {

                    if (!disableBFWs) {
                        /* bfwCompHdr */
                        offset = dissect_bfwCompHdr(tvb, extension_tree, offset,
                                                    &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);
                    }

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

                        /* No weights present */
                        if (!disableBFWs) {
                            /*******************************************************************/
                            /* Table 7.7.19.1-1 (there is no part -2 for disableBFWs case...), */
                            /* but for SE 11, bfwCompParam was only present for !disableBFWs   */
                            /*******************************************************************/

                            /* bfwCompParam */
                            bool compression_method_supported = false;
                            uint32_t exponent = 0;
                            unsigned num_trx_entries = 0;
                            uint16_t *trx;
                            offset = dissect_bfwCompParam(tvb, port_tree, pinfo, offset, comp_meth_ti,
                                                          &bfwcomphdr_comp_meth, &exponent, &compression_method_supported,
                                                          &num_trx_entries, &trx);

                            int bit_offset = offset*8;
                            int bfw_offset;

                            /* Add weights for each TRX */
                            unsigned trx_to_add = (num_trx_entries==0) ? pref_num_bf_antennas : num_trx_entries;
                            for (unsigned b=0; b < trx_to_add; b++) {

                                uint16_t trx_index = (num_trx_entries) ? trx[b] : b+1;

                                /* Create BFW subtree */
                                bfw_offset = bit_offset / 8;
                                uint8_t bfw_extent = ((bit_offset + (bfwcomphdr_iq_width*2)) / 8) - bfw_offset;
                                proto_item *bfw_ti = proto_tree_add_string_format(port_tree, hf_oran_bfw,
                                                                                  tvb, bfw_offset, bfw_extent,
                                                                                  "", "TRX %u: (", trx_index);
                                proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

                                /* I */
                                uint32_t bits = tvb_get_bits32(tvb, bit_offset, bfwcomphdr_iq_width, ENC_BIG_ENDIAN);
                                float value = decompress_value(bits, bfwcomphdr_comp_meth, bfwcomphdr_iq_width, exponent, NULL /* no ModCompr */, 0 /* RE */);
                                /* Add to tree. */
                                proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_i, tvb, bit_offset/8,
                                                                  (bfwcomphdr_iq_width+7)/8, value, "#%u=%f", b, value);
                                bit_offset += bfwcomphdr_iq_width;
                                proto_item_append_text(bfw_ti, "I%u=%f ", b, value);

                                /* Q */
                                bits = tvb_get_bits32(tvb, bit_offset, bfwcomphdr_iq_width, ENC_BIG_ENDIAN);
                                value = decompress_value(bits, bfwcomphdr_comp_meth, bfwcomphdr_iq_width, exponent, NULL /* no ModCompr */, 0 /* RE */);
                                /* Add to tree. */
                                proto_tree_add_float_format_value(bfw_tree, hf_oran_bfw_q, tvb, bit_offset/8,
                                                                  (bfwcomphdr_iq_width+7)/8, value, "#%u=%f", b, value);
                                bit_offset += bfwcomphdr_iq_width;
                                proto_item_append_text(bfw_ti, "Q%u=%f)", b, value);
                            }

                            offset = (bit_offset+7)/8;
                        }
                        else {
                            /* No weights... */
                        }

                        /* Set length of this port entry */
                        proto_item_set_len(port_ti, offset-port_start_offset);
                    }
                }
                break;
            }

            case 20:  /* SE 20: Puncturing extension */
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
                                                                         "", "Puncturing Pattern: %u/%u", n+1, numPuncPatterns);
                    proto_tree *pattern_tree = proto_item_add_subtree(pattern_ti, ett_oran_punc_pattern);

                    /* SymbolMask (14 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_symbolMask_ext20, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 1;

                    uint32_t startPuncPrb, numPuncPrb;

                    /* startPuncPrb (10 bits) */
                    proto_tree_add_item_ret_uint(pattern_tree, hf_oran_startPuncPrb, tvb, offset, 2, ENC_BIG_ENDIAN, &startPuncPrb);
                    offset += 2;
                    /* numPuncPrb (8 bits) */
                    proto_tree_add_item_ret_uint(pattern_tree, hf_oran_numPuncPrb, tvb, offset, 1, ENC_BIG_ENDIAN, &numPuncPrb);
                    offset += 1;

                    proto_item_append_text(pattern_ti, " [%u->%u]", startPuncPrb, startPuncPrb+numPuncPrb-1);

                    /* Make a hole in range of PRBs to report */
                    for (unsigned p=startPuncPrb; p < startPuncPrb+numPuncPrb; p++) {
                        if (p < MAX_PRBS) {
                            prbs_for_st10_type5[p] = false;
                        }
                    }

                    /* puncReMask (12 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_puncReMask, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 1;
                    /* rb (1 bit) */
                    proto_item *rb_ti = proto_tree_add_item(pattern_tree, hf_oran_rb, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* reserved (1 bit) */
                    proto_tree_add_item(pattern_tree, hf_oran_reserved_bit5, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* multiSDScope (1 bit) */
                    proto_tree_add_item(pattern_tree, hf_oran_multiSDScope, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* rbgIncl (1 bit) */
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

                        proto_item_append_text(rb_ti, " (ignored)");
                    }

                    proto_item_set_len(pattern_ti, offset-pattern_start_offset);
                }

                break;
            }
            case 21:  /* SE 21: Variable PRB group size for channel information */
            {
                /* ciPrbGroupSize */
                uint32_t ci_prb_group_size;
                proto_item *prb_group_size_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_ci_prb_group_size, tvb, offset, 1, ENC_BIG_ENDIAN, &ci_prb_group_size);
                offset += 1;

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
                        /* This value affects how SE 11 is interpreted */
                        ext11_settings.ext21_set = true;
                        ext11_settings.ext21_ci_prb_group_size = ci_prb_group_size;

                        if (numPrbc == 0) {
                            expert_add_info(pinfo, numprbc_ti, &ei_oran_numprbc_ext21_zero);
                        }
                        break;
                }

                /* reserved (6 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_6bits, tvb, offset, 1, ENC_BIG_ENDIAN);

                /* prgSize (2 bits). Interpretation depends upon section type (5 or 6), but also mplane parameters? */
                if (sectionType == SEC_C_UE_SCHED) {             /* Section Type 5 */
                    proto_tree_add_item(extension_tree, hf_oran_prg_size_st5, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                else if (sectionType == SEC_C_CH_INFO) {         /* Section Type 6 */
                    proto_tree_add_item(extension_tree, hf_oran_prg_size_st6, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                offset += 1;
                break;
            }

            case 22:  /* SE 22: ACK/NACK request */
            {
                uint32_t ack_nack_req_id;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_ack_nack_req_id, tvb, offset, 2,
                                             ENC_BIG_ENDIAN, &ack_nack_req_id);
                offset += 2;

                if (state) {
                    if (!PINFO_FD_VISITED(pinfo)) {
                        /* Add this request into conversation state on first pass */
                        ack_nack_request_t *request_details = wmem_new0(wmem_file_scope(), ack_nack_request_t);
                        request_details->request_frame_number = pinfo->num;
                        request_details->request_frame_time = pinfo->abs_ts;
                        request_details->requestType = SE22;
                        /* Insert into flow's tree */
                        wmem_tree_insert32(state->ack_nack_requests, ack_nack_req_id, request_details);
                    }
                    else {
                        /* Try to link forward to ST8 response */
                        ack_nack_request_t *response = wmem_tree_lookup32(state->ack_nack_requests,
                                                                          ack_nack_req_id);
                        if (response) {
                            show_link_to_acknack_response(extension_tree, tvb, pinfo, response);
                        }
                    }
                }
                break;
            }

            case 23:  /* SE 23: Arbitrary symbol pattern modulation compression parameters */
            {
                /* Green common header */

                /* numSymPrbPattern (4 bits) */
                uint32_t num_sym_prb_pattern;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_num_sym_prb_pattern, tvb, offset, 1, ENC_BIG_ENDIAN, &num_sym_prb_pattern);
                /* reserved (3 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_bits456, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* prbMode (1 bit) */
                bool prb_mode;
                proto_tree_add_item_ret_boolean(extension_tree, hf_oran_prb_mode, tvb, offset, 1, ENC_BIG_ENDIAN, &prb_mode);
                offset += 1;

                /* reserved (8 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Dissect each SymPrbPattern */
                for (uint32_t n=0; n < num_sym_prb_pattern; n++) {

                    /* Subtree */
                    proto_item *pattern_ti = proto_tree_add_string_format(extension_tree, hf_oran_sym_prb_pattern,
                                                                          tvb, offset, 1, "",
                                                                          prb_mode ? "PRB-BLOCK" : "PRB-MASK");
                    proto_tree *pattern_tree = proto_item_add_subtree(pattern_ti, ett_oran_sym_prb_pattern);


                    /* Orange part */

                    /* Reserved (2 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* symMask (14 bits) */
                    proto_tree_add_item(pattern_tree, hf_oran_sym_mask, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    /* numMcScaleOffset (4 bits) */
                    uint32_t numMcScaleOffset;
                    proto_tree_add_item_ret_uint(pattern_tree, hf_oran_num_mc_scale_offset, tvb, offset, 1, ENC_BIG_ENDIAN, &numMcScaleOffset);

                    if (!prb_mode) {     /* PRB-MASK */
                        /* prbPattern (4 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_prb_pattern, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        /* reserved (8 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    else {               /* PRB-BLOCK */
                        /* prbBlkOffset (8 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_prb_block_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        /* prbBlkSize (4 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_prb_block_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }

                    /* Yellowish part */
                    if (prb_mode) {   /* PRB-BLOCK */
                        /* prbBlkSize (4 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_prb_block_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }
                    else {
                        /* reserved (4 bits) */
                        proto_tree_add_item(pattern_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }

                    for (unsigned c=0; c < numMcScaleOffset; c++) {

                        if (c > 0) {
                            /* reserved (4 bits) */
                            proto_tree_add_item(pattern_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                        }

                        static int * const  remask_flags_even[] = {
                            &hf_oran_mc_scale_re_mask_re1_even,
                            &hf_oran_mc_scale_re_mask_re2_even,
                            &hf_oran_mc_scale_re_mask_re3_even,
                            &hf_oran_mc_scale_re_mask_re4_even,
                            &hf_oran_mc_scale_re_mask_re5_even,
                            &hf_oran_mc_scale_re_mask_re6_even,
                            &hf_oran_mc_scale_re_mask_re7_even,
                            &hf_oran_mc_scale_re_mask_re8_even,
                            &hf_oran_mc_scale_re_mask_re9_even,
                            &hf_oran_mc_scale_re_mask_re10_even,
                            &hf_oran_mc_scale_re_mask_re11_even,
                            &hf_oran_mc_scale_re_mask_re12_even,
                            NULL
                        };

                        /* mcScaleReMask (12 bits).  Defines which REs the following csf and mcScaleOffset apply to */
                        uint64_t mcScaleReMask, mcScaleOffset;
                        proto_tree_add_bitmask_ret_uint64(pattern_tree, tvb, offset,
                                                          hf_oran_mc_scale_re_mask_even,
                                                          ett_oran_mc_scale_remask,
                                                          remask_flags_even, ENC_BIG_ENDIAN, &mcScaleReMask);

                        offset += 2;
                        /* csf (1 bit) */
                        bool csf;
                        dissect_csf(pattern_tree, tvb, offset*8, ci_iq_width, &csf);
                        /* mcScaleOffset (15 bits) */
                        proto_item *ti = proto_tree_add_bits_ret_val(pattern_tree, hf_oran_mc_scale_offset, tvb, offset*8 + 1, 15, &mcScaleOffset, ENC_BIG_ENDIAN);
                        uint16_t exponent = (mcScaleOffset >> 11) & 0x000f; /* m.s. 4 bits */
                        uint16_t mantissa = mcScaleOffset & 0x07ff;         /* l.s. 11 bits */
                        float mcScaleOffset_value = ((float)mantissa/(1<<11)) * ((float)1.0 / (1 << exponent));
                        proto_item_append_text(ti, " (%f)", mcScaleOffset_value);

                        offset += 2;

                        /* Record this config.  */
                        section_mod_compr_config_t* sect_config = get_mod_compr_section_to_write(state, sectionId);

                        if (sect_config && sect_config->num_configs < MAX_MOD_COMPR_CONFIGS) {
                            unsigned i = sect_config->num_configs;
                            sect_config->configs[i].mod_compr_re_mask = (uint16_t)mcScaleReMask;
                            sect_config->configs[i].mod_compr_csf = csf;
                            sect_config->configs[i].mod_compr_scaler = mcScaleOffset_value;
                            sect_config->num_configs++;
                        }
                    }

                    proto_item_set_end(pattern_ti, tvb, offset);
                }
                break;
            }

            case 24:   /* SE 24: PUSCH DMRS configuration */
            {
                /* Hidden filter for bf (DMRS BF) */
                bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_HIDDEN(bf_ti);

                /* alpnPerSym (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_alpn_per_sym, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* antDmrsSnr (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_ant_dmrs_snr, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_bit2, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* userGroupSize (5 bits) */
                uint32_t user_group_size;
                proto_item *ugs_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_user_group_size, tvb, offset, 1, ENC_BIG_ENDIAN, &user_group_size);
                if (user_group_size == 0) {
                    proto_item_append_text(ugs_ti, " (not used)");
                }
                else if (user_group_size > 12) {
                    proto_item_append_text(ugs_ti, " (reserved)");
                }
                offset += 1;
                /* userGroupId (8 bits)*/
                uint32_t user_group_id;
                proto_item *ugi_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_user_group_id, tvb, offset, 1, ENC_BIG_ENDIAN, &user_group_id);
                if (user_group_id == 0) {
                    /* TODO: Value 0 can happen in several cases, described in 7.7.24.7.. */
                }
                if (user_group_id == 255) {
                    /* Value 255 is reserved */
                    expert_add_info(pinfo, ugi_ti, &ei_oran_user_group_id_reserved_value);
                }
                offset += 1;

                bool seen_value_to_inherit = false;
                bool inherited_config_has_transform_precoding = false;
                int dmrs_configs_seen = 0;

                /* Dissect each entry until reach number of configured ueIds (or run out of extlen bytes..) */
                uint32_t ueid_index = 0;
                while ((offset < (extension_start_offset + extlen*4)) && (ueid_index < number_of_ueids)) {
                    dmrs_configs_seen++;

                    /* Subtree */
                    proto_item *entry_ti = proto_tree_add_string_format(extension_tree, hf_oran_dmrs_entry,
                                                                        tvb, offset, 0, "",
                                                                        "Entry");
                    proto_tree *entry_tree = proto_item_add_subtree(entry_ti, ett_oran_dmrs_entry);

                    /* entryType (3 bits) */
                    uint32_t entry_type;
                    proto_item *entry_type_ti;
                    entry_type_ti = proto_tree_add_item_ret_uint(entry_tree, hf_oran_entry_type, tvb, offset, 1, ENC_BIG_ENDIAN, &entry_type);
                    if (entry_type > 3) {
                        proto_item_append_text(entry_type_ti, " (reserved)");
                    }

                    /* dmrsPortNumber (5 bits).  Values 0-11 allowed */
                    unsigned int dmrs_port_number;
                    proto_item *dpn_ti = proto_tree_add_item_ret_uint(entry_tree, hf_oran_dmrs_port_number, tvb, offset, 1, ENC_BIG_ENDIAN, &dmrs_port_number);
                    if (dmrs_port_number > 11) {
                        proto_item_append_text(dpn_ti, " (12-31 are reserved)");
                    }
                    offset += 1;

                    /* What follows depends upon entryType */
                    switch (entry_type) {
                        case 0:    /* dmrsPortNumber config same as previous,  ueId ueIdReset=0 */
                        case 1:    /* dmrsPortNumber config same as previous,  ueId ueIdReset=1 */
                            /* No further fields for these */
                            /* Error here if no previous values to inherit!! */
                            if (!seen_value_to_inherit) {
                                expert_add_info_format(pinfo, entry_type_ti, &ei_oran_se24_nothing_to_inherit,
                                                       "SE24: have seen entry type %u, but no previous config (type 2 or 3) to inherit config from", entry_type);

                            }
                            /* TODO: would be useful to repeat whole inherited config here? */
                            break;

                        case 2:    /* transform precoding disabled */
                        case 3:    /* transform precoding enabled */
                        {
                            /* Type 2/3 are very similar.. */

                            /* ueIdReset (1 bit) */
                            proto_tree_add_item(entry_tree, hf_oran_ueid_reset, tvb, offset, 1, ENC_BIG_ENDIAN);
                            /* reserved (1 bit) */
                            proto_tree_add_item(entry_tree, hf_oran_reserved_bit1, tvb, offset, 1, ENC_BIG_ENDIAN);

                            /* dmrsSymbolMask (14 bits) */
                            static int * const  dmrs_symbol_mask_flags[] = {
                                &hf_oran_dmrs_symbol_mask_s13,
                                &hf_oran_dmrs_symbol_mask_s12,
                                &hf_oran_dmrs_symbol_mask_s11,
                                &hf_oran_dmrs_symbol_mask_s10,
                                &hf_oran_dmrs_symbol_mask_s9,
                                &hf_oran_dmrs_symbol_mask_s8,
                                &hf_oran_dmrs_symbol_mask_s7,
                                &hf_oran_dmrs_symbol_mask_s6,
                                &hf_oran_dmrs_symbol_mask_s5,
                                &hf_oran_dmrs_symbol_mask_s4,
                                &hf_oran_dmrs_symbol_mask_s3,
                                &hf_oran_dmrs_symbol_mask_s2,
                                &hf_oran_dmrs_symbol_mask_s1,
                                &hf_oran_dmrs_symbol_mask_s0,
                                NULL
                            };
                            proto_tree_add_bitmask(entry_tree, tvb, offset,
                                                   hf_oran_dmrs_symbol_mask, ett_oran_dmrs_symbol_mask, dmrs_symbol_mask_flags, ENC_BIG_ENDIAN);
                            offset += 2;

                            /* scrambling */
                            proto_tree_add_item(entry_tree, hf_oran_scrambling, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;

                            /* nscid (1 bit) */
                            proto_tree_add_item(entry_tree, hf_oran_nscid, tvb, offset, 1, ENC_BIG_ENDIAN);

                            /* These 5 bits differ depending upon entry type */
                            if (entry_type == 2) {       /* type 2 */
                                /* dType (1 bit) */
                                proto_tree_add_item(entry_tree, hf_oran_dtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                                /* cdmWithoutData (2 bits) */
                                proto_tree_add_item(entry_tree, hf_oran_cmd_without_data, tvb, offset, 1, ENC_BIG_ENDIAN);
                                /* lambda (2 bits) */
                                proto_tree_add_item(entry_tree, hf_oran_lambda, tvb, offset, 1, ENC_BIG_ENDIAN);
                            }
                            else {                        /* type 3 */
                                /* reserved (1 bit) */
                                proto_tree_add_item(entry_tree, hf_oran_reserved_bit1, tvb, offset, 1, ENC_BIG_ENDIAN);
                                /* lowPaprType (2 bits) */
                                proto_tree_add_item(entry_tree, hf_oran_low_papr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                                /* hoppingMode (2 bits) */
                                proto_tree_add_item(entry_tree, hf_oran_hopping_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
                            }

                            /* firstPrb (9 bits) */
                            proto_tree_add_item(entry_tree, hf_oran_first_prb, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 1;
                            /* lastPrb (9 bits) */
                            proto_tree_add_item(entry_tree, hf_oran_last_prb, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            /* Reserved (16 bits) */
                            proto_tree_add_item(entry_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;

                            /* Could now see entry types 0 or 1 - they have these values to inherit */
                            seen_value_to_inherit = true;
                            inherited_config_has_transform_precoding = (entry_type == 3);
                            break;
                        }

                        default:
                            /* reserved - expert info */
                            break;
                    }

                    proto_item_append_text(entry_ti, " [UEId=%u] (dmrsPortNumber=%2u) (type %u - %s) ",
                                           ueids[ueid_index++], dmrs_port_number, entry_type, val_to_str_const(entry_type, entry_type_vals, "Unknown"));
                    proto_item_set_end(entry_ti, tvb, offset);

                    if (entry_type <= 1) {
                        proto_item_append_text(entry_ti, " [transform-precoding %s]",
                                               inherited_config_has_transform_precoding ? "enabled" : "disabled");
                    }
                }

                proto_item_append_text(extension_ti, " (%d DMRS configs seen)", dmrs_configs_seen);
                break;
            }

            case 25:  /* SE 25: Symbol reordering for DMRS-BF */
                /* Just dissect each available block of 7 bytes as the 14 symbols for a layer,
                   where each layer could be one or apply to all layers. */
            {
                /* TODO: should only appear in one section of a message - check? */
                unsigned layer = 0;
                proto_item *layer_ti;
                while (offset+7 <= (extension_start_offset + extlen*4)) {
                    /* Layer subtree */
                    layer_ti = proto_tree_add_string_format(extension_tree, hf_oran_symbol_reordering_layer,
                                                            tvb, offset, 7, "",
                                                            "Layer");
                    proto_tree *layer_tree = proto_item_add_subtree(layer_ti, ett_oran_symbol_reordering_layer);

                    /* All 14 symbols for a layer (or all layers) */
                    for (unsigned s=0; s < 14; s++) {
                        proto_item *sym_ti;
                        /* txWinForOnAirSymbol */
                        unsigned int tx_win_for_on_air_symbol;
                        sym_ti = proto_tree_add_item_ret_uint(layer_tree,
                                                              (s % 2) ? hf_oran_tx_win_for_on_air_symbol_r : hf_oran_tx_win_for_on_air_symbol_l,
                                                              tvb, offset, 1, ENC_BIG_ENDIAN, &tx_win_for_on_air_symbol);
                        if (tx_win_for_on_air_symbol == 0x0F) {
                            /* Ordering not affected */
                            proto_item_append_text(sym_ti, " (sym %u - no info)", s);
                        }
                        else {
                            proto_item_append_text(sym_ti, " (sym %u)", s);
                        }
                        if (s % 2) {
                            offset += 1;
                        }
                    }

                    proto_item_append_text(layer_ti,     " (layer %u)", ++layer);
                    proto_item_append_text(extension_ti, " (layer %u)", layer);
                }
                /* Set layer subtree label */
                if (layer == 1) {
                    proto_item_append_text(layer_ti,     " (all)");
                    proto_item_append_text(extension_ti, " (all)");
                }
                if (layer == 0) {
                    /* TODO: are no layers valid?  What does it mean? */
                    proto_item_append_text(extension_ti, " (none)");
                }
                break;
            }

            case 26:  /* SE 26: Frequency offset feedback */
                /* Reserved (8 bits). N.B., added after draft? */
                proto_tree_add_item(extension_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* Reserved (1 bit) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* numFoFb (7 bits) */
                unsigned num_fo_fb;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_num_fo_fb, tvb, offset, 1, ENC_BIG_ENDIAN, &num_fo_fb);
                offset += 1;

                /* Add each freqOffsetFb value */
                for (unsigned n=0; n < num_fo_fb; n++) {
                    unsigned freq_offset_fb;
                    /* freqOffsetFb (16 bits) */
                    proto_item *offset_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_freq_offset_fb,
                                                                         tvb, offset, 2, ENC_BIG_ENDIAN, &freq_offset_fb);
                    /* Show if maps onto a -ve number */
                    if ((freq_offset_fb >= 0x8ad0) && (freq_offset_fb <= 0xffff)) {
                        proto_item_append_text(offset_ti, "(value %d)", -1 - (0xffff-freq_offset_fb));
                    }
                    proto_item_append_text(offset_ti, " [#%u]", n+1);
                    offset += 2;
                }
                break;

            case 27: /* SE 27: O-DU controlled dimensionality reduction */
            {
                /* Hidden filter for bf (DMRS BF) */
                bf_ti = proto_tree_add_item(tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_HIDDEN(bf_ti);

                /* beamType (2 bits) */
                unsigned beam_type;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_beam_type, tvb, offset, 1, ENC_BIG_ENDIAN, &beam_type);
                /* reserved (6 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_last_6bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* numElements */
                unsigned num_elements;
                proto_item *num_elements_ti = proto_tree_add_item_ret_uint(extension_tree, hf_oran_num_elements, tvb, offset, 1, ENC_BIG_ENDIAN, &num_elements);
                if (num_elements == 0) {
                    num_elements = 256;
                    proto_item_append_text(num_elements_ti, " (256");
                }

                offset += 1;

                /* beamId value(s) */
                switch (beam_type) {
                    case 0:
                        for (unsigned n=0; n < num_elements; n++) {
                            /* reserved (1 bit) + beamId */
                            proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(c_section_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                        }
                        break;
                    case 1:
                        /* reserved (1 bit) + beamId */
                        proto_tree_add_item(extension_tree, hf_oran_reserved_1bit, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(c_section_tree, hf_oran_beamId, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        break;
                    default:
                        /* Unknown type... */
                        break;
                }
                break;
            }

            case 28: /* SE 28: O-DU controlled frequency resolution for SINR reporting */
            {
                /* reserved (3 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_3bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* numUeSinrRpt */
                uint32_t num_ue_sinr_rpt;
                proto_tree_add_item_ret_uint(extension_tree, hf_oran_num_ue_sinr_rpt, tvb, offset, 1, ENC_BIG_ENDIAN, &num_ue_sinr_rpt);
                offset += 1;

                for (uint32_t n=0; n < num_ue_sinr_rpt; n++) {
                    /* reserved (1 bit) */
                    proto_tree_add_item(extension_tree, (n % 2) ? hf_oran_reserved_bit4 : hf_oran_reserved_1bit,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);

                    /* numSinrPerPrb (3 bits).  Taken from alternate nibbles within byte.  */
                    proto_tree_add_item(extension_tree, (n % 2) ? hf_oran_num_sinr_per_prb_right : hf_oran_num_sinr_per_prb,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (n % 2) {
                        offset += 1;
                    }
                }

                /* May need to skip beyond half-used byte */
                if (num_ue_sinr_rpt % 2) {
                    offset += 1;
                }
                break;
            }

            case 29: /* SE 29: Cyclic delay adjustment */
                /* reserved (4 bits) */
                proto_tree_add_item(extension_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* cdScgSize (4 bits) */
                proto_tree_add_item(extension_tree, hf_oran_cd_scg_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* cdScgPhaseStep */
                proto_tree_add_item(extension_tree, hf_oran_cd_scg_phase_step, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;


            default:
                /* Other/unexpected extension types */
                expert_add_info_format(pinfo, exttype_ti, &ei_oran_unhandled_se,
                                       "SE %u (%s) not supported by dissector",
                                       exttype, val_to_str_const(exttype, exttype_vals, "Reserved"));
                ext_unhandled = true;
                break;
        }

        /* Check offset compared with extlen.  There should be 0-3 bytes of padding */
        int num_padding_bytes = (extension_start_offset + (extlen*4) - offset);
        if (!ext_unhandled && ((num_padding_bytes<0) || (num_padding_bytes>3))) {
            expert_add_info_format(pinfo, extlen_ti, &ei_oran_extlen_wrong,
                                   "extlen signalled %u bytes (+ 0-3 bytes padding), but %u were dissected",
                                   extlen*4, offset-extension_start_offset);
        }

        /* Move offset to beyond signalled length of extension */
        offset = extension_start_offset + (extlen*4);

        /* Set length of extension header. */
        proto_item_set_len(extension_ti, extlen*4);
    }
    /* End of section extension handling */



    /* RRM measurement reports have measurement reports *after* extensions */
    if (sectionType == SEC_C_RRM_MEAS_REPORTS)   /* Section Type 10 */
    {
        /* Hidden filter for bf (DMFS-BF). No BF weights though.. */
        bf_ti = proto_tree_add_item(c_section_tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(bf_ti);

        bool mf;
        do {
            /* Measurement report subtree */
            proto_item *mr_ti = proto_tree_add_string_format(c_section_tree, hf_oran_measurement_report,
                                                             tvb, offset, 1, "", "Measurement Report");
            proto_tree *mr_tree = proto_item_add_subtree(mr_ti, ett_oran_measurement_report);
            unsigned report_start_offset = offset;

            /* more fragments (after this one) (1 bit) */
            proto_tree_add_item_ret_boolean(mr_tree, hf_oran_mf, tvb, offset, 1, ENC_BIG_ENDIAN, &mf);

            /* measTypeId (7 bits) */
            uint32_t meas_type_id;
            proto_item *meas_type_id_ti;
            meas_type_id_ti = proto_tree_add_item_ret_uint(mr_tree, hf_oran_meas_type_id, tvb, offset, 1, ENC_BIG_ENDIAN, &meas_type_id);
            offset += 1;

            /* Common to all measurement types */
            unsigned num_elements = 0;
            if (meas_type_id == 6) {
                /* numElements */
                proto_tree_add_item_ret_uint(mr_tree, hf_oran_num_elements, tvb, offset, 1, ENC_BIG_ENDIAN, &num_elements);
            }
            else {
                /* All other meas ids have a reserved byte */
                proto_tree_add_item(mr_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            offset += 1;

            /* measDataSize (16 bits). N.B. begins at mf field, i.e. 2 bytes before this one  */
            unsigned meas_data_size;
            proto_item *meas_data_size_ti;
            meas_data_size_ti = proto_tree_add_item_ret_uint(mr_tree, hf_oran_meas_data_size, tvb, offset, 2, ENC_BIG_ENDIAN, &meas_data_size);
            meas_data_size *= 4;
            proto_item_append_text(meas_data_size_ti, " (%u bytes)", meas_data_size);
            offset += 2;

            /* Summary for measurement report root */
            proto_item_append_text(mr_ti, " (measTypeId=%u - %s)",
                                   meas_type_id, val_to_str_const(meas_type_id, meas_type_id_vals, "unknown"));
            /* And section header */
            proto_item_append_text(tree, " (%s)", val_to_str_const(meas_type_id, meas_type_id_vals, "unknown"));
            /* And Info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str_const(meas_type_id, meas_type_id_vals, "unknown"));

            /* Handle specific message type fields */
            switch (meas_type_id) {
                case 1:
                {
                    /* ueTae */
                    unsigned ue_tae;
                    proto_item *ue_tae_ti;
                    ue_tae_ti = proto_tree_add_item_ret_uint(mr_tree, hf_oran_ue_tae, tvb, offset, 2, ENC_BIG_ENDIAN, &ue_tae);
                    /* Show if maps onto a -ve number */
                    if ((ue_tae >= 0x8ad0) && (ue_tae <= 0xffff)) {
                        proto_item_append_text(ue_tae_ti, "(value %d)", -1 - (0xffff-ue_tae));
                    }
                    offset += 2;

                    /* Reserved (16 bits) */
                    proto_tree_add_item(mr_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                }
                case 2:
                    /* ueLayerPower entries (how many? for now just use up meas_data_size..) */
                    /* TODO: add number of distinct dmrsPortNumber entries seen in SE24 and save in state? */
                    /* Or would it make sense to use the preference 'pref_num_bf_antennas' ? */
                    for (unsigned n=0; n < (meas_data_size-4)/2; n++) {
                        unsigned ue_layer_power;
                        proto_item *ue_layer_power_ti;
                        ue_layer_power_ti = proto_tree_add_item_ret_uint(mr_tree, hf_oran_ue_layer_power, tvb, offset, 2, ENC_BIG_ENDIAN, &ue_layer_power);
                        /* Show if maps onto a -ve number */
                        if ((ue_layer_power >= 0x8ad0) && (ue_layer_power <= 0xffff)) {
                            proto_item_append_text(ue_layer_power_ti, "(value %d)", -1 - (0xffff-ue_layer_power));
                        }
                        offset += 2;
                    }
                    /* padding out to 4 bytes */
                    break;
                case 3:
                {
                    /* ueFreqOffset */
                    unsigned ue_freq_offset;
                    proto_item *ue_freq_offset_ti;
                    ue_freq_offset_ti = proto_tree_add_item_ret_uint(mr_tree, hf_oran_ue_freq_offset, tvb, offset, 2, ENC_BIG_ENDIAN, &ue_freq_offset);
                    /* Show if maps onto a -ve number */
                    if ((ue_freq_offset >= 0x8ad0) && (ue_freq_offset <= 0xffff)) {
                        proto_item_append_text(ue_freq_offset_ti, "(value %d)", -1 - (0xffff-ue_freq_offset));
                    }
                    offset += 2;

                    /* Reserved (16 bits) */
                    proto_tree_add_item(mr_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                }
                case 4:
                case 5:
                    /* reserved (2 bits) */
                    proto_tree_add_item(mr_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* symbolMask (14 bits) */
                    offset = dissect_symbolmask(tvb, mr_tree, offset, NULL, NULL);

                    /* 2 bytes for each PRB ipnPower */
                    for (unsigned prb=0; prb<MAX_PRBS; prb++) {
                        /* Skip if should not be reported */
                        if (!prbs_for_st10_type5[prb]) {
                            continue;
                        }
                        unsigned ipn_power;
                        proto_item *ipn_power_ti;
                        /* ipnPower (2 bytes) */
                        ipn_power_ti = proto_tree_add_item_ret_uint(mr_tree, hf_oran_ipn_power, tvb, offset, 2, ENC_BIG_ENDIAN, &ipn_power);
                        proto_item_append_text(ipn_power_ti, " (PRB %3d)", prb);
                        /* Show if maps onto a -ve number */
                        if ((ipn_power >= 0x8ad0) && (ipn_power <= 0xffff)) {
                            proto_item_append_text(ipn_power_ti, " (value %d)", -1 - (0xffff-ipn_power));
                        }
                        offset += 2;
                    }
                    /* padding out to 4 bytes */
                    break;
                case 6:
                    /* antDmrsSnrVal entries */
                    for (unsigned n=0; n < num_elements; n++) {
                        unsigned snr_value;
                        proto_item *snr_value_ti;
                        /* antDmrsSnrVal (2 bytes) */
                        snr_value_ti = proto_tree_add_item_ret_uint(mr_tree, hf_oran_ant_dmrs_snr_val, tvb, offset, 2, ENC_BIG_ENDIAN, &snr_value);
                        proto_item_append_text(snr_value_ti, " (elem %2u)", n+1);
                        /* Show if maps onto a -ve number */
                        if ((snr_value >= 0x8ad0) && (snr_value <= 0xffff)) {
                            proto_item_append_text(snr_value_ti, " (value %d)", -1 - (0xffff-snr_value));
                        }
                        offset += 2;
                    }
                    break;

                default:
                    /* Anything else is not expected */
                    expert_add_info_format(pinfo, meas_type_id_ti, &ei_oran_unexpected_measTypeId,
                                           "measTypeId %u (%s) not supported - only 1-6 are expected",
                                           meas_type_id,
                                           val_to_str_const(meas_type_id, meas_type_id_vals, "reserved"));
                    break;

            }

            /* Pad out to next 4 bytes */
            offset += WS_PADDING_TO_4(offset-report_start_offset);

            /* TODO: verify dissected size of report vs meas_data_size? */

            /* End of measurement report tree */
            proto_item_set_end(mr_ti, tvb, offset);
        } while (mf);
    }

    /*  Request for RRM Measurements has measurement commands after extensions */
    else if (sectionType == SEC_C_REQUEST_RRM_MEAS)               /* Section Type 11 */
    {
        bool mf = true;
        do {
            /* Measurement command subtree */
            proto_item *mc_ti = proto_tree_add_string_format(c_section_tree, hf_oran_measurement_command,
                                                             tvb, offset, 8, "", "Measurement Command");
            proto_tree *mc_tree = proto_item_add_subtree(mc_ti, ett_oran_measurement_command);

            /* mf (1 bit).  1st measurement command is always preset */
            proto_tree_add_item_ret_boolean(mc_tree, hf_oran_mf, tvb, offset, 1, ENC_BIG_ENDIAN, &mf);

            /* measTypeId (7 bits) */
            uint32_t meas_type_id;
            proto_item *meas_type_id_ti;
            meas_type_id_ti = proto_tree_add_item_ret_uint(mc_tree, hf_oran_meas_type_id, tvb, offset, 1, ENC_BIG_ENDIAN, &meas_type_id);
            offset += 1;

            proto_item *meas_command_ti;
            uint32_t meas_command_size;

            switch (meas_type_id) {
                case 5:                           /* command for IpN for unallocated PRBs */
                    /* reserved (1 byte) */
                    proto_tree_add_item(mc_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    /* measCmdSize.  Presumably number of words so in future could skip unrecognised command types.. */
                    meas_command_ti = proto_tree_add_item_ret_uint(mc_tree, hf_oran_meas_cmd_size, tvb, offset, 2, ENC_BIG_ENDIAN, &meas_command_size);
                    proto_item_append_text(meas_command_ti, " (%u bytes)", meas_command_size*4);
                    offset += 2;
                    /* reserved (2 bits) */
                    proto_tree_add_item(mc_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* symbolMask (14 bits) */
                    offset = dissect_symbolmask(tvb, mc_tree, offset, NULL, NULL);
                    /* reserved (16 bits) */
                    proto_tree_add_item(mc_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;

                default:
                    /* Anything else is not expected */
                    expert_add_info_format(pinfo, meas_type_id_ti, &ei_oran_unexpected_measTypeId,
                                           "measTypeId %u (%s) not supported - only 5 is expected",
                                           meas_type_id,
                                           val_to_str_const(meas_type_id, meas_type_id_vals, "reserved"));
                    break;
            }
            proto_item_append_text(mc_ti, " (%s)", val_to_str_const(meas_type_id, meas_type_id_vals, "unknown"));

        } while (mf);
    }

    /* Set extent of overall section */
    proto_item_set_len(sectionHeading, offset);

    return offset;
}

/* Dissect udCompHdr (user data compression header, 7.5.2.10) */
/* bit_width and comp_meth are out params */
static int dissect_udcomphdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset,
                             bool ignore,
                             unsigned *bit_width, unsigned *comp_meth, proto_item **comp_meth_ti)
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
    *comp_meth_ti = proto_tree_add_item_ret_uint(udcomphdr_tree, hf_oran_udCompHdrMeth, tvb, offset, 1, ENC_NA, &ud_comp_meth);
    if (comp_meth) {
        *comp_meth = ud_comp_meth;
    }

    /* Summary */
    if (!ignore) {
        proto_item_append_text(udcomphdr_ti, " (IqWidth=%u, udCompMeth=%s)",
                               *bit_width, rval_to_str_const(ud_comp_meth, ud_comp_header_meth, "Unknown"));
    }
    else {
        proto_item_append_text(udcomphdr_ti, " (ignored)");
        if (hdr_iq_width || ud_comp_meth) {
            expert_add_info_format(pinfo, udcomphdr_ti, &ei_oran_udpcomphdr_should_be_zero,
                                   "udCompHdr in C-Plane for DL should be 0 - found 0x%02x",
                                   tvb_get_uint8(tvb, offset));
        }

    }
    return offset+1;
}

/* Dissect udCompParam (user data compression parameter, 8.3.3.15) */
/* bit_width and comp_meth are out params */
static int dissect_udcompparam(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset,
                               unsigned comp_meth,
                               uint32_t *exponent, uint16_t *sReSMask,
                               bool for_sinr)
{
    if (for_sinr && (comp_meth != COMP_BLOCK_FP)) {
        /* sinrCompParam only present when bfp is used */
        return offset;
    }

    if (comp_meth == COMP_NONE ||
        comp_meth == COMP_MODULATION ||
        comp_meth == MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS) {

        /* Not even creating a subtree for udCompMeth 0, 4, 8 */
        return offset;
    }

    /* Subtree */
    unsigned start_offset = offset;
    proto_item *udcompparam_ti = proto_tree_add_string_format(tree, hf_oran_udCompParam,
                                                         tvb, offset, 1, "",
                                                         (for_sinr) ? "sinrCompParam" : "udCompParam");
    proto_tree *udcompparam_tree = proto_item_add_subtree(udcompparam_ti, ett_oran_udcompparam);

    /* Show comp_meth as a generated field */
    proto_item *meth_ti = proto_tree_add_uint(udcompparam_tree, hf_oran_udCompHdrMeth_pref, tvb, 0, 0, comp_meth);
    proto_item_set_generated(meth_ti);

    uint32_t param_exponent;
    uint64_t param_sresmask;

    static int * const  sres_mask_flags[] = {
        &hf_oran_sReSMask_re12,
        &hf_oran_sReSMask_re11,
        &hf_oran_sReSMask_re10,
        &hf_oran_sReSMask_re9,
        &hf_oran_sReSMask_re8,
        &hf_oran_sReSMask_re7,
        &hf_oran_sReSMask_re6,
        &hf_oran_sReSMask_re5,
        &hf_oran_sReSMask_re4,
        &hf_oran_sReSMask_re3,
        &hf_oran_sReSMask_re2,
        &hf_oran_sReSMask_re1,
        NULL
    };

    switch (comp_meth) {
        case COMP_BLOCK_FP:                    /* 1 */
        case BFP_AND_SELECTIVE_RE_WITH_MASKS:  /* 7 */
            /* reserved (4 bits) */
            proto_tree_add_item(udcompparam_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
            /* exponent (4 bits) */
            proto_tree_add_item_ret_uint(udcompparam_tree, hf_oran_exponent,
                                         tvb, offset, 1, ENC_BIG_ENDIAN, &param_exponent);
            *exponent = param_exponent;
            proto_item_append_text(udcompparam_ti, " (Exponent=%u)", param_exponent);
            offset += 1;
            break;

        case COMP_BLOCK_SCALE:                 /* 2 */
            /* Separate into integer and fractional bits? */
            proto_tree_add_item(udcompparam_tree, hf_oran_blockScaler,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;

        case COMP_U_LAW:                      /* 3 */
            /* compBitWidth, compShift */
            proto_tree_add_item(udcompparam_tree, hf_oran_compBitWidth,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(udcompparam_tree, hf_oran_compShift,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;

        case BFP_AND_SELECTIVE_RE:            /* 5 */
        {
            /* sReSMask (exponent in middle!) */
            proto_item *sresmask_ti;
            sresmask_ti = proto_tree_add_bitmask_ret_uint64(udcompparam_tree, tvb, offset,
                                                            hf_oran_sReSMask,
                                                            ett_oran_sresmask,
                                                            sres_mask_flags,
                                                            ENC_NA,
                                                            &param_sresmask);

            /* Get rid of exponent-shaped gap */
            param_sresmask = ((param_sresmask >> 4) & 0x0f00) | (param_sresmask & 0xff);
            unsigned res = 0;
            for (unsigned n=0; n < 12; n++) {
                if ((param_sresmask >> n) & 0x1) {
                    res++;
                }
            }
            proto_item_append_text(sresmask_ti, "   (%2u REs)", res);

            /* exponent */
            proto_tree_add_item_ret_uint(udcompparam_tree, hf_oran_exponent,
                                         tvb, offset, 1, ENC_BIG_ENDIAN, &param_exponent);
            *sReSMask = (uint16_t)param_sresmask;
            *exponent = param_exponent;

            proto_item_append_text(udcompparam_ti, " (exponent=%u, %u REs)", *exponent, res);
            offset += 2;
            break;
        }

        case MOD_COMPR_AND_SELECTIVE_RE:      /* 6 */
        {
            /* sReSMask (exponent in middle!) */
            proto_item *sresmask_ti;

            sresmask_ti = proto_tree_add_bitmask_ret_uint64(udcompparam_tree, tvb, offset,
                                                            hf_oran_sReSMask,
                                                            ett_oran_sresmask,
                                                            sres_mask_flags,
                                                            ENC_NA,
                                                            &param_sresmask);

            /* Get rid of reserved-shaped gap */
            param_sresmask = ((param_sresmask >> 4) & 0x0f00) | (param_sresmask & 0xff);
            unsigned res = 0;
            for (unsigned n=0; n < 12; n++) {
                if ((param_sresmask >> n) & 0x1) {
                    res++;
                }
            }
            proto_item_append_text(sresmask_ti, "   (%u REs)", res);

            /* reserved (4 bits) */
            proto_tree_add_item(udcompparam_tree, hf_oran_reserved_last_4bits,
                                         tvb, offset, 1, ENC_BIG_ENDIAN);
            *sReSMask = (uint16_t)param_sresmask;

            proto_item_append_text(udcompparam_ti, " (%u REs)", res);
            offset += 2;
            break;
        }

        default:
            /* reserved (set to all zeros), but how many bytes?? */
            break;
    }

    proto_item_set_len(udcompparam_ti, offset-start_offset);
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

static void dissect_payload_version(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, unsigned offset)
{
    unsigned version;
    proto_item *ti = proto_tree_add_item_ret_uint(tree, hf_oran_payload_version, tvb, offset, 1, ENC_NA, &version);
    if (version != 1) {
        expert_add_info_format(pinfo, ti, &ei_oran_version_unsupported,
                               "PayloadVersion %u not supported by dissector (only 1 is known)",
                               version);
        /* TODO: should throw an exception? */
    }
}

static void show_link_to_acknack_request(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                                         ack_nack_request_t *request)
{
    /* Request frame */
    proto_item *ti = proto_tree_add_uint(tree, hf_oran_acknack_request_frame,
                                         tvb, 0, 0, request->request_frame_number);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Work out gap between frames (in ms) */
    int seconds_between_packets = (int)
          (pinfo->abs_ts.secs - request->request_frame_time.secs);
    int nseconds_between_packets =
          pinfo->abs_ts.nsecs - request->request_frame_time.nsecs;

    int total_gap = (seconds_between_packets*1000) +
                     ((nseconds_between_packets+500000) / 1000000);

    ti = proto_tree_add_uint(tree, hf_oran_acknack_request_time,
                             tvb, 0, 0, total_gap);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Type of request */
    ti = proto_tree_add_uint(tree, hf_oran_acknack_request_type,
                             tvb, 0, 0, request->requestType);
    PROTO_ITEM_SET_GENERATED(ti);
}

static void show_link_to_acknack_response(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                                          ack_nack_request_t *response)
{
    if (response->response_frame_number == 0) {
        /* Requests may not get a response, and can't always tell when  to expect one */
        return;
    }

    /* Response frame */
    proto_item *ti = proto_tree_add_uint(tree, hf_oran_acknack_response_frame,
                                         tvb, 0, 0, response->response_frame_number);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Work out gap between frames (in ms) */
    int seconds_between_packets = (int)
          (response->response_frame_time.secs - pinfo->abs_ts.secs);
    int nseconds_between_packets =
          response->response_frame_time.nsecs - pinfo->abs_ts.nsecs;

    int total_gap = (seconds_between_packets*1000) +
                     ((nseconds_between_packets+500000) / 1000000);

    ti = proto_tree_add_uint(tree, hf_oran_acknack_response_time,
                             tvb, 0, 0, total_gap);
    PROTO_ITEM_SET_GENERATED(ti);
}



/* Control plane dissector (section 7). */
static int dissect_oran_c(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, oran_tap_info *tap_info, void *data _U_)
{
    /* Hidden filter for plane */
    proto_item *plane_ti = proto_tree_add_item(tree, hf_oran_cplane, tvb, 0, 0, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(plane_ti);

    /* Set up structures needed to add the protocol subtree and manage it */
    unsigned offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "O-RAN-FH-C");
    col_set_str(pinfo->cinfo, COL_INFO, "C-Plane");

    tap_info->userplane = false;

    /* Create display subtree for the protocol */
    proto_item *protocol_item = proto_tree_add_item(tree, proto_oran, tvb, 0, -1, ENC_NA);
    proto_item_append_text(protocol_item, "-C");
    proto_tree *oran_tree = proto_item_add_subtree(protocol_item, ett_oran);

    /* ecpriRtcid (eAxC ID) */
    uint16_t eAxC;
    addPcOrRtcid(tvb, oran_tree, &offset, hf_oran_ecpri_rtcid, &eAxC);
    tap_info->eaxc = eAxC;

    /* Look up any existing conversation state for eAxC+plane */
    uint32_t key = make_flow_key(pinfo, eAxC, ORAN_C_PLANE, false);
    flow_state_t* state = (flow_state_t*)wmem_tree_lookup32(flow_states_table, key);

    /* Message identifier */
    uint8_t seq_id;
    proto_item *seq_id_ti;
    offset = addSeqid(tvb, oran_tree, offset, ORAN_C_PLANE, &seq_id, &seq_id_ti, pinfo);

    /* Section common subtree */
    int section_tree_offset = offset;
    proto_item *sectionHeading = proto_tree_add_string_format(oran_tree, hf_oran_c_section_common,
                                                              tvb, offset, 0, "", "C-Plane Section Type ");
    proto_tree *section_tree = proto_item_add_subtree(sectionHeading, ett_oran_c_section_common);

    /* Peek ahead at the section type */
    uint32_t sectionType = 0;
    sectionType = tvb_get_uint8(tvb, offset+5);

    uint32_t scs = 0;
    proto_item *scs_ti = NULL;

    /* dataDirection */
    uint32_t direction = 0;
    proto_item *datadir_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_data_direction, tvb, offset, 1, ENC_NA, &direction);
    tap_info->uplink = (direction==0);

    /* Update/report status of conversation */
    if (!PINFO_FD_VISITED(pinfo)) {

        if (state == NULL) {
            /* Allocate new state */
            state = wmem_new0(wmem_file_scope(), flow_state_t);
            state->ack_nack_requests = wmem_tree_new(wmem_epan_scope());
            wmem_tree_insert32(flow_states_table, key, state);
        }

        /* Check sequence analysis status */
        if (state->last_frame_seen[direction] && (seq_id != state->next_expected_sequence_number[direction])) {
            /* Store this result */
            flow_result_t *result = wmem_new0(wmem_file_scope(), flow_result_t);
            result->unexpected_seq_number = true;
            result->expected_sequence_number = state->next_expected_sequence_number[direction];
            result->previous_frame = state->last_frame[direction];
            wmem_tree_insert32(flow_results_table, pinfo->num, result);
        }
        /* Update conversation info */
        state->last_frame[direction] = pinfo->num;
        state->last_frame_seen[direction] = true;
        state->next_expected_sequence_number[direction] = (seq_id+1) % 256;
    }

    /* Show any issues associated with this frame number */
    flow_result_t *result = wmem_tree_lookup32(flow_results_table, pinfo->num);
    if (result!=NULL && result->unexpected_seq_number) {
        expert_add_info_format(pinfo, seq_id_ti,
                               (direction == DIR_UPLINK) ?
                                   &ei_oran_cplane_unexpected_sequence_number_ul :
                                   &ei_oran_cplane_unexpected_sequence_number_dl,
                               "Sequence number %u expected, but got %u",
                               result->expected_sequence_number, seq_id);

        /* Update tap info */
        uint32_t missing_sns = (256 + seq_id - result->expected_sequence_number) % 256;
        /* Don't get confused by being slightly out of order.. */
        if (missing_sns < 128) {
            tap_info->missing_sns = missing_sns;
        }
        else {
            tap_info->missing_sns = 0;
        }

        /* TODO: could add previous/next frames (in seqId tree?) ? */
    }

    /* payloadVersion */
    dissect_payload_version(section_tree, tvb, pinfo, offset);

    /* filterIndex */
    if (sectionType == SEC_C_SLOT_CONTROL || sectionType == SEC_C_ACK_NACK_FEEDBACK) {
        /* scs (for ST4 and ST8) */
        scs_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_frameStructure_subcarrier_spacing, tvb, offset, 1, ENC_NA, &scs);
    }
    else if (sectionType == SEC_C_RRM_MEAS_REPORTS || sectionType == SEC_C_REQUEST_RRM_MEAS) {
        /* reserved (4 bits) */
        proto_tree_add_item(section_tree, hf_oran_reserved_last_4bits, tvb, offset, 1, ENC_NA);
    }
    else if (sectionType != SEC_C_LAA) {
        /* filterIndex (most common case) */
        proto_tree_add_item(section_tree, hf_oran_filter_index, tvb, offset, 1, ENC_NA);
    }
    offset += 1;

    unsigned ref_a_offset = offset;
    /* frameId */
    uint32_t frameId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_frame_id, tvb, offset, 1, ENC_NA, &frameId);
    tap_info->frame = frameId;
    offset += 1;

    /* subframeId */
    uint32_t subframeId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_subframe_id, tvb, offset, 1, ENC_NA, &subframeId);
    /* slotId */
    uint32_t slotId = 0;
    proto_tree_add_item_ret_uint(section_tree, hf_oran_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN, &slotId);
    tap_info->slot = slotId;
    offset++;

    /* startSymbolId */
    uint32_t startSymbolId = 0;
    proto_item *ssid_ti = NULL;
    if ((sectionType == SEC_C_ACK_NACK_FEEDBACK) ||  /* Section Type 8 */
        (sectionType == SEC_C_SINR_REPORTING)) {     /* Section Type 9 */
        /* symbolId */
        proto_tree_add_item_ret_uint(section_tree, hf_oran_symbolId, tvb, offset, 1, ENC_NA, &startSymbolId);
    }
    else if (sectionType != SEC_C_LAA) {
         /* startSymbolId is in most section types */
        ssid_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_start_symbol_id, tvb, offset, 1, ENC_NA, &startSymbolId);
        if (startSymbolId && (sectionType == SEC_C_RRM_MEAS_REPORTS)) {      /* Section Type 10 */
            proto_item_append_text(ssid_ti, " (should be 0 for ST10!)");
            expert_add_info_format(pinfo, ssid_ti, &ei_oran_st10_startsymbolid_not_0,
                                   "startSymbolId should be 0 for ST10 - found %u", startSymbolId);
        }
    }
    else {
        /* reserved (6 bits) */
        proto_tree_add_item(section_tree, hf_oran_reserved_last_6bits, tvb, offset, 1, ENC_NA);
    }
    offset++;

    char id[16];
    snprintf(id, 16, "%d-%d-%d-%d", frameId, subframeId, slotId, startSymbolId);
    proto_item *pi = proto_tree_add_string(section_tree, hf_oran_refa, tvb, ref_a_offset, 3, id);
    proto_item_set_generated(pi);

    uint32_t cmd_scope = 0;
    bool st8_ready = false;

    /* numberOfSections (or whatever section has instead) */
    uint32_t nSections = 0;
    if (sectionType == SEC_C_SLOT_CONTROL) {          /* Section Type 4 */
        /* Slot Control has these fields instead */
        /* reserved (4 bits) */
        proto_tree_add_item(section_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
        /* cmdScope (4 bits) */
        proto_tree_add_item_ret_uint(section_tree, hf_oran_cmd_scope, tvb, offset, 1, ENC_NA, &cmd_scope);
    }
    else if (sectionType == SEC_C_ACK_NACK_FEEDBACK) {    /* Section Type 8 */
        /* reserved (7 bits) */
        proto_tree_add_item(section_tree, hf_oran_reserved_7bits, tvb, offset, 1, ENC_NA);
        /* ready (1 bit) */
        /* TODO: when set, ready in slotId+1.. */
        proto_tree_add_item_ret_boolean(section_tree, hf_oran_ready, tvb, offset, 1, ENC_NA, &st8_ready);
        if (!st8_ready) {
            /* SCS value is ignored, and may be set to any value by O-RU */
            proto_item_append_text(scs_ti, " (ignored)");
        }
    }
    else if (sectionType != SEC_C_LAA) {
        /* numberOfSections */
        proto_tree_add_item_ret_uint(section_tree, hf_oran_numberOfSections, tvb, offset, 1, ENC_NA, &nSections);
    }
    else {
        proto_tree_add_item(section_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_NA);
    }
    offset++;

    /* sectionType */
    proto_tree_add_item_ret_uint(section_tree, hf_oran_sectionType, tvb, offset, 1, ENC_NA, &sectionType);
    offset += 1;

    /* Check that dataDirection is consistent with section type */
    if (sectionType == SEC_C_SINR_REPORTING && direction != 0) {   /* Section Type 9 */
        expert_add_info(pinfo, datadir_ti, &ei_oran_st9_not_ul);
    }
    if (sectionType == SEC_C_RRM_MEAS_REPORTS && direction != 0) {  /* Section Type 10 */
        expert_add_info(pinfo, datadir_ti, &ei_oran_st10_not_ul);
    }

    /* Note this section type in stats */
    if (sectionType < SEC_C_MAX_INDEX) {
        tap_info->section_types[sectionType] = true;
    }

    /* Section-type-specific fields following common header (white entries in Section Type diagrams) */
    unsigned bit_width = 0;
    int      comp_meth = 0;
    proto_item *comp_meth_ti;
    unsigned ci_comp_method = 0;
    uint8_t  ci_comp_opt = 0;

    uint32_t num_ues = 0;
    uint32_t number_of_acks = 0, number_of_nacks = 0;

    uint32_t num_sinr_per_prb = 0;

    switch (sectionType) {
        case SEC_C_UNUSED_RB:   /* Section Type 0 */
            /* timeOffset */
            proto_tree_add_item(section_tree, hf_oran_timeOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* frameStructure */
            offset = dissect_frame_structure(section_tree, tvb, offset,
                                             subframeId, slotId);

            /* cpLength */
            proto_tree_add_item(section_tree, hf_oran_cpLength, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* reserved */
            proto_tree_add_item(section_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case SEC_C_NORMAL:       /* Section Type 1 */
        case SEC_C_UE_SCHED:     /* Section Type 5 */
            /* udCompHdr */
            offset = dissect_udcomphdr(tvb, pinfo, section_tree, offset,
                                       (direction==1), /* ignore for DL */
                                       &bit_width, &comp_meth, &comp_meth_ti);
            /* reserved */
            proto_tree_add_item(section_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        case SEC_C_SLOT_CONTROL: /* Section Type 4 */
            break;

        case SEC_C_PRACH:        /* Section Type 3 */
            /* timeOffset */
            proto_tree_add_item(section_tree, hf_oran_timeOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* frameStructure */
            offset = dissect_frame_structure(section_tree, tvb, offset,
                                             subframeId, slotId);
            /* cpLength */
            proto_tree_add_item(section_tree, hf_oran_cpLength, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* udCompHdr */
            offset = dissect_udcomphdr(tvb, pinfo, section_tree, offset,
                                       (direction==1), /* ignore for DL */
                                       &bit_width, &comp_meth, &comp_meth_ti);
            break;

        case SEC_C_CH_INFO:     /* Section Type 6 */
            /* numberOfUEs */
            proto_tree_add_item_ret_uint(section_tree, hf_oran_numberOfUEs, tvb, offset, 1, ENC_NA, &num_ues);
            offset += 1;
            /* ciCompHdr (was reserved) */
            offset = dissect_cicomphdr(tvb, pinfo, section_tree, offset, &bit_width, &ci_comp_method, &ci_comp_opt);

            /* Number of sections may not be filled in (at all, or correctly), so set to the number of UEs.
               The data entries are per-UE... they don't have a sectionID, but they could have section extensions... */
            if (nSections == 0 || num_ues > nSections) {
                nSections = num_ues;
            }
            break;

        case SEC_C_RSVD2:
            break;

        case SEC_C_LAA:                   /* Section Type 7 */
            proto_tree_add_item(section_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;

        case SEC_C_ACK_NACK_FEEDBACK:     /* Section Type 8 */
            /* numberOfAcks (1 byte) */
            proto_tree_add_item_ret_uint(section_tree, hf_oran_number_of_acks, tvb, offset, 1, ENC_BIG_ENDIAN, &number_of_acks);
            offset += 1;
            /* numberOfNacks (1 byte) */
            proto_tree_add_item_ret_uint(section_tree, hf_oran_number_of_nacks, tvb, offset, 1, ENC_BIG_ENDIAN, &number_of_nacks);
            offset += 1;

            /* Show ACKs and NACKs. For both, try to link back to request. */
            for (unsigned int n=1; n <= number_of_acks; n++) {
                uint32_t ackid;
                proto_item *ack_ti;
                ack_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_ackid, tvb, offset, 2, ENC_BIG_ENDIAN, &ackid);
                offset += 2;

                /* Look up request table in state (which really should be set by now, but test anyway). */
                if (state && state->ack_nack_requests) {
                    ack_nack_request_t *request = wmem_tree_lookup32(state->ack_nack_requests, ackid);
                    if (request != NULL) {
                        /* On first pass, update with this response */
                        if (!PINFO_FD_VISITED(pinfo)) {
                            request->response_frame_number = pinfo->num;
                            request->response_frame_time = pinfo->abs_ts;
                        }

                        /* Show request details */
                        show_link_to_acknack_request(section_tree, tvb, pinfo, request);
                    }
                    else {
                        /* Request not found */
                        expert_add_info_format(pinfo, ack_ti, &ei_oran_acknack_no_request,
                                               "Response for ackId=%u received, but no request found",
                                               ackid);
                    }
                }
            }
            for (unsigned int m=1; m <= number_of_nacks; m++) {
                uint32_t nackid;
                proto_item *nack_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_nackid, tvb, offset, 2, ENC_BIG_ENDIAN, &nackid);
                offset += 2;

                expert_add_info_format(pinfo, nack_ti, &ei_oran_st8_nackid,
                                       "Received Nack for ackNackId=%u",
                                       nackid);

                /* Look up request table in state. */
                if (state && state->ack_nack_requests) {
                    ack_nack_request_t *request = wmem_tree_lookup32(state->ack_nack_requests, nackid);
                    if (request) {
                        /* On first pass, update with this response */
                        if (!PINFO_FD_VISITED(pinfo)) {
                            request->response_frame_number = pinfo->num;
                            request->response_frame_time = pinfo->abs_ts;
                        }

                        /* Show request details */
                        show_link_to_acknack_request(section_tree, tvb, pinfo, request);
                    }
                    else {
                        /* Request not found */
                        expert_add_info_format(pinfo, nack_ti, &ei_oran_acknack_no_request,
                                               "Response for nackId=%u received, but no request found",
                                               nackid);
                    }
                }
            }
            break;

        case SEC_C_SINR_REPORTING:     /* Section Type 9 */
        {
            /* numSinrPerPrb (3 bits) */
            proto_item *nspp_ti;
            nspp_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_num_sinr_per_prb, tvb, offset, 1, ENC_BIG_ENDIAN, &num_sinr_per_prb);
            switch (num_sinr_per_prb) {
                case 0:
                    num_sinr_per_prb = 1; break;
                case 1:
                    num_sinr_per_prb = 2; break;
                case 2:
                    num_sinr_per_prb = 3; break;
                case 3:
                    num_sinr_per_prb = 4; break;
                case 4:
                    num_sinr_per_prb = 6; break;
                case 5:
                    num_sinr_per_prb = 12; break;

                default:
                    proto_item_append_text(nspp_ti, " (invalid)");
                    num_sinr_per_prb = 1;
                    expert_add_info_format(pinfo, nspp_ti, &ei_oran_num_sinr_per_prb_unknown,
                                           "Invalid numSinrPerPrb value (%u)",
                                           num_sinr_per_prb);
            }

            /* reserved (13 bits) */
            proto_tree_add_item(section_tree, hf_oran_reserved_last_5bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(section_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        }

        case SEC_C_RRM_MEAS_REPORTS:    /* Section Type 10 */
        case SEC_C_REQUEST_RRM_MEAS:    /* Section Type 11 */
            /* reserved (16 bits) */
            proto_tree_add_item(section_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
    };

    /* Update udCompHdr details in state for UL U-Plane */
    if (state && direction==0) {
        switch (sectionType) {
            case SEC_C_NORMAL:    /* Section Type 1 */
            case SEC_C_PRACH:     /* Section Type 3 */
            case SEC_C_UE_SCHED:  /* Section Type 5 */
                state->ul_ud_comp_hdr_set = true;
                state->ul_ud_comp_hdr_bit_width = bit_width;
                state->ul_ud_comp_hdr_compression = comp_meth;
                state->ul_ud_comp_hdr_frame = pinfo->num;
                break;
            default:
                break;
        }
    }


    proto_item_append_text(sectionHeading, "%d, %s, frameId: %d, subframeId: %d, slotId: %d, startSymbolId: %d",
                           sectionType, val_to_str_const(direction, data_direction_vals, "Unknown"),
                           frameId, subframeId, slotId, startSymbolId);
    if (nSections) {
        proto_item_append_text(sectionHeading, ", numberOfSections=%u", nSections);
    }

    write_pdu_label_and_info(protocol_item, NULL, pinfo, ", Type: %2d %s", sectionType,
                             rval_to_str_const(sectionType, section_types_short, "Unknown"));

    /* Set actual length of C-Plane section header */
    proto_item_set_len(section_tree, offset - section_tree_offset);

    if (sectionType == SEC_C_ACK_NACK_FEEDBACK) {
        write_pdu_label_and_info(oran_tree, section_tree, pinfo,
                                 (st8_ready) ? " (Ready)" : " (ACK)");
    }


    /* Section type 4 doesn't have normal sections, so deal with here before normal sections */
    if (sectionType == SEC_C_SLOT_CONTROL) {
        /* numberOfST4Cmds */
        uint32_t no_st4_cmds, st4_cmd_len, num_slots, ack_nack_req_id, st4_cmd_type;
        proto_item *no_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_number_of_st4_cmds,
                                                         tvb, offset, 1, ENC_NA, &no_st4_cmds);
        if (no_st4_cmds == 0) {
            expert_add_info_format(pinfo, no_ti, &ei_oran_st4_no_cmds,
                                   "Not valid for ST4 to carry no commands");
        }
        offset += 1;

        /* reserved (1 byte) */
        proto_tree_add_item(section_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Loop over commands.  Each has 8-byte common header, followed by cmd-specific payload */
        proto_item *len_ti;
        for (uint32_t n=0; n < no_st4_cmds; n++) {
            /* Table 7.4.6-2: Section Type 4 Command common header format */
            proto_item *hdr_ti = proto_tree_add_string_format(section_tree, hf_oran_st4_cmd_header,
                                                              tvb, offset, 8, "",
                                                              "Type 4 Command common header");
            proto_tree *hdr_tree = proto_item_add_subtree(hdr_ti, ett_oran_st4_cmd_header);

            /* st4CmdType */
            proto_tree_add_item_ret_uint(hdr_tree, hf_oran_st4_cmd_type, tvb, offset, 1, ENC_NA, &st4_cmd_type);
            offset += 1;

            /* st4CmdLen */
            len_ti = proto_tree_add_item_ret_uint(hdr_tree, hf_oran_st4_cmd_len, tvb, offset, 2, ENC_BIG_ENDIAN, &st4_cmd_len);
            if (st4_cmd_len == 0) {
                /* Meaning of 0 not yet defined (v15.00) */
                proto_item_append_text(len_ti, " (reserved)");
                expert_add_info(pinfo, len_ti, &ei_oran_st4_zero_len_cmd);
            }
            else {
                proto_item_append_text(len_ti, " (%u bytes)", st4_cmd_len*4);
            }
            offset += 2;

            /* numSlots */
            proto_item *slots_ti = proto_tree_add_item_ret_uint(hdr_tree, hf_oran_st4_cmd_num_slots, tvb, offset, 1, ENC_NA, &num_slots);
            if (num_slots == 0) {
                proto_item_append_text(slots_ti, " (until changed)");
            }
            offset += 1;

            /* ackNackReqId */
            proto_item *ack_nack_req_id_ti;
            ack_nack_req_id_ti = proto_tree_add_item_ret_uint(hdr_tree, hf_oran_st4_cmd_ack_nack_req_id, tvb, offset, 2, ENC_BIG_ENDIAN, &ack_nack_req_id);
            offset += 2;
            if (ack_nack_req_id == 0) {
                proto_item_append_text(ack_nack_req_id_ti, " (no Section type 8 response expected)");
            }

            /* reserved (16 bits) */
            proto_tree_add_item(hdr_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Set common header summary */
            proto_item_append_text(hdr_ti, " (cmd=%s, len=%u, slots=%u, ackNackReqId=%u)",
                                   rval_to_str_const(st4_cmd_type, st4_cmd_type_vals, "Unknown"),
                                   st4_cmd_len, num_slots, ack_nack_req_id);

            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                            rval_to_str_const(st4_cmd_type, st4_cmd_type_vals, "Unknown"));


            /* Subtree for this command body */
            proto_item *command_ti = proto_tree_add_string_format(section_tree, hf_oran_st4_cmd,
                                                              tvb, offset, 0, "",
                                                              "Type 4 Command (%s)", rval_to_str_const(st4_cmd_type, st4_cmd_type_vals, "Unknown"));
            proto_tree *command_tree = proto_item_add_subtree(command_ti, ett_oran_st4_cmd);

            unsigned command_start_offset = offset;

            /* Check fields compatible with chosen command. */
            if (st4_cmd_type==1) {
                if (num_slots != 0) {
                    /* "the value of numSlots should be set to zero for this command type" */
                    expert_add_info_format(pinfo, slots_ti, &ei_oran_numslots_not_zero,
                                           "numSlots should be zero for ST4 command 1 - found %u",
                                           num_slots);
                }
            }

            if (st4_cmd_type==3 || st4_cmd_type==4) {
                if (startSymbolId != 0) {
                    /* "expected reception window for the commands is the symbol zero reception window" */
                    expert_add_info_format(pinfo, ssid_ti, &ei_oran_start_symbol_id_not_zero,
                                           "startSymbolId should be zero for ST4 commands 3&4 - found %u",
                                           startSymbolId);
                }
            }

            /* Add format for this command */
            switch (st4_cmd_type) {
                case 1:  /* TIME_DOMAIN_BEAM_CONFIG */
                {
                    bool disable_tdbfns;
                    uint32_t bfwcomphdr_iq_width, bfwcomphdr_comp_meth;

                    /* Hidden filter for bf */
                    proto_item *bf_ti = proto_tree_add_item(command_tree, hf_oran_bf, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(bf_ti);

                    /* reserved (2 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* symbolMask (14 bits) */
                    uint32_t symbol_mask;
                    proto_item *symbol_mask_ti;
                    offset = dissect_symbolmask(tvb, command_tree, offset, &symbol_mask, &symbol_mask_ti);
                    /* Symbol bits before 'startSymbolId' in Section Type 4 common header should be set to 0 by O-DU and shall be ignored by O-RU */
                    /* lsb is symbol 0 */
                    for (unsigned s=0; s < 14; s++) {
                        if ((startSymbolId & (1 << s)) && (startSymbolId > s)) {
                            proto_item_append_text(symbol_mask_ti, " (startSymbolId is %u, so some lower symbol bits ignored!)", startSymbolId);
                            expert_add_info(pinfo, symbol_mask_ti, &ei_oran_start_symbol_id_bits_ignored);
                            break;
                        }
                    }

                    /* disableTDBFNs (1 bit) */
                    proto_tree_add_item_ret_boolean(command_tree, hf_oran_disable_tdbfns, tvb, offset, 1, ENC_BIG_ENDIAN, &disable_tdbfns);

                    /* tdBeamNum (15 bits) */
                    proto_tree_add_item(command_tree, hf_oran_td_beam_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* bfwCompHdr (2 subheaders - bfwIqWidth and bfwCompMeth)*/
                    offset = dissect_bfwCompHdr(tvb, command_tree, offset,
                                                &bfwcomphdr_iq_width, &bfwcomphdr_comp_meth, &comp_meth_ti);
                    /* reserved (3 bytes) */
                    proto_tree_add_bits_item(command_tree, hf_oran_reserved, tvb, offset*8, 24, ENC_BIG_ENDIAN);
                    offset += 3;

                    if (disable_tdbfns) {
                        /* No beamnum information to show so get out. */
                        break;
                    }

                    /* Read beam entries until reach end of command length */
                    while ((offset - command_start_offset) < (st4_cmd_len * 4)) {

                        /* disableTDBFWs (1 bit) */
                        bool disable_tdbfws;
                        proto_tree_add_item_ret_boolean(command_tree, hf_oran_disable_tdbfws, tvb, offset, 1, ENC_BIG_ENDIAN, &disable_tdbfws);

                        /* tdBeamNum (15 bits) */
                        proto_tree_add_item(command_tree, hf_oran_td_beam_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;

                        /* Showing BFWs? */
                        if (!disable_tdbfws) {

                            /* bfwCompParam */
                            unsigned exponent = 0;
                            bool     supported = false;
                            unsigned num_trx_entries;
                            uint16_t *trx_entries;
                            offset = dissect_bfwCompParam(tvb, command_tree, pinfo, offset, comp_meth_ti,
                                                          &bfwcomphdr_comp_meth, &exponent, &supported,
                                                          &num_trx_entries, &trx_entries);

                            /* Antenna count from preference */
                            unsigned num_trx = pref_num_bf_antennas;
                            int bit_offset = offset*8;

                            for (unsigned trx=0; trx < num_trx; trx++) {
                                /* Create antenna subtree */
                                int bfw_offset = bit_offset / 8;
                                proto_item *bfw_ti = proto_tree_add_string_format(command_tree, hf_oran_bfw,
                                                                                  tvb, bfw_offset, 0, "", "TRX %3u: (", trx);
                                proto_tree *bfw_tree = proto_item_add_subtree(bfw_ti, ett_oran_bfw);

                                /* I value */
                                /* Get bits, and convert to float. */
                                uint32_t bits = tvb_get_bits32(tvb, bit_offset, bfwcomphdr_iq_width, ENC_BIG_ENDIAN);
                                float value = decompress_value(bits, bfwcomphdr_comp_meth, bfwcomphdr_iq_width, exponent, NULL /* no ModCompr*/, 0 /* RE */);
                                /* Add to tree. */
                                proto_tree_add_float(bfw_tree, hf_oran_bfw_i, tvb, bit_offset/8,
                                                     (bfwcomphdr_iq_width+7)/8, value);
                                bit_offset += bfwcomphdr_iq_width;
                                proto_item_append_text(bfw_ti, "I=%f ", value);

                                /* Leave a gap between I and Q values */
                                proto_item_append_text(bfw_ti, "  ");

                                /* Q value */
                                /* Get bits, and convert to float. */
                                bits = tvb_get_bits32(tvb, bit_offset, bfwcomphdr_iq_width, ENC_BIG_ENDIAN);
                                value = decompress_value(bits, bfwcomphdr_comp_meth, bfwcomphdr_iq_width, exponent, NULL /* no ModCompr*/, 0 /* RE */);
                                /* Add to tree. */
                                proto_tree_add_float(bfw_tree, hf_oran_bfw_q, tvb, bit_offset/8,
                                                     (bfwcomphdr_iq_width+7)/8, value);
                                bit_offset += bfwcomphdr_iq_width;
                                proto_item_append_text(bfw_ti, "Q=%f", value);

                                proto_item_append_text(bfw_ti, ")");
                                proto_item_set_len(bfw_ti, (bit_offset+7)/8  - bfw_offset);
                            }
                            /* Need to round to next byte */
                            offset = (bit_offset+7)/8;
                        }
                    }
                    break;
                }
                case 2:  /* TDD_CONFIG_PATTERN */
                    /* reserved (2 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* dirPattern (14 bits) */
                    proto_tree_add_item(command_tree, hf_oran_dir_pattern, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* reserved (2 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* guardPattern (14 bits) */
                    proto_tree_add_item(command_tree, hf_oran_guard_pattern, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;

                case 3:  /* TRX_CONTROL */
                {
                    /* Only allowed cmdScope is ARRAY-COMMAND */
                    if (cmd_scope != 0) {
                        expert_add_info(pinfo, command_tree, &ei_oran_trx_control_cmd_scope);
                    }

                    /* reserved (2 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* log2MaskBits (4 bits) */
                    unsigned log2maskbits;
                    proto_tree_add_item_ret_uint(command_tree, hf_oran_log2maskbits, tvb, offset, 1, ENC_BIG_ENDIAN, &log2maskbits);
                    /* sleepMode */
                    uint32_t sleep_mode;
                    proto_tree_add_item_ret_uint(command_tree, hf_oran_sleepmode_trx, tvb, offset, 1, ENC_BIG_ENDIAN, &sleep_mode);
                    offset += 1;

                    /* reserved (4 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* numSlotsExt (20 bits) */
                    uint32_t num_slots_ext;
                    proto_item *num_slots_ext_ti = proto_tree_add_item_ret_uint(command_tree, hf_oran_num_slots_ext, tvb, offset, 3, ENC_BIG_ENDIAN, &num_slots_ext);
                    if (num_slots==0 && num_slots_ext==0) {
                        proto_item_append_text(num_slots_ext_ti, " (undefined sleep period)");
                    }
                    else {
                        /* Time should be rounded up according to SCS */
                        float total = (float)(num_slots + num_slots_ext);
                        /* From table 7.5.2.13-3 */
                        float slot_length_by_scs[16] = { 1000, 500, 250, 125, 62.5, 31.25,
                                                         0, 0, 0, 0, 0, 0,  /* reserved */
                                                         1000, 1000, 1000, 1000 };
                        float slot_length = slot_length_by_scs[scs];
                        /* Only using valid SCS. TODO: is this test ok? */
                        if (slot_length != 0) {
                            /* Round up to next slot */
                            total = ((int)(total / slot_length) + 1) * slot_length;
                            proto_item_append_text(num_slots_ext_ti, " (defined sleep period of %f us)", total);
                        }
                    }
                    offset += 3;

                    /* reserved (2 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);

                    /* symbolMask (14 bits) */
                    uint32_t symbol_mask;
                    proto_item *sm_ti;
                    offset = dissect_symbolmask(tvb, command_tree, offset, &symbol_mask, &sm_ti);
                    if (symbol_mask == 0x0) {
                        proto_item_append_text(sm_ti, " (wake)");
                        col_append_str(pinfo->cinfo, COL_INFO, " (wake)");
                    }
                    else if (symbol_mask == 0x3fff) {
                        proto_item_append_text(sm_ti, " (sleep)");
                        col_append_str(pinfo->cinfo, COL_INFO, " (sleep)");
                    }
                    else {
                        expert_add_info_format(pinfo, sm_ti, &ei_oran_bad_symbolmask,
                                               "For non-zero sleepMode (%u), symbolMask should be 0x0 or 0x3fff - found 0x%05x",
                                               sleep_mode, symbol_mask);
                    }
                    offset += 2;

                    /* antMask (16-2048 bits).  Size is lookup from log2MaskBits enum.. */
                    unsigned antmask_length = 2;
                    if (log2maskbits >= 4) {
                        antmask_length = (1 << log2maskbits) / 8;
                    }
                    proto_item *ant_mask_ti = proto_tree_add_item(command_tree, hf_oran_antMask_trx_control, tvb, offset, antmask_length, ENC_NA);
                    /* show count */
                    unsigned antenna_count = 0;
                    for (unsigned b=0; b < antmask_length; b++) {
                        uint8_t byte = tvb_get_uint8(tvb, offset+b);
                        for (unsigned bit=0; bit < 8; bit++) {
                            if ((1 << bit) & byte) {
                                antenna_count++;
                            }
                        }
                    }
                    proto_item_append_text(ant_mask_ti, " (%u antennas)", antenna_count);
                    offset += antmask_length;

                    /* Pad to next 4-byte boundary */
                    offset = WS_ROUNDUP_4(offset);
                    break;
                }

                case 4:  /* ASM (advanced sleep mode) */
                    /* reserved (2+4=6 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_6bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* sleepMode (2 bits) */
                    uint32_t sleep_mode;
                    proto_tree_add_item_ret_uint(command_tree, hf_oran_sleepmode_asm, tvb, offset, 1, ENC_BIG_ENDIAN, &sleep_mode);
                    offset += 1;

                    /* reserved (4 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* numSlotsExt (20 bits) */
                    proto_tree_add_item(command_tree, hf_oran_num_slots_ext, tvb, offset, 3, ENC_BIG_ENDIAN);
                    offset += 3;

                    /* reserved (2 bits) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_2bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* symbolMask (14 bits) */
                    uint32_t symbol_mask;
                    proto_item *sm_ti;
                    offset = dissect_symbolmask(tvb, command_tree, offset, &symbol_mask, &sm_ti);
                    if (symbol_mask == 0x0) {
                        proto_item_append_text(sm_ti, " (wake)");
                        col_append_str(pinfo->cinfo, COL_INFO, " (wake)");
                    }
                    else if (symbol_mask == 0x3fff) {
                        proto_item_append_text(sm_ti, " (sleep)");
                        col_append_str(pinfo->cinfo, COL_INFO, " (sleep)");
                    }
                    else {
                        expert_add_info_format(pinfo, sm_ti, &ei_oran_bad_symbolmask,
                                               "For non-zero sleepMode (%u), symbolMask should be 0x0 or 0x3fff - found 0x%05x",
                                               sleep_mode, symbol_mask);
                    }
                    offset += 2;

                    /* reserved (2 bytes) */
                    proto_tree_add_item(command_tree, hf_oran_reserved_16bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;

                default:
                    /* Error! */
                    expert_add_info_format(pinfo, len_ti, &ei_oran_st4_unknown_cmd,
                                           "Dissected ST4 command (%u) not recognised",
                                            st4_cmd_type);
                    break;
            }

            /* Check apparent size of padding (0-3 bytes ok) */
            long padding_remaining = command_start_offset + (st4_cmd_len * 4) - offset;
            if (padding_remaining < 0 || padding_remaining > 3) {
                expert_add_info_format(pinfo, len_ti, &ei_oran_st4_wrong_len_cmd,
                                       "Dissected ST4 command does not match signalled st4CmdLen - set to %u (%u bytes) but dissected %u bytes",
                                        st4_cmd_len, st4_cmd_len*4, offset-command_start_offset);
            }

            /* Advance by signalled length (needs to be aligned on 4-byte boundary) */
            offset = command_start_offset + (st4_cmd_len * 4);

            /* Set end of command tree */
            proto_item_set_end(command_ti, tvb, offset);

            if (ack_nack_req_id != 0 && state && state->ack_nack_requests) {
                if (!PINFO_FD_VISITED(pinfo)) {
                    /* Add this request into conversation state on first pass */
                    ack_nack_request_t *request_details = wmem_new0(wmem_file_scope(), ack_nack_request_t);
                    request_details->request_frame_number = pinfo->num;
                    request_details->request_frame_time = pinfo->abs_ts;
                    request_details->requestType = ST4Cmd1+st4_cmd_type-1;

                    wmem_tree_insert32(state->ack_nack_requests,
                                       ack_nack_req_id,
                                       request_details);
                }
                else {
                    /* On later passes, try to link forward to ST8 response */
                    ack_nack_request_t *response = wmem_tree_lookup32(state->ack_nack_requests,
                                                                      ack_nack_req_id);
                    if (response) {
                        show_link_to_acknack_response(section_tree, tvb, pinfo, response);
                    }
                }
            }
        }
    }
    /* LAA doesn't have sections either.. */
    else if (sectionType == SEC_C_LAA) {   /* Section Type 7 */
        /* 7.2.5 Table 6.4-6 */
        unsigned mcot;
        proto_item *mcot_ti;

        /* laaMsgType */
        uint32_t laa_msg_type;
        proto_item *laa_msg_type_ti;
        laa_msg_type_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_laaMsgType, tvb, offset, 1, ENC_NA, &laa_msg_type);
        /* laaMsgLen */
        uint32_t laa_msg_len;
        proto_item *len_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_laaMsgLen, tvb, offset, 1, ENC_NA, &laa_msg_len);
        proto_item_append_text(len_ti, " (%u bytes)", 4*laa_msg_len);
        if (laa_msg_len == 0) {
            proto_item_append_text(len_ti, " (reserved)");
        }
        offset += 1;

        int payload_offset = offset;

        /* Payload */
        switch (laa_msg_type) {
            case 0:
                /* LBT_PDSCH_REQ */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtOffset (10 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtMode  (2 bits) */
                proto_tree_add_bits_item(section_tree, hf_oran_lbtMode, tvb, offset*8+2, 2, ENC_BIG_ENDIAN);
                /* reserved (1 bit) */
                proto_tree_add_item(section_tree, hf_oran_reserved_bit4, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* lbtDeferFactor (3 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtDeferFactor, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtBackoffCounter (10 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtBackoffCounter, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 1;
                /* MCOT (4 bits) */
                mcot_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_MCOT, tvb, offset, 1, ENC_BIG_ENDIAN, &mcot);
                if (mcot<1 || mcot>10) {
                    proto_item_append_text(mcot_ti, " (should be in range 1-10!)");
                    expert_add_info_format(pinfo, mcot_ti, &ei_oran_mcot_out_of_range,
                                           "MCOT seen with value %u (must be 1-10)", mcot);

                }
                /* reserved (10 bits) */
                proto_tree_add_bits_item(section_tree, hf_oran_reserved, tvb, (offset*8)+6, 10, ENC_BIG_ENDIAN);
                break;
            case 1:
                /* LBT_DRS_REQ */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtOffset (10 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtOffset, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtMode  (2 bits) */
                proto_tree_add_bits_item(section_tree, hf_oran_lbtMode, tvb, offset*8+2, 2, ENC_BIG_ENDIAN);
                /* reserved (28 bits) */
                proto_tree_add_bits_item(section_tree, hf_oran_reserved, tvb, (offset*8)+4, 28, ENC_BIG_ENDIAN);
                break;
            case 2:
                /* LBT_PDSCH_RSP */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtPdschRes (2 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtPdschRes, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* inParSF (1 bit) */
                proto_tree_add_item(section_tree, hf_oran_initialPartialSF, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* sfStatus (1 bit) */
                proto_tree_add_item(section_tree, hf_oran_sfStatus, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* sfnSf (12 bits) */
                proto_tree_add_item(section_tree, hf_oran_sfnSfEnd, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* reserved (24 bits) */
                proto_tree_add_bits_item(section_tree, hf_oran_reserved, tvb, (offset*8), 24, ENC_BIG_ENDIAN);
                break;
            case 3:
                /* LBT_DRS_RSP */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtDrsRes (1 bit) */
                proto_tree_add_item(section_tree, hf_oran_lbtDrsRes, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (7 bits) */
                proto_tree_add_item(section_tree, hf_oran_reserved_last_7bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 4:
                /* LBT_Buffer_Error */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtBufErr (1 bit) */
                proto_tree_add_item(section_tree, hf_oran_lbtBufErr, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (7 bits) */
                proto_tree_add_item(section_tree, hf_oran_reserved_last_7bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 5:
                /* LBT_CWCONFIG_REQ */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtCWConfig_H (8 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtCWConfig_H, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtCWConfig_T (8 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtCWConfig_T, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* lbtMode  (2 bits) */
                proto_tree_add_bits_item(section_tree, hf_oran_lbtMode, tvb, offset*8, 2, ENC_BIG_ENDIAN);
                /* lbtTrafficClass (3 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtTrafficClass, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (19 bits) */
                proto_tree_add_bits_item(section_tree, hf_oran_reserved, tvb, (offset*8)+5, 19, ENC_BIG_ENDIAN);
                break;
            case 6:
                /* LBT_CWCONFIG_RSP */
                /* lbtHandle (16 bits) */
                proto_tree_add_item(section_tree, hf_oran_lbtHandle, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* lbtCWR_Rst (1 bit) */
                proto_tree_add_item(section_tree, hf_oran_lbtCWR_Rst, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* reserved (7 bits) */
                proto_tree_add_item(section_tree, hf_oran_reserved_last_7bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            default:
                /* Unhandled! */
                expert_add_info_format(pinfo, laa_msg_type_ti, &ei_oran_laa_msg_type_unsupported,
                                       "laaMsgType %u not supported by dissector",
                                       laa_msg_type);

                break;
        }
        /* For now just skip indicated length of bytes */
        offset = payload_offset + 4*(laa_msg_len+1);
    }


    /* Dissect each C section */
    for (uint32_t i = 0; i < nSections; ++i) {
        tvbuff_t *section_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);
        offset += dissect_oran_c_section(section_tvb, oran_tree, pinfo, state, sectionType, tap_info,
                                         protocol_item,
                                         subframeId, slotId,
                                         bit_width, ci_comp_method, ci_comp_opt,
                                         num_sinr_per_prb);
    }

    /* Expert error if we are short of tvb by > 3 bytes */
    if (tvb_reported_length_remaining(tvb, offset) > 3) {
        expert_add_info_format(pinfo, protocol_item, &ei_oran_frame_length,
                               "%u bytes remain at end of frame - should be 0-3",
                               tvb_reported_length_remaining(tvb, offset));
    }

    return tvb_captured_length(tvb);
}

static int dissect_oran_u_re(tvbuff_t *tvb, proto_tree *tree,
                             unsigned sample_number, int samples_offset,
                             oran_tap_info *tap_info,
                             unsigned sample_bit_width,
                             int comp_meth,
                             uint32_t exponent,
                             section_mod_compr_config_t *mod_compr_params,
                             uint8_t re)
{
    /* I */
    unsigned i_bits = tvb_get_bits32(tvb, samples_offset, sample_bit_width, ENC_BIG_ENDIAN);
    float i_value = decompress_value(i_bits, comp_meth, sample_bit_width, exponent, mod_compr_params, re);
    unsigned sample_len_in_bytes = ((samples_offset%8)+sample_bit_width+7)/8;
    proto_item *i_ti = proto_tree_add_float(tree, hf_oran_iSample, tvb, samples_offset/8, sample_len_in_bytes, i_value);
    proto_item_set_text(i_ti, "iSample: % 0.7f  0x%04x (RE-%2u in the PRB)", i_value, i_bits, sample_number);
    samples_offset += sample_bit_width;
    /* Q */
    unsigned q_bits = tvb_get_bits32(tvb, samples_offset, sample_bit_width, ENC_BIG_ENDIAN);
    float q_value = decompress_value(q_bits, comp_meth, sample_bit_width, exponent, mod_compr_params, re);
    sample_len_in_bytes = ((samples_offset%8)+sample_bit_width+7)/8;
    proto_item *q_ti = proto_tree_add_float(tree, hf_oran_qSample, tvb, samples_offset/8, sample_len_in_bytes, q_value);
    proto_item_set_text(q_ti, "qSample: % 0.7f  0x%04x (RE-%2u in the PRB)", q_value, q_bits, sample_number);
    samples_offset += sample_bit_width;

    /* Update RE stats */
    tap_info->num_res++;
    /* if (i_value == 0.0 && q_value == 0.0) { */
    /* TODO: is just checking bits from frame good enough - assuming this always corresponds to a zero value? */
    if (i_bits == 0 && q_bits == 0) {
        tap_info->num_res_zero++;
    }
    else {
        tap_info->non_zero_re_in_current_prb = true;
    }
    return samples_offset;
}


static bool udcomplen_appears_present(bool udcomphdr_present, tvbuff_t *tvb, int offset)
{
    if (!udcomplen_heuristic_result_set) {
        /* All sections will start the same way */
        unsigned int section_bytes_before_field = (udcomphdr_present) ? 6 : 4;

        /* Move offset back to the start of the section */
        offset -= section_bytes_before_field;

        do {
            /* This field appears several bytes into the U-plane section */
            uint32_t length_remaining = tvb_reported_length_remaining(tvb, offset);
            /* Are there enough bytes to still read the length field? */
            if (section_bytes_before_field+2 > length_remaining) {
                udcomplen_heuristic_result = false;
                udcomplen_heuristic_result_set = true;
                break;
            }

            /* Read the length field */
            uint16_t udcomplen = tvb_get_ntohs(tvb, offset+section_bytes_before_field);

            /* Is this less than a valid section? Realistic minimal section will be bigger than this..
             * Could take into account numPrbU, etc */
            if (udcomplen < section_bytes_before_field+2) {
                udcomplen_heuristic_result = false;
                udcomplen_heuristic_result_set = true;
                break;
            }

            /* Does this section fit into the frame? */
            if (udcomplen > length_remaining) {
                udcomplen_heuristic_result = false;
                udcomplen_heuristic_result_set = true;
                break;
            }

            /* Move past this section */
            offset += udcomplen;

            /* Are we at the end of the frame? */
            /* TODO: if frame is less than 60 bytes, there may be > 4 bytes, likely zeros.. */
            if (tvb_reported_length_remaining(tvb, offset) < 4) {
                udcomplen_heuristic_result = true;
                udcomplen_heuristic_result_set = true;
            }
        } while (!udcomplen_heuristic_result_set);
    }
    return udcomplen_heuristic_result;
}

static bool at_udcomphdr(tvbuff_t *tvb, int offset)
{
    if (tvb_captured_length_remaining(tvb, offset) < 2) {
        return false;
    }
    uint8_t first_byte = tvb_get_uint8(tvb, offset);
    uint8_t reserved_byte = tvb_get_uint8(tvb, offset+1);

    /* - iq width could be anything, though unlikely to be signalled as (say) < 1-3? */
    /* - meth should be 0-8 */
    /* - reserved byte should be 0 */
    return (((first_byte & 0x0f) <= MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS) && (reserved_byte == 0));
}

static bool udcomphdr_appears_present(flow_state_t *flow, uint32_t direction, tvbuff_t *tvb, int offset)
{
    /* Should really not happen, but guard against this anyway. */
    if (flow == NULL) {
        /* No state to update. */
        return false;
    }

    if (direction == DIR_UPLINK) {
        if (flow->udcomphdrUplink_heuristic_result_set) {
            /* Return cached value */
            return flow->udcomphdrUplink_heuristic_result;
        }
        else {
            /* Work it out, and save answer for next time */
            flow->udcomphdrUplink_heuristic_result_set = true;
            flow->udcomphdrUplink_heuristic_result = at_udcomphdr(tvb, offset);
            return flow->udcomphdrUplink_heuristic_result;
        }
    }
    else {
        /* Downlink */
        if (flow->udcomphdrDownlink_heuristic_result_set) {
            /* Return cached value */
            return flow->udcomphdrDownlink_heuristic_result;
        }
        else {
            /* Work it out, and save answer for next time */
            flow->udcomphdrDownlink_heuristic_result_set = true;
            flow->udcomphdrDownlink_heuristic_result = at_udcomphdr(tvb, offset);
            return flow->udcomphdrDownlink_heuristic_result;
        }
    }
}

/* User plane dissector (section 8) */
static int
dissect_oran_u(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               oran_tap_info *tap_info, void *data _U_)
{
    /* Hidden filter for plane */
    proto_item *plane_ti = proto_tree_add_item(tree, hf_oran_uplane, tvb, 0, 0, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(plane_ti);

    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "O-RAN-FH-U");
    col_set_str(pinfo->cinfo, COL_INFO, "U-Plane");

    tap_info->userplane = true;

    /* Create display subtree for the protocol */
    proto_item *protocol_item = proto_tree_add_item(tree, proto_oran, tvb, 0, -1, ENC_NA);
    proto_item_append_text(protocol_item, "-U");
    proto_tree *oran_tree = proto_item_add_subtree(protocol_item, ett_oran);

    /* Transport header */
    /* Real-time control data / IQ data transfer message series identifier */
    uint16_t eAxC;
    addPcOrRtcid(tvb, oran_tree, &offset, hf_oran_ecpri_pcid, &eAxC);
    tap_info->eaxc = eAxC;

    /* Update/report status of conversation */
    uint32_t key = make_flow_key(pinfo, eAxC, ORAN_U_PLANE, false);
    flow_state_t* state = (flow_state_t*)wmem_tree_lookup32(flow_states_table, key);

    /* Message identifier */
    uint8_t seq_id;
    proto_item *seq_id_ti;
    offset = addSeqid(tvb, oran_tree, offset, ORAN_U_PLANE, &seq_id, &seq_id_ti, pinfo);

    /* Common header for time reference */
    proto_item *timingHeader = proto_tree_add_string_format(oran_tree, hf_oran_timing_header,
                                                            tvb, offset, 4, "", "Timing Header (");
    proto_tree *timing_header_tree = proto_item_add_subtree(timingHeader, ett_oran_u_timing);

    /* dataDirection */
    uint32_t direction;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_data_direction, tvb, offset, 1, ENC_NA, &direction);
    tap_info->uplink = (direction==0);
    /* payloadVersion */
    dissect_payload_version(timing_header_tree, tvb, pinfo, offset);
    /* filterIndex */
    proto_tree_add_item(timing_header_tree, hf_oran_filter_index, tvb, offset, 1, ENC_NA);
    offset += 1;

    int ref_a_offset = offset;

    /* frameId */
    uint32_t frameId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_frame_id, tvb, offset, 1, ENC_NA, &frameId);
    tap_info->frame = frameId;
    offset += 1;

    /* subframeId */
    uint32_t subframeId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_subframe_id, tvb, offset, 1, ENC_NA, &subframeId);
    /* slotId */
    uint32_t slotId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN, &slotId);
    tap_info->slot = slotId;
    offset++;
    /* symbolId */
    uint32_t symbolId = 0;
    proto_tree_add_item_ret_uint(timing_header_tree, hf_oran_symbolId, tvb, offset, 1, ENC_NA, &symbolId);
    offset++;

    char id[16];
    snprintf(id, 16, "%d-%d-%d-%d", frameId, subframeId, slotId, symbolId);
    proto_item *pi = proto_tree_add_string(timing_header_tree, hf_oran_refa, tvb, ref_a_offset, 3, id);
    proto_item_set_generated(pi);

    proto_item_append_text(timingHeader, "%s, frameId: %d, subframeId: %d, slotId: %d, symbolId: %d)",
        val_to_str_const(direction, data_direction_vals, "Unknown"), frameId, subframeId, slotId, symbolId);

    unsigned sample_bit_width;
    int compression;
    int includeUdCompHeader;

    /* Also look up C-PLANE state (sent in opposite direction) so may check current compression settings */
    uint32_t cplane_key = make_flow_key(pinfo, eAxC, ORAN_C_PLANE, true);
    flow_state_t* cplane_state = (flow_state_t*)wmem_tree_lookup32(flow_states_table, cplane_key);
    uint32_t cplane_samedir_key = make_flow_key(pinfo, eAxC, ORAN_C_PLANE, false);
    flow_state_t* cplane_samedir_state = (flow_state_t*)wmem_tree_lookup32(flow_states_table, cplane_samedir_key);


    if (!PINFO_FD_VISITED(pinfo)) {
        /* Create conversation if doesn't exist yet */
        if (!state)  {
            /* Allocate new state */
            state = wmem_new0(wmem_file_scope(), flow_state_t);
            state->ack_nack_requests = wmem_tree_new(wmem_epan_scope());
            wmem_tree_insert32(flow_states_table, key, state);
        }

        /* Check sequence analysis status */
        if (state->last_frame_seen[direction] && (seq_id != state->next_expected_sequence_number[direction])) {
            /* Store this result */
            flow_result_t *result = wmem_new0(wmem_file_scope(), flow_result_t);
            result->unexpected_seq_number = true;
            result->expected_sequence_number = state->next_expected_sequence_number[direction];
            result->previous_frame = state->last_frame[direction];
            wmem_tree_insert32(flow_results_table, pinfo->num, result);
        }
        /* Update sequence analysis state */
        state->last_frame[direction] = pinfo->num;
        state->last_frame_seen[direction] = true;
        state->next_expected_sequence_number[direction] = (seq_id+1) % 256;
    }

    /* Show any issues associated with this frame number */
    flow_result_t *result = wmem_tree_lookup32(flow_results_table, pinfo->num);
    if (result) {
        if (result->unexpected_seq_number) {
            expert_add_info_format(pinfo, seq_id_ti,
                                   (direction == DIR_UPLINK) ?
                                        &ei_oran_uplane_unexpected_sequence_number_ul :
                                        &ei_oran_uplane_unexpected_sequence_number_dl,
                                   "Sequence number %u expected, but got %u",
                                   result->expected_sequence_number, seq_id);
            tap_info->missing_sns = (256 + seq_id - result->expected_sequence_number) % 256;
            /* TODO: could add previous/next frame (in seqId tree?) ? */
        }
    }

    /* Checking UL timing within current slot.  Disabled if limit set to 0. */
    /* N.B., timing is relative to first seen frame,
       not some notion of the beginning of the slot from sync, offset by some timing.. */
    if (direction == DIR_UPLINK && us_allowed_for_ul_in_symbol > 0) {
        uint32_t timing_key = get_timing_key(frameId, subframeId, slotId, symbolId);
        if (!PINFO_FD_VISITED(pinfo)) {
            /* Set state on first pass */
            ul_timing_for_slot* timing = (ul_timing_for_slot*)wmem_tree_lookup32(ul_symbol_timing, timing_key);
            if (!timing) {
                /* Allocate new state */
                timing = wmem_new0(wmem_file_scope(), ul_timing_for_slot);
                timing->first_frame = pinfo->num;
                timing->first_frame_time = pinfo->abs_ts;
                timing->frames_seen_in_symbol = 1;
                timing->last_frame_in_symbol = pinfo->num;
                wmem_tree_insert32(ul_symbol_timing, timing_key, timing);
            }
            else {
                /* Update existing state */
                timing->frames_seen_in_symbol++;
                timing->last_frame_in_symbol = pinfo->num;
            }
        }
        else {
            /* Subsequent passes - look up result */
            ul_timing_for_slot* timing = (ul_timing_for_slot*)wmem_tree_lookup32(ul_symbol_timing, timing_key);
            if (timing) {  /* Really shouldn't fail! */
                if (timing->frames_seen_in_symbol > 1) {
                    /* Work out gap between frames (in microseconds) back to frame carrying first seen symbol */
                    int seconds_between_packets = (int)
                          (pinfo->abs_ts.secs - timing->first_frame_time.secs);
                    int nseconds_between_packets =
                          pinfo->abs_ts.nsecs - timing->first_frame_time.nsecs;


                    /* Round to nearest microsecond. */
                    uint32_t total_gap = (seconds_between_packets*1000000) +
                                         ((nseconds_between_packets+500) / 1000);

                    /* Show how long it has been */
                    proto_item *ti = NULL;
                    if (pinfo->num != timing->first_frame) {
                        ti = proto_tree_add_uint(timingHeader, hf_oran_u_section_ul_symbol_time, tvb, 0, 0, total_gap);
                        proto_item_set_generated(ti);
                    }

                    if (total_gap > us_allowed_for_ul_in_symbol) {
                        expert_add_info_format(pinfo, ti, &ei_oran_ul_uplane_symbol_too_long,
                                               "UL U-Plane Tx took longer (%u us) than limit set in preferences (%u us)",
                                               total_gap, us_allowed_for_ul_in_symbol);
                    }

                    /* Show how many frames were received */
                    ti = proto_tree_add_uint(timingHeader, hf_oran_u_section_ul_symbol_frames, tvb, 0, 0, timing->frames_seen_in_symbol);
                    proto_item_set_generated(ti);

                    /* Link to first frame for this symbol */
                    if (pinfo->num != timing->first_frame) {
                        ti = proto_tree_add_uint(timingHeader, hf_oran_u_section_ul_symbol_first_frame, tvb, 0, 0, timing->first_frame);
                        proto_item_set_generated(ti);
                    }

                    /* And also last frame */
                    if (pinfo->num != timing->last_frame_in_symbol) {
                        ti = proto_tree_add_uint(timingHeader, hf_oran_u_section_ul_symbol_last_frame, tvb, 0, 0, timing->last_frame_in_symbol);
                        proto_item_set_generated(ti);
                    }

                    tap_info->ul_delay_in_us = total_gap;
                }
            }
        }
    }


    /* Look up preferences for samples */
    if (direction == DIR_UPLINK) {
        sample_bit_width = pref_sample_bit_width_uplink;
        compression = pref_iqCompressionUplink;
        includeUdCompHeader = pref_includeUdCompHeaderUplink;
    } else {
        sample_bit_width = pref_sample_bit_width_downlink;
        compression = pref_iqCompressionDownlink;
        includeUdCompHeader = pref_includeUdCompHeaderDownlink;
    }

    /* If uplink, load any udCompHdr settings written by C-Plane */
    bool ud_cmp_hdr_cplane = false;
    if (cplane_state && direction == 0) {
        /* Initialise settings from udpCompHdr from C-Plane */
        if (cplane_state->ul_ud_comp_hdr_set) {
            sample_bit_width = cplane_state->ul_ud_comp_hdr_bit_width;
            compression =      cplane_state->ul_ud_comp_hdr_compression;
            ud_cmp_hdr_cplane = true;
        }
    }

    /* Need a valid value (e.g. 9, 14).  0 definitely won't work, as won't progress around loop! */
    /* N.B. may yet be overwritten by udCompHdr settings in sections below! */
    if (sample_bit_width == 0) {
        expert_add_info_format(pinfo, protocol_item, &ei_oran_invalid_sample_bit_width,
                               "%cL Sample bit width from %s (%u) not valid, so can't decode sections",
                               (direction == DIR_UPLINK) ? 'U' : 'D',
                               !ud_cmp_hdr_cplane ? "preference" : "C-Plane",
                               sample_bit_width);
        return offset;
    }

    unsigned bytesLeft;
    unsigned number_of_sections = 0;
    unsigned nBytesPerPrb =0;

    /* Add each section (not from count, just keep parsing until payload used) */
    do {
        /* Section subtree */
        unsigned section_start_offset = offset;
        proto_item *sectionHeading = proto_tree_add_string_format(oran_tree, hf_oran_u_section,
                                                                  tvb, offset, 0, "", "Section");
        proto_tree *section_tree = proto_item_add_subtree(sectionHeading, ett_oran_u_section);

        /* Section Header fields (darker green part) */

        /* sectionId */
        uint32_t sectionId = 0;
        proto_item *ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_section_id, tvb, offset, 2, ENC_BIG_ENDIAN, &sectionId);
        if (sectionId == 4095) {
            proto_item_append_text(ti, " (not default coupling C/U planes using sectionId)");
        }
        offset++;

        if (tap_info->num_section_ids < MAX_SECTION_IDs) {
            tap_info->section_ids[tap_info->num_section_ids++] = sectionId;
        }

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

        proto_item *ud_comp_meth_item, *ud_comp_len_ti=NULL;
        uint32_t ud_comp_len;

        /* udCompHdr (if preferences indicate will be present) */
        bool included = (includeUdCompHeader==1) ||   /* 1 means present.. */
                        (includeUdCompHeader==2 && udcomphdr_appears_present(state, direction, tvb, offset));
        if (included) {
            /* 7.5.2.10 */
            /* Extract these values to inform how wide IQ samples in each PRB will be. */
            offset = dissect_udcomphdr(tvb, pinfo, section_tree, offset, false, &sample_bit_width,
                                       &compression, &ud_comp_meth_item);

            /* Not part of udCompHdr */
            proto_tree_add_item(section_tree, hf_oran_reserved_8bits, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else {
            /* No fields to dissect - just showing comp values from prefs */
            /* iqWidth */
            proto_item *iq_width_item = proto_tree_add_uint(section_tree, hf_oran_udCompHdrIqWidth_pref, tvb, 0, 0, sample_bit_width);
            proto_item_append_text(iq_width_item, (ud_cmp_hdr_cplane) ? " (from c-plane)" : " (from preferences)");
            proto_item_set_generated(iq_width_item);

            /* udCompMethod */
            ud_comp_meth_item = proto_tree_add_uint(section_tree, hf_oran_udCompHdrMeth_pref, tvb, 0, 0, compression);
            proto_item_append_text(ud_comp_meth_item, (ud_cmp_hdr_cplane) ? " (from c-plane)" : " (from preferences)");
            proto_item_set_generated(ud_comp_meth_item);

            /* Point back to C-Plane, if used */
            /* TODO: doesn't work with multiple port mappings using SE10.. */
            if (ud_cmp_hdr_cplane) {
                proto_item *cplane_ti = proto_tree_add_uint(section_tree, hf_oran_ul_cplane_ud_comp_hdr_frame, tvb, offset, 0, cplane_state->ul_ud_comp_hdr_frame);
                proto_item_set_generated(cplane_ti);
            }
        }

        /* Not supported! TODO: other places where comp method is looked up (e.g., bfw?) */
        switch (compression) {
            case COMP_NONE:
            case COMP_BLOCK_FP:
            case BFP_AND_SELECTIVE_RE:
            case COMP_MODULATION:
            case MOD_COMPR_AND_SELECTIVE_RE:
                break;
            default:
                expert_add_info_format(pinfo, ud_comp_meth_item, &ei_oran_unsupported_compression_method,
                                   "Compression method %u (%s) not supported by dissector",
                                   compression,
                                   rval_to_str_const(compression, ud_comp_header_meth, "reserved"));
        }

        /* udCompLen (when supported, methods 5,6,7,8) */
        if (compression >= BFP_AND_SELECTIVE_RE) {
            bool supported = (pref_support_udcompLen==1) || /* supported */
                             (pref_support_udcompLen==2 && udcomplen_appears_present(includeUdCompHeader, tvb, offset));

            if (supported) {
                ud_comp_len_ti = proto_tree_add_item_ret_uint(section_tree, hf_oran_udCompLen, tvb, offset, 2, ENC_BIG_ENDIAN, &ud_comp_len);
                if (ud_comp_len <= 1) {
                    proto_item_append_text(ud_comp_len_ti, " (reserved)");
                }
                /* TODO: report if less than a viable section in frame? */
                /* Check that there is this much length left in the frame */
                if ((int)ud_comp_len > tvb_reported_length_remaining(tvb, section_start_offset)) {
                    expert_add_info_format(pinfo, ud_comp_len_ti, &ei_oran_ud_comp_len_wrong_size,
                                           "udCompLen indicates %u bytes in section, but only %u are left in frame",
                                           ud_comp_len, tvb_reported_length_remaining(tvb, section_start_offset));
                }
                /* Actual length of section will be checked below, at the end of the section */
                offset += 2;
            }
        }

        /* sReSMask1 + sReSMask2 (depends upon compression method) */
        uint64_t sresmask1=0, sresmask2=0;
        if (compression == BFP_AND_SELECTIVE_RE_WITH_MASKS ||
            compression == MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS)
        {
            static int * const  sres_mask1_2_flags[] = {
                &hf_oran_sReSMask1_2_re12,
                &hf_oran_sReSMask1_2_re11,
                &hf_oran_sReSMask1_2_re10,
                &hf_oran_sReSMask1_2_re9,
                &hf_oran_sReSMask_re8,
                &hf_oran_sReSMask_re7,
                &hf_oran_sReSMask_re6,
                &hf_oran_sReSMask_re5,
                &hf_oran_sReSMask_re4,
                &hf_oran_sReSMask_re3,
                &hf_oran_sReSMask_re2,
                &hf_oran_sReSMask_re1,
                NULL
            };

            /* reserved (4 bits) */
            proto_tree_add_item(section_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
            /* sReSMask1 (12 bits) */
            proto_item *sresmask_ti;
            sresmask_ti = proto_tree_add_bitmask_ret_uint64(section_tree, tvb, offset,
                                                            hf_oran_sReSMask1,
                                                            ett_oran_sresmask,
                                                            sres_mask1_2_flags,
                                                            ENC_NA,
                                                            &sresmask1);
            offset += 2;
            /* Count REs present */
            unsigned res = 0;
            for (unsigned n=0; n < 12; n++) {
                if ((sresmask1 >> n) & 0x1) {
                    res++;
                }
            }
            proto_item_append_text(sresmask_ti, "   (%u REs)", res);


            /* reserved (4 bits) */
            proto_tree_add_item(section_tree, hf_oran_reserved_4bits, tvb, offset, 1, ENC_NA);
            /* sReSMask2 (12 bits) */
            sresmask_ti = proto_tree_add_bitmask_ret_uint64(section_tree, tvb, offset,
                                                            hf_oran_sReSMask2,
                                                            ett_oran_sresmask,
                                                            sres_mask1_2_flags,
                                                            ENC_NA,
                                                            &sresmask2);
            offset += 2;

            if (rb == 1) {
                proto_item_append_text(sresmask_ti, " (ignored)");
                if (sresmask2 != 0) {
                    expert_add_info(pinfo, ud_comp_len_ti, &ei_oran_sresmask2_not_zero_with_rb);
                }
            }
            else {
                /* Count REs present */
                res = 0;
                for (unsigned n=0; n < 12; n++) {
                    if ((sresmask2 >> n) & 0x1) {
                        res++;
                    }
                }
                proto_item_append_text(sresmask_ti, "   (%u REs)", res);
            }
        }

        write_section_info(sectionHeading, pinfo, protocol_item, sectionId, startPrbu, numPrbu, rb);

        /* TODO: should this use the same pref as c-plane? */
        if (numPrbu == 0) {
            /* Special case for all PRBs (NR: the total number of PRBs may be > 255) */
            numPrbu = pref_data_plane_section_total_rbs;
            startPrbu = 0;  /* may already be 0... */
        }

        section_mod_compr_config_t* mod_compr_config = get_mod_compr_section_to_read(cplane_samedir_state, sectionId);

        /* Add each PRB */
        for (unsigned i = 0; i < numPrbu; i++) {
            /* Create subtree */
            proto_item *prbHeading = proto_tree_add_string_format(section_tree, hf_oran_samples_prb,
                                                                  tvb, offset, 0,
                                                                  "", "PRB");
            proto_tree *rb_tree = proto_item_add_subtree(prbHeading, ett_oran_u_prb);
            uint32_t exponent = 0;
            uint16_t sresmask = 0;

            /* udCompParam (depends upon compression method) */
            int before = offset;
            offset = dissect_udcompparam(tvb, pinfo, rb_tree, offset, compression, &exponent, &sresmask, false);
            int udcompparam_len = offset-before;

            /* Show PRB number in root */
            proto_item_append_text(prbHeading, " %3u", startPrbu + i*(1+rb));

            /* Work out how many REs / PRB */
            unsigned res_per_prb = 12;
            uint16_t sresmask_to_use = 0x0fff;

            if (compression >= BFP_AND_SELECTIVE_RE) {
                /* Work out which mask should be used */
                if (compression==BFP_AND_SELECTIVE_RE || compression==MOD_COMPR_AND_SELECTIVE_RE) {
                    /* Selective RE cases, use value from compModParam */
                    sresmask_to_use = (uint16_t)sresmask;
                }
                else {
                    /* With masks (in section).  Choose between sresmask1 and sresmask2 */
                    if (rb==1 || (i%1)==0) {
                        /* Even values */
                        sresmask_to_use = (uint16_t)sresmask1;
                    }
                    else {
                        /* Odd values */
                        sresmask_to_use = (uint16_t)sresmask2;
                    }
                }

                /* Count REs present using sresmask */
                res_per_prb = 0;
                /* Use sresmask to pick out which REs are present */
                for (unsigned n=0; n<12; n++) {
                    if (sresmask_to_use & (1<<n)) {
                        res_per_prb++;
                    }
                }
            }

            /* N.B. bytes for samples need to be padded out to next byte
               (certainly where there aren't 12 REs in PRB..) */
            unsigned nBytesForSamples = (sample_bit_width * res_per_prb * 2 + 7) / 8;
            nBytesPerPrb = nBytesForSamples + udcompparam_len;

            proto_tree_add_item(rb_tree, hf_oran_iq_user_data, tvb, offset, nBytesForSamples, ENC_NA);

            tap_info->non_zero_re_in_current_prb = false;

            /* Optionally trying to show I/Q RE values */
            if (pref_showIQSampleValues) {
                /* Individual values */
                unsigned samples_offset = offset*8;
                unsigned samples = 0;

                if (compression >= BFP_AND_SELECTIVE_RE) {
                    /* Use sresmask to pick out which REs are present */
                    for (unsigned n=1; n<=12; n++) {
                        if (sresmask_to_use & (1<<(n-1))) {
                            samples_offset = dissect_oran_u_re(tvb, rb_tree,
                                                               n, samples_offset, tap_info, sample_bit_width, compression, exponent, mod_compr_config, n);
                            samples++;
                        }
                    }
                }
                else {
                    /* All 12 REs are present */
                    for (unsigned n=1; n<=12; n++) {
                        samples_offset = dissect_oran_u_re(tvb, rb_tree,
                                                           n, samples_offset, tap_info, sample_bit_width, compression, exponent, mod_compr_config, n);
                        samples++;
                    }
                }
                proto_item_append_text(prbHeading, " (%u REs)", samples);

                /* Was this PRB all zeros? */
                if (!tap_info->non_zero_re_in_current_prb) {
                    tap_info->num_prbs_zero++;
                    /* Add a filter to make zero-valued PRBs more findable */
                    proto_tree_add_item(rb_tree, hf_oran_zero_prb, tvb,
                                                            samples_offset/8, nBytesForSamples, ENC_NA);
                    proto_item_append_text(prbHeading, " (all zeros)");
                }
            }

            tap_info->num_prbs++;


            /* Advance past samples */
            offset += nBytesForSamples;

            /* Set end of prb subtree */
            proto_item_set_end(prbHeading, tvb, offset);
        }

        /* Set extent of section */
        proto_item_set_len(sectionHeading, offset-section_start_offset);
        if (ud_comp_len_ti != NULL && ((offset-section_start_offset != ud_comp_len))) {
            expert_add_info_format(pinfo, ud_comp_len_ti, &ei_oran_ud_comp_len_wrong_size,
                                   "udCompLen indicates %u bytes in section, but dissected %u instead",
                                   ud_comp_len, offset-section_start_offset);
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


/**********************************************************************/
/* Main dissection function.                                          */
/* N.B. ecpri message type passed in as 'data' arg by eCPRI dissector */
static int
dissect_oran(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t ecpri_message_type = *(uint32_t *)data;
    int offset = 0;

    /* Allocate and zero tap struct */
    oran_tap_info *tap_info = wmem_new0(wmem_file_scope(), oran_tap_info);
    tap_info->pdu_size = pinfo->fd->pkt_len;

    switch (ecpri_message_type) {
        case ECPRI_MT_IQ_DATA:
            offset = dissect_oran_u(tvb, pinfo, tree, tap_info, data);
            break;
        case ECPRI_MT_RT_CTRL_DATA:
            offset = dissect_oran_c(tvb, pinfo, tree, tap_info, data);
            break;
        default:
            /* Not dissecting other types - assume these are handled by eCPRI dissector */
            return 0;
    }

    tap_queue_packet(oran_tap, pinfo, tap_info);

    return offset;
}

static void oran_init_protocol(void)
{
    udcomplen_heuristic_result_set = false;
    udcomplen_heuristic_result = false;
}


/* Register the protocol with Wireshark. */
void
proto_register_oran(void)
{
    static hf_register_info hf[] = {

       /* Section 5.1.3.2.7 */
       { &hf_oran_du_port_id,
         { "DU Port ID", "oran_fh_cus.du_port_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           "Processing unit at O-RU - width set in dissector preference", HFILL }
       },

       /* Section 5.1.3.2.7 */
       { &hf_oran_bandsector_id,
         { "BandSector ID", "oran_fh_cus.bandsector_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           "Aggregated cell identified - width set in dissector preference", HFILL }
       },

       /* Section 5.1.3.2.7 */
       { &hf_oran_cc_id,
         { "CC ID", "oran_fh_cus.cc_id",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           "Component Carrier - width set in dissector preference", HFILL }
       },

        /* Section 5.1.3.2.7 */
        { &hf_oran_ru_port_id,
          { "RU Port ID", "oran_fh_cus.ru_port_id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Logical flow - width set in dissector preference", HFILL }
        },

        /* Section 5.1.3.2.8 */
        { &hf_oran_sequence_id,
          { "Sequence ID", "oran_fh_cus.sequence_id",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "The Sequence ID wraps around individually per eAxC", HFILL }
        },

        /* Section 5.1.3.2.8 */
        { &hf_oran_e_bit,
          { "E Bit", "oran_fh_cus.e_bit",
            FT_UINT8, BASE_DEC,
            VALS(e_bit), 0x80,
            "Indicate the last message of a subsequence (U-Plane only)", HFILL }
        },

        /* Section 5.1.3.2.8 */
        { &hf_oran_subsequence_id,
          { "Subsequence ID", "oran_fh_cus.subsequence_id",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            "The subsequence ID (for eCPRI layer fragmentation)", HFILL }
        },

        { &hf_oran_previous_frame,
          { "Previous frame in stream", "oran_fh_cus.previous-frame",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0,
            "Previous frame in sequence", HFILL }
        },

        /* Section 7.5.2.1 */
        { &hf_oran_data_direction,
          { "Data Direction", "oran_fh_cus.data_direction",
            FT_UINT8, BASE_DEC,
            VALS(data_direction_vals), 0x80,
            "gNB data direction", HFILL }
        },

        /* Section 7.5.2.2 */
        { &hf_oran_payload_version,
          { "Payload Version", "oran_fh_cus.payloadVersion",
            FT_UINT8, BASE_DEC,
            NULL, 0x70,
            "Payload protocol version the following IEs", HFILL}
        },

        /* Section 7.5.2.3 */
        { &hf_oran_filter_index,
          { "Filter Index", "oran_fh_cus.filterIndex",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(filter_indices), 0x0f,
            "used between IQ data and air interface, both in DL and UL", HFILL}
        },

        /* Section 7.5.2.4 */
        { &hf_oran_frame_id,
          { "Frame ID", "oran_fh_cus.frameId",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "A counter for 10 ms frames (wrapping period 2.56 seconds)", HFILL}
        },

        /* Section 7.5.2.5 */
        { &hf_oran_subframe_id,
          { "Subframe ID", "oran_fh_cus.subframe_id",
            FT_UINT8, BASE_DEC,
            NULL, 0xf0,
            "A counter for 1 ms sub-frames within 10ms frame", HFILL}
        },

        /* Section 7.5.2.6 */
        { &hf_oran_slot_id,
          { "Slot ID", "oran_fh_cus.slotId",
            FT_UINT16, BASE_DEC,
            NULL, 0x0fc0,
            "Slot number within a 1ms sub-frame", HFILL}
        },

        /* Generated for convenience */
        { &hf_oran_slot_within_frame,
          { "Slot within frame", "oran_fh_cus.slot-within-frame",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Slot within frame, to match DCT logs", HFILL}
        },

        /* Section 7.5.2.7 */
        { &hf_oran_start_symbol_id,
          { "Start Symbol ID", "oran_fh_cus.startSymbolId",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            "The first symbol number within slot affected", HFILL}
        },

        /* Section 7.5.2.8 */
        { &hf_oran_numberOfSections,
          { "Number of Sections", "oran_fh_cus.numberOfSections",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "The number of section IDs included in this message", HFILL}
        },

        /* Section 7.5.2.9 */
        { &hf_oran_sectionType,
          { "Section Type", "oran_fh_cus.sectionType",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(section_types), 0x0,
            "Determines the characteristics of U-plane data", HFILL}
        },

        /* Section 7.5.2.10 */
        { &hf_oran_udCompHdr,
          { "udCompHdr", "oran_fh_cus.udCompHdr",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* Section 7.5.2.11 */
        { &hf_oran_numberOfUEs,
          { "Number Of UEs", "oran_fh_cus.numberOfUEs",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Indicates number of UEs for which channel info is provided", HFILL}
        },

        /* Section 7.5.2.12 */
        { &hf_oran_timeOffset,
          { "Time Offset", "oran_fh_cus.timeOffset",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "from start of the slot to start of CP in samples", HFILL}
        },

        /* Section 7.5.2.13 */
        { &hf_oran_frameStructure_fft,
          { "FFT Size", "oran_fh_cus.frameStructure.fft",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(frame_structure_fft), 0xf0,
            "The FFT/iFFT size being used for all IQ data processing related to this message", HFILL }
        },

        /* Section 7.5.2.13 */
        { &hf_oran_frameStructure_subcarrier_spacing,
          { "Subcarrier Spacing", "oran_fh_cus.frameStructure.spacing",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(subcarrier_spacings), 0x0f,
            "The sub carrier spacing as well as the number of slots per 1ms sub-frame",
            HFILL }
        },

        /* Section 7.5.2.14 */
        { &hf_oran_cpLength,
          { "cpLength", "oran_fh_cus.cpLength",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "cyclic prefix length", HFILL}
        },

        { &hf_oran_timing_header,
          { "Timing Header", "oran_fh_cus.timingHeader",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* Section 7.5.3.1 */
        { &hf_oran_section_id,
          { "sectionId", "oran_fh_cus.sectionId",
            FT_UINT16, BASE_DEC,
            NULL, 0xfff0,
            "section identifier of data", HFILL}
        },

        /* Section 7.5.3.2 */
        { &hf_oran_rb,
          { "rb", "oran_fh_cus.rb",
            FT_UINT8, BASE_DEC,
            VALS(rb_vals), 0x08,
            "resource block indicator", HFILL}
        },

        /* Section 7.5.5.3 */
        { &hf_oran_symInc,
          { "symInc", "oran_fh_cus.symInc",
            FT_UINT8, BASE_DEC,
            VALS(sym_inc_vals), 0x04,
            "Symbol Number Increment Command", HFILL}
        },

        /* Section 7.5.3.4 */
        { &hf_oran_startPrbc,
          { "startPrbc", "oran_fh_cus.startPrbc",
            FT_UINT16, BASE_DEC,
            NULL, 0x03ff,
            "Starting PRB of Control Plane Section", HFILL}
        },

        /* Section 7.5.3.5 */
        { &hf_oran_reMask_re1,
          { "RE 1", "oran_fh_cus.reMask-RE1",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x8000,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re2,
          { "RE 2", "oran_fh_cus.reMask-RE2",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x4000,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re3,
          { "RE 3", "oran_fh_cus.reMask-RE3",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x2000,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re4,
          { "RE 4", "oran_fh_cus.reMask-RE4",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x1000,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re5,
          { "RE 5", "oran_fh_cus.reMask-RE5",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0800,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re6,
          { "RE 6", "oran_fh_cus.reMask-RE6",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0400,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re7,
          { "RE 7", "oran_fh_cus.reMask-RE7",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0200,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re8,
          { "RE 8", "oran_fh_cus.reMask-RE8",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0100,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re9,
          { "RE 9", "oran_fh_cus.reMask-RE9",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0080,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re10,
          { "RE 10", "oran_fh_cus.reMask-RE10",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0040,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re11,
          { "RE 11", "oran_fh_cus.reMask-RE11",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0020,
            NULL, HFILL}
        },
        { &hf_oran_reMask_re12,
          { "RE 12", "oran_fh_cus.reMask-RE12",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0010,
            NULL, HFILL}
        },
        { &hf_oran_reMask,
          { "RE Mask", "oran_fh_cus.reMask",
            FT_UINT16, BASE_HEX,
            NULL, 0xfff0,
            "The Resource Element (RE) mask within a PRB", HFILL}
        },

        /* Section 7.5.3.6 */
        { &hf_oran_numPrbc,
          { "numPrbc", "oran_fh_cus.numPrbc",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Number of contiguous PRBs per data section description", HFILL}
        },

        /* Section 7.5.3.7 */
        { &hf_oran_numSymbol,
          { "Number of Symbols", "oran_fh_cus.numSymbol",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "Defines number of symbols to which the section control is applicable", HFILL}
        },

        /* Section 7.5.3.8 */
        { &hf_oran_ef,
          { "Extension Flag", "oran_fh_cus.ef",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            "Indicates if more section extensions follow", HFILL}
        },

        /* Section 7.5.3.9 */
        { &hf_oran_beamId,
          { "Beam ID", "oran_fh_cus.beamId",
             FT_UINT16, BASE_DEC,
             NULL, 0x7fff,
             "Defines the beam pattern to be applied to the U-Plane data", HFILL}
        },

        { &hf_oran_extension,
          { "Extension", "oran_fh_cus.extension",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Section extension", HFILL}
        },

        /* Section 7.6.2.1 */
        { &hf_oran_exttype,
          { "extType", "oran_fh_cus.extType",
            FT_UINT8, BASE_DEC,
            VALS(exttype_vals), 0x7f,
            "The extension type, which provides additional parameters specific to subject data extension", HFILL}
        },

        /* Section 7.6.2.3 */
        { &hf_oran_extlen,
          { "extLen", "oran_fh_cus.extLen",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Extension length in 32-bit words", HFILL}
        },

        /* Section 7.7.1 */
        { &hf_oran_bfw,
          { "bfw", "oran_fh_cus.bfw",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Set of weights for a particular antenna", HFILL}
        },
        { &hf_oran_bfw_bundle,
          { "Bundle", "oran_fh_cus.bfw.bundle",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Bundle of BFWs", HFILL}
        },
        { &hf_oran_bfw_bundle_id,
          { "Bundle Id", "oran_fh_cus.bfw.bundleId",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        /* Section 7.7.1.4 */
        { &hf_oran_bfw_i,
          { "bfwI", "oran_fh_cus.bfwI",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "In-phase", HFILL}
        },
        /* Section 7.7.1.5 */
        { &hf_oran_bfw_q,
          { "bfwQ", "oran_fh_cus.bfwQ",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "Quadrature", HFILL}
        },

        /* Section 7.5.3.10 */
        { &hf_oran_ueId,
          { "UE ID", "oran_fh_cus.ueId",
            FT_UINT16, BASE_DEC,
            NULL, 0x7fff,
            "logical identifier for set of channel info", HFILL}
        },

        /* Section 7.5.3.11 */
        { &hf_oran_freqOffset,
          { "Frequency Offset", "oran_fh_cus.freqOffset",
            FT_UINT24, BASE_DEC,
            NULL, 0x0,
            "with respect to the carrier center frequency before additional filtering", HFILL}
        },

        /* Section 7.5.3.12 */
        { &hf_oran_regularizationFactor,
          { "Regularization Factor", "oran_fh_cus.regularizationFactor",
            FT_INT16, BASE_DEC,
            NULL, 0x0,
            "Signed value to support MMSE operation within O-RU", HFILL}
        },

        /* Section 7.5.3.14 */
        { &hf_oran_laaMsgType,
          { "LAA Message Type", "oran_fh_cus.laaMsgType",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(laaMsgTypes), 0xf0,
            NULL, HFILL}
        },

        /* Section 7.5.3.15 */
        { &hf_oran_laaMsgLen,
          { "LAA Message Length", "oran_fh_cus.laaMsgLen",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "number of 32-bit words in the LAA section", HFILL}
        },

        /* Section 7.5.3.16 */
        { &hf_oran_lbtHandle,
          { "LBT Handle", "oran_fh_cus.lbtHandle",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            "label to identify transaction", HFILL}
         },

        /* Section 7.5.3.17 */
        { &hf_oran_lbtDeferFactor,
          { "Defer Factor", "oran_fh_cus.lbtDeferFactor",
            FT_UINT8, BASE_DEC,
            NULL, 0x07,
            "Defer factor in sensing slots as described in 3GPP TS 36.213 Section 15.1.1", HFILL}
        },

        /* Section 7.5.3.18 */
        { &hf_oran_lbtBackoffCounter,
          { "Backoff Counter", "oran_fh_cus.lbtBackoffCounter",
            FT_UINT16, BASE_DEC,
            NULL, 0xffc0,
            "LBT backoff counter in sensing slots as described in 3GPP TS 36.213 Section 15.1.1", HFILL}
        },

        /* Section 7.5.3.19 */
        { &hf_oran_lbtOffset,
          { "LBT Offset", "oran_fh_cus.lbtOffset",
            FT_UINT16, BASE_DEC,
            NULL, 0xffc0,
            "LBT start time in microseconds from the beginning of the subframe scheduled by this message", HFILL}
        },

        /* Section 7.5.3.20 */
        { &hf_oran_MCOT,
          { "Maximum Channel Occupancy Time", "oran_fh_cus.MCOT",
            FT_UINT8, BASE_DEC,
            NULL, 0x3c,
            "LTE TXOP duration in subframes as described in 3GPP TS 36.213 Section 15.1.1", HFILL}
        },

        /* Section 7.5.3.21 */
        { &hf_oran_lbtMode,
          { "LBT Mode", "oran_fh_cus.lbtMode",
            FT_UINT8, BASE_DEC,
            VALS(lbtMode_vals), 0x0,
            NULL, HFILL}
        },

        /* Section 7.5.3.22 */
        { &hf_oran_lbtPdschRes,
          { "lbtPdschRes", "oran_fh_cus.lbtPdschRes",
            FT_UINT8, BASE_DEC,
            VALS(lbtPdschRes_vals), 0xc0,
            "LBT result of SFN/SF", HFILL}
        },

        /* Section 7.5.3.23 */
        { &hf_oran_sfStatus,
          { "sfStatus", "oran_fh_cus.sfStatus",
            FT_BOOLEAN, 8,
            TFS(&tfs_sfStatus), 0x10,
            "Indicates whether the subframe was dropped or transmitted", HFILL}
        },

        /* Section 7.5.3.22 */
        { &hf_oran_lbtDrsRes,
          { "lbtDrsRes", "oran_fh_cus.lbtDrsRes",
            FT_BOOLEAN, 8,
            TFS(&tfs_fail_success), 0x80,
            "Indicates whether the subframe was dropped or transmitted", HFILL}
        },

        /* Section 7.5.3.25 */
        { &hf_oran_initialPartialSF,
          { "Initial partial SF", "oran_fh_cus.initialPartialSF",
            FT_BOOLEAN, 8,
            TFS(&tfs_partial_full_sf), 0x40,
            "Indicates whether the initial SF in the LBT process is full or partial", HFILL}
        },

        /* Section 7.5.3.26. */
        { &hf_oran_lbtBufErr,
          { "lbtBufErr", "oran_fh_cus.lbtBufErr",
            FT_BOOLEAN, 8,
            TFS(&tfs_lbtBufErr), 0x80,
            "LBT buffer error", HFILL}
        },

        /* Section 7.5.3.27 */
        { &hf_oran_sfnSfEnd,
          { "SFN/SF End", "oran_fh_cus.sfnSfEnd",
            FT_UINT16, BASE_DEC,
            NULL, 0x0fff,
            "SFN/SF by which the DRS window must end", HFILL}
        },

        /* Section 7.5.3.28 */
        { &hf_oran_lbtCWConfig_H,
          { "lbtCWConfig_H", "oran_fh_cus.lbtCWConfig_H",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "HARQ parameters for congestion window management", HFILL}
        },

        /* Section 7.5.3.29 */
        { &hf_oran_lbtCWConfig_T,
          { "lbtCWConfig_T", "oran_fh_cus.lbtCWConfig_T",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "TB parameters for congestion window management", HFILL}
        },

        /* Section 7.5.3.30 */
        { &hf_oran_lbtTrafficClass,
          { "lbtTrafficClass", "oran_fh_cus.lbtTrafficClass",
            FT_UINT8, BASE_DEC,
            VALS(lbtTrafficClass_vals), 0x38,
            "Traffic class priority for congestion window management", HFILL}
        },

        /* Section 7.5.3.31 */
        { &hf_oran_lbtCWR_Rst,
          { "lbtCWR_Rst", "oran_fh_cus.lbtCWR_Rst",
            FT_BOOLEAN, 8,
            TFS(&tfs_fail_success), 0x80,
            "notification about packet reception successful or not", HFILL}
        },

        /* Reserved fields */
        { &hf_oran_reserved,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL}
        },

        { &hf_oran_reserved_1bit,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x80,
            NULL, HFILL}
        },
        { &hf_oran_reserved_2bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0xc0,
            NULL, HFILL}
        },
        { &hf_oran_reserved_3bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0xe0,
            NULL, HFILL}
        },
        { &hf_oran_reserved_4bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0xf0,
            NULL, HFILL}
        },
        { &hf_oran_reserved_last_4bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x0f,
            NULL, HFILL}
        },
        { &hf_oran_reserved_last_5bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x1f,
            NULL, HFILL}
        },
        { &hf_oran_reserved_6bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0xfc,
            NULL, HFILL}
        },
        { &hf_oran_reserved_last_6bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x3f,
            NULL, HFILL}
        },
        { &hf_oran_reserved_7bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0xfe,
            NULL, HFILL}
        },
        { &hf_oran_reserved_last_7bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x7f,
            NULL, HFILL}
        },
        { &hf_oran_reserved_8bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_reserved_16bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_reserved_15bits,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT16, BASE_HEX,
            NULL, 0x7fff,
            NULL, HFILL}
        },
        { &hf_oran_reserved_bit1,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x40,
            NULL, HFILL}
        },
        { &hf_oran_reserved_bit2,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x20,
            NULL, HFILL}
        },
        { &hf_oran_reserved_bit4,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x08,
            NULL, HFILL}
        },
        { &hf_oran_reserved_bit5,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x04,
            NULL, HFILL}
        },
        { &hf_oran_reserved_bits123,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x70,
            NULL, HFILL}
        },
        { &hf_oran_reserved_bits456,
          { "reserved", "oran_fh_cus.reserved",
            FT_UINT8, BASE_HEX,
            NULL, 0x0e,
            NULL, HFILL}
        },


        /* 7.7.11.10 */
        { &hf_oran_bundle_offset,
          { "BundleOffset", "oran_fh_cus.bundleOffset",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            "offset between start of first PRB bundle and startPrbc", HFILL}
        },
        /* 7.7.11.9 */
        { &hf_oran_cont_ind,
          { "contInd", "oran_fh_cus.contInd",
            FT_BOOLEAN, 8,
            TFS(&continuity_indication_tfs), 0x80,
            "PRB region continuity flag", HFILL}
        },

        /* 7.7.1.2 bfwCompHdr (beamforming weight compression header) */
        { &hf_oran_bfwCompHdr,
          { "bfwCompHdr", "oran_fh_cus.bfwCompHdr",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Compression method and IQ bit width for beamforming weights", HFILL}
        },
        { &hf_oran_bfwCompHdr_iqWidth,
          { "IQ Bit Width", "oran_fh_cus.bfwCompHdr_iqWidth",
            FT_UINT8, BASE_HEX,
            VALS(bfw_comp_headers_iq_width), 0xf0,
            "IQ bit width for the beamforming weights", HFILL}
        },
        { &hf_oran_bfwCompHdr_compMeth,
          { "Compression Method", "oran_fh_cus.bfwCompHdr_compMeth",
            FT_UINT8, BASE_HEX,
            VALS(bfw_comp_headers_comp_meth), 0x0f,
            "compression method for the beamforming weights", HFILL}
        },

        /* 7.5.3.32 */
        { &hf_oran_ciCompParam,
          { "ciCompParam", "oran_fh_cus.ciCompParam",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "channel information compression parameter", HFILL}
        },

        /* Table 7.5.3.32-1 */
        { &hf_oran_blockScaler,
          { "blockScaler", "oran_fh_cus.blockScaler",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            "unsigned, 1 integer bit, 7 fractional bits", HFILL}
        },
        { &hf_oran_compBitWidth,
          { "compBitWidth", "oran_fh_cus.compBitWidth",
            FT_UINT8, BASE_DEC,
            NULL, 0xf0,
            "Length of I bits and length of Q bits after compression over entire PRB", HFILL}
        },
        { &hf_oran_compShift,
          { "compShift", "oran_fh_cus.compShift",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "The shift applied to the entire PRB", HFILL}
        },

        { &hf_oran_active_beamspace_coefficient_n1,
          { "N1", "oran_fh_cus.activeBeamspace_Coefficient_n1",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x80,
            NULL, HFILL}
        },
        { &hf_oran_active_beamspace_coefficient_n2,
          { "N2", "oran_fh_cus.activeBeamspace_Coefficient_n2",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x40,
            NULL, HFILL}
        },
        { &hf_oran_active_beamspace_coefficient_n3,
          { "N3", "oran_fh_cus.activeBeamspace_Coefficient_n3",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x20,
            NULL, HFILL}
        },
        { &hf_oran_active_beamspace_coefficient_n4,
          { "N4", "oran_fh_cus.activeBeamspace_Coefficient_n4",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x10,
            NULL, HFILL}
        },
        { &hf_oran_active_beamspace_coefficient_n5,
          { "N5", "oran_fh_cus.activeBeamspace_Coefficient_n5",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL}
        },
        { &hf_oran_active_beamspace_coefficient_n6,
          { "N6", "oran_fh_cus.activeBeamspace_Coefficient_n6",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL}
        },
        { &hf_oran_active_beamspace_coefficient_n7,
          { "N7", "oran_fh_cus.activeBeamspace_Coefficient_n7",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL}
        },
        { &hf_oran_active_beamspace_coefficient_n8,
          { "N8", "oran_fh_cus.activeBeamspace_Coefficient_n8",
            FT_BOOLEAN, 8,
            TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL}
        },

        { &hf_oran_activeBeamspaceCoefficientMask,
          { "activeBeamspaceCoefficientMask", "oran_fh_cus.activeBeamspaceCoefficientMask",
            FT_UINT8, BASE_HEX,
            NULL, 0xff,
            NULL, HFILL}
        },
        { &hf_oran_activeBeamspaceCoefficientMask_bits_set,
          { "Array elements set", "oran_fh_cus.activeBeamspaceCoefficientMask.bits-set",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* Section 7.7.6.6 */
        { &hf_oran_se6_repetition,
          { "repetition", "oran_fh_cus.repetition",
            FT_BOOLEAN, BASE_NONE,
            TFS(&repetition_se6_tfs), 0x0,
            "Repetition of a highest priority data section for C-Plane", HFILL}
        },
        /* 7.7.20.9 */
        { &hf_oran_rbgSize,
          { "rbgSize", "oran_fh_cus.rbgSize",
            FT_UINT8, BASE_HEX,
            VALS(rbg_size_vals), 0x70,
            "Number of PRBs of the resource block groups allocated by the bit mask", HFILL}
        },
        /* 7.7.20.10 */
        { &hf_oran_rbgMask,
          { "rbgMask", "oran_fh_cus.rbgMask",
            FT_UINT32, BASE_HEX,
            NULL, 0x0fffffff,
            "Each bit indicates whether a corresponding resource block group is present", HFILL}
        },
        /* 7.7.6.5.  Also 7.7.12.3 and 7.7.19.5 */
        { &hf_oran_noncontig_priority,
          { "priority", "oran_fh_cus.priority",
            FT_UINT8, BASE_HEX,
            VALS(priority_vals), 0xc0,
            NULL, HFILL}
        },

        /* 7.7.6.4 */
        { &hf_oran_symbol_mask,
          { "symbolMask", "oran_fh_cus.symbolMask",
            FT_UINT16, BASE_HEX,
            NULL, 0x3fff,
            "Each bit indicates whether the rbgMask applies to a given symbol in the slot", HFILL}
        },
        { &hf_oran_symbol_mask_s13,
          { "symbol 13", "oran_fh_cus.symbolMask.symbol-13",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x2000,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s12,
          { "symbol 12", "oran_fh_cus.symbolMask.symbol-12",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x1000,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s11,
          { "symbol 11", "oran_fh_cus.symbolMask.symbol-11",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0800,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s10,
          { "symbol 10", "oran_fh_cus.symbolMask.symbol-10",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0400,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s9,
          { "symbol 9", "oran_fh_cus.symbolMask.symbol-9",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0200,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s8,
          { "symbol 8", "oran_fh_cus.symbolMask.symbol-8",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0100,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s7,
          { "symbol 7", "oran_fh_cus.symbolMask.symbol-7",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0080,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s6,
          { "symbol 6", "oran_fh_cus.symbolMask.symbol-6",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0040,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s5,
          { "symbol 5", "oran_fh_cus.symbolMask.symbol-5",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0020,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s4,
          { "symbol 4", "oran_fh_cus.symbolMask.symbol-4",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0010,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s3,
          { "symbol 3", "oran_fh_cus.symbolMask.symbol-3",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0008,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s2,
          { "symbol 2", "oran_fh_cus.symbolMask.symbol-2",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0004,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s1,
          { "symbol 1", "oran_fh_cus.symbolMask.symbol-1",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0002,
            NULL, HFILL}
        },
        { &hf_oran_symbol_mask_s0,
          { "symbol 0", "oran_fh_cus.symbolMask.symbol-0",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0001,
            NULL, HFILL}
        },


        /* 7.7.22.2 */
        { &hf_oran_ack_nack_req_id,
          { "ackNackReqId", "oran_fh_cus.ackNackReqId",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            "Indicates the ACK/NACK request ID of a section description", HFILL}
        },

        /* Subtree for next 2 items */
        { &hf_oran_frequency_range,
          { "Frequency Range", "oran_fh_cus.frequencyRange",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* 7.7.12.4 */
        { &hf_oran_off_start_prb,
          { "offStartPrb", "oran_fh_cus.offStartPrb",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Offset of PRB range start", HFILL}
        },
        /* 7.7.12.5 */
        { &hf_oran_num_prb,
          { "numPrb", "oran_fh_cus.numPrb",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Number of PRBs in PRB range", HFILL}
        },

        /* symbolId 8.3.3.7 */
        { &hf_oran_symbolId,
          { "Symbol Identifier", "oran_fh_cus.symbolId",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            "Identifies a symbol number within a slot", HFILL}
        },

        /* startPrbu 8.3.3.11 */
        { &hf_oran_startPrbu,
          { "startPrbu", "oran_fh_cus.startPrbu",
            FT_UINT16, BASE_DEC,
            NULL, 0x03ff,
            "starting PRB of user plane section", HFILL}
        },

        /* numPrbu 8.3.3.12 */
        { &hf_oran_numPrbu,
          { "numPrbu", "oran_fh_cus.numPrbu",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "number of PRBs per user plane section", HFILL}
        },

        /* 7.7.1.3 */
        { &hf_oran_bfwCompParam,
          { "bfwCompParam", "oran_fh_cus.bfwCompParam",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Beamforming weight compression parameter", HFILL}
        },

        /* 6.3.3.13 */
        { &hf_oran_udCompHdrMeth,
          { "User Data Compression Method", "oran_fh_cus.udCompHdrMeth",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(ud_comp_header_meth), 0x0f,
            "Defines the compression method for the user data in every section in the C-Plane message", HFILL}
        },
        { &hf_oran_udCompHdrMeth_pref,
          { "User Data Compression Method", "oran_fh_cus.udCompHdrMeth",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(ud_comp_header_meth), 0x0,
            "Defines the compression method for the user data in every section in the C-Plane message", HFILL}
        },
        /* 8.3.3.18 */
        { &hf_oran_udCompLen,
          { "udCompLen", "oran_fh_cus.udCompLen",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "PRB field length in octets", HFILL}
        },

        /* 7.5.2.10 */
        { &hf_oran_udCompHdrIqWidth,
          { "User Data IQ width", "oran_fh_cus.udCompHdrWidth",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(ud_comp_header_width), 0xf0,
            "Defines the IQ bit width for the user data in every section in the C-Plane message", HFILL}
        },
        { &hf_oran_udCompHdrIqWidth_pref,
          { "User Data IQ width", "oran_fh_cus.udCompHdrWidth",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Defines the IQ bit width for the user data in every section in the C-Plane message", HFILL}
        },

        { &hf_oran_sinrCompHdrIqWidth_pref,
          { "SINR IQ width", "oran_fh_cus.sinrCompHdrWidth",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Defines the IQ bit width for SINR data in section type 9", HFILL}
        },
        { &hf_oran_sinrCompHdrMeth_pref,
          { "SINR Compression Method", "oran_fh_cus.sinrCompHdrMeth",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(ud_comp_header_meth), 0x0,
            "Defines the compression method for SINR data in section type 9", HFILL}
         },

        /* Section 8.3.3.15 (not always present - depends upon meth) */
        { &hf_oran_udCompParam,
          { "User Data Compression Parameter", "oran_fh_cus.udCompParam",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Applies to whatever compression method is specified by the associated sectionID's compMeth value", HFILL}
        },
        /* 8.3.3.18 */
        { &hf_oran_sReSMask,
          { "sReSMask", "oran_fh_cus.sReSMask",
            FT_UINT16, BASE_HEX,
            NULL, 0xf0ff,
            "selective RE sending mask", HFILL}
        },

        { &hf_oran_sReSMask_re12,
          { "RE-12", "oran_fh_cus.sReSMask-re12",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x8000,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re11,
          { "RE-11", "oran_fh_cus.sReSMask-re11",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x4000,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re10,
          { "RE-10", "oran_fh_cus.sReSMask-re10",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x2000,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re9,
          { "RE-9", "oran_fh_cus.sReSMask-re9",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x1000,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re8,
          { "RE-8", "oran_fh_cus.sReSMask-re8",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0080,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re7,
          { "RE-7", "oran_fh_cus.sReSMask-re7",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0040,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re6,
          { "RE-6", "oran_fh_cus.sReSMask-re6",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0020,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re5,
          { "RE-5", "oran_fh_cus.sReSMask-re5",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0010,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re4,
          { "RE-4", "oran_fh_cus.sReSMask-re4",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0008,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re3,
          { "RE-3", "oran_fh_cus.sReSMask-re3",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0004,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re2,
          { "RE-2", "oran_fh_cus.sReSMask-re2",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0002,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask_re1,
          { "RE-1", "oran_fh_cus.sReSMask-re1",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0001,
            NULL, HFILL}
        },

        /* 8.3.3.20 */
        { &hf_oran_sReSMask1,
          { "sReSMask1", "oran_fh_cus.sReSMask1",
            FT_UINT16, BASE_HEX,
            NULL, 0x0fff,
            "selective RE sending mask 1", HFILL}
        },
        /* 8.3.3.21 */
        { &hf_oran_sReSMask2,
          { "sReSMask2", "oran_fh_cus.sReSMask2",
            FT_UINT16, BASE_HEX,
            NULL, 0x0fff,
            "selective RE sending mask 2", HFILL}
        },

        { &hf_oran_sReSMask1_2_re12,
          { "RE-12", "oran_fh_cus.sReSMask-re12",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0800,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask1_2_re11,
          { "RE-11", "oran_fh_cus.sReSMask-re11",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0400,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask1_2_re10,
          { "RE-10", "oran_fh_cus.sReSMask-re10",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0200,
            NULL, HFILL}
        },
        { &hf_oran_sReSMask1_2_re9,
          { "RE-9", "oran_fh_cus.sReSMask-re9",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0100,
            NULL, HFILL}
        },

        /* Section 6.3.3.15 */
        { &hf_oran_iSample,
          { "iSample", "oran_fh_cus.iSample",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "In-phase Sample value", HFILL}
        },

        /* Section 6.3.3.16 */
        { &hf_oran_qSample,
          { "qSample", "oran_fh_cus.qSample",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "Quadrature Sample value", HFILL}
        },

        { &hf_oran_exponent,
          { "Exponent", "oran_fh_cus.exponent",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "Exponent applicable to the I & Q mantissas", HFILL }
        },

        { &hf_oran_iq_user_data,
          { "IQ User Data", "oran_fh_cus.iq_user_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "Used for the In-phase and Quadrature sample mantissa", HFILL }
        },


        { &hf_oran_u_section_ul_symbol_time,
          { "Microseconds since first UL U-plane frame for this symbol", "oran_fh_cus.us-since-first-ul-frame",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oran_u_section_ul_symbol_frames,
          { "Number of UL frames sent for this symbol", "oran_fh_cus.number-ul-frames-in-symbol",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oran_u_section_ul_symbol_first_frame,
          { "First UL frame for this symbol", "oran_fh_cus.first-ul-frame-in-symbol",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0,
            NULL, HFILL }
        },
        { &hf_oran_u_section_ul_symbol_last_frame,
          { "Last UL frame for this symbol", "oran_fh_cus.last-ul-frame-in-symbol",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0,
            NULL, HFILL }
        },

        { &hf_oran_c_eAxC_ID,
          { "c_eAxC_ID", "oran_fh_cus.c_eaxc_id",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "This is a calculated field for the c_eAxC ID, which identifies the message stream", HFILL }
        },

        { &hf_oran_refa,
          { "RefA", "oran_fh_cus.refa",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "This is a calculated field for the RefA ID, which provides a reference in time", HFILL }
        },


        /* Section 7.5.2.15 */
        { &hf_oran_ciCompHdr,
          { "ciCompHdr", "oran_fh_cus.ciCompHdr",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_ciCompHdrMeth,
          { "User Data Compression Method", "oran_fh_cus.ciCompHdrMeth",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(ud_comp_header_meth), 0x0e,
            "Defines the compression method for the user data in every section in the C-Plane message", HFILL}
         },
        { &hf_oran_ciCompHdrIqWidth,
          { "User Data IQ width", "oran_fh_cus.udCompHdrWidth",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(ud_comp_header_width), 0xf0,
            "Defines the IQ bit width for the user data in every section in the C-Plane message", HFILL}
        },
        { &hf_oran_ciCompOpt,
          { "ciCompOpt", "oran_fh_cus.ciCompOpt",
            FT_UINT8, BASE_DEC,
            VALS(ci_comp_opt_vals), 0x01,
            NULL, HFILL }
        },

        /* 7.7.11.7 */
        { &hf_oran_disable_bfws,
          { "disableBFWs", "oran_fh_cus.disableBFWs",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            "Indicate if BFWs under section extension are disabled", HFILL }
        },
        /* 7.7.11.8 */
        { &hf_oran_rad,
          { "RAD", "oran_fh_cus.rad",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            "Reset After PRB Discontinuity", HFILL }
        },
        /* 7.7.11.4 */
        { &hf_oran_num_bund_prbs,
          { "numBundPrb", "oran_fh_cus.numBundPrb",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Number of bundled PRBs per BFWs", HFILL }
        },
        { &hf_oran_beam_id,
          { "beamId", "oran_fh_cus.beamId",
            FT_UINT16, BASE_DEC,
            NULL, 0x7fff,
            NULL, HFILL }
        },
        { &hf_oran_num_weights_per_bundle,
          { "Num weights per bundle", "oran_fh_cus.num_weights_per_bundle",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "From dissector preference", HFILL }
        },

        { &hf_oran_samples_prb,
          {"PRB", "oran_fh_cus.prb",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Grouping of samples for a particular Physical Resource Block", HFILL}
         },

        /* 7.5.3.13 */
        { &hf_oran_ciSample,
          { "ciSample", "oran_fh_cus.ciSample",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Sample (I and Q values)", HFILL}
        },
        { &hf_oran_ciIsample,
          { "ciIsample", "oran_fh_cus.ciISample",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "Channel information complex value - I part", HFILL}
        },
        { &hf_oran_ciQsample,
          { "ciQsample", "oran_fh_cus.ciQSample",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            "Channel information complex value - Q part", HFILL}
        },

        /* 7.7.10.2 */
        { &hf_oran_beamGroupType,
          { "beamGroupType", "oran_fh_cus.beamGroupType",
            FT_UINT8, BASE_DEC,
            VALS(beam_group_type_vals), 0xc0,
            "The type of beam grouping", HFILL }
        },
        /* 7.7.10.3 */
        { &hf_oran_numPortc,
          { "numPortc", "oran_fh_cus.numPortc",
            FT_UINT8, BASE_DEC,
            NULL, 0x3f,
            "The number of eAxC ports", HFILL }
        },

        /* 7.7.4.2 (1 bit) */
        { &hf_oran_csf,
          { "csf", "oran_fh_cus.csf",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            "constellation shift flag", HFILL }
        },
        /* 7.7.4.3 */
        { &hf_oran_modcompscaler,
          { "modCompScaler", "oran_fh_cus.modcompscaler",
            FT_UINT16, BASE_DEC,
            NULL, 0x7fff,
            "modulation compression scaler value", HFILL }
        },

        /* 7.7.5.1 */
        { &hf_oran_modcomp_param_set,
          { "Set", "oran_fh_cus.modcomp-param-set",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },



        /* mcScaleReMask 7.7.5.2 (12 bits) */

        /* First entry (starts with msb within byte) */
        { &hf_oran_mc_scale_re_mask_re1,
          { "RE 1", "oran_fh_cus.mcscalermask-RE1",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x8000,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re2,
          { "RE 2", "oran_fh_cus.mcscalermask-RE2",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x4000,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re3,
          { "RE 3", "oran_fh_cus.mcscalermask-RE3",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x2000,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re4,
          { "RE 4", "oran_fh_cus.mcscalermask-RE4",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x1000,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re5,
          { "RE 5", "oran_fh_cus.mcscalermask-RE5",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0800,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re6,
          { "RE 6", "oran_fh_cus.mcscalermask-RE6",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0400,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re7,
          { "RE 7", "oran_fh_cus.mcscalermask-RE7",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0200,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re8,
          { "RE 8", "oran_fh_cus.mcscalermask-RE8",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0100,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re9,
          { "RE 9", "oran_fh_cus.mcscalermask-RE9",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0080,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re10,
          { "RE 10", "oran_fh_cus.mcscalermask-RE10",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0040,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re11,
          { "RE 11", "oran_fh_cus.mcscalermask-RE11",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0020,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re12,
          { "RE 12", "oran_fh_cus.mcscalermask-RE12",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0010,
            NULL, HFILL}
        },

        /* Even tries entry (starts with 5th bit within byte) */
        { &hf_oran_mc_scale_re_mask_re1_even,
          { "RE 1", "oran_fh_cus.mcscalermask-RE1",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0800,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re2_even,
          { "RE 2", "oran_fh_cus.mcscalermask-RE2",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0400,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re3_even,
          { "RE 3", "oran_fh_cus.mcscalermask-RE3",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0200,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re4_even,
          { "RE 4", "oran_fh_cus.mcscalermask-RE4",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0100,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re5_even,
          { "RE 5", "oran_fh_cus.mcscalermask-RE5",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0080,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re6_even,
          { "RE 6", "oran_fh_cus.mcscalermask-RE6",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0040,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re7_even,
          { "RE 7", "oran_fh_cus.mcscalermask-RE7",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0020,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re8_even,
          { "RE 8", "oran_fh_cus.mcscalermask-RE8",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0010,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re9_even,
          { "RE 9", "oran_fh_cus.mcscalermask-RE9",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0008,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re10_even,
          { "RE 10", "oran_fh_cus.mcscalermask-RE10",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0004,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re11_even,
          { "RE 11", "oran_fh_cus.mcscalermask-RE11",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0002,
            NULL, HFILL}
        },
        { &hf_oran_mc_scale_re_mask_re12_even,
          { "RE 12", "oran_fh_cus.mcscalermask-RE12",
            FT_BOOLEAN, 16,
            TFS(&tfs_applicable_not_applicable), 0x0001,
            NULL, HFILL}
        },

        { &hf_oran_mc_scale_re_mask,
          { "mcScaleReMask", "oran_fh_cus.mcscaleremask",
            FT_UINT16, BASE_HEX,
            NULL, 0xfff0,
            "modulation compression power scale RE mask", HFILL }
        },
        { &hf_oran_mc_scale_re_mask_even,
          { "mcScaleReMask", "oran_fh_cus.mcscaleremask",
            FT_UINT16, BASE_HEX,
            NULL, 0x0fff,
            "modulation compression power scale RE mask", HFILL }
        },

        /* mcScaleOffset 7.7.5.4 (15 bits) */
        { &hf_oran_mc_scale_offset,
          { "mcScaleOffset", "oran_fh_cus.mcscaleoffset",
            FT_UINT24, BASE_DEC,
            NULL, 0x0,
            "scaling value for modulation compression", HFILL }
        },
        /* eAxCmask (7.7.7.2) */
        { &hf_oran_eAxC_mask,
          { "eAxC Mask", "oran_fh_cus.eaxcmask",
            FT_UINT16, BASE_HEX,
            NULL, 0xffff,
            "Which eAxC_ID values the C-Plane message applies to", HFILL }
        },
        /* technology (interface name) 7.7.9.2 */
        { &hf_oran_technology,
          { "Technology", "oran_fh_cus.technology",
            FT_UINT8, BASE_DEC,
            VALS(interface_name_vals), 0x0,
            "Interface name (that C-PLane section applies to)", HFILL }
        },
        /* Exttype 14 (7.7.14.2) */
        { &hf_oran_nullLayerInd,
          { "nullLayerInd", "oran_fh_cus.nulllayerind",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            "Whether corresponding layer is nulling-layer or not", HFILL }
        },

        /* Exttype 19 */
        /* 7.7.19.3 */
        { &hf_oran_se19_repetition,
          { "repetition", "oran_fh_cus.repetition",
            FT_BOOLEAN, BASE_NONE,
            TFS(&repetition_se19_tfs), 0x0,
            "repeat port info flag", HFILL}
        },
        /* 7.7.19.8 */
        /* TODO: break down into each RE as done for 7.5.3.5 ? */
        { &hf_oran_portReMask,
          { "portReMask", "oran_fh_cus.portReMask",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), 0x0fff,
            "RE bitmask per port", HFILL }
        },
        /* 7.7.19.9 */
        { &hf_oran_portSymbolMask,
          { "portSymbolMask", "oran_fh_cus.portSymbolMask",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), 0x3fff,
            "Symbol bitmask port port", HFILL }
        },

        { &hf_oran_ext19_port,
          {"Port", "oran_fh_cus.ext19.port",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Entry for a given port in ext19", HFILL}
         },

        /* Ext 13 */
        { &hf_oran_prb_allocation,
          {"PRB allocation", "oran_fh_cus.prb-allocation",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
         },
        /* 7.7.13.2 */
        { &hf_oran_nextSymbolId,
          { "nextSymbolId", "oran_fh_cus.nextSymbolId",
            FT_UINT8, BASE_DEC,
            NULL, 0x3c,
            "offset of PRB range start", HFILL }
        },
        /* 7.7.13.3 */
        { &hf_oran_nextStartPrbc,
          { "nextStartPrbc", "oran_fh_cus.nextStartPrbc",
            FT_UINT16, BASE_DEC,
            NULL, 0x03ff,
            "number of PRBs in PRB range", HFILL }
        },

        /* Puncturing patters as appears in SE 20 */
        { &hf_oran_puncPattern,
          { "puncPattern", "oran_fh_cus.puncPattern",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* 7.7.20.2 numPuncPatterns */
        { &hf_oran_numPuncPatterns,
          { "numPuncPatterns", "oran_fh_cus.numPuncPatterns",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "number of puncturing patterns", HFILL }
        },
        /* 7.7.20.3 symbolMask */
        { &hf_oran_symbolMask_ext20,
          { "symbolMask", "oran_fh_cus.symbolMask",
            FT_UINT16, BASE_HEX,
            NULL, 0xfffc,
            "Bitmask where each bit indicates the symbols associated with the puncturing pattern", HFILL}
        },
        /* 7.7.20.4 startPuncPrb */
        { &hf_oran_startPuncPrb,
          { "startPuncPrb", "oran_fh_cus.startPuncPrb",
            FT_UINT16, BASE_DEC,
            NULL, 0x03ff,
            "starting PRB to which one puncturing pattern applies", HFILL}
        },
        /* 7.7.20.5 numPuncPrb */
        { &hf_oran_numPuncPrb,
          { "numPuncPrb", "oran_fh_cus.numPuncPrb",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "the number of PRBs of the puncturing pattern", HFILL}
        },
        /* 7.7.20.6 puncReMask */
        { &hf_oran_puncReMask,
          { "puncReMask", "oran_fh_cus.puncReMask",
            FT_UINT16, BASE_DEC,
            NULL, 0xffc0,
            "puncturing pattern RE mask", HFILL}
        },
        /* 7.7.20.12 multiSDScope */
        { &hf_oran_multiSDScope,
          { "multiSDScope", "oran_fh_cus.multiSDScope",
            FT_BOOLEAN, 8,
            TFS(&multi_sd_scope_tfs), 0x02,
            "multiple section description scope flag", HFILL}
        },
        /* 7.7.20.4 rbgIncl */
        { &hf_oran_RbgIncl,
          { "rbgIncl", "oran_fh_cus.rbgIncl",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            "rbg included flag", HFILL}
        },

        /* 7.7.21.2 ciPrbGroupSize */
        { &hf_oran_ci_prb_group_size,
          { "ciPrbGroupSize", "oran_fh_cus.ciPrbGroupSize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "channel information PRB group size", HFILL}
        },
        /* 7.21.3 */
        { &hf_oran_prg_size_st5,
          { "prgSize", "oran_fh_cus.prgSize",
            FT_UINT8, BASE_DEC,
            VALS(prg_size_st5_vals), 0x03,
            "precoding resource block group size", HFILL}
        },
        { &hf_oran_prg_size_st6,
          { "prgSize", "oran_fh_cus.prgSize",
            FT_UINT8, BASE_DEC,
            VALS(prg_size_st6_vals), 0x03,
            "precoding resource block group size", HFILL}
        },

        /* 7.7.17.2 numUeID */
        { &hf_oran_num_ueid,
          { "numUeID", "oran_fh_cus.numUeID",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "number of ueIDs per user", HFILL}
        },

        /* 7.7.16.2 antMask */
        { &hf_oran_antMask,
          { "antMask", "oran_fh_cus.antMask",
            FT_UINT64, BASE_HEX,
            NULL, 0xffffffffffffffff,
            "indices of antennas to be pre-combined per RX endpoint", HFILL}
        },

        /* 7.7.18.2 transmissionWindowOffset */
        { &hf_oran_transmissionWindowOffset,
          { "transmissionWindowOffset", "oran_fh_cus.transmissionWindowOffset",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "start of the transmission window as an offset to when the transmission window would have been without this parameter, i.e. (Ta3_max - Ta3_min)", HFILL}
        },
        /* 7.7.18.3 transmissionWindowSize */
        { &hf_oran_transmissionWindowSize,
          { "transmissionWindowSize", "oran_fh_cus.transmissionWindowSize",
            FT_UINT16, BASE_DEC,
            NULL, 0x3fff,
            "size of the transmission window in resolution µs", HFILL}
        },
        /* 7.7.18.4 toT */
        { &hf_oran_toT,
          { "toT", "oran_fh_cus.toT",
            FT_UINT8, BASE_DEC,
            VALS(type_of_transmission_vals), 0x03,
            "type of transmission", HFILL}
        },

        /* 7.7.2.2 bfaCompHdr */
        { &hf_oran_bfaCompHdr,
          { "bfaCompHdr", "oran_fh_cus.bfaCompHdr",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "beamforming attributes compression header", HFILL}
        },
        /* 7.7.2.2-2: bfAzPtWidth */
        { &hf_oran_bfAzPtWidth,
          { "bfAzPtWidth", "oran_fh_cus.bfAzPtWidth",
            FT_UINT8, BASE_DEC,
            VALS(bfa_bw_vals), 0x38,
            NULL, HFILL}
        },
        /* 7.7.2.2-3: bfZePtWidth */
        { &hf_oran_bfZePtWidth,
          { "bfZePtWidth", "oran_fh_cus.bfZePtWidth",
            FT_UINT8, BASE_DEC,
            VALS(bfa_bw_vals), 0x07,
            NULL, HFILL}
        },
        /* 7.7.2.2-4: bfAz3ddWidth */
        { &hf_oran_bfAz3ddWidth,
          { "bfAz3ddWidth", "oran_fh_cus.bfAz3ddWidth",
            FT_UINT8, BASE_DEC,
            VALS(bfa_bw_vals), 0x38,
            NULL, HFILL}
        },
        /* 7.7.2.2-5: bfZe3ddWidth */
        { &hf_oran_bfZe3ddWidth,
          { "bfZe3ddWidth", "oran_fh_cus.bfZe3ddWidth",
            FT_UINT8, BASE_DEC,
            VALS(bfa_bw_vals), 0x07,
            NULL, HFILL}
        },

        /* 7.7.2.3 bfAzPt */
        { &hf_oran_bfAzPt,
          { "bfAzPt", "oran_fh_cus.bfAzPt",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "beamforming azimuth pointing parameter", HFILL}
        },
        /* 7.7.2.4 bfZePt */
        { &hf_oran_bfZePt,
          { "bfZePt", "oran_fh_cus.bfZePt",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "beamforming zenith pointing parameter", HFILL}
        },
        /* 7.7.2.5 bfAz3dd */
        { &hf_oran_bfAz3dd,
          { "bfAz3dd", "oran_fh_cus.bfAz3dd",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "beamforming azimuth beamwidth parameter", HFILL}
        },
        /* 7.7.2.6 bfZe3dd */
        { &hf_oran_bfZe3dd,
          { "bfZe3dd", "oran_fh_cus.bfZe3dd",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "beamforming zenith beamwidth parameter", HFILL}
        },

        /* 7.7.2.7 bfAzSl */
        { &hf_oran_bfAzSl,
          { "bfAzSl", "oran_fh_cus.bfAzSl",
            FT_UINT8, BASE_DEC,
            VALS(sidelobe_suppression_vals), 0x38,
            "beamforming azimuth sidelobe parameter", HFILL}
        },
        /* 7.7.2.8 bfZeSl */
        { &hf_oran_bfZeSl,
          { "bfZeSl", "oran_fh_cus.bfZeSl",
            FT_UINT8, BASE_DEC,
            VALS(sidelobe_suppression_vals), 0x07,
            "beamforming zenith sidelobe parameter", HFILL}
        },

        /* 7.5.2.17 */
        { &hf_oran_cmd_scope,
          { "cmdScope", "oran_fh_cus.cmdScope",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(cmd_scope_vals), 0x0f,
            "command scope", HFILL}
        },
        /* 7.5.2.18 */
        { &hf_oran_number_of_st4_cmds,
          { "numberOfST4Cmds", "oran_fh_cus.numberOfST4Cmds",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Number of Section Type 4 commands", HFILL}
        },

        { &hf_oran_st4_cmd_header,
          { "Command common header", "oran_fh_cus.st4CmdCommonHeader",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* 7.5.3.38 */
        { &hf_oran_st4_cmd_type,
          { "st4CmdType", "oran_fh_cus.st4CmdType",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(st4_cmd_type_vals), 0x0,
            NULL, HFILL}
        },
        /* 7.5.3.39 */
        { &hf_oran_st4_cmd_len,
          { "st4CmdLen", "oran_fh_cus.st4CmdLen",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Length of command in 32-bit words", HFILL}
        },
        /* 7.5.3.40 */
        { &hf_oran_st4_cmd_num_slots,
          { "numSlots", "oran_fh_cus.st4NumSlots",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Contiguous slots for which command is applicable", HFILL}
        },
        /* 7.5.3.41 */
        { &hf_oran_st4_cmd_ack_nack_req_id,
          { "ackNackReqId", "oran_fh_cus.ackNackReqId",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "ACK/NACK Request Id", HFILL}
        },

        { &hf_oran_st4_cmd,
          { "Command", "oran_fh_cus.st4Cmd",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* 7.5.3.52 */
        { &hf_oran_sleepmode_trx,
          { "sleepMode", "oran_fh_cus.sleepMode",
            FT_UINT8, BASE_HEX,
            VALS(sleep_mode_trx_vals), 0x03,
            NULL, HFILL}
        },
        { &hf_oran_sleepmode_asm,
          { "sleepMode", "oran_fh_cus.sleepMode",
            FT_UINT8, BASE_HEX,
            VALS(sleep_mode_asm_vals), 0x03,
            NULL, HFILL}
        },

        /* 7.5.3.51 */
        { &hf_oran_log2maskbits,
          { "log2MaskBits", "oran_fh_cus.log2MaskBits",
            FT_UINT8, BASE_HEX,
            VALS(log2maskbits_vals), 0x3c,
            "Number of bits to appear in antMask", HFILL}
        },
        /* 7.5.3.53 */
        { &hf_oran_num_slots_ext,
          { "numSlotsExt", "oran_fh_cus.numSlotsExt",
            FT_UINT24, BASE_HEX,
            NULL, 0x0fffff,
            NULL, HFILL}
        },
        /* 7.5.3.54 */
        { &hf_oran_antMask_trx_control,
          { "antMask", "oran_fh_cus.trxControl.antMask",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "which antennas should sleep or wake-up", HFILL}
        },
        /* 7.5.3.55 */
        { &hf_oran_ready,
          { "ready", "oran_fh_cus.ready",
            FT_BOOLEAN, 8,
            TFS(&ready_tfs), 0x01,
            "wake-up ready indicator", HFILL}
        },
        /* 7.5.3.34 */
        { &hf_oran_number_of_acks,
          { "numberOfAcks", "oran_fh_cus.numberOfAcks",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "number of ACKs for one eAxC_ID", HFILL}
        },
        /* 7.5.3.35 */
        { &hf_oran_number_of_nacks,
          { "numberOfNacks", "oran_fh_cus.numberOfNacks",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "number of NACKs for one eAxC_ID", HFILL}
        },
        /* 7.5.3.36 */
        { &hf_oran_ackid,
          { "ackId", "oran_fh_cus.ackId",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        /* 7.5.3.37 */
        { &hf_oran_nackid,
          { "nackId", "oran_fh_cus.nackId",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* Links between acknack requests & responses */
        { &hf_oran_acknack_request_frame,
          { "Request Frame", "oran_fh_cus.ackNackId.request-frame",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL}
        },
        { &hf_oran_acknack_request_time,
          { "Time since request in ms", "oran_fh_cus.ackNackId.time-since-request",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            "Time between request and response", HFILL}
        },
        { &hf_oran_acknack_request_type,
          { "Request Type", "oran_fh_cus.ackNackId.request-type",
            FT_UINT32, BASE_DEC,
            VALS(acknack_type_vals), 0x0,
            NULL, HFILL}
        },
        { &hf_oran_acknack_response_frame,
          { "Response Frame", "oran_fh_cus.ackNackId.response-frame",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL}
        },
        { &hf_oran_acknack_response_time,
          { "Time to response in ms", "oran_fh_cus.ackNackId.time-to-response",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            "Time between request and response", HFILL}
        },

        /* 7.5.3.43 */
        { &hf_oran_disable_tdbfns,
          { "disableTDBFNs", "oran_fh_cus.disableTDBFNs",
            FT_BOOLEAN, 8,
            TFS(&disable_tdbfns_tfs), 0x80,
            NULL, HFILL}
        },

        /* 7.5.3.44 */
        { &hf_oran_td_beam_group,
          { "tdBeamGrp", "oran_fh_cus.tdBeamGrp",
            FT_UINT16, BASE_HEX,
            NULL, 0x7fff,
            "Applies to symbolMask in command header", HFILL}
        },
        /* 7.5.3.43 */
        { &hf_oran_disable_tdbfws,
          { "disableTDBFWs", "oran_fh_cus.disableTDBFWs",
            FT_BOOLEAN, 8,
            TFS(&beam_numbers_included_tfs), 0x80,
            NULL, HFILL}
        },

        /* 7.5.3.56 */
        { &hf_oran_td_beam_num,
          { "tdBeamNum", "oran_fh_cus.tdBeamNum",
            FT_UINT16, BASE_HEX,
            NULL, 0x7fff,
            "time-domain beam number", HFILL}
        },

        /* 7.5.3.49 */
        { &hf_oran_dir_pattern,
          { "dirPattern", "oran_fh_cus.dirPattern",
            FT_BOOLEAN, 16,
            TFS(&symbol_direction_tfs), 0x3fff,
            "symbol data direction (gNB Tx/Rx) pattern", HFILL}
        },
        /* 7.5.3.50 */
        { &hf_oran_guard_pattern,
          { "guardPattern", "oran_fh_cus.guardPattern",
            FT_BOOLEAN, 16,
            TFS(&symbol_guard_tfs), 0x3fff,
            "guard pattern bitmask", HFILL}
        },

        /* For convenient filtering */
        { &hf_oran_cplane,
          { "C-Plane", "oran_fh_cus.c-plane",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_uplane,
          { "U-Plane", "oran_fh_cus.u-plane",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_bf,
          { "BeamForming", "oran_fh_cus.bf",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_zero_prb,
          { "Zero PRB", "oran_fh_cus.zero-prb",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            "All of the REs in this PRB are zero", HFILL}
        },

        /* 5.1.3.2.7 */
        { &hf_oran_ecpri_pcid,
          { "ecpriPcid", "oran_fh_cus.ecpriPcid",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            "IQ data transfer message series identifier", HFILL}
        },
        { &hf_oran_ecpri_rtcid,
          { "ecpriRtcid", "oran_fh_cus.ecpriRtcid",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            "Real time control data identifier", HFILL}
        },
        /* 5.1.3.2.8 */
        { &hf_oran_ecpri_seqid,
          { "ecpriSeqid", "oran_fh_cus.ecpriSeqid",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            "message identifier", HFILL}
        },

        /* 7.7.23.2 */
        { &hf_oran_num_sym_prb_pattern,
          { "numSymPrbPattern", "oran_fh_cus.numSymPrbPattern",
            FT_UINT8, BASE_DEC,
            NULL, 0xf0,
            "number of symbol and resource block patterns", HFILL}
        },
        /* 7.7.23.11 */
        { &hf_oran_prb_mode,
          { "prbMode", "oran_fh_cus.prbMode",
            FT_BOOLEAN, 8,
            TFS(&prb_mode_tfs), 0x01,
            "PRB Mode", HFILL}
        },

        { &hf_oran_sym_prb_pattern,
          { "symPrbPattern", "oran_fh_cus.symPrbPattern",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* 7.7.23.3 */
        { &hf_oran_sym_mask,
          { "symMask", "oran_fh_cus.symMask",
            FT_UINT16, BASE_HEX,
            NULL, 0x3fff,
            "symbol mask part of symPrbPattern", HFILL}
        },
        /* 7.7.23.5 */
        {&hf_oran_num_mc_scale_offset,
         {"numMcScaleOffset", "oran_fh_cus.numMcScaleOffset",
          FT_UINT8, BASE_DEC,
          NULL, 0xf0,
          "number of modulation compression scaling value per symPrbPattern",
          HFILL}
        },
        /* 7.7.23.4 */
        { &hf_oran_prb_pattern,
          { "prbPattern", "oran_fh_cus.prbPattern",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "resource block pattern part of symPrbPattern", HFILL}
        },

        /* 7.7.3.2 */
        { &hf_oran_codebook_index,
          { "codebookIndex", "oran_fh_cus.codebookIndex",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "precoder codebook used for transmission", HFILL}
        },
        /* 7.7.3.3 */
        { &hf_oran_layerid,
          { "layerID", "oran_fh_cus.layerID",
            FT_UINT8, BASE_DEC,
            NULL, 0xf0,
            "Layer ID for DL transmission", HFILL}
        },
        /* 7.7.3.5 */
        { &hf_oran_numlayers,
          { "numLayers", "oran_fh_cus.numLayers",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "number of layers for DL transmission", HFILL}
        },
        /* 7.7.3.4 */
        { &hf_oran_txscheme,
          { "txScheme", "oran_fh_cus.txScheme",
            FT_UINT8, BASE_DEC,
            NULL, 0xf0,
            "transmission scheme", HFILL}
        },
        /* 7.7.3.6 */
        { &hf_oran_crs_remask,
          { "crsReMask", "oran_fh_cus.crsReMask",
            FT_UINT16, BASE_HEX,
            NULL, 0x0fff,
            "CRS resource element mask", HFILL}
        },
        /* 7.7.3.8 */
        { &hf_oran_crs_shift,
          { "crsShift", "oran_fh_cus.crsShift",
            FT_UINT8, BASE_HEX,
            NULL, 0x80,
            "CRS resource element mask", HFILL}
        },
        /* 7.7.3.7 */
        { &hf_oran_crs_symnum,
          { "crsSymNum", "oran_fh_cus.crsSymNum",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            "CRS symbol number indication", HFILL}
        },
        /* 7.7.3.9 */
        { &hf_oran_beamid_ap1,
          { "beamIdAP1", "oran_fh_cus.beamIdAP1",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f,
            "beam id to be used for antenna port 1", HFILL}
        },
        /* 7.7.3.10 */
        { &hf_oran_beamid_ap2,
          { "beamIdAP2", "oran_fh_cus.beamIdAP2",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f,
            "beam id to be used for antenna port 2", HFILL}
        },
        /* 7.7.3.11 */
        { &hf_oran_beamid_ap3,
          { "beamIdAP3", "oran_fh_cus.beamIdAP3",
            FT_UINT16, BASE_DEC,
            NULL, 0x7f,
            "beam id to be used for antenna port 3", HFILL}
        },

        /* 7.7.10.3a */
        { &hf_oran_port_list_index,
          { "portListIndex", "oran_fh_cus.portListIndex",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "the index of an eAxC_ID in the port-list", HFILL}
        },

        { &hf_oran_alpn_per_sym,
          { "alpnPerSym", "oran_fh_cus.alpnPerSym",
            FT_UINT8, BASE_HEX,
            VALS(alpn_per_sym_vals), 0x80,
            NULL, HFILL}
        },
        { &hf_oran_ant_dmrs_snr,
          { "antDmrsSnr", "oran_fh_cus.antDmrsSnr",
            FT_UINT8, BASE_HEX,
            VALS(ant_dmrs_snr_vals), 0x40,
            NULL, HFILL}
        },

        /* 7.7.24.6 */
        { &hf_oran_user_group_size,
          { "userGroupSize", "oran_fh_cus.userGroupSize",
            FT_UINT8, BASE_DEC,
            NULL, 0x1f,
            "number of UE data layers in the user group identified by userGroupId", HFILL}
        },
        /* 7.7.24.7 */
        { &hf_oran_user_group_id,
          { "userGroupId", "oran_fh_cus.userGroupId",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "indicates user group described by the section", HFILL}
        },
        /* 7.7.24.8 */
        { &hf_oran_entry_type,
          { "entryType", "oran_fh_cus.entryType",
            FT_UINT8, BASE_DEC,
            VALS(entry_type_vals), 0xe0,
            "indicates format of the entry", HFILL}
        },
        /* 7.7.24.9 */
        { &hf_oran_dmrs_port_number,
          { "dmrsPortNumber", "oran_fh_cus.dmrsPortNumber",
            FT_UINT8, BASE_DEC,
            NULL, 0x1f,
            "DMRS antenna port number for the associated ueId", HFILL}
        },
        /* 7.7.24.10 */
        { &hf_oran_ueid_reset,
          { "ueidReset", "oran_fh_cus.ueidReset",
            FT_BOOLEAN, 8,
            TFS(&tfs_ueid_reset), 0x80,
            "same UEID as the previous slot", HFILL}
        },
        /* 7.7.24.11 */
        { &hf_oran_dmrs_symbol_mask,
          { "dmrsSymbolMask", "oran_fh_cus.dmrsSymbolMask",
            FT_UINT16, BASE_HEX,
            NULL, 0x3fff,
            "symbols within the slot containing DMRS", HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s13,
          { "symbol 13", "oran_fh_cus.dmrsSymbolMask.symbol-13",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x2000,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s12,
          { "symbol 12", "oran_fh_cus.dmrsSymbolMask.symbol-12",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x1000,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s11,
          { "symbol 11", "oran_fh_cus.dmrsSymbolMask.symbol-11",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0800,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s10,
          { "symbol 10", "oran_fh_cus.dmrsSymbolMask.symbol-10",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0400,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s9,
          { "symbol 9", "oran_fh_cus.dmrsSymbolMask.symbol-9",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0200,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s8,
          { "symbol 8", "oran_fh_cus.dmrsSymbolMask.symbol-8",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0100,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s7,
          { "symbol 7", "oran_fh_cus.dmrsSymbolMask.symbol-7",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0080,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s6,
          { "symbol 6", "oran_fh_cus.dmrsSymbolMask.symbol-6",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0040,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s5,
          { "symbol 5", "oran_fh_cus.dmrsSymbolMask.symbol-5",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0020,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s4,
          { "symbol 4", "oran_fh_cus.dmrsSymbolMask.symbol-4",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0010,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s3,
          { "symbol 3", "oran_fh_cus.dmrsSymbolMask.symbol-3",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0008,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s2,
          { "symbol 2", "oran_fh_cus.dmrsSymbolMask.symbol-2",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0004,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s1,
          { "symbol 1", "oran_fh_cus.dmrsSymbolMask.symbol-1",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0002,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_symbol_mask_s0,
          { "symbol 0", "oran_fh_cus.dmrsSymbolMask.symbol-0",
            FT_BOOLEAN, 16,
            TFS(&tfs_present_not_present), 0x0001,
            NULL, HFILL}
        },

        /* 7.7.24.12 */
        { &hf_oran_scrambling,
          { "scrambling", "oran_fh_cus.scrambling",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            "used to calculate the seed value required to initialize pseudo-random generator", HFILL}
        },
        /* 7.7.24.13 */
        { &hf_oran_nscid,
          { "nscid", "oran_fh_cus.nscid",
            FT_UINT8, BASE_HEX,
            NULL, 0x80,
            "used to calculate the seed value for pseudo-random generator", HFILL}
        },
        /* 7.7.24.14 */
        { &hf_oran_dtype,
          { "dType", "oran_fh_cus.dType",
            FT_UINT8, BASE_HEX,
            VALS(dtype_vals), 0x40,
            "PUSCH DMRS configuration type", HFILL}
        },
        /* 7.7.24.15 */
        { &hf_oran_cmd_without_data,
          { "cmdWithoutData", "oran_fh_cus.cmdWithoutData",
            FT_UINT8, BASE_HEX,
            NULL, 0x30,
            "number of DMRS CDM groups without data", HFILL}
        },
        /* 7.7.24.16 */
        { &hf_oran_lambda,
          { "lambda", "oran_fh_cus.lambda",
            FT_UINT8, BASE_HEX,
            NULL, 0x0c,
            NULL, HFILL}
        },
        /* 7.7.24.19 */
        { &hf_oran_first_prb,
          { "firstPrb", "oran_fh_cus.firstPrb",
            FT_UINT16, BASE_DEC,
            NULL, 0x03fe,
            NULL, HFILL}
        },
        /* 7.7.24.20 */
        { &hf_oran_last_prb,
          { "lastPrb", "oran_fh_cus.lastPrb",
            FT_UINT16, BASE_DEC,
            NULL, 0x01ff,
            NULL, HFILL}
        },

        /* 7.7.24.17 */
        /* TODO: add value_string */
        { &hf_oran_low_papr_type,
          { "lowPaprType", "oran_fh_cus.lowPaprType",
            FT_UINT8, BASE_HEX,
            VALS(papr_type_vals), 0x30,
            NULL, HFILL}
        },
        /* 7.7.24.18 */
        { &hf_oran_hopping_mode,
          { "hoppingMode", "oran_fh_cus.hoppingMode",
            FT_UINT8, BASE_HEX,
            VALS(hopping_mode_vals), 0x0c,
            NULL, HFILL}
        },

        { &hf_oran_tx_win_for_on_air_symbol_l,
          { "txWinForOnAirSymbol", "oran_fh_cus.txWinForOnAirSymbol",
            FT_UINT8, BASE_DEC,
            NULL, 0xf0,
            NULL, HFILL}
        },
        { &hf_oran_tx_win_for_on_air_symbol_r,
          { "txWinForOnAirSymbol", "oran_fh_cus.txWinForOnAirSymbol",
            FT_UINT8, BASE_DEC,
            NULL, 0x0f,
            NULL, HFILL}
        },
        /* 7.7.26.2 */
        { &hf_oran_num_fo_fb,
          { "numFoFb", "oran_fh_cus.numFoFb",
            FT_UINT8, BASE_DEC,
            NULL, 0x7f,
            "number of frequency offset feedback", HFILL}
        },
        /* 7.7.26.3 */
        { &hf_oran_freq_offset_fb,
          { "freqOffsetFb", "oran_fh_cus.freqOffsetFb",
            FT_UINT16, BASE_HEX_DEC | BASE_RANGE_STRING,
            RVALS(freq_offset_fb_values), 0x0,
            "UE frequency offset feedback", HFILL}
        },

        /* 7.7.28.2 */
        { &hf_oran_num_ue_sinr_rpt,
          { "numUeSinrRpt", "oran_fh_cus.numUeSinrRpt",
            FT_UINT8, BASE_DEC,
            NULL, 0x1f,
            "number of sinr reported UEs {1 - 12}", HFILL}
        },

        /* 7.5.2.19 */
        { &hf_oran_num_sinr_per_prb,
          { "numSinrPerPrb", "oran_fh_cus.numSinrPerPrb",
            FT_UINT8, BASE_DEC,
            VALS(num_sinr_per_prb_vals), 0x70,
            "number of SINR values per PRB", HFILL}
        },
        { &hf_oran_num_sinr_per_prb_right,
          { "numSinrPerPrb", "oran_fh_cus.numSinrPerPrb",
            FT_UINT8, BASE_DEC,
            VALS(num_sinr_per_prb_vals), 0x07,
            "number of SINR values per PRB", HFILL}
        },

        /* 7.5.3.68 */
        { &hf_oran_sinr_value,
          { "sinrValue", "oran_fh_cus.sinrValue",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        { &hf_oran_measurement_report,
          { "Measurement Report", "oran_fh_cus.measurement-report",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        /* 7.5.3.57 */
        { &hf_oran_mf,
          { "mf", "oran_fh_cus.mf",
            FT_BOOLEAN, 8,
            TFS(&measurement_flag_tfs), 0x80,
            "measurement flag", HFILL}
        },
        /* 7.5.3.59 */
        { &hf_oran_meas_data_size,
          { "measDataSize", "oran_fh_cus.measDataSize",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "measurement data size (in words)", HFILL}
        },

        /* 7.5.3.58 */
        { &hf_oran_meas_type_id,
          { "measTypeId", "oran_fh_cus.measTypeId",
            FT_UINT8, BASE_DEC,
            VALS(meas_type_id_vals), 0x7F,
            "measurement report type identifier", HFILL}
        },
        /* 7.5.3.66 */
        { &hf_oran_num_elements,
          { "numElements", "oran_fh_cus.numElements",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "measurement report type identifier", HFILL}
        },
        /* 7.5.3.60 */
        { &hf_oran_ue_tae,
          { "ueTae", "oran_fh_cus.ueTae",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(freq_offset_fb_values), 0x0,
            "UE Timing Advance Error", HFILL}
        },
        /* 7.5.3.61 */
        { &hf_oran_ue_layer_power,
          { "ueLayerPower", "oran_fh_cus.ueLayerPower",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(freq_offset_fb_values), 0x0,
            "UE Layer Power", HFILL}
        },

        /* 7.5.3.62 */
        { &hf_oran_ue_freq_offset,
          { "ueFreqOffset", "oran_fh_cus.ueFreqOffset",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(freq_offset_fb_values), 0x0,
            "UE frequency offset", HFILL}
        },
        /* 7.5.3.63 */
        { &hf_oran_ipn_power,
          { "ipnPower", "oran_fh_cus.ipnPower",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(freq_offset_fb_values), 0x0,
            "Interference plus Noise power", HFILL}
        },
        /* 7.5.3.64 */
        { &hf_oran_ant_dmrs_snr_val,
          { "antDmrsSnrVal", "oran_fh_cus.antDmrsSnrVal",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(freq_offset_fb_values), 0x0,
            "antenna DMRS-SNR", HFILL}
        },

        { &hf_oran_measurement_command,
          { "Measurement Command", "oran_fh_cus.measurement-command",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* 7.5.27.2 */
        { &hf_oran_beam_type,
         {"beamType", "oran_fh_cus.beamType",
          FT_UINT16, BASE_DEC,
          VALS(beam_type_vals), 0xc0,
          NULL,
          HFILL}
        },
        /* 7.5.3.65 */
        { &hf_oran_meas_cmd_size,
         {"measCmdSize", "oran_fh_cus.measCmdSize",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          "measurement command size in words",
          HFILL}
        },

        { &hf_oran_symbol_reordering_layer,
          { "Layer", "oran_fh_cus.layer",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_dmrs_entry,
          { "Entry", "oran_fh_cus.dmrs-entry",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* 7.7.29.3 */
        { &hf_oran_cd_scg_size,
          {"cdScgSize", "oran_fh_cus.cdScgSize",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(cd_scg_size_vals), 0x0f,
            "Cyclic delay subcarrier group size",
            HFILL}
        },
        /* 7.7.29.4 */
        { &hf_oran_cd_scg_phase_step,
          {"cdScgPhaseStep", "oran_fh_cus.cdScgPhaseStep",
            FT_INT8, BASE_DEC,
            NULL, 0x0,
            "Cyclic delay subcarrier group phase step",
            HFILL}
        },

        { &hf_oran_c_section_common,
          { "Common Section", "oran_fh_cus.c-plane.section.common",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_c_section,
          { "Section", "oran_fh_cus.c-plane.section",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_oran_u_section,
          { "Section", "oran_fh_cus.u-plane.section",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /* Link back to UL C-plane where udCompHdr was recorded */
        { &hf_oran_ul_cplane_ud_comp_hdr_frame,
          { "C-Plane UL udCompHdr frame", "oran_fh_cus.ul-cplane.udCompHdr",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL}
        },
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
        &ett_oran_bfw_bundle,
        &ett_oran_bfw,
        &ett_oran_frequency_range,
        &ett_oran_prb_cisamples,
        &ett_oran_cisample,
        &ett_oran_udcomphdr,
        &ett_oran_udcompparam,
        &ett_oran_cicomphdr,
        &ett_oran_cicompparam,
        &ett_oran_bfwcomphdr,
        &ett_oran_bfwcompparam,
        &ett_oran_ext19_port,
        &ett_oran_prb_allocation,
        &ett_oran_punc_pattern,
        &ett_oran_bfacomphdr,
        &ett_oran_modcomp_param_set,
        &ett_oran_st4_cmd_header,
        &ett_oran_st4_cmd,
        &ett_oran_sym_prb_pattern,
        &ett_oran_measurement_report,
        &ett_oran_measurement_command,
        &ett_oran_sresmask,
        &ett_oran_c_section_common,
        &ett_oran_c_section,
        &ett_oran_remask,
        &ett_oran_mc_scale_remask,
        &ett_oran_symbol_reordering_layer,
        &ett_oran_dmrs_entry,
        &ett_oran_dmrs_symbol_mask,
        &ett_oran_symbol_mask,
        &ett_active_beamspace_coefficient_mask
    };

    static int *ext_ett[HIGHEST_EXTTYPE];
    for (unsigned extno=0; extno<HIGHEST_EXTTYPE; extno++) {
        ext_ett[extno] = &ett_oran_c_section_extension[extno];
    }

    expert_module_t* expert_oran;

    static ei_register_info ei[] = {
        { &ei_oran_unsupported_bfw_compression_method, { "oran_fh_cus.unsupported_bfw_compression_method", PI_UNDECODED, PI_WARN, "Unsupported BFW Compression Method", EXPFILL }},
        { &ei_oran_invalid_sample_bit_width, { "oran_fh_cus.invalid_sample_bit_width", PI_UNDECODED, PI_ERROR, "Unsupported sample bit width", EXPFILL }},
        { &ei_oran_reserved_numBundPrb, { "oran_fh_cus.reserved_numBundPrb", PI_MALFORMED, PI_ERROR, "Reserved value of numBundPrb", EXPFILL }},
        { &ei_oran_extlen_wrong, { "oran_fh_cus.extlen_wrong", PI_MALFORMED, PI_ERROR, "extlen doesn't match number of dissected bytes", EXPFILL }},
        { &ei_oran_invalid_eaxc_bit_width, { "oran_fh_cus.invalid_eaxc_bit_width", PI_UNDECODED, PI_ERROR, "Inconsistent eAxC bit width", EXPFILL }},
        { &ei_oran_extlen_zero, { "oran_fh_cus.extlen_zero", PI_MALFORMED, PI_ERROR, "extlen - zero is reserved value", EXPFILL }},
        { &ei_oran_rbg_size_reserved, { "oran_fh_cus.rbg_size_reserved", PI_MALFORMED, PI_ERROR, "rbgSize - zero is reserved value", EXPFILL }},
        { &ei_oran_frame_length, { "oran_fh_cus.frame_length", PI_MALFORMED, PI_ERROR, "there should be 0-3 bytes remaining after PDU in frame", EXPFILL }},
        { &ei_oran_numprbc_ext21_zero, { "oran_fh_cus.numprbc_ext21_zero", PI_MALFORMED, PI_ERROR, "numPrbc shall not be set to 0 when ciPrbGroupSize is configured", EXPFILL }},
        { &ei_oran_ci_prb_group_size_reserved, { "oran_fh_cus.ci_prb_group_size_reserved", PI_MALFORMED, PI_WARN, "ciPrbGroupSize should be 2-254", EXPFILL }},
        { &ei_oran_st8_nackid, { "oran_fh_cus.st8_nackid", PI_SEQUENCE, PI_WARN, "operation for this ackId failed", EXPFILL }},
        { &ei_oran_st4_no_cmds, { "oran_fh_cus.st4_nackid", PI_MALFORMED, PI_ERROR, "Not valid to have no commands in ST4", EXPFILL }},
        { &ei_oran_st4_zero_len_cmd, { "oran_fh_cus.st4_zero_len_cmd", PI_MALFORMED, PI_WARN, "ST4 cmd with length 0 is reserved", EXPFILL }},
        { &ei_oran_st4_wrong_len_cmd, { "oran_fh_cus.st4_wrong_len_cmd", PI_MALFORMED, PI_ERROR, "ST4 cmd with length not matching contents", EXPFILL }},
        { &ei_oran_st4_unknown_cmd, { "oran_fh_cus.st4_unknown_cmd", PI_MALFORMED, PI_ERROR, "ST4 cmd with unknown command code", EXPFILL }},
        { &ei_oran_mcot_out_of_range, { "oran_fh_cus.mcot_out_of_range", PI_MALFORMED, PI_ERROR, "MCOT should be 1-10", EXPFILL }},
        { &ei_oran_se10_unknown_beamgrouptype, { "oran_fh_cus.se10_unknown_beamgrouptype", PI_MALFORMED, PI_WARN, "SE10 - unknown BeamGroupType value", EXPFILL }},
        { &ei_oran_se10_not_allowed, { "oran_fh_cus.se10_not_allowed", PI_MALFORMED, PI_WARN, "SE10 - type not allowed for sectionType", EXPFILL }},
        { &ei_oran_start_symbol_id_not_zero, { "oran_fh_cus.startsymbolid_shall_be_zero", PI_MALFORMED, PI_WARN, "For ST4 commands 3&4, startSymbolId shall be 0", EXPFILL }},
        { &ei_oran_trx_control_cmd_scope, { "oran_fh_cus.trx_command.bad_cmdscope", PI_MALFORMED, PI_WARN, "TRX command must have cmdScope of ARRAY-COMMAND", EXPFILL }},
        { &ei_oran_unhandled_se, { "oran_fh_cus.se_not_handled", PI_UNDECODED, PI_WARN, "SE not recognised/handled by dissector", EXPFILL }},
        { &ei_oran_bad_symbolmask, { "oran_fh_cus.bad_symbol_mask", PI_MALFORMED, PI_WARN, "For non-zero sleepMode, symbolMask must be 0x0 or 0x3ffff", EXPFILL }},
        { &ei_oran_numslots_not_zero, { "oran_fh_cus.numslots_not_zero", PI_MALFORMED, PI_WARN, "For ST4 TIME_DOMAIN_BEAM_WEIGHTS, numSlots should be 0", EXPFILL }},
        { &ei_oran_version_unsupported, { "oran_fh_cus.version_unsupported", PI_UNDECODED, PI_WARN, "Protocol version unsupported", EXPFILL }},
        { &ei_oran_laa_msg_type_unsupported, { "oran_fh_cus.laa_msg_type_unsupported", PI_UNDECODED, PI_WARN, "laaMsgType unsupported", EXPFILL }},
        { &ei_oran_se_on_unsupported_st, { "oran_fh_cus.se_on_unsupported_st", PI_MALFORMED, PI_WARN, "Section Extension should not appear on this Section Type", EXPFILL }},
        { &ei_oran_cplane_unexpected_sequence_number_ul, { "oran_fh_cus.unexpected_seq_no_cplane.ul", PI_SEQUENCE, PI_WARN, "Unexpected sequence number seen in C-Plane UL", EXPFILL }},
        { &ei_oran_cplane_unexpected_sequence_number_dl, { "oran_fh_cus.unexpected_seq_no_cplane.dl", PI_SEQUENCE, PI_WARN, "Unexpected sequence number seen in C-Plane DL", EXPFILL }},
        { &ei_oran_uplane_unexpected_sequence_number_ul, { "oran_fh_cus.unexpected_seq_no_uplane.ul", PI_SEQUENCE, PI_WARN, "Unexpected sequence number seen in U-Plane UL", EXPFILL }},
        { &ei_oran_uplane_unexpected_sequence_number_dl, { "oran_fh_cus.unexpected_seq_no_uplane.dl", PI_SEQUENCE, PI_WARN, "Unexpected sequence number seen in U-Plane DL", EXPFILL }},
        { &ei_oran_acknack_no_request, { "oran_fh_cus.acknack_no_request", PI_SEQUENCE, PI_WARN, "Have ackNackId response, but no request", EXPFILL }},
        { &ei_oran_udpcomphdr_should_be_zero, { "oran_fh_cus.udcomphdr_should_be_zero", PI_MALFORMED, PI_WARN, "C-Plane udCompHdr in DL should be set to 0", EXPFILL }},
        { &ei_oran_radio_fragmentation_c_plane, { "oran_fh_cus.radio_fragmentation_c_plane", PI_MALFORMED, PI_ERROR, "Radio fragmentation not allowed in C-PLane", EXPFILL }},
        { &ei_oran_radio_fragmentation_u_plane, { "oran_fh_cus.radio_fragmentation_u_plane", PI_UNDECODED, PI_WARN, "Radio fragmentation in C-PLane not yet supported", EXPFILL }},
        { &ei_oran_lastRbdid_out_of_range, { "oran_fh_cus.lastrbdid_out_of_range", PI_MALFORMED, PI_WARN, "SE 6 has bad rbgSize", EXPFILL }},
        { &ei_oran_rbgMask_beyond_last_rbdid, { "oran_fh_cus.rbgmask_beyond_lastrbdid", PI_MALFORMED, PI_WARN, "rbgMask has bits set beyond lastRbgId", EXPFILL }},
        { &ei_oran_unexpected_measTypeId, { "oran_fh_cus.unexpected_meastypeid", PI_MALFORMED, PI_WARN, "unexpected measTypeId", EXPFILL }},
        { &ei_oran_unsupported_compression_method, { "oran_fh_cus.compression_type_unsupported", PI_UNDECODED, PI_WARN, "Unsupported compression type", EXPFILL }},
        { &ei_oran_ud_comp_len_wrong_size, { "oran_fh_cus.ud_comp_len_wrong_size", PI_MALFORMED, PI_WARN, "udCompLen does not match length of U-Plane section", EXPFILL }},
        { &ei_oran_sresmask2_not_zero_with_rb, { "oran_fh_cus.sresmask2_not_zero", PI_MALFORMED, PI_WARN, "sReSMask2 should be zero when rb set", EXPFILL }},
        { &ei_oran_st6_rb_shall_be_0, { "oran_fh_cus.st6_rb_set", PI_MALFORMED, PI_WARN, "rb should not be set for Section Type 6", EXPFILL }},
        { &ei_oran_st9_not_ul, { "oran_fh_cus.st9_not_ul", PI_MALFORMED, PI_WARN, "Section Type 9 should only be sent in uplink direction", EXPFILL }},
        { &ei_oran_st10_numsymbol_not_14, { "oran_fh_cus.st10_numsymbol_not_14", PI_MALFORMED, PI_WARN, "numSymbol should be 14 for Section Type 10", EXPFILL }},
        { &ei_oran_st10_startsymbolid_not_0, { "oran_fh_cus.st10_startsymbolid_not_0", PI_MALFORMED, PI_WARN, "startSymbolId should be 0 for Section Type 10", EXPFILL }},
        { &ei_oran_st10_not_ul, { "oran_fh_cus.st10_not_ul", PI_MALFORMED, PI_WARN, "Section Type 10 should only be sent in uplink direction", EXPFILL }},
        { &ei_oran_se24_nothing_to_inherit, { "oran_fh_cus.se24_nothing_to_inherit", PI_MALFORMED, PI_WARN, "SE10 doesn't have type 2 or 3 before trying to inherit", EXPFILL }},
        { &ei_oran_num_sinr_per_prb_unknown, { "oran_fh_cus.unexpected_num_sinr_per_prb", PI_MALFORMED, PI_WARN, "invalid numSinrPerPrb value", EXPFILL }},
        { &ei_oran_start_symbol_id_bits_ignored, { "oran_fh_cus.start_symbol_id_bits_ignored", PI_MALFORMED, PI_WARN, "some startSymbolId lower bits ignored", EXPFILL }},
        { &ei_oran_user_group_id_reserved_value, { "oran_fh_cus.user_group_id.reserved_value", PI_MALFORMED, PI_WARN, "userGroupId value 255 is reserved", EXPFILL }},
        { &ei_oran_port_list_index_zero, { "oran_fh_cus.port_list_index.zero", PI_MALFORMED, PI_WARN, "portListIndex should not be zero", EXPFILL }},
        { &ei_oran_ul_uplane_symbol_too_long, { "oran_fh_cus.ul_uplane_symbol_tx_too_slow", PI_RECEIVE, PI_WARN, "UL U-Plane Tx took too long for symbol (limit set in preference)", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_oran = proto_register_protocol("O-RAN Fronthaul CUS", "O-RAN FH CUS", "oran_fh_cus");

    /* Allow dissector to find be found by name. */
    register_dissector("oran_fh_cus", dissect_oran, proto_oran);

    /* Register the tap name. */
    oran_tap = register_tap("oran-fh-cus");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_oran, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_subtree_array(ext_ett, array_length(ext_ett));


    expert_oran = expert_register_protocol(proto_oran);
    expert_register_field_array(expert_oran, ei, array_length(ei));

    module_t * oran_module = prefs_register_protocol(proto_oran, NULL);

    /* prefs_register_static_text_preference(oran_module, "oran.stream", "", ""); */

    /* Register bit width/compression preferences separately by direction. */
    prefs_register_uint_preference(oran_module, "oran.du_port_id_bits", "DU Port ID bits [a]",
        "The bit width of DU Port ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_du_port_id_bits);
    prefs_register_uint_preference(oran_module, "oran.bandsector_id_bits", "BandSector ID bits [b]",
        "The bit width of BandSector ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_bandsector_id_bits);
    prefs_register_uint_preference(oran_module, "oran.cc_id_bits", "CC ID bits [c]",
        "The bit width of CC ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_cc_id_bits);
    prefs_register_uint_preference(oran_module, "oran.ru_port_id_bits", "RU Port ID bits [d]",
        "The bit width of RU Port ID - sum of a,b,c&d (eAxC) must be 16", 10, &pref_ru_port_id_bits);

    prefs_register_static_text_preference(oran_module, "oran.ul", "", "");

    /* Uplink userplane */
    prefs_register_uint_preference(oran_module, "oran.iq_bitwidth_up", "IQ Bitwidth Uplink",
        "The bit width of a sample in the Uplink (if no udcompHdr and no C-Plane)", 10, &pref_sample_bit_width_uplink);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_up", "Uplink User Data Compression",
        "Uplink User Data Compression (if no udcompHdr and no C-Plane)", &pref_iqCompressionUplink, ul_compression_options, false);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_hdr_up", "udCompHdr field is present for uplink",
        "The udCompHdr field in U-Plane messages may or may not be present, depending on the "
        "configuration of the O-RU. This preference instructs the dissector to expect "
        "this field to be present in uplink messages",
        &pref_includeUdCompHeaderUplink, udcomphdr_present_options, false);
    prefs_register_uint_preference(oran_module, "oran.ul_slot_us_limit", "Microseconds allowed for UL tx in symbol",
        "Maximum number of microseconds allowed for UL slot transmission before expert warning (zero to disable).  N.B. timing relative to first frame seen for same symbol",
        10, &us_allowed_for_ul_in_symbol);



    prefs_register_static_text_preference(oran_module, "oran.dl", "", "");

    /* Downlink userplane */
    prefs_register_uint_preference(oran_module, "oran.iq_bitwidth_down", "IQ Bitwidth Downlink",
        "The bit width of a sample in the Downlink (if no udcompHdr)", 10, &pref_sample_bit_width_downlink);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_down", "Downlink User Data Compression",
        "Downlink User Data Compression", &pref_iqCompressionDownlink, dl_compression_options, false);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_hdr_down", "udCompHdr field is present for downlink",
        "The udCompHdr field in U-Plane messages may or may not be present, depending on the "
        "configuration of the O-RU. This preference instructs the dissector to expect "
        "this field to be present in downlink messages",
        &pref_includeUdCompHeaderDownlink, udcomphdr_present_options, false);

    prefs_register_static_text_preference(oran_module, "oran.sinr", "", "");

    /* SINR */
    prefs_register_uint_preference(oran_module, "oran.iq_bitwidth_sinr", "IQ Bitwidth SINR",
        "The bit width of a sample in SINR", 10, &pref_sample_bit_width_sinr);
    prefs_register_enum_preference(oran_module, "oran.ud_comp_sinr", "SINR Compression",
        "SINR Compression", &pref_iqCompressionSINR, ul_compression_options, false);


    /* BF-related */
    prefs_register_static_text_preference(oran_module, "oran.bf", "", "");

    prefs_register_obsolete_preference(oran_module, "oran.num_weights_per_bundle");

    prefs_register_uint_preference(oran_module, "oran.num_bf_antennas", "Number of beam weights",
        "Number of array elements that BF weights will be provided for", 10, &pref_num_bf_antennas);

    prefs_register_obsolete_preference(oran_module, "oran.num_bf_weights");

    prefs_register_bool_preference(oran_module, "oran.st6_4byte_alignment_required", "Use 4-byte alignment for ST6 sections",
        "Default is 1-byte alignment", &st6_4byte_alignment);


    /* Misc (and will seldom need to be accessed) */
    prefs_register_static_text_preference(oran_module, "oran.misc", "", "");

    prefs_register_bool_preference(oran_module, "oran.show_iq_samples", "Show IQ Sample values",
        "When enabled, for U-Plane frames show each I and Q value in PRB", &pref_showIQSampleValues);

    prefs_register_enum_preference(oran_module, "oran.support_udcomplen", "udCompLen supported",
        "When enabled, U-Plane messages with relevant compression schemes will include udCompLen",
        &pref_support_udcompLen, udcomplen_support_options, false);

    prefs_register_uint_preference(oran_module, "oran.rbs_in_uplane_section", "Total RBs in User-Plane data section",
        "This is used if numPrbu is signalled as 0", 10, &pref_data_plane_section_total_rbs);

    prefs_register_bool_preference(oran_module, "oran.unscaled_iq", "Show unscaled I/Q values",
        "", &show_unscaled_values);

    prefs_register_obsolete_preference(oran_module, "oran.k_antenna_ports");


    flow_states_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    flow_results_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    ul_symbol_timing = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    register_init_routine(&oran_init_protocol);
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
