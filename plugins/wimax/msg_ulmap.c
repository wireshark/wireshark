/* msg_ulmap.c
 * WiMax MAC Management UL-MAP Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Mike Harvey <michael.harvey@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "wimax_mac.h"
#include "wimax_bits.h"
#include "wimax_utils.h"

extern	gboolean include_cor2_changes;

void proto_register_mac_mgmt_msg_ulmap(void);
void proto_reg_handoff_mac_mgmt_msg_ulmap(void);

#define MAC_MGMT_MSG_ULMAP 3

#define XBIT_HF(bits, hf) \
	proto_tree_add_bits_item(tree, hf, tvb, bit, bits, ENC_BIG_ENDIAN); bit += bits;

#define XBIT_HF_VALUE(var, bits, hf) \
	do { \
	var = TVB_BIT_BITS(bit, tvb, bits); \
	proto_tree_add_bits_item(tree, hf, tvb, bit, bits, ENC_BIG_ENDIAN); \
	bit += bits; \
	} while(0)

#define VNIB(var, nibs, hf) \
	do { \
	var = TVB_NIB_NIBS(nib, tvb, nibs); \
	proto_tree_add_uint(tree, hf, tvb, NIBHI(nib, nibs), var); \
	nib += nibs; \
	} while(0)

/* from msg_ucd.c */
extern guint cqich_id_size;		/* Set for CQICH_Alloc_IE */

/* from msg_dlmap.c */
extern gint harq;
extern gint ir_type;
extern gint N_layer;
extern gint RCID_Type;

static gint proto_mac_mgmt_msg_ulmap_decoder = -1;

static gint ett_ulmap = -1;
static gint ett_ulmap_ie = -1;
static gint ett_ulmap_ffb = -1;
/* static gint ett_ulmap_c = -1;    */
/* static gint ett_ulmap_c_ie = -1; */
/* static gint ett_ulmap_s = -1;    */
/* static gint ett_ulmap_s_ie = -1; */
static gint ett_287_1 = -1;
static gint ett_287_2 = -1;
static gint ett_289 = -1;
static gint ett_290 = -1;
static gint ett_290b = -1;
static gint ett_291 = -1;
static gint ett_292 = -1;
static gint ett_293 = -1;
static gint ett_294 = -1;
static gint ett_295 = -1;
static gint ett_299 = -1;
static gint ett_300 = -1;
static gint ett_302 = -1;
static gint ett_302a = -1;
static gint ett_302b = -1;
static gint ett_302c = -1;
static gint ett_302d = -1;
static gint ett_302e = -1;
static gint ett_302f = -1;
static gint ett_302g = -1;
static gint ett_302h = -1;
static gint ett_302i = -1;
static gint ett_302j = -1;
static gint ett_302k = -1;
static gint ett_302l = -1;
static gint ett_302m = -1;
static gint ett_302n = -1;
static gint ett_302o = -1;
static gint ett_302p = -1;
static gint ett_302q = -1;
static gint ett_302r = -1;
static gint ett_302s = -1;
static gint ett_302t = -1;
static gint ett_302u = -1;
static gint ett_302v = -1;
static gint ett_306 = -1;
static gint ett_306_ul = -1;
static gint ett_308b = -1;
static gint ett_315d = -1;

#define DCD_DOWNLINK_BURST_PROFILE        1
#define DCD_BS_EIRP                       2
#define DCD_FRAME_DURATION                3
#define DCD_PHY_TYPE                      4
#define DCD_POWER_ADJUSTMENT              5
#define DCD_CHANNEL_NR                    6
#define DCD_TTG                           7
#define DCD_RTG                           8
#define DCD_RSS                           9
#define DCD_CHANNEL_SWITCH_FRAME_NR      10
#define DCD_FREQUENCY                    12
#define DCD_BS_ID                        13
#define DCD_FRAME_DURATION_CODE          14
#define DCD_FRAME_NR                     15
#define DCD_SIZE_CQICH_ID                16
#define DCD_H_ARQ_ACK_DELAY              17
#define DCD_MAC_VERSION                 148
#define DCD_RESTART_COUNT               154

#define DCD_BURST_FREQUENCY               1
#define DCD_BURST_FEC_CODE_TYPE         150
#define DCD_BURST_DIUC_EXIT_THRESHOLD   151
#define DCD_BURST_DIUC_ENTRY_THRESHOLD  152
#define DCD_BURST_TCS_ENABLE            153

#define DCD_TLV_T_541_TYPE_FUNCTION_ACTION                                1
#define DCD_TLV_T542_TRIGGER_VALUE                                        2
#define DCD_TLV_T_543_TRIGGER_AVERAGING_DURATION                          3
#define DCD_TLV_T_19_PERMUTATION_TYPE_FOR_BROADCAST_REGION_IN_HARQ_ZONE  19
#define DCD_TLV_T_20_MAXIMUM_RETRANSMISSION                              20
#define DCD_TLV_T_21_DEFAULT_RSSI_AND_CINR_AVERAGING_PARAMETER           21
#define DCD_TLV_T_22_DL_AMC_ALLOCATED_PHYSICAL_BANDS_BITMAP              22
#define DCD_TLV_T_31_H_ADD_THRESHOLD                                     31
#define DCD_TLV_T_32_H_DELETE_THRESHOLD                                  32
#define DCD_TLV_T_33_ASR                                                 33
#define DCD_TLV_T_34_DL_REGION_DEFINITION                                34
#define DCD_TLV_T_35_PAGING_GROUP_ID                                     35
#define DCD_TLV_T_36_TUSC1_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP         36
#define DCD_TLV_T_37_TUSC2_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP         37
#define DCD_TLV_T_45_PAGING_INTERVAL_LENGTH                              45
#define DCD_TLV_T_50_HO_TYPE_SUPPORT                                     50
#define DCD_TLV_T_51_HYSTERSIS_MARGIN                                    51
#define DCD_TLV_T_52_TIME_TO_TRIGGER_DURATION                            52
#define DCD_TLV_T_54_TRIGGER                                             54
#define DCD_TLV_T_153_DOWNLINK_BURST_PROFILE_FOR_MULTIPLE_FEC_TYPES     153

#define UL_MAP_NCT_PMP  0
#define UL_MAP_NCT_DM   1
#define UL_MAP_NCT_PTP  2

#if 0
/* NCT messages */
static const value_string nct_msgs[] =
{
    { UL_MAP_NCT_PMP, "PMP" },
    { UL_MAP_NCT_PMP, "DM" },
    { UL_MAP_NCT_PMP, "PTP" },
    { 0,  NULL }
};
#endif

#if 0
/* Repetition Coding Indications */
static const value_string rep_msgs[] =
{
    { 0, "No Repetition Coding" },
    { 1, "Repetition Coding of 2 Used" },
    { 2, "Repetition Coding of 4 Used" },
    { 3, "Repetition Coding of 6 Used" },
    { 0,  NULL }
};
#endif

#if 0
/* DL Frame Prefix Coding Indications */
static const value_string boost_msgs[] =
{
    { 0, "Normal (not boosted)" },
    { 1, "+6dB" },
    { 2, "-6dB" },
    { 3, "+9dB" },
    { 4, "+3dB" },
    { 5, "-3dB" },
    { 6, "-9dB" },
    { 7, "-12dB" },
    { 0,  NULL }
};
#endif

/* ul-map fields */
static gint hf_ulmap_reserved = -1;
static gint hf_ulmap_ucd_count = -1;
static gint hf_ulmap_alloc_start_time = -1;
static gint hf_ulmap_ofdma_sym = -1;
static gint hf_ulmap_ie_diuc_ext = -1;
static gint hf_ulmap_ie_diuc_ext2 = -1;
static gint hf_ulmap_ie_length = -1;
static gint hf_ulmap_ie_reserved_extended2_duic = -1;
static gint hf_ulmap_ie_reserved_extended_duic = -1;
/* static gint hf_ulmap_fch_expected = -1; */

/* static gint hf_ulmap_ie = -1; */

static gint hf_ulmap_ie_cid      = -1;
static gint hf_ulmap_ie_uiuc     = -1;
static gint hf_ulmap_uiuc12_symofs = -1;
static gint hf_ulmap_uiuc12_subofs = -1;
static gint hf_ulmap_uiuc12_numsym = -1;
static gint hf_ulmap_uiuc12_numsub = -1;
static gint hf_ulmap_uiuc12_method = -1;
static gint hf_ulmap_uiuc12_dri    = -1;
static gint hf_ulmap_uiuc10_dur    = -1;
static gint hf_ulmap_uiuc10_rep    = -1;
static gint hf_ulmap_uiuc10_slot_offset = -1;

static gint hf_ulmap_uiuc14_dur  = -1;
static gint hf_ulmap_uiuc14_uiuc = -1;
static gint hf_ulmap_uiuc14_rep  = -1;
static gint hf_ulmap_uiuc14_idx  = -1;
static gint hf_ulmap_uiuc14_code = -1;
static gint hf_ulmap_uiuc14_sym  = -1;
static gint hf_ulmap_uiuc14_sub  = -1;
static gint hf_ulmap_uiuc14_bwr  = -1;

/* static gint hf_ulmap_uiuc11_ext = -1; */
/* static gint hf_ulmap_uiuc11_len = -1; */
/* static gint hf_ulmap_uiuc11_data = -1; */
/* static gint hf_ulmap_uiuc15_ext = -1; */
/* static gint hf_ulmap_uiuc15_len = -1; */
/* static gint hf_ulmap_uiuc15_data = -1; */

static gint hf_ulmap_uiuc0_symofs = -1;
static gint hf_ulmap_uiuc0_subofs = -1;
static gint hf_ulmap_uiuc0_numsym = -1;
static gint hf_ulmap_uiuc0_numsub = -1;
static gint hf_ulmap_uiuc0_rsv    = -1;

static gint hf_ulmap_uiuc13_symofs = -1;
static gint hf_ulmap_uiuc13_subofs = -1;
static gint hf_ulmap_uiuc13_numsym = -1;
static gint hf_ulmap_uiuc13_numsub = -1;
static gint hf_ulmap_uiuc13_papr   = -1;
static gint hf_ulmap_uiuc13_zone   = -1;
static gint hf_ulmap_uiuc13_rsv    = -1;
/* static gint hf_ulmap_crc16         = -1; */
static gint hf_ulmap_padding       = -1;

/* Generated via "one time" script to help create filterable fields */
static int hf_ulmap_dedicated_ul_control_length = -1;
static int hf_ulmap_dedicated_ul_control_control_header = -1;
static int hf_ulmap_dedicated_ul_control_num_sdma_layers = -1;
static int hf_ulmap_dedicated_ul_control_pilot_pattern = -1;
static int hf_ulmap_dedicated_mimo_ul_control_matrix = -1;
static int hf_ulmap_dedicated_mimo_ul_control_n_layer = -1;
static int hf_ulmap_harq_chase_dedicated_ul_control_indicator = -1;
static int hf_ulmap_harq_chase_uiuc = -1;
static int hf_ulmap_harq_chase_repetition_coding_indication = -1;
static int hf_ulmap_harq_chase_duration = -1;
static int hf_ulmap_harq_chase_acid = -1;
static int hf_ulmap_harq_chase_ai_sn = -1;
static int hf_ulmap_harq_chase_ack_disable = -1;
static int hf_ulmap_reserved_uint = -1;
static int hf_ulmap_harq_ir_ctc_dedicated_ul_control_indicator = -1;
static int hf_ulmap_harq_ir_ctc_nep = -1;
static int hf_ulmap_harq_ir_ctc_nsch = -1;
static int hf_ulmap_harq_ir_ctc_spid = -1;
static int hf_ulmap_harq_ir_ctc_acin = -1;
static int hf_ulmap_harq_ir_ctc_ai_sn = -1;
static int hf_ulmap_harq_ir_ctc_ack_disable = -1;
static int hf_ulmap_harq_ir_cc_dedicated_ul_control_indicator = -1;
static int hf_ulmap_harq_ir_cc_uiuc = -1;
static int hf_ulmap_harq_ir_cc_repetition_coding_indication = -1;
static int hf_ulmap_harq_ir_cc_duration = -1;
static int hf_ulmap_harq_ir_cc_spid = -1;
static int hf_ulmap_harq_ir_cc_acid = -1;
static int hf_ulmap_harq_ir_cc_ai_sn = -1;
static int hf_ulmap_harq_ir_cc_ack_disable = -1;
static int hf_ulmap_mimo_ul_chase_harq_mu_indicator = -1;
static int hf_ulmap_mimo_ul_chase_harq_dedicated_mimo_ulcontrol_indicator = -1;
static int hf_ulmap_mimo_ul_chase_harq_ack_disable = -1;
static int hf_ulmap_mimo_ul_chase_harq_matrix = -1;
static int hf_ulmap_mimo_ul_chase_harq_duration = -1;
static int hf_ulmap_mimo_ul_chase_harq_uiuc = -1;
static int hf_ulmap_mimo_ul_chase_harq_repetition_coding_indication = -1;
static int hf_ulmap_mimo_ul_chase_harq_acid = -1;
static int hf_ulmap_mimo_ul_chase_harq_ai_sn = -1;
static int hf_ulmap_mimo_ul_ir_harq_mu_indicator = -1;
static int hf_ulmap_mimo_ul_ir_harq_dedicated_mimo_ul_control_indicator = -1;
static int hf_ulmap_mimo_ul_ir_harq_ack_disable = -1;
static int hf_ulmap_mimo_ul_ir_harq_matrix = -1;
static int hf_ulmap_mimo_ul_ir_harq_nsch = -1;
static int hf_ulmap_mimo_ul_ir_harq_nep = -1;
static int hf_ulmap_mimo_ul_ir_harq_spid = -1;
static int hf_ulmap_mimo_ul_ir_harq_acid = -1;
static int hf_ulmap_mimo_ul_ir_harq_ai_sn = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_mu_indicator = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_dedicated_mimo_ul_control_indicator = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_ack_disable = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_matrix = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_duration = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_uiuc = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_repetition_coding_indication = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_acid = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_ai_sn = -1;
static int hf_ulmap_mimo_ul_ir_harq_cc_spid = -1;
static int hf_ulmap_mimo_ul_stc_harq_tx_count = -1;
static int hf_ulmap_mimo_ul_stc_harq_duration = -1;
static int hf_ulmap_mimo_ul_stc_harq_sub_burst_offset_indication = -1;
static int hf_ulmap_mimo_ul_stc_harq_sub_burst_offset = -1;
static int hf_ulmap_mimo_ul_stc_harq_ack_disable = -1;
static int hf_ulmap_mimo_ul_stc_harq_uiuc = -1;
static int hf_ulmap_mimo_ul_stc_harq_repetition_coding_indication = -1;
static int hf_ulmap_mimo_ul_stc_harq_acid = -1;
static int hf_ulmap_power_control = -1;
static int hf_ulmap_power_measurement_frame = -1;
static int hf_ulmap_mini_subcha_alloc_extended_2_uiuc = -1;
static int hf_ulmap_mini_subcha_alloc_length = -1;
static int hf_ulmap_mini_subcha_alloc_ctype = -1;
static int hf_ulmap_mini_subcha_alloc_duration = -1;
static int hf_ulmap_mini_subcha_alloc_cid = -1;
static int hf_ulmap_mini_subcha_alloc_uiuc = -1;
static int hf_ulmap_mini_subcha_alloc_repetition = -1;
static int hf_ulmap_mini_subcha_alloc_padding = -1;
static int hf_ulmap_aas_ul_extended_uiuc = -1;
static int hf_ulmap_aas_ul_length = -1;
static int hf_ulmap_aas_ul_permutation = -1;
static int hf_ulmap_aas_ul_ul_permbase = -1;
static int hf_ulmap_aas_ul_ofdma_symbol_offset = -1;
static int hf_ulmap_aas_ul_aas_zone_length = -1;
static int hf_ulmap_aas_ul_uplink_preamble_config = -1;
static int hf_ulmap_aas_ul_preamble_type = -1;
static int hf_ulmap_cqich_alloc_extended_uiuc = -1;
static int hf_ulmap_cqich_alloc_length = -1;
static int hf_ulmap_cqich_alloc_cqich_id = -1;
static int hf_ulmap_cqich_alloc_allocation_offset = -1;
static int hf_ulmap_cqich_alloc_period = -1;
static int hf_ulmap_cqich_alloc_frame_offset = -1;
static int hf_ulmap_cqich_alloc_duration = -1;
static int hf_ulmap_cqich_alloc_report_configuration_included = -1;
static int hf_ulmap_cqich_alloc_feedback_type = -1;
static int hf_ulmap_cqich_alloc_report_type = -1;
static int hf_ulmap_cqich_alloc_cinr_preamble_report_type = -1;
static int hf_ulmap_cqich_alloc_zone_permutation = -1;
static int hf_ulmap_cqich_alloc_zone_type = -1;
static int hf_ulmap_cqich_alloc_zone_prbs_id = -1;
static int hf_ulmap_cqich_alloc_major_group_indication = -1;
static int hf_ulmap_cqich_alloc_pusc_major_group_bitmap = -1;
static int hf_ulmap_cqich_alloc_cinr_zone_measurement_type = -1;
static int hf_ulmap_cqich_alloc_averaging_parameter_included = -1;
static int hf_ulmap_cqich_alloc_averaging_parameter = -1;
static int hf_ulmap_cqich_alloc_mimo_permutation_feedback_cycle = -1;
static int hf_ulmap_zone_extended_uiuc = -1;
static int hf_ulmap_zone_length = -1;
static int hf_ulmap_zone_ofdma_symbol_offset = -1;
static int hf_ulmap_zone_permutation = -1;
static int hf_ulmap_zone_ul_permbase = -1;
static int hf_ulmap_zone_amc_type = -1;
static int hf_ulmap_zone_use_all_sc_indicator = -1;
static int hf_ulmap_zone_disable_subchannel_rotation = -1;
static int hf_ulmap_phymod_ul_extended_uiuc = -1;
static int hf_ulmap_phymod_ul_length = -1;
static int hf_ulmap_phymod_ul_preamble_modifier_type = -1;
static int hf_ulmap_phymod_ul_preamble_frequency_shift_index = -1;
static int hf_ulmap_phymod_ul_preamble_time_shift_index = -1;
static int hf_ulmap_phymod_ul_pilot_pattern_modifier = -1;
static int hf_ulmap_phymod_ul_pilot_pattern_index = -1;
static int hf_ulmap_fast_tracking_extended_uiuc = -1;
static int hf_ulmap_fast_tracking_length = -1;
static int hf_ulmap_fast_tracking_map_index = -1;
static int hf_ulmap_fast_tracking_power_correction = -1;
static int hf_ulmap_fast_tracking_frequency_correction = -1;
static int hf_ulmap_fast_tracking_time_correction = -1;
static int hf_ulmap_pusc_burst_allocation_extended_uiuc = -1;
static int hf_ulmap_pusc_burst_allocation_length = -1;
static int hf_ulmap_pusc_burst_allocation_uiuc = -1;
static int hf_ulmap_pusc_burst_allocation_segment = -1;
static int hf_ulmap_pusc_burst_allocation_ul_permbase = -1;
static int hf_ulmap_pusc_burst_allocation_ofdma_symbol_offset = -1;
static int hf_ulmap_pusc_burst_allocation_subchannel_offset = -1;
static int hf_ulmap_pusc_burst_allocation_duration = -1;
static int hf_ulmap_pusc_burst_allocation_repetition_coding_indication = -1;
static int hf_ulmap_fast_ranging_extended_uiuc = -1;
static int hf_ulmap_fast_ranging_length = -1;
static int hf_ulmap_fast_ranging_ho_id_indicator = -1;
static int hf_ulmap_fast_ranging_ho_id = -1;
static int hf_ulmap_fast_ranging_mac_address = -1;
static int hf_ulmap_fast_ranging_uiuc = -1;
static int hf_ulmap_fast_ranging_duration = -1;
static int hf_ulmap_fast_ranging_repetition_coding_indication = -1;
static int hf_ulmap_allocation_start_extended_uiuc = -1;
static int hf_ulmap_allocation_start_length = -1;
static int hf_ulmap_allocation_start_ofdma_symbol_offset = -1;
static int hf_ulmap_allocation_start_subchannel_offset = -1;
static int hf_ulmap_cqich_enhanced_alloc_extended_2_uiuc = -1;
static int hf_ulmap_cqich_enhanced_alloc_length = -1;
static int hf_ulmap_cqich_enhanced_alloc_cqich_id = -1;
static int hf_ulmap_cqich_enhanced_alloc_period = -1;
static int hf_ulmap_cqich_enhanced_alloc_frame_offset = -1;
static int hf_ulmap_cqich_enhanced_alloc_duration = -1;
static int hf_ulmap_cqich_enhanced_alloc_cqich_num = -1;
static int hf_ulmap_cqich_enhanced_alloc_feedback_type = -1;
static int hf_ulmap_cqich_enhanced_alloc_allocation_index = -1;
static int hf_ulmap_cqich_enhanced_alloc_cqich_type = -1;
static int hf_ulmap_cqich_enhanced_alloc_sttd_indication = -1;
static int hf_ulmap_cqich_enhanced_alloc_band_amc_precoding_mode = -1;
static int hf_ulmap_cqich_enhanced_alloc_nr_precoders_feedback = -1;
static int hf_ulmap_anchor_bs_switch_extended_2_uiuc = -1;
static int hf_ulmap_anchor_bs_switch_length = -1;
static int hf_ulmap_anchor_bs_switch_n_anchor_bs_switch = -1;
static int hf_ulmap_anchor_bs_switch_reduced_cid = -1;
static int hf_ulmap_anchor_bs_switch_action_code = -1;
static int hf_ulmap_anchor_bs_switch_action_time = -1;
static int hf_ulmap_anchor_bs_switch_temp_bs_id = -1;
static int hf_ulmap_anchor_bs_switch_ak_change_indicator = -1;
static int hf_ulmap_anchor_bs_switch_cqich_allocation_indicator = -1;
static int hf_ulmap_anchor_bs_switch_cqich_id = -1;
static int hf_ulmap_anchor_bs_switch_feedback_channel_offset = -1;
static int hf_ulmap_anchor_bs_switch_period = -1;
static int hf_ulmap_anchor_bs_switch_frame_offset = -1;
static int hf_ulmap_anchor_bs_switch_duration = -1;
static int hf_ulmap_anchor_bs_switch_mimo_permutation_feedback_code = -1;
static int hf_ulmap_sounding_command_extended_2_uiuc = -1;
static int hf_ulmap_sounding_command_length = -1;
static int hf_ulmap_sounding_command_type = -1;
static int hf_ulmap_sounding_command_send_sounding_report_flag = -1;
static int hf_ulmap_sounding_command_relevance_flag = -1;
static int hf_ulmap_sounding_command_relevance = -1;
static int hf_ulmap_sounding_command_include_additional_feedback = -1;
static int hf_ulmap_sounding_command_num_sounding_symbols = -1;
static int hf_ulmap_sounding_command_separability_type = -1;
static int hf_ulmap_sounding_command_max_cyclic_shift_index_p = -1;
static int hf_ulmap_sounding_command_decimation_value = -1;
static int hf_ulmap_sounding_command_decimation_offset_randomization = -1;
static int hf_ulmap_sounding_command_symbol_index = -1;
static int hf_ulmap_sounding_command_number_of_cids = -1;
static int hf_ulmap_sounding_command_shorted_basic_cid = -1;
static int hf_ulmap_sounding_command_power_assignment_method = -1;
static int hf_ulmap_sounding_command_power_boost = -1;
static int hf_ulmap_sounding_command_multi_antenna_flag = -1;
static int hf_ulmap_sounding_command_allocation_mode = -1;
static int hf_ulmap_sounding_command_band_bit_map = -1;
static int hf_ulmap_sounding_command_starting_frequency_band = -1;
static int hf_ulmap_sounding_command_number_of_frequency_bands = -1;
static int hf_ulmap_sounding_command_cyclic_time_shift_index = -1;
static int hf_ulmap_sounding_command_decimation_offset = -1;
static int hf_ulmap_sounding_command_use_same_symbol_for_additional_feedback = -1;
static int hf_ulmap_sounding_command_periodicity = -1;
static int hf_ulmap_sounding_command_permutation = -1;
static int hf_ulmap_sounding_command_dl_permbase = -1;
static int hf_ulmap_sounding_command_shortened_basic_cid = -1;
static int hf_ulmap_sounding_command_subchannel_offset = -1;
static int hf_ulmap_sounding_command_number_of_subchannels = -1;
static int hf_ulmap_harq_ulmap_extended_2_uiuc = -1;
static int hf_ulmap_harq_ulmap_length = -1;
static int hf_ulmap_harq_ulmap_rcid_type = -1;
static int hf_ulmap_harq_ulmap_mode = -1;
static int hf_ulmap_harq_ulmap_allocation_start_indication = -1;
static int hf_ulmap_harq_ulmap_ofdma_symbol_offset = -1;
static int hf_ulmap_harq_ulmap_subchannel_offset = -1;
static int hf_ulmap_harq_ulmap_n_sub_burst = -1;
static int hf_ulmap_harq_ackch_region_alloc_extended_2_uiuc = -1;
static int hf_ulmap_harq_ackch_region_alloc_length = -1;
static int hf_ulmap_harq_ackch_region_alloc_ofdma_symbol_offset = -1;
static int hf_ulmap_harq_ackch_region_alloc_subchannel_offset = -1;
static int hf_ulmap_harq_ackch_region_alloc_num_ofdma_symbols = -1;
static int hf_ulmap_harq_ackch_region_alloc_num_subchannels = -1;
static int hf_ulmap_aas_sdma_extended_2_uiuc = -1;
static int hf_ulmap_aas_sdma_length = -1;
static int hf_ulmap_aas_sdma_rcid_type = -1;
static int hf_ulmap_aas_sdma_num_burst_region = -1;
static int hf_ulmap_aas_sdma_slot_offset = -1;
static int hf_ulmap_aas_sdma_slot_duration = -1;
static int hf_ulmap_aas_sdma_number_of_users = -1;
static int hf_ulmap_aas_sdma_encoding_mode = -1;
static int hf_ulmap_aas_sdma_power_adjust = -1;
static int hf_ulmap_aas_sdma_pilot_pattern_modifier = -1;
static int hf_ulmap_aas_sdma_preamble_modifier_index = -1;
static int hf_ulmap_aas_sdma_pilot_pattern = -1;
static int hf_ulmap_aas_sdma_diuc = -1;
static int hf_ulmap_aas_sdma_repetition_coding_indication = -1;
static int hf_ulmap_aas_sdma_acid = -1;
static int hf_ulmap_aas_sdma_ai_sn = -1;
static int hf_ulmap_aas_sdma_nep = -1;
static int hf_ulmap_aas_sdma_nsch = -1;
static int hf_ulmap_aas_sdma_spid = -1;
static int hf_ulmap_aas_sdma_power_adjustment = -1;
static int hf_ulmap_feedback_polling_extended_2_uiuc = -1;
static int hf_ulmap_feedback_polling_length = -1;
static int hf_ulmap_feedback_polling_num_allocation = -1;
static int hf_ulmap_feedback_polling_dedicated_ul_allocation_included = -1;
static int hf_ulmap_feedback_polling_basic_cid = -1;
static int hf_ulmap_feedback_polling_allocation_duration = -1;
static int hf_ulmap_feedback_polling_type = -1;
static int hf_ulmap_feedback_polling_frame_offset = -1;
static int hf_ulmap_feedback_polling_period = -1;
static int hf_ulmap_feedback_polling_uiuc = -1;
static int hf_ulmap_feedback_polling_ofdma_symbol_offset = -1;
static int hf_ulmap_feedback_polling_subchannel_offset = -1;
static int hf_ulmap_feedback_polling_duration = -1;
static int hf_ulmap_feedback_polling_repetition_coding_indication = -1;
static int hf_ulmap_reduced_aas_aas_zone_configuration_included = -1;
static int hf_ulmap_reduced_aas_aas_zone_position_included = -1;
static int hf_ulmap_reduced_aas_ul_map_information_included = -1;
static int hf_ulmap_reduced_aas_phy_modification_included = -1;
static int hf_ulmap_reduced_aas_power_control_included = -1;
static int hf_ulmap_reduced_aas_include_feedback_header = -1;
static int hf_ulmap_reduced_aas_encoding_mode = -1;
static int hf_ulmap_reduced_aas_permutation = -1;
static int hf_ulmap_reduced_aas_ul_permbase = -1;
static int hf_ulmap_reduced_aas_preamble_indication = -1;
static int hf_ulmap_reduced_aas_padding = -1;
static int hf_ulmap_reduced_aas_zone_symbol_offset = -1;
static int hf_ulmap_reduced_aas_zone_length = -1;
static int hf_ulmap_reduced_aas_ucd_count = -1;
static int hf_ulmap_reduced_aas_private_map_alloc_start_time = -1;
static int hf_ulmap_reduced_aas_pilot_pattern_index = -1;
static int hf_ulmap_reduced_aas_preamble_select = -1;
static int hf_ulmap_reduced_aas_preamble_shift_index = -1;
static int hf_ulmap_reduced_aas_pilot_pattern_modifier = -1;
static int hf_ulmap_reduced_aas_power_control = -1;
static int hf_ulmap_reduced_aas_ul_frame_offset = -1;
static int hf_ulmap_reduced_aas_slot_offset = -1;
static int hf_ulmap_reduced_aas_slot_duration = -1;
static int hf_ulmap_reduced_aas_uiuc_nep = -1;
static int hf_ulmap_reduced_aas_acid = -1;
static int hf_ulmap_reduced_aas_ai_sn = -1;
static int hf_ulmap_reduced_aas_nsch = -1;
static int hf_ulmap_reduced_aas_spid = -1;
static int hf_ulmap_reduced_aas_repetition_coding_indication = -1;

static expert_field ei_ulmap_not_implemented = EI_INIT;

/*  This gets called each time a capture file is loaded. */
void init_wimax_globals(void)
{
    cqich_id_size = 0;
    harq = 0;
    ir_type = 0;
    N_layer = 0;
    RCID_Type = 0;
}

/********************************************************************
 * UL-MAP HARQ Sub-Burst IEs
 * 8.4.5.4.24 table 302j
 * these functions take offset/length in bits
 *******************************************************************/

static gint Dedicated_UL_Control_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24.1 Dedicated_UL_Control_IE -- table 302r */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    gint sdma;

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302r, NULL, "Dedicated_UL_Control_IE");

    XBIT_HF(4, hf_ulmap_dedicated_ul_control_length);
    XBIT_HF_VALUE(sdma, 4, hf_ulmap_dedicated_ul_control_control_header);
    if ((sdma & 1) == 1) {
        XBIT_HF(2, hf_ulmap_dedicated_ul_control_num_sdma_layers);
        XBIT_HF(2, hf_ulmap_dedicated_ul_control_pilot_pattern);
    }
    return (bit - offset); /* length in bits */
}

static gint Dedicated_MIMO_UL_Control_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24.2 Dedicated_MIMO_UL_Control_IE -- table 302s */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302s, NULL, "Dedicated_MIMO_UL_Control_IE");

    XBIT_HF(2, hf_ulmap_dedicated_mimo_ul_control_matrix);
    XBIT_HF_VALUE(N_layer, 2, hf_ulmap_dedicated_mimo_ul_control_n_layer);

    return (bit - offset); /* length in bits */
}

/* begin Sub-Burst IEs */

static gint UL_HARQ_Chase_Sub_Burst_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 UL_HARQ_Chase_sub_burst_IE -- table 302k */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    /*proto_item *generic_item = NULL;*/
    gint duci;
    /*guint16 calculated_crc;*/

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, BITHI(offset,length), ett_302k, NULL, "UL_HARQ_Chase_Sub_Burst_IE");

    bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
    XBIT_HF_VALUE(duci, 1, hf_ulmap_harq_chase_dedicated_ul_control_indicator);
    if (duci == 1) {
        bit += Dedicated_UL_Control_IE(tree, bit, length, tvb);
    }
    XBIT_HF(4, hf_ulmap_harq_chase_uiuc);
    XBIT_HF(2, hf_ulmap_harq_chase_repetition_coding_indication);
    XBIT_HF(10, hf_ulmap_harq_chase_duration);
    XBIT_HF(4, hf_ulmap_harq_chase_acid);
    XBIT_HF(1, hf_ulmap_harq_chase_ai_sn);
    XBIT_HF(1, hf_ulmap_harq_chase_ack_disable);
    XBIT_HF(1, hf_ulmap_reserved_uint);

#if 0
    if (include_cor2_changes)
    {
		calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
		proto_tree_add_checksum(tree, tvb, BITHI(bit,16), hf_ulmap_crc16, -1, NULL, pinfo, calculated_crc,
									ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
		bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint UL_HARQ_IR_CTC_Sub_Burst_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 UL_HARQ_IR_CTC_sub_burst_IE -- table 302l */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    /*proto_item *generic_item = NULL;*/
    gint duci;
    /*guint16 calculated_crc;*/

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302l, NULL, "UL_HARQ_IR_CTC_Sub_Burst_IE");

    bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
    XBIT_HF_VALUE(duci, 1, hf_ulmap_harq_ir_ctc_dedicated_ul_control_indicator);
    if (duci == 1) {
        bit += Dedicated_UL_Control_IE(tree, bit, length, tvb);
    }
    XBIT_HF(4, hf_ulmap_harq_ir_ctc_nep);
    XBIT_HF(4, hf_ulmap_harq_ir_ctc_nsch);
    XBIT_HF(2, hf_ulmap_harq_ir_ctc_spid);
    XBIT_HF(4, hf_ulmap_harq_ir_ctc_acin);
    XBIT_HF(1, hf_ulmap_harq_ir_ctc_ai_sn);
    XBIT_HF(1, hf_ulmap_harq_ir_ctc_ack_disable);
    XBIT_HF(3, hf_ulmap_reserved_uint);

#if 0
    if (include_cor2_changes)
    {
		/* CRC-16 is always appended */
		calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
		proto_tree_add_checksum(tree, tvb, BITHI(bit,16), hf_ulmap_crc16, -1, NULL, pinfo, calculated_crc,
									ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
		bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint UL_HARQ_IR_CC_Sub_Burst_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 UL_HARQ_IR_CC_sub_burst_IE -- table 302m */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    /*proto_item *generic_item = NULL;*/
    gint duci;
    /*guint16 calculated_crc;*/

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302m, NULL, "UL_HARQ_IR_CC_Sub_Burst_IE");

    bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
    XBIT_HF_VALUE(duci, 1, hf_ulmap_harq_ir_cc_dedicated_ul_control_indicator);
    if (duci == 1) {
        bit += Dedicated_UL_Control_IE(tree, bit, length, tvb);
    }
    XBIT_HF(4, hf_ulmap_harq_ir_cc_uiuc);
    XBIT_HF(2, hf_ulmap_harq_ir_cc_repetition_coding_indication);
    XBIT_HF(10, hf_ulmap_harq_ir_cc_duration);
    XBIT_HF(2, hf_ulmap_harq_ir_cc_spid);
    XBIT_HF(4, hf_ulmap_harq_ir_cc_acid);
    XBIT_HF(1, hf_ulmap_harq_ir_cc_ai_sn);
    XBIT_HF(1, hf_ulmap_harq_ir_cc_ack_disable);
    XBIT_HF(3, hf_ulmap_reserved_uint);

#if 0
    if (include_cor2_changes)
    {
		/* CRC-16 is always appended */
		calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
		proto_tree_add_checksum(tree, tvb, BITHI(bit,16), hf_ulmap_crc16, -1, NULL, pinfo, calculated_crc,
									ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

		bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_Chase_HARQ_Sub_Burst_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_Chase_HARQ_Sub_Burst_IE -- table 302n */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    /*proto_item *generic_item = NULL;*/
    gint muin,dmci,ackd,i;
    /*guint16 calculated_crc;*/

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302n, NULL, "MIMO_UL_Chase_HARQ_Sub_Burst_IE");

    XBIT_HF_VALUE(muin, 1, hf_ulmap_mimo_ul_chase_harq_mu_indicator);
    XBIT_HF_VALUE(dmci, 1, hf_ulmap_mimo_ul_chase_harq_dedicated_mimo_ulcontrol_indicator);
    XBIT_HF_VALUE(ackd, 1, hf_ulmap_mimo_ul_chase_harq_ack_disable);
    if (muin == 0) {
        bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
        if (dmci) {
            bit += Dedicated_MIMO_UL_Control_IE(tree, bit, length, tvb);
        }
    } else {
        XBIT_HF(1, hf_ulmap_mimo_ul_chase_harq_matrix);
    }
    XBIT_HF(10, hf_ulmap_mimo_ul_chase_harq_duration);
    for (i = 0; i < N_layer; i++) {
        if (muin == 1) {
            bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
        }
        XBIT_HF(4, hf_ulmap_mimo_ul_chase_harq_uiuc);
        XBIT_HF(2, hf_ulmap_mimo_ul_chase_harq_repetition_coding_indication);
        if (ackd == 0) {
            XBIT_HF(4, hf_ulmap_mimo_ul_chase_harq_acid);
            XBIT_HF(1, hf_ulmap_mimo_ul_chase_harq_ai_sn);
        }
    }

#if 0
    if (include_cor2_changes)
    {
		/* CRC-16 is always appended */
		calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
		proto_tree_add_checksum(tree, tvb, BITHI(bit,16), hf_ulmap_crc16, -1, NULL, pinfo, calculated_crc,
									ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

		bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_IR_HARQ__Sub_Burst_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_IR_HARQ__Sub_Burst_IE -- table 302o */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    /*proto_item *generic_item = NULL;*/
    gint muin,dmci,ackd,i;
    /*guint16 calculated_crc;*/

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302o, NULL, "MIMO_UL_IR_HARQ__Sub_Burst_IE");

    XBIT_HF_VALUE(muin, 1, hf_ulmap_mimo_ul_ir_harq_mu_indicator);
    XBIT_HF_VALUE(dmci, 1, hf_ulmap_mimo_ul_ir_harq_dedicated_mimo_ul_control_indicator);
    XBIT_HF_VALUE(ackd, 1, hf_ulmap_mimo_ul_ir_harq_ack_disable);
    if (muin == 0) {
        bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
        if (dmci) {
            bit += Dedicated_MIMO_UL_Control_IE(tree, bit, length, tvb);
        }
    } else {
        XBIT_HF(1, hf_ulmap_mimo_ul_ir_harq_matrix);
    }
    XBIT_HF(4, hf_ulmap_mimo_ul_ir_harq_nsch);
    for (i = 0; i < N_layer; i++) {
        if (muin == 1) {
            bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
        }
        XBIT_HF(4, hf_ulmap_mimo_ul_ir_harq_nep);
        if (ackd == 0) {
            XBIT_HF(2, hf_ulmap_mimo_ul_ir_harq_spid);
            XBIT_HF(4, hf_ulmap_mimo_ul_ir_harq_acid);
            XBIT_HF(1, hf_ulmap_mimo_ul_ir_harq_ai_sn);
        }
    }

#if 0
    if (include_cor2_changes)
    {
		/* CRC-16 is always appended */
		calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
		proto_tree_add_checksum(tree, tvb, BITHI(bit,16), hf_ulmap_crc16, -1, NULL, pinfo, calculated_crc,
									ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

		bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE -- table 302p */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    /*proto_item *generic_item = NULL;*/
    gint muin,dmci,ackd,i;
    /*guint16 calculated_crc;*/

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302p, NULL, "MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE");

    XBIT_HF_VALUE(muin, 1, hf_ulmap_mimo_ul_ir_harq_cc_mu_indicator);
    XBIT_HF_VALUE(dmci, 1, hf_ulmap_mimo_ul_ir_harq_cc_dedicated_mimo_ul_control_indicator);
    XBIT_HF_VALUE(ackd, 1, hf_ulmap_mimo_ul_ir_harq_cc_ack_disable);
    if (muin == 0) {
        bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
        if (dmci) {
            bit += Dedicated_MIMO_UL_Control_IE(tree, bit, length, tvb);
        }
    } else {
        XBIT_HF(1, hf_ulmap_mimo_ul_ir_harq_cc_matrix);
    }
    XBIT_HF(10, hf_ulmap_mimo_ul_ir_harq_cc_duration);
    for (i = 0; i < N_layer; i++) {
        if (muin == 1) {
            bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
        }
        XBIT_HF(4, hf_ulmap_mimo_ul_ir_harq_cc_uiuc);
        XBIT_HF(2, hf_ulmap_mimo_ul_ir_harq_cc_repetition_coding_indication);
        if (ackd == 0) {
            XBIT_HF(4, hf_ulmap_mimo_ul_ir_harq_cc_acid);
            XBIT_HF(1, hf_ulmap_mimo_ul_ir_harq_cc_ai_sn);
            XBIT_HF(2, hf_ulmap_mimo_ul_ir_harq_cc_spid);
        }
    }

#if 0
    if (include_cor2_changes)
    {
		/* CRC-16 is always appended */
		calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
		proto_tree_add_checksum(tree, tvb, BITHI(bit,16), hf_ulmap_crc16, -1, NULL, pinfo, calculated_crc,
									ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

		bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_STC_HARQ_Sub_Burst_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_STC_HARQ_Sub_Burst_IE -- table 302q */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    proto_item *tree;
    /*proto_item *generic_item = NULL;*/
    gint ackd,txct,sboi;
    /*guint16 calculated_crc;*/

    bit = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302q, NULL, "MIMO_UL_STC_HARQ_Sub_Burst_IE");

    XBIT_HF_VALUE(txct, 2, hf_ulmap_mimo_ul_stc_harq_tx_count);
    XBIT_HF(10, hf_ulmap_mimo_ul_stc_harq_duration);
    XBIT_HF_VALUE(sboi, 1, hf_ulmap_mimo_ul_stc_harq_sub_burst_offset_indication);
    /*XBIT_HF_VALUE(muin, 1, hf_ulmap_reserved_uint);*/
    if (sboi == 1) {
        XBIT_HF(8, hf_ulmap_mimo_ul_stc_harq_sub_burst_offset);
    }
    bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
    XBIT_HF_VALUE(ackd, 1, hf_ulmap_mimo_ul_stc_harq_ack_disable);
    if (txct == 0) {
        XBIT_HF(4, hf_ulmap_mimo_ul_stc_harq_uiuc);
        XBIT_HF(2, hf_ulmap_mimo_ul_stc_harq_repetition_coding_indication);
    }
    if (ackd == 0) {
        XBIT_HF(4, hf_ulmap_mimo_ul_stc_harq_acid);
    }

#if 0
    if (include_cor2_changes)
    {
		/* CRC-16 is always appended */
		calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
		proto_tree_add_checksum(tree, tvb, BITHI(bit,16), hf_ulmap_crc16, -1, NULL, pinfo, calculated_crc,
									ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

		bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

/********************************************************************
 * UL-MAP Extended IEs
 * table 290a
 *******************************************************************/

static gint Power_Control_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 0 */
    /* 8.4.5.4.5 Power_Control_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *tree;

    nib = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_292, NULL, "Power_Control_IE");

    VNIB(data, 1, hf_ulmap_ie_diuc_ext);
    VNIB(data, 1, hf_ulmap_ie_length);

    VNIB(data, 2, hf_ulmap_power_control);
    VNIB(data, 2, hf_ulmap_power_measurement_frame);
    return nib;
}

static gint Mini_Subchannel_allocation_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 1 */
    /* 8.4.5.4.8 [2] Mini-Subchannel_allocation_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    guint idx;
    proto_item *tree;
    gint j, M;
    const gint m_table[4] = { 2, 2, 3, 6 };

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_295, NULL, "Mini_subchannel_allocation_IE");

    XBIT_HF(4, hf_ulmap_mini_subcha_alloc_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_mini_subcha_alloc_length);

    XBIT_HF_VALUE(idx, 2, hf_ulmap_mini_subcha_alloc_ctype);
    M = m_table[idx];
    XBIT_HF(6, hf_ulmap_mini_subcha_alloc_duration);

    for (j = 0; j < M; j++) {
        data = TVB_BIT_BITS(bit, tvb, 16);
        proto_tree_add_uint_format(tree, hf_ulmap_mini_subcha_alloc_cid, tvb, BITHI(bit, 16), data, "CID(%d): %d", j, data);
        bit += 16;
        data = TVB_BIT_BITS(bit, tvb, 4);
        proto_tree_add_uint_format(tree, hf_ulmap_mini_subcha_alloc_uiuc, tvb, BITHI(bit, 4), data, "UIUC(%d): %d", j, data);
        bit += 4;
        data = TVB_BIT_BITS(bit, tvb, 2);
        proto_tree_add_uint_format(tree, hf_ulmap_mini_subcha_alloc_repetition, tvb, BITHI(bit, 2), data, "Repetition(%d): %d", j, data);
        bit += 2;
    }
    if (M == 3) {
        XBIT_HF(4, hf_ulmap_mini_subcha_alloc_padding);
    }
    return BIT_TO_NIB(bit);
}

static gint AAS_UL_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 2 */
    /* 8.4.5.4.6 [2] AAS_UL_IE*/
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_293, NULL, "AAS_UL_IE");

    XBIT_HF(4, hf_ulmap_aas_ul_extended_uiuc);
    XBIT_HF(4, hf_ulmap_aas_ul_length);

    XBIT_HF(2, hf_ulmap_aas_ul_permutation);
    XBIT_HF(7, hf_ulmap_aas_ul_ul_permbase);
    XBIT_HF(8, hf_ulmap_aas_ul_ofdma_symbol_offset);
    XBIT_HF(8, hf_ulmap_aas_ul_aas_zone_length);
    XBIT_HF(2, hf_ulmap_aas_ul_uplink_preamble_config);
    XBIT_HF(1, hf_ulmap_aas_ul_preamble_type);
    XBIT_HF(4, hf_ulmap_reserved_uint);
    return BIT_TO_NIB(bit);
}

static gint CQICH_Alloc_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 3 */
    /* 8.4.5.4.12 [2] CQICH_Alloc_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    gint target;
    proto_item *tree;
    gint rci, rtype, ftype, zperm, mgi, api, pad;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_300, NULL, "CQICH_Alloc_IE");

    XBIT_HF(4, hf_ulmap_cqich_alloc_extended_uiuc);
    XBIT_HF_VALUE(data, 4, hf_ulmap_cqich_alloc_length);
    target = bit + BYTE_TO_BIT(data);

    if (cqich_id_size == 0) {
        proto_tree_add_uint_format_value(tree, hf_ulmap_cqich_alloc_cqich_id, tvb, BITHI(bit, 1), cqich_id_size, "n/a (size == 0 bits)");
    } else {
        /* variable from 0-9 bits */
        data = TVB_BIT_BITS16(bit, tvb, cqich_id_size);
        proto_tree_add_uint_format_value(tree, hf_ulmap_cqich_alloc_cqich_id, tvb, BITHI(bit, cqich_id_size), data, "%d (%d bits)", data, cqich_id_size);
        bit += cqich_id_size;
    }

    XBIT_HF(6, hf_ulmap_cqich_alloc_allocation_offset);
    XBIT_HF(2, hf_ulmap_cqich_alloc_period);
    XBIT_HF(3, hf_ulmap_cqich_alloc_frame_offset);
    XBIT_HF(3, hf_ulmap_cqich_alloc_duration);
    XBIT_HF_VALUE(rci, 1, hf_ulmap_cqich_alloc_report_configuration_included);
    if (rci)
    {
        XBIT_HF_VALUE(ftype, 2, hf_ulmap_cqich_alloc_feedback_type);
        XBIT_HF_VALUE(rtype, 1, hf_ulmap_cqich_alloc_report_type);
        if (rtype == 0) {
            XBIT_HF(1, hf_ulmap_cqich_alloc_cinr_preamble_report_type);
        }
        else {
            XBIT_HF_VALUE(zperm, 3, hf_ulmap_cqich_alloc_zone_permutation);
            XBIT_HF(2, hf_ulmap_cqich_alloc_zone_type);
            XBIT_HF(2, hf_ulmap_cqich_alloc_zone_prbs_id);
            if (zperm == 0 || zperm == 1) {
                XBIT_HF_VALUE(mgi, 1, hf_ulmap_cqich_alloc_major_group_indication);
                if (mgi == 1) {
                    /* PUSC major group bitmap*/
                    XBIT_HF(6, hf_ulmap_cqich_alloc_pusc_major_group_bitmap);
                }
            }
            XBIT_HF(1, hf_ulmap_cqich_alloc_cinr_zone_measurement_type);
        }
        if (ftype == 0) {
            XBIT_HF_VALUE(api, 1, hf_ulmap_cqich_alloc_averaging_parameter_included);
            if (api == 1) {
                XBIT_HF(4, hf_ulmap_cqich_alloc_averaging_parameter);
            }
        }
    }
    XBIT_HF(2, hf_ulmap_cqich_alloc_mimo_permutation_feedback_cycle);

    pad = target - bit;
    if (pad) {
        proto_tree_add_bytes_format_value(tree, hf_ulmap_padding, tvb, BITHI(bit, pad), NULL, "%d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);	/* Return position in nibbles. */
}

static gint UL_Zone_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 4 */
    /* 8.4.5.4.7 [2] UL_Zone_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_294, NULL, "UL_Zone_IE");

    XBIT_HF(4, hf_ulmap_zone_extended_uiuc);
    XBIT_HF(4, hf_ulmap_zone_length);

    XBIT_HF(7, hf_ulmap_zone_ofdma_symbol_offset);
    XBIT_HF(2, hf_ulmap_zone_permutation);
    XBIT_HF(7, hf_ulmap_zone_ul_permbase);
    XBIT_HF(2, hf_ulmap_zone_amc_type);
    XBIT_HF(1, hf_ulmap_zone_use_all_sc_indicator);
    XBIT_HF(1, hf_ulmap_zone_disable_subchannel_rotation);
    XBIT_HF(4, hf_ulmap_reserved_uint);
    return BIT_TO_NIB(bit);
}

static gint PHYMOD_UL_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 5 */
    /* 8.4.5.4.14 [2] PHYMOD_UL_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;
    gint pmt;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302, NULL, "PHYMOD_UL_IE");

    XBIT_HF(4, hf_ulmap_phymod_ul_extended_uiuc);
    XBIT_HF(4, hf_ulmap_phymod_ul_length);

    XBIT_HF_VALUE(pmt, 1, hf_ulmap_phymod_ul_preamble_modifier_type);
    if (pmt == 0) {
        XBIT_HF(4, hf_ulmap_phymod_ul_preamble_frequency_shift_index);
    } else {
        XBIT_HF(4, hf_ulmap_phymod_ul_preamble_time_shift_index);
    }
    XBIT_HF(1, hf_ulmap_phymod_ul_pilot_pattern_modifier);
    XBIT_HF(2, hf_ulmap_phymod_ul_pilot_pattern_index);
    return BIT_TO_NIB(bit);
}

static gint MIMO_UL_IE(proto_tree *uiuc_tree, packet_info* pinfo, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 6 */
    /* 8.4.5.4.11 MIMO_UL_Basic_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *tree;

    nib = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_299, NULL, "MIMO_UL_Basic_IE");

    VNIB(data, 1, hf_ulmap_ie_diuc_ext);
    VNIB(data, 1, hf_ulmap_ie_length);
    proto_tree_add_expert(tree, pinfo, &ei_ulmap_not_implemented, tvb, NIBHI(nib,length-2));
    return nib;
}

static gint ULMAP_Fast_Tracking_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 7 */
    /* 8.4.5.4.22 [2] ULMAP_Fast_Tracking_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302h, NULL, "Fast_Tracking_IE");

    length = NIB_TO_BIT(length);

    XBIT_HF(4, hf_ulmap_fast_tracking_extended_uiuc);
    XBIT_HF(4, hf_ulmap_fast_tracking_length);

    XBIT_HF(2, hf_ulmap_fast_tracking_map_index);
    XBIT_HF(6, hf_ulmap_reserved_uint);
    while (bit < (length-7)) {
        XBIT_HF(3, hf_ulmap_fast_tracking_power_correction);
        XBIT_HF(3, hf_ulmap_fast_tracking_frequency_correction);
        XBIT_HF(2, hf_ulmap_fast_tracking_time_correction);
    }
    return BIT_TO_NIB(bit);
}

static gint UL_PUSC_Burst_Allocation_in_other_segment_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 8 */
    /* 8.4.5.4.17 [2] UL_PUSC_Burst_Allocation_in_other_segment_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302c, NULL, "UL_PUSC_Burst_Allocation_in_Other_Segment_IE");

    XBIT_HF(4, hf_ulmap_pusc_burst_allocation_extended_uiuc);
    XBIT_HF(4, hf_ulmap_pusc_burst_allocation_length);

    XBIT_HF(4, hf_ulmap_pusc_burst_allocation_uiuc);
    XBIT_HF(2, hf_ulmap_pusc_burst_allocation_segment);
    XBIT_HF(7, hf_ulmap_pusc_burst_allocation_ul_permbase);
    XBIT_HF(8, hf_ulmap_pusc_burst_allocation_ofdma_symbol_offset);
    XBIT_HF(6, hf_ulmap_pusc_burst_allocation_subchannel_offset);
    XBIT_HF(10, hf_ulmap_pusc_burst_allocation_duration);
    XBIT_HF(2, hf_ulmap_pusc_burst_allocation_repetition_coding_indication);
    XBIT_HF(1, hf_ulmap_reserved_uint);
    return BIT_TO_NIB(bit);
}

static gint Fast_Ranging_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 9 */
    /* 8.4.5.4.21 [2] Fast_Ranging_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;
    gint hidi;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302g, NULL, "Fast_Ranging_IE");

    XBIT_HF(4, hf_ulmap_fast_ranging_extended_uiuc);
    XBIT_HF(4, hf_ulmap_fast_ranging_length);

    XBIT_HF_VALUE(hidi, 1, hf_ulmap_fast_ranging_ho_id_indicator);
    XBIT_HF(7, hf_ulmap_reserved_uint);
    if (hidi == 1) {
        XBIT_HF(8, hf_ulmap_fast_ranging_ho_id);
        /* XBIT_HF(40, hf_ulmap_reserved_uint); TODO */
    } else {
        proto_tree_add_item(tree, hf_ulmap_fast_ranging_mac_address, tvb, BITHI(bit, 48), ENC_NA);
        bit += 48;
    }
    XBIT_HF(4, hf_ulmap_fast_ranging_uiuc);
    XBIT_HF(10, hf_ulmap_fast_ranging_duration);
    XBIT_HF(2, hf_ulmap_fast_ranging_repetition_coding_indication);
    return BIT_TO_NIB(bit);
}

static gint UL_Allocation_Start_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 0xA */
    /* 8.4.5.4.15 [2] UL_Allocation_Start_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302a, NULL, "UL_Allocation_start_IE");

    XBIT_HF(4, hf_ulmap_allocation_start_extended_uiuc);
    XBIT_HF(4, hf_ulmap_allocation_start_length);

    XBIT_HF(8, hf_ulmap_allocation_start_ofdma_symbol_offset);
    XBIT_HF(7, hf_ulmap_allocation_start_subchannel_offset);
    XBIT_HF(1, hf_ulmap_reserved_uint);
    return BIT_TO_NIB(bit);
}


/********************************************************************
 * UL-MAP Extended-2 IEs
 * table 290c
 *******************************************************************/

static gint CQICH_Enhanced_Allocation_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 0 */
    /* 8.4.5.4.16 [2] CQICH_Enhanced_Allocation_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *tree;
    gint i, cnum, bapm;
    guint pad;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302b, NULL, "CQICH_Enhanced_Alloc_IE");

    XBIT_HF(4, hf_ulmap_cqich_enhanced_alloc_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_cqich_enhanced_alloc_length);

    if (cqich_id_size == 0) {
        proto_tree_add_uint_format_value(tree, hf_ulmap_cqich_enhanced_alloc_cqich_id, tvb, BITHI(bit, 1), cqich_id_size, "n/a (size == 0 bits)");
    } else {
        /* variable from 0-9 bits */
        data = TVB_BIT_BITS16(bit, tvb, cqich_id_size);
        proto_tree_add_uint_format_value(tree, hf_ulmap_cqich_enhanced_alloc_cqich_id, tvb, BITHI(bit, cqich_id_size), data, "%d (%d bits)", data, cqich_id_size);
        bit += cqich_id_size;
    }

    XBIT_HF(3, hf_ulmap_cqich_enhanced_alloc_period);
    XBIT_HF(3, hf_ulmap_cqich_enhanced_alloc_frame_offset);
    XBIT_HF(3, hf_ulmap_cqich_enhanced_alloc_duration);
    XBIT_HF_VALUE(cnum, 4, hf_ulmap_cqich_enhanced_alloc_cqich_num);
    cnum += 1;
    for (i = 0; i < cnum; i++) {
        XBIT_HF(3, hf_ulmap_cqich_enhanced_alloc_feedback_type);
        XBIT_HF(6, hf_ulmap_cqich_enhanced_alloc_allocation_index);
        XBIT_HF(3, hf_ulmap_cqich_enhanced_alloc_cqich_type);
        XBIT_HF(1, hf_ulmap_cqich_enhanced_alloc_sttd_indication);
    }
    XBIT_HF_VALUE(bapm, 1, hf_ulmap_cqich_enhanced_alloc_band_amc_precoding_mode);
    if (bapm == 1) {
        XBIT_HF(3, hf_ulmap_cqich_enhanced_alloc_nr_precoders_feedback);
    }

    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_bytes_format_value(tree, hf_ulmap_padding, tvb, BITHI(bit, pad), NULL, "%d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint HO_Anchor_Active_UL_MAP_IE(proto_tree *uiuc_tree, packet_info* pinfo, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 1 */
    /* 8.4.5.4.18 [2] HO_Anchor_Active_UL_MAP_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *tree;

    nib = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302d, NULL, "HO_Anchor_Active_UL_MAP_IE");

    VNIB(data, 1, hf_ulmap_ie_diuc_ext2);
    VNIB(data, 2, hf_ulmap_ie_length);
    proto_tree_add_expert(tree, pinfo, &ei_ulmap_not_implemented, tvb, NIBHI(nib,length-3));
    return nib;
}

static gint HO_Active_Anchor_UL_MAP_IE(proto_tree *uiuc_tree, packet_info* pinfo, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 2 */
    /* 8.4.5.4.19 [2] HO_Active_Anchor_UL_MAP_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *tree;

    nib = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302e, NULL, "HO_Active_Anchor_UL_MAP_IE");

    VNIB(data, 1, hf_ulmap_ie_diuc_ext2);
    VNIB(data, 2, hf_ulmap_ie_length);
    proto_tree_add_expert(tree, pinfo, &ei_ulmap_not_implemented, tvb, NIBHI(nib,length-3));
    return nib;
}

static gint Anchor_BS_switch_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 3 */
    /* 8.4.5.4.23 [2] Anchor_BS_switch_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *tree;
    gint nbss, acod, cqai, pad;
    gint i;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302i, NULL, "Anchor_BS_switch_IE");

    XBIT_HF(4, hf_ulmap_anchor_bs_switch_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_anchor_bs_switch_length);

    XBIT_HF_VALUE(nbss, 4, hf_ulmap_anchor_bs_switch_n_anchor_bs_switch);
    for (i = 0; i < nbss; i++) {
        XBIT_HF(12, hf_ulmap_anchor_bs_switch_reduced_cid);
        XBIT_HF_VALUE(acod, 2, hf_ulmap_anchor_bs_switch_action_code);
        if (acod == 1) {
            XBIT_HF(3, hf_ulmap_anchor_bs_switch_action_time);
            XBIT_HF(3, hf_ulmap_anchor_bs_switch_temp_bs_id);
            XBIT_HF(2, hf_ulmap_reserved_uint);
        }
        if (acod == 0 || acod == 1) {
	    XBIT_HF(1, hf_ulmap_anchor_bs_switch_ak_change_indicator);
            XBIT_HF_VALUE(cqai, 1, hf_ulmap_anchor_bs_switch_cqich_allocation_indicator);
            if (cqai == 1) {
                /* variable bits from 0-9 */
                if (cqich_id_size == 0) {
                    proto_tree_add_uint_format_value(tree, hf_ulmap_anchor_bs_switch_cqich_id, tvb, BITHI(bit, 1), cqich_id_size, "n/a (size == 0 bits)");
                } else {
                    data = TVB_BIT_BITS16(bit, tvb, cqich_id_size);
                    proto_tree_add_uint_format_value(tree, hf_ulmap_anchor_bs_switch_cqich_id, tvb, BITHI(bit, cqich_id_size),
                        data, "%d (%d bits)", data, cqich_id_size);
                    bit += cqich_id_size;
                }
                XBIT_HF(6, hf_ulmap_anchor_bs_switch_feedback_channel_offset);
                XBIT_HF(2, hf_ulmap_anchor_bs_switch_period);
                XBIT_HF(3, hf_ulmap_anchor_bs_switch_frame_offset);
                XBIT_HF(3, hf_ulmap_anchor_bs_switch_duration);
                XBIT_HF(2, hf_ulmap_anchor_bs_switch_mimo_permutation_feedback_code);
                pad = BIT_PADDING(bit,8);
                if (pad) {
                    proto_tree_add_uint_format_value(tree, hf_ulmap_reserved, tvb, BITHI(bit,pad), 0, "%d bits", pad);
                }
            }
        } else {
            XBIT_HF(2, hf_ulmap_reserved_uint);
        }
    }
    XBIT_HF(4, hf_ulmap_reserved_uint);
    return BIT_TO_NIB(bit);
}

static gint UL_sounding_command_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 4 */
    /* 8.4.5.4.26 [2] UL_sounding_command_IE */
    /* see 8.4.6.2.7.1 */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;
    gint stype, srlf, iafb, pad, sept, nssym, ncid, amod;
    gint i, j;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_315d, NULL, "UL_Sounding_Command_IE");

    XBIT_HF(4, hf_ulmap_sounding_command_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_sounding_command_length);

    XBIT_HF_VALUE(stype, 1, hf_ulmap_sounding_command_type);
    XBIT_HF(1, hf_ulmap_sounding_command_send_sounding_report_flag);
    XBIT_HF_VALUE(srlf, 1, hf_ulmap_sounding_command_relevance_flag);
    if (srlf == 0) {
        XBIT_HF(1, hf_ulmap_sounding_command_relevance);
        XBIT_HF(2, hf_ulmap_reserved_uint);
    } else {
        XBIT_HF(3, hf_ulmap_reserved_uint);
    }
    XBIT_HF_VALUE(iafb, 2, hf_ulmap_sounding_command_include_additional_feedback);
    if (stype == 0) {
        XBIT_HF_VALUE(nssym, 3, hf_ulmap_sounding_command_num_sounding_symbols);
        XBIT_HF(1, hf_ulmap_reserved_uint);
        for (i = 0; i < nssym; i++) {
            XBIT_HF_VALUE(sept, 1, hf_ulmap_sounding_command_separability_type);
            if (sept == 0) {
                XBIT_HF(3, hf_ulmap_sounding_command_max_cyclic_shift_index_p);
                XBIT_HF(1, hf_ulmap_reserved_uint);
            } else {
                XBIT_HF(3, hf_ulmap_sounding_command_decimation_value);
                XBIT_HF(1, hf_ulmap_sounding_command_decimation_offset_randomization);
            }
            XBIT_HF(3, hf_ulmap_sounding_command_symbol_index);
            XBIT_HF_VALUE(ncid, 7, hf_ulmap_sounding_command_number_of_cids);
            XBIT_HF(1, hf_ulmap_reserved_uint);
            for (j = 0; j < ncid; j++) {
                XBIT_HF(12, hf_ulmap_sounding_command_shorted_basic_cid);
                XBIT_HF(2, hf_ulmap_sounding_command_power_assignment_method);
                XBIT_HF(1, hf_ulmap_sounding_command_power_boost);
                XBIT_HF(1, hf_ulmap_sounding_command_multi_antenna_flag);
                XBIT_HF_VALUE(amod, 1, hf_ulmap_sounding_command_allocation_mode);
                if (amod == 1) {
                    XBIT_HF(12, hf_ulmap_sounding_command_band_bit_map);
                    XBIT_HF(2, hf_ulmap_reserved_uint);
                } else {
                    XBIT_HF(7, hf_ulmap_sounding_command_starting_frequency_band);
                    XBIT_HF(7, hf_ulmap_sounding_command_number_of_frequency_bands);
                }
                if (srlf == 1) {
                    XBIT_HF(1, hf_ulmap_sounding_command_relevance);
                } else {
                    XBIT_HF(1, hf_ulmap_reserved_uint);
                }
                if (sept == 0) {
                    XBIT_HF(5, hf_ulmap_sounding_command_cyclic_time_shift_index);
                } else {
                    XBIT_HF(6, hf_ulmap_sounding_command_decimation_offset);
                    if (iafb == 1) {
                        XBIT_HF(1, hf_ulmap_sounding_command_use_same_symbol_for_additional_feedback);
                        XBIT_HF(2, hf_ulmap_reserved_uint);
                    } else {
                        XBIT_HF(3, hf_ulmap_reserved_uint);
                    }
                }
                XBIT_HF(3, hf_ulmap_sounding_command_periodicity);
            }
        }
    } else {
        XBIT_HF(3, hf_ulmap_sounding_command_permutation);
        XBIT_HF(6, hf_ulmap_sounding_command_dl_permbase);
        XBIT_HF_VALUE(nssym, 3, hf_ulmap_sounding_command_num_sounding_symbols);
        for (i = 0; i < nssym; i++) {
            XBIT_HF_VALUE(ncid, 7, hf_ulmap_sounding_command_number_of_cids);
            XBIT_HF(1, hf_ulmap_reserved_uint);
            for (j = 0; j < ncid; j++) {
                XBIT_HF(12, hf_ulmap_sounding_command_shortened_basic_cid);
                if (srlf) {
                    XBIT_HF(1, hf_ulmap_sounding_command_relevance);
                    XBIT_HF(3, hf_ulmap_reserved_uint);
                }
                XBIT_HF(7, hf_ulmap_sounding_command_subchannel_offset);
                XBIT_HF(1, hf_ulmap_sounding_command_power_boost);
                XBIT_HF(3, hf_ulmap_sounding_command_number_of_subchannels);
                XBIT_HF(3, hf_ulmap_sounding_command_periodicity);
                XBIT_HF(2, hf_ulmap_sounding_command_power_assignment_method);
            }
        }
    }
    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_bytes_format_value(tree, hf_ulmap_padding, tvb, BITHI(bit, pad), NULL, "%d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint MIMO_UL_Enhanced_IE(proto_tree *uiuc_tree, packet_info* pinfo, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 6 */
    /* 8.4.5.4.20 [2] MIMO_UL_Enhanced_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *tree;

    nib = offset;

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302f, NULL, "MIMO_UL_Enhanced_IE");

    VNIB(data, 1, hf_ulmap_ie_diuc_ext2);
    VNIB(data, 2, hf_ulmap_ie_length);
    proto_tree_add_expert(tree, pinfo, &ei_ulmap_not_implemented, tvb, NIBHI(nib,length-3));
    return nib;
}

static gint HARQ_ULMAP_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 7 */
    /* 8.4.5.4.24 HARQ_ULMAP_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;
    gint bitlength;
    gint lastbit;
    gint pad, mode, alsi, nsub;
    gint i;

    bit = NIB_TO_BIT(offset);
    bitlength = NIB_TO_BIT(length);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302j, NULL, "HARQ_ULMAP_IE");

    XBIT_HF(4, hf_ulmap_harq_ulmap_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_harq_ulmap_length);

    XBIT_HF_VALUE(RCID_Type, 2, hf_ulmap_harq_ulmap_rcid_type);
    XBIT_HF(2, hf_ulmap_reserved_uint);
    lastbit = bit + bitlength -16 - 4;
    while (bit < lastbit) {
        XBIT_HF_VALUE(mode, 3, hf_ulmap_harq_ulmap_mode);
        XBIT_HF_VALUE(alsi, 1, hf_ulmap_harq_ulmap_allocation_start_indication);
        if (alsi == 1) {
            XBIT_HF(8, hf_ulmap_harq_ulmap_ofdma_symbol_offset);
            XBIT_HF(7, hf_ulmap_harq_ulmap_subchannel_offset);
            XBIT_HF(1, hf_ulmap_reserved_uint);
        }
        XBIT_HF_VALUE(nsub, 4, hf_ulmap_harq_ulmap_n_sub_burst);
        nsub++;
        for (i = 0; i < nsub; i++) {
            if (mode == 0) {
                bit += UL_HARQ_Chase_Sub_Burst_IE(tree, bit, bitlength, tvb);
            } else if (mode == 1) {
               bit +=  UL_HARQ_IR_CTC_Sub_Burst_IE(tree, bit, bitlength, tvb);
            } else if (mode == 2) {
                bit += UL_HARQ_IR_CC_Sub_Burst_IE(tree, bit, bitlength, tvb);
            } else if (mode == 3) {
                bit += MIMO_UL_Chase_HARQ_Sub_Burst_IE(tree, bit, bitlength, tvb);
            } else if (mode == 4) {
                bit += MIMO_UL_IR_HARQ__Sub_Burst_IE(tree, bit, bitlength, tvb);
            } else if (mode == 5) {
                bit += MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE(tree, bit, bitlength, tvb);
            } else if (mode == 6) {
                bit += MIMO_UL_STC_HARQ_Sub_Burst_IE(tree, bit, bitlength, tvb);
            }
        }
    }

    pad = NIB_TO_BIT(offset) + bitlength - bit;
    if (pad) {
        proto_tree_add_bytes_format_value(tree, hf_ulmap_padding, tvb, BITHI(bit, pad), NULL, "%d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint HARQ_ACKCH_Region_Allocation_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 8 */
    /* 8.4.5.4.25 [2] HARQ_ACKCH_Region_Allocation_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302t, NULL, "HARQ_ACKCH_Region_IE");

    XBIT_HF(4, hf_ulmap_harq_ackch_region_alloc_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_harq_ackch_region_alloc_length);

    XBIT_HF(8, hf_ulmap_harq_ackch_region_alloc_ofdma_symbol_offset);
    XBIT_HF(7, hf_ulmap_harq_ackch_region_alloc_subchannel_offset);
    XBIT_HF(5, hf_ulmap_harq_ackch_region_alloc_num_ofdma_symbols);
    XBIT_HF(4, hf_ulmap_harq_ackch_region_alloc_num_subchannels);
    return BIT_TO_NIB(bit);
}

static gint AAS_SDMA_UL_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 0xE */
    /* 8.4.5.4.27 [2] AAS_SDMA_UL_IE  */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;
    gint nreg, pad, user, encm, ppmd, padj;
    gint aasp = 0; /* TODO AAS UL preamble used */
    gint ii, jj;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302u, NULL, "AAS_SDMA_UL_IE");

    XBIT_HF(4, hf_ulmap_aas_sdma_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_aas_sdma_length);

    XBIT_HF_VALUE(RCID_Type, 2, hf_ulmap_aas_sdma_rcid_type);
    XBIT_HF_VALUE(nreg, 4, hf_ulmap_aas_sdma_num_burst_region);
    XBIT_HF(2, hf_ulmap_reserved_uint);
    for (ii = 0; ii < nreg; ii++) {
        XBIT_HF(12, hf_ulmap_aas_sdma_slot_offset);
        XBIT_HF(10, hf_ulmap_aas_sdma_slot_duration);
        XBIT_HF_VALUE(user, 3, hf_ulmap_aas_sdma_number_of_users);
        XBIT_HF(3, hf_ulmap_reserved_uint);
        for (jj = 0; jj < user; jj++) {
            bit += RCID_IE(tree, bit, length, tvb, RCID_Type);
            XBIT_HF_VALUE(encm, 2, hf_ulmap_aas_sdma_encoding_mode);
            XBIT_HF_VALUE(padj, 1, hf_ulmap_aas_sdma_power_adjust);
            XBIT_HF_VALUE(ppmd, 1, hf_ulmap_aas_sdma_pilot_pattern_modifier);
            if (aasp) {
                XBIT_HF(4, hf_ulmap_aas_sdma_preamble_modifier_index);
            }
            if (ppmd) {
                XBIT_HF(2, hf_ulmap_aas_sdma_pilot_pattern);
                XBIT_HF(2, hf_ulmap_reserved_uint);
            }
            if (encm == 0) {
                XBIT_HF(4, hf_ulmap_aas_sdma_diuc);
                XBIT_HF(2, hf_ulmap_aas_sdma_repetition_coding_indication);
                XBIT_HF(2, hf_ulmap_reserved_uint);
            }
            if (encm == 1) {
                XBIT_HF(4, hf_ulmap_aas_sdma_diuc);
                XBIT_HF(2, hf_ulmap_aas_sdma_repetition_coding_indication);
                XBIT_HF(4, hf_ulmap_aas_sdma_acid);
                XBIT_HF(1, hf_ulmap_aas_sdma_ai_sn);
                XBIT_HF(1, hf_ulmap_reserved_uint);
            }
            if (encm == 2) {
                XBIT_HF(4, hf_ulmap_aas_sdma_nep);
                XBIT_HF(4, hf_ulmap_aas_sdma_nsch);
                XBIT_HF(2, hf_ulmap_aas_sdma_spid);
                XBIT_HF(4, hf_ulmap_aas_sdma_acid);
                XBIT_HF(1, hf_ulmap_aas_sdma_ai_sn);
                XBIT_HF(1, hf_ulmap_reserved_uint);
            }
            if (encm == 3) {
                XBIT_HF(4, hf_ulmap_aas_sdma_diuc);
                XBIT_HF(2, hf_ulmap_aas_sdma_repetition_coding_indication);
                XBIT_HF(2, hf_ulmap_aas_sdma_spid);
                XBIT_HF(4, hf_ulmap_aas_sdma_acid);
                XBIT_HF(1, hf_ulmap_aas_sdma_ai_sn);
                XBIT_HF(3, hf_ulmap_reserved_uint);
            }
            if (padj) {
                XBIT_HF(8, hf_ulmap_aas_sdma_power_adjustment);

            }
        }
    }

    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_bytes_format_value(tree, hf_ulmap_padding, tvb, BITHI(bit, pad), NULL, "%d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint Feedback_Polling_IE(proto_tree *uiuc_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 0xF */
    /* 8.4.5.4.28 [2] Feedback_Polling_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    proto_item *tree;
    gint nalloc, dula, pad, adur;
    gint i;

    bit = NIB_TO_BIT(offset);

    tree = proto_tree_add_subtree(uiuc_tree, tvb, NIBHI(offset, length), ett_302v, NULL, "Feedback_Polling_IE");

    XBIT_HF(4, hf_ulmap_feedback_polling_extended_2_uiuc);
    XBIT_HF(8, hf_ulmap_feedback_polling_length);

    XBIT_HF_VALUE(nalloc, 4, hf_ulmap_feedback_polling_num_allocation);
    XBIT_HF_VALUE(dula, 1, hf_ulmap_feedback_polling_dedicated_ul_allocation_included);
    XBIT_HF(3, hf_ulmap_reserved_uint);
    for (i = 0; i < nalloc; i++) {
        XBIT_HF(16, hf_ulmap_feedback_polling_basic_cid);
        XBIT_HF_VALUE(adur, 3, hf_ulmap_feedback_polling_allocation_duration);
        if (adur != 0) {
            XBIT_HF(4, hf_ulmap_feedback_polling_type);
            XBIT_HF(3, hf_ulmap_feedback_polling_frame_offset);
            XBIT_HF(2, hf_ulmap_feedback_polling_period);
            if (dula == 1) {
                XBIT_HF(4, hf_ulmap_feedback_polling_uiuc);
                XBIT_HF(8, hf_ulmap_feedback_polling_ofdma_symbol_offset);
                XBIT_HF(7, hf_ulmap_feedback_polling_subchannel_offset);
                XBIT_HF(3, hf_ulmap_feedback_polling_duration);
                XBIT_HF(2, hf_ulmap_feedback_polling_repetition_coding_indication);
            }
        }
    }
    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_bytes_format_value(tree, hf_ulmap_padding, tvb, BITHI(bit, pad), NULL, "%d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}


/********************************************************************
 * UL-MAP Miscellany
 *******************************************************************/

gint dissect_ulmap_ie( proto_tree *ie_tree, packet_info* pinfo, gint offset, gint length _U_, tvbuff_t *tvb)
{
    /* decode a single UL-MAP IE and return the
     * length of the IE in nibbles
     * offset = start of IE (nibbles)
     * length = total length of tvb (nibbles) */
    proto_item *ti;
    proto_tree *tree;
    gint nibble;
    gint uiuc, ext_uiuc, ext2_uiuc, len, aas_or_amc;
    guint cid;
    guint data;
    guint32 data32;

    nibble = offset;

    /* 8.4.5.4 UL-MAP IE format - table 287 */
    cid = TVB_NIB_WORD(nibble, tvb);
    uiuc = TVB_NIB_NIBBLE(nibble + 4, tvb);

    if (uiuc == 0)
    {
        /* 8.4.5.4.9 FAST-FEEDBACK channel */
        tree = proto_tree_add_subtree(ie_tree, tvb, NIBHI(nibble, 5+8), ett_ulmap_ffb, NULL, "FAST FEEDBACK Allocation IE");

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = TVB_NIB_LONG(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_symofs, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_subofs, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_numsym, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_numsub, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_rsv,    tvb, NIBHI(nibble, 8), data);
        nibble += 8;
    }
    else if (uiuc == 11)
    {
        /* 8.4.5.4.4.2 [2] extended-2 UIUC IE table 290b */
        ext2_uiuc = TVB_NIB_NIBBLE(5+nibble, tvb);
        len = TVB_NIB_BYTE(5+nibble+1, tvb);

        tree = proto_tree_add_subtree_format(ie_tree, tvb, NIBHI(nibble, 5+3+len*2), ett_290b, NULL, "UIUC: %d (Extended-2 IE)", uiuc);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

#if 0
        proto_tree_add_uint(tree, hf_ulmap_uiuc11_ext, tvb, NIBHI(nibble, 1), ext2_uiuc);
        nibble += 1;
        proto_tree_add_uint(tree, hf_ulmap_uiuc11_len, tvb, NIBHI(nibble, 2), len);
        nibble += 2;
#endif

        len = 3 + BYTE_TO_NIB(len); /* length in nibbles */

        /* data table 290c 8.4.5.4.4.2 */
        switch (ext2_uiuc) {
            case 0x00:
                /* 8.4.5.4.16 CQICH_Enhanced_Allocation_IE */
                nibble = CQICH_Enhanced_Allocation_IE(tree, nibble, len, tvb);
                break;
            case 0x01:
                /* 8.4.5.4.18 HO_Anchor_Active_UL_MAP_IE */
                nibble = HO_Anchor_Active_UL_MAP_IE(tree, pinfo, nibble, len, tvb);
                break;
            case 0x02:
                /* 8.4.5.4.19 HO_Active_Anchor_UL_MAP_IE */
                nibble = HO_Active_Anchor_UL_MAP_IE(tree, pinfo, nibble, len, tvb);
                break;
            case 0x03:
                /* 8.4.5.4.23 Anchor_BS_switch_IE */
                nibble = Anchor_BS_switch_IE(tree, nibble, len, tvb);
                break;
            case 0x04:
                /* 8.4.5.4.26 UL_sounding_command_IE */
                nibble = UL_sounding_command_IE(tree, nibble, len, tvb);
                break;
            case 0x06:
                /* 8.4.5.4.20 MIMO_UL_Enhanced_IE */
                nibble = MIMO_UL_Enhanced_IE(tree, pinfo, nibble, len, tvb);
                break;
            case 0x07:
                /* 8.4.5.4.24 HARQ_ULMAP_IE */
                nibble = HARQ_ULMAP_IE(tree, nibble, len, tvb);
                break;
            case 0x08:
                /* 8.4.5.4.25 HARQ_ACKCH_Region_Allocation_IE */
                nibble = HARQ_ACKCH_Region_Allocation_IE(tree, nibble, len, tvb);
                break;
            case 0x0e:
                /* 8.4.5.4.27 AAS_SDMA_UL_IE */
                nibble = AAS_SDMA_UL_IE(tree, nibble, len, tvb);
                break;
            case 0x0f:
                /* 8.4.5.4.28 Feedback_Polling_IE */
                nibble = Feedback_Polling_IE(tree, nibble, len, tvb);
                break;

            default:
                proto_tree_add_bytes_format(tree, hf_ulmap_ie_reserved_extended2_duic, tvb, NIBHI(nibble, len), NULL, "(reserved Extended-2 UIUC: %d)", ext2_uiuc);
                nibble += len;
                break;

        }
    }
    else if (uiuc == 12)
    {
        /* 8.4.5.4 [2] CDMA bandwidth request, CDMA ranging */
        tree = proto_tree_add_subtree(ie_tree, tvb, NIBHI(nibble, 5+8), ett_287_1, NULL, "CDMA Bandwidth/Ranging Request IE");

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data32 = TVB_NIB_LONG(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_symofs, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_subofs, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_numsym, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_numsub, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_method, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_dri,    tvb, NIBHI(nibble,8), data32);
        nibble += 8;
    }
    else if (uiuc == 13)
    {
        /* 8.4.5.4.2 [2] PAPR reduction allocation, safety zone - table 289 */
        tree = proto_tree_add_subtree(ie_tree, tvb, NIBHI(nibble,5+8), ett_289, NULL, "PAPR/Safety/Sounding Zone IE");


        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = TVB_NIB_LONG(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_symofs, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_subofs, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_numsym, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_numsub, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_papr,   tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_zone,   tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_rsv,    tvb, NIBHI(nibble,8), data);
        nibble += 8;
    }
    else if (uiuc == 14)
    {
        /* 8.4.5.4.3 [2] CDMA allocation IE */
        tree = proto_tree_add_subtree(ie_tree, tvb, NIBHI(nibble,5+10), ett_290, &ti, "CDMA allocation IE");

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = TVB_NIB_WORD(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_dur,  tvb, NIBHI(nibble,2), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_uiuc, tvb, NIBHI(nibble+1,2), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_rep,  tvb, NIBHI(nibble+2,1), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_idx,  tvb, NIBHI(nibble+3,1), data);
        nibble += 4;

        data = TVB_NIB_BYTE(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_code, tvb, NIBHI(nibble,2), data);
        proto_item_append_text(ti, " (0x%02x)", data);
        nibble += 2;

        data = TVB_NIB_BYTE(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_sym,  tvb, NIBHI(nibble,2), data);
        proto_item_append_text(ti, " (0x%02x)", data);
        nibble += 2;

        data = TVB_NIB_BYTE(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_sub,  tvb, NIBHI(nibble,2), data);
        proto_item_append_text(ti, " (0x%02x)", data >> 1);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_bwr,  tvb, NIBHI(nibble+1,1), data);
        nibble += 2;
    }
    else if (uiuc == 15)
    {
        /* 8.4.5.4.4 [1] Extended UIUC dependent IE table 291 */
        ext_uiuc = TVB_NIB_NIBBLE(5+nibble, tvb);
        len = TVB_NIB_NIBBLE(5+nibble+1, tvb);

        tree = proto_tree_add_subtree_format(ie_tree, tvb, NIBHI(nibble, 5+2+len*2), ett_291, NULL, "UIUC: %d (Extended IE)", uiuc);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble,4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble,1), uiuc);
        nibble += 1;

#if 0
        ti = proto_tree_add_uint(tree, hf_ulmap_uiuc11_ext, tvb, NIBHI(nibble,1), ext_uiuc);
        nibble += 1;
        proto_tree_add_uint(tree, hf_ulmap_uiuc11_len, tvb, NIBHI(nibble,1), len);
        nibble += 1;
#endif

        len = 2 + BYTE_TO_NIB(len); /* length in nibbles */

        /* data table 290a 8.4.5.4.4.1 */
        switch (ext_uiuc) {
            case 0x00:
                /* 8.4.5.4.5 Power_Control_IE */
                nibble = Power_Control_IE(tree, nibble, len, tvb);
                break;
            case 0x01:
                /* 8.4.5.4.8 Mini-Subchannel_allocation_IE*/
                nibble = Mini_Subchannel_allocation_IE(tree, nibble, len, tvb);
                break;
            case 0x02:
                /* 8.4.5.4.6 AAS_UL_IE*/
                nibble = AAS_UL_IE(tree, nibble, len, tvb);
                break;
            case 0x03:
                /* 8.4.5.4.12 CQICH_Alloc_IE */
                nibble = CQICH_Alloc_IE(tree, nibble, len, tvb);
                break;
            case 0x04:
                /* 8.4.5.4.7 UL_Zone_IE */
                nibble = UL_Zone_IE(tree, nibble, len, tvb);
                break;
            case 0x05:
                /* 8.4.5.4.14 PHYMOD_UL_IE */
                nibble = PHYMOD_UL_IE(tree, nibble, len, tvb);
                break;
            case 0x06:
                /* 8.4.5.4.11 MIMO_UL_IE */
                nibble = MIMO_UL_IE(tree, pinfo, nibble, len, tvb);
                break;
            case 0x07:
                /* 8.4.5.4.22 ULMAP_Fast_Tracking_IE */
                nibble = ULMAP_Fast_Tracking_IE(tree, nibble, len, tvb);
                break;
            case 0x08:
                /* 8.4.5.4.17 UL_PUSC_Burst_Allocation_in_other_segment_IE */
                nibble = UL_PUSC_Burst_Allocation_in_other_segment_IE(tree, nibble, len, tvb);
                break;
            case 0x09:
                /* 8.4.5.4.21 Fast_Ranging_IE */
                nibble = Fast_Ranging_IE(tree, nibble, len, tvb);
                break;
            case 0x0a:
                /* 8.4.5.4.15 UL_Allocation_Start_IE */
                nibble = UL_Allocation_Start_IE(tree, nibble, len, tvb);
                break;
            default:
                proto_tree_add_bytes_format_value(tree, hf_ulmap_ie_reserved_extended_duic, tvb, NIBHI(nibble,len), NULL, "(reserved Extended UIUC: %d)", ext_uiuc);
                nibble += len;
                break;
        }
    }
    else
    {
        /* 8.4.5.4 [2] regular IE 1-10, data grant burst type */
        aas_or_amc = 0; /* TODO */
        len = 3;

        if (aas_or_amc) len += 3;

        tree = proto_tree_add_subtree(ie_tree, tvb, NIBHI(nibble, 5+len), ett_287_2, NULL, "Data Grant Burst Profile");

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = TVB_NIB_WORD(nibble, tvb);
        proto_tree_add_uint(tree, hf_ulmap_uiuc10_dur, tvb, NIBHI(nibble,3), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc10_rep, tvb, NIBHI(nibble+2,1), data);
        nibble += 3;

        if (aas_or_amc) {
            data = TVB_NIB_BITS12(nibble, tvb);
            proto_tree_add_uint(tree, hf_ulmap_uiuc10_slot_offset, tvb, NIBHI(nibble,3), data);
            nibble += 3;
        }
    }

    /* length in nibbles */
    return (nibble - offset);
}

static int dissect_mac_mgmt_msg_ulmap_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    /* 6.3.2.3.4 [2] UL-MAP table 18 */
    guint offset = 0;
    guint length;
    guint nib, pad;
    proto_item *ti         = NULL;
    proto_tree *ulmap_tree = NULL;
    proto_tree *ie_tree    = NULL;
    guint tvb_len;

    tvb_len = tvb_reported_length(tvb);

    /* display MAC UL-MAP */
    ti = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_ulmap_decoder, tvb, offset, -1, "UL-MAP");
    ulmap_tree = proto_item_add_subtree(ti, ett_ulmap);

    proto_tree_add_item(ulmap_tree, hf_ulmap_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ulmap_tree, hf_ulmap_ucd_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ulmap_tree, hf_ulmap_alloc_start_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ulmap_tree, hf_ulmap_ofdma_sym, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* UL-MAP IEs */
    length = tvb_len - offset; /* remaining length in bytes */
    ie_tree = proto_tree_add_subtree_format(ulmap_tree, tvb, offset, length, ett_ulmap_ie, NULL, "UL-MAP IEs (%u bytes)", length);

    /* length = BYTE_TO_NIB(length); */ /* convert length to nibbles */
    nib = BYTE_TO_NIB(offset);
    while (nib < ((tvb_len*2)-1)) {
        nib += dissect_ulmap_ie(ie_tree, pinfo, nib, tvb_len*2, tvb);
    }
    pad = NIB_PADDING(nib);
    if (pad) {
        proto_tree_add_bytes_format(ulmap_tree, hf_ulmap_padding, tvb, NIBHI(nib,1), NULL, "Padding nibble");
        nib++;
    }
    return tvb_captured_length(tvb);
}

/*gint wimax_decode_ulmapc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)*/
gint wimax_decode_ulmapc(proto_tree *base_tree, packet_info* pinfo, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.6.2 [2] Compressed UL-MAP */
    /* returns length in nibbles */
    gint nib;
    guint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_tree *ie_tree = NULL;

    nib = offset;

    /* display MAC UL-MAP */
    ti = proto_tree_add_protocol_format(base_tree, proto_mac_mgmt_msg_ulmap_decoder, tvb, NIBHI(offset,length-offset), "Compressed UL-MAP (%u bytes)", NIB_ADDR(length-offset));
    tree = proto_item_add_subtree(ti, ett_306);

    /* Decode and display the UL-MAP */
    data = TVB_NIB_BYTE(nib, tvb);
    proto_tree_add_uint(tree, hf_ulmap_ucd_count, tvb, NIBHI(nib,2), data);
    nib += 2;
    data = TVB_NIB_LONG(nib, tvb);
    proto_tree_add_uint(tree, hf_ulmap_alloc_start_time, tvb, NIBHI(nib,8), data);
    nib += 8;
    data = TVB_NIB_BYTE(nib, tvb);
    proto_tree_add_uint(tree, hf_ulmap_ofdma_sym, tvb, NIBHI(nib,2), data); /* added 2005 */
    nib += 2;

    ie_tree = proto_tree_add_subtree_format(tree, tvb, NIBHI(nib,length-nib), ett_306_ul, NULL, "UL-MAP IEs (%u bytes)", NIB_ADDR(length-nib));
    while (nib < length-1) {
        nib += dissect_ulmap_ie(ie_tree, pinfo, nib, length-nib, tvb);
    }

    /* padding */
    if (nib & 1) {
        proto_tree_add_bytes_format(tree, hf_ulmap_padding, tvb, NIBHI(nib,1), NULL, "Padding nibble");
        nib++;
    }


    return length;
}


gint wimax_decode_ulmap_reduced_aas(proto_tree *base_tree, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.8.2 Reduced AAS private UL-MAP */
    /* offset and length are in bits since this is called from within
     * the Reduced AAS private DL-MAP
     * return length in bits */
    gint bit;
    guint data;
    proto_tree *tree;
    gint azci, azpi, umii, phmi, powi;

    bit = offset;

    tree = proto_tree_add_subtree(base_tree, tvb, BITHI(bit,length), ett_308b, NULL, "Reduced_AAS_Private_UL_MAP");

    /* Decode and display the Reduced AAS private UL-MAP */
    XBIT_HF_VALUE(azci, 1, hf_ulmap_reduced_aas_aas_zone_configuration_included);
    XBIT_HF_VALUE(azpi, 1, hf_ulmap_reduced_aas_aas_zone_position_included);
    XBIT_HF_VALUE(umii, 1, hf_ulmap_reduced_aas_ul_map_information_included);
    XBIT_HF_VALUE(phmi, 1, hf_ulmap_reduced_aas_phy_modification_included);
    XBIT_HF_VALUE(powi, 1, hf_ulmap_reduced_aas_power_control_included);
    XBIT_HF(2, hf_ulmap_reduced_aas_include_feedback_header);
    XBIT_HF(2, hf_ulmap_reduced_aas_encoding_mode);

    if (azci) {
        XBIT_HF(2, hf_ulmap_reduced_aas_permutation);
        XBIT_HF(7, hf_ulmap_reduced_aas_ul_permbase);
        XBIT_HF(2, hf_ulmap_reduced_aas_preamble_indication);
        XBIT_HF(5, hf_ulmap_reduced_aas_padding);
    }
    if (azpi) {
        XBIT_HF(8, hf_ulmap_reduced_aas_zone_symbol_offset);
        XBIT_HF(8, hf_ulmap_reduced_aas_zone_length);
    }
    if (umii) {
        XBIT_HF(8, hf_ulmap_reduced_aas_ucd_count);
        data = TVB_BIT_BITS64(bit,tvb,32);
        proto_tree_add_uint64(tree, hf_ulmap_reduced_aas_private_map_alloc_start_time, tvb, BITHI(bit,32), data);
        bit += 32;
    }
    if (phmi) {
        XBIT_HF(1, hf_ulmap_reduced_aas_preamble_select);
        XBIT_HF(4, hf_ulmap_reduced_aas_preamble_shift_index);
        XBIT_HF(1, hf_ulmap_reduced_aas_pilot_pattern_modifier);
        data = TVB_BIT_BITS32(bit,tvb,22);
        proto_tree_add_uint64(tree, hf_ulmap_reduced_aas_pilot_pattern_index, tvb, BITHI(bit,22), data);
        bit += 22;
    }
    if (powi) {
        XBIT_HF(8, hf_ulmap_reduced_aas_power_control);
    }
    XBIT_HF(3, hf_ulmap_reduced_aas_ul_frame_offset);
    XBIT_HF(12, hf_ulmap_reduced_aas_slot_offset);
    XBIT_HF(10, hf_ulmap_reduced_aas_slot_duration);
    XBIT_HF(4, hf_ulmap_reduced_aas_uiuc_nep);
    if (harq) {
        XBIT_HF(4, hf_ulmap_reduced_aas_acid);
        XBIT_HF(1, hf_ulmap_reduced_aas_ai_sn);
        XBIT_HF(3, hf_ulmap_reserved_uint);
        if (ir_type) {
            XBIT_HF(4, hf_ulmap_reduced_aas_nsch);
            XBIT_HF(2, hf_ulmap_reduced_aas_spid);
            XBIT_HF(2, hf_ulmap_reserved_uint);
        }
    }
    XBIT_HF(2, hf_ulmap_reduced_aas_repetition_coding_indication);

    return (bit - offset); /* length in bits */
}


/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_ulmap(void)
{
	/* UL-MAP fields display */
	static hf_register_info hf[] =
	{
#if 0
		{
			&hf_ulmap_fch_expected,
			{
				"FCH Expected", "wmx.ulmap.fch.expected",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
#if 0
		{
			&hf_ulmap_ie,
			{
				"UL-MAP IE", "wmx.ulmap.ie",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
		{
			&hf_ulmap_ie_cid,
			{
				"CID", "wmx.ulmap.ie.cid",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ie_uiuc,
			{
				"UIUC", "wmx.ulmap.ie.uiuc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ofdma_sym,
			{
				"Num OFDMA Symbols", "wmx.ulmap.ofdma.sym",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ie_diuc_ext,
			{
				"Extended DIUC", "wmx.ulmap.ie.ext_diuc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ie_diuc_ext2,
			{
				"Extended-2 DIUC", "wmx.ulmap.ie.ext2_diuc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ie_length,
			{
				"Length", "wmx.ilmap.ie.length",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ie_reserved_extended2_duic,
			{
				"Reserved Extended-2 DIUC", "wmx.ulmap.ie.ext2_diuc_reserved",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ie_reserved_extended_duic,
			{
				"Reserved Extended DIUC", "wmx.ulmap.ie.ext_diuc_reserved",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_reserved,
			{
				"Reserved", "wmx.ulmap.rsv",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_alloc_start_time,
			{
				"Uplink Channel ID", "wmx.ulmap.start",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ucd_count,
			{
				"UCD Count", "wmx.ulmap.ucd",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_numsub,
			{
				"No. subchannels", "wmx.ulmap.uiuc0.numsub",
				FT_UINT32,	BASE_DEC, NULL, 0x000003f8, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_numsym,
			{
				"No. OFDMA symbols", "wmx.ulmap.uiuc0.numsym",
				FT_UINT32,	BASE_DEC, NULL, 0x0001fc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_rsv,
			{
				"Reserved", "wmx.ulmap.uiuc0.rsv",
				FT_UINT32,	BASE_DEC, NULL, 0x00000007, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_subofs,
			{
				"Subchannel offset", "wmx.ulmap.uiuc0.subofs",
				FT_UINT32,	BASE_DEC, NULL, 0x00fe0000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_symofs,
			{
				"OFDMA symbol offset", "wmx.ulmap.uiuc0.symofs",
				FT_UINT32,	BASE_DEC, NULL, 0xff000000, NULL, HFILL
			}
		},
#if 0
		{
			&hf_ulmap_uiuc11_data,
			{
				"Data", "wmx.ulmap.uiuc11.data",
				FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc11_ext,
			{
				"Extended 2 UIUC", "wmx.ulmap.uiuc11.ext",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc11_len,
			{
				"Length", "wmx.ulmap.uiuc11.len",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
		{
			&hf_ulmap_uiuc12_dri,
			{
				"Dedicated ranging indicator", "wmx.ulmap.uiuc12.dri",
				FT_UINT32, BASE_DEC, NULL, 0x00000001, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc10_dur,
			{
				"Duration", "wmx.ulmap.uiuc12.dur",
				FT_UINT16, BASE_DEC, NULL, 0xFFc0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_method,
			{
				"Ranging Method", "wmx.ulmap.uiuc12.method",
				FT_UINT32, BASE_DEC, NULL, 0x00000006, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_numsub,
			{
				"No. Subchannels", "wmx.ulmap.uiuc12.numsub",
				FT_UINT32, BASE_DEC, NULL, 0x000003F8, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_numsym,
			{
				"No. OFDMA Symbols", "wmx.ulmap.uiuc12.numsym",
				FT_UINT32, BASE_DEC, NULL, 0x0001Fc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc10_rep,
			{
				"Repetition Coding indication", "wmx.ulmap.uiuc10.rep",
				FT_UINT16, BASE_DEC, NULL, 0x0030, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc10_slot_offset,
			{
				"Slot offset", "wmx.ulmap.uiuc10.slot_offset",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_subofs,
			{
				"Subchannel Offset", "wmx.ulmap.uiuc12.subofs",
				FT_UINT32, BASE_DEC, NULL, 0x00Fe0000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_symofs,
			{
				"OFDMA Symbol Offset", "wmx.ulmap.uiuc12.symofs",
				FT_UINT32, BASE_DEC, NULL, 0xFF000000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_numsub,
			{
				"No. Subchannels/SZ Shift Value", "wmx.ulmap.uiuc13.numsub",
				FT_UINT32,	BASE_DEC, NULL, 0x000003f8, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_numsym,
			{
				"No. OFDMA symbols", "wmx.ulmap.uiuc13.numsym",
				FT_UINT32,	BASE_DEC, NULL, 0x0001fc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_papr,
			{
				"PAPR Reduction/Safety Zone", "wmx.ulmap.uiuc13.papr",
				FT_UINT32,	BASE_DEC, NULL, 0x00000004, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_rsv,
			{
				"Reserved", "wmx.ulmap.uiuc13.rsv",
				FT_UINT32,	BASE_DEC, NULL, 0x00000001, NULL, HFILL
			}
		},
#if 0
		{
			&hf_ulmap_crc16,
			{
				"CRC-16", "wmx.ulmap.crc16",
				FT_UINT32,	BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
#endif
		{
			&hf_ulmap_padding,
			{
				"Padding", "wmx.ulmap.padding",
				FT_BYTES,	BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_subofs,
			{
				"Subchannel offset", "wmx.ulmap.uiuc13.subofs",
				FT_UINT32,	BASE_DEC, NULL, 0x00fe0000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_symofs,
			{
				"OFDMA symbol offset", "wmx.ulmap.uiuc13.symofs",
				FT_UINT32,	BASE_DEC, NULL, 0xff000000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_zone,
			{
				"Sounding Zone", "wmx.ulmap.uiuc13.zone",
				FT_UINT32,	BASE_DEC, NULL, 0x00000002, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_bwr,
			{
				"BW request mandatory", "wmx.ulmap.uiuc14.bwr",
				FT_UINT8,  BASE_DEC, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_code,
			{
				"Ranging code", "wmx.ulmap.uiuc14.code",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_dur,
			{
				"Duration", "wmx.ulmap.uiuc14.dur",
				FT_UINT16, BASE_DEC, NULL, 0xfc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_idx,
			{
				"Frame Number Index", "wmx.ulmap.uiuc14.idx",
				FT_UINT16, BASE_DEC, NULL, 0x000F, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_rep,
			{
				"Repetition Coding Indication", "wmx.ulmap.uiuc14.rep",
				FT_UINT16, BASE_DEC, NULL, 0x0030, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_sub,
			{
				"Ranging subchannel", "wmx.ulmap.uiuc14.sub",
				FT_UINT8,  BASE_DEC, NULL, 0xfe, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_sym,
			{
				"Ranging symbol", "wmx.ulmap.uiuc14.sym",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_uiuc,
			{
				"UIUC", "wmx.ulmap.uiuc14.uiuc",
				FT_UINT16, BASE_DEC, NULL, 0x03c0, NULL, HFILL
			}
		},
#if 0
		{
			&hf_ulmap_uiuc15_data,
			{
				"Data", "wmx.ulmap.uiuc15.data",
				FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc15_ext,
			{
				"Extended UIUC", "wmx.ulmap.uiuc15.ext",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc15_len,
			{
				"Length", "wmx.ulmap.uiuc15.len",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
		/* Generated via "one time" script to help create filterable fields */
		{ &hf_ulmap_dedicated_ul_control_length, { "Length", "wmx.ulmap.dedicated_ul_control.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_dedicated_ul_control_control_header, { "Control Header", "wmx.ulmap.dedicated_ul_control.control_header", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_dedicated_ul_control_num_sdma_layers, { "Num SDMA layers", "wmx.ulmap.dedicated_ul_control.num_sdma_layers", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_dedicated_ul_control_pilot_pattern, { "Pilot Pattern", "wmx.ulmap.dedicated_ul_control.pilot_pattern", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_dedicated_mimo_ul_control_matrix, { "Matrix", "wmx.ulmap.dedicated_mimo_ul_control.matrix", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_dedicated_mimo_ul_control_n_layer, { "N_layer", "wmx.ulmap.dedicated_mimo_ul_control.n_layer", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_chase_dedicated_ul_control_indicator, { "Dedicated UL Control Indicator", "wmx.ulmap.harq_chase.dedicated_ul_control_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_chase_uiuc, { "UIUC", "wmx.ulmap.harq_chase.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_chase_repetition_coding_indication, { "Repetition Coding Indication", "wmx.ulmap.harq_chase.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_chase_duration, { "Duration", "wmx.ulmap.harq_chase.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_chase_acid, { "ACID", "wmx.ulmap.harq_chase.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_chase_ai_sn, { "AI_SN", "wmx.ulmap.harq_chase.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_chase_ack_disable, { "ACK_disable", "wmx.ulmap.harq_chase.ack_disable", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reserved_uint, { "Reserved", "wmx.ulmap.reserved.uint", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_ctc_dedicated_ul_control_indicator, { "Dedicated UL Control Indicator", "wmx.ulmap.harq_ir_ctc.dedicated_ul_control_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_ctc_nep, { "N(EP)", "wmx.ulmap.harq_ir_ctc.nep", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_ctc_nsch, { "N(SCH)", "wmx.ulmap.harq_ir_ctc.nsch", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_ctc_spid, { "SPID", "wmx.ulmap.harq_ir_ctc.spid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_ctc_acin, { "ACIN", "wmx.ulmap.harq_ir_ctc.acin", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_ctc_ai_sn, { "AI_SN", "wmx.ulmap.harq_ir_ctc.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_ctc_ack_disable, { "ACK_disable", "wmx.ulmap.harq_ir_ctc.ack_disable", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_dedicated_ul_control_indicator, { "Dedicated UL Control Indicator", "wmx.ulmap.harq_ir_cc.dedicated_ul_control_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_uiuc, { "UIUC", "wmx.ulmap.harq_ir_cc.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_repetition_coding_indication, { "Repetition Coding Indication", "wmx.ulmap.harq_ir_cc.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_duration, { "Duration", "wmx.ulmap.harq_ir_cc.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_spid, { "SPID", "wmx.ulmap.harq_ir_cc.spid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_acid, { "ACID", "wmx.ulmap.harq_ir_cc.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_ai_sn, { "AI_SN", "wmx.ulmap.harq_ir_cc.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ir_cc_ack_disable, { "ACK_disable", "wmx.ulmap.harq_ir_cc.ack_disable", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_mu_indicator, { "MU indicator", "wmx.ulmap.mimo_ul_chase_harq.mu_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_dedicated_mimo_ulcontrol_indicator, { "Dedicated MIMO ULControl Indicator", "wmx.ulmap.mimo_ul_chase_harq.dedicated_mimo_ulcontrol_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_ack_disable, { "ACK Disable", "wmx.ulmap.mimo_ul_chase_harq.ack_disable", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_matrix, { "Matrix", "wmx.ulmap.mimo_ul_chase_harq.matrix", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_duration, { "Duration", "wmx.ulmap.mimo_ul_chase_harq.duration", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_uiuc, { "UIUC", "wmx.ulmap.mimo_ul_chase_harq.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_repetition_coding_indication, { "Repetition Coding Indication", "wmx.ulmap.mimo_ul_chase_harq.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_acid, { "ACID", "wmx.ulmap.mimo_ul_chase_harq.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_chase_harq_ai_sn, { "AI_SN", "wmx.ulmap.mimo_ul_chase_harq.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_mu_indicator, { "MU indicator", "wmx.ulmap.mimo_ul_ir_harq.mu_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_dedicated_mimo_ul_control_indicator, { "Dedicated MIMO UL Control Indicator", "wmx.ulmap.mimo_ul_ir_harq.dedicated_mimo_ul_control_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_ack_disable, { "ACK Disable", "wmx.ulmap.mimo_ul_ir_harq.ack_disable", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_matrix, { "Matrix", "wmx.ulmap.mimo_ul_ir_harq.matrix", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_nsch, { "N(SCH)", "wmx.ulmap.mimo_ul_ir_harq.nsch", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_nep, { "N(EP)", "wmx.ulmap.mimo_ul_ir_harq.nep", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_spid, { "SPID", "wmx.ulmap.mimo_ul_ir_harq.spid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_acid, { "ACID", "wmx.ulmap.mimo_ul_ir_harq.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_ai_sn, { "AI_SN", "wmx.ulmap.mimo_ul_ir_harq.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_mu_indicator, { "MU indicator", "wmx.ulmap.mimo_ul_ir_harq_cc.mu_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_dedicated_mimo_ul_control_indicator, { "Dedicated MIMO UL Control Indicator", "wmx.ulmap.mimo_ul_ir_harq_cc.dedicated_mimo_ul_control_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_ack_disable, { "ACK Disable", "wmx.ulmap.mimo_ul_ir_harq_cc.ack_disable", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_matrix, { "Matrix", "wmx.ulmap.mimo_ul_ir_harq_cc.matrix", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_duration, { "Duration", "wmx.ulmap.mimo_ul_ir_harq_cc.duration", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_uiuc, { "UIUC", "wmx.ulmap.mimo_ul_ir_harq_cc.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_repetition_coding_indication, { "Repetition Coding Indication", "wmx.ulmap.mimo_ul_ir_harq_cc.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_acid, { "ACID", "wmx.ulmap.mimo_ul_ir_harq_cc.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_ai_sn, { "AI_SN", "wmx.ulmap.mimo_ul_ir_harq_cc.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_ir_harq_cc_spid, { "SPID", "wmx.ulmap.mimo_ul_ir_harq_cc.spid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_tx_count, { "Tx count", "wmx.ulmap.mimo_ul_stc_harq.tx_count", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_duration, { "Duration", "wmx.ulmap.mimo_ul_stc_harq.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_sub_burst_offset_indication, { "Sub-burst offset indication", "wmx.ulmap.mimo_ul_stc_harq.sub_burst_offset_indication", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_sub_burst_offset, { "Sub-burst offset", "wmx.ulmap.mimo_ul_stc_harq.sub_burst_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_ack_disable, { "ACK Disable", "wmx.ulmap.mimo_ul_stc_harq.ack_disable", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_uiuc, { "UIUC", "wmx.ulmap.mimo_ul_stc_harq.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_repetition_coding_indication, { "Repetition Coding Indication", "wmx.ulmap.mimo_ul_stc_harq.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mimo_ul_stc_harq_acid, { "ACID", "wmx.ulmap.mimo_ul_stc_harq.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_power_control, { "Power Control", "wmx.ulmap.power_control", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_power_measurement_frame, { "Power measurement frame", "wmx.ulmap.power_measurement_frame", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.mini_subcha_alloc.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_length, { "Length", "wmx.ulmap.mini_subcha_alloc.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_ctype, { "Ctype", "wmx.ulmap.mini_subcha_alloc.ctype", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_duration, { "Duration", "wmx.ulmap.mini_subcha_alloc.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_cid, { "CID", "wmx.ulmap.mini_subcha_alloc.cid", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_uiuc, { "UIUC", "wmx.ulmap.mini_subcha_alloc.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_repetition, { "Repetition", "wmx.ulmap.mini_subcha_alloc.repetition", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_mini_subcha_alloc_padding, { "Padding", "wmx.ulmap.mini_subcha_alloc.padding", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_extended_uiuc, { "Extended UIUC", "wmx.ulmap.aas_ul.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_length, { "Length", "wmx.ulmap.aas_ul.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_permutation, { "Permutation", "wmx.ulmap.aas_ul.permutation", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_ul_permbase, { "UL_PermBase", "wmx.ulmap.aas_ul.ul_permbase", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_ofdma_symbol_offset, { "OFDMA symbol offset", "wmx.ulmap.aas_ul.ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_aas_zone_length, { "AAS zone length", "wmx.ulmap.aas_ul.aas_zone_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_uplink_preamble_config, { "Uplink preamble config", "wmx.ulmap.aas_ul.uplink_preamble_config", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_ul_preamble_type, { "Preamble type", "wmx.ulmap.aas_ul.preamble_type", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_extended_uiuc, { "Extended UIUC", "wmx.ulmap.cqich_alloc.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_length, { "Length", "wmx.ulmap.cqich_alloc.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_cqich_id, { "CQICH_ID", "wmx.ulmap.cqich_alloc.cqich_id", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_allocation_offset, { "Allocation offset", "wmx.ulmap.cqich_alloc.allocation_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_period, { "Period (p)", "wmx.ulmap.cqich_alloc.period", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_frame_offset, { "Frame offset", "wmx.ulmap.cqich_alloc.frame_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_duration, { "Duration (d)", "wmx.ulmap.cqich_alloc.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_report_configuration_included, { "Report configuration included", "wmx.ulmap.cqich_alloc.report_configuration_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_feedback_type, { "Feedback Type", "wmx.ulmap.cqich_alloc.feedback_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_report_type, { "Report type", "wmx.ulmap.cqich_alloc.report_type", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_cinr_preamble_report_type, { "CINR preamble report type", "wmx.ulmap.cqich_alloc.cinr_preamble_report_type", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_zone_permutation, { "Zone permutation", "wmx.ulmap.cqich_alloc.zone_permutation", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_zone_type, { "Zone type", "wmx.ulmap.cqich_alloc.zone_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_zone_prbs_id, { "Zone PRBS_ID", "wmx.ulmap.cqich_alloc.zone_prbs_id", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_major_group_indication, { "Major group indication", "wmx.ulmap.cqich_alloc.major_group_indication", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_pusc_major_group_bitmap, { "PUSC Major group bitmap", "wmx.ulmap.cqich_alloc.pusc_major_group_bitmap", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_cinr_zone_measurement_type, { "CINR zone measurement type", "wmx.ulmap.cqich_alloc.cinr_zone_measurement_type", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_averaging_parameter_included, { "Averaging parameter included", "wmx.ulmap.cqich_alloc.averaging_parameter_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_averaging_parameter, { "Averaging parameter", "wmx.ulmap.cqich_alloc.averaging_parameter", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_alloc_mimo_permutation_feedback_cycle, { "MIMO_permutation_feedback_cycle", "wmx.ulmap.cqich_alloc.mimo_permutation_feedback_cycle", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_extended_uiuc, { "Extended UIUC", "wmx.ulmap.zone.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_length, { "Length", "wmx.ulmap.zone.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_ofdma_symbol_offset, { "OFDMA symbol offset", "wmx.ulmap.zone.ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_permutation, { "Permutation", "wmx.ulmap.zone.permutation", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_ul_permbase, { "UL_PermBase", "wmx.ulmap.zone.ul_permbase", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_amc_type, { "AMC type", "wmx.ulmap.zone.amc_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_use_all_sc_indicator, { "Use All SC indicator", "wmx.ulmap.zone.use_all_sc_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_zone_disable_subchannel_rotation, { "Disable subchannel rotation", "wmx.ulmap.zone.disable_subchannel_rotation", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_phymod_ul_extended_uiuc, { "Extended UIUC", "wmx.ulmap.phymod_ul.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_phymod_ul_length, { "Length", "wmx.ulmap.phymod_ul.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_phymod_ul_preamble_modifier_type, { "Preamble Modifier Type", "wmx.ulmap.phymod_ul.preamble_modifier_type", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_phymod_ul_preamble_frequency_shift_index, { "Preamble frequency shift index", "wmx.ulmap.phymod_ul.preamble_frequency_shift_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_phymod_ul_preamble_time_shift_index, { "Preamble Time Shift index", "wmx.ulmap.phymod_ul.preamble_time_shift_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_phymod_ul_pilot_pattern_modifier, { "Pilot Pattern Modifier", "wmx.ulmap.phymod_ul.pilot_pattern_modifier", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_phymod_ul_pilot_pattern_index, { "Pilot Pattern Index", "wmx.ulmap.phymod_ul.pilot_pattern_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_tracking_extended_uiuc, { "Extended UIUC", "wmx.ulmap.fast_tracking.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_tracking_length, { "Length", "wmx.ulmap.fast_tracking.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_tracking_map_index, { "Map Index", "wmx.ulmap.fast_tracking.map_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_tracking_power_correction, { "Power correction", "wmx.ulmap.fast_tracking.power_correction", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_tracking_frequency_correction, { "Frequency correction", "wmx.ulmap.fast_tracking.frequency_correction", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_tracking_time_correction, { "Time correction", "wmx.ulmap.fast_tracking.time_correction", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_extended_uiuc, { "Extended UIUC", "wmx.ulmap.pusc_burst_allocation.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_length, { "Length", "wmx.ulmap.pusc_burst_allocation.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_uiuc, { "UIUC", "wmx.ulmap.pusc_burst_allocation.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_segment, { "Segment", "wmx.ulmap.pusc_burst_allocation.segment", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_ul_permbase, { "UL_PermBase", "wmx.ulmap.pusc_burst_allocation.ul_permbase", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_ofdma_symbol_offset, { "OFDMA symbol offset", "wmx.ulmap.pusc_burst_allocation.ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_subchannel_offset, { "Subchannel offset", "wmx.ulmap.pusc_burst_allocation.subchannel_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_duration, { "Duration", "wmx.ulmap.pusc_burst_allocation.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_pusc_burst_allocation_repetition_coding_indication, { "Repetition coding indication", "wmx.ulmap.pusc_burst_allocation.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_extended_uiuc, { "Extended UIUC", "wmx.ulmap.fast_ranging.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_length, { "Length", "wmx.ulmap.fast_ranging.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_ho_id_indicator, { "HO_ID indicator", "wmx.ulmap.fast_ranging.ho_id_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_ho_id, { "HO_ID", "wmx.ulmap.fast_ranging.ho_id", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_mac_address, { "MAC address", "wmx.ulmap.fast_ranging.mac_address", FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_uiuc, { "UIUC", "wmx.ulmap.fast_ranging.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_duration, { "Duration", "wmx.ulmap.fast_ranging.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_fast_ranging_repetition_coding_indication, { "Repetition coding indication", "wmx.ulmap.fast_ranging.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_allocation_start_extended_uiuc, { "Extended UIUC", "wmx.ulmap.allocation_start.extended_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_allocation_start_length, { "Length", "wmx.ulmap.allocation_start.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_allocation_start_ofdma_symbol_offset, { "OFDMA symbol offset", "wmx.ulmap.allocation_start.ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_allocation_start_subchannel_offset, { "Subchannel offset", "wmx.ulmap.allocation_start.subchannel_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.cqich_enhanced_alloc.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_length, { "Length", "wmx.ulmap.cqich_enhanced_alloc.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_cqich_id, { "CQICH_ID", "wmx.ulmap.cqich_enhanced_alloc.cqich_id", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_period, { "Period (p)", "wmx.ulmap.cqich_enhanced_alloc.period", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_frame_offset, { "Frame offset", "wmx.ulmap.cqich_enhanced_alloc.frame_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_duration, { "Duration (d)", "wmx.ulmap.cqich_enhanced_alloc.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_cqich_num, { "CQICH_Num", "wmx.ulmap.cqich_enhanced_alloc.cqich_num", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_feedback_type, { "Feedback Type", "wmx.ulmap.cqich_enhanced_alloc.feedback_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_allocation_index, { "Allocation Index", "wmx.ulmap.cqich_enhanced_alloc.allocation_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_cqich_type, { "CQICH Type", "wmx.ulmap.cqich_enhanced_alloc.cqich_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_sttd_indication, { "STTD indication", "wmx.ulmap.cqich_enhanced_alloc.sttd_indication", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_band_amc_precoding_mode, { "Band_AMC_Precoding_Mode", "wmx.ulmap.cqich_enhanced_alloc.band_amc_precoding_mode", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_cqich_enhanced_alloc_nr_precoders_feedback, { "Nr_Precoders_Feedback (=N)", "wmx.ulmap.cqich_enhanced_alloc.nr_precoders_feedback", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.anchor_bs_switch.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_length, { "Length", "wmx.ulmap.anchor_bs_switch.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_n_anchor_bs_switch, { "N_Anchor_BS_switch", "wmx.ulmap.anchor_bs_switch.n_anchor_bs_switch", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_reduced_cid, { "Reduced CID", "wmx.ulmap.anchor_bs_switch.reduced_cid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_action_code, { "Action Code", "wmx.ulmap.anchor_bs_switch.action_code", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_action_time, { "Action Time (A)", "wmx.ulmap.anchor_bs_switch.action_time", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_temp_bs_id, { "TEMP_BS_ID", "wmx.ulmap.anchor_bs_switch.temp_bs_id", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_ak_change_indicator, { "AK Change Indicator", "wmx.ulmap.anchor_bs_switch.ak_change_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_cqich_allocation_indicator, { "CQICH Allocation Indicator", "wmx.ulmap.anchor_bs_switch.cqich_allocation_indicator", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_feedback_channel_offset, { "Feedback channel offset", "wmx.ulmap.anchor_bs_switch.feedback_channel_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_cqich_id, { "CQICH_ID", "wmx.ulmap.anchor_bs_switch.cqich_id", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_period, { "Period (=p)", "wmx.ulmap.anchor_bs_switch.period", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_frame_offset, { "Frame offset", "wmx.ulmap.anchor_bs_switch.frame_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_duration, { "Duration (=d)", "wmx.ulmap.anchor_bs_switch.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_anchor_bs_switch_mimo_permutation_feedback_code, { "MIMO_permutation_feedback_code", "wmx.ulmap.anchor_bs_switch.mimo_permutation_feedback_code", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.sounding_command.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_length, { "Length", "wmx.ulmap.sounding_command.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_type, { "Sounding_Type", "wmx.ulmap.sounding_command.sounding_command.type", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_send_sounding_report_flag, { "Send Sounding Report Flag", "wmx.ulmap.sounding_command.send_sounding_report_flag", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_relevance_flag, { "Sounding Relevance Flag", "wmx.ulmap.sounding_command.relevance_flag", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_relevance, { "Sounding_Relevance", "wmx.ulmap.sounding_command.sounding_relevance", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_include_additional_feedback, { "Include additional feedback", "wmx.ulmap.sounding_command.include_additional_feedback", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_num_sounding_symbols, { "Num_Sounding_Symbols", "wmx.ulmap.sounding_command.num_sounding_symbols", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_separability_type, { "Separability Type", "wmx.ulmap.sounding_command.separability_type", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_max_cyclic_shift_index_p, { "Max Cyclic Shift Index P", "wmx.ulmap.sounding_command.max_cyclic_shift_index_p", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_decimation_value, { "Decimation Value D", "wmx.ulmap.sounding_command.decimation_value", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_decimation_offset_randomization, { "Decimation offset randomization", "wmx.ulmap.sounding_command.decimation_offset_randomization", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_symbol_index, { "Sounding symbol index", "wmx.ulmap.sounding_command.sounding_command.symbol_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_number_of_cids, { "Number of CIDs", "wmx.ulmap.sounding_command.number_of_cids", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_shorted_basic_cid, { "Shorted Basic CID", "wmx.ulmap.sounding_command.shorted_basic_cid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_power_assignment_method, { "Power Assignment Method", "wmx.ulmap.sounding_command.power_assignment_method", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_power_boost, { "Power boost", "wmx.ulmap.sounding_command.power_boost", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_multi_antenna_flag, { "Multi-Antenna Flag", "wmx.ulmap.sounding_command.multi_antenna_flag", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_allocation_mode, { "Allocation Mode", "wmx.ulmap.sounding_command.allocation_mode", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_band_bit_map, { "Band bit map", "wmx.ulmap.sounding_command.band_bit_map", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_starting_frequency_band, { "Starting frequency band", "wmx.ulmap.sounding_command.starting_frequency_band", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_number_of_frequency_bands, { "Number of frequency bands", "wmx.ulmap.sounding_command.number_of_frequency_bands", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_cyclic_time_shift_index, { "Cyclic time shift index m", "wmx.ulmap.sounding_command.cyclic_time_shift_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_decimation_offset, { "Decimation offset d", "wmx.ulmap.sounding_command.decimation_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_use_same_symbol_for_additional_feedback, { "Use same symbol for additional feedback", "wmx.ulmap.sounding_command.use_same_symbol_for_additional_feedback", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_periodicity, { "Periodicity", "wmx.ulmap.sounding_command.periodicity", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_permutation, { "Permutation", "wmx.ulmap.sounding_command.permutation", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_dl_permbase, { "DL_PermBase", "wmx.ulmap.sounding_command.dl_permbase", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_shortened_basic_cid, { "Shortened basic CID", "wmx.ulmap.sounding_command.shortened_basic_cid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_subchannel_offset, { "Subchannel offset", "wmx.ulmap.sounding_command.subchannel_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_sounding_command_number_of_subchannels, { "Number of subchannels", "wmx.ulmap.sounding_command.number_of_subchannels", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.harq_ulmap.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_length, { "Length", "wmx.ulmap.harq_ulmap.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_rcid_type, { "RCID_Type", "wmx.ulmap.harq_ulmap.rcid_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_mode, { "Mode", "wmx.ulmap.harq_ulmap.mode", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_allocation_start_indication, { "Allocation Start Indication", "wmx.ulmap.harq_ulmap.allocation_start_indication", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_ofdma_symbol_offset, { "OFDMA Symbol offset", "wmx.ulmap.harq_ulmap.ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_subchannel_offset, { "Subchannel offset", "wmx.ulmap.harq_ulmap.subchannel_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ulmap_n_sub_burst, { "N sub Burst", "wmx.ulmap.harq_ulmap.n_sub_burst", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ackch_region_alloc_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.harq_ackch_region_alloc.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ackch_region_alloc_length, { "Length", "wmx.ulmap.harq_ackch_region_alloc.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ackch_region_alloc_ofdma_symbol_offset, { "OFDMA Symbol Offset", "wmx.ulmap.harq_ackch_region_alloc.ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ackch_region_alloc_subchannel_offset, { "Subchannel Offset", "wmx.ulmap.harq_ackch_region_alloc.subchannel_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ackch_region_alloc_num_ofdma_symbols, { "No. OFDMA Symbols", "wmx.ulmap.harq_ackch_region_alloc.num_ofdma_symbols", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_harq_ackch_region_alloc_num_subchannels, { "No. Subchannels", "wmx.ulmap.harq_ackch_region_alloc.num_subchannels", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.aas_sdma.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_length, { "Length", "wmx.ulmap.aas_sdma.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_rcid_type, { "RCID_Type", "wmx.ulmap.aas_sdma.rcid_type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_num_burst_region, { "Num Burst Region", "wmx.ulmap.aas_sdma.num_burst_region", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_slot_offset, { "Slot offset", "wmx.ulmap.aas_sdma.slot_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_slot_duration, { "Slot duration", "wmx.ulmap.aas_sdma.slot_duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_number_of_users, { "Number of users", "wmx.ulmap.aas_sdma.number_of_users", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_encoding_mode, { "Encoding Mode", "wmx.ulmap.aas_sdma.encoding_mode", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_power_adjust, { "Power Adjust", "wmx.ulmap.aas_sdma.power_adjust", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_pilot_pattern_modifier, { "Pilot Pattern Modifier", "wmx.ulmap.aas_sdma.pilot_pattern_modifier", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_preamble_modifier_index, { "Preamble Modifier Index", "wmx.ulmap.aas_sdma.preamble_modifier_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_pilot_pattern, { "Pilot Pattern", "wmx.ulmap.aas_sdma.pilot_pattern", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_diuc, { "DIUC", "wmx.ulmap.aas_sdma.diuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_repetition_coding_indication, { "Repetition Coding Indication", "wmx.ulmap.aas_sdma.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_acid, { "ACID", "wmx.ulmap.aas_sdma.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_ai_sn, { "AI_SN", "wmx.ulmap.aas_sdma.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_nep, { "N(EP)", "wmx.ulmap.aas_sdma.nep", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_nsch, { "N(SCH)", "wmx.ulmap.aas_sdma.nsch", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_spid, { "SPID", "wmx.ulmap.aas_sdma.spid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_aas_sdma_power_adjustment, { "Power Adjustment", "wmx.ulmap.aas_sdma.power_adjustment", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_extended_2_uiuc, { "Extended-2 UIUC", "wmx.ulmap.feedback_polling.extended_2_uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_length, { "Length", "wmx.ulmap.feedback_polling.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_num_allocation, { "Num_Allocation", "wmx.ulmap.feedback_polling.num_allocation", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_dedicated_ul_allocation_included, { "Dedicated UL Allocation included", "wmx.ulmap.feedback_polling.dedicated_ul_allocation_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_basic_cid, { "Basic CID", "wmx.ulmap.feedback_polling.basic_cid", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_allocation_duration, { "Allocation Duration (d)", "wmx.ulmap.feedback_polling.allocation_duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_type, { "Feedback type", "wmx.ulmap.feedback_polling.feedback_polling.type", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_frame_offset, { "Frame Offset", "wmx.ulmap.feedback_polling.frame_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_period, { "Period (p)", "wmx.ulmap.feedback_polling.perio", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_uiuc, { "UIUC", "wmx.ulmap.feedback_polling.uiuc", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_ofdma_symbol_offset, { "OFDMA Symbol Offset", "wmx.ulmap.feedback_polling.ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_subchannel_offset, { "Subchannel offset", "wmx.ulmap.feedback_polling.subchannel_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_duration, { "Duration", "wmx.ulmap.feedback_polling.duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_feedback_polling_repetition_coding_indication, { "Repetition coding indication", "wmx.ulmap.feedback_polling.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_aas_zone_configuration_included, { "AAS zone configuration included", "wmx.ulmap.reduced_aas.aas_zone_configuration_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_aas_zone_position_included, { "AAS zone position included", "wmx.ulmap.reduced_aas.aas_zone_position_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_ul_map_information_included, { "UL-MAP information included", "wmx.ulmap.reduced_aas.ul_map_information_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_phy_modification_included, { "PHY modification included", "wmx.ulmap.reduced_aas.phy_modification_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_power_control_included, { "Power Control included", "wmx.ulmap.reduced_aas.power_control_included", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_include_feedback_header, { "Include Feedback Header", "wmx.ulmap.reduced_aas.include_feedback_header", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_encoding_mode, { "Encoding Mode", "wmx.ulmap.reduced_aas.encoding_mode", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_permutation, { "Permutation", "wmx.ulmap.reduced_aas.permutation", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_ul_permbase, { "UL_PermBase", "wmx.ulmap.reduced_aas.ul_permbase", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_preamble_indication, { "Preamble Indication", "wmx.ulmap.reduced_aas.preamble_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_padding, { "Padding", "wmx.ulmap.reduced_aas.padding", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_zone_symbol_offset, { "Zone Symbol Offset", "wmx.ulmap.reduced_aas.zone_symbol_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_zone_length, { "Zone Length", "wmx.ulmap.reduced_aas.zone_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_ucd_count, { "UCD Count", "wmx.ulmap.reduced_aas.ucd_count", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_private_map_alloc_start_time, { "Private Map Allocation Start Time", "wmx.ulmap.reduced_aas.private_map_alloc_start_time", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_pilot_pattern_index, { "Pilot Pattern Index", "wmx.ulmap.reduced_aas.pilot_pattern_index", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_preamble_select, { "Preamble Select", "wmx.ulmap.reduced_aas.preamble_select", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_preamble_shift_index, { "Preamble Shift Index", "wmx.ulmap.reduced_aas.preamble_shift_index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_pilot_pattern_modifier, { "Pilot Pattern Modifier", "wmx.ulmap.reduced_aas.pilot_pattern_modifier", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_power_control, { "Power Control", "wmx.ulmap.reduced_aas.power_control", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_ul_frame_offset, { "UL Frame Offset", "wmx.ulmap.reduced_aas.ul_frame_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_slot_offset, { "Slot Offset", "wmx.ulmap.reduced_aas.slot_offset", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_slot_duration, { "Slot Duration", "wmx.ulmap.reduced_aas.slot_duration", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_uiuc_nep, { "UIUC / N(EP)", "wmx.ulmap.reduced_aas.uiuc_nep", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_acid, { "ACID", "wmx.ulmap.reduced_aas.acid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_ai_sn, { "AI_SN", "wmx.ulmap.reduced_aas.ai_sn", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_nsch, { "N(SCH)", "wmx.ulmap.reduced_aas.nsch", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_spid, { "SPID", "wmx.ulmap.reduced_aas.spid", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_ulmap_reduced_aas_repetition_coding_indication, { "Repetition Coding Indication", "wmx.ulmap.reduced_aas.repetition_coding_indication", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_ulmap,
			&ett_ulmap_ie,
			&ett_ulmap_ffb,
			/* &ett_ulmap_c,    */
			/* &ett_ulmap_c_ie, */
			/* &ett_ulmap_s,    */
			/* &ett_ulmap_s_ie, */
			&ett_287_1,
			&ett_287_2,
			&ett_289,
			&ett_290,
			&ett_290b,
			&ett_291,
			&ett_292,
			&ett_293,
			&ett_294,
			&ett_295,
			&ett_299,
			&ett_300,
			&ett_302,
			&ett_302a,
			&ett_302b,
			&ett_302c,
			&ett_302d,
			&ett_302e,
			&ett_302f,
			&ett_302h,
			&ett_302g,
			&ett_302i,
			&ett_302j,
			&ett_302k,
			&ett_302l,
			&ett_302m,
			&ett_302n,
			&ett_302o,
			&ett_302p,
			&ett_302q,
			&ett_302r,
			&ett_302s,
			&ett_302t,
			&ett_302u,
			&ett_302v,
			&ett_306,
			&ett_306_ul,
			&ett_308b,
			&ett_315d,
		};

	static ei_register_info ei[] = {
		{ &ei_ulmap_not_implemented, { "wmx.ulmap.not_implemented", PI_UNDECODED, PI_WARN, "Not implemented", EXPFILL }},
	};

	expert_module_t* expert_mac_mgmt_msg_ulmap;

	proto_mac_mgmt_msg_ulmap_decoder = proto_register_protocol (
		"WiMax ULMAP Messages", /* name       */
		"WiMax ULMAP",    /* short name */
		"wmx.ulmap"       /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_ulmap_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mac_mgmt_msg_ulmap = expert_register_protocol(proto_mac_mgmt_msg_ulmap_decoder);
	expert_register_field_array(expert_mac_mgmt_msg_ulmap, ei, array_length(ei));
}

void proto_reg_handoff_mac_mgmt_msg_ulmap(void)
{
	dissector_handle_t ulmap_handle;

	ulmap_handle = create_dissector_handle(dissect_mac_mgmt_msg_ulmap_decoder, proto_mac_mgmt_msg_ulmap_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_UL_MAP, ulmap_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
