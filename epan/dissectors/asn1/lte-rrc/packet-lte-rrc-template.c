/* packet-lte-rrc-template.c
 * Routines for Evolved Universal Terrestrial Radio Access (E-UTRA);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 36.331 V17.1.0 Release 17) packet dissection
 * Copyright 2008, Vincent Helfre
 * Copyright 2009-2022, Pascal Quantin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>

#include <wsutil/str_util.h>
#include <wsutil/epochs.h>

#include "packet-per.h"
#include "packet-rrc.h"
#include "packet-gsm_a_common.h"
#include "packet-lpp.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-mac-lte.h"
#include "packet-rlc-lte.h"
#include "packet-pdcp-lte.h"
#include "packet-nr-rrc.h"
#include "packet-lte-rrc.h"

#define PNAME  "LTE Radio Resource Control (RRC) protocol"
#define PSNAME "LTE RRC"
#define PFNAME "lte_rrc"

void proto_register_lte_rrc(void);
void proto_reg_handoff_lte_rrc(void);

static dissector_handle_t nas_eps_handle = NULL;
static dissector_handle_t nas_5gs_handle = NULL;
static dissector_handle_t rrc_irat_ho_to_utran_cmd_handle = NULL;
static dissector_handle_t rrc_sys_info_cont_handle = NULL;
static dissector_handle_t gsm_a_dtap_handle = NULL;
static dissector_handle_t gsm_rlcmac_dl_handle = NULL;
static dissector_handle_t nr_rrc_reconf_handle = NULL;
static dissector_handle_t lte_rrc_conn_reconf_handle;
static dissector_handle_t lte_rrc_dl_ccch_handle;

static wmem_map_t *lte_rrc_etws_cmas_dcs_hash = NULL;

/* Keep track of where/how the System Info value has changed */
static wmem_map_t *lte_rrc_system_info_value_changed_hash = NULL;
static guint8     system_info_value_current;
static gboolean   system_info_value_current_set;

static gboolean lte_rrc_nas_in_root_tree;

extern int proto_mac_lte;
extern int proto_rlc_lte;
extern int proto_pdcp_lte;


/* Include constants */
#include "packet-lte-rrc-val.h"

/* Initialize the protocol and registered fields */
static int proto_lte_rrc = -1;

#include "packet-lte-rrc-hf.c"

static int hf_lte_rrc_eutra_cap_feat_group_ind_1 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_2 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_3 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_4 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_5 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_6 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_7 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_8 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_9 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_10 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_11 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_12 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_13 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_14 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_15 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_16 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_17 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_18 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_19 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_20 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_21 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_22 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_23 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_24 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_25 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_26 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_27 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_28 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_29 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_30 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_31 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_32 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_33 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_34 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_35 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_36 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_37 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_38 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_39 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_40 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_41 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_42 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_43 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_44 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_45 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_46 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_47 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_48 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_49 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_50 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_51 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_52 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_53 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_54 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_55 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_56 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_57 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_58 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_59 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_60 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_61 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_62 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_63 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_64 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_101 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_102 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_103 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_104 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_105 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_106 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_107 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_108 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_109 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_110 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_111 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_112 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_113 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_114 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_115 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_116 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_117 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_118 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_119 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_120 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_121 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_122 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_123 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_124 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_125 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_126 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_127 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_128 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_129 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_130 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_131 = -1;
static int hf_lte_rrc_eutra_cap_feat_group_ind_132 = -1;
static int hf_lte_rrc_serialNumber_gs = -1;
static int hf_lte_rrc_serialNumber_msg_code = -1;
static int hf_lte_rrc_serialNumber_upd_nb = -1;
static int hf_lte_rrc_warningType_value = -1;
static int hf_lte_rrc_warningType_emergency_user_alert = -1;
static int hf_lte_rrc_warningType_popup = -1;
static int hf_lte_rrc_warningMessageSegment_nb_pages = -1;
static int hf_lte_rrc_warningMessageSegment_decoded_page = -1;
static int hf_lte_rrc_interBandTDD_CA_WithDifferentConfig_bit1 = -1;
static int hf_lte_rrc_interBandTDD_CA_WithDifferentConfig_bit2 = -1;
static int hf_lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit1 = -1;
static int hf_lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit2 = -1;
static int hf_lte_rrc_aperiodicCSI_Reporting_r13_bit1 = -1;
static int hf_lte_rrc_aperiodicCSI_Reporting_r13_bit2 = -1;
static int hf_lte_rrc_codebook_HARQ_ACK_r13_bit1 = -1;
static int hf_lte_rrc_codebook_HARQ_ACK_r13_bit2 = -1;
static int hf_lte_rrc_sr_config_periodicity = -1;
static int hf_lte_rrc_sr_config_subframe_offset = -1;
static int hf_lte_rrc_cdma_time = -1;
static int hf_lte_rrc_utc_time = -1;
static int hf_lte_rrc_local_time = -1;
static int hf_lte_rrc_absolute_time = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm1 = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm2 = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm3 = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm4 = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm6 = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm8 = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm9 = -1;
static int hf_lte_rrc_transmissionModeList_r12_tm10 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_0 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_1 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_2 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_3 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_4 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_5 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_6 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_7 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_8 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_9 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_10 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_11 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_12 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_13 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_14 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_15 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_16 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_17 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_18 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_19 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_20 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_21 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_22 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_23 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_24 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_25 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_26 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_27 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_28 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_29 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_30 = -1;
static int hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_31 = -1;
static int hf_lte_rrc_sib11_fragments = -1;
static int hf_lte_rrc_sib11_fragment = -1;
static int hf_lte_rrc_sib11_fragment_overlap = -1;
static int hf_lte_rrc_sib11_fragment_overlap_conflict = -1;
static int hf_lte_rrc_sib11_fragment_multiple_tails = -1;
static int hf_lte_rrc_sib11_fragment_too_long_fragment = -1;
static int hf_lte_rrc_sib11_fragment_error = -1;
static int hf_lte_rrc_sib11_fragment_count = -1;
static int hf_lte_rrc_sib11_reassembled_in = -1;
static int hf_lte_rrc_sib11_reassembled_length = -1;
static int hf_lte_rrc_sib11_reassembled_data = -1;
static int hf_lte_rrc_sib12_fragments = -1;
static int hf_lte_rrc_sib12_fragment = -1;
static int hf_lte_rrc_sib12_fragment_overlap = -1;
static int hf_lte_rrc_sib12_fragment_overlap_conflict = -1;
static int hf_lte_rrc_sib12_fragment_multiple_tails = -1;
static int hf_lte_rrc_sib12_fragment_too_long_fragment = -1;
static int hf_lte_rrc_sib12_fragment_error = -1;
static int hf_lte_rrc_sib12_fragment_count = -1;
static int hf_lte_rrc_sib12_reassembled_in = -1;
static int hf_lte_rrc_sib12_reassembled_length = -1;
static int hf_lte_rrc_sib12_reassembled_data = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit1 = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit2 = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit3 = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit4 = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit5 = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit6 = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit7 = -1;
static int hf_lte_rrc_measGapPatterns_r15_bit8 = -1;

/* Initialize the subtree pointers */
static int ett_lte_rrc = -1;

#include "packet-lte-rrc-ett.c"

static gint ett_lte_rrc_featureGroupIndicators = -1;
static gint ett_lte_rrc_featureGroupIndRel9Add = -1;
static gint ett_lte_rrc_featureGroupIndRel10 = -1;
static gint ett_lte_rrc_absTimeInfo = -1;
static gint ett_lte_rrc_nas_SecurityParam = -1;
static gint ett_lte_rrc_targetRAT_MessageContainer = -1;
static gint ett_lte_rrc_siPsiSibContainer = -1;
static gint ett_lte_rrc_dedicatedInfoNAS = -1;
static gint ett_lte_rrc_timeInfo = -1;
static gint ett_lte_rrc_serialNumber = -1;
static gint ett_lte_rrc_warningType = -1;
static gint ett_lte_rrc_dataCodingScheme = -1;
static gint ett_lte_rrc_warningMessageSegment = -1;
static gint ett_lte_rrc_interBandTDD_CA_WithDifferentConfig = -1;
static gint ett_lte_rrc_tdd_FDD_CA_PCellDuplex_r12 = -1;
static gint ett_lte_rrc_aperiodicCSI_Reporting_r13 = -1;
static gint ett_lte_rrc_codebook_HARQ_ACK_r13 = -1;
static gint ett_lte_rrc_sr_ConfigIndex = -1;
static gint ett_lte_rrc_transmissionModeList_r12 = -1;
static gint ett_lte_rrc_modifiedMPR_Behavior_r10 = -1;
static gint ett_lte_rrc_sib11_fragment = -1;
static gint ett_lte_rrc_sib11_fragments = -1;
static gint ett_lte_rrc_sib12_fragment = -1;
static gint ett_lte_rrc_sib12_fragments = -1;
static gint ett_lte_rrc_nr_SecondaryCellGroupConfig_r15 = -1;
static gint ett_lte_rrc_nr_RadioBearerConfig_r15 = -1;
static gint ett_lte_rrc_nr_RadioBearerConfigS_r15 = -1;
static gint ett_lte_rrc_sl_ConfigDedicatedForNR_r16 = -1;
static gint ett_lte_rrc_nr_SecondaryCellGroupConfig = -1;
static gint ett_lte_rrc_scg_ConfigResponseNR_r15 = -1;
static gint ett_lte_rrc_scg_ConfigResponseNR_r16 = -1;
static gint ett_lte_rrc_measResultSCG_r15 = -1;
static gint ett_lte_rrc_measResultSCG_r16 = -1;
static gint ett_lte_rrc_ul_DCCH_MessageNR_r15 = -1;
static gint ett_lte_rrc_ul_DCCH_MessageNR_r16 = -1;
static gint ett_lte_rrc_sourceRB_ConfigNR_r15 = -1;
static gint ett_lte_rrc_sourceRB_ConfigSN_NR_r15 = -1;
static gint ett_lte_rrc_sourceOtherConfigSN_NR_r15 = -1;
static gint ett_lte_rrc_sourceContextEN_DC_r15 = -1;
static gint ett_lte_rrc_requestedFreqBandsNR_MRDC_r15 = -1;
static gint ett_lte_rrc_measGapPatterns_r15 = -1;
static gint ett_lte_rrc_nas_Container_r15 = -1;
static gint ett_lte_rrc_sourceRB_ConfigIntra5GC_r15 = -1;
static gint ett_lte_rrc_selectedbandCombinationInfoEN_DC_v1540 = -1;
static gint ett_lte_rrc_requestedCapabilityCommon_r15 = -1;
static gint ett_lte_rrc_sidelinkUEInformationNR_r16 = -1;
static gint ett_lte_rrc_ueAssistanceInformationNR_r16 = -1;
static gint ett_lte_rrc_sl_ParameterNR_r16 = -1;
static gint ett_lte_rrc_v2x_BandParametersNR_r16 = -1;
static gint ett_lte_rrc_ueAssistanceInformationNR_SCG_r16 = -1;
static gint ett_lte_rrc_assistanceDataSIB_Element_r15 = -1;
static gint ett_lte_rrc_overheatingAssistanceForSCG_r16 = -1;
static gint ett_lte_rrc_overheatingAssistanceForSCG_FR2_2_r17 = -1;
static gint ett_lte_rrc_triggerConditionSN_r17 = -1;

static expert_field ei_lte_rrc_number_pages_le15 = EI_INIT;
static expert_field ei_lte_rrc_si_info_value_changed = EI_INIT;
static expert_field ei_lte_rrc_sibs_changing = EI_INIT;
static expert_field ei_lte_rrc_sibs_changing_edrx = EI_INIT;
static expert_field ei_lte_rrc_earthquake_warning_sys = EI_INIT;
static expert_field ei_lte_rrc_commercial_mobile_alert_sys = EI_INIT;
static expert_field ei_lte_rrc_unexpected_type_value = EI_INIT;
static expert_field ei_lte_rrc_unexpected_length_value = EI_INIT;
static expert_field ei_lte_rrc_too_many_group_a_rapids = EI_INIT;
static expert_field ei_lte_rrc_invalid_drx_config = EI_INIT;

static const unit_name_string units_sr_periods = { " SR period", " SR periods" };
static const unit_name_string units_short_drx_cycles = { " shortDRX-Cycle", " shortDRX-Cycles" };

static reassembly_table lte_rrc_sib11_reassembly_table;
static reassembly_table lte_rrc_sib12_reassembly_table;

static const fragment_items lte_rrc_sib11_frag_items = {
    &ett_lte_rrc_sib11_fragment,
    &ett_lte_rrc_sib11_fragments,
    &hf_lte_rrc_sib11_fragments,
    &hf_lte_rrc_sib11_fragment,
    &hf_lte_rrc_sib11_fragment_overlap,
    &hf_lte_rrc_sib11_fragment_overlap_conflict,
    &hf_lte_rrc_sib11_fragment_multiple_tails,
    &hf_lte_rrc_sib11_fragment_too_long_fragment,
    &hf_lte_rrc_sib11_fragment_error,
    &hf_lte_rrc_sib11_fragment_count,
    &hf_lte_rrc_sib11_reassembled_in,
    &hf_lte_rrc_sib11_reassembled_length,
    &hf_lte_rrc_sib11_reassembled_data,
    "SIB11 warning message segments"
};

static const fragment_items lte_rrc_sib12_frag_items = {
    &ett_lte_rrc_sib12_fragment,
    &ett_lte_rrc_sib12_fragments,
    &hf_lte_rrc_sib12_fragments,
    &hf_lte_rrc_sib12_fragment,
    &hf_lte_rrc_sib12_fragment_overlap,
    &hf_lte_rrc_sib12_fragment_overlap_conflict,
    &hf_lte_rrc_sib12_fragment_multiple_tails,
    &hf_lte_rrc_sib12_fragment_too_long_fragment,
    &hf_lte_rrc_sib12_fragment_error,
    &hf_lte_rrc_sib12_fragment_count,
    &hf_lte_rrc_sib12_reassembled_in,
    &hf_lte_rrc_sib12_reassembled_length,
    &hf_lte_rrc_sib12_reassembled_data,
    "SIB12 warning message segments"
};

/* Forward declarations */
static int dissect_UECapabilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_RRCConnectionReconfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static const true_false_string lte_rrc_eutra_cap_feat_group_ind_1_val = {
  "Intra-subframe freq hopping for PUSCH scheduled by UL grant; DCI format 3a; Aperiodic CQI/PMI/RI report on PUSCH: Mode 2-0 & 2-2 - Supported",
  "Intra-subframe freq hopping for PUSCH scheduled by UL grant; DCI format 3a; Aperiodic CQI/PMI/RI report on PUSCH: Mode 2-0 & 2-2 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_2_val = {
  "Simultaneous CQI & ACK/NACK on PUCCH (format 2a/2b); Absolute TPC command for PUSCH; Resource alloc type 1 for PDSCH; Periodic CQI/PMI/RI report on PUCCH: Mode 2-0 & 2-1 - Supported",
  "Simultaneous CQI & ACK/NACK on PUCCH (format 2a/2b); Absolute TPC command for PUSCH; Resource alloc type 1 for PDSCH; Periodic CQI/PMI/RI report on PUCCH: Mode 2-0 & 2-1 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_3_val = {
  "5bit RLC UM SN; 7bit PDCP SN - Supported",
  "5bit RLC UM SN; 7bit PDCP SN - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_4_val = {
  "Short DRX cycle - Supported",
  "Short DRX cycle - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_5_val = {
  "Long DRX cycle; DRX command MAC control element - Supported",
  "Long DRX cycle; DRX command MAC control element - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_6_val = {
  "Prioritised bit rate - Supported",
  "Prioritised bit rate - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_7_val = {
  "RLC UM - Supported",
  "RLC UM - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_8_val = {
  "EUTRA RRC_CONNECTED to UTRA CELL_DCH PS handover - Supported",
  "EUTRA RRC_CONNECTED to UTRA CELL_DCH PS handover - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_9_val = {
  "EUTRA RRC_CONNECTED to GERAN GSM_Dedicated handover - Supported",
  "EUTRA RRC_CONNECTED to GERAN GSM_Dedicated handover - Not Supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_10_val = {
  "EUTRA RRC_CONNECTED to GERAN (Packet_) Idle by Cell Change Order; EUTRA RRC_CONNECTED to GERAN (Packet_) Idle by Cell Change Order with NACC - Supported",
  "EUTRA RRC_CONNECTED to GERAN (Packet_) Idle by Cell Change Order; EUTRA RRC_CONNECTED to GERAN (Packet_) Idle by Cell Change Order with NACC - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_11_val = {
  "EUTRA RRC_CONNECTED to CDMA2000 1xRTT CS Active handover - Supported",
  "EUTRA RRC_CONNECTED to CDMA2000 1xRTT CS Active handover - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_12_val = {
  "EUTRA RRC_CONNECTED to CDMA2000 HRPD Active handover - Supported",
  "EUTRA RRC_CONNECTED to CDMA2000 HRPD Active handover - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_13_val = {
  "Inter-frequency handover (within FDD or TDD) - Supported",
  "Inter-frequency handover (within FDD or TDD) - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_14_val = {
  "Measurement reporting event: Event A4 - Neighbour > threshold; Measurement reporting event: Event A5 - Serving < threshold1 & Neighbour > threshold2 - Supported",
  "Measurement reporting event: Event A4 - Neighbour > threshold; Measurement reporting event: Event A5 - Serving < threshold1 & Neighbour > threshold2 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_15_val = {
  "Measurement reporting event: Event B1 - Neighbour > threshold - Supported",
  "Measurement reporting event: Event B1 - Neighbour > threshold - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_16_val = {
  "non-ANR related periodical measurement reporting - Supported",
  "non-ANR related periodical measurement reporting - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_17_val = {
  "ANR related intra-frequency measurement reporting events - Supported",
  "ANR related intra-frequency measurement reporting events - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_18_val = {
  "ANR related inter-frequency measurement reporting events - Supported",
  "ANR related inter-frequency measurement reporting events - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_19_val = {
  "ANR related inter-RAT measurement reporting events - Supported",
  "ANR related inter-RAT measurement reporting events - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_20_val = {
  "SRB1 and SRB2 for DCCH + 8x AM DRB; SRB1 and SRB2 for DCCH + 5x AM DRB + 3x UM DRB (if indicator 7 is supported) - Supported",
  "SRB1 and SRB2 for DCCH + 8x AM DRB; SRB1 and SRB2 for DCCH + 5x AM DRB + 3x UM DRB (if indicator 7 is supported) - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_21_val = {
  "Predefined intra- and inter-subframe frequency hopping for PUSCH with N_sb > 1; Predefined inter-subframe frequency hopping for PUSCH with N_sb > 1 - Supported",
  "Predefined intra- and inter-subframe frequency hopping for PUSCH with N_sb > 1; Predefined inter-subframe frequency hopping for PUSCH with N_sb > 1 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_22_val = {
  "UTRAN measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Supported",
  "UTRAN measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_23_val = {
  "GERAN measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Supported",
  "GERAN measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_24_val = {
  "1xRTT measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Supported",
  "1xRTT measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_25_val = {
  "Inter-frequency measurements and reporting in E-UTRA connected mode - Supported",
  "Inter-frequency measurements and reporting in E-UTRA connected mode - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_26_val = {
  "HRPD measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Supported",
  "HRPD measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_27_val = {
  "EUTRA RRC_CONNECTED to UTRA CELL_DCH CS handover - Supported",
  "EUTRA RRC_CONNECTED to UTRA CELL_DCH CS handover - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_28_val = {
  "TTI bundling - Supported",
  "TTI bundling - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_29_val = {
  "Semi-Persistent Scheduling - Supported",
  "Semi-Persistent Scheduling - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_30_val = {
  "Handover between FDD and TDD - Supported",
  "Handover between FDD and TDD - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_31_val = {
  "Mechanisms defined for cells broadcasting multi band information - Supported",
  "Mechanisms defined for cells broadcasting multi band information - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_32_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_33_val = {
  "Inter-RAT ANR features for UTRAN FDD - Supported",
  "Inter-RAT ANR features for UTRAN FDD - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_34_val = {
  "Inter-RAT ANR features for GERAN - Supported",
  "Inter-RAT ANR features for GERAN - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_35_val = {
  "Inter-RAT ANR features for 1xRTT - Supported",
  "Inter-RAT ANR features for 1xRTT - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_36_val = {
  "Inter-RAT ANR features for HRPD - Supported",
  "Inter-RAT ANR features for HRPD - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_37_val = {
  "Inter-RAT ANR features for UTRAN TDD - Supported",
  "Inter-RAT ANR features for UTRAN TDD - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_38_val = {
  "EUTRA RRC_CONNECTED to UTRA TDD CELL_DCH PS handover - Supported",
  "EUTRA RRC_CONNECTED to UTRA TDD CELL_DCH PS handover - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_39_val = {
  "UTRAN TDD measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Supported",
  "UTRAN TDD measurements, reporting and measurement reporting event B2 in E-UTRA connected mode - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_40_val = {
  "EUTRA RRC_CONNECTED to UTRA TDD CELL_DCH CS handover - Supported",
  "EUTRA RRC_CONNECTED to UTRA TDD CELL_DCH CS handover - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_41_val = {
  "Measurement reporting event: Event B1 - Neighbour > threshold for UTRAN FDD - Supported",
  "Measurement reporting event: Event B1 - Neighbour > threshold for UTRAN FDD - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_42_val = {
  "DCI format 3a - Supported",
  "DCI format 3a - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_43_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_44_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_45_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_46_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_47_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_48_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_49_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_50_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_51_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_52_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_53_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_54_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_55_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_56_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_57_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_58_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_59_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_60_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_61_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_62_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_63_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_64_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_101_val = {
  "DMRS with OCC (orthogonal cover code) and SGH (sequence group hopping) disabling - Supported",
  "DMRS with OCC (orthogonal cover code) and SGH (sequence group hopping) disabling - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_102_val = {
  "Trigger type 1 SRS (aperiodic SRS) transmission (Up to X ports) - Supported",
  "Trigger type 1 SRS (aperiodic SRS) transmission (Up to X ports) - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_103_val = {
  "PDSCH TM9 when up to 4 CSI reference signal ports are configured - Supported",
  "PDSCH TM9 when up to 4 CSI reference signal ports are configured - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_104_val = {
  "PDSCH TM9 for TDD when 8 CSI reference signal ports are configured - Supported",
  "PDSCH TM9 for TDD when 8 CSI reference signal ports are configured - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_105_val = {
  "PUCCH RM2-0 when PDSCH TM9 is configured and RM2-1 when PDSCH TM9 and up to 4 CSI reference signal ports are configured - Supported",
  "PUCCH RM2-0 when PDSCH TM9 is configured and RM2-1 when PDSCH TM9 and up to 4 CSI reference signal ports are configured - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_106_val = {
  "PUCCH RM2-1 when PDSCH TM9 and 8 CSI reference signal ports are configured - Supported",
  "PUCCH RM2-1 when PDSCH TM9 and 8 CSI reference signal ports are configured - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_107_val = {
  "PUSCH RM2-0 when PDSCH TM9 is configured and RM2-2 when PDSCH TM9 and up to 4 CSI reference signal ports are configured - Supported",
  "PUSCH RM2-0 when PDSCH TM9 is configured and RM2-2 when PDSCH TM9 and up to 4 CSI reference signal ports are configured - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_108_val = {
  "PUSCH RM2-2 when PDSCH TM9 and 8 CSI reference signal ports are configured - Supported",
  "PUSCH RM2-2 when PDSCH TM9 and 8 CSI reference signal ports are configured - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_109_val = {
  "PUCCH RM1-1 submode 1 - Supported",
  "PUCCH RM1-1 submode 1 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_110_val = {
  "PUCCH RM1-1 submode 2 - Supported",
  "PUCCH RM1-1 submode 2 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_111_val = {
  "Measurement reporting trigger Event A6 - Supported",
  "Measurement reporting trigger Event A6 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_112_val = {
  "SCell addition within the Handover to EUTRA procedure - Supported",
  "SCell addition within the Handover to EUTRA procedure - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_113_val = {
  "Trigger type 0 SRS (periodic SRS) transmission on X Serving Cells - Supported",
  "Trigger type 0 SRS (periodic SRS) transmission on X Serving Cells - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_114_val = {
  "Reporting of both UTRA CPICH RSCP and Ec/N0 in a Measurement Report - Supported",
  "Reporting of both UTRA CPICH RSCP and Ec/N0 in a Measurement Report - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_115_val = {
  "Time domain ICIC RLM/RRM / ICIC RRM / ICIC CSI measurement sf restriction for the serving cell / neighbour cells - Supported",
  "Time domain ICIC RLM/RRM / ICIC RRM / ICIC CSI measurement sf restriction for the serving cell / neighbour cells - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_116_val = {
  "Relative transmit phase continuity for spatial multiplexing in UL - Supported",
  "Relative transmit phase continuity for spatial multiplexing in UL - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_117_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_118_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_119_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_120_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_121_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_122_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_123_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_124_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_125_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_126_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_127_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_128_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_129_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_130_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_131_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_132_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
};

static const value_string lte_rrc_schedulingInfoSIB1_BR_r13_vals[] = {
  {  0, "SystemInformationBlockType1-BR is not scheduled"},
  {  1, "4 PDSCH repetitions - TBS 208 bits"},
  {  2, "8 PDSCH repetitions - TBS 208 bits"},
  {  3, "16 PDSCH repetitions - TBS 208 bits"},
  {  4, "4 PDSCH repetitions - TBS 256 bits"},
  {  5, "8 PDSCH repetitions - TBS 256 bits"},
  {  6, "16 PDSCH repetitions - TBS 256 bits"},
  {  7, "4 PDSCH repetitions - TBS 328 bits"},
  {  8, "8 PDSCH repetitions - TBS 328 bits"},
  {  9, "16 PDSCH repetitions - TBS 328 bits"},
  { 10, "4 PDSCH repetitions - TBS 504 bits"},
  { 11, "8 PDSCH repetitions - TBS 504 bits"},
  { 12, "16 PDSCH repetitions - TBS 504 bits"},
  { 13, "4 PDSCH repetitions - TBS 712 bits"},
  { 14, "8 PDSCH repetitions - TBS 712 bits"},
  { 15, "16 PDSCH repetitions - TBS 712 bits"},
  { 16, "4 PDSCH repetitions - TBS 936 bits"},
  { 17, "8 PDSCH repetitions - TBS 936 bits"},
  { 18, "16 PDSCH repetitions - TBS 936 bits"},
  {  0, NULL}
};
static value_string_ext lte_rrc_schedulingInfoSIB1_BR_r13_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_schedulingInfoSIB1_BR_r13_vals);

static const value_string lte_rrc_q_RxLevMin_vals[] = {
  { -70, "-140dBm"},
  { -69, "-138dBm"},
  { -68, "-136dBm"},
  { -67, "-134dBm"},
  { -66, "-132dBm"},
  { -65, "-130dBm"},
  { -64, "-128dBm"},
  { -63, "-126dBm"},
  { -62, "-124dBm"},
  { -61, "-122dBm"},
  { -60, "-120dBm"},
  { -59, "-118dBm"},
  { -58, "-116dBm"},
  { -57, "-114dBm"},
  { -56, "-112dBm"},
  { -55, "-110dBm"},
  { -54, "-108dBm"},
  { -53, "-106dBm"},
  { -52, "-104dBm"},
  { -51, "-102dBm"},
  { -50, "-100dBm"},
  { -49, "-98dBm"},
  { -48, "-96dBm"},
  { -47, "-94dBm"},
  { -46, "-92dBm"},
  { -45, "-90dBm"},
  { -44, "-88dBm"},
  { -43, "-86dBm"},
  { -42, "-84dBm"},
  { -41, "-82dBm"},
  { -40, "-80dBm"},
  { -39, "-78dBm"},
  { -38, "-76dBm"},
  { -37, "-74dBm"},
  { -36, "-72dBm"},
  { -35, "-70dBm"},
  { -34, "-68dBm"},
  { -33, "-66dBm"},
  { -32, "-64dBm"},
  { -31, "-62dBm"},
  { -30, "-60dBm"},
  { -29, "-58dBm"},
  { -28, "-56dBm"},
  { -27, "-54dBm"},
  { -26, "-52dBm"},
  { -25, "-50dBm"},
  { -24, "-48dBm"},
  { -23, "-46dBm"},
  { -22, "-44dBm"},
  {   0, NULL}
};
static value_string_ext lte_rrc_q_RxLevMin_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_q_RxLevMin_vals);

static const value_string lte_rrc_q_RxLevMinOffset_vals[] = {
  { 1, "2dB"},
  { 2, "4dB"},
  { 3, "6dB"},
  { 4, "8dB"},
  { 5, "10dB"},
  { 6, "12dB"},
  { 7, "14dB"},
  { 8, "16dB"},
  { 0, NULL}
};

static const value_string lte_rrc_delta_RxLevMin_vals[] = {
  { -8, "-16dBm"},
  { -7, "-14dBm"},
  { -6, "-12dBm"},
  { -5, "-10dBm"},
  { -4, "-8dBm"},
  { -3, "-6dBm"},
  { -2, "-4dBm"},
  { -1, "-2dBm"},
  { 0, NULL}
};

static const value_string lte_rrc_messageSize_r14_vals[] =
{
    { 0,  "size = 0"},
    { 1,  "0 < size <= 10"},
    { 2,  "10 < size <= 12"},
    { 3,  "12 < size <= 14"},
    { 4,  "14 < size <= 17"},
    { 5,  "17 < size <= 19"},
    { 6,  "19 < size <= 22"},
    { 7,  "22 < size <= 26"},
    { 8,  "26 < size <= 31"},
    { 9,  "31 < size <= 36"},
    { 10, "36 < size <= 42"},
    { 11, "42 < size <= 49"},
    { 12, "49 < size <= 57"},
    { 13, "57 < size <= 67"},
    { 14, "67 < size <= 78"},
    { 15, "78 < size <= 91"},
    { 16, "91 < size <= 107"},
    { 17, "107 < size <= 125"},
    { 18, "125 < size <= 146"},
    { 19, "146 < size <= 171"},
    { 20, "171 < size <= 200"},
    { 21, "200 < size <= 234"},
    { 22, "234 < size <= 274"},
    { 23, "274 < size <= 321"},
    { 24, "321 < size <= 376"},
    { 25, "376 < size <= 440"},
    { 26, "440 < size <= 515"},
    { 27, "515 < size <= 603"},
    { 28, "603 < size <= 706"},
    { 29, "706 < size <= 826"},
    { 30, "826 < size <= 967"},
    { 31, "967 < size <= 1132"},
    { 32, "1132 < size <= 1326"},
    { 33, "1326 < size <= 1552"},
    { 34, "1552 < size <= 1817"},
    { 35, "1817 < size <= 2127"},
    { 36, "2127 < size <= 2490"},
    { 37, "2490 < size <= 2915"},
    { 38, "2915 < size <= 3413"},
    { 39, "3413 < size <= 3995"},
    { 40, "3995 < size <= 4677"},
    { 41, "4677 < size <= 5476"},
    { 42, "5476 < size <= 6411"},
    { 43, "6411 < size <= 7505"},
    { 44, "7505 < size <= 8787"},
    { 45, "8787 < size <= 10276"},
    { 46, "10287 < size <= 12043"},
    { 47, "12043 < size <= 14099"},
    { 48, "14099 < size <= 16507"},
    { 49, "16507 < size <= 19325"},
    { 50, "19325 < size <= 22624"},
    { 51, "22624 < size <= 26487"},
    { 52, "26487 < size <= 31009"},
    { 53, "31009 < size <= 36304"},
    { 54, "36304 < size <= 42502"},
    { 55, "42502 < size <= 49759"},
    { 56, "49759 < size <= 58255"},
    { 57, "58255 < size <= 68201"},
    { 58, "68201 < size <= 79846"},
    { 59, "79846 < size <= 93479"},
    { 60, "93479 < size <= 109439"},
    { 61, "109439 < size <= 128125"},
    { 62, "128125 < size <= 150000"},
    { 63, "size > 150000"},
    { 0, NULL }
};
static value_string_ext lte_rrc_messageSize_r14_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_messageSize_r14_vals);

static void
lte_rrc_timeConnFailure_r10_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ums (%u)", 100*v, v);
}

static const value_string lte_rrc_n_r12_vals[] = {
  {  0, "0 <= Nr < 256"},
  {  1, "256 <= Nr < 768"},
  {  2, "768 <= Nr < 1792"},
  {  3, "1792 <= Nr < 3840"},
  {  4, "3840 <= Nr < 7936"},
  {  5, "7936 <= Nr < 16128"},
  {  6, "16128 <= Nr < 32512"},
  {  7, "32512 <= Nr"},
  {  0, NULL},
};

static void
lte_rrc_m_r12_fmt(gchar *s, guint32 v)
{
  if (v == 255) {
    snprintf(s, ITEM_LABEL_LENGTH, "255 <= f(Nr) (255)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u <= f(Nr) < %u (%u)", v, v+1, v);
  }
}

static const value_string lte_rrc_BLER_Range_r12_vals[] = {
  {  0, "BLER < 0.1%"},
  {  1, "0.1% <= BLER < 0.123%"},
  {  2, "0.123% <= BLER < 0.151%"},
  {  3, "0.151% <= BLER < 0.186%"},
  {  4, "0.186% <= BLER < 0.229%"},
  {  5, "0.229% <= BLER < 0.282%"},
  {  6, "0.282% <= BLER < 0.347%"},
  {  7, "0.347% <= BLER < 0.426%"},
  {  8, "0.426% <= BLER < 0.525%"},
  {  9, "0.525% <= BLER < 0.645%"},
  { 10, "0.645% <= BLER < 0.794%"},
  { 11, "0.794% <= BLER < 0.976%"},
  { 12, "0.976% <= BLER < 1.201%"},
  { 13, "1.201% <= BLER < 1.478%"},
  { 14, "1.478% <= BLER < 1.818%"},
  { 15, "1.818% <= BLER < 2.236%"},
  { 16, "2.236% <= BLER < 2.751%"},
  { 17, "2.751% <= BLER < 3.384%"},
  { 18, "3.384% <= BLER < 4.163%"},
  { 19, "4.163% <= BLER < 5.121%"},
  { 20, "5.121% <= BLER < 6.300%"},
  { 21, "6.300% <= BLER < 7.750%"},
  { 22, "7.750% <= BLER < 9.533%"},
  { 23, "9.533% <= BLER < 11.728%"},
  { 24, "11.728% <= BLER < 14.427%"},
  { 25, "14.427% <= BLER < 17.478%"},
  { 26, "17.478% <= BLER < 21.833%"},
  { 27, "21.833% <= BLER < 26.858%"},
  { 28, "26.858% <= BLER < 33.040%"},
  { 29, "33.040% <= BLER < 40.645%"},
  { 30, "40.645% <= BLER < 50%"},
  { 31, "50% <= BLER"},
  { 0, NULL}
};
static value_string_ext lte_rrc_BLER_Range_r12_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_BLER_Range_r12_vals);

static const value_string lte_rrc_utra_q_RxLevMin_vals[] = {
  { -60, "-119dBm"},
  { -59, "-117dBm"},
  { -58, "-115dBm"},
  { -57, "-113dBm"},
  { -56, "-111dBm"},
  { -55, "-109dBm"},
  { -54, "-107dBm"},
  { -53, "-105dBm"},
  { -52, "-103dBm"},
  { -51, "-101dBm"},
  { -50, "-99dBm"},
  { -49, "-97dBm"},
  { -48, "-95dBm"},
  { -47, "-93dBm"},
  { -46, "-91dBm"},
  { -45, "-89dBm"},
  { -44, "-87dBm"},
  { -43, "-85dBm"},
  { -42, "-83dBm"},
  { -41, "-81dBm"},
  { -40, "-79dBm"},
  { -39, "-77dBm"},
  { -38, "-75dBm"},
  { -37, "-73dBm"},
  { -36, "-71dBm"},
  { -35, "-69dBm"},
  { -34, "-67dBm"},
  { -33, "-65dBm"},
  { -32, "-63dBm"},
  { -31, "-61dBm"},
  { -30, "-59dBm"},
  { -29, "-57dBm"},
  { -28, "-55dBm"},
  { -27, "-53dBm"},
  { -26, "-51dBm"},
  { -25, "-49dBm"},
  { -24, "-47dBm"},
  { -23, "-45dBm"},
  { -22, "-43dBm"},
  { -21, "-41dBm"},
  { -20, "-39dBm"},
  { -19, "-37dBm"},
  { -18, "-35dBm"},
  { -17, "-33dBm"},
  { -16, "-31dBm"},
  { -15, "-29dBm"},
  { -14, "-27dBm"},
  { -13, "-25dBm"},
  {   0, NULL}
};
static value_string_ext lte_rrc_utra_q_RxLevMin_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_utra_q_RxLevMin_vals);

static const value_string lte_rrc_geran_q_RxLevMin_vals[] = {
  { 0 , "-115dBm"},
  { 1 , "-113dBm"},
  { 2 , "-111dBm"},
  { 3 , "-109dBm"},
  { 4 , "-107dBm"},
  { 5 , "-105dBm"},
  { 6 , "-103dBm"},
  { 7 , "-101dBm"},
  { 8 , "-99dBm"},
  { 9 , "-97dBm"},
  { 10, "-95dBm"},
  { 11, "-93dBm"},
  { 12, "-91dBm"},
  { 13, "-89dBm"},
  { 14, "-87dBm"},
  { 15, "-85dBm"},
  { 16, "-83dBm"},
  { 17, "-81dBm"},
  { 18, "-79dBm"},
  { 19, "-77dBm"},
  { 20, "-75dBm"},
  { 21, "-73dBm"},
  { 22, "-71dBm"},
  { 23, "-69dBm"},
  { 24, "-67dBm"},
  { 25, "-65dBm"},
  { 26, "-63dBm"},
  { 27, "-61dBm"},
  { 28, "-59dBm"},
  { 29, "-57dBm"},
  { 30, "-55dBm"},
  { 31, "-53dBm"},
  { 32, "-51dBm"},
  { 33, "-49dBm"},
  { 34, "-47dBm"},
  { 35, "-45dBm"},
  { 36, "-43dBm"},
  { 37, "-41dBm"},
  { 38, "-39dBm"},
  { 39, "-37dBm"},
  { 40, "-35dBm"},
  { 41, "-33dBm"},
  { 42, "-31dBm"},
  { 43, "-29dBm"},
  { 44, "-27dBm"},
  { 45, "-25dBm"},
  {  0, NULL}
};
static value_string_ext lte_rrc_geran_q_RxLevMin_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_geran_q_RxLevMin_vals);

static const value_string lte_rrc_nomPDSCH_RS_EPRE_Offset_vals[] = {
  { -1, "-2dB"},
  {  0, "0dB"},
  {  1, "2dB"},
  {  2, "4dB"},
  {  3, "6dB"},
  {  4, "8dB"},
  {  5, "10dB"},
  {  6, "12dB"},
  {  0, NULL}
};

static const value_string lte_rrc_deltaPreambleMsg3_vals[] = {
  { -1, "-2dB"},
  {  0, "0dB"},
  {  1, "2dB"},
  {  2, "4dB"},
  {  3, "6dB"},
  {  4, "8dB"},
  {  5, "10dB"},
  {  6, "12dB"},
  {  0, NULL}
};

static const value_string lte_rrc_ReselectionThreshold_vals[] = {
  { 0 , "0dB"},
  { 1 , "2dB"},
  { 2 , "4dB"},
  { 3 , "6dB"},
  { 4 , "8dB"},
  { 5 , "10dB"},
  { 6 , "12dB"},
  { 7 , "14dB"},
  { 8 , "16dB"},
  { 9 , "18dB"},
  { 10, "20dB"},
  { 11, "22dB"},
  { 12, "24dB"},
  { 13, "26dB"},
  { 14, "28dB"},
  { 15, "30dB"},
  { 16, "32dB"},
  { 17, "34dB"},
  { 18, "36dB"},
  { 19, "38dB"},
  { 20, "40dB"},
  { 21, "42dB"},
  { 22, "44dB"},
  { 23, "46dB"},
  { 24, "48dB"},
  { 25, "50dB"},
  { 26, "52dB"},
  { 27, "54dB"},
  { 28, "56dB"},
  { 29, "58dB"},
  { 30, "60dB"},
  { 31, "62dB"},
  {  0, NULL}
};
static value_string_ext lte_rrc_ReselectionThreshold_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_ReselectionThreshold_vals);

static const value_string lte_rrc_ReselectionThreshold_NB_vals[] = {
  { 32, "64dB"},
  { 33, "66dB"},
  { 34, "68dB"},
  { 35, "70dB"},
  { 36, "72dB"},
  { 37, "74dB"},
  { 38, "76dB"},
  { 39, "78dB"},
  { 40, "80dB"},
  { 41, "82dB"},
  { 42, "84dB"},
  { 43, "86dB"},
  { 44, "88dB"},
  { 45, "90dB"},
  { 46, "92dB"},
  { 47, "94dB"},
  { 48, "96dB"},
  { 49, "98dB"},
  { 50, "100dB"},
  { 51, "102dB"},
  { 52, "104dB"},
  { 53, "106dB"},
  { 54, "108dB"},
  { 55, "110dB"},
  { 56, "112dB"},
  { 57, "114dB"},
  { 58, "116dB"},
  { 59, "118dB"},
  { 60, "120dB"},
  { 61, "122dB"},
  { 62, "124dB"},
  { 63, "126dB"},
  {  0, NULL}
};
static value_string_ext lte_rrc_ReselectionThreshold_NB_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_ReselectionThreshold_NB_vals);

static const value_string lte_rrc_Hysteresis_vals[] = {
  { 0 , "0dB"},
  { 1 , "0.5dB"},
  { 2 , "1dB"},
  { 3 , "1.5dB"},
  { 4 , "2dB"},
  { 5 , "2.5dB"},
  { 6 , "3dB"},
  { 7 , "3.5dB"},
  { 8 , "4dB"},
  { 9 , "4.5dB"},
  { 10, "5dB"},
  { 11, "5.5dB"},
  { 12, "6dB"},
  { 13, "6.5dB"},
  { 14, "7dB"},
  { 15, "7.5dB"},
  { 16, "8dB"},
  { 17, "8.5dB"},
  { 18, "9dB"},
  { 19, "9.5dB"},
  { 20, "10dB"},
  { 21, "10.5dB"},
  { 22, "11dB"},
  { 23, "11.5dB"},
  { 24, "12dB"},
  { 25, "12.5dB"},
  { 26, "13dB"},
  { 27, "13.5dB"},
  { 28, "14dB"},
  { 29, "14.5dB"},
  { 30, "15dB"},
  {  0, NULL}
};
static value_string_ext lte_rrc_Hysteresis_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_Hysteresis_vals);

static const value_string lte_rrc_s_Measure_vals[] = {
  {  0, "disabled"},
  {  1, "-139dBm"},
  {  2, "-138dBm"},
  {  3, "-137dBm"},
  {  4, "-136dBm"},
  {  5, "-135dBm"},
  {  6, "-134dBm"},
  {  7, "-133dBm"},
  {  8, "-132dBm"},
  {  9, "-131dBm"},
  { 10, "-130dBm"},
  { 11, "-129dBm"},
  { 12, "-128dBm"},
  { 13, "-127dBm"},
  { 14, "-126dBm"},
  { 15, "-125dBm"},
  { 16, "-124dBm"},
  { 17, "-123dBm"},
  { 18, "-122dBm"},
  { 19, "-121dBm"},
  { 20, "-120dBm"},
  { 21, "-119dBm"},
  { 22, "-118dBm"},
  { 23, "-117dBm"},
  { 24, "-116dBm"},
  { 25, "-115dBm"},
  { 26, "-114dBm"},
  { 27, "-113dBm"},
  { 28, "-112dBm"},
  { 29, "-111dBm"},
  { 30, "-110dBm"},
  { 31, "-109dBm"},
  { 32, "-108dBm"},
  { 33, "-107dBm"},
  { 34, "-106dBm"},
  { 35, "-105dBm"},
  { 36, "-104dBm"},
  { 37, "-103dBm"},
  { 38, "-102dBm"},
  { 39, "-101dBm"},
  { 40, "-100dBm"},
  { 41, "-99dBm"},
  { 42, "-98dBm"},
  { 43, "-97dBm"},
  { 44, "-96dBm"},
  { 45, "-95dBm"},
  { 46, "-94dBm"},
  { 47, "-93dBm"},
  { 48, "-92dBm"},
  { 49, "-91dBm"},
  { 50, "-90dBm"},
  { 51, "-89dBm"},
  { 52, "-88dBm"},
  { 53, "-87dBm"},
  { 54, "-86dBm"},
  { 55, "-85dBm"},
  { 56, "-84dBm"},
  { 57, "-83dBm"},
  { 58, "-82dBm"},
  { 59, "-81dBm"},
  { 60, "-80dBm"},
  { 61, "-79dBm"},
  { 62, "-78dBm"},
  { 63, "-77dBm"},
  { 64, "-76dBm"},
  { 65, "-75dBm"},
  { 66, "-74dBm"},
  { 67, "-73dBm"},
  { 68, "-72dBm"},
  { 69, "-71dBm"},
  { 70, "-70dBm"},
  { 71, "-69dBm"},
  { 72, "-68dBm"},
  { 73, "-67dBm"},
  { 74, "-66dBm"},
  { 75, "-65dBm"},
  { 76, "-64dBm"},
  { 77, "-63dBm"},
  { 78, "-62dBm"},
  { 79, "-61dBm"},
  { 80, "-60dBm"},
  { 81, "-59dBm"},
  { 82, "-58dBm"},
  { 83, "-57dBm"},
  { 84, "-56dBm"},
  { 85, "-55dBm"},
  { 86, "-54dBm"},
  { 87, "-53dBm"},
  { 88, "-52dBm"},
  { 89, "-51dBm"},
  { 90, "-50dBm"},
  { 91, "-49dBm"},
  { 92, "-48dBm"},
  { 93, "-47dBm"},
  { 94, "-46dBm"},
  { 95, "-45dBm"},
  { 96, "-44dBm"},
  { 97, "-43dBm"},
  {  0, NULL}
};
static value_string_ext lte_rrc_s_Measure_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_s_Measure_vals);

static const value_string lte_rrc_utra_EcN0_vals[] = {
  { 0 , "CPICH Ec/Io < -24dB"},
  { 1 , "-24dB <= CPICH Ec/Io < -23.5dB"},
  { 2 , "-23.5dB <= CPICH Ec/Io < -23dB"},
  { 3 , "-23dB <= CPICH Ec/Io < -22.5dB"},
  { 4 , "-22.5dB <= CPICH Ec/Io < -22dB"},
  { 5 , "-22dB <= CPICH Ec/Io < -21.5dB"},
  { 6 , "-21.5dB <= CPICH Ec/Io < -21dB"},
  { 7 , "-21dB <= CPICH Ec/Io < -20.5dB"},
  { 8 , "-20.5dB <= CPICH Ec/Io < -20dB"},
  { 9 , "-20dB <= CPICH Ec/Io < -19.5dB"},
  { 10, "-19.5dB <= CPICH Ec/Io < -19dB"},
  { 11, "-19dB <= CPICH Ec/Io < -18.5dB"},
  { 12, "-18.5dB <= CPICH Ec/Io < -18dB"},
  { 13, "-18dB <= CPICH Ec/Io < -17.5dB"},
  { 14, "-17.5dB <= CPICH Ec/Io < -17dB"},
  { 15, "-17dB <= CPICH Ec/Io < -16.5dB"},
  { 16, "-16.5dB <= CPICH Ec/Io < -16dB"},
  { 17, "-16dB <= CPICH Ec/Io < -15.5dB"},
  { 18, "-15.5dB <= CPICH Ec/Io < -15dB"},
  { 19, "-15dB <= CPICH Ec/Io < -14.5dB"},
  { 20, "-14.5dB <= CPICH Ec/Io < -14dB"},
  { 21, "-14dB <= CPICH Ec/Io < -13.5dB"},
  { 22, "-13.5dB <= CPICH Ec/Io < -13dB"},
  { 23, "-13dB <= CPICH Ec/Io < -12.5dB"},
  { 24, "-12.5dB <= CPICH Ec/Io < -12dB"},
  { 25, "-12dB <= CPICH Ec/Io < -11.5dB"},
  { 26, "-11.5dB <= CPICH Ec/Io < -11dB"},
  { 27, "-11dB <= CPICH Ec/Io < -10.5dB"},
  { 28, "-10.5dB <= CPICH Ec/Io < -10dB"},
  { 29, "-10dB <= CPICH Ec/Io < -9.5dB"},
  { 30, "-9.5dB <= CPICH Ec/Io < -9dB"},
  { 31, "-9dB <= CPICH Ec/Io < -8.5dB"},
  { 32, "-8.5dB <= CPICH Ec/Io < -8dB"},
  { 33, "-8dB <= CPICH Ec/Io < -7.5dB"},
  { 34, "-7.5dB <= CPICH Ec/Io < -7dB"},
  { 35, "-7dB <= CPICH Ec/Io < -6.5dB"},
  { 36, "-6.5dB <= CPICH Ec/Io < -6dB"},
  { 37, "-6dB <= CPICH Ec/Io < -5.5dB"},
  { 38, "-5.5dB <= CPICH Ec/Io < -5dB"},
  { 39, "-5dB <= CPICH Ec/Io < -4.5dB"},
  { 40, "-4.5dB <= CPICH Ec/Io < -4dB"},
  { 41, "-4dB <= CPICH Ec/Io < -3.5dB"},
  { 42, "-3.5dB <= CPICH Ec/Io < -3dB"},
  { 43, "-3dB <= CPICH Ec/Io < -2.5dB"},
  { 44, "-2.5dB <= CPICH Ec/Io < -2dB"},
  { 45, "-2dB <= CPICH Ec/Io < -1.5dB"},
  { 46, "-1.5dB <= CPICH Ec/Io < -1dB"},
  { 47, "-1dB <= CPICH Ec/Io < -0.5dB"},
  { 48, "-0.5dB <= CPICH Ec/Io < 0dB"},
  { 49, "0dB <= CPICH Ec/Io"},
  {  0, NULL}
};
static value_string_ext lte_rrc_utra_EcN0_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_utra_EcN0_vals);

static const value_string lte_rrc_utra_RSCP_vals[] = {
  { -5, "RSCP < -120dBm"},
  { -4, "-120dBm <= RSCP < -119dBm"},
  { -3, "-119dBm <= RSCP < -118dBm"},
  { -2, "-118dBm <= RSCP < -117dBm"},
  { -1, "-117dBm <= RSCP < -116dBm"},
  {  0, "-116dBm <= RSCP < -115dBm"},
  {  1, "-115dBm <= RSCP < -114dBm"},
  {  2, "-114dBm <= RSCP < -113dBm"},
  {  3, "-113dBm <= RSCP < -112dBm"},
  {  4, "-112dBm <= RSCP < -111dBm"},
  {  5, "-111dBm <= RSCP < -110dBm"},
  {  6, "-110dBm <= RSCP < -109dBm"},
  {  7, "-109dBm <= RSCP < -108dBm"},
  {  8, "-108dBm <= RSCP < -107dBm"},
  {  9, "-107dBm <= RSCP < -106dBm"},
  { 10, "-106dBm <= RSCP < -105dBm"},
  { 11, "-105dBm <= RSCP < -104dBm"},
  { 12, "-104dBm <= RSCP < -103dBm"},
  { 13, "-103dBm <= RSCP < -102dBm"},
  { 14, "-102dBm <= RSCP < -101dBm"},
  { 15, "-101dBm <= RSCP < -100dBm"},
  { 16, "-100dBm <= RSCP < -99dBm"},
  { 17, "-99dBm <= RSCP < -98dBm"},
  { 18, "-98dBm <= RSCP < -97dBm"},
  { 19, "-97dBm <= RSCP < -96dBm"},
  { 20, "-96dBm <= RSCP < -95dBm"},
  { 21, "-95dBm <= RSCP < -94dBm"},
  { 22, "-94dBm <= RSCP < -93dBm"},
  { 23, "-93dBm <= RSCP < -92dBm"},
  { 24, "-92dBm <= RSCP < -91dBm"},
  { 25, "-91dBm <= RSCP < -90dBm"},
  { 26, "-90dBm <= RSCP < -89dBm"},
  { 27, "-89dBm <= RSCP < -88dBm"},
  { 28, "-88dBm <= RSCP < -87dBm"},
  { 29, "-87dBm <= RSCP < -86dBm"},
  { 30, "-86dBm <= RSCP < -85dBm"},
  { 31, "-85dBm <= RSCP < -84dBm"},
  { 32, "-84dBm <= RSCP < -83dBm"},
  { 33, "-83dBm <= RSCP < -82dBm"},
  { 34, "-82dBm <= RSCP < -81dBm"},
  { 35, "-81dBm <= RSCP < -80dBm"},
  { 36, "-80dBm <= RSCP < -79dBm"},
  { 37, "-79dBm <= RSCP < -78dBm"},
  { 38, "-78dBm <= RSCP < -77dBm"},
  { 39, "-77dBm <= RSCP < -76dBm"},
  { 40, "-76dBm <= RSCP < -75dBm"},
  { 41, "-75dBm <= RSCP < -74dBm"},
  { 42, "-74dBm <= RSCP < -73dBm"},
  { 43, "-73dBm <= RSCP < -72dBm"},
  { 44, "-72dBm <= RSCP < -71dBm"},
  { 45, "-71dBm <= RSCP < -70dBm"},
  { 46, "-70dBm <= RSCP < -69dBm"},
  { 47, "-69dBm <= RSCP < -68dBm"},
  { 48, "-68dBm <= RSCP < -67dBm"},
  { 49, "-67dBm <= RSCP < -66dBm"},
  { 50, "-66dBm <= RSCP < -65dBm"},
  { 51, "-65dBm <= RSCP < -64dBm"},
  { 52, "-64dBm <= RSCP < -63dBm"},
  { 53, "-63dBm <= RSCP < -62dBm"},
  { 54, "-62dBm <= RSCP < -61dBm"},
  { 55, "-61dBm <= RSCP < -60dBm"},
  { 56, "-60dBm <= RSCP < -59dBm"},
  { 57, "-59dBm <= RSCP < -58dBm"},
  { 58, "-58dBm <= RSCP < -57dBm"},
  { 59, "-57dBm <= RSCP < -56dBm"},
  { 60, "-56dBm <= RSCP < -55dBm"},
  { 61, "-55dBm <= RSCP < -54dBm"},
  { 62, "-54dBm <= RSCP < -53dBm"},
  { 63, "-53dBm <= RSCP < -52dBm"},
  { 64, "-52dBm <= RSCP < -51dBm"},
  { 65, "-51dBm <= RSCP < -50dBm"},
  { 66, "-50dBm <= RSCP < -49dBm"},
  { 67, "-49dBm <= RSCP < -48dBm"},
  { 68, "-48dBm <= RSCP < -47dBm"},
  { 69, "-47dBm <= RSCP < -46dBm"},
  { 70, "-46dBm <= RSCP < -45dBm"},
  { 71, "-45dBm <= RSCP < -44dBm"},
  { 72, "-44dBm <= RSCP < -43dBm"},
  { 73, "-43dBm <= RSCP < -42dBm"},
  { 74, "-42dBm <= RSCP < -41dBm"},
  { 75, "-41dBm <= RSCP < -40dBm"},
  { 76, "-40dBm <= RSCP < -39dBm"},
  { 77, "-39dBm <= RSCP < -38dBm"},
  { 78, "-38dBm <= RSCP < -37dBm"},
  { 79, "-37dBm <= RSCP < -36dBm"},
  { 80, "-36dBm <= RSCP < -35dBm"},
  { 81, "-35dBm <= RSCP < -34dBm"},
  { 82, "-34dBm <= RSCP < -33dBm"},
  { 83, "-33dBm <= RSCP < -32dBm"},
  { 84, "-32dBm <= RSCP < -31dBm"},
  { 85, "-31dBm <= RSCP < -30dBm"},
  { 86, "-30dBm <= RSCP < -29dBm"},
  { 87, "-29dBm <= RSCP < -28dBm"},
  { 88, "-28dBm <= RSCP < -27dBm"},
  { 89, "-27dBm <= RSCP < -26dBm"},
  { 90, "-26dBm <= RSCP < -25dBm"},
  { 91, "-25dBm <= RSCP"},
  {  0, NULL}
};
static value_string_ext lte_rrc_utra_RSCP_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_utra_RSCP_vals);

static const value_string lte_rrc_a3_a6_c2_Offset_vals[] = {
  { -30, "-15dB"},
  { -29, "-14.5dB"},
  { -28, "-14dB"},
  { -27, "-13.5dB"},
  { -26, "-13dB"},
  { -25, "-12.5dB"},
  { -24, "-12dB"},
  { -23, "-11.5dB"},
  { -22, "-11dB"},
  { -21, "-10.5dB"},
  { -20, "-10dB"},
  { -19, "-9.5dB"},
  { -18, "-9dB"},
  { -17, "-8.5dB"},
  { -16, "-8dB"},
  { -15, "-7.5dB"},
  { -14, "-7dB"},
  { -13, "-6.5dB"},
  { -12, "-6dB"},
  { -11, "-5.5dB"},
  { -10, "-5dB"},
  {  -9, "-4.5dB"},
  {  -8, "-4dB"},
  {  -7, "-3.5dB"},
  {  -6, "-3dB"},
  {  -5, "-2.5dB"},
  {  -4, "-2dB"},
  {  -3, "-1.5dB"},
  {  -2, "-1dB"},
  {  -1, "-0.5dB"},
  {   0, "0dB"},
  {   1, "0.5dB"},
  {   2, "1dB"},
  {   3, "1.5dB"},
  {   4, "2dB"},
  {   5, "2.5dB"},
  {   6, "3dB"},
  {   7, "3.5dB"},
  {   8, "4dB"},
  {   9, "4.5dB"},
  {  10, "5dB"},
  {  11, "5.5dB"},
  {  12, "6dB"},
  {  13, "6.5dB"},
  {  14, "7dB"},
  {  15, "7.5dB"},
  {  16, "8dB"},
  {  17, "8.5dB"},
  {  18, "9dB"},
  {  19, "9.5dB"},
  {  20, "10dB"},
  {  21, "10.5dB"},
  {  22, "11dB"},
  {  23, "11.5dB"},
  {  24, "12dB"},
  {  25, "12.5dB"},
  {  26, "13dB"},
  {  27, "13.5dB"},
  {  28, "14dB"},
  {  29, "14.5dB"},
  {  30, "15dB"},
  {  0, NULL}
};
static value_string_ext lte_rrc_a3_a6_c2_Offset_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_a3_a6_c2_Offset_vals);

static const value_string lte_rrc_threshold_RSRP_vals[] = {
  {  0, "-140dBm"},
  {  1, "-139dBm"},
  {  2, "-138dBm"},
  {  3, "-137dBm"},
  {  4, "-136dBm"},
  {  5, "-135dBm"},
  {  6, "-134dBm"},
  {  7, "-133dBm"},
  {  8, "-132dBm"},
  {  9, "-131dBm"},
  { 10, "-130dBm"},
  { 11, "-129dBm"},
  { 12, "-128dBm"},
  { 13, "-127dBm"},
  { 14, "-126dBm"},
  { 15, "-125dBm"},
  { 16, "-124dBm"},
  { 17, "-123dBm"},
  { 18, "-122dBm"},
  { 19, "-121dBm"},
  { 20, "-120dBm"},
  { 21, "-119dBm"},
  { 22, "-118dBm"},
  { 23, "-117dBm"},
  { 24, "-116dBm"},
  { 25, "-115dBm"},
  { 26, "-114dBm"},
  { 27, "-113dBm"},
  { 28, "-112dBm"},
  { 29, "-111dBm"},
  { 30, "-110dBm"},
  { 31, "-109dBm"},
  { 32, "-108dBm"},
  { 33, "-107dBm"},
  { 34, "-106dBm"},
  { 35, "-105dBm"},
  { 36, "-104dBm"},
  { 37, "-103dBm"},
  { 38, "-102dBm"},
  { 39, "-101dBm"},
  { 40, "-100dBm"},
  { 41, "-99dBm"},
  { 42, "-98dBm"},
  { 43, "-97dBm"},
  { 44, "-96dBm"},
  { 45, "-95dBm"},
  { 46, "-94dBm"},
  { 47, "-93dBm"},
  { 48, "-92dBm"},
  { 49, "-91dBm"},
  { 50, "-90dBm"},
  { 51, "-89dBm"},
  { 52, "-88dBm"},
  { 53, "-87dBm"},
  { 54, "-86dBm"},
  { 55, "-85dBm"},
  { 56, "-84dBm"},
  { 57, "-83dBm"},
  { 58, "-82dBm"},
  { 59, "-81dBm"},
  { 60, "-80dBm"},
  { 61, "-79dBm"},
  { 62, "-78dBm"},
  { 63, "-77dBm"},
  { 64, "-76dBm"},
  { 65, "-75dBm"},
  { 66, "-74dBm"},
  { 67, "-73dBm"},
  { 68, "-72dBm"},
  { 69, "-71dBm"},
  { 70, "-70dBm"},
  { 71, "-69dBm"},
  { 72, "-68dBm"},
  { 73, "-67dBm"},
  { 74, "-66dBm"},
  { 75, "-65dBm"},
  { 76, "-64dBm"},
  { 77, "-63dBm"},
  { 78, "-62dBm"},
  { 79, "-61dBm"},
  { 80, "-60dBm"},
  { 81, "-59dBm"},
  { 82, "-58dBm"},
  { 83, "-57dBm"},
  { 84, "-56dBm"},
  { 85, "-55dBm"},
  { 86, "-54dBm"},
  { 87, "-53dBm"},
  { 88, "-52dBm"},
  { 89, "-51dBm"},
  { 90, "-50dBm"},
  { 91, "-49dBm"},
  { 92, "-48dBm"},
  { 93, "-47dBm"},
  { 94, "-46dBm"},
  { 95, "-45dBm"},
  { 96, "-44dBm"},
  { 97, "-43dBm"},
  {  0, NULL}
};
static value_string_ext lte_rrc_threshold_RSRP_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_threshold_RSRP_vals);

static const value_string lte_rrc_threshold_RSRQ_vals[] = {
  {  0, "-20dB"},
  {  1, "-19.5dB"},
  {  2, "-19dB"},
  {  3, "-18.5dB"},
  {  4, "-18dB"},
  {  5, "-17.5dB"},
  {  6, "-17dB"},
  {  7, "-16.5dB"},
  {  8, "-16dB"},
  {  9, "-15.5dB"},
  { 10, "-15dB"},
  { 11, "-14.5dB"},
  { 12, "-14dB"},
  { 13, "-13.5dB"},
  { 14, "-13dB"},
  { 15, "-12.5dB"},
  { 16, "-12dB"},
  { 17, "-11.5dB"},
  { 18, "-11dB"},
  { 19, "-10.5dB"},
  { 20, "-10dB"},
  { 21, "-9.5dB"},
  { 22, "-9dB"},
  { 23, "-8.5dB"},
  { 24, "-8dB"},
  { 25, "-7.5dB"},
  { 26, "-7dB"},
  { 27, "-6.5dB"},
  { 28, "-6dB"},
  { 29, "-5.5dB"},
  { 30, "-5dB"},
  { 31, "-4.5dB"},
  { 32, "-4dB"},
  { 33, "-3.5dB"},
  { 34, "-3dB"},
  {  0, NULL}
};
static value_string_ext lte_rrc_threshold_RSRQ_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_threshold_RSRQ_vals);

static const value_string lte_rrc_thresholdGERAN_vals[] = {
  { 0 , "-110dBm"},
  { 1 , "-109dBm"},
  { 2 , "-108dBm"},
  { 3 , "-107dBm"},
  { 4 , "-106dBm"},
  { 5 , "-105dBm"},
  { 6 , "-104dBm"},
  { 7 , "-103dBm"},
  { 8 , "-102dBm"},
  { 9 , "-101dBm"},
  { 10, "-100dBm"},
  { 11, "-99dBm"},
  { 12, "-98dBm"},
  { 13, "-97dBm"},
  { 14, "-96dBm"},
  { 15, "-95dBm"},
  { 16, "-94dBm"},
  { 17, "-93dBm"},
  { 18, "-92dBm"},
  { 19, "-91dBm"},
  { 20, "-90dBm"},
  { 21, "-89dBm"},
  { 22, "-88dBm"},
  { 23, "-87dBm"},
  { 24, "-86dBm"},
  { 25, "-85dBm"},
  { 26, "-84dBm"},
  { 27, "-83dBm"},
  { 28, "-82dBm"},
  { 29, "-81dBm"},
  { 30, "-80dBm"},
  { 31, "-79dBm"},
  { 32, "-78dBm"},
  { 33, "-77dBm"},
  { 34, "-76dBm"},
  { 35, "-75dBm"},
  { 36, "-74dBm"},
  { 37, "-73dBm"},
  { 38, "-72dBm"},
  { 39, "-71dBm"},
  { 40, "-70dBm"},
  { 41, "-69dBm"},
  { 42, "-68dBm"},
  { 43, "-67dBm"},
  { 44, "-66dBm"},
  { 45, "-65dBm"},
  { 46, "-64dBm"},
  { 47, "-63dBm"},
  { 48, "-62dBm"},
  { 49, "-61dBm"},
  { 50, "-60dBm"},
  { 51, "-59dBm"},
  { 52, "-58dBm"},
  { 53, "-57dBm"},
  { 54, "-56dBm"},
  { 55, "-55dBm"},
  { 56, "-54dBm"},
  { 57, "-53dBm"},
  { 58, "-52dBm"},
  { 59, "-51dBm"},
  { 60, "-50dBm"},
  { 61, "-49dBm"},
  { 62, "-48dBm"},
  { 63, "-47dBm"},
  {  0, NULL}
};
static value_string_ext lte_rrc_thresholdGERAN_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_thresholdGERAN_vals);

static const value_string lte_rrc_thresholdUTRA_EcN0_vals[] = {
  { 0 , "-24.5dB"},
  { 1 , "-24dB"},
  { 2 , "-23.5dB"},
  { 3 , "-23dB"},
  { 4 , "-22.5dB"},
  { 5 , "-22dB"},
  { 6 , "-21.5dB"},
  { 7 , "-21dB"},
  { 8 , "-20.5dB"},
  { 9 , "-20dB"},
  { 10, "-19.5dB"},
  { 11, "-19dB"},
  { 12, "-18.5dB"},
  { 13, "-18dB"},
  { 14, "-17.5dB"},
  { 15, "-17dB"},
  { 16, "-16.5dB"},
  { 17, "-16dB"},
  { 18, "-15.5dB"},
  { 19, "-15dB"},
  { 20, "-14.5dB"},
  { 21, "-14dB"},
  { 22, "-13.5dB"},
  { 23, "-13dB"},
  { 24, "-12.5dB"},
  { 25, "-12dB"},
  { 26, "-11.5dB"},
  { 27, "-11dB"},
  { 28, "-10.5dB"},
  { 29, "-10dB"},
  { 30, "-9.5dB"},
  { 31, "-9dB"},
  { 32, "-8.5dB"},
  { 33, "-8dB"},
  { 34, "-7.5dB"},
  { 35, "-7dB"},
  { 36, "-6.5dB"},
  { 37, "-6dB"},
  { 38, "-5.5dB"},
  { 39, "-5dB"},
  { 40, "-4.5dB"},
  { 41, "-4dB"},
  { 42, "-3.5dB"},
  { 43, "-3dB"},
  { 44, "-2.5dB"},
  { 45, "-2dB"},
  { 46, "-1.5dB"},
  { 47, "-1dB"},
  { 48, "-0.5dB"},
  { 49, "0dB"},
  {  0, NULL}
};
static value_string_ext lte_rrc_thresholdUTRA_EcN0_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_thresholdUTRA_EcN0_vals);

static const value_string lte_rrc_thresholdUTRA_RSCP_vals[] = {
  { -5, "-120dBm"},
  { -4, "-119dBm"},
  { -3, "-118dBm"},
  { -2, "-117dBm"},
  { -1, "-116dBm"},
  {  0, "-115dBm"},
  {  1, "-114dBm"},
  {  2, "-113dBm"},
  {  3, "-112dBm"},
  {  4, "-111dBm"},
  {  5, "-110dBm"},
  {  6, "-109dBm"},
  {  7, "-108dBm"},
  {  8, "-107dBm"},
  {  9, "-106dBm"},
  { 10, "-105dBm"},
  { 11, "-104dBm"},
  { 12, "-103dBm"},
  { 13, "-102dBm"},
  { 14, "-101dBm"},
  { 15, "-100dBm"},
  { 16, "-99dBm"},
  { 17, "-98dBm"},
  { 18, "-97dBm"},
  { 19, "-96dBm"},
  { 20, "-95dBm"},
  { 21, "-94dBm"},
  { 22, "-93dBm"},
  { 23, "-92dBm"},
  { 24, "-91dBm"},
  { 25, "-90dBm"},
  { 26, "-89dBm"},
  { 27, "-88dBm"},
  { 28, "-87dBm"},
  { 29, "-86dBm"},
  { 30, "-85dBm"},
  { 31, "-84dBm"},
  { 32, "-83dBm"},
  { 33, "-82dBm"},
  { 34, "-81dBm"},
  { 35, "-80dBm"},
  { 36, "-79dBm"},
  { 37, "-78dBm"},
  { 38, "-77dBm"},
  { 39, "-76dBm"},
  { 40, "-75dBm"},
  { 41, "-74dBm"},
  { 42, "-73dBm"},
  { 43, "-72dBm"},
  { 44, "-71dBm"},
  { 45, "-70dBm"},
  { 46, "-69dBm"},
  { 47, "-68dBm"},
  { 48, "-67dBm"},
  { 49, "-66dBm"},
  { 50, "-65dBm"},
  { 51, "-64dBm"},
  { 52, "-63dBm"},
  { 53, "-62dBm"},
  { 54, "-61dBm"},
  { 55, "-60dBm"},
  { 56, "-59dBm"},
  { 57, "-58dBm"},
  { 58, "-57dBm"},
  { 59, "-56dBm"},
  { 60, "-55dBm"},
  { 61, "-54dBm"},
  { 62, "-53dBm"},
  { 63, "-52dBm"},
  { 64, "-51dBm"},
  { 65, "-50dBm"},
  { 66, "-49dBm"},
  { 67, "-48dBm"},
  { 68, "-47dBm"},
  { 69, "-46dBm"},
  { 70, "-45dBm"},
  { 71, "-44dBm"},
  { 72, "-43dBm"},
  { 73, "-42dBm"},
  { 74, "-41dBm"},
  { 75, "-40dBm"},
  { 76, "-39dBm"},
  { 77, "-38dBm"},
  { 78, "-37dBm"},
  { 79, "-36dBm"},
  { 80, "-35dBm"},
  { 81, "-34dBm"},
  { 82, "-33dBm"},
  { 83, "-32dBm"},
  { 84, "-31dBm"},
  { 85, "-30dBm"},
  { 86, "-29dBm"},
  { 87, "-28dBm"},
  { 88, "-27dBm"},
  { 89, "-26dBm"},
  { 90, "-25dBm"},
  { 91, "-24dBm"},
  {  0, NULL}
};
static value_string_ext lte_rrc_thresholdUTRA_RSCP_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_thresholdUTRA_RSCP_vals);

static const value_string lte_rrc_RSRP_Range_vals[] = {
  {  0, "RSRP < -140dBm"},
  {  1, "-140dBm <= RSRP < -139dBm"},
  {  2, "-139dBm <= RSRP < -138dBm"},
  {  3, "-138dBm <= RSRP < -137dBm"},
  {  4, "-137dBm <= RSRP < -136dBm"},
  {  5, "-136dBm <= RSRP < -135dBm"},
  {  6, "-135dBm <= RSRP < -134dBm"},
  {  7, "-134dBm <= RSRP < -133dBm"},
  {  8, "-133dBm <= RSRP < -132dBm"},
  {  9, "-132dBm <= RSRP < -131dBm"},
  { 10, "-131dBm <= RSRP < -130dBm"},
  { 11, "-130dBm <= RSRP < -129dBm"},
  { 12, "-129dBm <= RSRP < -128dBm"},
  { 13, "-128dBm <= RSRP < -127dBm"},
  { 14, "-127dBm <= RSRP < -126dBm"},
  { 15, "-126dBm <= RSRP < -125dBm"},
  { 16, "-125dBm <= RSRP < -124dBm"},
  { 17, "-124dBm <= RSRP < -123dBm"},
  { 18, "-123dBm <= RSRP < -122dBm"},
  { 19, "-122dBm <= RSRP < -121dBm"},
  { 20, "-121dBm <= RSRP < -120dBm"},
  { 21, "-120dBm <= RSRP < -119dBm"},
  { 22, "-119dBm <= RSRP < -118dBm"},
  { 23, "-118dBm <= RSRP < -117dBm"},
  { 24, "-117dBm <= RSRP < -116dBm"},
  { 25, "-116dBm <= RSRP < -115dBm"},
  { 26, "-115dBm <= RSRP < -114dBm"},
  { 27, "-114dBm <= RSRP < -113dBm"},
  { 28, "-113dBm <= RSRP < -112dBm"},
  { 29, "-112dBm <= RSRP < -111dBm"},
  { 30, "-111dBm <= RSRP < -110dBm"},
  { 31, "-110dBm <= RSRP < -109dBm"},
  { 32, "-109dBm <= RSRP < -108dBm"},
  { 33, "-108dBm <= RSRP < -107dBm"},
  { 34, "-107dBm <= RSRP < -106dBm"},
  { 35, "-106dBm <= RSRP < -105dBm"},
  { 36, "-105dBm <= RSRP < -104dBm"},
  { 37, "-104dBm <= RSRP < -103dBm"},
  { 38, "-103dBm <= RSRP < -102dBm"},
  { 39, "-102dBm <= RSRP < -101dBm"},
  { 40, "-101dBm <= RSRP < -100dBm"},
  { 41, "-100dBm <= RSRP < -99dBm"},
  { 42, "-99dBm <= RSRP < -98dBm"},
  { 43, "-98dBm <= RSRP < -97dBm"},
  { 44, "-97dBm <= RSRP < -96dBm"},
  { 45, "-96dBm <= RSRP < -95dBm"},
  { 46, "-95dBm <= RSRP < -94dBm"},
  { 47, "-94dBm <= RSRP < -93dBm"},
  { 48, "-93dBm <= RSRP < -92dBm"},
  { 49, "-92dBm <= RSRP < -91dBm"},
  { 50, "-91dBm <= RSRP < -90dBm"},
  { 51, "-90dBm <= RSRP < -89dBm"},
  { 52, "-89dBm <= RSRP < -88dBm"},
  { 53, "-88dBm <= RSRP < -87dBm"},
  { 54, "-87dBm <= RSRP < -86dBm"},
  { 55, "-86dBm <= RSRP < -85dBm"},
  { 56, "-85dBm <= RSRP < -84dBm"},
  { 57, "-84dBm <= RSRP < -83dBm"},
  { 58, "-83dBm <= RSRP < -82dBm"},
  { 59, "-82dBm <= RSRP < -81dBm"},
  { 60, "-81dBm <= RSRP < -80dBm"},
  { 61, "-80dBm <= RSRP < -79dBm"},
  { 62, "-79dBm <= RSRP < -78dBm"},
  { 63, "-78dBm <= RSRP < -77dBm"},
  { 64, "-77dBm <= RSRP < -76dBm"},
  { 65, "-76dBm <= RSRP < -75dBm"},
  { 66, "-75dBm <= RSRP < -74dBm"},
  { 67, "-74dBm <= RSRP < -73dBm"},
  { 68, "-73dBm <= RSRP < -72dBm"},
  { 69, "-72dBm <= RSRP < -71dBm"},
  { 70, "-71dBm <= RSRP < -70dBm"},
  { 71, "-70dBm <= RSRP < -69dBm"},
  { 72, "-69dBm <= RSRP < -68dBm"},
  { 73, "-68dBm <= RSRP < -67dBm"},
  { 74, "-67dBm <= RSRP < -66dBm"},
  { 75, "-66dBm <= RSRP < -65dBm"},
  { 76, "-65dBm <= RSRP < -64dBm"},
  { 77, "-64dBm <= RSRP < -63dBm"},
  { 78, "-63dBm <= RSRP < -62dBm"},
  { 79, "-62dBm <= RSRP < -61dBm"},
  { 80, "-61dBm <= RSRP < -60dBm"},
  { 81, "-60dBm <= RSRP < -59dBm"},
  { 82, "-59dBm <= RSRP < -58dBm"},
  { 83, "-58dBm <= RSRP < -57dBm"},
  { 84, "-57dBm <= RSRP < -56dBm"},
  { 85, "-56dBm <= RSRP < -55dBm"},
  { 86, "-55dBm <= RSRP < -54dBm"},
  { 87, "-54dBm <= RSRP < -53dBm"},
  { 88, "-53dBm <= RSRP < -52dBm"},
  { 89, "-52dBm <= RSRP < -51dBm"},
  { 90, "-51dBm <= RSRP < -50dBm"},
  { 91, "-50dBm <= RSRP < -49dBm"},
  { 92, "-49dBm <= RSRP < -48dBm"},
  { 93, "-48dBm <= RSRP < -47dBm"},
  { 94, "-47dBm <= RSRP < -46dBm"},
  { 95, "-46dBm <= RSRP < -45dBm"},
  { 96, "-45dBm <= RSRP < -44dBm"},
  { 97, "-44dBm <= RSRP"},
  {  0, NULL}
};
static value_string_ext lte_rrc_RSRP_Range_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_RSRP_Range_vals);

static const value_string lte_rrc_RSRP_Range_v1360_vals[] = {
  { -17, "RSRP < -156dBm"},
  { -16, "-156dBm <= RSRP < -155dBm"},
  { -15, "-155dBm <= RSRP < -154dBm"},
  { -14, "-154dBm <= RSRP < -153dBm"},
  { -13, "-153dBm <= RSRP < -152dBm"},
  { -12, "-152dBm <= RSRP < -151dBm"},
  { -11, "-151dBm <= RSRP < -150dBm"},
  { -10, "-150dBm <= RSRP < -149dBm"},
  {  -9, "-149dBm <= RSRP < -148dBm"},
  {  -8, "-148dBm <= RSRP < -147dBm"},
  {  -7, "-147dBm <= RSRP < -146dBm"},
  {  -6, "-146dBm <= RSRP < -145dBm"},
  {  -5, "-145dBm <= RSRP < -144dBm"},
  {  -4, "-144dBm <= RSRP < -143dBm"},
  {  -3, "-143dBm <= RSRP < -142dBm"},
  {  -2, "-142dBm <= RSRP < -141dBm"},
  {  -1, "-141dBm <= RSRP < -140dBm"},
  {  0, NULL}
};
static value_string_ext lte_rrc_RSRP_Range_v1360_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_RSRP_Range_v1360_vals);

static const value_string lte_rrc_RSRP_RangeSL_vals[] = {
  {  0, "-infinity"},
  {  1, "-115dBm"},
  {  2, "-110dBm"},
  {  3, "-105dBm"},
  {  4, "-100dBm"},
  {  5, "-95dBm"},
  {  6, "-90dBm"},
  {  7, "-85dBm"},
  {  8, "-80dBm"},
  {  9, "-75dBm"},
  { 10, "-70dBm"},
  { 11, "-65dBm"},
  { 12, "-60dBm"},
  { 13, "+infinity"},
  {  0, NULL}
};

static const value_string lte_rrc_RSRP_RangeSL2_vals[] = {
  {  0, "-infinity"},
  {  1, "-110dBm"},
  {  2, "-100dBm"},
  {  3, "-90dBm"},
  {  4, "-80dBm"},
  {  5, "-70dBm"},
  {  6, "-60dBm"},
  {  7, "+infinity"},
  {  0, NULL}
};

#if 0
static const value_string lte_rrc_RSRP_RangeSL3_vals[] = {
  {  0, "-110dBm"},
  {  1, "-105dBm"},
  {  2, "-100dBm"},
  {  3, "-95dBm"},
  {  4, "-90dBm"},
  {  5, "-85dBm"},
  {  6, "-80dBm"},
  {  7, "-75dBm"},
  {  8, "-70dBm"},
  {  9, "-65dBm"},
  { 10, "-60dBm"},
  { 11, "+infinity"},
  {  0, NULL}
};
#endif

static const value_string lte_rrc_RSRP_RangeSL4_vals[] = {
  {  0, "-130dBm"},
  {  1, "-128dBm"},
  {  2, "-126dBm"},
  {  3, "-124dBm"},
  {  4, "-122dBm"},
  {  5, "-120dBm"},
  {  6, "-118dBm"},
  {  7, "-116dBm"},
  {  8, "-114dBm"},
  {  9, "-112dBm"},
  { 10, "-110dBm"},
  { 11, "-108dBm"},
  { 12, "-106dBm"},
  { 13, "-104dBm"},
  { 14, "-102dBm"},
  { 15, "-100dBm"},
  { 16, "-98dBm"},
  { 17, "-96dBm"},
  { 18, "-94dBm"},
  { 19, "-92dBm"},
  { 20, "-90dBm"},
  { 21, "-88dBm"},
  { 22, "-86dBm"},
  { 23, "-84dBm"},
  { 24, "-82dBm"},
  { 25, "-80dBm"},
  { 26, "-78dBm"},
  { 27, "-76dBm"},
  { 28, "-74dBm"},
  { 29, "-72dBm"},
  { 30, "-70dBm"},
  { 31, "-68dBm"},
  { 32, "-66dBm"},
  { 33, "-64dBm"},
  { 34, "-62dBm"},
  { 35, "-60dBm"},
  { 36, "-58dBm"},
  { 37, "-56dBm"},
  { 38, "-54dBm"},
  { 39, "-52dBm"},
  { 40, "-50dBm"},
  { 41, "-48dBm"},
  { 42, "-46dBm"},
  { 43, "-44dBm"},
  { 44, "-42dBm"},
  { 45, "-40dBm"},
  { 46, "-38dBm"},
  { 47, "-36dBm"},
  { 48, "-34dBm"},
  { 49, "+infinity"},
  {  0, NULL}
};
static value_string_ext lte_rrc_RSRP_RangeSL4_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_RSRP_RangeSL4_vals);

static void
lte_rrc_RSRP_RangeNR_r15_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SS-RSRP < -156dBm (0)");
  } else if (v == 126) {
    snprintf(s, ITEM_LABEL_LENGTH, "-31dBm <= SS-RSRP (126)");
  } else if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "Infinity (127)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= SS-RSRP < %ddBm (%u)", -157+v, -156+v, v);
  }
}

static const value_string lte_rrc_RSRQ_Range_vals[] = {
  {-34, "RSRQ < -36dB"},
  {-33, "-36dB <= RSRQ < -35.5dB"},
  {-32, "-35.5dB <= RSRQ < -35dB"},
  {-31, "-35dB <= RSRQ < -34.5dB"},
  {-30, "-34.5dB <= RSRQ < -34dB"},
  {-29, "-34dB <= RSRQ < -33.5dB"},
  {-28, "-33.5dB <= RSRQ < -33dB"},
  {-27, "-33dB <= RSRQ < -32.5dB"},
  {-26, "-32.5dB <= RSRQ < -32dB"},
  {-25, "-32dB <= RSRQ < -31.5dB"},
  {-24, "-31.5dB <= RSRQ < -31dB"},
  {-23, "-31dB <= RSRQ < -30.5dB"},
  {-22, "-30.5dB <= RSRQ < -30dB"},
  {-21, "-30dB <= RSRQ < -29.5dB"},
  {-20, "-29.5dB <= RSRQ < -29dB"},
  {-19, "-29dB <= RSRQ < -28.5dB"},
  {-18, "-28.5dB <= RSRQ < -28dB"},
  {-17, "-28dB <= RSRQ < -27.5dB"},
  {-16, "-27.5dB <= RSRQ < -27dB"},
  {-15, "-27dB <= RSRQ < -26.5dB"},
  {-14, "-26.5dB <= RSRQ < -26dB"},
  {-13, "-26dB <= RSRQ < -25.5dB"},
  {-12, "-25.5dB <= RSRQ < -25dB"},
  {-11, "-25dB <= RSRQ < -24.5dB"},
  {-10, "-24.5dB <= RSRQ < -24dB"},
  { -9, "-24dB <= RSRQ < -23.5dB"},
  { -8, "-23.5dB <= RSRQ < -23dB"},
  { -7, "-23dB <= RSRQ < -22.5dB"},
  { -6, "-22.5dB <= RSRQ < -22dB"},
  { -5, "-22dB <= RSRQ < -21.5dB"},
  { -4, "-21.5dB <= RSRQ < -21dB"},
  { -3, "-21dB <= RSRQ < -20.5dB"},
  { -2, "-20.5dB <= RSRQ < -20dB"},
  { -1, "-20dB <= RSRQ < -19.5dB"},
  {  0, "RSRQ < -19.5dB"},
  {  1, "-19.5dB <= RSRQ < -19dB"},
  {  2, "-19dB <= RSRQ < -18.5dB"},
  {  3, "-18.5dB <= RSRQ < -18dB"},
  {  4, "-18dB <= RSRQ < -17.5dB"},
  {  5, "-17.5dB <= RSRQ < -17dB"},
  {  6, "-17dB <= RSRQ < -16.5dB"},
  {  7, "-16.5dB <= RSRQ < -16dB"},
  {  8, "-16dB <= RSRQ < -15.5dB"},
  {  9, "-15.5dB <= RSRQ < -15dB"},
  { 10, "-15dB <= RSRQ < -14.5dB"},
  { 11, "-14.5dB <= RSRQ < -14dB"},
  { 12, "-14dB <= RSRQ < -13.5dB"},
  { 13, "-13.5dB <= RSRQ < -13dB"},
  { 14, "-13dB <= RSRQ < -12.5dB"},
  { 15, "-12.5dB <= RSRQ < -12dB"},
  { 16, "-12dB <= RSRQ < -11.5dB"},
  { 17, "-11.5dB <= RSRQ < -11dB"},
  { 18, "-11dB <= RSRQ < -10.5dB"},
  { 19, "-10.5dB <= RSRQ < -10dB"},
  { 20, "-10dB <= RSRQ < -9.5dB"},
  { 21, "-9.5dB <= RSRQ < -9dB"},
  { 22, "-9dB <= RSRQ < -8.5dB"},
  { 23, "-8.5dB <= RSRQ < -8dB"},
  { 24, "-8dB <= RSRQ < -7.5dB"},
  { 25, "-7.5dB <= RSRQ < -7dB"},
  { 26, "-7dB <= RSRQ < -6.5dB"},
  { 27, "-6.5dB <= RSRQ < -6dB"},
  { 28, "-6dB <= RSRQ < -5.5dB"},
  { 29, "-5.5dB <= RSRQ < -5dB"},
  { 30, "-5dB <= RSRQ < -4.5dB"},
  { 31, "-4.5dB <= RSRQ < -4dB"},
  { 32, "-4dB <= RSRQ < -3.5dB"},
  { 33, "-3.5dB <= RSRQ < -3dB"},
  { 34, "-3dB <= RSRQ"},
  { 35, "-3dB <= RSRQ < -2.5dB"},
  { 36, "-2.5dB <= RSRQ < -2dB"},
  { 37, "-2dB <= RSRQ < -1.5dB"},
  { 38, "-1.5dB <= RSRQ < -1dB"},
  { 39, "-1dB <= RSRQ < -0.5dB"},
  { 40, "-0.5dB <= RSRQ < 0dB"},
  { 41, "0dB <= RSRQ < 0.5dB"},
  { 42, "0.5dB <= RSRQ < 1dB"},
  { 43, "1dB <= RSRQ < 1.5dB"},
  { 44, "1.5dB <= RSRQ < 2dB"},
  { 45, "2dB <= RSRQ < 2.5dB"},
  { 46, "2.5dB <= RSRQ"},
  {  0, NULL}
};
static value_string_ext lte_rrc_RSRQ_Range_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_RSRQ_Range_vals);

static void
lte_rrc_RSRQ_RangeNR_r15_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SS-RSRQ < -43dB (0)");
  } else if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "20dB < SS-RSRQ (127)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= SS-RSRQ < %.1fdB (%u)", (((float)v-1)/2)-43, ((float)v/2)-43, v);
  }
}

static const value_string lte_rrc_MBSFN_RSRQ_Range_vals[] = {
  {  0, "RSRQ < -23dB"},
  {  1, "-23dB <= RSRQ < -22.5dB"},
  {  2, "-22.5dB <= RSRQ < -22dB"},
  {  3, "-22dB <= RSRQ < -21.5dB"},
  {  4, "-21.5dB <= RSRQ < -21dB"},
  {  5, "-21dB <= RSRQ < -20.5dB"},
  {  6, "-20.5dB <= RSRQ < -20dB"},
  {  7, "-20dB <= RSRQ < -19.5dB"},
  {  8, "-19.5dB <= RSRQ < -19dB"},
  {  9, "-19dB <= RSRQ < -18.5dB"},
  { 10, "-18.5dB <= RSRQ < -18dB"},
  { 11, "-18dB <= RSRQ < -17.5dB"},
  { 12, "-17.5dB <= RSRQ < -17dB"},
  { 13, "-17dB <= RSRQ < -16.5dB"},
  { 14, "-16.5dB <= RSRQ < -16dB"},
  { 15, "-16dB <= RSRQ < -15.5dB"},
  { 16, "-15.5dB <= RSRQ < -15dB"},
  { 17, "-15dB <= RSRQ < -14.5dB"},
  { 18, "-14.5dB <= RSRQ < -14dB"},
  { 19, "-14dB <= RSRQ < -13.5dB"},
  { 20, "-13.5dB <= RSRQ < -13dB"},
  { 21, "-13dB <= RSRQ < -12.5dB"},
  { 22, "-12.5dB <= RSRQ < -12dB"},
  { 23, "-12dB <= RSRQ < -11.5dB"},
  { 24, "-11.5dB <= RSRQ < -11dB"},
  { 25, "-11dB <= RSRQ < -10.5dB"},
  { 26, "-10.5dB <= RSRQ < -10dB"},
  { 27, "-10dB <= RSRQ < -9.5dB"},
  { 28, "-9.5dB <= RSRQ < -9dB"},
  { 29, "-9dB <= RSRQ < -8.5dB"},
  { 30, "-8.5dB <= RSRQ < -8dB"},
  { 31, "-8dB <= RSRQ"},
  {  0, NULL}
};
static value_string_ext lte_rrc_MBSFN_RSRQ_Range_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_MBSFN_RSRQ_Range_vals);

static void
lte_rrc_availableAdmissionCapacityWLAN_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%uus/s (%u)", 32*v, v);
}

static void
lte_rrc_ue_RxTxTimeDiffResult_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "T < 2Ts (0)");
  } else if (v < 2048) {
    snprintf(s, ITEM_LABEL_LENGTH, "%uTs <= T < %uTs (%u)", v*2, (v+1)*2, v);
  } else if (v < 4095) {
    snprintf(s, ITEM_LABEL_LENGTH, "%uTs <= T < %uTs (%u)", (v*8)-12288, ((v+1)*8)-12288, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "20472Ts <= T (4095)");
  }
}

static const true_false_string lte_rrc_duration_val = {
  "indefinite",
  "single"
};

static const value_string lte_rrc_eab_category_vals[] = {
  { 0, "a - all UEs" },
  { 1, "b - UEs not in their HPLMN/EHPLMN" },
  { 2, "c - UEs not in the most preferred PLMN of the country where they are roaming in EF OPLMNwACT list, nor in their HPLMN/EHPLMN" },
  { 0, NULL }
};

static const value_string lte_rrc_daylightSavingTime_vals[] = {
  { 0, "No adjustment for Daylight Saving Time"},
  { 1, "+1 hour adjustment for Daylight Saving Time"},
  { 2, "+2 hours adjustment for Daylight Saving Time"},
  { 3, "Reserved"},
  { 0, NULL},
};

static const value_string lte_rrc_neighCellConfig_vals[] = {
  { 0, "Not all neighbour cells have the same MBSFN subframe allocation as serving cell"},
  { 1, "No MBSFN subframes are present in all neighbour cells"},
  { 2, "The MBSFN subframe allocations of all neighbour cells are identical to or subsets of that in the serving cell"},
  { 3, "Different UL/DL allocation in neighbouring cells for TDD compared to the serving cell"},
  { 0, NULL},
};

static const value_string lte_rrc_messageIdentifier_vals[] = {
  { 0x03e8, "LCS CBS Message Identifier for E-OTD Assistance Data message"},
  { 0x03e9, "LCS CBS Message Identifier for DGPS Correction Data message"},
  { 0x03ea, "LCS CBS Message Identifier for GPS Ephemeris and Clock Correction Data message"},
  { 0x03eb, "LCS CBS Message Identifier for GPS Almanac and Other Data message"},
  { 0x1100, "ETWS Identifier for earthquake warning message"},
  { 0x1101, "ETWS Identifier for tsunami warning message"},
  { 0x1102, "ETWS Identifier for earthquake and tsunami combined warning message"},
  { 0x1103, "ETWS Identifier for test message"},
  { 0x1104, "ETWS Identifier for messages related to other emergency types"},
  { 0x1105, "ETWS Identifier for future extension"},
  { 0x1106, "ETWS Identifier for future extension"},
  { 0x1107, "ETWS Identifier for future extension"},
  { 0x1112, "CMAS Identifier for CMAS Presidential Level Alerts"},
  { 0x1113, "CMAS Identifier for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Observed"},
  { 0x1114, "CMAS Identifier for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Likely"},
  { 0x1115, "CMAS Identifier for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Observed"},
  { 0x1116, "CMAS Identifier for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Likely"},
  { 0x1117, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Observed"},
  { 0x1118, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Likely"},
  { 0x1119, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Observed"},
  { 0x111a, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Likely"},
  { 0x111b, "CMAS Identifier for Child Abduction Emergency (or Amber Alert)"},
  { 0x111c, "CMAS Identifier for the Required Monthly Test"},
  { 0x111d, "CMAS Identifier for CMAS Exercise"},
  { 0x111e, "CMAS Identifier for operator defined use"},
  { 0x111f, "CMAS Identifier for CMAS Presidential Level Alerts for additional languages"},
  { 0x1120, "CMAS Identifier for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Observed for additional languages"},
  { 0x1121, "CMAS Identifier for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Likely for additional languages"},
  { 0x1122, "CMAS Identifier for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Observed for additional languages"},
  { 0x1123, "CMAS Identifier for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Likely for additional languages"},
  { 0x1124, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Observed for additional languages"},
  { 0x1125, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Likely for additional languages"},
  { 0x1126, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Observed for additional languages"},
  { 0x1127, "CMAS Identifier for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Likely for additional languages"},
  { 0x1128, "CMAS Identifier for Child Abduction Emergency (or Amber Alert) for additional languages"},
  { 0x1129, "CMAS Identifier for the Required Monthly Test for additional languages"},
  { 0x112a, "CMAS Identifier for CMAS Exercise for additional languages"},
  { 0x112b, "CMAS Identifier for operator defined use for additional languages"},
  { 0x112c, "CMAS CBS Message Identifier for CMAS Public Safety Alerts"},
  { 0x112d, "CMAS CBS Message Identifier for CMAS Public Safety Alerts for additional languages"},
  { 0x112e, "CMAS CBS Message Identifier for CMAS State/Local WEA Test"},
  { 0x112f, "CMAS CBS Message Identifier for CMAS State/Local WEA Test for additional languages"},
  { 0x1130, "CMAS CBS Message Identifier for geo-fencing trigger messages"},
  { 0x1131, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality"},
  { 0x1132, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when an earthquake occurs"},
  { 0x1133, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a volcanic eruption occurs"},
  { 0x1134, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is water (e.g. flood, typhoon, hurricane or tsunami) occurs"},
  { 0x1135, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is fire (e.g. forest fire or building fire) occurs"},
  { 0x1136, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is pressure (e.g. landslide or avalanche) occurs"},
  { 0x1137, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is wind (e.g. tornado or gale) occurs"},
  { 0x1138, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is dust (e.g. yellow dust or sandstorm) occurs"},
  { 0x1139, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is chemical hazard (e.g. radiation leak or toxic substance leak) occurs"},
  { 0x113a, "Non-ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when an epidemic occurs"},
  { 0x113b, "Non-ETWS CBS Message Identifier for test message dedicated to UEs with no user interface and with ePWS functionality"},
  { 0x113c, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality"},
  { 0x113d, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when an earthquake occurs"},
  { 0x113e, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a volcanic eruption occurs"},
  { 0x113f, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is water (e.g. flood, typhoon, hurricane or tsunami) occurs"},
  { 0x1140, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is fire (e.g. forest fire or building fire) occurs"},
  { 0x1141, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is pressure (e.g. landslide or avalanche) occurs"},
  { 0x1142, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is wind (e.g. tornado or gale) occurs"},
  { 0x1143, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is dust (e.g. yellow dust or sandstorm) occurs"},
  { 0x1144, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when a disaster whose characteristic is chemical hazard (e.g. radiation leak or toxic substance leak) occurs"},
  { 0x1145, "ETWS CBS Message Identifier for warning message dedicated to UEs with no user interface and with ePWS functionality when an epidemic occurs"},
  { 0x1146, "ETWS CBS Message Identifier for test message dedicated to UEs with no user interface and with ePWS functionality"},
  { 0x1900, "EU-Info Message Identifier for the local language"},
  {      0, NULL},
};
value_string_ext lte_rrc_messageIdentifier_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_messageIdentifier_vals);

static const value_string lte_rrc_serialNumber_gs_vals[] = {
  { 0, "Display mode immediate, cell wide"},
  { 1, "Display mode normal, PLMN wide"},
  { 2, "Display mode normal, tracking area wide"},
  { 3, "Display mode normal, cell wide"},
  { 0, NULL},
};

static const value_string lte_rrc_warningType_vals[] = {
  { 0, "Earthquake"},
  { 1, "Tsunami"},
  { 2, "Earthquake and Tsunami"},
  { 3, "Test"},
  { 4, "Other"},
  { 0, NULL},
};

static const true_false_string lte_rrc_interBandTDD_CA_WithDifferentConfig_bit1_val = {
  "SCell DL subframes are a subset or superset of PCell by SIB1 configuration - Supported",
  "SCell DL subframes are a subset or superset of PCell by SIB1 configuration - Not supported",
};

static const true_false_string lte_rrc_interBandTDD_CA_WithDifferentConfig_bit2_val = {
  "SCell DL subframes are neither superset nor subset of PCell by SIB1 configuration - Supported",
  "SCell DL subframes are neither superset nor subset of PCell by SIB1 configuration - Not supported",
};

static const true_false_string lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit1_val = {
  "TDD PCell - Supported",
  "TDD PCell - Not supported"
};

static const true_false_string lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit2_val = {
  "FDD PCell - Supported",
  "FDD PCell - Not supported"
};

static const true_false_string hf_lte_rrc_aperiodicCSI_Reporting_r13_bit1_val = {
  "Aperiodic CSI reporting with 3 bits of the CSI request field size - Supported",
  "Aperiodic CSI reporting with 3 bits of the CSI request field size - Not supported"
};

static const true_false_string hf_lte_rrc_aperiodicCSI_Reporting_r13_bit2_val = {
  "Aperiodic CSI reporting mode 1-0 and mode 1-1 - Supported",
  "Aperiodic CSI reporting mode 1-0 and mode 1-1 - Not supported"
};

static const true_false_string hf_lte_rrc_codebook_HARQ_ACK_r13_bit1_val = {
  "DAI-based codebook size determination - Supported",
  "DAI-based codebook size determination - Not supported"
};

static const true_false_string hf_lte_rrc_codebook_HARQ_ACK_r13_bit2_val = {
  "Number of configured CCs based codebook size determination - Supported",
  "Number of configured CCs based codebook size determination - Not supported"
};

static const true_false_string lte_rrc_transmissionModeList_r12_val = {
  "NeighCellsInfo applies",
  "NeighCellsInfo does not apply"
};

static const value_string lte_rrc_excessDelay_r13_vals[] = {
  {  0, "ratio < 0.079%"},
  {  1, "0.079% < ratio < 0.100%"},
  {  2, "0.100% < ratio < 0.126%"},
  {  3, "0.126% < ratio < 0.158%"},
  {  4, "0.158% < ratio < 0.199%"},
  {  5, "0.199% < ratio < 0.251%"},
  {  6, "0.251% < ratio < 0.316%"},
  {  7, "0.316% < ratio < 0.398%"},
  {  8, "0.398% < ratio < 0.501%"},
  {  9, "0.501% < ratio < 0.631%"},
  { 10, "0.631% < ratio < 0.794%"},
  { 11, "0.794% < ratio < 1.000%"},
  { 12, "1.000% < ratio < 1.259%"},
  { 13, "1.259% < ratio < 1.585%"},
  { 14, "1.585% < ratio < 1.995%"},
  { 15, "1.995% < ratio < 2.511%"},
  { 16, "2.511% < ratio < 3.161%"},
  { 17, "3.161% < ratio < 3.980%"},
  { 18, "3.980% < ratio < 5.011%"},
  { 19, "5.011% < ratio < 6.309%"},
  { 20, "6.309% < ratio < 7.943%"},
  { 21, "7.943% < ratio < 10.00%"},
  { 22, "10.00% < ratio < 12.589%"},
  { 23, "12.589% < ratio < 15.849%"},
  { 24, "15.849% < ratio < 19.953%"},
  { 25, "19.953% < ratio < 25.119%"},
  { 26, "25.119% < ratio < 31.623%"},
  { 27, "31.623% < ratio < 39.811%"},
  { 28, "39.811% < ratio < 50.119%"},
  { 29, "50.119% < ratio < 63.096%"},
  { 30, "63.096% < ratio < 79.433%"},
  { 31, "79.433% < ratio < 100%"},
  {  0, NULL}
};
static value_string_ext lte_rrc_excessDelay_r13_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_excessDelay_r13_vals);

static void
lte_rrc_averageDelay_r16_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/10, v);
}

static void
lte_rrc_subframeBoundaryOffsetResult_r13_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "abs(deltaZ) < 700Ts (0)");
  } else if (v == 63) {
    snprintf(s, ITEM_LABEL_LENGTH, "1320Ts < abs(deltaZ) (63)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%uTs < abs(deltaZ) <= %uTs (%u)", 700+(v-1)*10, 700+v*10, v);
  }
}

static void
lte_rrc_RS_SINR_Range_r13_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RS-SINR < -23dB (0)");
  } else if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "40dB <= RS-SINR (127)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RS-SINR < %.1fdB (%u)", (((float)v-1)/2)-23, ((float)v/2)-23, v);
  }
}

static void
lte_rrc_RS_SINR_RangeNR_r15_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SS-SINR < -23dB (0)");
  } else if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "40dB < SS-SINR (127)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= SS-SINR < %.1fdB (%u)", (((float)v-1)/2)-23, ((float)v/2)-23, v);
  }
}

static void
lte_rrc_RSSI_Range_r13_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSSI < -100dBm (0)");
  } else if (v == 76) {
    snprintf(s, ITEM_LABEL_LENGTH, "-25dBm <= RSSI (76)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSSI < %ddBm (%u)", -100+(v-1), -100+v, v);
  }
}

static void
lte_rrc_scptm_FreqOffset_r14_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%udB (%u)", 2*v, v);
}

static void
lte_rrc_offsetDFN_r14_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "0ms (0)");
  } else if (v < 1000) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.3fms (%u)", ((float)v)/1000, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "1ms (1000)");
  }
}

static void
lte_rrc_thresholdWLAN_RSSI_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", -128+v, v);
}

static void
lte_rrc_cr_Limit_r14_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "0 (0)");
  } else if (v < 10000) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.4f (%u)", ((float)v)/10000, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "1 (10000)");
  }
}

static void
lte_rrc_SL_CBR_r14_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "0 (0)");
  } else if (v < 100) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.2f (%u)", ((float)v)/100, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "1 (100)");
  }
}

static void
lte_rrc_threshS_RSSI_CBR_r14_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", -112+(2*v), v);
}

static const value_string lte_rrc_schedulingInfoSIB1_NB_r13_vals[] = {
  {  0, "4 NPDSCH repetitions - TBS 208 bits"},
  {  1, "8 NPDSCH repetitions - TBS 208 bits"},
  {  2, "16 NPDSCH repetitions - TBS 208 bits"},
  {  3, "4 NPDSCH repetitions - TBS 328 bits"},
  {  4, "8 NPDSCH repetitions - TBS 328 bits"},
  {  5, "16 NPDSCH repetitions - TBS 328 bits"},
  {  6, "4 NPDSCH repetitions - TBS 440 bits"},
  {  7, "8 NPDSCH repetitions - TBS 440 bits"},
  {  8, "16 NPDSCH repetitions - TBS 440 bits"},
  {  9, "4 NPDSCH repetitions - TBS 680 bits"},
  { 10, "8 NPDSCH repetitions - TBS 680 bits"},
  { 11, "16 NPDSCH repetitions - TBS 680 bits"},
  {  0, NULL}
};
static value_string_ext lte_rrc_schedulingInfoSIB1_NB_r13_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_schedulingInfoSIB1_NB_r13_vals);

static void
lte_rrc_NRSRP_Range_NB_r14_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "NRSRP < -156dBm (0)");
  } else if (v < 113) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= NRSRP < %ddBm (%u)", v-157, v-156, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-44dBm <= NRSRP (97)");
  }
}

static void
lte_rrc_NRSRQ_Range_NB_r14_fmt(gchar *s, guint32 v)
{
  gint32 rsrq = (guint32)v;
  if (rsrq == -30) {
    snprintf(s, ITEM_LABEL_LENGTH, "NRSRQ < -34dB (-30)");
  } else if (rsrq < 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= NRSRQ < %.1fdB (%d)", (((float)rsrq-1)/2)-19, ((float)rsrq/2)-19, rsrq);
  } else if (rsrq == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "NRSRQ < -19.5dB (0)");
  } else if (rsrq < 34) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= NRSRQ < %.1fdB (%d)", (((float)rsrq-1)/2)-19.5, ((float)rsrq/2)-19.5, rsrq);
  } else if (rsrq == 34) {
    snprintf(s, ITEM_LABEL_LENGTH, "-3 <= NRSRQ (34)");
  } else if (rsrq < 46) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= NRSRQ < %.1fdB (%d)", (((float)rsrq-1)/2)-20, ((float)rsrq/2)-20, rsrq);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "2.5dB <= NRSRQ (46)");
  }
}

static void
lte_rrc_mbms_MaxBW_r14_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%u MHz (%u)", 40*v, v);
}

static void
lte_rrc_dl_1024QAM_TotalWeightedLayers_r15_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%u (%u)", 10+(2*v), v);
}

static void
lte_rrc_call_dissector(dissector_handle_t handle, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  TRY {
    call_dissector(handle, tvb, pinfo, tree);
  }
  CATCH_BOUNDS_ERRORS {
    show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
  }
  ENDTRY;
}

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/

typedef struct meas_capabilities_item_band_mappings_t {
  guint16 number_of_bands_set;
  guint16 number_of_interfreq_serving_read;
  guint16 number_of_interfreq_target_read;
  guint16 band_by_item[256];
} meas_capabilities_item_band_mappings_t;


/**********************************************************/
/* Struct to store all current uses of packet private data */
typedef struct lte_rrc_private_data_t
{
  guint8  rat_type;
  guint8  target_rat_type;
  guint8  si_or_psi_geran;
  guint8  ra_preambles;
  guint16 message_identifier;
  guint8 warning_message_segment_type;
  guint8 warning_message_segment_number;
  drb_mapping_t drb_mapping;
  drx_config_t  drx_config;
  pdcp_lte_security_info_t pdcp_security;
  meas_capabilities_item_band_mappings_t meas_capabilities_item_band_mappings;
  simult_pucch_pusch_cell_type cell_type;
  gboolean bcch_dl_sch_msg;
  lpp_pos_sib_type_t pos_sib_type;
} lte_rrc_private_data_t;

/* Helper function to get or create a struct that will be actx->private_data */
static lte_rrc_private_data_t* lte_rrc_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data != NULL) {
    return (lte_rrc_private_data_t*)actx->private_data;
  }
  else {
    lte_rrc_private_data_t* new_struct =
      wmem_new0(actx->pinfo->pool, lte_rrc_private_data_t);
    actx->private_data = new_struct;
    return new_struct;
  }
}


/* DRX config data */
static drx_config_t* private_data_get_drx_config(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return &private_data->drx_config;
}

/* DRB mapping info */
static drb_mapping_t* private_data_get_drb_mapping(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return &private_data->drb_mapping;
}


/* RAT type */
static guint8 private_data_get_rat_type(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->rat_type;
}

static void private_data_set_rat_type(asn1_ctx_t *actx, guint8 rat_type)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->rat_type = rat_type;
}


/* Target RAT type */
static guint8 private_data_get_rat_target_type(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->target_rat_type;
}

static void private_data_set_rat_target_type(asn1_ctx_t *actx, guint8 target_rat_type)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->target_rat_type = target_rat_type;
}


/* si_or_psi_geran */
static guint8 private_data_get_si_or_psi_geran(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->si_or_psi_geran;
}

static void private_data_set_si_or_psi_geran(asn1_ctx_t *actx, guint8 si_or_psi_geran)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->si_or_psi_geran = si_or_psi_geran;
}


/* Message identifier */
static guint16 private_data_get_message_identifier(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->message_identifier;
}

static void private_data_set_message_identifier(asn1_ctx_t *actx, guint16 message_identifier)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->message_identifier = message_identifier;
}


/* Warning message segment type */
static guint16 private_data_get_warning_message_segment_type(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->warning_message_segment_type;
}

static void private_data_set_warning_message_segment_type(asn1_ctx_t *actx, guint8 segment_type)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->warning_message_segment_type = segment_type;
}


/* Warning message segment number */
static guint16 private_data_get_warning_message_segment_number(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->warning_message_segment_number;
}

static void private_data_set_warning_message_segment_number(asn1_ctx_t *actx, guint8 segment_number)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->warning_message_segment_number = segment_number;
}


/* Number of RA-preambles */
static guint8 private_data_get_ra_preambles(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->ra_preambles;
}

static void private_data_set_ra_preambles(asn1_ctx_t *actx, guint8 ra_preambles)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->ra_preambles = ra_preambles;
}


/* PDCP Security info */
static pdcp_lte_security_info_t* private_data_pdcp_security_algorithms(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return &private_data->pdcp_security;
}


/* Measurement UE capabilities item -> band mappings */
static meas_capabilities_item_band_mappings_t* private_data_meas_capabilities_item_band_mappings(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return &private_data->meas_capabilities_item_band_mappings;
}

static void set_freq_band_indicator(guint32 value, asn1_ctx_t *actx)
{
  /* Store band mapping for this item in the next position */
  meas_capabilities_item_band_mappings_t *mappings = private_data_meas_capabilities_item_band_mappings(actx);
  if (mappings->number_of_bands_set < 256) {
    mappings->band_by_item[mappings->number_of_bands_set++] = (guint16)value;
  }
}

static void remove_last_freq_band_indicator(asn1_ctx_t *actx)
{
  meas_capabilities_item_band_mappings_t *mappings = private_data_meas_capabilities_item_band_mappings(actx);
  if ((mappings->number_of_bands_set > 0) && (mappings->number_of_bands_set < 256)) {
    mappings->number_of_bands_set--;
  }
}

/* Cell type for simultaneousPUCCH-PUSCH-r10 */
static simult_pucch_pusch_cell_type private_data_get_simult_pucch_pusch_cell_type(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->cell_type;
}

static void private_data_set_simult_pucch_pusch_cell_type(asn1_ctx_t *actx, simult_pucch_pusch_cell_type cell_type)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->cell_type = cell_type;
}

/* Is top message a BCCH DL-SCH BR/MBMS */
static gboolean private_data_get_bcch_dl_sch_msg(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->bcch_dl_sch_msg;
}

static void private_data_set_bcch_dl_sch_msg(asn1_ctx_t *actx, gboolean is_bcch_dl_sch)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->bcch_dl_sch_msg = is_bcch_dl_sch;
}

static lpp_pos_sib_type_t private_data_get_pos_sib_type(asn1_ctx_t *actx)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  return private_data->pos_sib_type;
}

static void private_data_set_pos_sib_type(asn1_ctx_t *actx, lpp_pos_sib_type_t pos_sib_type)
{
  lte_rrc_private_data_t *private_data = (lte_rrc_private_data_t*)lte_rrc_get_private_data(actx);
  private_data->pos_sib_type = pos_sib_type;
}

/*****************************************************************************/


static void
lte_rrc_localTimeOffset_fmt(gchar *s, guint32 v)
{
  gint32 time_offset = (gint32) v;

  snprintf(s, ITEM_LABEL_LENGTH, "UTC time %c %dhr %dmin (%d)",
             (time_offset < 0) ? '-':'+', abs(time_offset) >> 2,
             (abs(time_offset) & 0x03) * 15, time_offset);
}

static void
dissect_lte_rrc_warningMessageSegment(tvbuff_t *warning_msg_seg_tvb, proto_tree *tree, packet_info *pinfo, guint8 dataCodingScheme)
{
  guint32 offset;
  guint8 nb_of_pages, length, *str;
  proto_item *ti;
  tvbuff_t *cb_data_page_tvb, *cb_data_tvb;
  int i;

  nb_of_pages = tvb_get_guint8(warning_msg_seg_tvb, 0);
  ti = proto_tree_add_uint(tree, hf_lte_rrc_warningMessageSegment_nb_pages, warning_msg_seg_tvb, 0, 1, nb_of_pages);
  if (nb_of_pages > 15) {
    expert_add_info_format(pinfo, ti, &ei_lte_rrc_number_pages_le15,
                           "Number of pages should be <=15 (found %u)", nb_of_pages);
    nb_of_pages = 15;
  }
  for (i = 0, offset = 1; i < nb_of_pages; i++) {
    length = tvb_get_guint8(warning_msg_seg_tvb, offset+82);
    cb_data_page_tvb = tvb_new_subset_length(warning_msg_seg_tvb, offset, length);
    cb_data_tvb = dissect_cbs_data(dataCodingScheme, cb_data_page_tvb, tree, pinfo, 0);
    if (cb_data_tvb) {
      str = tvb_get_string_enc(pinfo->pool, cb_data_tvb, 0, tvb_reported_length(cb_data_tvb), ENC_UTF_8|ENC_NA);
      proto_tree_add_string_format(tree, hf_lte_rrc_warningMessageSegment_decoded_page, warning_msg_seg_tvb, offset, 83,
                                   str, "Decoded Page %u: %s", i+1, str);
    }
    offset += 83;
  }
}

static void
dissect_lte_rrc_featureGroupIndicators(tvbuff_t *featureGroupIndicators_tvb, asn1_ctx_t *actx)
{
  proto_tree *subtree;

  subtree = proto_item_add_subtree(actx->created_item, ett_lte_rrc_featureGroupIndicators);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_1, featureGroupIndicators_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_2, featureGroupIndicators_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_3, featureGroupIndicators_tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_4, featureGroupIndicators_tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_5, featureGroupIndicators_tvb, 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_6, featureGroupIndicators_tvb, 5, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_7, featureGroupIndicators_tvb, 6, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_8, featureGroupIndicators_tvb, 7, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_9, featureGroupIndicators_tvb, 8, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_10, featureGroupIndicators_tvb, 9, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_11, featureGroupIndicators_tvb, 10, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_12, featureGroupIndicators_tvb, 11, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_13, featureGroupIndicators_tvb, 12, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_14, featureGroupIndicators_tvb, 13, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_15, featureGroupIndicators_tvb, 14, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_16, featureGroupIndicators_tvb, 15, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_17, featureGroupIndicators_tvb, 16, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_18, featureGroupIndicators_tvb, 17, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_19, featureGroupIndicators_tvb, 18, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_20, featureGroupIndicators_tvb, 19, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_21, featureGroupIndicators_tvb, 20, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_22, featureGroupIndicators_tvb, 21, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_23, featureGroupIndicators_tvb, 22, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_24, featureGroupIndicators_tvb, 23, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_25, featureGroupIndicators_tvb, 24, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_26, featureGroupIndicators_tvb, 25, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_27, featureGroupIndicators_tvb, 26, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_28, featureGroupIndicators_tvb, 27, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_29, featureGroupIndicators_tvb, 28, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_30, featureGroupIndicators_tvb, 29, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_31, featureGroupIndicators_tvb, 30, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_32, featureGroupIndicators_tvb, 31, 1, ENC_BIG_ENDIAN);
}

static void
dissect_lte_rrc_featureGroupIndRel10(tvbuff_t *featureGroupIndRel10_tvb, asn1_ctx_t *actx)
{
  proto_tree *subtree;

  subtree = proto_item_add_subtree(actx->created_item, ett_lte_rrc_featureGroupIndRel10);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_101, featureGroupIndRel10_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_102, featureGroupIndRel10_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_103, featureGroupIndRel10_tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_104, featureGroupIndRel10_tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_105, featureGroupIndRel10_tvb, 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_106, featureGroupIndRel10_tvb, 5, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_107, featureGroupIndRel10_tvb, 6, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_108, featureGroupIndRel10_tvb, 7, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_109, featureGroupIndRel10_tvb, 8, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_110, featureGroupIndRel10_tvb, 9, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_111, featureGroupIndRel10_tvb, 10, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_112, featureGroupIndRel10_tvb, 11, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_113, featureGroupIndRel10_tvb, 12, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_114, featureGroupIndRel10_tvb, 13, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_115, featureGroupIndRel10_tvb, 14, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_116, featureGroupIndRel10_tvb, 15, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_117, featureGroupIndRel10_tvb, 16, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_118, featureGroupIndRel10_tvb, 17, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_119, featureGroupIndRel10_tvb, 18, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_120, featureGroupIndRel10_tvb, 19, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_121, featureGroupIndRel10_tvb, 20, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_122, featureGroupIndRel10_tvb, 21, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_123, featureGroupIndRel10_tvb, 22, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_124, featureGroupIndRel10_tvb, 23, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_125, featureGroupIndRel10_tvb, 24, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_126, featureGroupIndRel10_tvb, 25, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_127, featureGroupIndRel10_tvb, 26, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_128, featureGroupIndRel10_tvb, 27, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_129, featureGroupIndRel10_tvb, 28, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_130, featureGroupIndRel10_tvb, 29, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_131, featureGroupIndRel10_tvb, 30, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_132, featureGroupIndRel10_tvb, 31, 1, ENC_BIG_ENDIAN);
}

static void
dissect_lte_rrc_featureGroupIndRel9Add(tvbuff_t *featureGroupIndRel9Add_tvb, asn1_ctx_t *actx)
{
  proto_tree *subtree;

  subtree = proto_item_add_subtree(actx->created_item, ett_lte_rrc_featureGroupIndRel9Add);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_33, featureGroupIndRel9Add_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_34, featureGroupIndRel9Add_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_35, featureGroupIndRel9Add_tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_36, featureGroupIndRel9Add_tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_37, featureGroupIndRel9Add_tvb, 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_38, featureGroupIndRel9Add_tvb, 5, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_39, featureGroupIndRel9Add_tvb, 6, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_40, featureGroupIndRel9Add_tvb, 7, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_41, featureGroupIndRel9Add_tvb, 8, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_42, featureGroupIndRel9Add_tvb, 9, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_43, featureGroupIndRel9Add_tvb, 10, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_44, featureGroupIndRel9Add_tvb, 11, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_45, featureGroupIndRel9Add_tvb, 12, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_46, featureGroupIndRel9Add_tvb, 13, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_47, featureGroupIndRel9Add_tvb, 14, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_48, featureGroupIndRel9Add_tvb, 15, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_49, featureGroupIndRel9Add_tvb, 16, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_50, featureGroupIndRel9Add_tvb, 17, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_51, featureGroupIndRel9Add_tvb, 18, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_52, featureGroupIndRel9Add_tvb, 19, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_53, featureGroupIndRel9Add_tvb, 20, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_54, featureGroupIndRel9Add_tvb, 21, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_55, featureGroupIndRel9Add_tvb, 22, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_56, featureGroupIndRel9Add_tvb, 23, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_57, featureGroupIndRel9Add_tvb, 24, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_58, featureGroupIndRel9Add_tvb, 25, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_59, featureGroupIndRel9Add_tvb, 26, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_60, featureGroupIndRel9Add_tvb, 27, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_61, featureGroupIndRel9Add_tvb, 28, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_62, featureGroupIndRel9Add_tvb, 29, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_63, featureGroupIndRel9Add_tvb, 30, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bits_item(subtree, hf_lte_rrc_eutra_cap_feat_group_ind_64, featureGroupIndRel9Add_tvb, 31, 1, ENC_BIG_ENDIAN);
}

/* Functions to get enum values out of indices parsed */
/* If entry not found, return last element of array */
static guint32 drx_lookup_onDurationTimer(guint32 idx)
{
  static const guint32 vals[] = {1,2,3,4,5,6,8,10,20,30,40,50,60,80,100,200};

  if (idx < (sizeof(vals)/sizeof(guint32))) {
    return vals[idx];
  }
  return (sizeof(vals)/(sizeof(guint32)) - 1);
}

static guint32 drx_lookup_inactivityTimer(guint32 idx)
{
  static const guint32 vals[] = {
    1,2,3,4,5,6,8,10,20,30,40,50,60,80,100,200,300, 500,750,1280,1920,2560,0
  };

  if (idx < (sizeof(vals)/sizeof(guint32))) {
    return vals[idx];
  }
  return (sizeof(vals)/(sizeof(guint32)) - 1);
}

static guint32 drx_lookup_retransmissionTimer(guint32 idx)
{
  static const guint32 vals[] = {1,2,4,6,8,16,24,33};

  if (idx < (sizeof(vals)/sizeof(guint32))) {
    return vals[idx];
  }
  return (sizeof(vals)/(sizeof(guint32)) - 1);
}

static guint32 drx_lookup_longCycle(guint32 idx)
{
  static const guint32 vals[] = {
    10,20,32,40,64,80,128,160,256,320,512,640,1024,1280,2048,2560
  };

  if (idx < (sizeof(vals)/sizeof(guint32))) {
    return vals[idx];
  }
  return (sizeof(vals)/(sizeof(guint32)) - 1);
}

static guint32 drx_lookup_longCycle_v1130(guint32 idx)
{
  static const guint32 vals[] = {
    60,70
  };

  if (idx < (sizeof(vals)/sizeof(guint32))) {
    return vals[idx];
  }
  return (sizeof(vals)/(sizeof(guint32)) - 1);
}


static guint32 drx_lookup_shortCycle(guint32 idx)
{
  static const guint32 vals[] = {
    2,5,8,10,16,20,32,40,64,80,128,160,256,320,512,640
  };

  if (idx < (sizeof(vals)/sizeof(guint32))) {
    return vals[idx];
  }
  return (sizeof(vals)/(sizeof(guint32)) - 1);
}

static void drx_check_config_sane(drx_config_t *config, asn1_ctx_t *actx)
{
  /* OnDuration must be shorter than long cycle */
  if (config->onDurationTimer >= config->longCycle) {
      expert_add_info_format(actx->pinfo, actx->created_item, &ei_lte_rrc_invalid_drx_config,
                                  "OnDurationTimer (%u) should be less than long cycle (%u)",
                                  config->onDurationTimer, config->longCycle);
  }

  if (config->shortCycleConfigured) {
    /* Short cycle must be < long, and be a multiple of it */
    if (config->shortCycle >= config->longCycle) {
      expert_add_info_format(actx->pinfo, actx->created_item, &ei_lte_rrc_invalid_drx_config,
                                  "Short DRX cycle (%u) must be shorter than long cycle (%u)",
                                  config->shortCycle, config->longCycle);
    }
    /* Long cycle needs to be an exact multiple of the short cycle */
    else if (config->shortCycle && ((config->longCycle % config->shortCycle) != 0)) {
      expert_add_info_format(actx->pinfo, actx->created_item, &ei_lte_rrc_invalid_drx_config,
                                  "Short DRX cycle (%u) must divide the long cycle (%u) exactly",
                                  config->shortCycle, config->longCycle);

    }
    /* OnDuration shouldn't be longer than the short cycle */
    if (config->onDurationTimer >= config->shortCycle) {
      expert_add_info_format(actx->pinfo, actx->created_item, &ei_lte_rrc_invalid_drx_config,
                                  "OnDurationTimer (%u) should not be longer than the short cycle (%u)",
                                  config->onDurationTimer, config->shortCycle);
    }
    /* TODO: check that (onDuration+(shortCycle*shortCycleTimer)) < longCycle ? */
    /* TODO: check that (shortCycle*shortCycleTimer) < longCycle ? */
  }
}

/* Break sr-configIndex down into periodicity and offset.  From 36.231, 10.1 */
static void sr_lookup_configindex(guint32 config_index, guint16 *periodicity, guint16 *offset)
{
  if (config_index < 5) {
    *periodicity = 5;
    *offset = config_index;
  } else if (config_index < 15) {
    *periodicity = 10;
    *offset = config_index - 5;
  }
  else if (config_index < 35) {
    *periodicity = 20;
    *offset = config_index - 15;
  }
  else if (config_index < 75) {
    *periodicity = 40;
    *offset = config_index - 35;
  }
  else if (config_index < 155) {
    *periodicity = 80;
    *offset = config_index - 75;
  }
  else if (config_index < 157) {
    *periodicity = 2;
    *offset = config_index - 155;
  }
  else {
    *periodicity = 1;
    *offset = 0;
  }
}

#include "packet-lte-rrc-fn.c"

static int
dissect_lte_rrc_DL_CCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_CCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_DL_CCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_DL_DCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_DCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_lte_rrc_DL_DCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_UL_CCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UL_CCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_UL_CCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_UL_DCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UL_DCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_lte_rrc_UL_DCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_BCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC BCCH_BCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_BCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_DL_SCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_SCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_DL_SCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_DL_SCH_BR(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_SCH_BR");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_DL_SCH_Message_BR_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_PCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC PCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_PCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_MCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC MCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_MCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_Handover_Preparation_Info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE_HO_Prep_Info");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Don't want elements inside message updating Info column, so set now and
     freeze during dissection of PDU */
  col_set_str(pinfo->cinfo, COL_INFO, "HandoverPreparationInformation");
  col_set_writable(pinfo->cinfo, COL_INFO, FALSE);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_lte_rrc_HandoverPreparationInformation_PDU(tvb, pinfo, lte_rrc_tree, NULL);

  col_set_writable(pinfo->cinfo, COL_INFO, TRUE);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_SBCCH_SL_BCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC SBCCH_SL_BCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_SBCCH_SL_BCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_SBCCH_SL_BCH_V2X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC SBCCH_SL_BCH_V2X");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_SBCCH_SL_BCH_Message_V2X_r14_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_SC_MCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC SC MCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_SC_MCCH_Message_r13_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_DL_CCCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_CCCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_DL_CCCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_DL_DCCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_DCCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_DL_DCCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_UL_CCCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UL_CCCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_UL_CCCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_UL_DCCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UL_DCCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_UL_DCCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_BCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC BCCH_BCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_BCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_BCH_TDD_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC BCCH_BCH_TDD_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_BCH_Message_TDD_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_DL_SCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_SCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_DL_SCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_PCCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC PCCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_PCCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_SC_MCCH_NB(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC SC MCCH_NB");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_SC_MCCH_Message_NB_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_BCH_MBMS(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC BCCH_BCH_MBMS");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_BCH_Message_MBMS_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_BCCH_DL_SCH_MBMS(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_SCH_MBMS");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
  lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
  dissect_BCCH_DL_SCH_Message_MBMS_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_ue_eutra_capability_msg(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* lte_rrc_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UE EUTRA Capability");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_lte_rrc_UE_EUTRA_Capability_PDU(tvb, pinfo, lte_rrc_tree, NULL);
    return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_ueradioaccesscapabilityinformation_msg(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* lte_rrc_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UERadioAccessCapabilityInformation");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_lte_rrc_UERadioAccessCapabilityInformation_PDU(tvb, pinfo, lte_rrc_tree, NULL);
    return tvb_captured_length(tvb);
}

static int
dissect_lte_rrc_dissect_SystemInformationBlockType1_v890_IEs(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* lte_rrc_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC SystemInformationBlockType1-v890-IEs");
    col_set_str(pinfo->cinfo, COL_INFO, "LTE RRC SystemInformationBlockType1-v890-IEs");

    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_SystemInformationBlockType1_v890_IEs_PDU(tvb, pinfo, lte_rrc_tree, NULL);
    return tvb_captured_length(tvb);
}



/*--- proto_register_rrc -------------------------------------------*/
void proto_register_lte_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-lte-rrc-hfarr.c"

    { &hf_lte_rrc_eutra_cap_feat_group_ind_1,
      { "Indicator 1", "lte-rrc.eutra_cap_feat_group_ind_1",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_1_val), 0,
        "EUTRA Feature Group Indicator 1", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_2,
      { "Indicator 2", "lte-rrc.eutra_cap_feat_group_ind_2",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_2_val), 0,
        "EUTRA Feature Group Indicator 2", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_3,
      { "Indicator 3", "lte-rrc.eutra_cap_feat_group_ind_3",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_3_val), 0,
        "EUTRA Feature Group Indicator 3", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_4,
      { "Indicator 4", "lte-rrc.eutra_cap_feat_group_ind_4",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_4_val), 0,
        "EUTRA Feature Group Indicator 4", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_5,
      { "Indicator 5", "lte-rrc.eutra_cap_feat_group_ind_5",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_5_val), 0,
        "EUTRA Feature Group Indicator 5", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_6,
      { "Indicator 6", "lte-rrc.eutra_cap_feat_group_ind_6",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_6_val), 0,
        "EUTRA Feature Group Indicator 6", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_7,
      { "Indicator 7", "lte-rrc.eutra_cap_feat_group_ind_7",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_7_val), 0,
        "EUTRA Feature Group Indicator 7", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_8,
      { "Indicator 8", "lte-rrc.eutra_cap_feat_group_ind_8",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_8_val), 0,
        "EUTRA Feature Group Indicator 8", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_9,
      { "Indicator 9", "lte-rrc.eutra_cap_feat_group_ind_9",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_9_val), 0,
        "EUTRA Feature Group Indicator 9", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_10,
      { "Indicator 10", "lte-rrc.eutra_cap_feat_group_ind_10",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_10_val), 0,
        "EUTRA Feature Group Indicator 10", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_11,
      { "Indicator 11", "lte-rrc.eutra_cap_feat_group_ind_11",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_11_val), 0,
        "EUTRA Feature Group Indicator 11", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_12,
      { "Indicator 12", "lte-rrc.eutra_cap_feat_group_ind_12",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_12_val), 0,
        "EUTRA Feature Group Indicator 12", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_13,
      { "Indicator 13", "lte-rrc.eutra_cap_feat_group_ind_13",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_13_val), 0,
        "EUTRA Feature Group Indicator", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_14,
      { "Indicator 14", "lte-rrc.eutra_cap_feat_group_ind_14",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_14_val), 0,
        "EUTRA Feature Group Indicator 14", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_15,
      { "Indicator 15", "lte-rrc.eutra_cap_feat_group_ind_15",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_15_val), 0,
        "EUTRA Feature Group Indicator 15", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_16,
      { "Indicator 16", "lte-rrc.eutra_cap_feat_group_ind_16",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_16_val), 0,
        "EUTRA Feature Group Indicator 16", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_17,
      { "Indicator 17", "lte-rrc.eutra_cap_feat_group_ind_17",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_17_val), 0,
        "EUTRA Feature Group Indicator 17", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_18,
      { "Indicator 18", "lte-rrc.eutra_cap_feat_group_ind_18",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_18_val), 0,
        "EUTRA Feature Group Indicator 18", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_19,
      { "Indicator 19", "lte-rrc.eutra_cap_feat_group_ind_19",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_19_val), 0,
        "EUTRA Feature Group Indicator 19", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_20,
      { "Indicator 20", "lte-rrc.eutra_cap_feat_group_ind_20",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_20_val), 0,
        "EUTRA Feature Group Indicator 20", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_21,
      { "Indicator 21", "lte-rrc.eutra_cap_feat_group_ind_21",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_21_val), 0,
        "EUTRA Feature Group Indicator 21", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_22,
      { "Indicator 22", "lte-rrc.eutra_cap_feat_group_ind_22",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_22_val), 0,
        "EUTRA Feature Group Indicator 22", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_23,
      { "Indicator 23", "lte-rrc.eutra_cap_feat_group_ind_23",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_23_val), 0,
        "EUTRA Feature Group Indicator 23", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_24,
      { "Indicator 24", "lte-rrc.eutra_cap_feat_group_ind_24",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_24_val), 0,
        "EUTRA Feature Group Indicator 24", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_25,
      { "Indicator 25", "lte-rrc.eutra_cap_feat_group_ind_25",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_25_val), 0,
        "EUTRA Feature Group Indicator 25", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_26,
      { "Indicator 26", "lte-rrc.eutra_cap_feat_group_ind_26",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_26_val), 0,
        "EUTRA Feature Group Indicator 26", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_27,
      { "Indicator 27", "lte-rrc.eutra_cap_feat_group_ind_27",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_27_val), 0,
        "EUTRA Feature Group Indicator 27", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_28,
      { "Indicator 28", "lte-rrc.eutra_cap_feat_group_ind_28",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_28_val), 0,
        "EUTRA Feature Group Indicator 28", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_29,
      { "Indicator 29", "lte-rrc.eutra_cap_feat_group_ind_29",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_29_val), 0,
        "EUTRA Feature Group Indicator 29", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_30,
      { "Indicator 30", "lte-rrc.eutra_cap_feat_group_ind_30",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_30_val), 0,
        "EUTRA Feature Group Indicator 30", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_31,
      { "Indicator 31", "lte-rrc.eutra_cap_feat_group_ind_31",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_31_val), 0,
        "EUTRA Feature Group Indicator 31", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_32,
      { "Indicator 32", "lte-rrc.eutra_cap_feat_group_ind_32",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_32_val), 0,
        "EUTRA Feature Group Indicator 32", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_33,
      { "Indicator 33", "lte-rrc.eutra_cap_feat_group_ind_33",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_33_val), 0,
        "EUTRA Feature Group Indicator 33", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_34,
      { "Indicator 34", "lte-rrc.eutra_cap_feat_group_ind_34",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_34_val), 0,
        "EUTRA Feature Group Indicator 34", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_35,
      { "Indicator 35", "lte-rrc.eutra_cap_feat_group_ind_35",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_35_val), 0,
        "EUTRA Feature Group Indicator 35", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_36,
      { "Indicator 36", "lte-rrc.eutra_cap_feat_group_ind_36",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_36_val), 0,
        "EUTRA Feature Group Indicator 36", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_37,
      { "Indicator 37", "lte-rrc.eutra_cap_feat_group_ind_37",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_37_val), 0,
        "EUTRA Feature Group Indicator 37", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_38,
      { "Indicator 38", "lte-rrc.eutra_cap_feat_group_ind_38",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_38_val), 0,
        "EUTRA Feature Group Indicator 38", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_39,
      { "Indicator 39", "lte-rrc.eutra_cap_feat_group_ind_39",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_39_val), 0,
        "EUTRA Feature Group Indicator 39", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_40,
      { "Indicator 40", "lte-rrc.eutra_cap_feat_group_ind_40",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_40_val), 0,
        "EUTRA Feature Group Indicator 40", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_41,
      { "Indicator 41", "lte-rrc.eutra_cap_feat_group_ind_41",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_41_val), 0,
        "EUTRA Feature Group Indicator 41", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_42,
      { "Indicator 42", "lte-rrc.eutra_cap_feat_group_ind_42",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_42_val), 0,
        "EUTRA Feature Group Indicator 42", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_43,
      { "Indicator 43", "lte-rrc.eutra_cap_feat_group_ind_43",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_43_val), 0,
        "EUTRA Feature Group Indicator 43", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_44,
      { "Indicator 44", "lte-rrc.eutra_cap_feat_group_ind_44",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_44_val), 0,
        "EUTRA Feature Group Indicator 44", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_45,
      { "Indicator 45", "lte-rrc.eutra_cap_feat_group_ind_45",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_45_val), 0,
        "EUTRA Feature Group Indicator 45", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_46,
      { "Indicator 46", "lte-rrc.eutra_cap_feat_group_ind_46",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_46_val), 0,
        "EUTRA Feature Group Indicator 46", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_47,
      { "Indicator 47", "lte-rrc.eutra_cap_feat_group_ind_47",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_47_val), 0,
        "EUTRA Feature Group Indicator 47", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_48,
      { "Indicator 48", "lte-rrc.eutra_cap_feat_group_ind_48",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_48_val), 0,
        "EUTRA Feature Group Indicator 48", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_49,
      { "Indicator 49", "lte-rrc.eutra_cap_feat_group_ind_49",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_49_val), 0,
        "EUTRA Feature Group Indicator 49", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_50,
      { "Indicator 50", "lte-rrc.eutra_cap_feat_group_ind_50",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_50_val), 0,
        "EUTRA Feature Group Indicator 50", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_51,
      { "Indicator 51", "lte-rrc.eutra_cap_feat_group_ind_51",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_51_val), 0,
        "EUTRA Feature Group Indicator 51", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_52,
      { "Indicator 52", "lte-rrc.eutra_cap_feat_group_ind_52",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_52_val), 0,
        "EUTRA Feature Group Indicator 52", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_53,
      { "Indicator 53", "lte-rrc.eutra_cap_feat_group_ind_53",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_53_val), 0,
        "EUTRA Feature Group Indicator 53", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_54,
      { "Indicator 54", "lte-rrc.eutra_cap_feat_group_ind_54",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_54_val), 0,
        "EUTRA Feature Group Indicator 54", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_55,
      { "Indicator 55", "lte-rrc.eutra_cap_feat_group_ind_55",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_55_val), 0,
        "EUTRA Feature Group Indicator 55", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_56,
      { "Indicator 56", "lte-rrc.eutra_cap_feat_group_ind_56",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_56_val), 0,
        "EUTRA Feature Group Indicator 56", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_57,
      { "Indicator 57", "lte-rrc.eutra_cap_feat_group_ind_57",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_57_val), 0,
        "EUTRA Feature Group Indicator 57", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_58,
      { "Indicator 58", "lte-rrc.eutra_cap_feat_group_ind_58",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_58_val), 0,
        "EUTRA Feature Group Indicator 58", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_59,
      { "Indicator 59", "lte-rrc.eutra_cap_feat_group_ind_59",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_59_val), 0,
        "EUTRA Feature Group Indicator 59", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_60,
      { "Indicator 60", "lte-rrc.eutra_cap_feat_group_ind_60",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_60_val), 0,
        "EUTRA Feature Group Indicator 60", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_61,
      { "Indicator 61", "lte-rrc.eutra_cap_feat_group_ind_61",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_61_val), 0,
        "EUTRA Feature Group Indicator 61", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_62,
      { "Indicator 62", "lte-rrc.eutra_cap_feat_group_ind_62",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_62_val), 0,
        "EUTRA Feature Group Indicator 62", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_63,
      { "Indicator 63", "lte-rrc.eutra_cap_feat_group_ind_63",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_63_val), 0,
        "EUTRA Feature Group Indicator 63", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_64,
      { "Indicator 64", "lte-rrc.eutra_cap_feat_group_ind_64",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_64_val), 0,
        "EUTRA Feature Group Indicator 64", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_101,
      { "Indicator 101", "lte-rrc.eutra_cap_feat_group_ind_101",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_101_val), 0,
        "EUTRA Feature Group Indicator 101", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_102,
      { "Indicator 102", "lte-rrc.eutra_cap_feat_group_ind_102",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_102_val), 0,
        "EUTRA Feature Group Indicator 102", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_103,
      { "Indicator 103", "lte-rrc.eutra_cap_feat_group_ind_103",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_103_val), 0,
        "EUTRA Feature Group Indicator 103", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_104,
      { "Indicator 104", "lte-rrc.eutra_cap_feat_group_ind_104",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_104_val), 0,
        "EUTRA Feature Group Indicator 104", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_105,
      { "Indicator 105", "lte-rrc.eutra_cap_feat_group_ind_105",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_105_val), 0,
        "EUTRA Feature Group Indicator 105", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_106,
      { "Indicator 106", "lte-rrc.eutra_cap_feat_group_ind_106",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_106_val), 0,
        "EUTRA Feature Group Indicator 106", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_107,
      { "Indicator 107", "lte-rrc.eutra_cap_feat_group_ind_107",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_107_val), 0,
        "EUTRA Feature Group Indicator 107", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_108,
      { "Indicator 108", "lte-rrc.eutra_cap_feat_group_ind_108",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_108_val), 0,
        "EUTRA Feature Group Indicator 108", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_109,
      { "Indicator 109", "lte-rrc.eutra_cap_feat_group_ind_109",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_109_val), 0,
        "EUTRA Feature Group Indicator 109", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_110,
      { "Indicator 110", "lte-rrc.eutra_cap_feat_group_ind_110",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_110_val), 0,
        "EUTRA Feature Group Indicator 110", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_111,
      { "Indicator 111", "lte-rrc.eutra_cap_feat_group_ind_111",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_111_val), 0,
        "EUTRA Feature Group Indicator 111", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_112,
      { "Indicator 112", "lte-rrc.eutra_cap_feat_group_ind_112",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_112_val), 0,
        "EUTRA Feature Group Indicator 112", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_113,
      { "Indicator 113", "lte-rrc.eutra_cap_feat_group_ind_113",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_113_val), 0,
        "EUTRA Feature Group Indicator 113", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_114,
      { "Indicator 114", "lte-rrc.eutra_cap_feat_group_ind_114",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_114_val), 0,
        "EUTRA Feature Group Indicator 114", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_115,
      { "Indicator 115", "lte-rrc.eutra_cap_feat_group_ind_115",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_115_val), 0,
        "EUTRA Feature Group Indicator 115", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_116,
      { "Indicator 116", "lte-rrc.eutra_cap_feat_group_ind_116",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_116_val), 0,
        "EUTRA Feature Group Indicator 116", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_117,
      { "Indicator 117", "lte-rrc.eutra_cap_feat_group_ind_117",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_117_val), 0,
        "EUTRA Feature Group Indicator 117", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_118,
      { "Indicator 118", "lte-rrc.eutra_cap_feat_group_ind_118",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_118_val), 0,
        "EUTRA Feature Group Indicator 118", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_119,
      { "Indicator 119", "lte-rrc.eutra_cap_feat_group_ind_119",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_119_val), 0,
        "EUTRA Feature Group Indicator 119", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_120,
      { "Indicator 120", "lte-rrc.eutra_cap_feat_group_ind_120",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_120_val), 0,
        "EUTRA Feature Group Indicator 120", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_121,
      { "Indicator 121", "lte-rrc.eutra_cap_feat_group_ind_121",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_121_val), 0,
        "EUTRA Feature Group Indicator 121", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_122,
      { "Indicator 122", "lte-rrc.eutra_cap_feat_group_ind_122",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_122_val), 0,
        "EUTRA Feature Group Indicator 122", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_123,
      { "Indicator 123", "lte-rrc.eutra_cap_feat_group_ind_123",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_123_val), 0,
        "EUTRA Feature Group Indicator 123", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_124,
      { "Indicator 124", "lte-rrc.eutra_cap_feat_group_ind_124",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_124_val), 0,
        "EUTRA Feature Group Indicator 124", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_125,
      { "Indicator 125", "lte-rrc.eutra_cap_feat_group_ind_125",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_125_val), 0,
        "EUTRA Feature Group Indicator 125", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_126,
      { "Indicator 126", "lte-rrc.eutra_cap_feat_group_ind_126",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_126_val), 0,
        "EUTRA Feature Group Indicator 126", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_127,
      { "Indicator 127", "lte-rrc.eutra_cap_feat_group_ind_127",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_127_val), 0,
        "EUTRA Feature Group Indicator 127", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_128,
      { "Indicator 128", "lte-rrc.eutra_cap_feat_group_ind_128",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_128_val), 0,
        "EUTRA Feature Group Indicator 128", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_129,
      { "Indicator 129", "lte-rrc.eutra_cap_feat_group_ind_129",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_129_val), 0,
        "EUTRA Feature Group Indicator 129", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_130,
      { "Indicator 130", "lte-rrc.eutra_cap_feat_group_ind_130",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_130_val), 0,
        "EUTRA Feature Group Indicator 130", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_131,
      { "Indicator 131", "lte-rrc.eutra_cap_feat_group_ind_131",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_131_val), 0,
        "EUTRA Feature Group Indicator 131", HFILL }},
    { &hf_lte_rrc_eutra_cap_feat_group_ind_132,
      { "Indicator 132", "lte-rrc.eutra_cap_feat_group_ind_132",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_eutra_cap_feat_group_ind_132_val), 0,
        "EUTRA Feature Group Indicator 132", HFILL }},
    { &hf_lte_rrc_serialNumber_gs,
      { "Geographical Scope", "lte-rrc.serialNumber.gs",
        FT_UINT16, BASE_DEC, VALS(lte_rrc_serialNumber_gs_vals), 0xc000,
        NULL, HFILL }},
    { &hf_lte_rrc_serialNumber_msg_code,
      { "Message Code", "lte-rrc.serialNumber.msg_code",
        FT_UINT16, BASE_DEC, NULL, 0x3ff0,
        NULL, HFILL }},
    { &hf_lte_rrc_serialNumber_upd_nb,
      { "Update Number", "lte-rrc.serialNumber.upd_nb",
        FT_UINT16, BASE_DEC, NULL, 0x000f,
        NULL, HFILL }},
    { &hf_lte_rrc_warningType_value,
      { "Warning Type Value", "lte-rrc.warningType.value",
        FT_UINT16, BASE_DEC, VALS(lte_rrc_warningType_vals), 0xfe00,
        NULL, HFILL }},
    { &hf_lte_rrc_warningType_emergency_user_alert,
      { "Emergency User Alert", "lte-rrc.warningType.emergency_user_alert",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        NULL, HFILL }},
    { &hf_lte_rrc_warningType_popup,
      { "Popup", "lte-rrc.warningType.popup",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_lte_rrc_warningMessageSegment_nb_pages,
      { "Number of Pages", "lte-rrc.warningMessageSegment.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_warningMessageSegment_decoded_page,
      { "Decoded Page", "lte-rrc.warningMessageSegment.decoded_page",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_interBandTDD_CA_WithDifferentConfig_bit1,
      { "Bit 1", "lte-rrc.interBandTDD_CA_WithDifferentConfig.bit1",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_interBandTDD_CA_WithDifferentConfig_bit1_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_interBandTDD_CA_WithDifferentConfig_bit2,
      { "Bit 2", "lte-rrc.interBandTDD_CA_WithDifferentConfig.bit2",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_interBandTDD_CA_WithDifferentConfig_bit2_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit1,
      { "Bit 1", "lte-rrc.tdd_FDD_CA_PCellDuplex_r12.bit1",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit1_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit2,
      { "Bit 2", "lte-rrc.tdd_FDD_CA_PCellDuplex_r12.bit2",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_tdd_FDD_CA_PCellDuplex_r12_bit2_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_aperiodicCSI_Reporting_r13_bit1,
      { "Bit 1", "lte-rrc.aperiodicCSI_Reporting_r13.bit1",
        FT_BOOLEAN, BASE_NONE, TFS(&hf_lte_rrc_aperiodicCSI_Reporting_r13_bit1_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_aperiodicCSI_Reporting_r13_bit2,
      { "Bit 2", "lte-rrc.aperiodicCSI_Reporting_r13.bit2",
        FT_BOOLEAN, BASE_NONE, TFS(&hf_lte_rrc_aperiodicCSI_Reporting_r13_bit2_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_codebook_HARQ_ACK_r13_bit1,
      { "Bit 1", "lte-rrc.codebook_HARQ_ACK_r13.bit1",
        FT_BOOLEAN, BASE_NONE, TFS(&hf_lte_rrc_codebook_HARQ_ACK_r13_bit1_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_codebook_HARQ_ACK_r13_bit2,
      { "Bit 2", "lte-rrc.codebook_HARQ_ACK_r13.bit2",
        FT_BOOLEAN, BASE_NONE, TFS(&hf_lte_rrc_codebook_HARQ_ACK_r13_bit2_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sr_config_periodicity,
      { "Periodicity", "lte-rrc.sr_Periodicity",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_lte_rrc_sr_config_subframe_offset,
      { "Subframe Offset", "lte-rrc.sr_SubframeOffset",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_lte_rrc_cdma_time,
      { "CDMA  time", "lte-rrc.cdma_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_lte_rrc_utc_time,
      { "UTC   time", "lte-rrc.utc_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_lte_rrc_local_time,
      { "Local time", "lte-rrc.local_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }},
    { &hf_lte_rrc_absolute_time,
      { "Absolute time", "lte-rrc.absolute_time",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm1,
      { "TM1", "lte-rrc.transmissionModeList_r12.tm1",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm2,
      { "TM2", "lte-rrc.transmissionModeList_r12.tm2",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm3,
      { "TM3", "lte-rrc.transmissionModeList_r12.tm3",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm4,
      { "TM4", "lte-rrc.transmissionModeList_r12.tm4",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm6,
      { "TM6", "lte-rrc.transmissionModeList_r12.tm6",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm8,
      { "TM8", "lte-rrc.transmissionModeList_r12.tm8",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm9,
      { "TM9", "lte-rrc.transmissionModeList_r12.tm9",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_transmissionModeList_r12_tm10,
      { "TM10", "lte-rrc.transmissionModeList_r12.tm10",
        FT_BOOLEAN, BASE_NONE, TFS(&lte_rrc_transmissionModeList_r12_val), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_0,
      { "MPR/A-MPR behavior 0", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_0",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_1,
      { "MPR/A-MPR behavior 1", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_1",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_2,
      { "MPR/A-MPR behavior 2", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_2",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_3,
      { "MPR/A-MPR behavior 3", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_3",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_4,
      { "MPR/A-MPR behavior 4", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_4",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_5,
      { "MPR/A-MPR behavior 5", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_5",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_6,
      { "MPR/A-MPR behavior 6", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_6",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_7,
      { "MPR/A-MPR behavior 7", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_7",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_8,
      { "MPR/A-MPR behavior 8", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_8",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_9,
      { "MPR/A-MPR behavior 9", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_9",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_10,
      { "MPR/A-MPR behavior 10", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_10",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_11,
      { "MPR/A-MPR behavior 11", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_11",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_12,
      { "MPR/A-MPR behavior 12", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_12",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_13,
      { "MPR/A-MPR behavior 13", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_13",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_14,
      { "MPR/A-MPR behavior 14", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_14",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_15,
      { "MPR/A-MPR behavior 15", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_15",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_16,
      { "MPR/A-MPR behavior 16", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_16",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_17,
      { "MPR/A-MPR behavior 17", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_17",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_18,
      { "MPR/A-MPR behavior 18", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_18",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_19,
      { "MPR/A-MPR behavior 19", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_19",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_20,
      { "MPR/A-MPR behavior 20", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_20",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_21,
      { "MPR/A-MPR behavior 21", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_21",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_22,
      { "MPR/A-MPR behavior 22", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_22",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_23,
      { "MPR/A-MPR behavior 23", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_23",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_24,
      { "MPR/A-MPR behavior 24", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_24",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_25,
      { "MPR/A-MPR behavior 25", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_25",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_26,
      { "MPR/A-MPR behavior 26", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_26",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_27,
      { "MPR/A-MPR behavior 27", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_27",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_28,
      { "MPR/A-MPR behavior 28", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_28",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_29,
      { "MPR/A-MPR behavior 29", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_29",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_30,
      { "MPR/A-MPR behavior 30", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_30",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_modifiedMPR_Behavior_r10_mpr_ampr_31,
      { "MPR/A-MPR behavior 31", "lte-rrc.modifiedMPR_Behavior_r10.mpr_ampr_31",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragments,
      { "Fragments", "lte-rrc.warningMessageSegment.fragments",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragment,
      { "Fragment", "lte-rrc.warningMessageSegment.fragment",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragment_overlap,
      { "Fragment Overlap", "lte-rrc.warningMessageSegment.fragment_overlap",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragment_overlap_conflict,
      { "Fragment Overlap Conflict", "lte-rrc.warningMessageSegment.fragment_overlap_conflict",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragment_multiple_tails,
      { "Fragment Multiple Tails", "lte-rrc.warningMessageSegment.fragment_multiple_tails",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragment_too_long_fragment,
      { "Too Long Fragment", "lte-rrc.warningMessageSegment.fragment_too_long_fragment",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragment_error,
      { "Fragment Error", "lte-rrc.warningMessageSegment.fragment_error",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_fragment_count,
      { "Fragment Count", "lte-rrc.warningMessageSegment.fragment_count",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_reassembled_in,
      { "Reassembled In", "lte-rrc.warningMessageSegment.reassembled_in",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_reassembled_length,
      { "Reassembled Length", "lte-rrc.warningMessageSegment.reassembled_length",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib11_reassembled_data,
      { "Reassembled Data", "lte-rrc.warningMessageSegment.reassembled_data",
         FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragments,
      { "Fragments", "lte-rrc.warningMessageSegment_r9.fragments",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragment,
      { "Fragment", "lte-rrc.warningMessageSegment_r9.fragment",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragment_overlap,
      { "Fragment Overlap", "lte-rrc.warningMessageSegment_r9.fragment_overlap",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragment_overlap_conflict,
      { "Fragment Overlap Conflict", "lte-rrc.warningMessageSegment_r9.fragment_overlap_conflict",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragment_multiple_tails,
      { "Fragment Multiple Tails", "lte-rrc.warningMessageSegment_r9.fragment_multiple_tails",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragment_too_long_fragment,
      { "Too Long Fragment", "lte-rrc.warningMessageSegment_r9.fragment_too_long_fragment",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragment_error,
      { "Fragment Error", "lte-rrc.warningMessageSegment_r9.fragment_error",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_fragment_count,
      { "Fragment Count", "lte-rrc.warningMessageSegment_r9.fragment_count",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_reassembled_in,
      { "Reassembled In", "lte-rrc.warningMessageSegment_r9.reassembled_in",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_reassembled_length,
      { "Reassembled Length", "lte-rrc.warningMessageSegment_r9.reassembled_length",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_sib12_reassembled_data,
      { "Reassembled Data", "lte-rrc.warningMessageSegment_r9.reassembled_data",
         FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit1,
      { "Gap Pattern 4", "lte-rrc.measGapPatterns_r15.bit1",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit2,
      { "Gap Pattern 5", "lte-rrc.measGapPatterns_r15.bit2",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit3,
      { "Gap Pattern 6", "lte-rrc.measGapPatterns_r15.bit3",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit4,
      { "Gap Pattern 7", "lte-rrc.measGapPatterns_r15.bit4",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit5,
      { "Gap Pattern 8", "lte-rrc.measGapPatterns_r15.bit5",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit6,
      { "Gap Pattern 9", "lte-rrc.measGapPatterns_r15.bit6",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit7,
      { "Gap Pattern 10", "lte-rrc.measGapPatterns_r15.bit7",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }},
    { &hf_lte_rrc_measGapPatterns_r15_bit8,
      { "Gap Pattern 11", "lte-rrc.measGapPatterns_r15.bit8",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }}
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_lte_rrc,
#include "packet-lte-rrc-ettarr.c"

    &ett_lte_rrc_featureGroupIndicators,
    &ett_lte_rrc_featureGroupIndRel9Add,
    &ett_lte_rrc_featureGroupIndRel10,
    &ett_lte_rrc_absTimeInfo,
    &ett_lte_rrc_nas_SecurityParam,
    &ett_lte_rrc_targetRAT_MessageContainer,
    &ett_lte_rrc_siPsiSibContainer,
    &ett_lte_rrc_dedicatedInfoNAS,
    &ett_lte_rrc_timeInfo,
    &ett_lte_rrc_serialNumber,
    &ett_lte_rrc_warningType,
    &ett_lte_rrc_dataCodingScheme,
    &ett_lte_rrc_warningMessageSegment,
    &ett_lte_rrc_interBandTDD_CA_WithDifferentConfig,
    &ett_lte_rrc_tdd_FDD_CA_PCellDuplex_r12,
    &ett_lte_rrc_aperiodicCSI_Reporting_r13,
    &ett_lte_rrc_codebook_HARQ_ACK_r13,
    &ett_lte_rrc_sr_ConfigIndex,
    &ett_lte_rrc_transmissionModeList_r12,
    &ett_lte_rrc_modifiedMPR_Behavior_r10,
    &ett_lte_rrc_sib11_fragment,
    &ett_lte_rrc_sib11_fragments,
    &ett_lte_rrc_sib12_fragment,
    &ett_lte_rrc_sib12_fragments,
    &ett_lte_rrc_nr_SecondaryCellGroupConfig_r15,
    &ett_lte_rrc_nr_RadioBearerConfig_r15,
    &ett_lte_rrc_nr_RadioBearerConfigS_r15,
    &ett_lte_rrc_sl_ConfigDedicatedForNR_r16,
    &ett_lte_rrc_nr_SecondaryCellGroupConfig,
    &ett_lte_rrc_scg_ConfigResponseNR_r15,
    &ett_lte_rrc_scg_ConfigResponseNR_r16,
    &ett_lte_rrc_measResultSCG_r15,
    &ett_lte_rrc_measResultSCG_r16,
    &ett_lte_rrc_ul_DCCH_MessageNR_r15,
    &ett_lte_rrc_ul_DCCH_MessageNR_r16,
    &ett_lte_rrc_sourceRB_ConfigNR_r15,
    &ett_lte_rrc_sourceRB_ConfigSN_NR_r15,
    &ett_lte_rrc_sourceOtherConfigSN_NR_r15,
    &ett_lte_rrc_sourceContextEN_DC_r15,
    &ett_lte_rrc_requestedFreqBandsNR_MRDC_r15,
    &ett_lte_rrc_measGapPatterns_r15,
    &ett_lte_rrc_nas_Container_r15,
    &ett_lte_rrc_sourceRB_ConfigIntra5GC_r15,
    &ett_lte_rrc_selectedbandCombinationInfoEN_DC_v1540,
    &ett_lte_rrc_requestedCapabilityCommon_r15,
    &ett_lte_rrc_sidelinkUEInformationNR_r16,
    &ett_lte_rrc_ueAssistanceInformationNR_r16,
    &ett_lte_rrc_sl_ParameterNR_r16,
    &ett_lte_rrc_v2x_BandParametersNR_r16,
    &ett_lte_rrc_ueAssistanceInformationNR_SCG_r16,
    &ett_lte_rrc_assistanceDataSIB_Element_r15,
    &ett_lte_rrc_overheatingAssistanceForSCG_r16,
    &ett_lte_rrc_overheatingAssistanceForSCG_FR2_2_r17,
    &ett_lte_rrc_triggerConditionSN_r17
  };

  static ei_register_info ei[] = {
     { &ei_lte_rrc_number_pages_le15, { "lte_rrc.number_pages_le15", PI_MALFORMED, PI_ERROR, "Number of pages should be <=15", EXPFILL }},
     { &ei_lte_rrc_si_info_value_changed, { "lte_rrc.si_info_value_changed", PI_SEQUENCE, PI_WARN, "SI Info Value changed", EXPFILL }},
     { &ei_lte_rrc_sibs_changing, { "lte_rrc.sibs_changing", PI_SEQUENCE, PI_WARN, "SIBs changing in next BCCH modification period - signalled in Paging message", EXPFILL }},
     { &ei_lte_rrc_sibs_changing_edrx, { "lte_rrc.sibs_changing_edrx", PI_SEQUENCE, PI_WARN, "SIBs changing in next BCCH modification period for UEs in eDRX mode - signalled in Paging message", EXPFILL }},
     { &ei_lte_rrc_earthquake_warning_sys, { "lte_rrc.earthquake_warning_sys", PI_SEQUENCE, PI_WARN, "Earthquake and Tsunami Warning System Indication!", EXPFILL }},
     { &ei_lte_rrc_commercial_mobile_alert_sys, { "lte_rrc.commercial_mobile_alert_sys", PI_SEQUENCE, PI_WARN, "Commercial Mobile Alert System Indication!", EXPFILL }},
     { &ei_lte_rrc_unexpected_type_value, { "lte_rrc.unexpected_type_value", PI_MALFORMED, PI_ERROR, "Unexpected type value", EXPFILL }},
     { &ei_lte_rrc_unexpected_length_value, { "lte_rrc.unexpected_length_value", PI_MALFORMED, PI_ERROR, "Unexpected type length", EXPFILL }},
     { &ei_lte_rrc_too_many_group_a_rapids, { "lte_rrc.too_many_groupa_rapids", PI_MALFORMED, PI_ERROR, "Too many group A RAPIDs", EXPFILL }},
     { &ei_lte_rrc_invalid_drx_config, { "lte_rrc.invalid_drx_config", PI_MALFORMED, PI_ERROR, "Invalid dedicated DRX config detected", EXPFILL }},
  };

  expert_module_t* expert_lte_rrc;
  module_t *lte_rrc_module;

  /* Register protocol */
  proto_lte_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* These entry points will first create an lte_rrc root node */
  lte_rrc_dl_ccch_handle = register_dissector("lte_rrc.dl_ccch", dissect_lte_rrc_DL_CCCH, proto_lte_rrc);
  register_dissector("lte_rrc.dl_dcch", dissect_lte_rrc_DL_DCCH, proto_lte_rrc);
  register_dissector("lte_rrc.ul_ccch", dissect_lte_rrc_UL_CCCH, proto_lte_rrc);
  register_dissector("lte_rrc.ul_dcch", dissect_lte_rrc_UL_DCCH, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_bch", dissect_lte_rrc_BCCH_BCH, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_dl_sch", dissect_lte_rrc_BCCH_DL_SCH, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_dl_sch_br", dissect_lte_rrc_BCCH_DL_SCH_BR, proto_lte_rrc);
  register_dissector("lte_rrc.pcch", dissect_lte_rrc_PCCH, proto_lte_rrc);
  register_dissector("lte_rrc.mcch", dissect_lte_rrc_MCCH, proto_lte_rrc);
  register_dissector("lte_rrc.handover_prep_info", dissect_lte_rrc_Handover_Preparation_Info, proto_lte_rrc);
  register_dissector("lte_rrc.sbcch_sl_bch", dissect_lte_rrc_SBCCH_SL_BCH, proto_lte_rrc);
  register_dissector("lte_rrc.sbcch_sl_bch.v2x", dissect_lte_rrc_SBCCH_SL_BCH_V2X, proto_lte_rrc);
  register_dissector("lte_rrc.sc_mcch", dissect_lte_rrc_SC_MCCH, proto_lte_rrc);
  register_dissector("lte_rrc.dl_ccch.nb", dissect_lte_rrc_DL_CCCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.dl_dcch.nb", dissect_lte_rrc_DL_DCCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.ul_ccch.nb", dissect_lte_rrc_UL_CCCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.ul_dcch.nb", dissect_lte_rrc_UL_DCCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_bch.nb", dissect_lte_rrc_BCCH_BCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_bch.nb.tdd", dissect_lte_rrc_BCCH_BCH_TDD_NB, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_dl_sch.nb", dissect_lte_rrc_BCCH_DL_SCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.pcch.nb", dissect_lte_rrc_PCCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.sc_mcch.nb", dissect_lte_rrc_SC_MCCH_NB, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_bch.mbms", dissect_lte_rrc_BCCH_BCH_MBMS, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_dl_sch.mbms", dissect_lte_rrc_BCCH_DL_SCH_MBMS, proto_lte_rrc);
  register_dissector("lte-rrc.ue_eutra_cap.msg", dissect_lte_rrc_ue_eutra_capability_msg, proto_lte_rrc);
  register_dissector("lte-rrc.ue_radio_access_cap_info.msg", dissect_lte_rrc_ueradioaccesscapabilityinformation_msg, proto_lte_rrc);
  register_dissector("lte-rrc.systeminformationblocktype1_v890_ies", dissect_lte_rrc_dissect_SystemInformationBlockType1_v890_IEs, proto_lte_rrc);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lte_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_lte_rrc = expert_register_protocol(proto_lte_rrc);
  expert_register_field_array(expert_lte_rrc, ei, array_length(ei));

  /* Register the dissectors defined in lte-rrc.conf */
#include "packet-lte-rrc-dis-reg.c"

  lte_rrc_etws_cmas_dcs_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
  lte_rrc_system_info_value_changed_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

  reassembly_table_register(&lte_rrc_sib11_reassembly_table,
                        &addresses_reassembly_table_functions);
  reassembly_table_register(&lte_rrc_sib12_reassembly_table,
                        &addresses_reassembly_table_functions);

  /* Register configuration preferences */
  lte_rrc_module = prefs_register_protocol(proto_lte_rrc, NULL);
  prefs_register_bool_preference(lte_rrc_module, "nas_in_root_tree",
                                 "Show NAS PDU in root packet details",
                                 "Whether the NAS PDU should be shown in the root packet details tree",
                                 &lte_rrc_nas_in_root_tree);
}


/*--- proto_reg_handoff_rrc ---------------------------------------*/
void
proto_reg_handoff_lte_rrc(void)
{
  dissector_add_for_decode_as_with_preference("udp.port", lte_rrc_dl_ccch_handle);
  nas_eps_handle = find_dissector("nas-eps");
  nas_5gs_handle = find_dissector("nas-5gs");
  rrc_irat_ho_to_utran_cmd_handle = find_dissector("rrc.irat.ho_to_utran_cmd");
  rrc_sys_info_cont_handle = find_dissector("rrc.sysinfo.cont");
  gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
  gsm_rlcmac_dl_handle = find_dissector("gsm_rlcmac_dl");
  nr_rrc_reconf_handle = find_dissector("nr-rrc.rrc_reconf");
  lte_rrc_conn_reconf_handle = find_dissector("lte-rrc.rrc_conn_reconf");
}


