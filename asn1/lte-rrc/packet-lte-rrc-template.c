/* packet-lte-rrc-template.c
 * Routines for Evolved Universal Terrestrial Radio Access (E-UTRA);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 36.331 V11.1.0 Release 11) packet dissection
 * Copyright 2008, Vincent Helfre
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-rrc.h"
#include "packet-gsm_a_common.h"
#include "packet-lpp.h"

#define PNAME  "LTE Radio Resource Control (RRC) protocol"
#define PSNAME "LTE RRC"
#define PFNAME "lte_rrc"

static dissector_handle_t nas_eps_handle = NULL;
static dissector_handle_t rrc_irat_ho_to_utran_cmd_handle = NULL;
static dissector_handle_t rrc_sys_info_cont_handle = NULL;
static dissector_handle_t gsm_a_dtap_handle = NULL;
static dissector_handle_t gsm_rlcmac_dl_handle = NULL;
static guint32 lte_rrc_rat_type_value = -1;
static guint32 lte_rrc_ho_target_rat_type_value = -1;
static gint lte_rrc_si_or_psi_geran_val = -1;

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

/* Initialize the subtree pointers */
static int ett_lte_rrc = -1;

#include "packet-lte-rrc-ett.c"

static gint ett_lte_rrc_featureGroupIndicators = -1;
static gint ett_lte_rrc_featureGroupIndRel9Add = -1;
static gint ett_lte_rrc_featureGroupIndRel10 = -1;
static gint ett_lte_rrc_neighCellConfig = -1;
static gint ett_lte_rrc_absTimeInfo = -1;
static gint ett_lte_rrc_nas_SecurityParam = -1;
static gint ett_lte_rrc_targetRAT_MessageContainer = -1;
static gint ett_lte_rrc_siPsiSibContainer = -1;
static gint ett_lte_rrc_dedicatedInfoNAS = -1;

/* Forward declarations */
static int dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_UECapabilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_UE_EUTRA_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static const true_false_string lte_rrc_eutra_cap_feat_group_ind_1_val = {
  "Intra-subframe freq hopping for PUSCH scheduled by UL grant; DCI format 3a; PDSCH transmission mode 5; Aperiodic CQI/PMI/RI report on PUSCH: Mode 2-0 & 2-2 - Supported",
  "Intra-subframe freq hopping for PUSCH scheduled by UL grant; DCI format 3a; PDSCH transmission mode 5; Aperiodic CQI/PMI/RI report on PUSCH: Mode 2-0 & 2-2 - Not supported"
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
  "Undefined - Supported",
  "Undefined - Not supported"
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
  "Undefined - Supported",
  "Undefined - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_42_val = {
  "Undefined - Supported",
  "Undefined - Not supported"
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

static const value_string lte_rrc_a3_a6_Offset_vals[] = {
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
static value_string_ext lte_rrc_a3_a6_Offset_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_a3_a6_Offset_vals);

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

static const value_string lte_rrc_RSRQ_Range_vals[] = {
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
  {  0, NULL}
};
static value_string_ext lte_rrc_RSRQ_Range_vals_ext = VALUE_STRING_EXT_INIT(lte_rrc_RSRQ_Range_vals);

static const true_false_string lte_rrc_duration_val = {
  "indefinite",
  "single"
};

#include "packet-lte-rrc-fn.c"

static void
dissect_lte_rrc_DL_CCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_CCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_DL_CCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
}

static void
dissect_lte_rrc_DL_DCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_DCCH");
  col_clear(pinfo->cinfo, COL_INFO);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_DL_DCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
}


static void
dissect_lte_rrc_UL_CCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UL_CCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_UL_CCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
}

static void
dissect_lte_rrc_UL_DCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC UL_DCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_UL_DCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
}

static void
dissect_lte_rrc_BCCH_BCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC BCCH_BCH");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_BCCH_BCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
}

static void
dissect_lte_rrc_BCCH_DL_SCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC DL_SCH");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_BCCH_DL_SCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
}

static void
dissect_lte_rrc_PCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC PCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_PCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
}

static void
dissect_lte_rrc_MCCH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lte_rrc_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTE RRC MCCH");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_lte_rrc, tvb, 0, -1, ENC_NA);
    lte_rrc_tree = proto_item_add_subtree(ti, ett_lte_rrc);
    dissect_MCCH_Message_PDU(tvb, pinfo, lte_rrc_tree, NULL);
  }
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
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_lte_rrc,
#include "packet-lte-rrc-ettarr.c"

    &ett_lte_rrc_featureGroupIndicators,
    &ett_lte_rrc_featureGroupIndRel9Add,
    &ett_lte_rrc_featureGroupIndRel10,
    &ett_lte_rrc_neighCellConfig,
    &ett_lte_rrc_absTimeInfo,
    &ett_lte_rrc_nas_SecurityParam,
    &ett_lte_rrc_targetRAT_MessageContainer,
    &ett_lte_rrc_siPsiSibContainer,
    &ett_lte_rrc_dedicatedInfoNAS
  };


  /* Register protocol */
  proto_lte_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* These entry points will first create an lte_rrc root node */
  register_dissector("lte_rrc.dl_ccch", dissect_lte_rrc_DL_CCCH, proto_lte_rrc);
  register_dissector("lte_rrc.dl_dcch", dissect_lte_rrc_DL_DCCH, proto_lte_rrc);
  register_dissector("lte_rrc.ul_ccch", dissect_lte_rrc_UL_CCCH, proto_lte_rrc);
  register_dissector("lte_rrc.ul_dcch", dissect_lte_rrc_UL_DCCH, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_bch", dissect_lte_rrc_BCCH_BCH, proto_lte_rrc);
  register_dissector("lte_rrc.bcch_dl_sch", dissect_lte_rrc_BCCH_DL_SCH, proto_lte_rrc);
  register_dissector("lte_rrc.pcch", dissect_lte_rrc_PCCH, proto_lte_rrc);
  register_dissector("lte_rrc.mcch", dissect_lte_rrc_MCCH, proto_lte_rrc);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lte_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissectors defined in lte-rrc.conf */
#include "packet-lte-rrc-dis-reg.c"

}


/*--- proto_reg_handoff_rrc ---------------------------------------*/
void
proto_reg_handoff_lte_rrc(void)
{
	static dissector_handle_t lte_rrc_dl_ccch_handle;

	lte_rrc_dl_ccch_handle = find_dissector("lte_rrc.dl_ccch");
	dissector_add_handle("udp.port", lte_rrc_dl_ccch_handle);
	nas_eps_handle = find_dissector("nas-eps");
	rrc_irat_ho_to_utran_cmd_handle = find_dissector("rrc.irat.ho_to_utran_cmd");
	rrc_sys_info_cont_handle = find_dissector("rrc.sysinfo.cont");
	gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
	gsm_rlcmac_dl_handle = find_dissector("gsm_rlcmac_dl");
}


