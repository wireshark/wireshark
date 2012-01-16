/* packet-lte-rrc-template.c
 * Routines for Evolved Universal Terrestrial Radio Access (E-UTRA);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 36.331 V10.4.0 Release 10) packet dissection
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

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
static gint ett_lte_rrc_featureGroupIndicatorsV1020 = -1;
static gint ett_lte_rrc_neighCellConfig = -1;
static gint ett_lte_rrc_absTimeInfo = -1;

/* Forward declarations */
static int dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);
static int dissect_UECapabilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);
int dissect_lte_rrc_UE_EUTRA_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);

static const true_false_string lte_rrc_eutra_cap_feat_group_ind_1_val = {
  "Intra-subframe freq hopping for PUSCH scheduled by UL grant; DCI format 3a; PDSCH transmission mode 5; Aperiodic CQI/PMI/RI report on PUSCH: Mode 2-0 and 2-2 - Supported",
  "Intra-subframe freq hopping for PUSCH scheduled by UL grant; DCI format 3a; PDSCH transmission mode 5; Aperiodic CQI/PMI/RI report on PUSCH: Mode 2-0 and 2-2 - Not supported"
};
static const true_false_string lte_rrc_eutra_cap_feat_group_ind_2_val = {
  "Simultaneous CQI and ACK/NACK on PUCCH (format 2a/2b); Absolute TPC command for PUSCH; Resource alloc type 1 for PDSCH; Periodic CQI/PMI/RI report on PUCCH: Mode 2-0 and 2-1 - Supported",
  "Simultaneous CQI and ACK/NACK on PUCCH (format 2a/2b); Absolute TPC command for PUSCH; Resource alloc type 1 for PDSCH; Periodic CQI/PMI/RI report on PUCCH: Mode 2-0 and 2-1 - Not supported"
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
		dissect_DL_CCCH_Message_PDU(tvb, pinfo, lte_rrc_tree);
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
		dissect_DL_DCCH_Message_PDU(tvb, pinfo, lte_rrc_tree);
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
		dissect_UL_CCCH_Message_PDU(tvb, pinfo, lte_rrc_tree);
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
		dissect_UL_DCCH_Message_PDU(tvb, pinfo, lte_rrc_tree);
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
		dissect_BCCH_BCH_Message_PDU(tvb, pinfo, lte_rrc_tree);
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
		dissect_BCCH_DL_SCH_Message_PDU(tvb, pinfo, lte_rrc_tree);
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
    &ett_lte_rrc_featureGroupIndicatorsV1020,
    &ett_lte_rrc_neighCellConfig,
    &ett_lte_rrc_absTimeInfo,
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


