/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-umts_rrc_ies.h                                                    */
/* ../../tools/asn2wrs.py -u -e -p umts_rrc_ies -c umts_rrc_ies.cnf -s packet-umts_rrc_ies-template umts_rrc_InformationElements.asn */

/* Input file: packet-umts_rrc_ies-template.h */

#line 1 "packet-umts_rrc_ies-template.h"
/* packet-umts_rrc_ies.h
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification 	
 * (3GPP TS 25.331 version 6.7.0 Release 6) chapter 11.3 Information element dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 */

#ifndef PACKET_UMTS_RRC_IES_H
#define PACKET_UMTS_RRC_IES_H




/*--- Included file: packet-umts_rrc_ies-exp.h ---*/
#line 1 "packet-umts_rrc_ies-exp.h"
extern const value_string umts_rrc_ies_CN_DomainIdentity_vals[];
extern const value_string umts_rrc_ies_PagingRecordTypeID_vals[];
extern const value_string umts_rrc_ies_AccessStratumReleaseIndicator_vals[];
extern const value_string umts_rrc_ies_CellUpdateCause_vals[];
extern const value_string umts_rrc_ies_CellUpdateCause_ext_vals[];
extern const value_string umts_rrc_ies_CipheringAlgorithm_vals[];
extern const value_string umts_rrc_ies_DelayRestrictionFlag_vals[];
extern const value_string umts_rrc_ies_EstablishmentCause_vals[];
extern const value_string umts_rrc_ies_FailureCauseWithProtErr_vals[];
extern const value_string umts_rrc_ies_InitialUE_Identity_vals[];
extern const value_string umts_rrc_ies_PagingCause_vals[];
extern const value_string umts_rrc_ies_ProtocolErrorIndicator_vals[];
extern const value_string umts_rrc_ies_ProtocolErrorIndicatorWithMoreInfo_vals[];
extern const value_string umts_rrc_ies_RadioFrequencyBandTDDList_vals[];
extern const value_string umts_rrc_ies_RedirectionInfo_vals[];
extern const value_string umts_rrc_ies_RedirectionInfo_r6_vals[];
extern const value_string umts_rrc_ies_RejectionCause_vals[];
extern const value_string umts_rrc_ies_ReleaseCause_vals[];
extern const value_string umts_rrc_ies_RRC_StateIndicator_vals[];
extern const value_string umts_rrc_ies_SystemSpecificCapUpdateReq_v590ext_vals[];
extern const value_string umts_rrc_ies_URA_UpdateCause_vals[];
extern const value_string umts_rrc_ies_DefaultConfigMode_vals[];
extern const value_string umts_rrc_ies_PDCP_ROHC_TargetMode_vals[];
extern const value_string umts_rrc_ies_TFC_Subset_vals[];
extern const value_string umts_rrc_ies_BEACON_PL_Est_vals[];
extern const value_string umts_rrc_ies_DPC_Mode_vals[];
extern const value_string umts_rrc_ies_SSDT_UL_vals[];
extern const value_string umts_rrc_ies_TFC_ControlDuration_vals[];
extern const value_string umts_rrc_ies_TimeslotList_r4_vals[];
extern const value_string umts_rrc_ies_TX_DiversityMode_vals[];
extern const value_string umts_rrc_ies_UL_ChannelRequirement_vals[];
extern const value_string umts_rrc_ies_UL_ChannelRequirement_r4_vals[];
extern const value_string umts_rrc_ies_UL_ChannelRequirement_r5_vals[];
extern const value_string umts_rrc_ies_UL_ChannelRequirementWithCPCH_SetID_vals[];
extern const value_string umts_rrc_ies_UL_ChannelRequirementWithCPCH_SetID_r4_vals[];
extern const value_string umts_rrc_ies_UL_ChannelRequirementWithCPCH_SetID_r5_vals[];
extern const value_string umts_rrc_ies_UL_TimingAdvanceControl_vals[];
extern const value_string umts_rrc_ies_UL_TimingAdvanceControl_r4_vals[];
extern const value_string umts_rrc_ies_Frequency_Band_vals[];
extern const value_string umts_rrc_ies_EventResults_vals[];
extern const value_string umts_rrc_ies_MeasuredResults_vals[];
extern const value_string umts_rrc_ies_MeasuredResults_v590ext_vals[];
extern const value_string umts_rrc_ies_MeasurementCommand_vals[];
extern const value_string umts_rrc_ies_MeasurementCommand_r4_vals[];
extern const value_string umts_rrc_ies_SFN_Offset_Validity_vals[];
extern const value_string umts_rrc_ies_InterRAT_ChangeFailureCause_vals[];
extern const value_string umts_rrc_ies_InterRAT_HO_FailureCause_vals[];
extern const value_string umts_rrc_ies_SIB_Type_vals[];
extern const value_string umts_rrc_ies_MBMS_PL_ServiceRestrictInfo_r6_vals[];
int dissect_umts_rrc_ies_CN_DomainIdentity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CN_InformationInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CN_InformationInfo_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CN_InformationInfoFull(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_IntraDomainNasNodeSelector(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_NAS_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PagingRecordTypeID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PLMN_Identity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CellIdentity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CellIdentity_PerRL_List(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_URA_Identity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_AccessStratumReleaseIndicator(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_ActivationTime(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_C_RNTI(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CapabilityUpdateRequirement(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CapabilityUpdateRequirement_r4_ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CapabilityUpdateRequirement_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CellUpdateCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CellUpdateCause_ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CipheringAlgorithm(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CipheringModeInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_PhysChCapabilityFDD_v380ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DSCH_RNTI(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DelayRestrictionFlag(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_E_RNTI(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_EstablishmentCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_FailureCauseWithProtErr(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_FailureCauseWithProtErrTrId(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_GroupReleaseInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_H_RNTI(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UESpecificBehaviourInformation1idle(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UESpecificBehaviourInformation1interRAT(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InitialUE_Identity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_IntegrityCheckInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_IntegrityProtActivationInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_IntegrityProtectionModeInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_N_308(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PagingCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PagingRecordList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PagingRecord2List_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_ProtocolErrorIndicator(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_ProtocolErrorIndicatorWithMoreInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_ProtocolErrorMoreInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RadioFrequencyBandTDDList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Rb_timer_indicator(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RedirectionInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RedirectionInfo_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RejectionCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_ReleaseCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RRC_StateIndicator(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RRC_TransactionIdentifier(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SecurityCapability(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Serving_HSDSCH_CellInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_START_Value(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_STARTList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CapabilityUpdateRequirement_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SystemSpecificCapUpdateReq_v590ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_U_RNTI(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_U_RNTI_Short(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_CapabilityContainer_IEs(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_ConnTimersAndConstants(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_ConnTimersAndConstants_v3a0ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_ConnTimersAndConstants_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v370ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v380ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v3a0ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v3g0ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v650ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapabBandFDDList2(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapabBandFDDList_ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v4b0ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapabilityComp(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RF_CapabilityComp(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v590ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_RadioAccessCapability_v5c0ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_SecurityInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_SecurityInformation2(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_URA_UpdateCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UTRAN_DRX_CycleLengthCoefficient(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_WaitTime(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DefaultConfigIdentity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DefaultConfigIdentity_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DefaultConfigIdentity_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DefaultConfigMode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CounterSynchronisationInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CounterSynchronisationInfo_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PDCP_ROHC_TargetMode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PredefinedConfigIdentity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PredefinedConfigStatusList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PredefinedConfigStatusListComp(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PredefinedConfigSetWithDifferentValueTag(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_Info(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationReconfigList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_Info_Post(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationSetupList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationSetupList_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationSetupList_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationSetupList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RAB_InformationSetupList_r6_ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_ActivationTimeInfoList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_COUNT_C_InformationList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_COUNT_C_MSB_InformationList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_IdentityList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationAffectedList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationAffectedList_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationAffectedList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationChangedList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationReconfigList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationReconfigList_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationReconfigList_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationReconfigList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_InformationReleaseList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RB_PDCPContextRelocationList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SRB_InformationSetupList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SRB_InformationSetupList_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SRB_InformationSetupList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SRB_InformationSetupList2(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_CounterSynchronisationInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CPCH_SetID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_AddReconfTransChInfo2List(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_AddReconfTransChInfoList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_AddReconfTransChInfoList_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_AddReconfTransChInfoList_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CommonTransChInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CommonTransChInfo_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_DeletedTransChInfoList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_DeletedTransChInfoList_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DRAC_StaticInformationList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PowerOffsetInfoShort(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TFC_Subset(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TFCS_Identity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_AddReconfTransChInfoList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_AddReconfTransChInfoList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_CommonTransChInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_CommonTransChInfo_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DeletedTransChInfoList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DeletedTransChInfoList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Alpha(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_BEACON_PL_Est(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CCTrCH_PowerControlInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CCTrCH_PowerControlInfo_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CCTrCH_PowerControlInfo_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_ConstantValue(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_ConstantValueTdd(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CPCH_SetInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DHS_Sync(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CommonInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CommonInformation_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CommonInformation_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CommonInformation_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_CommonInformationPost(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_HSPDSCH_Information(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_HSPDSCH_Information_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_List(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_List_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_List_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_List_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_List_r5bis(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_ListPostFDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_PostTDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_InformationPerRL_PostTDD_LCR_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_PDSCH_Information(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DL_TPC_PowerOffsetPerRL_List(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DPC_Mode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DPCH_CompressedModeStatusInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DynamicPersistenceLevel(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_FrequencyInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_FrequencyInfoFDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_FrequencyInfoTDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_HARQ_Preamble_Mode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_HS_SICH_Power_Control_Info_TDD384(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MaxAllowedUL_TX_Power(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_OpenLoopPowerControl_IPDL_TDD_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PDSCH_CapacityAllocationInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PDSCH_CapacityAllocationInfo_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PDSCH_Identity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PDSCH_SysInfoList_HCR_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PrimaryCCPCH_TX_Power(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PrimaryCPICH_Info(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PUSCH_CapacityAllocationInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PUSCH_CapacityAllocationInfo_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PUSCH_Identity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PUSCH_SysInfoList_HCR_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RL_AdditionInformationList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RL_AdditionInformationList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_RL_RemovalInformationList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Scheduling_E_DCH_CellInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SpecialBurstScheduling(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SSDT_Information(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SSDT_Information_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SSDT_UL(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TFC_ControlDuration(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TimeslotList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TimeslotList_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TX_DiversityMode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_ChannelRequirement(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_ChannelRequirement_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_ChannelRequirement_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_ChannelRequirement_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_ChannelRequirementWithCPCH_SetID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_ChannelRequirementWithCPCH_SetID_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_ChannelRequirementWithCPCH_SetID_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DPCH_Info(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DPCH_Info_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DPCH_Info_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DPCH_Info_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DPCH_InfoPostFDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DPCH_InfoPostTDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_DPCH_InfoPostTDD_LCR_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_EDCH_Information_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_SynchronisationParameters_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_TimingAdvance(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_TimingAdvanceControl(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UL_TimingAdvanceControl_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_AdditionalMeasurementID_List(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Frequency_Band(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_DeltaRSCP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_EventResults(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Inter_FreqEventCriteriaList_v590ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Intra_FreqEventCriteriaList_v590ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_IntraFreqReportingCriteria_1b_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterFreqEventResults_LCR_r4_ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterRAT_TargetCellDescription(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterRATCellInfoIndication(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_IntraFreqCellID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_IntraFreqEvent_1d_r5(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasuredResults(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasuredResults_v390ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasuredResults_v590ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasuredResultsList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasuredResultsList_LCR_r4_ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasuredResultsOnRACH(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasuredResultsOnRACHinterFreq(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasurementCommand(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasurementCommand_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasurementIdentity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MeasurementReportingMode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_PrimaryCCPCH_RSCP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SFN_Offset_Validity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TimeslotListWithISCP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_TrafficVolumeMeasuredResultsList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_Positioning_GPS_AssistanceData(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_Positioning_Measurement_v390ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_Positioning_OTDOA_AssistanceData(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_Positioning_OTDOA_AssistanceData_r4ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_UE_Positioning_OTDOA_AssistanceData_UEB(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_BCCH_ModificationInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_CDMA2000_MessageList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_GERAN_SystemInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_GSM_MessageList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_GSMSecurityCapability_v6xyext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_GSM_TargetCellInfoList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterRAT_ChangeFailureCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_GERANIu_MessageList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterRAT_UE_RadioAccessCapabilityList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterRAT_UE_RadioAccessCapability_v590ext(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterRAT_UE_SecurityCapList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_InterRAT_HO_FailureCause(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Rplmn_Information(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_Rplmn_Information_r4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SegCount(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SegmentIndex(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SFN_Prime(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SIB_Data_fixed(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SIB_Data_variable(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_SIB_Type(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_CellGroupIdentity_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_CommonRBInformationList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_CurrentCell_SCCPCHList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_JoinedInformation_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_MICHConfigurationInfo_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_ModifedServiceList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_PtMActivationTime(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_MSCHConfigurationInfo_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_NeighbouringCellSCCPCHList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_NumberOfNeighbourCells_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_PhyChInformationList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_PL_ServiceRestrictInfo_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_PreferredFreqRequest_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_PreferredFrequencyList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_ServiceAccessInfoList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_ServiceIdentity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_ServiceSchedulingInfoList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_SIBType5_SCCPCHList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_TimersAndCouneters_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_TranspChInfoForEachCCTrCh_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_TranspChInfoForEachTrCh_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_ies_MBMS_UnmodifiedServiceList_r6(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

/*--- End of included file: packet-umts_rrc_ies-exp.h ---*/
#line 34 "packet-umts_rrc_ies-template.h"

#endif  /* PACKET_UMTS_RRC_IES_H */


