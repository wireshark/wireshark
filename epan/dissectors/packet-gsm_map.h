/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-gsm_map.h                                                           */
/* asn2wrs.py -b -q -L -c ./gsm_map.cnf -s ./packet-gsm_map-template -D . -O ../.. ../ros/Remote-Operations-Information-Objects.asn MobileDomainDefinitions.asn MAP-ApplicationContexts.asn MAP-SS-Code.asn MAP-BS-Code.asn MAP-TS-Code.asn MAP-ExtensionDataTypes.asn MAP-CommonDataTypes.asn MAP-SS-DataTypes.asn MAP-ER-DataTypes.asn MAP-SM-DataTypes.asn MAP-OM-DataTypes.asn MAP-MS-DataTypes.asn MAP-CH-DataTypes.asn MAP-LCS-DataTypes.asn MAP-GR-DataTypes.asn MAP-DialogueInformation.asn MAP-LocationServiceOperations.asn MAP-Group-Call-Operations.asn MAP-ShortMessageServiceOperations.asn MAP-SupplementaryServiceOperations.asn MAP-CallHandlingOperations.asn MAP-OperationAndMaintenanceOperations.asn MAP-MobileServiceOperations.asn MAP-Errors.asn MAP-Protocol.asn GSMMAP.asn SS-DataTypes.asn SS-Operations.asn Ericsson.asn Nokia.asn */

/* packet-gsm_map-template.h
 * Routines for GSM MAP packet dissection
 * Copyright 2004 - 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_GSM_MAP_H
#define PACKET_GSM_MAP_H

#include "ws_symbol_export.h"

/* Defines for the GSM MAP taps */
#define	GSM_MAP_MAX_NUM_OPR_CODES	256

typedef struct _gsm_map_tap_rec_t {
  bool invoke;
  uint32_t opcode;
  uint16_t size;
} gsm_map_tap_rec_t;


#define SMS_ENCODING_NOT_SET	0
#define SMS_ENCODING_7BIT		1
#define SMS_ENCODING_8BIT		2
#define SMS_ENCODING_UCS2		3
#define SMS_ENCODING_7BIT_LANG	4
#define SMS_ENCODING_UCS2_LANG	5

WS_DLL_PUBLIC const value_string gsm_map_opr_code_strings[];

extern const value_string ssCode_vals[];
extern const value_string gsm_map_PDP_Type_Organisation_vals[];
extern const value_string gsm_map_ietf_defined_pdp_vals[];
extern const value_string gsm_map_etsi_defined_pdp_vals[];

uint8_t dissect_cbs_data_coding_scheme(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint16_t offset);
void dissect_gsm_map_msisdn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree);

typedef enum {
  GSM_MAP_SM_RP_OA_NO_ID = 0,
  GSM_MAP_SM_RP_OA_MSISDN,
  GSM_MAP_SM_RP_OA_SERVICE_CENTER_ADDRESS
} gsm_map_sm_rp_oa_id;

typedef enum {
  GSM_MAP_SM_RP_DA_NO_ID = 0,
  GSM_MAP_SM_RP_DA_IMSI,
  GSM_MAP_SM_RP_DA_LMSI,
  GSM_MAP_SM_RP_DA_SERVICE_CENTER_ADDRESS
} gsm_map_sm_rp_da_id;

/* structure accessible via p_get_proto_data(wmem_file_scope(), pinfo, proto_gsm_map, 0) */
typedef struct {
  gsm_map_sm_rp_oa_id sm_rp_oa_id;
  const char *sm_rp_oa_str;
  gsm_map_sm_rp_da_id sm_rp_da_id;
  const char *sm_rp_da_str;
  uint32_t tcap_src_tid;
} gsm_map_packet_info_t;


/* --- Module Remote-Operations-Information-Objects --- --- ---               */


/* --- Module MobileDomainDefinitions --- --- ---                             */


/* --- Module MAP-ApplicationContexts --- --- ---                             */


/* --- Module MAP-SS-Code --- --- ---                                         */

int dissect_gsm_map_SS_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module MAP-BS-Code --- --- ---                                         */


/* --- Module MAP-TS-Code --- --- ---                                         */


/* --- Module MAP-ExtensionDataTypes --- --- ---                              */

int dissect_gsm_map_ExtensionContainer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module MAP-CommonDataTypes --- --- ---                                 */

extern const value_string gsm_map_NetworkResource_vals[];
extern const value_string gsm_map_LCSClientInternalID_vals[];
extern const value_string gsm_map_LCSServiceTypeID_vals[];
extern const value_string gsm_map_CellGlobalIdOrServiceAreaIdOrLAI_vals[];
extern const value_string gsm_map_BasicServiceCode_vals[];
extern const value_string gsm_map_Ext_BasicServiceCode_vals[];
int dissect_gsm_map_TBCD_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_AddressString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_gsm_map_ISDN_AddressString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ISDN_SubaddressString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ExternalSignalInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_AlertingPattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_GSN_Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_gsm_map_IMSI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_IMEI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_gsm_map_GlobalCellId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_NetworkResource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_NAEA_CIC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_LCSClientExternalID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_LCSClientInternalID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_LCSServiceTypeID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_RAIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_LAIFixedLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_BasicServiceCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_Ext_BasicServiceCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_AgeOfLocationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ISDN_AddressString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/* --- Module MAP-SS-DataTypes --- --- ---                                    */

extern const value_string gsm_map_ss_SS_Info_vals[];
extern const value_string gsm_map_ss_InterrogateSS_Res_vals[];
int dissect_gsm_map_ss_RegisterSS_Arg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_SS_Info(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_SS_Status(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_ForwardingOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_SS_ForBS_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_CCBS_Feature(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_InterrogateSS_Res(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_USSD_Arg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_USSD_Res(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_USSD_DataCodingScheme(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_USSD_String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_RegisterCC_EntryRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_EraseCC_EntryArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ss_EraseCC_EntryRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module MAP-ER-DataTypes --- --- ---                                    */

extern const value_string gsm_map_er_UnauthorizedLCSClient_Diagnostic_vals[];
extern const value_string gsm_map_er_PositionMethodFailure_Diagnostic_vals[];
int dissect_gsm_map_er_UnauthorizedLCSClient_Diagnostic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_er_PositionMethodFailure_Diagnostic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module MAP-SM-DataTypes --- --- ---                                    */

extern const value_string gsm_map_sm_SM_RP_DA_vals[];
extern const value_string gsm_map_sm_SM_RP_OA_vals[];
int dissect_gsm_map_sm_SM_RP_DA(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_sm_SM_RP_OA(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module MAP-OM-DataTypes --- --- ---                                    */


/* --- Module MAP-MS-DataTypes --- --- ---                                    */

extern const value_string gsm_map_ms_DefaultGPRS_Handling_vals[];
extern const value_string gsm_map_ms_NotificationToMSUser_vals[];
extern const value_string gsm_map_ms_DefaultSMS_Handling_vals[];
extern const value_string gsm_map_ms_SubscriberState_vals[];
int dissect_gsm_map_ms_DefaultGPRS_Handling(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_QoS_Subscribed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_Ext_QoS_Subscribed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_Ext2_QoS_Subscribed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_Ext3_QoS_Subscribed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_LSAIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_Ext_ForwOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_Ext_NoRepCondTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_CUG_Info(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_CUG_Index(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_CUG_Interlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_NotificationToMSUser(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_D_CSI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_O_CSI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_ServiceKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_O_BcsmCamelTDPCriteriaList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_SupportedCamelPhases(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_OfferedCamel4Functionalities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_DefaultSMS_Handling(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_MS_Classmark2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_GPRSMSClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_LocationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_GeographicalInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_SubscriberState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ms_GPRSChargingID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module MAP-CH-DataTypes --- --- ---                                    */

int dissect_gsm_map_ch_CUG_CheckInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ch_SuppressionOfAnnouncement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ch_CallReferenceNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_ch_UU_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module MAP-LCS-DataTypes --- --- ---                                   */

extern const value_string gsm_map_lcs_LCSClientType_vals[];
int dissect_gsm_map_lcs_LocationType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_DeferredLocationEventType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCS_ClientID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCSClientType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCSClientName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCSRequestorID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCS_Priority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCS_QoS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_SupportedGADShapes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCS_ReferenceNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCSCodeword(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_AreaEventInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_gsm_map_lcs_Ext_GeographicalInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_VelocityEstimate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_Add_GeographicalInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_map_lcs_LCS_ClientID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/* --- Module MAP-GR-DataTypes --- --- ---                                    */


/* --- Module MAP-DialogueInformation --- --- ---                             */


/* --- Module MAP-LocationServiceOperations --- --- ---                       */


/* --- Module MAP-Group-Call-Operations --- --- ---                           */


/* --- Module MAP-ShortMessageServiceOperations --- --- ---                   */


/* --- Module MAP-SupplementaryServiceOperations --- --- ---                  */


/* --- Module MAP-CallHandlingOperations --- --- ---                          */


/* --- Module MAP-OperationAndMaintenanceOperations --- --- ---               */


/* --- Module MAP-MobileServiceOperations --- --- ---                         */


/* --- Module MAP-Errors --- --- ---                                          */


/* --- Module MAP-Protocol --- --- ---                                        */


/* --- Module DummyMAP --- --- ---                                            */

extern const value_string gsm_old_GSMMAPLocalErrorcode_vals[];
extern const value_string gsm_old_GetPasswordArg_vals[];
int dissect_gsm_old_GSMMAPLocalErrorcode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_old_NewPassword(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_old_GetPasswordArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_old_CurrentPassword(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_old_SecurityHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gsm_old_ProtectedPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module SS-DataTypes --- --- ---                                        */

extern const value_string gsm_ss_LocationMethod_vals[];
int dissect_gsm_ss_LocationMethod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module SS-Operations --- --- ---                                       */


/* --- Module EricssonMAP --- --- ---                                         */


/* --- Module NokiaMAP-Extensions --- --- ---                                 */

int dissect_NokiaMAP_Extensions_ServiceKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


#endif  /* PACKET_GSM_MAP_H */
