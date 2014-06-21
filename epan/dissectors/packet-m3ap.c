/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-m3ap.c                                                              */
/* ../../tools/asn2wrs.py -p m3ap -c ./m3ap.cnf -s ./packet-m3ap-template -D . -O ../../epan/dissectors M3AP-CommonDataTypes.asn M3AP-Constants.asn M3AP-Containers.asn M3AP-IEs.asn M3AP-PDU-Contents.asn M3AP-PDU-Descriptions.asn */

/* Input file: packet-m3ap-template.c */

#line 1 "../../asn1/m3ap/packet-m3ap-template.c"
/* packet-m3ap.c
 * Routines for M3 Application Protocol packet dissection
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
 * Reference: 3GPP TS 36.444 v11.0.0
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gtpv2.h"
#include "packet-ntp.h"

#define PNAME  "M3 Application Protocol"
#define PSNAME "M3AP"
#define PFNAME "m3ap"

void proto_register_m3ap(void);
void proto_reg_handoff_m3ap(void);

/* M3AP uses port 36444 as recommended by IANA. */
#define M3AP_PORT 36444
static dissector_handle_t m3ap_handle=NULL;


/*--- Included file: packet-m3ap-val.h ---*/
#line 1 "../../asn1/m3ap/packet-m3ap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxnoofMBMSServiceAreaIdentitiesPerMCE 65536
#define maxnooferrors                  256
#define maxNrOfIndividualM3ConnectionsToReset 256

typedef enum _ProcedureCode_enum {
  id_mBMSsessionStart =   0,
  id_mBMSsessionStop =   1,
  id_errorIndication =   2,
  id_privateMessage =   3,
  id_Reset     =   4,
  id_mBMSsessionUpdate =   5,
  id_mCEConfigurationUpdate =   6,
  id_m3Setup   =   7
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_MME_MBMS_M3AP_ID =   0,
  id_MCE_MBMS_M3AP_ID =   1,
  id_TMGI      =   2,
  id_MBMS_Session_ID =   3,
  id_MBMS_E_RAB_QoS_Parameters =   4,
  id_MBMS_Session_Duration =   5,
  id_MBMS_Service_Area =   6,
  id_TNL_Information =   7,
  id_CriticalityDiagnostics =   8,
  id_Cause     =   9,
  id_MBMS_Service_Area_List =  10,
  id_MBMS_Service_Area_List_Item =  11,
  id_TimeToWait =  12,
  id_ResetType =  13,
  id_MBMS_Service_associatedLogicalM3_ConnectionItem =  14,
  id_MBMS_Service_associatedLogicalM3_ConnectionListResAck =  15,
  id_MinimumTimeToMBMSDataTransfer =  16,
  id_AllocationAndRetentionPriority =  17,
  id_Global_MCE_ID =  18,
  id_MCEname   =  19,
  id_MBMSServiceAreaList =  20,
  id_Time_ofMBMS_DataTransfer =  21,
  id_Time_ofMBMS_DataStop =  22
} ProtocolIE_ID_enum;

/*--- End of included file: packet-m3ap-val.h ---*/
#line 52 "../../asn1/m3ap/packet-m3ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_m3ap = -1;

static int hf_m3ap_Absolute_Time_ofMBMS_Data_value = -1;
static int hf_m3ap_IPAddress = -1;


/*--- Included file: packet-m3ap-hf.c ---*/
#line 1 "../../asn1/m3ap/packet-m3ap-hf.c"
static int hf_m3ap_Absolute_Time_ofMBMS_Data_PDU = -1;  /* Absolute_Time_ofMBMS_Data */
static int hf_m3ap_AllocationAndRetentionPriority_PDU = -1;  /* AllocationAndRetentionPriority */
static int hf_m3ap_Cause_PDU = -1;                /* Cause */
static int hf_m3ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_m3ap_Global_MCE_ID_PDU = -1;        /* Global_MCE_ID */
static int hf_m3ap_MBMS_E_RAB_QoS_Parameters_PDU = -1;  /* MBMS_E_RAB_QoS_Parameters */
static int hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem_PDU = -1;  /* MBMS_Service_associatedLogicalM3_ConnectionItem */
static int hf_m3ap_MBMS_Service_Area_PDU = -1;    /* MBMS_Service_Area */
static int hf_m3ap_MBMS_Session_Duration_PDU = -1;  /* MBMS_Session_Duration */
static int hf_m3ap_MBMS_Session_ID_PDU = -1;      /* MBMS_Session_ID */
static int hf_m3ap_MCE_MBMS_M3AP_ID_PDU = -1;     /* MCE_MBMS_M3AP_ID */
static int hf_m3ap_MCEname_PDU = -1;              /* MCEname */
static int hf_m3ap_MinimumTimeToMBMSDataTransfer_PDU = -1;  /* MinimumTimeToMBMSDataTransfer */
static int hf_m3ap_MME_MBMS_M3AP_ID_PDU = -1;     /* MME_MBMS_M3AP_ID */
static int hf_m3ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_m3ap_TMGI_PDU = -1;                 /* TMGI */
static int hf_m3ap_TNL_Information_PDU = -1;      /* TNL_Information */
static int hf_m3ap_MBMSSessionStartRequest_PDU = -1;  /* MBMSSessionStartRequest */
static int hf_m3ap_MBMSSessionStartResponse_PDU = -1;  /* MBMSSessionStartResponse */
static int hf_m3ap_MBMSSessionStartFailure_PDU = -1;  /* MBMSSessionStartFailure */
static int hf_m3ap_MBMSSessionStopRequest_PDU = -1;  /* MBMSSessionStopRequest */
static int hf_m3ap_MBMSSessionStopResponse_PDU = -1;  /* MBMSSessionStopResponse */
static int hf_m3ap_MBMSSessionUpdateRequest_PDU = -1;  /* MBMSSessionUpdateRequest */
static int hf_m3ap_MBMSSessionUpdateResponse_PDU = -1;  /* MBMSSessionUpdateResponse */
static int hf_m3ap_MBMSSessionUpdateFailure_PDU = -1;  /* MBMSSessionUpdateFailure */
static int hf_m3ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_m3ap_Reset_PDU = -1;                /* Reset */
static int hf_m3ap_ResetType_PDU = -1;            /* ResetType */
static int hf_m3ap_ResetAcknowledge_PDU = -1;     /* ResetAcknowledge */
static int hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck_PDU = -1;  /* MBMS_Service_associatedLogicalM3_ConnectionListResAck */
static int hf_m3ap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_m3ap_M3SetupRequest_PDU = -1;       /* M3SetupRequest */
static int hf_m3ap_MBMSServiceAreaListItem_PDU = -1;  /* MBMSServiceAreaListItem */
static int hf_m3ap_M3SetupResponse_PDU = -1;      /* M3SetupResponse */
static int hf_m3ap_M3SetupFailure_PDU = -1;       /* M3SetupFailure */
static int hf_m3ap_MCEConfigurationUpdate_PDU = -1;  /* MCEConfigurationUpdate */
static int hf_m3ap_MCEConfigurationUpdateAcknowledge_PDU = -1;  /* MCEConfigurationUpdateAcknowledge */
static int hf_m3ap_MCEConfigurationUpdateFailure_PDU = -1;  /* MCEConfigurationUpdateFailure */
static int hf_m3ap_M3AP_PDU_PDU = -1;             /* M3AP_PDU */
static int hf_m3ap_local = -1;                    /* INTEGER_0_maxPrivateIEs */
static int hf_m3ap_global = -1;                   /* OBJECT_IDENTIFIER */
static int hf_m3ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_m3ap_id = -1;                       /* ProtocolIE_ID */
static int hf_m3ap_criticality = -1;              /* Criticality */
static int hf_m3ap_ie_field_value = -1;           /* T_ie_field_value */
static int hf_m3ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_m3ap_ext_id = -1;                   /* ProtocolIE_ID */
static int hf_m3ap_extensionValue = -1;           /* T_extensionValue */
static int hf_m3ap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_m3ap_private_id = -1;               /* PrivateIE_ID */
static int hf_m3ap_private_value = -1;            /* T_private_value */
static int hf_m3ap_priorityLevel = -1;            /* PriorityLevel */
static int hf_m3ap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_m3ap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_m3ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_m3ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_m3ap_transport = -1;                /* CauseTransport */
static int hf_m3ap_nAS = -1;                      /* CauseNAS */
static int hf_m3ap_protocol = -1;                 /* CauseProtocol */
static int hf_m3ap_misc = -1;                     /* CauseMisc */
static int hf_m3ap_procedureCode = -1;            /* ProcedureCode */
static int hf_m3ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_m3ap_procedureCriticality = -1;     /* Criticality */
static int hf_m3ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_m3ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_m3ap_iECriticality = -1;            /* Criticality */
static int hf_m3ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_m3ap_typeOfError = -1;              /* TypeOfError */
static int hf_m3ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_m3ap_mCE_ID = -1;                   /* MCE_ID */
static int hf_m3ap_extendedMCE_ID = -1;           /* ExtendedMCE_ID */
static int hf_m3ap_mBMS_E_RAB_MaximumBitrateDL = -1;  /* BitRate */
static int hf_m3ap_mBMS_E_RAB_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_m3ap_qCI = -1;                      /* QCI */
static int hf_m3ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_m3ap_mME_MBMS_M3AP_ID = -1;         /* MME_MBMS_M3AP_ID */
static int hf_m3ap_mCE_MBMS_M3AP_ID = -1;         /* MCE_MBMS_M3AP_ID */
static int hf_m3ap_pLMNidentity = -1;             /* PLMN_Identity */
static int hf_m3ap_serviceID = -1;                /* OCTET_STRING_SIZE_3 */
static int hf_m3ap_iPMCAddress = -1;              /* IPAddress */
static int hf_m3ap_iPSourceAddress = -1;          /* IPAddress */
static int hf_m3ap_gTP_DLTEID = -1;               /* GTP_TEID */
static int hf_m3ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_m3ap_m3_Interface = -1;             /* ResetAll */
static int hf_m3ap_partOfM3_Interface = -1;       /* MBMS_Service_associatedLogicalM3_ConnectionListRes */
static int hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes_item = -1;  /* ProtocolIE_Single_Container */
static int hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck_item = -1;  /* ProtocolIE_Single_Container */
static int hf_m3ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_m3ap_MBMSServiceAreaListItem_item = -1;  /* MBMSServiceArea1 */
static int hf_m3ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_m3ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_m3ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_m3ap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_m3ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_m3ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-m3ap-hf.c ---*/
#line 60 "../../asn1/m3ap/packet-m3ap-template.c"

/* Initialize the subtree pointers */
static int ett_m3ap = -1;


/*--- Included file: packet-m3ap-ett.c ---*/
#line 1 "../../asn1/m3ap/packet-m3ap-ett.c"
static gint ett_m3ap_PrivateIE_ID = -1;
static gint ett_m3ap_ProtocolIE_Container = -1;
static gint ett_m3ap_ProtocolIE_Field = -1;
static gint ett_m3ap_ProtocolExtensionContainer = -1;
static gint ett_m3ap_ProtocolExtensionField = -1;
static gint ett_m3ap_PrivateIE_Container = -1;
static gint ett_m3ap_PrivateIE_Field = -1;
static gint ett_m3ap_AllocationAndRetentionPriority = -1;
static gint ett_m3ap_Cause = -1;
static gint ett_m3ap_CriticalityDiagnostics = -1;
static gint ett_m3ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_m3ap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_m3ap_Global_MCE_ID = -1;
static gint ett_m3ap_GBR_QosInformation = -1;
static gint ett_m3ap_MBMS_E_RAB_QoS_Parameters = -1;
static gint ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem = -1;
static gint ett_m3ap_TMGI = -1;
static gint ett_m3ap_TNL_Information = -1;
static gint ett_m3ap_MBMSSessionStartRequest = -1;
static gint ett_m3ap_MBMSSessionStartResponse = -1;
static gint ett_m3ap_MBMSSessionStartFailure = -1;
static gint ett_m3ap_MBMSSessionStopRequest = -1;
static gint ett_m3ap_MBMSSessionStopResponse = -1;
static gint ett_m3ap_MBMSSessionUpdateRequest = -1;
static gint ett_m3ap_MBMSSessionUpdateResponse = -1;
static gint ett_m3ap_MBMSSessionUpdateFailure = -1;
static gint ett_m3ap_ErrorIndication = -1;
static gint ett_m3ap_Reset = -1;
static gint ett_m3ap_ResetType = -1;
static gint ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes = -1;
static gint ett_m3ap_ResetAcknowledge = -1;
static gint ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck = -1;
static gint ett_m3ap_PrivateMessage = -1;
static gint ett_m3ap_M3SetupRequest = -1;
static gint ett_m3ap_MBMSServiceAreaListItem = -1;
static gint ett_m3ap_M3SetupResponse = -1;
static gint ett_m3ap_M3SetupFailure = -1;
static gint ett_m3ap_MCEConfigurationUpdate = -1;
static gint ett_m3ap_MCEConfigurationUpdateAcknowledge = -1;
static gint ett_m3ap_MCEConfigurationUpdateFailure = -1;
static gint ett_m3ap_M3AP_PDU = -1;
static gint ett_m3ap_InitiatingMessage = -1;
static gint ett_m3ap_SuccessfulOutcome = -1;
static gint ett_m3ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-m3ap-ett.c ---*/
#line 65 "../../asn1/m3ap/packet-m3ap-template.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
/*static guint32 ProtocolExtensionID; */
static int global_m3ap_port = M3AP_PORT;
static guint32 message_type;

/* Dissector tables */
static dissector_table_t m3ap_ies_dissector_table;
static dissector_table_t m3ap_extension_dissector_table;
static dissector_table_t m3ap_proc_imsg_dissector_table;
static dissector_table_t m3ap_proc_sout_dissector_table;
static dissector_table_t m3ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


/*--- Included file: packet-m3ap-fn.c ---*/
#line 1 "../../asn1/m3ap/packet-m3ap-fn.c"

static const value_string m3ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_m3ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_m3ap_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, FALSE);

  return offset;
}



static int
dissect_m3ap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string m3ap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_m3ap_local          , ASN1_NO_EXTENSIONS     , dissect_m3ap_INTEGER_0_maxPrivateIEs },
  {   1, &hf_m3ap_global         , ASN1_NO_EXTENSIONS     , dissect_m3ap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_m3ap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_m3ap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string m3ap_ProcedureCode_vals[] = {
  { id_mBMSsessionStart, "id-mBMSsessionStart" },
  { id_mBMSsessionStop, "id-mBMSsessionStop" },
  { id_errorIndication, "id-errorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { id_Reset, "id-Reset" },
  { id_mBMSsessionUpdate, "id-mBMSsessionUpdate" },
  { id_mCEConfigurationUpdate, "id-mCEConfigurationUpdate" },
  { id_m3Setup, "id-m3Setup" },
  { 0, NULL }
};

static value_string_ext m3ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(m3ap_ProcedureCode_vals);


static int
dissect_m3ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 66 "../../asn1/m3ap/m3ap.cnf"
     col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s",
                 val_to_str_ext(ProcedureCode, &m3ap_ProcedureCode_vals_ext,
                            "unknown message"));

  return offset;
}


static const value_string m3ap_ProtocolIE_ID_vals[] = {
  { id_MME_MBMS_M3AP_ID, "id-MME-MBMS-M3AP-ID" },
  { id_MCE_MBMS_M3AP_ID, "id-MCE-MBMS-M3AP-ID" },
  { id_TMGI, "id-TMGI" },
  { id_MBMS_Session_ID, "id-MBMS-Session-ID" },
  { id_MBMS_E_RAB_QoS_Parameters, "id-MBMS-E-RAB-QoS-Parameters" },
  { id_MBMS_Session_Duration, "id-MBMS-Session-Duration" },
  { id_MBMS_Service_Area, "id-MBMS-Service-Area" },
  { id_TNL_Information, "id-TNL-Information" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_Cause, "id-Cause" },
  { id_MBMS_Service_Area_List, "id-MBMS-Service-Area-List" },
  { id_MBMS_Service_Area_List_Item, "id-MBMS-Service-Area-List-Item" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_ResetType, "id-ResetType" },
  { id_MBMS_Service_associatedLogicalM3_ConnectionItem, "id-MBMS-Service-associatedLogicalM3-ConnectionItem" },
  { id_MBMS_Service_associatedLogicalM3_ConnectionListResAck, "id-MBMS-Service-associatedLogicalM3-ConnectionListResAck" },
  { id_MinimumTimeToMBMSDataTransfer, "id-MinimumTimeToMBMSDataTransfer" },
  { id_AllocationAndRetentionPriority, "id-AllocationAndRetentionPriority" },
  { id_Global_MCE_ID, "id-Global-MCE-ID" },
  { id_MCEname, "id-MCEname" },
  { id_MBMSServiceAreaList, "id-MBMSServiceAreaList" },
  { id_Time_ofMBMS_DataTransfer, "id-Time-ofMBMS-DataTransfer" },
  { id_Time_ofMBMS_DataStop, "id-Time-ofMBMS-DataStop" },
  { 0, NULL }
};

static value_string_ext m3ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(m3ap_ProtocolIE_ID_vals);


static int
dissect_m3ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, FALSE);

#line 51 "../../asn1/m3ap/m3ap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str_ext(ProtocolIE_ID, &m3ap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string m3ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_m3ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_m3ap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_m3ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_ID },
  { &hf_m3ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Criticality },
  { &hf_m3ap_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_m3ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Field },
};

static int
dissect_m3ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_m3ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_m3ap_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_m3ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_m3ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_m3ap_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_ID },
  { &hf_m3ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Criticality },
  { &hf_m3ap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_m3ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolExtensionField },
};

static int
dissect_m3ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_m3ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_m3ap_T_private_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_m3ap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_PrivateIE_ID },
  { &hf_m3ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Criticality },
  { &hf_m3ap_private_value  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_T_private_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_m3ap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_PrivateIE_Field },
};

static int
dissect_m3ap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_m3ap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_m3ap_Absolute_Time_ofMBMS_Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 146 "../../asn1/m3ap/m3ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  const gchar *time_str;
  gint tvb_len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, &parameter_tvb, NULL);


  if (!parameter_tvb)
    return offset;

  tvb_len = tvb_length(parameter_tvb);

  time_str = tvb_ntp_fmt_ts(parameter_tvb, 0);
  proto_tree_add_string(tree, hf_m3ap_Absolute_Time_ofMBMS_Data_value, parameter_tvb, 0, tvb_len, time_str);


  return offset;
}


static const value_string m3ap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_m3ap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string m3ap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_m3ap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string m3ap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_m3ap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationAndRetentionPriority_sequence[] = {
  { &hf_m3ap_priorityLevel  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_PriorityLevel },
  { &hf_m3ap_pre_emptionCapability, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Pre_emptionCapability },
  { &hf_m3ap_pre_emptionVulnerability, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Pre_emptionVulnerability },
  { &hf_m3ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_AllocationAndRetentionPriority, AllocationAndRetentionPriority_sequence);

  return offset;
}



static int
dissect_m3ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(10000000000), NULL, FALSE);

  return offset;
}


static const value_string m3ap_CauseRadioNetwork_vals[] = {
  {   0, "unknown-or-already-allocated-MME-MBMS-M3AP-ID" },
  {   1, "unknown-or-already-allocated-MCE-MBMS-M3AP-ID" },
  {   2, "unknown-or-inconsistent-pair-of-MBMS-M3AP-IDs" },
  {   3, "radio-resources-not-available" },
  {   4, "invalid-QoS-combination" },
  {   5, "interaction-with-other-procedure" },
  {   6, "not-supported-QCI-value" },
  {   7, "unspecified" },
  { 0, NULL }
};


static int
dissect_m3ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string m3ap_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_m3ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string m3ap_CauseNAS_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_m3ap_CauseNAS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string m3ap_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "abstract-syntax-error-falsely-constructed-message" },
  {   6, "unspecified" },
  { 0, NULL }
};


static int
dissect_m3ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string m3ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "not-enough-user-plane-processing-resources" },
  {   2, "hardware-failure" },
  {   3, "om-intervention" },
  {   4, "unspecified" },
  { 0, NULL }
};


static int
dissect_m3ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string m3ap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "nAS" },
  {   3, "protocol" },
  {   4, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_m3ap_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_m3ap_CauseRadioNetwork },
  {   1, &hf_m3ap_transport      , ASN1_EXTENSION_ROOT    , dissect_m3ap_CauseTransport },
  {   2, &hf_m3ap_nAS            , ASN1_EXTENSION_ROOT    , dissect_m3ap_CauseNAS },
  {   3, &hf_m3ap_protocol       , ASN1_EXTENSION_ROOT    , dissect_m3ap_CauseProtocol },
  {   4, &hf_m3ap_misc           , ASN1_EXTENSION_ROOT    , dissect_m3ap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_m3ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_m3ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const value_string m3ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_m3ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_m3ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_Criticality },
  { &hf_m3ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_ID },
  { &hf_m3ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_TypeOfError },
  { &hf_m3ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_m3ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_m3ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_m3ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxnooferrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_m3ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProcedureCode },
  { &hf_m3ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_TriggeringMessage },
  { &hf_m3ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_Criticality },
  { &hf_m3ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_CriticalityDiagnostics_IE_List },
  { &hf_m3ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_m3ap_ExtendedMCE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_m3ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 122 "../../asn1/m3ap/m3ap.cnf"
  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);

	if (!parameter_tvb)
		return offset;
	dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, FALSE);


  return offset;
}



static int
dissect_m3ap_MCE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t Global_MCE_ID_sequence[] = {
  { &hf_m3ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_PLMN_Identity },
  { &hf_m3ap_mCE_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_MCE_ID },
  { &hf_m3ap_extendedMCE_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ExtendedMCE_ID },
  { &hf_m3ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_Global_MCE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_Global_MCE_ID, Global_MCE_ID_sequence);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_m3ap_mBMS_E_RAB_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_BitRate },
  { &hf_m3ap_mBMS_E_RAB_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_BitRate },
  { &hf_m3ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}



static int
dissect_m3ap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_m3ap_IPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 133 "../../asn1/m3ap/m3ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  gint tvb_len;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 16, TRUE, &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  tvb_len = tvb_length(parameter_tvb);
  proto_tree_add_item(tree, hf_m3ap_IPAddress, parameter_tvb, 0, tvb_len, ENC_NA);


  return offset;
}



static int
dissect_m3ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MBMS_E_RAB_QoS_Parameters_sequence[] = {
  { &hf_m3ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_QCI },
  { &hf_m3ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_GBR_QosInformation },
  { &hf_m3ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMS_E_RAB_QoS_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMS_E_RAB_QoS_Parameters, MBMS_E_RAB_QoS_Parameters_sequence);

  return offset;
}



static int
dissect_m3ap_MME_MBMS_M3AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_m3ap_MCE_MBMS_M3AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MBMS_Service_associatedLogicalM3_ConnectionItem_sequence[] = {
  { &hf_m3ap_mME_MBMS_M3AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_MME_MBMS_M3AP_ID },
  { &hf_m3ap_mCE_MBMS_M3AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_MCE_MBMS_M3AP_ID },
  { &hf_m3ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem, MBMS_Service_associatedLogicalM3_ConnectionItem_sequence);

  return offset;
}



static int
dissect_m3ap_MBMSServiceArea1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_m3ap_MBMS_Service_Area(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 162 "../../asn1/m3ap/m3ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  guint16 tvb_len;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  tvb_len = tvb_length(parameter_tvb);

  dissect_gtpv2_mbms_service_area(parameter_tvb, actx->pinfo, tree, actx->created_item, tvb_len, 0, 0);


  return offset;
}



static int
dissect_m3ap_MBMS_Session_Duration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 176 "../../asn1/m3ap/m3ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  guint16 tvb_len;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  tvb_len = tvb_length(parameter_tvb);

  proto_item_append_text(actx->created_item, " ");
  dissect_gtpv2_mbms_session_duration(parameter_tvb, actx->pinfo, tree, actx->created_item, tvb_len, 0, 0);


  return offset;
}



static int
dissect_m3ap_MBMS_Session_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_m3ap_MCEname(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_m3ap_MinimumTimeToMBMSDataTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 192 "../../asn1/m3ap/m3ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  guint16 tvb_len;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  tvb_len = tvb_length(parameter_tvb);
  dissect_gtpv2_mbms_time_to_data_xfer(parameter_tvb, actx->pinfo, tree, actx->created_item, tvb_len, 0, 0);


  return offset;
}


static const value_string m3ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_m3ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_m3ap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t TMGI_sequence[] = {
  { &hf_m3ap_pLMNidentity   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_PLMN_Identity },
  { &hf_m3ap_serviceID      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_OCTET_STRING_SIZE_3 },
  { &hf_m3ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_TMGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_TMGI, TMGI_sequence);

  return offset;
}


static const per_sequence_t TNL_Information_sequence[] = {
  { &hf_m3ap_iPMCAddress    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_IPAddress },
  { &hf_m3ap_iPSourceAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_IPAddress },
  { &hf_m3ap_gTP_DLTEID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_GTP_TEID },
  { &hf_m3ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_m3ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_TNL_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_TNL_Information, TNL_Information_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStartRequest_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionStartRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 206 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Start Request ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionStartRequest, MBMSSessionStartRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStartResponse_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionStartResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 208 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Start Response ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionStartResponse, MBMSSessionStartResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStartFailure_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionStartFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 210 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Start Failure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionStartFailure, MBMSSessionStartFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStopRequest_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionStopRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 212 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Stop Request ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionStopRequest, MBMSSessionStopRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStopResponse_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionStopResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 214 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Stop Response ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionStopResponse, MBMSSessionStopResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdateRequest_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionUpdateRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 216 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Update Request ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionUpdateRequest, MBMSSessionUpdateRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdateResponse_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionUpdateResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 218 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Update Response ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionUpdateResponse, MBMSSessionUpdateResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdateFailure_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MBMSSessionUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 220 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMS Session Update Failure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MBMSSessionUpdateFailure, MBMSSessionUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 222 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"Error Indication ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 224 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"Reset ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_Reset, Reset_sequence);

  return offset;
}


static const value_string m3ap_ResetAll_vals[] = {
  {   0, "reset-all" },
  { 0, NULL }
};


static int
dissect_m3ap_ResetAll(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MBMS_Service_associatedLogicalM3_ConnectionListRes_sequence_of[1] = {
  { &hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Single_Container },
};

static int
dissect_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes, MBMS_Service_associatedLogicalM3_ConnectionListRes_sequence_of,
                                                  1, maxNrOfIndividualM3ConnectionsToReset, FALSE);

  return offset;
}


static const value_string m3ap_ResetType_vals[] = {
  {   0, "m3-Interface" },
  {   1, "partOfM3-Interface" },
  { 0, NULL }
};

static const per_choice_t ResetType_choice[] = {
  {   0, &hf_m3ap_m3_Interface   , ASN1_EXTENSION_ROOT    , dissect_m3ap_ResetAll },
  {   1, &hf_m3ap_partOfM3_Interface, ASN1_EXTENSION_ROOT    , dissect_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes },
  { 0, NULL, 0, NULL }
};

static int
dissect_m3ap_ResetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_m3ap_ResetType, ResetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_ResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 226 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"Reset Acknowledge ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t MBMS_Service_associatedLogicalM3_ConnectionListResAck_sequence_of[1] = {
  { &hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Single_Container },
};

static int
dissect_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck, MBMS_Service_associatedLogicalM3_ConnectionListResAck_sequence_of,
                                                  1, maxNrOfIndividualM3ConnectionsToReset, FALSE);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_m3ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 228 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"Private Message ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t M3SetupRequest_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_M3SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 236 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"M3 Setup Request ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_M3SetupRequest, M3SetupRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSServiceAreaListItem_sequence_of[1] = {
  { &hf_m3ap_MBMSServiceAreaListItem_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_MBMSServiceArea1 },
};

static int
dissect_m3ap_MBMSServiceAreaListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_m3ap_MBMSServiceAreaListItem, MBMSServiceAreaListItem_sequence_of,
                                                  1, maxnoofMBMSServiceAreaIdentitiesPerMCE, FALSE);

  return offset;
}


static const per_sequence_t M3SetupResponse_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_M3SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 238 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"M3 Setup Response ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_M3SetupResponse, M3SetupResponse_sequence);

  return offset;
}


static const per_sequence_t M3SetupFailure_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_M3SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 240 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"M3 Setup Failure ");



  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_M3SetupFailure, M3SetupFailure_sequence);

  return offset;
}


static const per_sequence_t MCEConfigurationUpdate_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MCEConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 230 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MCE Configuration Update ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MCEConfigurationUpdate, MCEConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t MCEConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MCEConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 232 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MCE Configuration Update Acknowledge ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MCEConfigurationUpdateAcknowledge, MCEConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t MCEConfigurationUpdateFailure_sequence[] = {
  { &hf_m3ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_m3ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_MCEConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 234 "../../asn1/m3ap/m3ap.cnf"
	col_set_str(actx->pinfo->cinfo, COL_INFO,"MCE Configuration Update Failure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_MCEConfigurationUpdateFailure, MCEConfigurationUpdateFailure_sequence);

  return offset;
}



static int
dissect_m3ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 73 "../../asn1/m3ap/m3ap.cnf"
	message_type = INITIATING_MESSAGE;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_m3ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProcedureCode },
  { &hf_m3ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Criticality },
  { &hf_m3ap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_m3ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 76 "../../asn1/m3ap/m3ap.cnf"
	message_type = SUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_m3ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProcedureCode },
  { &hf_m3ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Criticality },
  { &hf_m3ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_m3ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 79 "../../asn1/m3ap/m3ap.cnf"
	message_type = UNSUCCESSFUL_OUTCOME;







  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_m3ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_ProcedureCode },
  { &hf_m3ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_Criticality },
  { &hf_m3ap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_m3ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_m3ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_m3ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string m3ap_M3AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t M3AP_PDU_choice[] = {
  {   0, &hf_m3ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_m3ap_InitiatingMessage },
  {   1, &hf_m3ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_m3ap_SuccessfulOutcome },
  {   2, &hf_m3ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_m3ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_m3ap_M3AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_m3ap_M3AP_PDU, M3AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Absolute_Time_ofMBMS_Data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_Absolute_Time_ofMBMS_Data(tvb, offset, &asn1_ctx, tree, hf_m3ap_Absolute_Time_ofMBMS_Data_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AllocationAndRetentionPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_AllocationAndRetentionPriority(tvb, offset, &asn1_ctx, tree, hf_m3ap_AllocationAndRetentionPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_Cause(tvb, offset, &asn1_ctx, tree, hf_m3ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_m3ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Global_MCE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_Global_MCE_ID(tvb, offset, &asn1_ctx, tree, hf_m3ap_Global_MCE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMS_E_RAB_QoS_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMS_E_RAB_QoS_Parameters(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMS_E_RAB_QoS_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMS_Service_associatedLogicalM3_ConnectionItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMS_Service_Area_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMS_Service_Area(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMS_Service_Area_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMS_Session_Duration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMS_Session_Duration(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMS_Session_Duration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMS_Session_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMS_Session_ID(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMS_Session_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCE_MBMS_M3AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MCE_MBMS_M3AP_ID(tvb, offset, &asn1_ctx, tree, hf_m3ap_MCE_MBMS_M3AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCEname_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MCEname(tvb, offset, &asn1_ctx, tree, hf_m3ap_MCEname_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MinimumTimeToMBMSDataTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MinimumTimeToMBMSDataTransfer(tvb, offset, &asn1_ctx, tree, hf_m3ap_MinimumTimeToMBMSDataTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MME_MBMS_M3AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MME_MBMS_M3AP_ID(tvb, offset, &asn1_ctx, tree, hf_m3ap_MME_MBMS_M3AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_m3ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TMGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_TMGI(tvb, offset, &asn1_ctx, tree, hf_m3ap_TMGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNL_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_TNL_Information(tvb, offset, &asn1_ctx, tree, hf_m3ap_TNL_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStartRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionStartRequest(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionStartRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStartResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionStartResponse(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionStartResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStartFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionStartFailure(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionStartFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStopRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionStopRequest(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionStopRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStopResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionStopResponse(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionStopResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdateRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionUpdateRequest(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionUpdateRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdateResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionUpdateResponse(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionUpdateResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSSessionUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSSessionUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_m3ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_Reset(tvb, offset, &asn1_ctx, tree, hf_m3ap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_ResetType(tvb, offset, &asn1_ctx, tree, hf_m3ap_ResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_m3ap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMS_Service_associatedLogicalM3_ConnectionListResAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_m3ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M3SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_M3SetupRequest(tvb, offset, &asn1_ctx, tree, hf_m3ap_M3SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSServiceAreaListItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MBMSServiceAreaListItem(tvb, offset, &asn1_ctx, tree, hf_m3ap_MBMSServiceAreaListItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M3SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_M3SetupResponse(tvb, offset, &asn1_ctx, tree, hf_m3ap_M3SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M3SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_M3SetupFailure(tvb, offset, &asn1_ctx, tree, hf_m3ap_M3SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCEConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MCEConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_m3ap_MCEConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCEConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MCEConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_m3ap_MCEConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCEConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_MCEConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_m3ap_MCEConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M3AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_m3ap_M3AP_PDU(tvb, offset, &asn1_ctx, tree, hf_m3ap_M3AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-m3ap-fn.c ---*/
#line 93 "../../asn1/m3ap/packet-m3ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static void
dissect_m3ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item      *m3ap_item = NULL;
  proto_tree      *m3ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

  /* create the m3ap protocol tree */
  if (tree) {
    m3ap_item = proto_tree_add_item(tree, proto_m3ap, tvb, 0, -1, ENC_NA);
    m3ap_tree = proto_item_add_subtree(m3ap_item, ett_m3ap);

    dissect_M3AP_PDU_PDU(tvb, pinfo, m3ap_tree, NULL);
  }
}
/*--- proto_register_m3ap -------------------------------------------*/
void proto_register_m3ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_m3ap_Absolute_Time_ofMBMS_Data_value,
      { "Absolute-Time-ofMBMS-Data-value", "m3ap.Absolute_Time_ofMBMS_Data_value",
         FT_STRING, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },
    { &hf_m3ap_IPAddress,
      { "IPAddress", "m3ap.IPAddress",
         FT_IPv6, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },


/*--- Included file: packet-m3ap-hfarr.c ---*/
#line 1 "../../asn1/m3ap/packet-m3ap-hfarr.c"
    { &hf_m3ap_Absolute_Time_ofMBMS_Data_PDU,
      { "Absolute-Time-ofMBMS-Data", "m3ap.Absolute_Time_ofMBMS_Data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_AllocationAndRetentionPriority_PDU,
      { "AllocationAndRetentionPriority", "m3ap.AllocationAndRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_Cause_PDU,
      { "Cause", "m3ap.Cause",
        FT_UINT32, BASE_DEC, VALS(m3ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "m3ap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_Global_MCE_ID_PDU,
      { "Global-MCE-ID", "m3ap.Global_MCE_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMS_E_RAB_QoS_Parameters_PDU,
      { "MBMS-E-RAB-QoS-Parameters", "m3ap.MBMS_E_RAB_QoS_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem_PDU,
      { "MBMS-Service-associatedLogicalM3-ConnectionItem", "m3ap.MBMS_Service_associatedLogicalM3_ConnectionItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMS_Service_Area_PDU,
      { "MBMS-Service-Area", "m3ap.MBMS_Service_Area",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMS_Session_Duration_PDU,
      { "MBMS-Session-Duration", "m3ap.MBMS_Session_Duration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMS_Session_ID_PDU,
      { "MBMS-Session-ID", "m3ap.MBMS_Session_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MCE_MBMS_M3AP_ID_PDU,
      { "MCE-MBMS-M3AP-ID", "m3ap.MCE_MBMS_M3AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MCEname_PDU,
      { "MCEname", "m3ap.MCEname",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MinimumTimeToMBMSDataTransfer_PDU,
      { "MinimumTimeToMBMSDataTransfer", "m3ap.MinimumTimeToMBMSDataTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MME_MBMS_M3AP_ID_PDU,
      { "MME-MBMS-M3AP-ID", "m3ap.MME_MBMS_M3AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_TimeToWait_PDU,
      { "TimeToWait", "m3ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(m3ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_TMGI_PDU,
      { "TMGI", "m3ap.TMGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_TNL_Information_PDU,
      { "TNL-Information", "m3ap.TNL_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionStartRequest_PDU,
      { "MBMSSessionStartRequest", "m3ap.MBMSSessionStartRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionStartResponse_PDU,
      { "MBMSSessionStartResponse", "m3ap.MBMSSessionStartResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionStartFailure_PDU,
      { "MBMSSessionStartFailure", "m3ap.MBMSSessionStartFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionStopRequest_PDU,
      { "MBMSSessionStopRequest", "m3ap.MBMSSessionStopRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionStopResponse_PDU,
      { "MBMSSessionStopResponse", "m3ap.MBMSSessionStopResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionUpdateRequest_PDU,
      { "MBMSSessionUpdateRequest", "m3ap.MBMSSessionUpdateRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionUpdateResponse_PDU,
      { "MBMSSessionUpdateResponse", "m3ap.MBMSSessionUpdateResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSSessionUpdateFailure_PDU,
      { "MBMSSessionUpdateFailure", "m3ap.MBMSSessionUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_ErrorIndication_PDU,
      { "ErrorIndication", "m3ap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_Reset_PDU,
      { "Reset", "m3ap.Reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_ResetType_PDU,
      { "ResetType", "m3ap.ResetType",
        FT_UINT32, BASE_DEC, VALS(m3ap_ResetType_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_ResetAcknowledge_PDU,
      { "ResetAcknowledge", "m3ap.ResetAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck_PDU,
      { "MBMS-Service-associatedLogicalM3-ConnectionListResAck", "m3ap.MBMS_Service_associatedLogicalM3_ConnectionListResAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_PrivateMessage_PDU,
      { "PrivateMessage", "m3ap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_M3SetupRequest_PDU,
      { "M3SetupRequest", "m3ap.M3SetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMSServiceAreaListItem_PDU,
      { "MBMSServiceAreaListItem", "m3ap.MBMSServiceAreaListItem",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_M3SetupResponse_PDU,
      { "M3SetupResponse", "m3ap.M3SetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_M3SetupFailure_PDU,
      { "M3SetupFailure", "m3ap.M3SetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MCEConfigurationUpdate_PDU,
      { "MCEConfigurationUpdate", "m3ap.MCEConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MCEConfigurationUpdateAcknowledge_PDU,
      { "MCEConfigurationUpdateAcknowledge", "m3ap.MCEConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MCEConfigurationUpdateFailure_PDU,
      { "MCEConfigurationUpdateFailure", "m3ap.MCEConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_M3AP_PDU_PDU,
      { "M3AP-PDU", "m3ap.M3AP_PDU",
        FT_UINT32, BASE_DEC, VALS(m3ap_M3AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_local,
      { "local", "m3ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_m3ap_global,
      { "global", "m3ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_m3ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "m3ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_id,
      { "id", "m3ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &m3ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_m3ap_criticality,
      { "criticality", "m3ap.criticality",
        FT_UINT32, BASE_DEC, VALS(m3ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_ie_field_value,
      { "value", "m3ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_m3ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "m3ap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_ext_id,
      { "id", "m3ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &m3ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_m3ap_extensionValue,
      { "extensionValue", "m3ap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_PrivateIE_Container_item,
      { "PrivateIE-Field", "m3ap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_private_id,
      { "id", "m3ap.id",
        FT_UINT32, BASE_DEC, VALS(m3ap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_m3ap_private_value,
      { "value", "m3ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_private_value", HFILL }},
    { &hf_m3ap_priorityLevel,
      { "priorityLevel", "m3ap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(m3ap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_pre_emptionCapability,
      { "pre-emptionCapability", "m3ap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(m3ap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "m3ap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(m3ap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_iE_Extensions,
      { "iE-Extensions", "m3ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_m3ap_radioNetwork,
      { "radioNetwork", "m3ap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(m3ap_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_m3ap_transport,
      { "transport", "m3ap.transport",
        FT_UINT32, BASE_DEC, VALS(m3ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_m3ap_nAS,
      { "nAS", "m3ap.nAS",
        FT_UINT32, BASE_DEC, VALS(m3ap_CauseNAS_vals), 0,
        "CauseNAS", HFILL }},
    { &hf_m3ap_protocol,
      { "protocol", "m3ap.protocol",
        FT_UINT32, BASE_DEC, VALS(m3ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_m3ap_misc,
      { "misc", "m3ap.misc",
        FT_UINT32, BASE_DEC, VALS(m3ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_m3ap_procedureCode,
      { "procedureCode", "m3ap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &m3ap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_m3ap_triggeringMessage,
      { "triggeringMessage", "m3ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(m3ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_procedureCriticality,
      { "procedureCriticality", "m3ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(m3ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_m3ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "m3ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_m3ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "m3ap.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_iECriticality,
      { "iECriticality", "m3ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(m3ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_m3ap_iE_ID,
      { "iE-ID", "m3ap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &m3ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_m3ap_typeOfError,
      { "typeOfError", "m3ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(m3ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_m3ap_pLMN_Identity,
      { "pLMN-Identity", "m3ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_mCE_ID,
      { "mCE-ID", "m3ap.mCE_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_extendedMCE_ID,
      { "extendedMCE-ID", "m3ap.extendedMCE_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_mBMS_E_RAB_MaximumBitrateDL,
      { "mBMS-E-RAB-MaximumBitrateDL", "m3ap.mBMS_E_RAB_MaximumBitrateDL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_m3ap_mBMS_E_RAB_GuaranteedBitrateDL,
      { "mBMS-E-RAB-GuaranteedBitrateDL", "m3ap.mBMS_E_RAB_GuaranteedBitrateDL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_m3ap_qCI,
      { "qCI", "m3ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_gbrQosInformation,
      { "gbrQosInformation", "m3ap.gbrQosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QosInformation", HFILL }},
    { &hf_m3ap_mME_MBMS_M3AP_ID,
      { "mME-MBMS-M3AP-ID", "m3ap.mME_MBMS_M3AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_mCE_MBMS_M3AP_ID,
      { "mCE-MBMS-M3AP-ID", "m3ap.mCE_MBMS_M3AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_pLMNidentity,
      { "pLMNidentity", "m3ap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_m3ap_serviceID,
      { "serviceID", "m3ap.serviceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_m3ap_iPMCAddress,
      { "iPMCAddress", "m3ap.iPMCAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_m3ap_iPSourceAddress,
      { "iPSourceAddress", "m3ap.iPSourceAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_m3ap_gTP_DLTEID,
      { "gTP-DLTEID", "m3ap.gTP_DLTEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GTP_TEID", HFILL }},
    { &hf_m3ap_protocolIEs,
      { "protocolIEs", "m3ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_m3ap_m3_Interface,
      { "m3-Interface", "m3ap.m3_Interface",
        FT_UINT32, BASE_DEC, VALS(m3ap_ResetAll_vals), 0,
        "ResetAll", HFILL }},
    { &hf_m3ap_partOfM3_Interface,
      { "partOfM3-Interface", "m3ap.partOfM3_Interface",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBMS_Service_associatedLogicalM3_ConnectionListRes", HFILL }},
    { &hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes_item,
      { "ProtocolIE-Single-Container", "m3ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck_item,
      { "ProtocolIE-Single-Container", "m3ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_privateIEs,
      { "privateIEs", "m3ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_m3ap_MBMSServiceAreaListItem_item,
      { "MBMSServiceArea1", "m3ap.MBMSServiceArea1",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_initiatingMessage,
      { "initiatingMessage", "m3ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_successfulOutcome,
      { "successfulOutcome", "m3ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "m3ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_m3ap_initiatingMessagevalue,
      { "value", "m3ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_m3ap_successfulOutcome_value,
      { "value", "m3ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_m3ap_unsuccessfulOutcome_value,
      { "value", "m3ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-m3ap-hfarr.c ---*/
#line 154 "../../asn1/m3ap/packet-m3ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_m3ap,

/*--- Included file: packet-m3ap-ettarr.c ---*/
#line 1 "../../asn1/m3ap/packet-m3ap-ettarr.c"
    &ett_m3ap_PrivateIE_ID,
    &ett_m3ap_ProtocolIE_Container,
    &ett_m3ap_ProtocolIE_Field,
    &ett_m3ap_ProtocolExtensionContainer,
    &ett_m3ap_ProtocolExtensionField,
    &ett_m3ap_PrivateIE_Container,
    &ett_m3ap_PrivateIE_Field,
    &ett_m3ap_AllocationAndRetentionPriority,
    &ett_m3ap_Cause,
    &ett_m3ap_CriticalityDiagnostics,
    &ett_m3ap_CriticalityDiagnostics_IE_List,
    &ett_m3ap_CriticalityDiagnostics_IE_List_item,
    &ett_m3ap_Global_MCE_ID,
    &ett_m3ap_GBR_QosInformation,
    &ett_m3ap_MBMS_E_RAB_QoS_Parameters,
    &ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionItem,
    &ett_m3ap_TMGI,
    &ett_m3ap_TNL_Information,
    &ett_m3ap_MBMSSessionStartRequest,
    &ett_m3ap_MBMSSessionStartResponse,
    &ett_m3ap_MBMSSessionStartFailure,
    &ett_m3ap_MBMSSessionStopRequest,
    &ett_m3ap_MBMSSessionStopResponse,
    &ett_m3ap_MBMSSessionUpdateRequest,
    &ett_m3ap_MBMSSessionUpdateResponse,
    &ett_m3ap_MBMSSessionUpdateFailure,
    &ett_m3ap_ErrorIndication,
    &ett_m3ap_Reset,
    &ett_m3ap_ResetType,
    &ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListRes,
    &ett_m3ap_ResetAcknowledge,
    &ett_m3ap_MBMS_Service_associatedLogicalM3_ConnectionListResAck,
    &ett_m3ap_PrivateMessage,
    &ett_m3ap_M3SetupRequest,
    &ett_m3ap_MBMSServiceAreaListItem,
    &ett_m3ap_M3SetupResponse,
    &ett_m3ap_M3SetupFailure,
    &ett_m3ap_MCEConfigurationUpdate,
    &ett_m3ap_MCEConfigurationUpdateAcknowledge,
    &ett_m3ap_MCEConfigurationUpdateFailure,
    &ett_m3ap_M3AP_PDU,
    &ett_m3ap_InitiatingMessage,
    &ett_m3ap_SuccessfulOutcome,
    &ett_m3ap_UnsuccessfulOutcome,

/*--- End of included file: packet-m3ap-ettarr.c ---*/
#line 160 "../../asn1/m3ap/packet-m3ap-template.c"
  };


  /* Register protocol */
  proto_m3ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_m3ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector tables */
  m3ap_ies_dissector_table = register_dissector_table("m3ap.ies", "M3AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  m3ap_extension_dissector_table = register_dissector_table("m3ap.extension", "M3AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  m3ap_proc_imsg_dissector_table = register_dissector_table("m3ap.proc.imsg", "M3AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  m3ap_proc_sout_dissector_table = register_dissector_table("m3ap.proc.sout", "M3AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  m3ap_proc_uout_dissector_table = register_dissector_table("m3ap.proc.uout", "M3AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);
}


/*--- proto_reg_handoff_m3ap ---------------------------------------*/
void
proto_reg_handoff_m3ap(void)
{
  static gboolean inited = FALSE;
  static guint SctpPort;

  if( !inited ) {
    m3ap_handle = create_dissector_handle(dissect_m3ap, proto_m3ap);
    dissector_add_uint("sctp.ppi", PROTO_3GPP_M3AP_PROTOCOL_ID, m3ap_handle);
    inited = TRUE;

/*--- Included file: packet-m3ap-dis-tab.c ---*/
#line 1 "../../asn1/m3ap/packet-m3ap-dis-tab.c"
  dissector_add_uint("m3ap.ies", id_MME_MBMS_M3AP_ID, new_create_dissector_handle(dissect_MME_MBMS_M3AP_ID_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MCE_MBMS_M3AP_ID, new_create_dissector_handle(dissect_MCE_MBMS_M3AP_ID_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_TMGI, new_create_dissector_handle(dissect_TMGI_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MBMS_Session_ID, new_create_dissector_handle(dissect_MBMS_Session_ID_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MBMS_E_RAB_QoS_Parameters, new_create_dissector_handle(dissect_MBMS_E_RAB_QoS_Parameters_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MBMS_Session_Duration, new_create_dissector_handle(dissect_MBMS_Session_Duration_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MBMS_Service_Area, new_create_dissector_handle(dissect_MBMS_Service_Area_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_TNL_Information, new_create_dissector_handle(dissect_TNL_Information_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_TimeToWait, new_create_dissector_handle(dissect_TimeToWait_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_ResetType, new_create_dissector_handle(dissect_ResetType_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MBMS_Service_associatedLogicalM3_ConnectionItem, new_create_dissector_handle(dissect_MBMS_Service_associatedLogicalM3_ConnectionItem_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MBMS_Service_associatedLogicalM3_ConnectionListResAck, new_create_dissector_handle(dissect_MBMS_Service_associatedLogicalM3_ConnectionListResAck_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MinimumTimeToMBMSDataTransfer, new_create_dissector_handle(dissect_MinimumTimeToMBMSDataTransfer_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_AllocationAndRetentionPriority, new_create_dissector_handle(dissect_AllocationAndRetentionPriority_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_Global_MCE_ID, new_create_dissector_handle(dissect_Global_MCE_ID_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MCEname, new_create_dissector_handle(dissect_MCEname_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_MBMSServiceAreaList, new_create_dissector_handle(dissect_MBMSServiceAreaListItem_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_Time_ofMBMS_DataTransfer, new_create_dissector_handle(dissect_Absolute_Time_ofMBMS_Data_PDU, proto_m3ap));
  dissector_add_uint("m3ap.ies", id_Time_ofMBMS_DataStop, new_create_dissector_handle(dissect_Absolute_Time_ofMBMS_Data_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_mBMSsessionStart, new_create_dissector_handle(dissect_MBMSSessionStartRequest_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.sout", id_mBMSsessionStart, new_create_dissector_handle(dissect_MBMSSessionStartResponse_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.uout", id_mBMSsessionStart, new_create_dissector_handle(dissect_MBMSSessionStartFailure_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_mBMSsessionStop, new_create_dissector_handle(dissect_MBMSSessionStopRequest_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.sout", id_mBMSsessionStop, new_create_dissector_handle(dissect_MBMSSessionStopResponse_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_mBMSsessionUpdate, new_create_dissector_handle(dissect_MBMSSessionUpdateRequest_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.sout", id_mBMSsessionUpdate, new_create_dissector_handle(dissect_MBMSSessionUpdateResponse_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.uout", id_mBMSsessionUpdate, new_create_dissector_handle(dissect_MBMSSessionUpdateFailure_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_errorIndication, new_create_dissector_handle(dissect_ErrorIndication_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_Reset, new_create_dissector_handle(dissect_Reset_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.sout", id_Reset, new_create_dissector_handle(dissect_ResetAcknowledge_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_privateMessage, new_create_dissector_handle(dissect_PrivateMessage_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_mCEConfigurationUpdate, new_create_dissector_handle(dissect_MCEConfigurationUpdate_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.sout", id_mCEConfigurationUpdate, new_create_dissector_handle(dissect_MCEConfigurationUpdateAcknowledge_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.uout", id_mCEConfigurationUpdate, new_create_dissector_handle(dissect_MCEConfigurationUpdateFailure_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.imsg", id_m3Setup, new_create_dissector_handle(dissect_M3SetupRequest_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.sout", id_m3Setup, new_create_dissector_handle(dissect_M3SetupResponse_PDU, proto_m3ap));
  dissector_add_uint("m3ap.proc.uout", id_m3Setup, new_create_dissector_handle(dissect_M3SetupFailure_PDU, proto_m3ap));


/*--- End of included file: packet-m3ap-dis-tab.c ---*/
#line 190 "../../asn1/m3ap/packet-m3ap-template.c"
    dissector_add_uint("m3ap.extension", 17, new_create_dissector_handle(dissect_AllocationAndRetentionPriority_PDU, proto_m3ap));
  }
  else {
    if (SctpPort != 0) {
      dissector_delete_uint("sctp.port", SctpPort, m3ap_handle);
    }
  }

  SctpPort = global_m3ap_port;
  if (SctpPort != 0) {
    dissector_add_uint("sctp.port", SctpPort, m3ap_handle);
  }
}
