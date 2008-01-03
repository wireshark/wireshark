/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-x2ap.c                                                              */
/* ../../tools/asn2wrs.py -p x2ap -c x2ap.cnf -s packet-x2ap-template X2AP-CommonDataTypes.asn X2AP-Constants.asn X2AP-Containers.asn X2AP-IEs.asn X2AP-PDU-Contents.asn X2AP-PDU-Descriptions.asn */

/* Input file: packet-x2ap-template.c */

#line 1 "packet-x2ap-template.c"
/* packet-x2ap.c
 * Routines for dissecting Evolved Universal Terrestrial Radio Access Network (EUTRAN);
 * X2 Application Protocol (X2AP);
 * 3GPP TS 36.423 packet dissection
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
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
 * Ref: 
 * 3GPP TS 36.423 V8.0.0 (2007-12)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include <epan/asn1.h>

#include "packet-per.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "EUTRAN X2 Application Protocol (X2AP)"
#define PSNAME "X2AP"
#define PFNAME "x2ap"

#define SCCP_SSN_X2AP 143


/*--- Included file: packet-x2ap-val.h ---*/
#line 1 "packet-x2ap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxInterfaces                  16
#define maxCellineNB                   256
#define maxnoofCells                   16
#define maxnoofBearers                 16
#define maxNrOfErrors                  256
#define maxnoofPDCP_SN                 16
#define maxnoofEPLMNs                  15
#define maxnoofEPLMNsPlusOne           16
#define maxnoofForbLACs                256
#define maxnoofForbTAIs                256
#define maxnoofBPLMNs                  6

/* enumerated values for ProcedureCode */
#define X2AP_ID_HANDOVERPREPARATION   0
#define X2AP_ID_HANDOVERCANCEL   1
#define X2AP_ID_LOADINDICATION   2
#define X2AP_ID_ERRORINDICATION   3
#define X2AP_ID_SNSTATUSTRANSFER   4
#define X2AP_ID_RELEASERESOURCE   5
#define X2AP_ID_X2SETUP   6
#define X2AP_ID_RESET   7

typedef enum _ProtocolIE_ID_enum {
  id_Bearers_Admitted_Item =   0,
  id_Bearers_Admitted_List =   1,
  id_Bearers_NotAdmitted_Item =   2,
  id_Bearers_NotAdmitted_List =   3,
  id_Bearers_ToBeSetup_Item =   4,
  id_Cause     =   5,
  id_CellInformation =   6,
  id_CellInformation_Item =   7,
  id_InterfacesToTrace_Item =   8,
  id_New_eNB_UE_X2AP_ID =   9,
  id_Old_eNB_UE_X2AP_ID =  10,
  id_TargetCell_ID =  11,
  id_TargeteNBtoSource_eNBTransparentContainer =  12,
  id_TraceActivation =  13,
  id_UE_ContextInformation =  14,
  id_UE_HistoryInformation =  15,
  id_UE_X2AP_ID =  16,
  id_CriticalityDiagnostics =  17,
  id_Bearers_SubjectToStatusTransfer_List =  18,
  id_Bearers_SubjectToStatusTransfer_Item =  19,
  id_ServedCells =  20,
  id_ENB_ID    =  21,
  id_TimeToWait =  22
} ProtocolIE_ID_enum;

/*--- End of included file: packet-x2ap-val.h ---*/
#line 58 "packet-x2ap-template.c"

static dissector_handle_t x2ap_handle = NULL;

/* Initialize the protocol and registered fields */
static int proto_x2ap = -1;


/*--- Included file: packet-x2ap-hf.c ---*/
#line 1 "packet-x2ap-hf.c"
static int hf_x2ap_Cause_PDU = -1;                /* Cause */
static int hf_x2ap_CGI_PDU = -1;                  /* CGI */
static int hf_x2ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_x2ap_ENB_ID_PDU = -1;               /* ENB_ID */
static int hf_x2ap_InterfacesToTrace_Item_PDU = -1;  /* InterfacesToTrace_Item */
static int hf_x2ap_ServedCells_PDU = -1;          /* ServedCells */
static int hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU = -1;  /* TargeteNBtoSource_eNBTransparentContainer */
static int hf_x2ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_x2ap_TraceActivation_PDU = -1;      /* TraceActivation */
static int hf_x2ap_UE_HistoryInformation_PDU = -1;  /* UE_HistoryInformation */
static int hf_x2ap_UE_X2AP_ID_PDU = -1;           /* UE_X2AP_ID */
static int hf_x2ap_HandoverRequest_PDU = -1;      /* HandoverRequest */
static int hf_x2ap_UE_ContextInformation_PDU = -1;  /* UE_ContextInformation */
static int hf_x2ap_Bearers_ToBeSetup_Item_PDU = -1;  /* Bearers_ToBeSetup_Item */
static int hf_x2ap_HandoverRequestAcknowledge_PDU = -1;  /* HandoverRequestAcknowledge */
static int hf_x2ap_Bearers_Admitted_List_PDU = -1;  /* Bearers_Admitted_List */
static int hf_x2ap_Bearers_Admitted_Item_PDU = -1;  /* Bearers_Admitted_Item */
static int hf_x2ap_Bearers_NotAdmitted_List_PDU = -1;  /* Bearers_NotAdmitted_List */
static int hf_x2ap_Bearers_NotAdmitted_Item_PDU = -1;  /* Bearers_NotAdmitted_Item */
static int hf_x2ap_HandoverPreparationFailure_PDU = -1;  /* HandoverPreparationFailure */
static int hf_x2ap_SNStatusTransfer_PDU = -1;     /* SNStatusTransfer */
static int hf_x2ap_Bearers_SubjectToStatusTransfer_List_PDU = -1;  /* Bearers_SubjectToStatusTransfer_List */
static int hf_x2ap_Bearers_SubjectToStatusTransfer_Item_PDU = -1;  /* Bearers_SubjectToStatusTransfer_Item */
static int hf_x2ap_ReleaseResource_PDU = -1;      /* ReleaseResource */
static int hf_x2ap_HandoverCancel_PDU = -1;       /* HandoverCancel */
static int hf_x2ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_x2ap_ResetResponse_PDU = -1;        /* ResetResponse */
static int hf_x2ap_X2SetupRequest_PDU = -1;       /* X2SetupRequest */
static int hf_x2ap_X2SetupResponse_PDU = -1;      /* X2SetupResponse */
static int hf_x2ap_X2SetupFailure_PDU = -1;       /* X2SetupFailure */
static int hf_x2ap_LoadInformation_PDU = -1;      /* LoadInformation */
static int hf_x2ap_CellInformation_List_PDU = -1;  /* CellInformation_List */
static int hf_x2ap_CellInformation_Item_PDU = -1;  /* CellInformation_Item */
static int hf_x2ap_X2AP_PDU_PDU = -1;             /* X2AP_PDU */
static int hf_x2ap_local = -1;                    /* INTEGER_0_maxPrivateIEs */
static int hf_x2ap_global = -1;                   /* OBJECT_IDENTIFIER */
static int hf_x2ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_x2ap_id = -1;                       /* ProtocolIE_ID */
static int hf_x2ap_criticality = -1;              /* Criticality */
static int hf_x2ap_protocolIE_Field_value = -1;   /* ProtocolIE_Field_value */
static int hf_x2ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_x2ap_extension_id = -1;             /* ProtocolIE_ID */
static int hf_x2ap_extensionValue = -1;           /* T_extensionValue */
static int hf_x2ap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_x2ap_private_id = -1;               /* PrivateIE_ID */
static int hf_x2ap_privateIE_Field_value = -1;    /* PrivateIE_Field_value */
static int hf_x2ap_aggregateMaximumBitRateDownlink = -1;  /* SAE_Bearer_BitRate */
static int hf_x2ap_aggregateMaximumBitRateUplink = -1;  /* SAE_Bearer_BitRate */
static int hf_x2ap_BroadcastPLMNs_Item_item = -1;  /* PLMN_Identity */
static int hf_x2ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_x2ap_transport = -1;                /* CauseTransport */
static int hf_x2ap_protocol = -1;                 /* CauseProtocol */
static int hf_x2ap_misc = -1;                     /* CauseMisc */
static int hf_x2ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_x2ap_lAC = -1;                      /* LAC */
static int hf_x2ap_cI = -1;                       /* CI */
static int hf_x2ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_x2ap_procedureCode = -1;            /* ProcedureCode */
static int hf_x2ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_x2ap_procedureCriticality = -1;     /* Criticality */
static int hf_x2ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_x2ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_x2ap_iECriticality = -1;            /* Criticality */
static int hf_x2ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_x2ap_typeOfError = -1;              /* TypeOfError */
static int hf_x2ap_EPLMNs_item = -1;              /* PLMN_Identity */
static int hf_x2ap_ForbiddenTAs_item = -1;        /* ForbiddenTAs_Item */
static int hf_x2ap_forbiddenTAIs = -1;            /* ForbiddenTAIs */
static int hf_x2ap_ForbiddenTAIs_item = -1;       /* TAI */
static int hf_x2ap_ForbiddenLAs_item = -1;        /* ForbiddenLAs_Item */
static int hf_x2ap_forbiddenLACs = -1;            /* ForbiddenLACs */
static int hf_x2ap_ForbiddenLACs_item = -1;       /* LAC */
static int hf_x2ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_x2ap_gTP_TEID = -1;                 /* GTP_TEI */
static int hf_x2ap_equivalentPLMNs = -1;          /* EPLMNs */
static int hf_x2ap_forbiddenTAs = -1;             /* ForbiddenTAs */
static int hf_x2ap_forbiddenLAs = -1;             /* ForbiddenLAs */
static int hf_x2ap_forbiddenInterRATs = -1;       /* ForbiddenInterRATs */
static int hf_x2ap_InterfacesToTrace_item = -1;   /* ProtocolIE_Single_Container */
static int hf_x2ap_traceInterface = -1;           /* TraceInterface */
static int hf_x2ap_traceDepth = -1;               /* TraceDepth */
static int hf_x2ap_global_Cell_ID = -1;           /* CGI */
static int hf_x2ap_cellType = -1;                 /* CellType */
static int hf_x2ap_time_UE_StayedInCell = -1;     /* Time_UE_StayedInCell */
static int hf_x2ap_label = -1;                    /* INTEGER_1_256 */
static int hf_x2ap_allocationAndRetentionPriority = -1;  /* OCTET_STRING */
static int hf_x2ap_sAE_BearerType = -1;           /* SAE_BearerType */
static int hf_x2ap_sAE_GBR_bearer = -1;           /* SAE_GBR_Bearer */
static int hf_x2ap_sAE_non_GBR_bearer = -1;       /* SAE_Non_GBR_Bearer */
static int hf_x2ap_sAE_Bearer_MaximumBitrateDL = -1;  /* SAE_Bearer_BitRate */
static int hf_x2ap_sAE_Bearer_MaximumBitrateUL = -1;  /* SAE_Bearer_BitRate */
static int hf_x2ap_sAE_Bearer_GuaranteedBitrateDL = -1;  /* SAE_Bearer_BitRate */
static int hf_x2ap_sAE_Bearer_GuaranteedBitrateUL = -1;  /* SAE_Bearer_BitRate */
static int hf_x2ap_sAE_non_GBR_Bearer_Type = -1;  /* T_sAE_non_GBR_Bearer_Type */
static int hf_x2ap_ServedCells_item = -1;         /* ServedCell_Information */
static int hf_x2ap_phyCID = -1;                   /* PhyCID */
static int hf_x2ap_cellId = -1;                   /* CellId */
static int hf_x2ap_tAI = -1;                      /* TAI */
static int hf_x2ap_broadcastPLMNs = -1;           /* BroadcastPLMNs_Item */
static int hf_x2ap_frequency = -1;                /* Frequency */
static int hf_x2ap_traceReference = -1;           /* TraceReference */
static int hf_x2ap_interfacesToTrace = -1;        /* InterfacesToTrace */
static int hf_x2ap_UE_HistoryInformation_item = -1;  /* LastVisitedCell_Item */
static int hf_x2ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_x2ap_mME_UE_S1AP_ID = -1;           /* UE_S1AP_ID */
static int hf_x2ap_aggregateMaximumBitRate = -1;  /* AggregateMaximumBitRate */
static int hf_x2ap_bearers_ToBeSetup_List = -1;   /* Bearers_ToBeSetup_List */
static int hf_x2ap_rRC_Context = -1;              /* RRC_Context */
static int hf_x2ap_servingPLMN = -1;              /* PLMN_Identity */
static int hf_x2ap_handoverRestrictionList = -1;  /* HandoverRestrictionList */
static int hf_x2ap_Bearers_ToBeSetup_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sAE_Bearer_ID = -1;            /* Bearer_ID */
static int hf_x2ap_sAE_BearerLevel_QoS_Parameters = -1;  /* SAE_BearerLevel_QoS_Parameters */
static int hf_x2ap_dL_Forwarding = -1;            /* DL_Forwarding */
static int hf_x2ap_uL_GTPtunnelEndpoint = -1;     /* GTPtunnelEndpoint */
static int hf_x2ap_rB_type = -1;                  /* RB_type */
static int hf_x2ap_Bearers_Admitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_bearer_ID = -1;                /* Bearer_ID */
static int hf_x2ap_uL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_dL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_Bearers_NotAdmitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_cause = -1;                    /* Cause */
static int hf_x2ap_Bearers_SubjectToStatusTransfer_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_pDCP_SNofULSDUsNotToBeRetransmitted_List = -1;  /* PDCP_SNofULSDUsNotToBeRetransmitted_List */
static int hf_x2ap_uL_PDCP_SN_NextInSequenceExpected = -1;  /* PDCP_SN */
static int hf_x2ap_dL_PDCP_SN_NextToAssign = -1;  /* PDCP_SN */
static int hf_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List_item = -1;  /* PDCP_SN */
static int hf_x2ap_CellInformation_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_interferenceOverloadIndication = -1;  /* InterferenceOverloadIndication */
static int hf_x2ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_x2ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_x2ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_x2ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_x2ap_initiatingMessage_value = -1;  /* InitiatingMessage_value */
static int hf_x2ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_x2ap_value = -1;                    /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-x2ap-hf.c ---*/
#line 65 "packet-x2ap-template.c"

/* Initialize the subtree pointers */
static int ett_x2ap = -1;


/*--- Included file: packet-x2ap-ett.c ---*/
#line 1 "packet-x2ap-ett.c"
static gint ett_x2ap_PrivateIE_ID = -1;
static gint ett_x2ap_ProtocolIE_Container = -1;
static gint ett_x2ap_ProtocolIE_Field = -1;
static gint ett_x2ap_ProtocolExtensionContainer = -1;
static gint ett_x2ap_ProtocolExtensionField = -1;
static gint ett_x2ap_PrivateIE_Container = -1;
static gint ett_x2ap_PrivateIE_Field = -1;
static gint ett_x2ap_AggregateMaximumBitRate = -1;
static gint ett_x2ap_BroadcastPLMNs_Item = -1;
static gint ett_x2ap_Cause = -1;
static gint ett_x2ap_CGI = -1;
static gint ett_x2ap_CriticalityDiagnostics = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_x2ap_EPLMNs = -1;
static gint ett_x2ap_ForbiddenTAs = -1;
static gint ett_x2ap_ForbiddenTAs_Item = -1;
static gint ett_x2ap_ForbiddenTAIs = -1;
static gint ett_x2ap_ForbiddenLAs = -1;
static gint ett_x2ap_ForbiddenLAs_Item = -1;
static gint ett_x2ap_ForbiddenLACs = -1;
static gint ett_x2ap_GTPtunnelEndpoint = -1;
static gint ett_x2ap_HandoverRestrictionList = -1;
static gint ett_x2ap_InterfacesToTrace = -1;
static gint ett_x2ap_InterfacesToTrace_Item = -1;
static gint ett_x2ap_LastVisitedCell_Item = -1;
static gint ett_x2ap_SAE_BearerLevel_QoS_Parameters = -1;
static gint ett_x2ap_SAE_BearerType = -1;
static gint ett_x2ap_SAE_GBR_Bearer = -1;
static gint ett_x2ap_SAE_Non_GBR_Bearer = -1;
static gint ett_x2ap_ServedCells = -1;
static gint ett_x2ap_ServedCell_Information = -1;
static gint ett_x2ap_TraceActivation = -1;
static gint ett_x2ap_UE_HistoryInformation = -1;
static gint ett_x2ap_HandoverRequest = -1;
static gint ett_x2ap_UE_ContextInformation = -1;
static gint ett_x2ap_Bearers_ToBeSetup_List = -1;
static gint ett_x2ap_Bearers_ToBeSetup_Item = -1;
static gint ett_x2ap_HandoverRequestAcknowledge = -1;
static gint ett_x2ap_Bearers_Admitted_List = -1;
static gint ett_x2ap_Bearers_Admitted_Item = -1;
static gint ett_x2ap_Bearers_NotAdmitted_List = -1;
static gint ett_x2ap_Bearers_NotAdmitted_Item = -1;
static gint ett_x2ap_HandoverPreparationFailure = -1;
static gint ett_x2ap_SNStatusTransfer = -1;
static gint ett_x2ap_Bearers_SubjectToStatusTransfer_List = -1;
static gint ett_x2ap_Bearers_SubjectToStatusTransfer_Item = -1;
static gint ett_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List = -1;
static gint ett_x2ap_ReleaseResource = -1;
static gint ett_x2ap_HandoverCancel = -1;
static gint ett_x2ap_ErrorIndication = -1;
static gint ett_x2ap_ResetRequest = -1;
static gint ett_x2ap_ResetResponse = -1;
static gint ett_x2ap_X2SetupRequest = -1;
static gint ett_x2ap_X2SetupResponse = -1;
static gint ett_x2ap_X2SetupFailure = -1;
static gint ett_x2ap_LoadInformation = -1;
static gint ett_x2ap_CellInformation_List = -1;
static gint ett_x2ap_CellInformation_Item = -1;
static gint ett_x2ap_PrivateMessage = -1;
static gint ett_x2ap_X2AP_PDU = -1;
static gint ett_x2ap_InitiatingMessage = -1;
static gint ett_x2ap_SuccessfulOutcome = -1;
static gint ett_x2ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-x2ap-ett.c ---*/
#line 70 "packet-x2ap-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ddMode;
static const gchar *ProcedureID;

/* Dissector tables */
static dissector_table_t x2ap_ies_dissector_table;
static dissector_table_t x2ap_extension_dissector_table;
static dissector_table_t x2ap_proc_imsg_dissector_table;
static dissector_table_t x2ap_proc_sout_dissector_table;
static dissector_table_t x2ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/*--- Included file: packet-x2ap-fn.c ---*/
#line 1 "packet-x2ap-fn.c"

static const value_string x2ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_x2ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, maxPrivateIEs, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string x2ap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_x2ap_local          , ASN1_NO_EXTENSIONS     , dissect_x2ap_INTEGER_0_maxPrivateIEs },
  {   1, &hf_x2ap_global         , ASN1_NO_EXTENSIONS     , dissect_x2ap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string x2ap_ProcedureCode_vals[] = {
  { X2AP_ID_HANDOVERPREPARATION, "id-handoverPreparation" },
  { X2AP_ID_HANDOVERCANCEL, "id-handoverCancel" },
  { X2AP_ID_LOADINDICATION, "id-loadIndication" },
  { X2AP_ID_ERRORINDICATION, "id-errorIndication" },
  { X2AP_ID_SNSTATUSTRANSFER, "id-snStatusTransfer" },
  { X2AP_ID_RELEASERESOURCE, "id-releaseResource" },
  { X2AP_ID_X2SETUP, "id-x2Setup" },
  { X2AP_ID_RESET, "id-reset" },
  { 0, NULL }
};


static int
dissect_x2ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 61 "x2ap.cnf"
  ProcedureCode = 0xFFFF;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, &ProcedureCode, FALSE);

#line 54 "x2ap.cnf"
	if (check_col(actx->pinfo->cinfo, COL_INFO))
       col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str(ProcedureCode, x2ap_ProcedureCode_vals,
                              "unknown message"));

  return offset;
}


static const value_string x2ap_ProtocolIE_ID_vals[] = {
  { id_Bearers_Admitted_Item, "id-Bearers-Admitted-Item" },
  { id_Bearers_Admitted_List, "id-Bearers-Admitted-List" },
  { id_Bearers_NotAdmitted_Item, "id-Bearers-NotAdmitted-Item" },
  { id_Bearers_NotAdmitted_List, "id-Bearers-NotAdmitted-List" },
  { id_Bearers_ToBeSetup_Item, "id-Bearers-ToBeSetup-Item" },
  { id_Cause, "id-Cause" },
  { id_CellInformation, "id-CellInformation" },
  { id_CellInformation_Item, "id-CellInformation-Item" },
  { id_InterfacesToTrace_Item, "id-InterfacesToTrace-Item" },
  { id_New_eNB_UE_X2AP_ID, "id-New-eNB-UE-X2AP-ID" },
  { id_Old_eNB_UE_X2AP_ID, "id-Old-eNB-UE-X2AP-ID" },
  { id_TargetCell_ID, "id-TargetCell-ID" },
  { id_TargeteNBtoSource_eNBTransparentContainer, "id-TargeteNBtoSource-eNBTransparentContainer" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_UE_ContextInformation, "id-UE-ContextInformation" },
  { id_UE_HistoryInformation, "id-UE-HistoryInformation" },
  { id_UE_X2AP_ID, "id-UE-X2AP-ID" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_Bearers_SubjectToStatusTransfer_List, "id-Bearers-SubjectToStatusTransfer-List" },
  { id_Bearers_SubjectToStatusTransfer_Item, "id-Bearers-SubjectToStatusTransfer-Item" },
  { id_ServedCells, "id-ServedCells" },
  { id_ENB_ID, "id-ENB-ID" },
  { id_TimeToWait, "id-TimeToWait" },
  { 0, NULL }
};


static int
dissect_x2ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, maxProtocolIEs, &ProtocolIE_ID, FALSE);

  return offset;
}


static const value_string x2ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_x2ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_ProtocolIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_x2ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_ID },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_protocolIE_Field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_x2ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Field },
};

static int
dissect_x2ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs);

  return offset;
}



static int
dissect_x2ap_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x2ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x2ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_x2ap_extension_id   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_ID },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_x2ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolExtensionField },
};

static int
dissect_x2ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions);

  return offset;
}



static int
dissect_x2ap_PrivateIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_x2ap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_ID },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_privateIE_Field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_x2ap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_Field },
};

static int
dissect_x2ap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs);

  return offset;
}



static int
dissect_x2ap_SAE_Bearer_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AggregateMaximumBitRate_sequence[] = {
  { &hf_x2ap_aggregateMaximumBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_Bearer_BitRate },
  { &hf_x2ap_aggregateMaximumBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_Bearer_BitRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_AggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_AggregateMaximumBitRate, AggregateMaximumBitRate_sequence);

  return offset;
}



static int
dissect_x2ap_Bearer_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t BroadcastPLMNs_Item_sequence_of[1] = {
  { &hf_x2ap_BroadcastPLMNs_Item_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
};

static int
dissect_x2ap_BroadcastPLMNs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_BroadcastPLMNs_Item, BroadcastPLMNs_Item_sequence_of,
                                                  1, maxnoofBPLMNs);

  return offset;
}


static const value_string x2ap_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "unspecified" },
  {   6, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "hardware-failure" },
  {   2, "om-intervention" },
  {   3, "not-enough-user-plane-processing-resources" },
  {   4, "unspecified" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_x2ap_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseRadioNetwork },
  {   1, &hf_x2ap_transport      , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseTransport },
  {   2, &hf_x2ap_protocol       , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseProtocol },
  {   3, &hf_x2ap_misc           , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const value_string x2ap_CellType_vals[] = {
  {   0, "macro" },
  {   1, "micro" },
  {   2, "pico" },
  {   3, "femto" },
  { 0, NULL }
};


static int
dissect_x2ap_CellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_CellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_CI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t CGI_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_lAC            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_LAC },
  { &hf_x2ap_cI             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CI },
  { &hf_x2ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CGI, CGI_sequence);

  return offset;
}


static const value_string x2ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_x2ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_x2ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_ID },
  { &hf_x2ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TypeOfError },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_x2ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_x2ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProcedureCode },
  { &hf_x2ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_TriggeringMessage },
  { &hf_x2ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Criticality },
  { &hf_x2ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_CriticalityDiagnostics_IE_List },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_x2ap_DL_data_received(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string x2ap_DL_Forwarding_vals[] = {
  {   0, "dL-forwardingProposed" },
  { 0, NULL }
};


static int
dissect_x2ap_DL_Forwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t EPLMNs_sequence_of[1] = {
  { &hf_x2ap_EPLMNs_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
};

static int
dissect_x2ap_EPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_EPLMNs, EPLMNs_sequence_of,
                                                  1, maxnoofEPLMNs);

  return offset;
}


static const value_string x2ap_ForbiddenInterRATs_vals[] = {
  {   0, "all" },
  {   1, "gsm" },
  {   2, "wcdma" },
  { 0, NULL }
};


static int
dissect_x2ap_ForbiddenInterRATs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_TAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t ForbiddenTAIs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenTAIs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_TAI },
};

static int
dissect_x2ap_ForbiddenTAIs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenTAIs, ForbiddenTAIs_sequence_of,
                                                  1, maxnoofForbTAIs);

  return offset;
}


static const per_sequence_t ForbiddenTAs_Item_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_forbiddenTAIs  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenTAIs },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ForbiddenTAs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ForbiddenTAs_Item, ForbiddenTAs_Item_sequence);

  return offset;
}


static const per_sequence_t ForbiddenTAs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenTAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenTAs_Item },
};

static int
dissect_x2ap_ForbiddenTAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenTAs, ForbiddenTAs_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne);

  return offset;
}


static const per_sequence_t ForbiddenLACs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenLACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_LAC },
};

static int
dissect_x2ap_ForbiddenLACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenLACs, ForbiddenLACs_sequence_of,
                                                  1, maxnoofForbLACs);

  return offset;
}


static const per_sequence_t ForbiddenLAs_Item_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_forbiddenLACs  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenLACs },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ForbiddenLAs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ForbiddenLAs_Item, ForbiddenLAs_Item_sequence);

  return offset;
}


static const per_sequence_t ForbiddenLAs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenLAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenLAs_Item },
};

static int
dissect_x2ap_ForbiddenLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenLAs, ForbiddenLAs_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne);

  return offset;
}



static int
dissect_x2ap_Frequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL);

  return offset;
}



static int
dissect_x2ap_GTP_TEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const per_sequence_t GTPtunnelEndpoint_sequence[] = {
  { &hf_x2ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TransportLayerAddress },
  { &hf_x2ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTP_TEI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GTPtunnelEndpoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GTPtunnelEndpoint, GTPtunnelEndpoint_sequence);

  return offset;
}


static const per_sequence_t HandoverRestrictionList_sequence[] = {
  { &hf_x2ap_equivalentPLMNs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_EPLMNs },
  { &hf_x2ap_forbiddenTAs   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ForbiddenTAs },
  { &hf_x2ap_forbiddenLAs   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ForbiddenLAs },
  { &hf_x2ap_forbiddenInterRATs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ForbiddenInterRATs },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverRestrictionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverRestrictionList, HandoverRestrictionList_sequence);

  return offset;
}


static const per_sequence_t InterfacesToTrace_sequence_of[1] = {
  { &hf_x2ap_InterfacesToTrace_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_InterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_InterfacesToTrace, InterfacesToTrace_sequence_of,
                                                  0, maxInterfaces);

  return offset;
}


static const value_string x2ap_TraceInterface_vals[] = {
  {   0, "s1" },
  {   1, "x2" },
  {   2, "uu" },
  { 0, NULL }
};


static int
dissect_x2ap_TraceInterface(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  { 0, NULL }
};


static int
dissect_x2ap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t InterfacesToTrace_Item_sequence[] = {
  { &hf_x2ap_traceInterface , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TraceInterface },
  { &hf_x2ap_traceDepth     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TraceDepth },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_InterfacesToTrace_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_InterfacesToTrace_Item, InterfacesToTrace_Item_sequence);

  return offset;
}



static int
dissect_x2ap_InterferenceOverloadIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_Time_UE_StayedInCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t LastVisitedCell_Item_sequence[] = {
  { &hf_x2ap_global_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CGI },
  { &hf_x2ap_cellType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CellType },
  { &hf_x2ap_time_UE_StayedInCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Time_UE_StayedInCell },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_LastVisitedCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_LastVisitedCell_Item, LastVisitedCell_Item_sequence);

  return offset;
}



static int
dissect_x2ap_PDCP_SN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_x2ap_PhyCID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_RB_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_x2ap_RRC_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_1_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 256U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t SAE_GBR_Bearer_sequence[] = {
  { &hf_x2ap_sAE_Bearer_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_Bearer_BitRate },
  { &hf_x2ap_sAE_Bearer_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_Bearer_BitRate },
  { &hf_x2ap_sAE_Bearer_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_Bearer_BitRate },
  { &hf_x2ap_sAE_Bearer_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_Bearer_BitRate },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SAE_GBR_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SAE_GBR_Bearer, SAE_GBR_Bearer_sequence);

  return offset;
}


static const value_string x2ap_T_sAE_non_GBR_Bearer_Type_vals[] = {
  {   0, "non-GBR-Bearer" },
  { 0, NULL }
};


static int
dissect_x2ap_T_sAE_non_GBR_Bearer_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SAE_Non_GBR_Bearer_sequence[] = {
  { &hf_x2ap_sAE_non_GBR_Bearer_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_T_sAE_non_GBR_Bearer_Type },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SAE_Non_GBR_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SAE_Non_GBR_Bearer, SAE_Non_GBR_Bearer_sequence);

  return offset;
}


static const value_string x2ap_SAE_BearerType_vals[] = {
  {   0, "sAE-GBR-bearer" },
  {   1, "sAE-non-GBR-bearer" },
  { 0, NULL }
};

static const per_choice_t SAE_BearerType_choice[] = {
  {   0, &hf_x2ap_sAE_GBR_bearer , ASN1_EXTENSION_ROOT    , dissect_x2ap_SAE_GBR_Bearer },
  {   1, &hf_x2ap_sAE_non_GBR_bearer, ASN1_EXTENSION_ROOT    , dissect_x2ap_SAE_Non_GBR_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_SAE_BearerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_SAE_BearerType, SAE_BearerType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SAE_BearerLevel_QoS_Parameters_sequence[] = {
  { &hf_x2ap_label          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_1_256 },
  { &hf_x2ap_allocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_OCTET_STRING },
  { &hf_x2ap_sAE_BearerType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_BearerType },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SAE_BearerLevel_QoS_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SAE_BearerLevel_QoS_Parameters, SAE_BearerLevel_QoS_Parameters_sequence);

  return offset;
}


static const per_sequence_t ServedCell_Information_sequence[] = {
  { &hf_x2ap_phyCID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PhyCID },
  { &hf_x2ap_cellId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CellId },
  { &hf_x2ap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TAI },
  { &hf_x2ap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BroadcastPLMNs_Item },
  { &hf_x2ap_frequency      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Frequency },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCell_Information, ServedCell_Information_sequence);

  return offset;
}


static const per_sequence_t ServedCells_sequence_of[1] = {
  { &hf_x2ap_ServedCells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCell_Information },
};

static int
dissect_x2ap_ServedCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ServedCells, ServedCells_sequence_of,
                                                  1, maxCellineNB);

  return offset;
}



static int
dissect_x2ap_TargeteNBtoSource_eNBTransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_TraceReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t TraceActivation_sequence[] = {
  { &hf_x2ap_traceReference , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TraceReference },
  { &hf_x2ap_interfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_InterfacesToTrace },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TraceActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TraceActivation, TraceActivation_sequence);

  return offset;
}


static const per_sequence_t UE_HistoryInformation_sequence_of[1] = {
  { &hf_x2ap_UE_HistoryInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_LastVisitedCell_Item },
};

static int
dissect_x2ap_UE_HistoryInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_UE_HistoryInformation, UE_HistoryInformation_sequence_of,
                                                  1, maxnoofCells);

  return offset;
}



static int
dissect_x2ap_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UE_X2AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t HandoverRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverRequest, HandoverRequest_sequence);

  return offset;
}


static const per_sequence_t Bearers_ToBeSetup_List_sequence_of[1] = {
  { &hf_x2ap_Bearers_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_Bearers_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Bearers_ToBeSetup_List, Bearers_ToBeSetup_List_sequence_of,
                                                  0, maxnoofBearers);

  return offset;
}


static const per_sequence_t UE_ContextInformation_sequence[] = {
  { &hf_x2ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UE_S1AP_ID },
  { &hf_x2ap_aggregateMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AggregateMaximumBitRate },
  { &hf_x2ap_bearers_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Bearers_ToBeSetup_List },
  { &hf_x2ap_rRC_Context    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RRC_Context },
  { &hf_x2ap_servingPLMN    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_handoverRestrictionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_HandoverRestrictionList },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UE_ContextInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UE_ContextInformation, UE_ContextInformation_sequence);

  return offset;
}


static const per_sequence_t Bearers_ToBeSetup_Item_sequence[] = {
  { &hf_x2ap_sAE_Bearer_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Bearer_ID },
  { &hf_x2ap_sAE_BearerLevel_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SAE_BearerLevel_QoS_Parameters },
  { &hf_x2ap_dL_Forwarding  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_Forwarding },
  { &hf_x2ap_uL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_rB_type        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RB_type },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_Bearers_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_Bearers_ToBeSetup_Item, Bearers_ToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t HandoverRequestAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverRequestAcknowledge, HandoverRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t Bearers_Admitted_List_sequence_of[1] = {
  { &hf_x2ap_Bearers_Admitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_Bearers_Admitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Bearers_Admitted_List, Bearers_Admitted_List_sequence_of,
                                                  1, maxnoofBearers);

  return offset;
}


static const per_sequence_t Bearers_Admitted_Item_sequence[] = {
  { &hf_x2ap_bearer_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Bearer_ID },
  { &hf_x2ap_uL_GTP_TunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_dL_GTP_TunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_Bearers_Admitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_Bearers_Admitted_Item, Bearers_Admitted_Item_sequence);

  return offset;
}


static const per_sequence_t Bearers_NotAdmitted_List_sequence_of[1] = {
  { &hf_x2ap_Bearers_NotAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_Bearers_NotAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Bearers_NotAdmitted_List, Bearers_NotAdmitted_List_sequence_of,
                                                  1, maxnoofBearers);

  return offset;
}


static const per_sequence_t Bearers_NotAdmitted_Item_sequence[] = {
  { &hf_x2ap_bearer_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Bearer_ID },
  { &hf_x2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cause },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_Bearers_NotAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_Bearers_NotAdmitted_Item, Bearers_NotAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t HandoverPreparationFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverPreparationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverPreparationFailure, HandoverPreparationFailure_sequence);

  return offset;
}


static const per_sequence_t SNStatusTransfer_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SNStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SNStatusTransfer, SNStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t Bearers_SubjectToStatusTransfer_List_sequence_of[1] = {
  { &hf_x2ap_Bearers_SubjectToStatusTransfer_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_Bearers_SubjectToStatusTransfer_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Bearers_SubjectToStatusTransfer_List, Bearers_SubjectToStatusTransfer_List_sequence_of,
                                                  1, maxnoofBearers);

  return offset;
}


static const per_sequence_t PDCP_SNofULSDUsNotToBeRetransmitted_List_sequence_of[1] = {
  { &hf_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PDCP_SN },
};

static int
dissect_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List, PDCP_SNofULSDUsNotToBeRetransmitted_List_sequence_of,
                                                  1, maxnoofPDCP_SN);

  return offset;
}


static const per_sequence_t Bearers_SubjectToStatusTransfer_Item_sequence[] = {
  { &hf_x2ap_bearer_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Bearer_ID },
  { &hf_x2ap_pDCP_SNofULSDUsNotToBeRetransmitted_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List },
  { &hf_x2ap_uL_PDCP_SN_NextInSequenceExpected, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PDCP_SN },
  { &hf_x2ap_dL_PDCP_SN_NextToAssign, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PDCP_SN },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_Bearers_SubjectToStatusTransfer_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_Bearers_SubjectToStatusTransfer_Item, Bearers_SubjectToStatusTransfer_Item_sequence);

  return offset;
}


static const per_sequence_t ReleaseResource_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ReleaseResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ReleaseResource, ReleaseResource_sequence);

  return offset;
}


static const per_sequence_t HandoverCancel_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverCancel, HandoverCancel_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t ResetRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResetRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResetRequest, ResetRequest_sequence);

  return offset;
}


static const per_sequence_t ResetResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResetResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResetResponse, ResetResponse_sequence);

  return offset;
}


static const per_sequence_t X2SetupRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2SetupRequest, X2SetupRequest_sequence);

  return offset;
}


static const per_sequence_t X2SetupResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2SetupResponse, X2SetupResponse_sequence);

  return offset;
}


static const per_sequence_t X2SetupFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2SetupFailure, X2SetupFailure_sequence);

  return offset;
}


static const per_sequence_t LoadInformation_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_LoadInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_LoadInformation, LoadInformation_sequence);

  return offset;
}


static const per_sequence_t CellInformation_List_sequence_of[1] = {
  { &hf_x2ap_CellInformation_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_CellInformation_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CellInformation_List, CellInformation_List_sequence_of,
                                                  1, maxCellineNB);

  return offset;
}


static const per_sequence_t CellInformation_Item_sequence[] = {
  { &hf_x2ap_global_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CGI },
  { &hf_x2ap_interferenceOverloadIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_InterferenceOverloadIndication },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellInformation_Item, CellInformation_Item_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_x2ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}



static int
dissect_x2ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProcedureCode },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_initiatingMessage_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_x2ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProcedureCode },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_x2ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProcedureCode },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string x2ap_X2AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t X2AP_PDU_choice[] = {
  {   0, &hf_x2ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_x2ap_InitiatingMessage },
  {   1, &hf_x2ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_x2ap_SuccessfulOutcome },
  {   2, &hf_x2ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_x2ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_X2AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_X2AP_PDU, X2AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Cause(tvb, offset, &asn1_ctx, tree, hf_x2ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CGI(tvb, offset, &asn1_ctx, tree, hf_x2ap_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_x2ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ENB_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_ENB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterfacesToTrace_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_InterfacesToTrace_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_InterfacesToTrace_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ServedCells(tvb, offset, &asn1_ctx, tree, hf_x2ap_ServedCells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargeteNBtoSource_eNBTransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TargeteNBtoSource_eNBTransparentContainer(tvb, offset, &asn1_ctx, tree, hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_x2ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TraceActivation(tvb, offset, &asn1_ctx, tree, hf_x2ap_TraceActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_HistoryInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_HistoryInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_HistoryInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_X2AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_X2AP_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_X2AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ContextInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_ContextInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_ContextInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Bearers_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_Bearers_ToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_Admitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Bearers_Admitted_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_Bearers_Admitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_Admitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Bearers_Admitted_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_Bearers_Admitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_NotAdmitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Bearers_NotAdmitted_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_Bearers_NotAdmitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_NotAdmitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Bearers_NotAdmitted_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_Bearers_NotAdmitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverPreparationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverPreparationFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverPreparationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNStatusTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SNStatusTransfer(tvb, offset, &asn1_ctx, tree, hf_x2ap_SNStatusTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_SubjectToStatusTransfer_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Bearers_SubjectToStatusTransfer_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_Bearers_SubjectToStatusTransfer_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_SubjectToStatusTransfer_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Bearers_SubjectToStatusTransfer_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_Bearers_SubjectToStatusTransfer_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReleaseResource_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReleaseResource(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReleaseResource_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCancel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverCancel(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverCancel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResetResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResetResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2SetupRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2SetupResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2SetupFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LoadInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_LoadInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_LoadInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellInformation_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellInformation_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellInformation_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellInformation_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellInformation_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellInformation_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static void dissect_X2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_x2ap_X2AP_PDU(tvb, 0, &asn1_ctx, tree, hf_x2ap_X2AP_PDU_PDU);
}


/*--- End of included file: packet-x2ap-fn.c ---*/
#line 91 "packet-x2ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(x2ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(x2ap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(x2ap_proc_imsg_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(x2ap_proc_sout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(x2ap_proc_uout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static void
dissect_x2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*x2ap_item = NULL;
	proto_tree	*x2ap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "X2AP");

	/* create the x2ap protocol tree */
	x2ap_item = proto_tree_add_item(tree, proto_x2ap, tvb, 0, -1, FALSE);
	x2ap_tree = proto_item_add_subtree(x2ap_item, ett_x2ap);
	
	dissect_X2AP_PDU_PDU(tvb, pinfo, x2ap_tree);
}

/*--- proto_register_x2ap -------------------------------------------*/
void proto_register_x2ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {

/*--- Included file: packet-x2ap-hfarr.c ---*/
#line 1 "packet-x2ap-hfarr.c"
    { &hf_x2ap_Cause_PDU,
      { "Cause", "x2ap.Cause",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cause_vals), 0,
        "x2ap.Cause", HFILL }},
    { &hf_x2ap_CGI_PDU,
      { "CGI", "x2ap.CGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CGI", HFILL }},
    { &hf_x2ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "x2ap.CriticalityDiagnostics",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CriticalityDiagnostics", HFILL }},
    { &hf_x2ap_ENB_ID_PDU,
      { "ENB-ID", "x2ap.ENB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ENB_ID", HFILL }},
    { &hf_x2ap_InterfacesToTrace_Item_PDU,
      { "InterfacesToTrace-Item", "x2ap.InterfacesToTrace_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.InterfacesToTrace_Item", HFILL }},
    { &hf_x2ap_ServedCells_PDU,
      { "ServedCells", "x2ap.ServedCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ServedCells", HFILL }},
    { &hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU,
      { "TargeteNBtoSource-eNBTransparentContainer", "x2ap.TargeteNBtoSource_eNBTransparentContainer",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.TargeteNBtoSource_eNBTransparentContainer", HFILL }},
    { &hf_x2ap_TimeToWait_PDU,
      { "TimeToWait", "x2ap.TimeToWait",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.TimeToWait", HFILL }},
    { &hf_x2ap_TraceActivation_PDU,
      { "TraceActivation", "x2ap.TraceActivation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.TraceActivation", HFILL }},
    { &hf_x2ap_UE_HistoryInformation_PDU,
      { "UE-HistoryInformation", "x2ap.UE_HistoryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.UE_HistoryInformation", HFILL }},
    { &hf_x2ap_UE_X2AP_ID_PDU,
      { "UE-X2AP-ID", "x2ap.UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.UE_X2AP_ID", HFILL }},
    { &hf_x2ap_HandoverRequest_PDU,
      { "HandoverRequest", "x2ap.HandoverRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.HandoverRequest", HFILL }},
    { &hf_x2ap_UE_ContextInformation_PDU,
      { "UE-ContextInformation", "x2ap.UE_ContextInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.UE_ContextInformation", HFILL }},
    { &hf_x2ap_Bearers_ToBeSetup_Item_PDU,
      { "Bearers-ToBeSetup-Item", "x2ap.Bearers_ToBeSetup_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.Bearers_ToBeSetup_Item", HFILL }},
    { &hf_x2ap_HandoverRequestAcknowledge_PDU,
      { "HandoverRequestAcknowledge", "x2ap.HandoverRequestAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.HandoverRequestAcknowledge", HFILL }},
    { &hf_x2ap_Bearers_Admitted_List_PDU,
      { "Bearers-Admitted-List", "x2ap.Bearers_Admitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.Bearers_Admitted_List", HFILL }},
    { &hf_x2ap_Bearers_Admitted_Item_PDU,
      { "Bearers-Admitted-Item", "x2ap.Bearers_Admitted_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.Bearers_Admitted_Item", HFILL }},
    { &hf_x2ap_Bearers_NotAdmitted_List_PDU,
      { "Bearers-NotAdmitted-List", "x2ap.Bearers_NotAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.Bearers_NotAdmitted_List", HFILL }},
    { &hf_x2ap_Bearers_NotAdmitted_Item_PDU,
      { "Bearers-NotAdmitted-Item", "x2ap.Bearers_NotAdmitted_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.Bearers_NotAdmitted_Item", HFILL }},
    { &hf_x2ap_HandoverPreparationFailure_PDU,
      { "HandoverPreparationFailure", "x2ap.HandoverPreparationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.HandoverPreparationFailure", HFILL }},
    { &hf_x2ap_SNStatusTransfer_PDU,
      { "SNStatusTransfer", "x2ap.SNStatusTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.SNStatusTransfer", HFILL }},
    { &hf_x2ap_Bearers_SubjectToStatusTransfer_List_PDU,
      { "Bearers-SubjectToStatusTransfer-List", "x2ap.Bearers_SubjectToStatusTransfer_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.Bearers_SubjectToStatusTransfer_List", HFILL }},
    { &hf_x2ap_Bearers_SubjectToStatusTransfer_Item_PDU,
      { "Bearers-SubjectToStatusTransfer-Item", "x2ap.Bearers_SubjectToStatusTransfer_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.Bearers_SubjectToStatusTransfer_Item", HFILL }},
    { &hf_x2ap_ReleaseResource_PDU,
      { "ReleaseResource", "x2ap.ReleaseResource",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ReleaseResource", HFILL }},
    { &hf_x2ap_HandoverCancel_PDU,
      { "HandoverCancel", "x2ap.HandoverCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.HandoverCancel", HFILL }},
    { &hf_x2ap_ErrorIndication_PDU,
      { "ErrorIndication", "x2ap.ErrorIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ErrorIndication", HFILL }},
    { &hf_x2ap_ResetResponse_PDU,
      { "ResetResponse", "x2ap.ResetResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ResetResponse", HFILL }},
    { &hf_x2ap_X2SetupRequest_PDU,
      { "X2SetupRequest", "x2ap.X2SetupRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.X2SetupRequest", HFILL }},
    { &hf_x2ap_X2SetupResponse_PDU,
      { "X2SetupResponse", "x2ap.X2SetupResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.X2SetupResponse", HFILL }},
    { &hf_x2ap_X2SetupFailure_PDU,
      { "X2SetupFailure", "x2ap.X2SetupFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.X2SetupFailure", HFILL }},
    { &hf_x2ap_LoadInformation_PDU,
      { "LoadInformation", "x2ap.LoadInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.LoadInformation", HFILL }},
    { &hf_x2ap_CellInformation_List_PDU,
      { "CellInformation-List", "x2ap.CellInformation_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.CellInformation_List", HFILL }},
    { &hf_x2ap_CellInformation_Item_PDU,
      { "CellInformation-Item", "x2ap.CellInformation_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CellInformation_Item", HFILL }},
    { &hf_x2ap_X2AP_PDU_PDU,
      { "X2AP-PDU", "x2ap.X2AP_PDU",
        FT_UINT32, BASE_DEC, VALS(x2ap_X2AP_PDU_vals), 0,
        "x2ap.X2AP_PDU", HFILL }},
    { &hf_x2ap_local,
      { "local", "x2ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_x2ap_global,
      { "global", "x2ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "x2ap.OBJECT_IDENTIFIER", HFILL }},
    { &hf_x2ap_ProtocolIE_Container_item,
      { "Item", "x2ap.ProtocolIE_Container_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Field", HFILL }},
    { &hf_x2ap_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProtocolIE_ID_vals), 0,
        "x2ap.ProtocolIE_ID", HFILL }},
    { &hf_x2ap_criticality,
      { "criticality", "x2ap.criticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        "x2ap.Criticality", HFILL }},
    { &hf_x2ap_protocolIE_Field_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Field_value", HFILL }},
    { &hf_x2ap_ProtocolExtensionContainer_item,
      { "Item", "x2ap.ProtocolExtensionContainer_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolExtensionField", HFILL }},
    { &hf_x2ap_extension_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProtocolIE_ID_vals), 0,
        "x2ap.ProtocolIE_ID", HFILL }},
    { &hf_x2ap_extensionValue,
      { "extensionValue", "x2ap.extensionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.T_extensionValue", HFILL }},
    { &hf_x2ap_PrivateIE_Container_item,
      { "Item", "x2ap.PrivateIE_Container_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.PrivateIE_Field", HFILL }},
    { &hf_x2ap_private_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC, VALS(x2ap_PrivateIE_ID_vals), 0,
        "x2ap.PrivateIE_ID", HFILL }},
    { &hf_x2ap_privateIE_Field_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.PrivateIE_Field_value", HFILL }},
    { &hf_x2ap_aggregateMaximumBitRateDownlink,
      { "aggregateMaximumBitRateDownlink", "x2ap.aggregateMaximumBitRateDownlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.SAE_Bearer_BitRate", HFILL }},
    { &hf_x2ap_aggregateMaximumBitRateUplink,
      { "aggregateMaximumBitRateUplink", "x2ap.aggregateMaximumBitRateUplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.SAE_Bearer_BitRate", HFILL }},
    { &hf_x2ap_BroadcastPLMNs_Item_item,
      { "Item", "x2ap.BroadcastPLMNs_Item_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.PLMN_Identity", HFILL }},
    { &hf_x2ap_radioNetwork,
      { "radioNetwork", "x2ap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseRadioNetwork_vals), 0,
        "x2ap.CauseRadioNetwork", HFILL }},
    { &hf_x2ap_transport,
      { "transport", "x2ap.transport",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseTransport_vals), 0,
        "x2ap.CauseTransport", HFILL }},
    { &hf_x2ap_protocol,
      { "protocol", "x2ap.protocol",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseProtocol_vals), 0,
        "x2ap.CauseProtocol", HFILL }},
    { &hf_x2ap_misc,
      { "misc", "x2ap.misc",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseMisc_vals), 0,
        "x2ap.CauseMisc", HFILL }},
    { &hf_x2ap_pLMN_Identity,
      { "pLMN-Identity", "x2ap.pLMN_Identity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.PLMN_Identity", HFILL }},
    { &hf_x2ap_lAC,
      { "lAC", "x2ap.lAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.LAC", HFILL }},
    { &hf_x2ap_cI,
      { "cI", "x2ap.cI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.CI", HFILL }},
    { &hf_x2ap_iE_Extensions,
      { "iE-Extensions", "x2ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ProtocolExtensionContainer", HFILL }},
    { &hf_x2ap_procedureCode,
      { "procedureCode", "x2ap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProcedureCode_vals), 0,
        "x2ap.ProcedureCode", HFILL }},
    { &hf_x2ap_triggeringMessage,
      { "triggeringMessage", "x2ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(x2ap_TriggeringMessage_vals), 0,
        "x2ap.TriggeringMessage", HFILL }},
    { &hf_x2ap_procedureCriticality,
      { "procedureCriticality", "x2ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        "x2ap.Criticality", HFILL }},
    { &hf_x2ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "x2ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_x2ap_CriticalityDiagnostics_IE_List_item,
      { "Item", "x2ap.CriticalityDiagnostics_IE_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CriticalityDiagnostics_IE_List_item", HFILL }},
    { &hf_x2ap_iECriticality,
      { "iECriticality", "x2ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        "x2ap.Criticality", HFILL }},
    { &hf_x2ap_iE_ID,
      { "iE-ID", "x2ap.iE_ID",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProtocolIE_ID_vals), 0,
        "x2ap.ProtocolIE_ID", HFILL }},
    { &hf_x2ap_typeOfError,
      { "typeOfError", "x2ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(x2ap_TypeOfError_vals), 0,
        "x2ap.TypeOfError", HFILL }},
    { &hf_x2ap_EPLMNs_item,
      { "Item", "x2ap.EPLMNs_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.PLMN_Identity", HFILL }},
    { &hf_x2ap_ForbiddenTAs_item,
      { "Item", "x2ap.ForbiddenTAs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ForbiddenTAs_Item", HFILL }},
    { &hf_x2ap_forbiddenTAIs,
      { "forbiddenTAIs", "x2ap.forbiddenTAIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ForbiddenTAIs", HFILL }},
    { &hf_x2ap_ForbiddenTAIs_item,
      { "Item", "x2ap.ForbiddenTAIs_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.TAI", HFILL }},
    { &hf_x2ap_ForbiddenLAs_item,
      { "Item", "x2ap.ForbiddenLAs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ForbiddenLAs_Item", HFILL }},
    { &hf_x2ap_forbiddenLACs,
      { "forbiddenLACs", "x2ap.forbiddenLACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ForbiddenLACs", HFILL }},
    { &hf_x2ap_ForbiddenLACs_item,
      { "Item", "x2ap.ForbiddenLACs_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.LAC", HFILL }},
    { &hf_x2ap_transportLayerAddress,
      { "transportLayerAddress", "x2ap.transportLayerAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.TransportLayerAddress", HFILL }},
    { &hf_x2ap_gTP_TEID,
      { "gTP-TEID", "x2ap.gTP_TEID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.GTP_TEI", HFILL }},
    { &hf_x2ap_equivalentPLMNs,
      { "equivalentPLMNs", "x2ap.equivalentPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.EPLMNs", HFILL }},
    { &hf_x2ap_forbiddenTAs,
      { "forbiddenTAs", "x2ap.forbiddenTAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ForbiddenTAs", HFILL }},
    { &hf_x2ap_forbiddenLAs,
      { "forbiddenLAs", "x2ap.forbiddenLAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ForbiddenLAs", HFILL }},
    { &hf_x2ap_forbiddenInterRATs,
      { "forbiddenInterRATs", "x2ap.forbiddenInterRATs",
        FT_UINT32, BASE_DEC, VALS(x2ap_ForbiddenInterRATs_vals), 0,
        "x2ap.ForbiddenInterRATs", HFILL }},
    { &hf_x2ap_InterfacesToTrace_item,
      { "Item", "x2ap.InterfacesToTrace_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_traceInterface,
      { "traceInterface", "x2ap.traceInterface",
        FT_UINT32, BASE_DEC, VALS(x2ap_TraceInterface_vals), 0,
        "x2ap.TraceInterface", HFILL }},
    { &hf_x2ap_traceDepth,
      { "traceDepth", "x2ap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(x2ap_TraceDepth_vals), 0,
        "x2ap.TraceDepth", HFILL }},
    { &hf_x2ap_global_Cell_ID,
      { "global-Cell-ID", "x2ap.global_Cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CGI", HFILL }},
    { &hf_x2ap_cellType,
      { "cellType", "x2ap.cellType",
        FT_UINT32, BASE_DEC, VALS(x2ap_CellType_vals), 0,
        "x2ap.CellType", HFILL }},
    { &hf_x2ap_time_UE_StayedInCell,
      { "time-UE-StayedInCell", "x2ap.time_UE_StayedInCell",
        FT_INT32, BASE_DEC, NULL, 0,
        "x2ap.Time_UE_StayedInCell", HFILL }},
    { &hf_x2ap_label,
      { "label", "x2ap.label",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.INTEGER_1_256", HFILL }},
    { &hf_x2ap_allocationAndRetentionPriority,
      { "allocationAndRetentionPriority", "x2ap.allocationAndRetentionPriority",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.OCTET_STRING", HFILL }},
    { &hf_x2ap_sAE_BearerType,
      { "sAE-BearerType", "x2ap.sAE_BearerType",
        FT_UINT32, BASE_DEC, VALS(x2ap_SAE_BearerType_vals), 0,
        "x2ap.SAE_BearerType", HFILL }},
    { &hf_x2ap_sAE_GBR_bearer,
      { "sAE-GBR-bearer", "x2ap.sAE_GBR_bearer",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.SAE_GBR_Bearer", HFILL }},
    { &hf_x2ap_sAE_non_GBR_bearer,
      { "sAE-non-GBR-bearer", "x2ap.sAE_non_GBR_bearer",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.SAE_Non_GBR_Bearer", HFILL }},
    { &hf_x2ap_sAE_Bearer_MaximumBitrateDL,
      { "sAE-Bearer-MaximumBitrateDL", "x2ap.sAE_Bearer_MaximumBitrateDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.SAE_Bearer_BitRate", HFILL }},
    { &hf_x2ap_sAE_Bearer_MaximumBitrateUL,
      { "sAE-Bearer-MaximumBitrateUL", "x2ap.sAE_Bearer_MaximumBitrateUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.SAE_Bearer_BitRate", HFILL }},
    { &hf_x2ap_sAE_Bearer_GuaranteedBitrateDL,
      { "sAE-Bearer-GuaranteedBitrateDL", "x2ap.sAE_Bearer_GuaranteedBitrateDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.SAE_Bearer_BitRate", HFILL }},
    { &hf_x2ap_sAE_Bearer_GuaranteedBitrateUL,
      { "sAE-Bearer-GuaranteedBitrateUL", "x2ap.sAE_Bearer_GuaranteedBitrateUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.SAE_Bearer_BitRate", HFILL }},
    { &hf_x2ap_sAE_non_GBR_Bearer_Type,
      { "sAE-non-GBR-Bearer-Type", "x2ap.sAE_non_GBR_Bearer_Type",
        FT_UINT32, BASE_DEC, VALS(x2ap_T_sAE_non_GBR_Bearer_Type_vals), 0,
        "x2ap.T_sAE_non_GBR_Bearer_Type", HFILL }},
    { &hf_x2ap_ServedCells_item,
      { "Item", "x2ap.ServedCells_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ServedCell_Information", HFILL }},
    { &hf_x2ap_phyCID,
      { "phyCID", "x2ap.phyCID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.PhyCID", HFILL }},
    { &hf_x2ap_cellId,
      { "cellId", "x2ap.cellId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.CellId", HFILL }},
    { &hf_x2ap_tAI,
      { "tAI", "x2ap.tAI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.TAI", HFILL }},
    { &hf_x2ap_broadcastPLMNs,
      { "broadcastPLMNs", "x2ap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BroadcastPLMNs_Item", HFILL }},
    { &hf_x2ap_frequency,
      { "frequency", "x2ap.frequency",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.Frequency", HFILL }},
    { &hf_x2ap_traceReference,
      { "traceReference", "x2ap.traceReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.TraceReference", HFILL }},
    { &hf_x2ap_interfacesToTrace,
      { "interfacesToTrace", "x2ap.interfacesToTrace",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.InterfacesToTrace", HFILL }},
    { &hf_x2ap_UE_HistoryInformation_item,
      { "Item", "x2ap.UE_HistoryInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.LastVisitedCell_Item", HFILL }},
    { &hf_x2ap_protocolIEs,
      { "protocolIEs", "x2ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ProtocolIE_Container", HFILL }},
    { &hf_x2ap_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "x2ap.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.UE_S1AP_ID", HFILL }},
    { &hf_x2ap_aggregateMaximumBitRate,
      { "aggregateMaximumBitRate", "x2ap.aggregateMaximumBitRate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.AggregateMaximumBitRate", HFILL }},
    { &hf_x2ap_bearers_ToBeSetup_List,
      { "bearers-ToBeSetup-List", "x2ap.bearers_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.Bearers_ToBeSetup_List", HFILL }},
    { &hf_x2ap_rRC_Context,
      { "rRC-Context", "x2ap.rRC_Context",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.RRC_Context", HFILL }},
    { &hf_x2ap_servingPLMN,
      { "servingPLMN", "x2ap.servingPLMN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.PLMN_Identity", HFILL }},
    { &hf_x2ap_handoverRestrictionList,
      { "handoverRestrictionList", "x2ap.handoverRestrictionList",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.HandoverRestrictionList", HFILL }},
    { &hf_x2ap_Bearers_ToBeSetup_List_item,
      { "Item", "x2ap.Bearers_ToBeSetup_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_sAE_Bearer_ID,
      { "sAE-Bearer-ID", "x2ap.sAE_Bearer_ID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.Bearer_ID", HFILL }},
    { &hf_x2ap_sAE_BearerLevel_QoS_Parameters,
      { "sAE-BearerLevel-QoS-Parameters", "x2ap.sAE_BearerLevel_QoS_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.SAE_BearerLevel_QoS_Parameters", HFILL }},
    { &hf_x2ap_dL_Forwarding,
      { "dL-Forwarding", "x2ap.dL_Forwarding",
        FT_UINT32, BASE_DEC, VALS(x2ap_DL_Forwarding_vals), 0,
        "x2ap.DL_Forwarding", HFILL }},
    { &hf_x2ap_uL_GTPtunnelEndpoint,
      { "uL-GTPtunnelEndpoint", "x2ap.uL_GTPtunnelEndpoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_rB_type,
      { "rB-type", "x2ap.rB_type",
        FT_INT32, BASE_DEC, NULL, 0,
        "x2ap.RB_type", HFILL }},
    { &hf_x2ap_Bearers_Admitted_List_item,
      { "Item", "x2ap.Bearers_Admitted_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_bearer_ID,
      { "bearer-ID", "x2ap.bearer_ID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.Bearer_ID", HFILL }},
    { &hf_x2ap_uL_GTP_TunnelEndpoint,
      { "uL-GTP-TunnelEndpoint", "x2ap.uL_GTP_TunnelEndpoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_dL_GTP_TunnelEndpoint,
      { "dL-GTP-TunnelEndpoint", "x2ap.dL_GTP_TunnelEndpoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_Bearers_NotAdmitted_List_item,
      { "Item", "x2ap.Bearers_NotAdmitted_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_cause,
      { "cause", "x2ap.cause",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cause_vals), 0,
        "x2ap.Cause", HFILL }},
    { &hf_x2ap_Bearers_SubjectToStatusTransfer_List_item,
      { "Item", "x2ap.Bearers_SubjectToStatusTransfer_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_pDCP_SNofULSDUsNotToBeRetransmitted_List,
      { "pDCP-SNofULSDUsNotToBeRetransmitted-List", "x2ap.pDCP_SNofULSDUsNotToBeRetransmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.PDCP_SNofULSDUsNotToBeRetransmitted_List", HFILL }},
    { &hf_x2ap_uL_PDCP_SN_NextInSequenceExpected,
      { "uL-PDCP-SN-NextInSequenceExpected", "x2ap.uL_PDCP_SN_NextInSequenceExpected",
        FT_INT32, BASE_DEC, NULL, 0,
        "x2ap.PDCP_SN", HFILL }},
    { &hf_x2ap_dL_PDCP_SN_NextToAssign,
      { "dL-PDCP-SN-NextToAssign", "x2ap.dL_PDCP_SN_NextToAssign",
        FT_INT32, BASE_DEC, NULL, 0,
        "x2ap.PDCP_SN", HFILL }},
    { &hf_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List_item,
      { "Item", "x2ap.PDCP_SNofULSDUsNotToBeRetransmitted_List_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "x2ap.PDCP_SN", HFILL }},
    { &hf_x2ap_CellInformation_List_item,
      { "Item", "x2ap.CellInformation_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_interferenceOverloadIndication,
      { "interferenceOverloadIndication", "x2ap.interferenceOverloadIndication",
        FT_BYTES, BASE_HEX, NULL, 0,
        "x2ap.InterferenceOverloadIndication", HFILL }},
    { &hf_x2ap_privateIEs,
      { "privateIEs", "x2ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.PrivateIE_Container", HFILL }},
    { &hf_x2ap_initiatingMessage,
      { "initiatingMessage", "x2ap.initiatingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.InitiatingMessage", HFILL }},
    { &hf_x2ap_successfulOutcome,
      { "successfulOutcome", "x2ap.successfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.SuccessfulOutcome", HFILL }},
    { &hf_x2ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "x2ap.unsuccessfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.UnsuccessfulOutcome", HFILL }},
    { &hf_x2ap_initiatingMessage_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.InitiatingMessage_value", HFILL }},
    { &hf_x2ap_successfulOutcome_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.SuccessfulOutcome_value", HFILL }},
    { &hf_x2ap_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-x2ap-hfarr.c ---*/
#line 144 "packet-x2ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_x2ap,

/*--- Included file: packet-x2ap-ettarr.c ---*/
#line 1 "packet-x2ap-ettarr.c"
    &ett_x2ap_PrivateIE_ID,
    &ett_x2ap_ProtocolIE_Container,
    &ett_x2ap_ProtocolIE_Field,
    &ett_x2ap_ProtocolExtensionContainer,
    &ett_x2ap_ProtocolExtensionField,
    &ett_x2ap_PrivateIE_Container,
    &ett_x2ap_PrivateIE_Field,
    &ett_x2ap_AggregateMaximumBitRate,
    &ett_x2ap_BroadcastPLMNs_Item,
    &ett_x2ap_Cause,
    &ett_x2ap_CGI,
    &ett_x2ap_CriticalityDiagnostics,
    &ett_x2ap_CriticalityDiagnostics_IE_List,
    &ett_x2ap_CriticalityDiagnostics_IE_List_item,
    &ett_x2ap_EPLMNs,
    &ett_x2ap_ForbiddenTAs,
    &ett_x2ap_ForbiddenTAs_Item,
    &ett_x2ap_ForbiddenTAIs,
    &ett_x2ap_ForbiddenLAs,
    &ett_x2ap_ForbiddenLAs_Item,
    &ett_x2ap_ForbiddenLACs,
    &ett_x2ap_GTPtunnelEndpoint,
    &ett_x2ap_HandoverRestrictionList,
    &ett_x2ap_InterfacesToTrace,
    &ett_x2ap_InterfacesToTrace_Item,
    &ett_x2ap_LastVisitedCell_Item,
    &ett_x2ap_SAE_BearerLevel_QoS_Parameters,
    &ett_x2ap_SAE_BearerType,
    &ett_x2ap_SAE_GBR_Bearer,
    &ett_x2ap_SAE_Non_GBR_Bearer,
    &ett_x2ap_ServedCells,
    &ett_x2ap_ServedCell_Information,
    &ett_x2ap_TraceActivation,
    &ett_x2ap_UE_HistoryInformation,
    &ett_x2ap_HandoverRequest,
    &ett_x2ap_UE_ContextInformation,
    &ett_x2ap_Bearers_ToBeSetup_List,
    &ett_x2ap_Bearers_ToBeSetup_Item,
    &ett_x2ap_HandoverRequestAcknowledge,
    &ett_x2ap_Bearers_Admitted_List,
    &ett_x2ap_Bearers_Admitted_Item,
    &ett_x2ap_Bearers_NotAdmitted_List,
    &ett_x2ap_Bearers_NotAdmitted_Item,
    &ett_x2ap_HandoverPreparationFailure,
    &ett_x2ap_SNStatusTransfer,
    &ett_x2ap_Bearers_SubjectToStatusTransfer_List,
    &ett_x2ap_Bearers_SubjectToStatusTransfer_Item,
    &ett_x2ap_PDCP_SNofULSDUsNotToBeRetransmitted_List,
    &ett_x2ap_ReleaseResource,
    &ett_x2ap_HandoverCancel,
    &ett_x2ap_ErrorIndication,
    &ett_x2ap_ResetRequest,
    &ett_x2ap_ResetResponse,
    &ett_x2ap_X2SetupRequest,
    &ett_x2ap_X2SetupResponse,
    &ett_x2ap_X2SetupFailure,
    &ett_x2ap_LoadInformation,
    &ett_x2ap_CellInformation_List,
    &ett_x2ap_CellInformation_Item,
    &ett_x2ap_PrivateMessage,
    &ett_x2ap_X2AP_PDU,
    &ett_x2ap_InitiatingMessage,
    &ett_x2ap_SuccessfulOutcome,
    &ett_x2ap_UnsuccessfulOutcome,

/*--- End of included file: packet-x2ap-ettarr.c ---*/
#line 150 "packet-x2ap-template.c"
  };


  /* Register protocol */
  proto_x2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
 
  /* Register dissector */
  register_dissector("x2ap", dissect_x2ap, proto_x2ap);
  x2ap_handle = find_dissector("x2ap");

  /* Register dissector tables */
  x2ap_ies_dissector_table = register_dissector_table("x2ap.ies", "X2AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  x2ap_extension_dissector_table = register_dissector_table("x2ap.extension", "X2AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  x2ap_proc_imsg_dissector_table = register_dissector_table("x2ap.proc.imsg", "X2AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_STRING, BASE_NONE);
  x2ap_proc_sout_dissector_table = register_dissector_table("x2ap.proc.sout", "X2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_STRING, BASE_NONE);
  x2ap_proc_uout_dissector_table = register_dissector_table("x2ap.proc.uout", "X2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_STRING, BASE_NONE);

}


/*--- proto_reg_handoff_x2ap ---------------------------------------*/
void
proto_reg_handoff_x2ap(void)
{

	dissector_add("sctp.port", 0, x2ap_handle);


/*--- Included file: packet-x2ap-dis-tab.c ---*/
#line 1 "packet-x2ap-dis-tab.c"
  dissector_add("x2ap.ies", id_Bearers_Admitted_Item, new_create_dissector_handle(dissect_Bearers_Admitted_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_Admitted_List, new_create_dissector_handle(dissect_Bearers_Admitted_List_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_NotAdmitted_Item, new_create_dissector_handle(dissect_Bearers_NotAdmitted_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_NotAdmitted_List, new_create_dissector_handle(dissect_Bearers_NotAdmitted_List_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_ToBeSetup_Item, new_create_dissector_handle(dissect_Bearers_ToBeSetup_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CellInformation, new_create_dissector_handle(dissect_CellInformation_List_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CellInformation_Item, new_create_dissector_handle(dissect_CellInformation_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_InterfacesToTrace_Item, new_create_dissector_handle(dissect_InterfacesToTrace_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_New_eNB_UE_X2AP_ID, new_create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Old_eNB_UE_X2AP_ID, new_create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_TargetCell_ID, new_create_dissector_handle(dissect_CGI_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_TargeteNBtoSource_eNBTransparentContainer, new_create_dissector_handle(dissect_TargeteNBtoSource_eNBTransparentContainer_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_TraceActivation, new_create_dissector_handle(dissect_TraceActivation_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_UE_ContextInformation, new_create_dissector_handle(dissect_UE_ContextInformation_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_UE_HistoryInformation, new_create_dissector_handle(dissect_UE_HistoryInformation_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_UE_X2AP_ID, new_create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_SubjectToStatusTransfer_List, new_create_dissector_handle(dissect_Bearers_SubjectToStatusTransfer_List_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_SubjectToStatusTransfer_Item, new_create_dissector_handle(dissect_Bearers_SubjectToStatusTransfer_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_ServedCells, new_create_dissector_handle(dissect_ServedCells_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_ENB_ID, new_create_dissector_handle(dissect_ENB_ID_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_TimeToWait, new_create_dissector_handle(dissect_TimeToWait_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-handoverPreparation", new_create_dissector_handle(dissect_HandoverRequest_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.sout", "id-handoverPreparation", new_create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.uout", "id-handoverPreparation", new_create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-snStatusTransfer", new_create_dissector_handle(dissect_SNStatusTransfer_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-releaseResource", new_create_dissector_handle(dissect_ReleaseResource_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-handoverCancel", new_create_dissector_handle(dissect_HandoverCancel_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-errorIndication", new_create_dissector_handle(dissect_ErrorIndication_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-reset", new_create_dissector_handle(dissect_ResetResponse_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-x2Setup", new_create_dissector_handle(dissect_X2SetupRequest_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.sout", "id-x2Setup", new_create_dissector_handle(dissect_X2SetupResponse_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.uout", "id-x2Setup", new_create_dissector_handle(dissect_X2SetupFailure_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "LoadInformation", new_create_dissector_handle(dissect_LoadInformation_PDU, proto_x2ap));


/*--- End of included file: packet-x2ap-dis-tab.c ---*/
#line 181 "packet-x2ap-template.c"
}


