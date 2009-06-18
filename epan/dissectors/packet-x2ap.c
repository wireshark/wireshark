/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-x2ap.c                                                              */
/* ../../tools/asn2wrs.py -p x2ap -c ./x2ap.cnf -s ./packet-x2ap-template -D . X2AP-CommonDataTypes.asn X2AP-Constants.asn X2AP-Containers.asn X2AP-IEs.asn X2AP-PDU-Contents.asn X2AP-PDU-Descriptions.asn */

/* Input file: packet-x2ap-template.c */

#line 1 "packet-x2ap-template.c"
/* packet-x2ap.c
 * Routines for dissecting Evolved Universal Terrestrial Radio Access Network (EUTRAN);
 * X2 Application Protocol (X2AP);
 * 3GPP TS 36.423 packet dissection
 * Copyright 2007-2008, Anders Broman <anders.broman@ericsson.com>
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
#define maxEARFCN                      32767
#define maxInterfaces                  16
#define maxCellineNB                   256
#define maxnoofCells                   16
#define maxnoofBearers                 256
#define maxNrOfErrors                  256
#define maxnoofPDCP_SN                 16
#define maxnoofEPLMNs                  15
#define maxnoofEPLMNsPlusOne           16
#define maxnoofForbLACs                4096
#define maxnoofForbTACs                4096
#define maxnoofBPLMNs                  6
#define maxnoofPRBs                    110
#define maxPools                       16

/* enumerated values for ProcedureCode */
#define X2AP_ID_HANDOVERPREPARATION   0
#define X2AP_ID_HANDOVERCANCEL   1
#define X2AP_ID_LOADINDICATION   2
#define X2AP_ID_ERRORINDICATION   3
#define X2AP_ID_SNSTATUSTRANSFER   4
#define X2AP_ID_UECONTEXTRELEASE   5
#define X2AP_ID_X2SETUP   6
#define X2AP_ID_RESET   7
#define X2AP_ID_ENBCONFIGURATIONUPDATE   8
#define X2AP_ID_RESOURCESTATUSUPDATEINITIATION   9
#define X2AP_ID_RESOURCESTATUSREPORTING  10

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
  id_GlobalENB_ID =  21,
  id_TimeToWait =  22,
  id_GUMMEI_ID =  23,
  id_GUGroupIDList =  24,
  id_ServedCellsToAdd =  25,
  id_ServedCellsToModify =  26,
  id_ServedCellsToDelete =  27,
  id_Registration_Request =  28,
  id_CellToReport =  29,
  id_ReportingPeriodicity =  30,
  id_CellToReport_Item =  31,
  id_CellMeasurementResult =  32,
  id_CellMeasurementResult_Item =  33,
  id_GUGroupIDListToAdd =  34,
  id_GUGroupIDListToDelete =  35
} ProtocolIE_ID_enum;

/*--- End of included file: packet-x2ap-val.h ---*/
#line 57 "packet-x2ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_x2ap = -1;


/*--- Included file: packet-x2ap-hf.c ---*/
#line 1 "packet-x2ap-hf.c"
static int hf_x2ap_Cause_PDU = -1;                /* Cause */
static int hf_x2ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_x2ap_ECGI_PDU = -1;                 /* ECGI */
static int hf_x2ap_GlobalENB_ID_PDU = -1;         /* GlobalENB_ID */
static int hf_x2ap_GUGroupIDList_PDU = -1;        /* GUGroupIDList */
static int hf_x2ap_GUMMEI_PDU = -1;               /* GUMMEI */
static int hf_x2ap_InterfacesToTrace_Item_PDU = -1;  /* InterfacesToTrace_Item */
static int hf_x2ap_Registration_Request_PDU = -1;  /* Registration_Request */
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
static int hf_x2ap_UEContextRelease_PDU = -1;     /* UEContextRelease */
static int hf_x2ap_HandoverCancel_PDU = -1;       /* HandoverCancel */
static int hf_x2ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_x2ap_ResetRequest_PDU = -1;         /* ResetRequest */
static int hf_x2ap_ResetResponse_PDU = -1;        /* ResetResponse */
static int hf_x2ap_X2SetupRequest_PDU = -1;       /* X2SetupRequest */
static int hf_x2ap_X2SetupResponse_PDU = -1;      /* X2SetupResponse */
static int hf_x2ap_X2SetupFailure_PDU = -1;       /* X2SetupFailure */
static int hf_x2ap_LoadInformation_PDU = -1;      /* LoadInformation */
static int hf_x2ap_CellInformation_List_PDU = -1;  /* CellInformation_List */
static int hf_x2ap_CellInformation_Item_PDU = -1;  /* CellInformation_Item */
static int hf_x2ap_ENBConfigurationUpdate_PDU = -1;  /* ENBConfigurationUpdate */
static int hf_x2ap_ServedCellsToModify_PDU = -1;  /* ServedCellsToModify */
static int hf_x2ap_Old_ECGIs_PDU = -1;            /* Old_ECGIs */
static int hf_x2ap_ENBConfigurationUpdateAcknowledge_PDU = -1;  /* ENBConfigurationUpdateAcknowledge */
static int hf_x2ap_ENBConfigurationUpdateFailure_PDU = -1;  /* ENBConfigurationUpdateFailure */
static int hf_x2ap_ResourceStatusRequest_PDU = -1;  /* ResourceStatusRequest */
static int hf_x2ap_CellToReport_List_PDU = -1;    /* CellToReport_List */
static int hf_x2ap_CellToReport_Item_PDU = -1;    /* CellToReport_Item */
static int hf_x2ap_ReportingPeriod_PDU = -1;      /* ReportingPeriod */
static int hf_x2ap_ResourceStatusResponse_PDU = -1;  /* ResourceStatusResponse */
static int hf_x2ap_ResourceStatusFailure_PDU = -1;  /* ResourceStatusFailure */
static int hf_x2ap_ResourceStatusUpdate_PDU = -1;  /* ResourceStatusUpdate */
static int hf_x2ap_CellMeasurementResult_List_PDU = -1;  /* CellMeasurementResult_List */
static int hf_x2ap_CellMeasurementResult_Item_PDU = -1;  /* CellMeasurementResult_Item */
static int hf_x2ap_X2AP_PDU_PDU = -1;             /* X2AP_PDU */
static int hf_x2ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_x2ap_id = -1;                       /* ProtocolIE_ID */
static int hf_x2ap_criticality = -1;              /* Criticality */
static int hf_x2ap_protocolIE_Field_value = -1;   /* ProtocolIE_Field_value */
static int hf_x2ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_x2ap_extension_id = -1;             /* ProtocolIE_ID */
static int hf_x2ap_extensionValue = -1;           /* T_extensionValue */
static int hf_x2ap_BroadcastPLMNs_Item_item = -1;  /* PLMN_Identity */
static int hf_x2ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_x2ap_transport = -1;                /* CauseTransport */
static int hf_x2ap_protocol = -1;                 /* CauseProtocol */
static int hf_x2ap_misc = -1;                     /* CauseMisc */
static int hf_x2ap_pDCP_SN = -1;                  /* PDCP_SN */
static int hf_x2ap_hFN = -1;                      /* HFN */
static int hf_x2ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_x2ap_procedureCode = -1;            /* ProcedureCode */
static int hf_x2ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_x2ap_procedureCriticality = -1;     /* Criticality */
static int hf_x2ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_x2ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_x2ap_iECriticality = -1;            /* Criticality */
static int hf_x2ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_x2ap_typeOfError = -1;              /* TypeOfError */
static int hf_x2ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_x2ap_eUTRANcellIdentifier = -1;     /* EUTRANCellIdentifier */
static int hf_x2ap_macro_eNB_ID = -1;             /* BIT_STRING_SIZE_20 */
static int hf_x2ap_home_eNB_ID = -1;              /* BIT_STRING_SIZE_28 */
static int hf_x2ap_EPLMNs_item = -1;              /* PLMN_Identity */
static int hf_x2ap_ForbiddenTAs_item = -1;        /* ForbiddenTAs_Item */
static int hf_x2ap_forbiddenTACs = -1;            /* ForbiddenTACs */
static int hf_x2ap_ForbiddenTACs_item = -1;       /* TAC */
static int hf_x2ap_ForbiddenLAs_item = -1;        /* ForbiddenLAs_Item */
static int hf_x2ap_forbiddenLACs = -1;            /* ForbiddenLACs */
static int hf_x2ap_ForbiddenLACs_item = -1;       /* LAC */
static int hf_x2ap_sAE_Bearer_MaximumBitrateDL = -1;  /* BitRate */
static int hf_x2ap_sAE_Bearer_MaximumBitrateUL = -1;  /* BitRate */
static int hf_x2ap_sAE_Bearer_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_x2ap_sAE_Bearer_GuaranteedBitrateUL = -1;  /* BitRate */
static int hf_x2ap_eNB_ID = -1;                   /* ENB_ID */
static int hf_x2ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_x2ap_gTP_TEID = -1;                 /* GTP_TEI */
static int hf_x2ap_GUGroupIDList_item = -1;       /* GU_Group_ID */
static int hf_x2ap_mME_Group_ID = -1;             /* MME_Group_ID */
static int hf_x2ap_gU_Group_ID = -1;              /* GU_Group_ID */
static int hf_x2ap_mMME_Code = -1;                /* MME_Code */
static int hf_x2ap_servingPLMN = -1;              /* PLMN_Identity */
static int hf_x2ap_equivalentPLMNs = -1;          /* EPLMNs */
static int hf_x2ap_forbiddenTAs = -1;             /* ForbiddenTAs */
static int hf_x2ap_forbiddenLAs = -1;             /* ForbiddenLAs */
static int hf_x2ap_forbiddenInterRATs = -1;       /* ForbiddenInterRATs */
static int hf_x2ap_InterfacesToTrace_item = -1;   /* ProtocolIE_Single_Container */
static int hf_x2ap_traceInterface = -1;           /* TraceInterface */
static int hf_x2ap_traceDepth = -1;               /* TraceDepth */
static int hf_x2ap_global_Cell_ID = -1;           /* ECGI */
static int hf_x2ap_cellType = -1;                 /* CellType */
static int hf_x2ap_time_UE_StayedInCell = -1;     /* Time_UE_StayedInCell */
static int hf_x2ap_eventType = -1;                /* EventType */
static int hf_x2ap_reportArea = -1;               /* ReportArea */
static int hf_x2ap_rNTP_PerPRB = -1;              /* BIT_STRING_SIZE_6_110_ */
static int hf_x2ap_rNTP_Threshold = -1;           /* RNTP_Threshold */
static int hf_x2ap_numberOfCellSpecificAntennaPorts = -1;  /* T_numberOfCellSpecificAntennaPorts */
static int hf_x2ap_p_B = -1;                      /* INTEGER_0_3_ */
static int hf_x2ap_pDCCH_InterferenceImpact = -1;  /* INTEGER_0_4_ */
static int hf_x2ap_qCI = -1;                      /* QCI */
static int hf_x2ap_allocationAndRetentionPriority = -1;  /* AllocationAndRetentionPriority */
static int hf_x2ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_x2ap_ServedCells_item = -1;         /* ServedCell_Information */
static int hf_x2ap_phyCID = -1;                   /* PhyCID */
static int hf_x2ap_cellId = -1;                   /* ECGI */
static int hf_x2ap_tAC = -1;                      /* TAC */
static int hf_x2ap_broadcastPLMNs = -1;           /* BroadcastPLMNs_Item */
static int hf_x2ap_uL_EARFCN = -1;                /* EARFCN */
static int hf_x2ap_dL_EARFCN = -1;                /* EARFCN */
static int hf_x2ap_cell_Transmission_Bandwidth = -1;  /* Cell_Transmission_Bandwidth */
static int hf_x2ap_traceReference = -1;           /* TraceReference */
static int hf_x2ap_interfacesToTrace = -1;        /* InterfacesToTrace */
static int hf_x2ap_UE_HistoryInformation_item = -1;  /* LastVisitedCell_Item */
static int hf_x2ap_uEaggregateMaximumBitRateDownlink = -1;  /* BitRate */
static int hf_x2ap_uEaggregateMaximumBitRateUplink = -1;  /* BitRate */
static int hf_x2ap_UL_InterferenceOverloadIndication_item = -1;  /* UL_InterferenceOverloadIndication_Item */
static int hf_x2ap_UL_HighInterferenceIndicationInfo_item = -1;  /* UL_HighInterferenceIndicationInfo_Item */
static int hf_x2ap_ul_interferenceindication = -1;  /* UL_HighInterferenceIndication */
static int hf_x2ap_target_Cell_ID = -1;           /* ECGI */
static int hf_x2ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_x2ap_mME_UE_S1AP_ID = -1;           /* UE_S1AP_ID */
static int hf_x2ap_uEaggregateMaximumBitRate = -1;  /* UEAggregateMaximumBitRate */
static int hf_x2ap_subscriberProfileIDforRFP = -1;  /* SubscriberProfileIDforRFP */
static int hf_x2ap_bearers_ToBeSetup_List = -1;   /* Bearers_ToBeSetup_List */
static int hf_x2ap_rRC_Context = -1;              /* RRC_Context */
static int hf_x2ap_handoverRestrictionList = -1;  /* HandoverRestrictionList */
static int hf_x2ap_locationReportingInformation = -1;  /* LocationReportingInformation */
static int hf_x2ap_Bearers_ToBeSetup_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sAE_Bearer_ID = -1;            /* Bearer_ID */
static int hf_x2ap_sAE_BearerLevel_QoS_Parameters = -1;  /* SAE_BearerLevel_QoS_Parameters */
static int hf_x2ap_dL_Forwarding = -1;            /* DL_Forwarding */
static int hf_x2ap_uL_GTPtunnelEndpoint = -1;     /* GTPtunnelEndpoint */
static int hf_x2ap_Bearers_Admitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_bearer_ID = -1;                /* Bearer_ID */
static int hf_x2ap_uL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_dL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_Bearers_NotAdmitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_cause = -1;                    /* Cause */
static int hf_x2ap_Bearers_SubjectToStatusTransfer_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_receiveStatusofULPDCPSDUs = -1;  /* ReceiveStatusofULPDCPSDUs */
static int hf_x2ap_uL_COUNTvalue = -1;            /* COUNTvalue */
static int hf_x2ap_dL_COUNTvalue = -1;            /* COUNTvalue */
static int hf_x2ap_CellInformation_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_cell_ID = -1;                  /* ECGI */
static int hf_x2ap_ul_InterferenceOverloadIndication = -1;  /* UL_InterferenceOverloadIndication */
static int hf_x2ap_ul_HighInterferenceIndicationInfo = -1;  /* UL_HighInterferenceIndicationInfo */
static int hf_x2ap_relativeNarrowbandTxPower = -1;  /* RelativeNarrowbandTxPower */
static int hf_x2ap_ServedCellsToModify_item = -1;  /* ServedCellsToModify_Item */
static int hf_x2ap_old_ecgi = -1;                 /* ECGI */
static int hf_x2ap_served_cells = -1;             /* ServedCell_Information */
static int hf_x2ap_Old_ECGIs_item = -1;           /* ECGI */
static int hf_x2ap_CellToReport_List_item = -1;   /* ProtocolIE_Single_Container */
static int hf_x2ap_CellMeasurementResult_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_resoureStatus = -1;            /* ResourceStatus */
static int hf_x2ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_x2ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_x2ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_x2ap_initiatingMessage_value = -1;  /* InitiatingMessage_value */
static int hf_x2ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_x2ap_value = -1;                    /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-x2ap-hf.c ---*/
#line 62 "packet-x2ap-template.c"

/* Initialize the subtree pointers */
static int ett_x2ap = -1;


/*--- Included file: packet-x2ap-ett.c ---*/
#line 1 "packet-x2ap-ett.c"
static gint ett_x2ap_ProtocolIE_Container = -1;
static gint ett_x2ap_ProtocolIE_Field = -1;
static gint ett_x2ap_ProtocolExtensionContainer = -1;
static gint ett_x2ap_ProtocolExtensionField = -1;
static gint ett_x2ap_BroadcastPLMNs_Item = -1;
static gint ett_x2ap_Cause = -1;
static gint ett_x2ap_COUNTvalue = -1;
static gint ett_x2ap_CriticalityDiagnostics = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_x2ap_ECGI = -1;
static gint ett_x2ap_ENB_ID = -1;
static gint ett_x2ap_EPLMNs = -1;
static gint ett_x2ap_ForbiddenTAs = -1;
static gint ett_x2ap_ForbiddenTAs_Item = -1;
static gint ett_x2ap_ForbiddenTACs = -1;
static gint ett_x2ap_ForbiddenLAs = -1;
static gint ett_x2ap_ForbiddenLAs_Item = -1;
static gint ett_x2ap_ForbiddenLACs = -1;
static gint ett_x2ap_GBR_QosInformation = -1;
static gint ett_x2ap_GlobalENB_ID = -1;
static gint ett_x2ap_GTPtunnelEndpoint = -1;
static gint ett_x2ap_GUGroupIDList = -1;
static gint ett_x2ap_GU_Group_ID = -1;
static gint ett_x2ap_GUMMEI = -1;
static gint ett_x2ap_HandoverRestrictionList = -1;
static gint ett_x2ap_InterfacesToTrace = -1;
static gint ett_x2ap_InterfacesToTrace_Item = -1;
static gint ett_x2ap_LastVisitedCell_Item = -1;
static gint ett_x2ap_LocationReportingInformation = -1;
static gint ett_x2ap_RelativeNarrowbandTxPower = -1;
static gint ett_x2ap_SAE_BearerLevel_QoS_Parameters = -1;
static gint ett_x2ap_ServedCells = -1;
static gint ett_x2ap_ServedCell_Information = -1;
static gint ett_x2ap_TraceActivation = -1;
static gint ett_x2ap_UE_HistoryInformation = -1;
static gint ett_x2ap_UEAggregateMaximumBitRate = -1;
static gint ett_x2ap_UL_InterferenceOverloadIndication = -1;
static gint ett_x2ap_UL_HighInterferenceIndicationInfo = -1;
static gint ett_x2ap_UL_HighInterferenceIndicationInfo_Item = -1;
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
static gint ett_x2ap_UEContextRelease = -1;
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
static gint ett_x2ap_ENBConfigurationUpdate = -1;
static gint ett_x2ap_ServedCellsToModify = -1;
static gint ett_x2ap_ServedCellsToModify_Item = -1;
static gint ett_x2ap_Old_ECGIs = -1;
static gint ett_x2ap_ENBConfigurationUpdateAcknowledge = -1;
static gint ett_x2ap_ENBConfigurationUpdateFailure = -1;
static gint ett_x2ap_ResourceStatusRequest = -1;
static gint ett_x2ap_CellToReport_List = -1;
static gint ett_x2ap_CellToReport_Item = -1;
static gint ett_x2ap_ResourceStatusResponse = -1;
static gint ett_x2ap_ResourceStatusFailure = -1;
static gint ett_x2ap_ResourceStatusUpdate = -1;
static gint ett_x2ap_CellMeasurementResult_List = -1;
static gint ett_x2ap_CellMeasurementResult_Item = -1;
static gint ett_x2ap_X2AP_PDU = -1;
static gint ett_x2ap_InitiatingMessage = -1;
static gint ett_x2ap_SuccessfulOutcome = -1;
static gint ett_x2ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-x2ap-ett.c ---*/
#line 67 "packet-x2ap-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
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


static const value_string x2ap_ProcedureCode_vals[] = {
  { X2AP_ID_HANDOVERPREPARATION, "id-handoverPreparation" },
  { X2AP_ID_HANDOVERCANCEL, "id-handoverCancel" },
  { X2AP_ID_LOADINDICATION, "id-loadIndication" },
  { X2AP_ID_ERRORINDICATION, "id-errorIndication" },
  { X2AP_ID_SNSTATUSTRANSFER, "id-snStatusTransfer" },
  { X2AP_ID_UECONTEXTRELEASE, "id-uEContextRelease" },
  { X2AP_ID_X2SETUP, "id-x2Setup" },
  { X2AP_ID_RESET, "id-reset" },
  { X2AP_ID_ENBCONFIGURATIONUPDATE, "id-eNBConfigurationUpdate" },
  { X2AP_ID_RESOURCESTATUSUPDATEINITIATION, "id-resourceStatusUpdateInitiation" },
  { X2AP_ID_RESOURCESTATUSREPORTING, "id-resourceStatusReporting" },
  { 0, NULL }
};


static int
dissect_x2ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 69 "x2ap.cnf"
  ProcedureCode = 0xFFFF;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 62 "x2ap.cnf"
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
  { id_GlobalENB_ID, "id-GlobalENB-ID" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_GUMMEI_ID, "id-GUMMEI-ID" },
  { id_GUGroupIDList, "id-GUGroupIDList" },
  { id_ServedCellsToAdd, "id-ServedCellsToAdd" },
  { id_ServedCellsToModify, "id-ServedCellsToModify" },
  { id_ServedCellsToDelete, "id-ServedCellsToDelete" },
  { id_Registration_Request, "id-Registration-Request" },
  { id_CellToReport, "id-CellToReport" },
  { id_ReportingPeriodicity, "id-ReportingPeriodicity" },
  { id_CellToReport_Item, "id-CellToReport-Item" },
  { id_CellMeasurementResult, "id-CellMeasurementResult" },
  { id_CellMeasurementResult_Item, "id-CellMeasurementResult-Item" },
  { id_GUGroupIDListToAdd, "id-GUGroupIDListToAdd" },
  { id_GUGroupIDListToDelete, "id-GUGroupIDListToDelete" },
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
                                                  0, maxProtocolIEs, FALSE);

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
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_x2ap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_Bearer_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GINT64_CONSTANT(10000000000U), NULL, FALSE);

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
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}


static const value_string x2ap_CauseRadioNetwork_vals[] = {
  {   0, "handover-desirable-for-radio-reasons" },
  {   1, "time-critical-handover" },
  {   2, "resource-optimisation-handover" },
  {   3, "reduce-load-in-serving-cell" },
  {   4, "partial-handover" },
  {   5, "unknown-new-eNB-UE-X2AP-ID" },
  {   6, "unknown-old-eNB-UE-X2AP-ID" },
  {   7, "unknown-pair-of-UE-X2AP-ID" },
  {   8, "ho-target-not-allowed" },
  {   9, "tx2relocoverall-expiry" },
  {  10, "trelocprep-expiry" },
  {  11, "cell-not-available" },
  {  12, "no-radio-resources-available-in-target-cell" },
  {  13, "invalid-MME-GroupID" },
  {  14, "unknown-MME-Code" },
  {  15, "unspecified" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

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


static const value_string x2ap_Cell_Transmission_Bandwidth_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  { 0, NULL }
};


static int
dissect_x2ap_Cell_Transmission_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_PDCP_SN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_HFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNTvalue_sequence[] = {
  { &hf_x2ap_pDCP_SN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PDCP_SN },
  { &hf_x2ap_hFN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_HFN },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_COUNTvalue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_COUNTvalue, COUNTvalue_sequence);

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
                                                  1, maxNrOfErrors, FALSE);

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
dissect_x2ap_EARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxEARFCN, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_EUTRANCellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}


static const per_sequence_t ECGI_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_eUTRANcellIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EUTRANCellIdentifier },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ECGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ECGI, ECGI_sequence);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}


static const value_string x2ap_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_x2ap_macro_eNB_ID   , ASN1_EXTENSION_ROOT    , dissect_x2ap_BIT_STRING_SIZE_20 },
  {   1, &hf_x2ap_home_eNB_ID    , ASN1_EXTENSION_ROOT    , dissect_x2ap_BIT_STRING_SIZE_28 },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EPLMNs_sequence_of[1] = {
  { &hf_x2ap_EPLMNs_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
};

static int
dissect_x2ap_EPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_EPLMNs, EPLMNs_sequence_of,
                                                  1, maxnoofEPLMNs, FALSE);

  return offset;
}


static const value_string x2ap_EventType_vals[] = {
  {   0, "change-of-serving-cell" },
  { 0, NULL }
};


static int
dissect_x2ap_EventType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_ForbiddenInterRATs_vals[] = {
  {   0, "all" },
  {   1, "geran" },
  {   2, "utran" },
  { 0, NULL }
};


static int
dissect_x2ap_ForbiddenInterRATs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t ForbiddenTACs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenTACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_TAC },
};

static int
dissect_x2ap_ForbiddenTACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenTACs, ForbiddenTACs_sequence_of,
                                                  1, maxnoofForbTACs, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenTAs_Item_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_forbiddenTACs  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenTACs },
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
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}



static int
dissect_x2ap_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t ForbiddenLACs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenLACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_LAC },
};

static int
dissect_x2ap_ForbiddenLACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenLACs, ForbiddenLACs_sequence_of,
                                                  1, maxnoofForbLACs, FALSE);

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
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_x2ap_sAE_Bearer_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_sAE_Bearer_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_sAE_Bearer_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_sAE_Bearer_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t GlobalENB_ID_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_eNB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ENB_ID },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GlobalENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GlobalENB_ID, GlobalENB_ID_sequence);

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



static int
dissect_x2ap_MME_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t GU_Group_ID_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_mME_Group_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MME_Group_ID },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GU_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GU_Group_ID, GU_Group_ID_sequence);

  return offset;
}


static const per_sequence_t GUGroupIDList_sequence_of[1] = {
  { &hf_x2ap_GUGroupIDList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_GU_Group_ID },
};

static int
dissect_x2ap_GUGroupIDList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_GUGroupIDList, GUGroupIDList_sequence_of,
                                                  1, maxPools, FALSE);

  return offset;
}



static int
dissect_x2ap_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t GUMMEI_sequence[] = {
  { &hf_x2ap_gU_Group_ID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GU_Group_ID },
  { &hf_x2ap_mMME_Code      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MME_Code },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const per_sequence_t HandoverRestrictionList_sequence[] = {
  { &hf_x2ap_servingPLMN    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
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
                                                  1, maxInterfaces, FALSE);

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
  {   3, "vendorMinimum" },
  {   4, "vendorMedium" },
  {   5, "vendorMaximum" },
  { 0, NULL }
};


static int
dissect_x2ap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

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
dissect_x2ap_Time_UE_StayedInCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t LastVisitedCell_Item_sequence[] = {
  { &hf_x2ap_global_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
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


static const value_string x2ap_ReportArea_vals[] = {
  {   0, "ecgi" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LocationReportingInformation_sequence[] = {
  { &hf_x2ap_eventType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EventType },
  { &hf_x2ap_reportArea     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ReportArea },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_LocationReportingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_LocationReportingInformation, LocationReportingInformation_sequence);

  return offset;
}



static int
dissect_x2ap_PhyCID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 504U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_ReceiveStatusofULPDCPSDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4096, 4096, FALSE, NULL);

  return offset;
}


static const value_string x2ap_Registration_Request_vals[] = {
  {   0, "start" },
  {   1, "stop" },
  { 0, NULL }
};


static int
dissect_x2ap_Registration_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_6_110_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 110, TRUE, NULL);

  return offset;
}


static const value_string x2ap_RNTP_Threshold_vals[] = {
  {   0, "minusInfinity" },
  {   1, "minusEleven" },
  {   2, "minusTen" },
  {   3, "minusNine" },
  {   4, "minusEight" },
  {   5, "minusSeven" },
  {   6, "minusSix" },
  {   7, "minusFive" },
  {   8, "minusFour" },
  {   9, "minusThree" },
  {  10, "minusTwo" },
  {  11, "minusOne" },
  {  12, "zero" },
  {  13, "one" },
  {  14, "two" },
  {  15, "three" },
  { 0, NULL }
};


static int
dissect_x2ap_RNTP_Threshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_T_numberOfCellSpecificAntennaPorts_vals[] = {
  {   0, "one" },
  {   1, "two" },
  {   2, "four" },
  { 0, NULL }
};


static int
dissect_x2ap_T_numberOfCellSpecificAntennaPorts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_3_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_4_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RelativeNarrowbandTxPower_sequence[] = {
  { &hf_x2ap_rNTP_PerPRB    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_6_110_ },
  { &hf_x2ap_rNTP_Threshold , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RNTP_Threshold },
  { &hf_x2ap_numberOfCellSpecificAntennaPorts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_T_numberOfCellSpecificAntennaPorts },
  { &hf_x2ap_p_B            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_3_ },
  { &hf_x2ap_pDCCH_InterferenceImpact, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_4_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RelativeNarrowbandTxPower(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RelativeNarrowbandTxPower, RelativeNarrowbandTxPower_sequence);

  return offset;
}



static int
dissect_x2ap_RRC_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_ResourceStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t SAE_BearerLevel_QoS_Parameters_sequence[] = {
  { &hf_x2ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_QCI },
  { &hf_x2ap_allocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AllocationAndRetentionPriority },
  { &hf_x2ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GBR_QosInformation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
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
  { &hf_x2ap_cellId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TAC },
  { &hf_x2ap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BroadcastPLMNs_Item },
  { &hf_x2ap_uL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_dL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_cell_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cell_Transmission_Bandwidth },
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
                                                  1, maxCellineNB, FALSE);

  return offset;
}



static int
dissect_x2ap_SubscriberProfileIDforRFP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

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
                                       8, 8, FALSE, NULL);

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
                                                  1, maxnoofCells, FALSE);

  return offset;
}



static int
dissect_x2ap_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UE_X2AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UEAggregateMaximumBitRate_sequence[] = {
  { &hf_x2ap_uEaggregateMaximumBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_uEaggregateMaximumBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UEAggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UEAggregateMaximumBitRate, UEAggregateMaximumBitRate_sequence);

  return offset;
}


static const value_string x2ap_UL_InterferenceOverloadIndication_Item_vals[] = {
  {   0, "high-interference" },
  {   1, "medium-interference" },
  {   2, "low-interference" },
  { 0, NULL }
};


static int
dissect_x2ap_UL_InterferenceOverloadIndication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UL_InterferenceOverloadIndication_sequence_of[1] = {
  { &hf_x2ap_UL_InterferenceOverloadIndication_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_InterferenceOverloadIndication_Item },
};

static int
dissect_x2ap_UL_InterferenceOverloadIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_UL_InterferenceOverloadIndication, UL_InterferenceOverloadIndication_sequence_of,
                                                  1, maxnoofPRBs, FALSE);

  return offset;
}



static int
dissect_x2ap_UL_HighInterferenceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 110, TRUE, NULL);

  return offset;
}


static const per_sequence_t UL_HighInterferenceIndicationInfo_Item_sequence[] = {
  { &hf_x2ap_ul_interferenceindication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_HighInterferenceIndication },
  { &hf_x2ap_target_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UL_HighInterferenceIndicationInfo_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UL_HighInterferenceIndicationInfo_Item, UL_HighInterferenceIndicationInfo_Item_sequence);

  return offset;
}


static const per_sequence_t UL_HighInterferenceIndicationInfo_sequence_of[1] = {
  { &hf_x2ap_UL_HighInterferenceIndicationInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_HighInterferenceIndicationInfo_Item },
};

static int
dissect_x2ap_UL_HighInterferenceIndicationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_UL_HighInterferenceIndicationInfo, UL_HighInterferenceIndicationInfo_sequence_of,
                                                  1, maxCellineNB, FALSE);

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
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t UE_ContextInformation_sequence[] = {
  { &hf_x2ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UE_S1AP_ID },
  { &hf_x2ap_uEaggregateMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UEAggregateMaximumBitRate },
  { &hf_x2ap_subscriberProfileIDforRFP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SubscriberProfileIDforRFP },
  { &hf_x2ap_bearers_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Bearers_ToBeSetup_List },
  { &hf_x2ap_rRC_Context    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RRC_Context },
  { &hf_x2ap_handoverRestrictionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_HandoverRestrictionList },
  { &hf_x2ap_locationReportingInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_LocationReportingInformation },
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
  { &hf_x2ap_dL_Forwarding  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_DL_Forwarding },
  { &hf_x2ap_uL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
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
                                                  1, maxnoofBearers, FALSE);

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
                                                  1, maxnoofBearers, FALSE);

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
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t Bearers_SubjectToStatusTransfer_Item_sequence[] = {
  { &hf_x2ap_bearer_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Bearer_ID },
  { &hf_x2ap_receiveStatusofULPDCPSDUs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ReceiveStatusofULPDCPSDUs },
  { &hf_x2ap_uL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_COUNTvalue },
  { &hf_x2ap_dL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_COUNTvalue },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_Bearers_SubjectToStatusTransfer_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_Bearers_SubjectToStatusTransfer_Item, Bearers_SubjectToStatusTransfer_Item_sequence);

  return offset;
}


static const per_sequence_t UEContextRelease_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UEContextRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UEContextRelease, UEContextRelease_sequence);

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
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellInformation_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_ul_InterferenceOverloadIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_UL_InterferenceOverloadIndication },
  { &hf_x2ap_ul_HighInterferenceIndicationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_UL_HighInterferenceIndicationInfo },
  { &hf_x2ap_relativeNarrowbandTxPower, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_RelativeNarrowbandTxPower },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellInformation_Item, CellInformation_Item_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdate_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ENBConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ENBConfigurationUpdate, ENBConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToModify_Item_sequence[] = {
  { &hf_x2ap_old_ecgi       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_served_cells   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCell_Information },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCellsToModify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCellsToModify_Item, ServedCellsToModify_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToModify_sequence_of[1] = {
  { &hf_x2ap_ServedCellsToModify_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCellsToModify_Item },
};

static int
dissect_x2ap_ServedCellsToModify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ServedCellsToModify, ServedCellsToModify_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t Old_ECGIs_sequence_of[1] = {
  { &hf_x2ap_Old_ECGIs_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
};

static int
dissect_x2ap_Old_ECGIs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Old_ECGIs, Old_ECGIs_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ENBConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ENBConfigurationUpdateAcknowledge, ENBConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdateFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ENBConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ENBConfigurationUpdateFailure, ENBConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusRequest, ResourceStatusRequest_sequence);

  return offset;
}


static const per_sequence_t CellToReport_List_sequence_of[1] = {
  { &hf_x2ap_CellToReport_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_CellToReport_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CellToReport_List, CellToReport_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellToReport_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellToReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellToReport_Item, CellToReport_Item_sequence);

  return offset;
}


static const value_string x2ap_ReportingPeriod_vals[] = {
  {   0, "ffs" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportingPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceStatusResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusResponse, ResourceStatusResponse_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusFailure, ResourceStatusFailure_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusUpdate_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusUpdate, ResourceStatusUpdate_sequence);

  return offset;
}


static const per_sequence_t CellMeasurementResult_List_sequence_of[1] = {
  { &hf_x2ap_CellMeasurementResult_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_CellMeasurementResult_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CellMeasurementResult_List, CellMeasurementResult_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellMeasurementResult_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_resoureStatus  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ResourceStatus },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellMeasurementResult_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellMeasurementResult_Item, CellMeasurementResult_Item_sequence);

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
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_x2ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ECGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ECGI(tvb, offset, &asn1_ctx, tree, hf_x2ap_ECGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalENB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_GlobalENB_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_GlobalENB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GUGroupIDList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_GUGroupIDList(tvb, offset, &asn1_ctx, tree, hf_x2ap_GUGroupIDList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GUMMEI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_GUMMEI(tvb, offset, &asn1_ctx, tree, hf_x2ap_GUMMEI_PDU);
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
static int dissect_Registration_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Registration_Request(tvb, offset, &asn1_ctx, tree, hf_x2ap_Registration_Request_PDU);
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
static int dissect_UEContextRelease_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UEContextRelease(tvb, offset, &asn1_ctx, tree, hf_x2ap_UEContextRelease_PDU);
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
static int dissect_ResetRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResetRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResetRequest_PDU);
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
static int dissect_ENBConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ENBConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_x2ap_ENBConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCellsToModify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ServedCellsToModify(tvb, offset, &asn1_ctx, tree, hf_x2ap_ServedCellsToModify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Old_ECGIs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Old_ECGIs(tvb, offset, &asn1_ctx, tree, hf_x2ap_Old_ECGIs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ENBConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_ENBConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ENBConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_ENBConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellToReport_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellToReport_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellToReport_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellToReport_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellToReport_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellToReport_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingPeriod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReportingPeriod(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReportingPeriod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusUpdate(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellMeasurementResult_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellMeasurementResult_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellMeasurementResult_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellMeasurementResult_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellMeasurementResult_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellMeasurementResult_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static void dissect_X2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_x2ap_X2AP_PDU(tvb, 0, &asn1_ctx, tree, hf_x2ap_X2AP_PDU_PDU);
}


/*--- End of included file: packet-x2ap-fn.c ---*/
#line 87 "packet-x2ap-template.c"

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
    { &hf_x2ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "x2ap.CriticalityDiagnostics",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CriticalityDiagnostics", HFILL }},
    { &hf_x2ap_ECGI_PDU,
      { "ECGI", "x2ap.ECGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ECGI", HFILL }},
    { &hf_x2ap_GlobalENB_ID_PDU,
      { "GlobalENB-ID", "x2ap.GlobalENB_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GlobalENB_ID", HFILL }},
    { &hf_x2ap_GUGroupIDList_PDU,
      { "GUGroupIDList", "x2ap.GUGroupIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.GUGroupIDList", HFILL }},
    { &hf_x2ap_GUMMEI_PDU,
      { "GUMMEI", "x2ap.GUMMEI",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GUMMEI", HFILL }},
    { &hf_x2ap_InterfacesToTrace_Item_PDU,
      { "InterfacesToTrace-Item", "x2ap.InterfacesToTrace_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.InterfacesToTrace_Item", HFILL }},
    { &hf_x2ap_Registration_Request_PDU,
      { "Registration-Request", "x2ap.Registration_Request",
        FT_UINT32, BASE_DEC, VALS(x2ap_Registration_Request_vals), 0,
        "x2ap.Registration_Request", HFILL }},
    { &hf_x2ap_ServedCells_PDU,
      { "ServedCells", "x2ap.ServedCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ServedCells", HFILL }},
    { &hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU,
      { "TargeteNBtoSource-eNBTransparentContainer", "x2ap.TargeteNBtoSource_eNBTransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.TargeteNBtoSource_eNBTransparentContainer", HFILL }},
    { &hf_x2ap_TimeToWait_PDU,
      { "TimeToWait", "x2ap.TimeToWait",
        FT_BYTES, BASE_NONE, NULL, 0,
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
    { &hf_x2ap_UEContextRelease_PDU,
      { "UEContextRelease", "x2ap.UEContextRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.UEContextRelease", HFILL }},
    { &hf_x2ap_HandoverCancel_PDU,
      { "HandoverCancel", "x2ap.HandoverCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.HandoverCancel", HFILL }},
    { &hf_x2ap_ErrorIndication_PDU,
      { "ErrorIndication", "x2ap.ErrorIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ErrorIndication", HFILL }},
    { &hf_x2ap_ResetRequest_PDU,
      { "ResetRequest", "x2ap.ResetRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ResetRequest", HFILL }},
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
    { &hf_x2ap_ENBConfigurationUpdate_PDU,
      { "ENBConfigurationUpdate", "x2ap.ENBConfigurationUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ENBConfigurationUpdate", HFILL }},
    { &hf_x2ap_ServedCellsToModify_PDU,
      { "ServedCellsToModify", "x2ap.ServedCellsToModify",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ServedCellsToModify", HFILL }},
    { &hf_x2ap_Old_ECGIs_PDU,
      { "Old-ECGIs", "x2ap.Old_ECGIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.Old_ECGIs", HFILL }},
    { &hf_x2ap_ENBConfigurationUpdateAcknowledge_PDU,
      { "ENBConfigurationUpdateAcknowledge", "x2ap.ENBConfigurationUpdateAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ENBConfigurationUpdateAcknowledge", HFILL }},
    { &hf_x2ap_ENBConfigurationUpdateFailure_PDU,
      { "ENBConfigurationUpdateFailure", "x2ap.ENBConfigurationUpdateFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ENBConfigurationUpdateFailure", HFILL }},
    { &hf_x2ap_ResourceStatusRequest_PDU,
      { "ResourceStatusRequest", "x2ap.ResourceStatusRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ResourceStatusRequest", HFILL }},
    { &hf_x2ap_CellToReport_List_PDU,
      { "CellToReport-List", "x2ap.CellToReport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.CellToReport_List", HFILL }},
    { &hf_x2ap_CellToReport_Item_PDU,
      { "CellToReport-Item", "x2ap.CellToReport_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CellToReport_Item", HFILL }},
    { &hf_x2ap_ReportingPeriod_PDU,
      { "ReportingPeriod", "x2ap.ReportingPeriod",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportingPeriod_vals), 0,
        "x2ap.ReportingPeriod", HFILL }},
    { &hf_x2ap_ResourceStatusResponse_PDU,
      { "ResourceStatusResponse", "x2ap.ResourceStatusResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ResourceStatusResponse", HFILL }},
    { &hf_x2ap_ResourceStatusFailure_PDU,
      { "ResourceStatusFailure", "x2ap.ResourceStatusFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ResourceStatusFailure", HFILL }},
    { &hf_x2ap_ResourceStatusUpdate_PDU,
      { "ResourceStatusUpdate", "x2ap.ResourceStatusUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ResourceStatusUpdate", HFILL }},
    { &hf_x2ap_CellMeasurementResult_List_PDU,
      { "CellMeasurementResult-List", "x2ap.CellMeasurementResult_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.CellMeasurementResult_List", HFILL }},
    { &hf_x2ap_CellMeasurementResult_Item_PDU,
      { "CellMeasurementResult-Item", "x2ap.CellMeasurementResult_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.CellMeasurementResult_Item", HFILL }},
    { &hf_x2ap_X2AP_PDU_PDU,
      { "X2AP-PDU", "x2ap.X2AP_PDU",
        FT_UINT32, BASE_DEC, VALS(x2ap_X2AP_PDU_vals), 0,
        "x2ap.X2AP_PDU", HFILL }},
    { &hf_x2ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "x2ap.ProtocolIE_Field",
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
      { "ProtocolExtensionField", "x2ap.ProtocolExtensionField",
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
    { &hf_x2ap_BroadcastPLMNs_Item_item,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
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
    { &hf_x2ap_pDCP_SN,
      { "pDCP-SN", "x2ap.pDCP_SN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.PDCP_SN", HFILL }},
    { &hf_x2ap_hFN,
      { "hFN", "x2ap.hFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.HFN", HFILL }},
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
      { "CriticalityDiagnostics-IE-List item", "x2ap.CriticalityDiagnostics_IE_List_item",
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
    { &hf_x2ap_pLMN_Identity,
      { "pLMN-Identity", "x2ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.PLMN_Identity", HFILL }},
    { &hf_x2ap_eUTRANcellIdentifier,
      { "eUTRANcellIdentifier", "x2ap.eUTRANcellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.EUTRANCellIdentifier", HFILL }},
    { &hf_x2ap_macro_eNB_ID,
      { "macro-eNB-ID", "x2ap.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.BIT_STRING_SIZE_20", HFILL }},
    { &hf_x2ap_home_eNB_ID,
      { "home-eNB-ID", "x2ap.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.BIT_STRING_SIZE_28", HFILL }},
    { &hf_x2ap_EPLMNs_item,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.PLMN_Identity", HFILL }},
    { &hf_x2ap_ForbiddenTAs_item,
      { "ForbiddenTAs-Item", "x2ap.ForbiddenTAs_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ForbiddenTAs_Item", HFILL }},
    { &hf_x2ap_forbiddenTACs,
      { "forbiddenTACs", "x2ap.forbiddenTACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ForbiddenTACs", HFILL }},
    { &hf_x2ap_ForbiddenTACs_item,
      { "TAC", "x2ap.TAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.TAC", HFILL }},
    { &hf_x2ap_ForbiddenLAs_item,
      { "ForbiddenLAs-Item", "x2ap.ForbiddenLAs_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ForbiddenLAs_Item", HFILL }},
    { &hf_x2ap_forbiddenLACs,
      { "forbiddenLACs", "x2ap.forbiddenLACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ForbiddenLACs", HFILL }},
    { &hf_x2ap_ForbiddenLACs_item,
      { "LAC", "x2ap.LAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.LAC", HFILL }},
    { &hf_x2ap_sAE_Bearer_MaximumBitrateDL,
      { "sAE-Bearer-MaximumBitrateDL", "x2ap.sAE_Bearer_MaximumBitrateDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BitRate", HFILL }},
    { &hf_x2ap_sAE_Bearer_MaximumBitrateUL,
      { "sAE-Bearer-MaximumBitrateUL", "x2ap.sAE_Bearer_MaximumBitrateUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BitRate", HFILL }},
    { &hf_x2ap_sAE_Bearer_GuaranteedBitrateDL,
      { "sAE-Bearer-GuaranteedBitrateDL", "x2ap.sAE_Bearer_GuaranteedBitrateDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BitRate", HFILL }},
    { &hf_x2ap_sAE_Bearer_GuaranteedBitrateUL,
      { "sAE-Bearer-GuaranteedBitrateUL", "x2ap.sAE_Bearer_GuaranteedBitrateUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BitRate", HFILL }},
    { &hf_x2ap_eNB_ID,
      { "eNB-ID", "x2ap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(x2ap_ENB_ID_vals), 0,
        "x2ap.ENB_ID", HFILL }},
    { &hf_x2ap_transportLayerAddress,
      { "transportLayerAddress", "x2ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.TransportLayerAddress", HFILL }},
    { &hf_x2ap_gTP_TEID,
      { "gTP-TEID", "x2ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.GTP_TEI", HFILL }},
    { &hf_x2ap_GUGroupIDList_item,
      { "GU-Group-ID", "x2ap.GU_Group_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GU_Group_ID", HFILL }},
    { &hf_x2ap_mME_Group_ID,
      { "mME-Group-ID", "x2ap.mME_Group_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.MME_Group_ID", HFILL }},
    { &hf_x2ap_gU_Group_ID,
      { "gU-Group-ID", "x2ap.gU_Group_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GU_Group_ID", HFILL }},
    { &hf_x2ap_mMME_Code,
      { "mMME-Code", "x2ap.mMME_Code",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.MME_Code", HFILL }},
    { &hf_x2ap_servingPLMN,
      { "servingPLMN", "x2ap.servingPLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.PLMN_Identity", HFILL }},
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
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
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
        "x2ap.ECGI", HFILL }},
    { &hf_x2ap_cellType,
      { "cellType", "x2ap.cellType",
        FT_UINT32, BASE_DEC, VALS(x2ap_CellType_vals), 0,
        "x2ap.CellType", HFILL }},
    { &hf_x2ap_time_UE_StayedInCell,
      { "time-UE-StayedInCell", "x2ap.time_UE_StayedInCell",
        FT_INT32, BASE_DEC, NULL, 0,
        "x2ap.Time_UE_StayedInCell", HFILL }},
    { &hf_x2ap_eventType,
      { "eventType", "x2ap.eventType",
        FT_UINT32, BASE_DEC, VALS(x2ap_EventType_vals), 0,
        "x2ap.EventType", HFILL }},
    { &hf_x2ap_reportArea,
      { "reportArea", "x2ap.reportArea",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportArea_vals), 0,
        "x2ap.ReportArea", HFILL }},
    { &hf_x2ap_rNTP_PerPRB,
      { "rNTP-PerPRB", "x2ap.rNTP_PerPRB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.BIT_STRING_SIZE_6_110_", HFILL }},
    { &hf_x2ap_rNTP_Threshold,
      { "rNTP-Threshold", "x2ap.rNTP_Threshold",
        FT_UINT32, BASE_DEC, VALS(x2ap_RNTP_Threshold_vals), 0,
        "x2ap.RNTP_Threshold", HFILL }},
    { &hf_x2ap_numberOfCellSpecificAntennaPorts,
      { "numberOfCellSpecificAntennaPorts", "x2ap.numberOfCellSpecificAntennaPorts",
        FT_UINT32, BASE_DEC, VALS(x2ap_T_numberOfCellSpecificAntennaPorts_vals), 0,
        "x2ap.T_numberOfCellSpecificAntennaPorts", HFILL }},
    { &hf_x2ap_p_B,
      { "p-B", "x2ap.p_B",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.INTEGER_0_3_", HFILL }},
    { &hf_x2ap_pDCCH_InterferenceImpact,
      { "pDCCH-InterferenceImpact", "x2ap.pDCCH_InterferenceImpact",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.INTEGER_0_4_", HFILL }},
    { &hf_x2ap_qCI,
      { "qCI", "x2ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.QCI", HFILL }},
    { &hf_x2ap_allocationAndRetentionPriority,
      { "allocationAndRetentionPriority", "x2ap.allocationAndRetentionPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.AllocationAndRetentionPriority", HFILL }},
    { &hf_x2ap_gbrQosInformation,
      { "gbrQosInformation", "x2ap.gbrQosInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.GBR_QosInformation", HFILL }},
    { &hf_x2ap_ServedCells_item,
      { "ServedCell-Information", "x2ap.ServedCell_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ServedCell_Information", HFILL }},
    { &hf_x2ap_phyCID,
      { "phyCID", "x2ap.phyCID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.PhyCID", HFILL }},
    { &hf_x2ap_cellId,
      { "cellId", "x2ap.cellId",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ECGI", HFILL }},
    { &hf_x2ap_tAC,
      { "tAC", "x2ap.tAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.TAC", HFILL }},
    { &hf_x2ap_broadcastPLMNs,
      { "broadcastPLMNs", "x2ap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BroadcastPLMNs_Item", HFILL }},
    { &hf_x2ap_uL_EARFCN,
      { "uL-EARFCN", "x2ap.uL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.EARFCN", HFILL }},
    { &hf_x2ap_dL_EARFCN,
      { "dL-EARFCN", "x2ap.dL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.EARFCN", HFILL }},
    { &hf_x2ap_cell_Transmission_Bandwidth,
      { "cell-Transmission-Bandwidth", "x2ap.cell_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cell_Transmission_Bandwidth_vals), 0,
        "x2ap.Cell_Transmission_Bandwidth", HFILL }},
    { &hf_x2ap_traceReference,
      { "traceReference", "x2ap.traceReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.TraceReference", HFILL }},
    { &hf_x2ap_interfacesToTrace,
      { "interfacesToTrace", "x2ap.interfacesToTrace",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.InterfacesToTrace", HFILL }},
    { &hf_x2ap_UE_HistoryInformation_item,
      { "LastVisitedCell-Item", "x2ap.LastVisitedCell_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.LastVisitedCell_Item", HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRateDownlink,
      { "uEaggregateMaximumBitRateDownlink", "x2ap.uEaggregateMaximumBitRateDownlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BitRate", HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRateUplink,
      { "uEaggregateMaximumBitRateUplink", "x2ap.uEaggregateMaximumBitRateUplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.BitRate", HFILL }},
    { &hf_x2ap_UL_InterferenceOverloadIndication_item,
      { "UL-InterferenceOverloadIndication-Item", "x2ap.UL_InterferenceOverloadIndication_Item",
        FT_UINT32, BASE_DEC, VALS(x2ap_UL_InterferenceOverloadIndication_Item_vals), 0,
        "x2ap.UL_InterferenceOverloadIndication_Item", HFILL }},
    { &hf_x2ap_UL_HighInterferenceIndicationInfo_item,
      { "UL-HighInterferenceIndicationInfo-Item", "x2ap.UL_HighInterferenceIndicationInfo_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.UL_HighInterferenceIndicationInfo_Item", HFILL }},
    { &hf_x2ap_ul_interferenceindication,
      { "ul-interferenceindication", "x2ap.ul_interferenceindication",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.UL_HighInterferenceIndication", HFILL }},
    { &hf_x2ap_target_Cell_ID,
      { "target-Cell-ID", "x2ap.target_Cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ECGI", HFILL }},
    { &hf_x2ap_protocolIEs,
      { "protocolIEs", "x2ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.ProtocolIE_Container", HFILL }},
    { &hf_x2ap_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "x2ap.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.UE_S1AP_ID", HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRate,
      { "uEaggregateMaximumBitRate", "x2ap.uEaggregateMaximumBitRate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.UEAggregateMaximumBitRate", HFILL }},
    { &hf_x2ap_subscriberProfileIDforRFP,
      { "subscriberProfileIDforRFP", "x2ap.subscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.SubscriberProfileIDforRFP", HFILL }},
    { &hf_x2ap_bearers_ToBeSetup_List,
      { "bearers-ToBeSetup-List", "x2ap.bearers_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.Bearers_ToBeSetup_List", HFILL }},
    { &hf_x2ap_rRC_Context,
      { "rRC-Context", "x2ap.rRC_Context",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.RRC_Context", HFILL }},
    { &hf_x2ap_handoverRestrictionList,
      { "handoverRestrictionList", "x2ap.handoverRestrictionList",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.HandoverRestrictionList", HFILL }},
    { &hf_x2ap_locationReportingInformation,
      { "locationReportingInformation", "x2ap.locationReportingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.LocationReportingInformation", HFILL }},
    { &hf_x2ap_Bearers_ToBeSetup_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_sAE_Bearer_ID,
      { "sAE-Bearer-ID", "x2ap.sAE_Bearer_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
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
    { &hf_x2ap_Bearers_Admitted_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_bearer_ID,
      { "bearer-ID", "x2ap.bearer_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
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
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_cause,
      { "cause", "x2ap.cause",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cause_vals), 0,
        "x2ap.Cause", HFILL }},
    { &hf_x2ap_Bearers_SubjectToStatusTransfer_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_receiveStatusofULPDCPSDUs,
      { "receiveStatusofULPDCPSDUs", "x2ap.receiveStatusofULPDCPSDUs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x2ap.ReceiveStatusofULPDCPSDUs", HFILL }},
    { &hf_x2ap_uL_COUNTvalue,
      { "uL-COUNTvalue", "x2ap.uL_COUNTvalue",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.COUNTvalue", HFILL }},
    { &hf_x2ap_dL_COUNTvalue,
      { "dL-COUNTvalue", "x2ap.dL_COUNTvalue",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.COUNTvalue", HFILL }},
    { &hf_x2ap_CellInformation_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_cell_ID,
      { "cell-ID", "x2ap.cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ECGI", HFILL }},
    { &hf_x2ap_ul_InterferenceOverloadIndication,
      { "ul-InterferenceOverloadIndication", "x2ap.ul_InterferenceOverloadIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.UL_InterferenceOverloadIndication", HFILL }},
    { &hf_x2ap_ul_HighInterferenceIndicationInfo,
      { "ul-HighInterferenceIndicationInfo", "x2ap.ul_HighInterferenceIndicationInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x2ap.UL_HighInterferenceIndicationInfo", HFILL }},
    { &hf_x2ap_relativeNarrowbandTxPower,
      { "relativeNarrowbandTxPower", "x2ap.relativeNarrowbandTxPower",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.RelativeNarrowbandTxPower", HFILL }},
    { &hf_x2ap_ServedCellsToModify_item,
      { "ServedCellsToModify-Item", "x2ap.ServedCellsToModify_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ServedCellsToModify_Item", HFILL }},
    { &hf_x2ap_old_ecgi,
      { "old-ecgi", "x2ap.old_ecgi",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ECGI", HFILL }},
    { &hf_x2ap_served_cells,
      { "served-cells", "x2ap.served_cells",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ServedCell_Information", HFILL }},
    { &hf_x2ap_Old_ECGIs_item,
      { "ECGI", "x2ap.ECGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ECGI", HFILL }},
    { &hf_x2ap_CellToReport_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_CellMeasurementResult_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        "x2ap.ProtocolIE_Single_Container", HFILL }},
    { &hf_x2ap_resoureStatus,
      { "resoureStatus", "x2ap.resoureStatus",
        FT_INT32, BASE_DEC, NULL, 0,
        "x2ap.ResourceStatus", HFILL }},
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
#line 140 "packet-x2ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_x2ap,

/*--- Included file: packet-x2ap-ettarr.c ---*/
#line 1 "packet-x2ap-ettarr.c"
    &ett_x2ap_ProtocolIE_Container,
    &ett_x2ap_ProtocolIE_Field,
    &ett_x2ap_ProtocolExtensionContainer,
    &ett_x2ap_ProtocolExtensionField,
    &ett_x2ap_BroadcastPLMNs_Item,
    &ett_x2ap_Cause,
    &ett_x2ap_COUNTvalue,
    &ett_x2ap_CriticalityDiagnostics,
    &ett_x2ap_CriticalityDiagnostics_IE_List,
    &ett_x2ap_CriticalityDiagnostics_IE_List_item,
    &ett_x2ap_ECGI,
    &ett_x2ap_ENB_ID,
    &ett_x2ap_EPLMNs,
    &ett_x2ap_ForbiddenTAs,
    &ett_x2ap_ForbiddenTAs_Item,
    &ett_x2ap_ForbiddenTACs,
    &ett_x2ap_ForbiddenLAs,
    &ett_x2ap_ForbiddenLAs_Item,
    &ett_x2ap_ForbiddenLACs,
    &ett_x2ap_GBR_QosInformation,
    &ett_x2ap_GlobalENB_ID,
    &ett_x2ap_GTPtunnelEndpoint,
    &ett_x2ap_GUGroupIDList,
    &ett_x2ap_GU_Group_ID,
    &ett_x2ap_GUMMEI,
    &ett_x2ap_HandoverRestrictionList,
    &ett_x2ap_InterfacesToTrace,
    &ett_x2ap_InterfacesToTrace_Item,
    &ett_x2ap_LastVisitedCell_Item,
    &ett_x2ap_LocationReportingInformation,
    &ett_x2ap_RelativeNarrowbandTxPower,
    &ett_x2ap_SAE_BearerLevel_QoS_Parameters,
    &ett_x2ap_ServedCells,
    &ett_x2ap_ServedCell_Information,
    &ett_x2ap_TraceActivation,
    &ett_x2ap_UE_HistoryInformation,
    &ett_x2ap_UEAggregateMaximumBitRate,
    &ett_x2ap_UL_InterferenceOverloadIndication,
    &ett_x2ap_UL_HighInterferenceIndicationInfo,
    &ett_x2ap_UL_HighInterferenceIndicationInfo_Item,
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
    &ett_x2ap_UEContextRelease,
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
    &ett_x2ap_ENBConfigurationUpdate,
    &ett_x2ap_ServedCellsToModify,
    &ett_x2ap_ServedCellsToModify_Item,
    &ett_x2ap_Old_ECGIs,
    &ett_x2ap_ENBConfigurationUpdateAcknowledge,
    &ett_x2ap_ENBConfigurationUpdateFailure,
    &ett_x2ap_ResourceStatusRequest,
    &ett_x2ap_CellToReport_List,
    &ett_x2ap_CellToReport_Item,
    &ett_x2ap_ResourceStatusResponse,
    &ett_x2ap_ResourceStatusFailure,
    &ett_x2ap_ResourceStatusUpdate,
    &ett_x2ap_CellMeasurementResult_List,
    &ett_x2ap_CellMeasurementResult_Item,
    &ett_x2ap_X2AP_PDU,
    &ett_x2ap_InitiatingMessage,
    &ett_x2ap_SuccessfulOutcome,
    &ett_x2ap_UnsuccessfulOutcome,

/*--- End of included file: packet-x2ap-ettarr.c ---*/
#line 146 "packet-x2ap-template.c"
  };


  /* Register protocol */
  proto_x2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
 
  /* Register dissector */
  register_dissector("x2ap", dissect_x2ap, proto_x2ap);

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
	dissector_handle_t x2ap_handle;

	x2ap_handle = find_dissector("x2ap");
	dissector_add_handle("sctp.port", x2ap_handle);  /* for "decode-as" */


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
  dissector_add("x2ap.ies", id_TargetCell_ID, new_create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_TargeteNBtoSource_eNBTransparentContainer, new_create_dissector_handle(dissect_TargeteNBtoSource_eNBTransparentContainer_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_TraceActivation, new_create_dissector_handle(dissect_TraceActivation_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_UE_ContextInformation, new_create_dissector_handle(dissect_UE_ContextInformation_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_UE_HistoryInformation, new_create_dissector_handle(dissect_UE_HistoryInformation_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_UE_X2AP_ID, new_create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_SubjectToStatusTransfer_List, new_create_dissector_handle(dissect_Bearers_SubjectToStatusTransfer_List_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Bearers_SubjectToStatusTransfer_Item, new_create_dissector_handle(dissect_Bearers_SubjectToStatusTransfer_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_ServedCells, new_create_dissector_handle(dissect_ServedCells_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_GlobalENB_ID, new_create_dissector_handle(dissect_GlobalENB_ID_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_TimeToWait, new_create_dissector_handle(dissect_TimeToWait_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_GUMMEI_ID, new_create_dissector_handle(dissect_GUMMEI_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_GUGroupIDList, new_create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_ServedCellsToAdd, new_create_dissector_handle(dissect_ServedCells_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_ServedCellsToModify, new_create_dissector_handle(dissect_ServedCellsToModify_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_ServedCellsToDelete, new_create_dissector_handle(dissect_Old_ECGIs_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_Registration_Request, new_create_dissector_handle(dissect_Registration_Request_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CellToReport, new_create_dissector_handle(dissect_CellToReport_List_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_ReportingPeriodicity, new_create_dissector_handle(dissect_ReportingPeriod_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CellToReport_Item, new_create_dissector_handle(dissect_CellToReport_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CellMeasurementResult, new_create_dissector_handle(dissect_CellMeasurementResult_List_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_CellMeasurementResult_Item, new_create_dissector_handle(dissect_CellMeasurementResult_Item_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_GUGroupIDListToAdd, new_create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add("x2ap.ies", id_GUGroupIDListToDelete, new_create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-handoverPreparation", new_create_dissector_handle(dissect_HandoverRequest_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.sout", "id-handoverPreparation", new_create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.uout", "id-handoverPreparation", new_create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-snStatusTransfer", new_create_dissector_handle(dissect_SNStatusTransfer_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-uEContextRelease", new_create_dissector_handle(dissect_UEContextRelease_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-handoverCancel", new_create_dissector_handle(dissect_HandoverCancel_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-errorIndication", new_create_dissector_handle(dissect_ErrorIndication_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-reset", new_create_dissector_handle(dissect_ResetRequest_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.sout", "id-reset", new_create_dissector_handle(dissect_ResetResponse_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-x2Setup", new_create_dissector_handle(dissect_X2SetupRequest_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.sout", "id-x2Setup", new_create_dissector_handle(dissect_X2SetupResponse_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.uout", "id-x2Setup", new_create_dissector_handle(dissect_X2SetupFailure_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-loadIndication", new_create_dissector_handle(dissect_LoadInformation_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-eNBConfigurationUpdate", new_create_dissector_handle(dissect_ENBConfigurationUpdate_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.sout", "id-eNBConfigurationUpdate", new_create_dissector_handle(dissect_ENBConfigurationUpdateAcknowledge_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.uout", "id-eNBConfigurationUpdate", new_create_dissector_handle(dissect_ENBConfigurationUpdateFailure_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-resourceStatusUpdateInitiation", new_create_dissector_handle(dissect_ResourceStatusRequest_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.sout", "id-resourceStatusUpdateInitiation", new_create_dissector_handle(dissect_ResourceStatusResponse_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.uout", "id-resourceStatusUpdateInitiation", new_create_dissector_handle(dissect_ResourceStatusFailure_PDU, proto_x2ap));
  dissector_add_string("x2ap.proc.imsg", "id-resourceStatusReporting", new_create_dissector_handle(dissect_ResourceStatusUpdate_PDU, proto_x2ap));


/*--- End of included file: packet-x2ap-dis-tab.c ---*/
#line 178 "packet-x2ap-template.c"
}


