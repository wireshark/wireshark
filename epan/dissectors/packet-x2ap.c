/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-x2ap.c                                                              */
/* ../../tools/asn2wrs.py -p x2ap -c ./x2ap.cnf -s ./packet-x2ap-template -D . X2AP-CommonDataTypes.asn X2AP-Constants.asn X2AP-Containers.asn X2AP-IEs.asn X2AP-PDU-Contents.asn X2AP-PDU-Descriptions.asn */

/* Input file: packet-x2ap-template.c */

#line 1 "../../asn1/x2ap/packet-x2ap-template.c"
/* packet-x2ap.c
 * Routines for dissecting Evolved Universal Terrestrial Radio Access Network (EUTRAN);
 * X2 Application Protocol (X2AP);
 * 3GPP TS 36.423 packet dissection
 * Copyright 2007-2010, Anders Broman <anders.broman@ericsson.com>
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
 * 3GPP TS 36.423 V9.2.0 (2010-03)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>

#include "packet-per.h"
#include "packet-e212.h"
#include "packet-frame.h"
#include "packet-lte-rrc.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "EUTRAN X2 Application Protocol (X2AP)"
#define PSNAME "X2AP"
#define PFNAME "x2ap"

/* Dissector will use SCTP PPID 27 or SCTP port. IANA assigned port = 36422 */
#define SCTP_PORT_X2AP	36422


/*--- Included file: packet-x2ap-val.h ---*/
#line 1 "../../asn1/x2ap/packet-x2ap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxEARFCN                      65535
#define maxInterfaces                  16
#define maxCellineNB                   256
#define maxnoofBearers                 256
#define maxNrOfErrors                  256
#define maxnoofPDCP_SN                 16
#define maxnoofEPLMNs                  15
#define maxnoofEPLMNsPlusOne           16
#define maxnoofForbLACs                4096
#define maxnoofForbTACs                4096
#define maxnoofBPLMNs                  6
#define maxnoofNeighbours              512
#define maxnoofPRBs                    110
#define maxPools                       16
#define maxnoofCells                   16
#define maxnoofMBSFN                   8

typedef enum _ProcedureCode_enum {
  id_handoverPreparation =   0,
  id_handoverCancel =   1,
  id_loadIndication =   2,
  id_errorIndication =   3,
  id_snStatusTransfer =   4,
  id_uEContextRelease =   5,
  id_x2Setup   =   6,
  id_reset     =   7,
  id_eNBConfigurationUpdate =   8,
  id_resourceStatusReportingInitiation =   9,
  id_resourceStatusReporting =  10,
  id_privateMessage =  11,
  id_mobilitySettingsChange =  12,
  id_rLFIndication =  13,
  id_handoverReport =  14,
  id_cellActivation =  15
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_E_RABs_Admitted_Item =   0,
  id_E_RABs_Admitted_List =   1,
  id_E_RAB_Item =   2,
  id_E_RABs_NotAdmitted_List =   3,
  id_E_RABs_ToBeSetup_Item =   4,
  id_Cause     =   5,
  id_CellInformation =   6,
  id_CellInformation_Item =   7,
  id_New_eNB_UE_X2AP_ID =   9,
  id_Old_eNB_UE_X2AP_ID =  10,
  id_TargetCell_ID =  11,
  id_TargeteNBtoSource_eNBTransparentContainer =  12,
  id_TraceActivation =  13,
  id_UE_ContextInformation =  14,
  id_UE_HistoryInformation =  15,
  id_UE_X2AP_ID =  16,
  id_CriticalityDiagnostics =  17,
  id_E_RABs_SubjectToStatusTransfer_List =  18,
  id_E_RABs_SubjectToStatusTransfer_Item =  19,
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
  id_GUGroupIDToAddList =  34,
  id_GUGroupIDToDeleteList =  35,
  id_SRVCCOperationPossible =  36,
  id_Measurement_ID =  37,
  id_ReportCharacteristics =  38,
  id_ENB1_Measurement_ID =  39,
  id_ENB2_Measurement_ID =  40,
  id_Number_of_Antennaports =  41,
  id_CompositeAvailableCapacityGroup =  42,
  id_ENB1_Cell_ID =  43,
  id_ENB2_Cell_ID =  44,
  id_ENB2_Proposed_Mobility_Parameters =  45,
  id_ENB1_Mobility_Parameters =  46,
  id_ENB2_Mobility_Parameters_Modification_Range =  47,
  id_FailureCellPCI =  48,
  id_Re_establishmentCellECGI =  49,
  id_FailureCellCRNTI =  50,
  id_ShortMAC_I =  51,
  id_SourceCellECGI =  52,
  id_FailureCellECGI =  53,
  id_HandoverReportType =  54,
  id_PRACH_Configuration =  55,
  id_MBSFN_Subframe_Info =  56,
  id_ServedCellsToActivate =  57,
  id_ActivatedCellList =  58,
  id_DeactivationIndication =  59,
  id_UE_RLF_Report_Container =  60
} ProtocolIE_ID_enum;

/*--- End of included file: packet-x2ap-val.h ---*/
#line 60 "../../asn1/x2ap/packet-x2ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_x2ap = -1;
static int hf_x2ap_transportLayerAddressIPv4 = -1;
static int hf_x2ap_transportLayerAddressIPv6 = -1;

/*--- Included file: packet-x2ap-hf.c ---*/
#line 1 "../../asn1/x2ap/packet-x2ap-hf.c"
static int hf_x2ap_Cause_PDU = -1;                /* Cause */
static int hf_x2ap_CompositeAvailableCapacityGroup_PDU = -1;  /* CompositeAvailableCapacityGroup */
static int hf_x2ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_x2ap_CRNTI_PDU = -1;                /* CRNTI */
static int hf_x2ap_DeactivationIndication_PDU = -1;  /* DeactivationIndication */
static int hf_x2ap_ECGI_PDU = -1;                 /* ECGI */
static int hf_x2ap_E_RAB_List_PDU = -1;           /* E_RAB_List */
static int hf_x2ap_E_RAB_Item_PDU = -1;           /* E_RAB_Item */
static int hf_x2ap_GlobalENB_ID_PDU = -1;         /* GlobalENB_ID */
static int hf_x2ap_GUGroupIDList_PDU = -1;        /* GUGroupIDList */
static int hf_x2ap_GUMMEI_PDU = -1;               /* GUMMEI */
static int hf_x2ap_HandoverReportType_PDU = -1;   /* HandoverReportType */
static int hf_x2ap_Measurement_ID_PDU = -1;       /* Measurement_ID */
static int hf_x2ap_MBSFN_Subframe_Infolist_PDU = -1;  /* MBSFN_Subframe_Infolist */
static int hf_x2ap_MobilityParametersModificationRange_PDU = -1;  /* MobilityParametersModificationRange */
static int hf_x2ap_MobilityParametersInformation_PDU = -1;  /* MobilityParametersInformation */
static int hf_x2ap_Number_of_Antennaports_PDU = -1;  /* Number_of_Antennaports */
static int hf_x2ap_PCI_PDU = -1;                  /* PCI */
static int hf_x2ap_PRACH_Configuration_PDU = -1;  /* PRACH_Configuration */
static int hf_x2ap_Registration_Request_PDU = -1;  /* Registration_Request */
static int hf_x2ap_ReportCharacteristics_PDU = -1;  /* ReportCharacteristics */
static int hf_x2ap_ServedCells_PDU = -1;          /* ServedCells */
static int hf_x2ap_ShortMAC_I_PDU = -1;           /* ShortMAC_I */
static int hf_x2ap_SRVCCOperationPossible_PDU = -1;  /* SRVCCOperationPossible */
static int hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU = -1;  /* TargeteNBtoSource_eNBTransparentContainer */
static int hf_x2ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_x2ap_TraceActivation_PDU = -1;      /* TraceActivation */
static int hf_x2ap_UE_HistoryInformation_PDU = -1;  /* UE_HistoryInformation */
static int hf_x2ap_UE_X2AP_ID_PDU = -1;           /* UE_X2AP_ID */
static int hf_x2ap_UE_RLF_Report_Container_PDU = -1;  /* UE_RLF_Report_Container */
static int hf_x2ap_HandoverRequest_PDU = -1;      /* HandoverRequest */
static int hf_x2ap_UE_ContextInformation_PDU = -1;  /* UE_ContextInformation */
static int hf_x2ap_E_RABs_ToBeSetup_Item_PDU = -1;  /* E_RABs_ToBeSetup_Item */
static int hf_x2ap_HandoverRequestAcknowledge_PDU = -1;  /* HandoverRequestAcknowledge */
static int hf_x2ap_E_RABs_Admitted_List_PDU = -1;  /* E_RABs_Admitted_List */
static int hf_x2ap_E_RABs_Admitted_Item_PDU = -1;  /* E_RABs_Admitted_Item */
static int hf_x2ap_HandoverPreparationFailure_PDU = -1;  /* HandoverPreparationFailure */
static int hf_x2ap_HandoverReport_PDU = -1;       /* HandoverReport */
static int hf_x2ap_SNStatusTransfer_PDU = -1;     /* SNStatusTransfer */
static int hf_x2ap_E_RABs_SubjectToStatusTransfer_List_PDU = -1;  /* E_RABs_SubjectToStatusTransfer_List */
static int hf_x2ap_E_RABs_SubjectToStatusTransfer_Item_PDU = -1;  /* E_RABs_SubjectToStatusTransfer_Item */
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
static int hf_x2ap_ReportingPeriodicity_PDU = -1;  /* ReportingPeriodicity */
static int hf_x2ap_ResourceStatusResponse_PDU = -1;  /* ResourceStatusResponse */
static int hf_x2ap_ResourceStatusFailure_PDU = -1;  /* ResourceStatusFailure */
static int hf_x2ap_ResourceStatusUpdate_PDU = -1;  /* ResourceStatusUpdate */
static int hf_x2ap_CellMeasurementResult_List_PDU = -1;  /* CellMeasurementResult_List */
static int hf_x2ap_CellMeasurementResult_Item_PDU = -1;  /* CellMeasurementResult_Item */
static int hf_x2ap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_x2ap_MobilityChangeRequest_PDU = -1;  /* MobilityChangeRequest */
static int hf_x2ap_MobilityChangeAcknowledge_PDU = -1;  /* MobilityChangeAcknowledge */
static int hf_x2ap_MobilityChangeFailure_PDU = -1;  /* MobilityChangeFailure */
static int hf_x2ap_RLFIndication_PDU = -1;        /* RLFIndication */
static int hf_x2ap_CellActivationRequest_PDU = -1;  /* CellActivationRequest */
static int hf_x2ap_ServedCellsToActivate_PDU = -1;  /* ServedCellsToActivate */
static int hf_x2ap_CellActivationResponse_PDU = -1;  /* CellActivationResponse */
static int hf_x2ap_ActivatedCellList_PDU = -1;    /* ActivatedCellList */
static int hf_x2ap_CellActivationFailure_PDU = -1;  /* CellActivationFailure */
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
static int hf_x2ap_key_eNodeB_star = -1;          /* Key_eNodeB_Star */
static int hf_x2ap_nextHopChainingCount = -1;     /* NextHopChainingCount */
static int hf_x2ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_x2ap_priorityLevel = -1;            /* PriorityLevel */
static int hf_x2ap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_x2ap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_x2ap_BroadcastPLMNs_Item_item = -1;  /* PLMN_Identity */
static int hf_x2ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_x2ap_transport = -1;                /* CauseTransport */
static int hf_x2ap_protocol = -1;                 /* CauseProtocol */
static int hf_x2ap_misc = -1;                     /* CauseMisc */
static int hf_x2ap_cell_Size = -1;                /* Cell_Size */
static int hf_x2ap_dL_CompositeAvailableCapacity = -1;  /* CompositeAvailableCapacity */
static int hf_x2ap_uL_CompositeAvailableCapacity = -1;  /* CompositeAvailableCapacity */
static int hf_x2ap_cellCapacityClassValue = -1;   /* CellCapacityClassValue */
static int hf_x2ap_capacityValue = -1;            /* CapacityValue */
static int hf_x2ap_pDCP_SN = -1;                  /* PDCP_SN */
static int hf_x2ap_hFN = -1;                      /* HFN */
static int hf_x2ap_procedureCode = -1;            /* ProcedureCode */
static int hf_x2ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_x2ap_procedureCriticality = -1;     /* Criticality */
static int hf_x2ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_x2ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_x2ap_iECriticality = -1;            /* Criticality */
static int hf_x2ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_x2ap_typeOfError = -1;              /* TypeOfError */
static int hf_x2ap_uL_EARFCN = -1;                /* EARFCN */
static int hf_x2ap_dL_EARFCN = -1;                /* EARFCN */
static int hf_x2ap_uL_Transmission_Bandwidth = -1;  /* Transmission_Bandwidth */
static int hf_x2ap_dL_Transmission_Bandwidth = -1;  /* Transmission_Bandwidth */
static int hf_x2ap_eARFCN = -1;                   /* EARFCN */
static int hf_x2ap_transmission_Bandwidth = -1;   /* Transmission_Bandwidth */
static int hf_x2ap_subframeAssignment = -1;       /* SubframeAssignment */
static int hf_x2ap_specialSubframe_Info = -1;     /* SpecialSubframe_Info */
static int hf_x2ap_fDD = -1;                      /* FDD_Info */
static int hf_x2ap_tDD = -1;                      /* TDD_Info */
static int hf_x2ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_x2ap_eUTRANcellIdentifier = -1;     /* EUTRANCellIdentifier */
static int hf_x2ap_macro_eNB_ID = -1;             /* BIT_STRING_SIZE_20 */
static int hf_x2ap_home_eNB_ID = -1;              /* BIT_STRING_SIZE_28 */
static int hf_x2ap_EPLMNs_item = -1;              /* PLMN_Identity */
static int hf_x2ap_qCI = -1;                      /* QCI */
static int hf_x2ap_allocationAndRetentionPriority = -1;  /* AllocationAndRetentionPriority */
static int hf_x2ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_x2ap_E_RAB_List_item = -1;          /* ProtocolIE_Single_Container */
static int hf_x2ap_e_RAB_ID = -1;                 /* E_RAB_ID */
static int hf_x2ap_cause = -1;                    /* Cause */
static int hf_x2ap_ForbiddenTAs_item = -1;        /* ForbiddenTAs_Item */
static int hf_x2ap_forbiddenTACs = -1;            /* ForbiddenTACs */
static int hf_x2ap_ForbiddenTACs_item = -1;       /* TAC */
static int hf_x2ap_ForbiddenLAs_item = -1;        /* ForbiddenLAs_Item */
static int hf_x2ap_forbiddenLACs = -1;            /* ForbiddenLACs */
static int hf_x2ap_ForbiddenLACs_item = -1;       /* LAC */
static int hf_x2ap_e_RAB_MaximumBitrateDL = -1;   /* BitRate */
static int hf_x2ap_e_RAB_MaximumBitrateUL = -1;   /* BitRate */
static int hf_x2ap_e_RAB_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_x2ap_e_RAB_GuaranteedBitrateUL = -1;  /* BitRate */
static int hf_x2ap_eNB_ID = -1;                   /* ENB_ID */
static int hf_x2ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_x2ap_gTP_TEID = -1;                 /* GTP_TEI */
static int hf_x2ap_GUGroupIDList_item = -1;       /* GU_Group_ID */
static int hf_x2ap_mME_Group_ID = -1;             /* MME_Group_ID */
static int hf_x2ap_gU_Group_ID = -1;              /* GU_Group_ID */
static int hf_x2ap_mME_Code = -1;                 /* MME_Code */
static int hf_x2ap_servingPLMN = -1;              /* PLMN_Identity */
static int hf_x2ap_equivalentPLMNs = -1;          /* EPLMNs */
static int hf_x2ap_forbiddenTAs = -1;             /* ForbiddenTAs */
static int hf_x2ap_forbiddenLAs = -1;             /* ForbiddenLAs */
static int hf_x2ap_forbiddenInterRATs = -1;       /* ForbiddenInterRATs */
static int hf_x2ap_dLHWLoadIndicator = -1;        /* LoadIndicator */
static int hf_x2ap_uLHWLoadIndicator = -1;        /* LoadIndicator */
static int hf_x2ap_e_UTRAN_Cell = -1;             /* LastVisitedEUTRANCellInformation */
static int hf_x2ap_uTRAN_Cell = -1;               /* LastVisitedUTRANCellInformation */
static int hf_x2ap_gERAN_Cell = -1;               /* LastVisitedGERANCellInformation */
static int hf_x2ap_global_Cell_ID = -1;           /* ECGI */
static int hf_x2ap_cellType = -1;                 /* CellType */
static int hf_x2ap_time_UE_StayedInCell = -1;     /* Time_UE_StayedInCell */
static int hf_x2ap_undefined = -1;                /* NULL */
static int hf_x2ap_eventType = -1;                /* EventType */
static int hf_x2ap_reportArea = -1;               /* ReportArea */
static int hf_x2ap_MBSFN_Subframe_Infolist_item = -1;  /* MBSFN_Subframe_Info */
static int hf_x2ap_radioframeAllocationPeriod = -1;  /* RadioframeAllocationPeriod */
static int hf_x2ap_radioframeAllocationOffset = -1;  /* RadioframeAllocationOffset */
static int hf_x2ap_subframeAllocation = -1;       /* SubframeAllocation */
static int hf_x2ap_handoverTriggerChangeLowerLimit = -1;  /* INTEGER_M20_20 */
static int hf_x2ap_handoverTriggerChangeUpperLimit = -1;  /* INTEGER_M20_20 */
static int hf_x2ap_handoverTriggerChange = -1;    /* INTEGER_M20_20 */
static int hf_x2ap_Neighbour_Information_item = -1;  /* Neighbour_Information_item */
static int hf_x2ap_eCGI = -1;                     /* ECGI */
static int hf_x2ap_pCI = -1;                      /* PCI */
static int hf_x2ap_rootSequenceIndex = -1;        /* INTEGER_0_837 */
static int hf_x2ap_zeroCorrelationIndex = -1;     /* INTEGER_0_15 */
static int hf_x2ap_highSpeedFlag = -1;            /* BOOLEAN */
static int hf_x2ap_prach_FreqOffset = -1;         /* INTEGER_0_94 */
static int hf_x2ap_prach_ConfigIndex = -1;        /* INTEGER_0_63 */
static int hf_x2ap_rNTP_PerPRB = -1;              /* BIT_STRING_SIZE_6_110_ */
static int hf_x2ap_rNTP_Threshold = -1;           /* RNTP_Threshold */
static int hf_x2ap_numberOfCellSpecificAntennaPorts = -1;  /* T_numberOfCellSpecificAntennaPorts */
static int hf_x2ap_p_B = -1;                      /* INTEGER_0_3_ */
static int hf_x2ap_pDCCH_InterferenceImpact = -1;  /* INTEGER_0_4_ */
static int hf_x2ap_dL_GBR_PRB_usage = -1;         /* DL_GBR_PRB_usage */
static int hf_x2ap_uL_GBR_PRB_usage = -1;         /* UL_GBR_PRB_usage */
static int hf_x2ap_dL_non_GBR_PRB_usage = -1;     /* DL_non_GBR_PRB_usage */
static int hf_x2ap_uL_non_GBR_PRB_usage = -1;     /* UL_non_GBR_PRB_usage */
static int hf_x2ap_dL_Total_PRB_usage = -1;       /* DL_Total_PRB_usage */
static int hf_x2ap_uL_Total_PRB_usage = -1;       /* UL_Total_PRB_usage */
static int hf_x2ap_dLS1TNLLoadIndicator = -1;     /* LoadIndicator */
static int hf_x2ap_uLS1TNLLoadIndicator = -1;     /* LoadIndicator */
static int hf_x2ap_ServedCells_item = -1;         /* ServedCells_item */
static int hf_x2ap_servedCellInfo = -1;           /* ServedCell_Information */
static int hf_x2ap_neighbour_Info = -1;           /* Neighbour_Information */
static int hf_x2ap_cellId = -1;                   /* ECGI */
static int hf_x2ap_tAC = -1;                      /* TAC */
static int hf_x2ap_broadcastPLMNs = -1;           /* BroadcastPLMNs_Item */
static int hf_x2ap_eUTRA_Mode_Info = -1;          /* EUTRA_Mode_Info */
static int hf_x2ap_specialSubframePatterns = -1;  /* SpecialSubframePatterns */
static int hf_x2ap_cyclicPrefixDL = -1;           /* CyclicPrefixDL */
static int hf_x2ap_cyclicPrefixUL = -1;           /* CyclicPrefixUL */
static int hf_x2ap_oneframe = -1;                 /* Oneframe */
static int hf_x2ap_fourframes = -1;               /* Fourframes */
static int hf_x2ap_eUTRANTraceID = -1;            /* EUTRANTraceID */
static int hf_x2ap_interfacesToTrace = -1;        /* InterfacesToTrace */
static int hf_x2ap_traceDepth = -1;               /* TraceDepth */
static int hf_x2ap_traceCollectionEntityIPAddress = -1;  /* TraceCollectionEntityIPAddress */
static int hf_x2ap_UE_HistoryInformation_item = -1;  /* LastVisitedCell_Item */
static int hf_x2ap_uEaggregateMaximumBitRateDownlink = -1;  /* BitRate */
static int hf_x2ap_uEaggregateMaximumBitRateUplink = -1;  /* BitRate */
static int hf_x2ap_encryptionAlgorithms = -1;     /* EncryptionAlgorithms */
static int hf_x2ap_integrityProtectionAlgorithms = -1;  /* IntegrityProtectionAlgorithms */
static int hf_x2ap_UL_InterferenceOverloadIndication_item = -1;  /* UL_InterferenceOverloadIndication_Item */
static int hf_x2ap_UL_HighInterferenceIndicationInfo_item = -1;  /* UL_HighInterferenceIndicationInfo_Item */
static int hf_x2ap_target_Cell_ID = -1;           /* ECGI */
static int hf_x2ap_ul_interferenceindication = -1;  /* UL_HighInterferenceIndication */
static int hf_x2ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_x2ap_mME_UE_S1AP_ID = -1;           /* UE_S1AP_ID */
static int hf_x2ap_uESecurityCapabilities = -1;   /* UESecurityCapabilities */
static int hf_x2ap_aS_SecurityInformation = -1;   /* AS_SecurityInformation */
static int hf_x2ap_uEaggregateMaximumBitRate = -1;  /* UEAggregateMaximumBitRate */
static int hf_x2ap_subscriberProfileIDforRFP = -1;  /* SubscriberProfileIDforRFP */
static int hf_x2ap_e_RABs_ToBeSetup_List = -1;    /* E_RABs_ToBeSetup_List */
static int hf_x2ap_rRC_Context = -1;              /* RRC_Context */
static int hf_x2ap_handoverRestrictionList = -1;  /* HandoverRestrictionList */
static int hf_x2ap_locationReportingInformation = -1;  /* LocationReportingInformation */
static int hf_x2ap_E_RABs_ToBeSetup_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_e_RAB_Level_QoS_Parameters = -1;  /* E_RAB_Level_QoS_Parameters */
static int hf_x2ap_dL_Forwarding = -1;            /* DL_Forwarding */
static int hf_x2ap_uL_GTPtunnelEndpoint = -1;     /* GTPtunnelEndpoint */
static int hf_x2ap_E_RABs_Admitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_uL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_dL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_E_RABs_SubjectToStatusTransfer_List_item = -1;  /* ProtocolIE_Single_Container */
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
static int hf_x2ap_Old_ECGIs_item = -1;           /* ECGI */
static int hf_x2ap_CellToReport_List_item = -1;   /* ProtocolIE_Single_Container */
static int hf_x2ap_CellMeasurementResult_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_hWOverLoadIndicator = -1;      /* HWLoadIndicator */
static int hf_x2ap_s1TNLOverLoadIndicator = -1;   /* S1TNLLoadIndicator */
static int hf_x2ap_radioResourceStatus = -1;      /* RadioResourceStatus */
static int hf_x2ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_x2ap_ServedCellsToActivate_item = -1;  /* ServedCellsToActivate_Item */
static int hf_x2ap_ecgi = -1;                     /* ECGI */
static int hf_x2ap_ActivatedCellList_item = -1;   /* ActivatedCellList_Item */
static int hf_x2ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_x2ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_x2ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_x2ap_initiatingMessage_value = -1;  /* InitiatingMessage_value */
static int hf_x2ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_x2ap_value = -1;                    /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-x2ap-hf.c ---*/
#line 66 "../../asn1/x2ap/packet-x2ap-template.c"

/* Initialize the subtree pointers */
static int ett_x2ap = -1;
static int ett_x2ap_TransportLayerAddress = -1;

/*--- Included file: packet-x2ap-ett.c ---*/
#line 1 "../../asn1/x2ap/packet-x2ap-ett.c"
static gint ett_x2ap_PrivateIE_ID = -1;
static gint ett_x2ap_ProtocolIE_Container = -1;
static gint ett_x2ap_ProtocolIE_Field = -1;
static gint ett_x2ap_ProtocolExtensionContainer = -1;
static gint ett_x2ap_ProtocolExtensionField = -1;
static gint ett_x2ap_PrivateIE_Container = -1;
static gint ett_x2ap_PrivateIE_Field = -1;
static gint ett_x2ap_AS_SecurityInformation = -1;
static gint ett_x2ap_AllocationAndRetentionPriority = -1;
static gint ett_x2ap_BroadcastPLMNs_Item = -1;
static gint ett_x2ap_Cause = -1;
static gint ett_x2ap_CellType = -1;
static gint ett_x2ap_CompositeAvailableCapacityGroup = -1;
static gint ett_x2ap_CompositeAvailableCapacity = -1;
static gint ett_x2ap_COUNTvalue = -1;
static gint ett_x2ap_CriticalityDiagnostics = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_x2ap_FDD_Info = -1;
static gint ett_x2ap_TDD_Info = -1;
static gint ett_x2ap_EUTRA_Mode_Info = -1;
static gint ett_x2ap_ECGI = -1;
static gint ett_x2ap_ENB_ID = -1;
static gint ett_x2ap_EPLMNs = -1;
static gint ett_x2ap_E_RAB_Level_QoS_Parameters = -1;
static gint ett_x2ap_E_RAB_List = -1;
static gint ett_x2ap_E_RAB_Item = -1;
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
static gint ett_x2ap_HWLoadIndicator = -1;
static gint ett_x2ap_LastVisitedCell_Item = -1;
static gint ett_x2ap_LastVisitedEUTRANCellInformation = -1;
static gint ett_x2ap_LastVisitedGERANCellInformation = -1;
static gint ett_x2ap_LocationReportingInformation = -1;
static gint ett_x2ap_MBSFN_Subframe_Infolist = -1;
static gint ett_x2ap_MBSFN_Subframe_Info = -1;
static gint ett_x2ap_MobilityParametersModificationRange = -1;
static gint ett_x2ap_MobilityParametersInformation = -1;
static gint ett_x2ap_Neighbour_Information = -1;
static gint ett_x2ap_Neighbour_Information_item = -1;
static gint ett_x2ap_PRACH_Configuration = -1;
static gint ett_x2ap_RelativeNarrowbandTxPower = -1;
static gint ett_x2ap_RadioResourceStatus = -1;
static gint ett_x2ap_S1TNLLoadIndicator = -1;
static gint ett_x2ap_ServedCells = -1;
static gint ett_x2ap_ServedCells_item = -1;
static gint ett_x2ap_ServedCell_Information = -1;
static gint ett_x2ap_SpecialSubframe_Info = -1;
static gint ett_x2ap_SubframeAllocation = -1;
static gint ett_x2ap_TraceActivation = -1;
static gint ett_x2ap_UE_HistoryInformation = -1;
static gint ett_x2ap_UEAggregateMaximumBitRate = -1;
static gint ett_x2ap_UESecurityCapabilities = -1;
static gint ett_x2ap_UL_InterferenceOverloadIndication = -1;
static gint ett_x2ap_UL_HighInterferenceIndicationInfo = -1;
static gint ett_x2ap_UL_HighInterferenceIndicationInfo_Item = -1;
static gint ett_x2ap_HandoverRequest = -1;
static gint ett_x2ap_UE_ContextInformation = -1;
static gint ett_x2ap_E_RABs_ToBeSetup_List = -1;
static gint ett_x2ap_E_RABs_ToBeSetup_Item = -1;
static gint ett_x2ap_HandoverRequestAcknowledge = -1;
static gint ett_x2ap_E_RABs_Admitted_List = -1;
static gint ett_x2ap_E_RABs_Admitted_Item = -1;
static gint ett_x2ap_HandoverPreparationFailure = -1;
static gint ett_x2ap_HandoverReport = -1;
static gint ett_x2ap_SNStatusTransfer = -1;
static gint ett_x2ap_E_RABs_SubjectToStatusTransfer_List = -1;
static gint ett_x2ap_E_RABs_SubjectToStatusTransfer_Item = -1;
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
static gint ett_x2ap_PrivateMessage = -1;
static gint ett_x2ap_MobilityChangeRequest = -1;
static gint ett_x2ap_MobilityChangeAcknowledge = -1;
static gint ett_x2ap_MobilityChangeFailure = -1;
static gint ett_x2ap_RLFIndication = -1;
static gint ett_x2ap_CellActivationRequest = -1;
static gint ett_x2ap_ServedCellsToActivate = -1;
static gint ett_x2ap_ServedCellsToActivate_Item = -1;
static gint ett_x2ap_CellActivationResponse = -1;
static gint ett_x2ap_ActivatedCellList = -1;
static gint ett_x2ap_ActivatedCellList_Item = -1;
static gint ett_x2ap_CellActivationFailure = -1;
static gint ett_x2ap_X2AP_PDU = -1;
static gint ett_x2ap_InitiatingMessage = -1;
static gint ett_x2ap_SuccessfulOutcome = -1;
static gint ett_x2ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-x2ap-ett.c ---*/
#line 71 "../../asn1/x2ap/packet-x2ap-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint gbl_x2apSctpPort=SCTP_PORT_X2AP;

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
void proto_reg_handoff_x2ap(void);


/*--- Included file: packet-x2ap-fn.c ---*/
#line 1 "../../asn1/x2ap/packet-x2ap-fn.c"

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
  { id_handoverPreparation, "id-handoverPreparation" },
  { id_handoverCancel, "id-handoverCancel" },
  { id_loadIndication, "id-loadIndication" },
  { id_errorIndication, "id-errorIndication" },
  { id_snStatusTransfer, "id-snStatusTransfer" },
  { id_uEContextRelease, "id-uEContextRelease" },
  { id_x2Setup, "id-x2Setup" },
  { id_reset, "id-reset" },
  { id_eNBConfigurationUpdate, "id-eNBConfigurationUpdate" },
  { id_resourceStatusReportingInitiation, "id-resourceStatusReportingInitiation" },
  { id_resourceStatusReporting, "id-resourceStatusReporting" },
  { id_privateMessage, "id-privateMessage" },
  { id_mobilitySettingsChange, "id-mobilitySettingsChange" },
  { id_rLFIndication, "id-rLFIndication" },
  { id_handoverReport, "id-handoverReport" },
  { id_cellActivation, "id-cellActivation" },
  { 0, NULL }
};


static int
dissect_x2ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 67 "../../asn1/x2ap/x2ap.cnf"
  ProcedureCode = 0xFFFF;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 61 "../../asn1/x2ap/x2ap.cnf"
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                val_to_str(ProcedureCode, x2ap_ProcedureCode_vals,
                           "unknown message"));

  return offset;
}


static const value_string x2ap_ProtocolIE_ID_vals[] = {
  { id_E_RABs_Admitted_Item, "id-E-RABs-Admitted-Item" },
  { id_E_RABs_Admitted_List, "id-E-RABs-Admitted-List" },
  { id_E_RAB_Item, "id-E-RAB-Item" },
  { id_E_RABs_NotAdmitted_List, "id-E-RABs-NotAdmitted-List" },
  { id_E_RABs_ToBeSetup_Item, "id-E-RABs-ToBeSetup-Item" },
  { id_Cause, "id-Cause" },
  { id_CellInformation, "id-CellInformation" },
  { id_CellInformation_Item, "id-CellInformation-Item" },
  { id_New_eNB_UE_X2AP_ID, "id-New-eNB-UE-X2AP-ID" },
  { id_Old_eNB_UE_X2AP_ID, "id-Old-eNB-UE-X2AP-ID" },
  { id_TargetCell_ID, "id-TargetCell-ID" },
  { id_TargeteNBtoSource_eNBTransparentContainer, "id-TargeteNBtoSource-eNBTransparentContainer" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_UE_ContextInformation, "id-UE-ContextInformation" },
  { id_UE_HistoryInformation, "id-UE-HistoryInformation" },
  { id_UE_X2AP_ID, "id-UE-X2AP-ID" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_E_RABs_SubjectToStatusTransfer_List, "id-E-RABs-SubjectToStatusTransfer-List" },
  { id_E_RABs_SubjectToStatusTransfer_Item, "id-E-RABs-SubjectToStatusTransfer-Item" },
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
  { id_GUGroupIDToAddList, "id-GUGroupIDToAddList" },
  { id_GUGroupIDToDeleteList, "id-GUGroupIDToDeleteList" },
  { id_SRVCCOperationPossible, "id-SRVCCOperationPossible" },
  { id_Measurement_ID, "id-Measurement-ID" },
  { id_ReportCharacteristics, "id-ReportCharacteristics" },
  { id_ENB1_Measurement_ID, "id-ENB1-Measurement-ID" },
  { id_ENB2_Measurement_ID, "id-ENB2-Measurement-ID" },
  { id_Number_of_Antennaports, "id-Number-of-Antennaports" },
  { id_CompositeAvailableCapacityGroup, "id-CompositeAvailableCapacityGroup" },
  { id_ENB1_Cell_ID, "id-ENB1-Cell-ID" },
  { id_ENB2_Cell_ID, "id-ENB2-Cell-ID" },
  { id_ENB2_Proposed_Mobility_Parameters, "id-ENB2-Proposed-Mobility-Parameters" },
  { id_ENB1_Mobility_Parameters, "id-ENB1-Mobility-Parameters" },
  { id_ENB2_Mobility_Parameters_Modification_Range, "id-ENB2-Mobility-Parameters-Modification-Range" },
  { id_FailureCellPCI, "id-FailureCellPCI" },
  { id_Re_establishmentCellECGI, "id-Re-establishmentCellECGI" },
  { id_FailureCellCRNTI, "id-FailureCellCRNTI" },
  { id_ShortMAC_I, "id-ShortMAC-I" },
  { id_SourceCellECGI, "id-SourceCellECGI" },
  { id_FailureCellECGI, "id-FailureCellECGI" },
  { id_HandoverReportType, "id-HandoverReportType" },
  { id_PRACH_Configuration, "id-PRACH-Configuration" },
  { id_MBSFN_Subframe_Info, "id-MBSFN-Subframe-Info" },
  { id_ServedCellsToActivate, "id-ServedCellsToActivate" },
  { id_ActivatedCellList, "id-ActivatedCellList" },
  { id_DeactivationIndication, "id-DeactivationIndication" },
  { id_UE_RLF_Report_Container, "id-UE-RLF-Report-Container" },
  { 0, NULL }
};


static int
dissect_x2ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, FALSE);

#line 50 "../../asn1/x2ap/x2ap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(x2ap_ProtocolIE_ID_vals), "unknown (%d)"));
  }

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
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_x2ap_Key_eNodeB_Star(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_NextHopChainingCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AS_SecurityInformation_sequence[] = {
  { &hf_x2ap_key_eNodeB_star, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Key_eNodeB_Star },
  { &hf_x2ap_nextHopChainingCount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_NextHopChainingCount },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_AS_SecurityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_AS_SecurityInformation, AS_SecurityInformation_sequence);

  return offset;
}


static const value_string x2ap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_x2ap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string x2ap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_x2ap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string x2ap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_x2ap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationAndRetentionPriority_sequence[] = {
  { &hf_x2ap_priorityLevel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PriorityLevel },
  { &hf_x2ap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Pre_emptionCapability },
  { &hf_x2ap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Pre_emptionVulnerability },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_AllocationAndRetentionPriority, AllocationAndRetentionPriority_sequence);

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
#line 78 "../../asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);


	if(tvb_length(tvb)==0) 
		return offset;
		
	if (!parameter_tvb)
		return offset;
	dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, FALSE);


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



static int
dissect_x2ap_CapacityValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_CellCapacityClassValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, TRUE);

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
  {  15, "encryption-and-or-integrity-protection-algorithms-not-supported" },
  {  16, "reportCharacteristicsEmpty" },
  {  17, "noReportPeriodicity" },
  {  18, "existingMeasurementID" },
  {  19, "unknown-eNB-Measurement-ID" },
  {  20, "measurement-temporarily-not-available" },
  {  21, "unspecified" },
  {  22, "load-balancing" },
  {  23, "handover-optimisation" },
  {  24, "value-out-of-allowed-range" },
  {  25, "multiple-E-RAB-ID-instances" },
  {  26, "switch-off-ongoing" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     22, NULL, TRUE, 5, NULL);

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


static const value_string x2ap_Cell_Size_vals[] = {
  {   0, "verysmall" },
  {   1, "small" },
  {   2, "medium" },
  {   3, "large" },
  { 0, NULL }
};


static int
dissect_x2ap_Cell_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CellType_sequence[] = {
  { &hf_x2ap_cell_Size      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cell_Size },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellType, CellType_sequence);

  return offset;
}


static const per_sequence_t CompositeAvailableCapacity_sequence[] = {
  { &hf_x2ap_cellCapacityClassValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_CellCapacityClassValue },
  { &hf_x2ap_capacityValue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CapacityValue },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CompositeAvailableCapacity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CompositeAvailableCapacity, CompositeAvailableCapacity_sequence);

  return offset;
}


static const per_sequence_t CompositeAvailableCapacityGroup_sequence[] = {
  { &hf_x2ap_dL_CompositeAvailableCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CompositeAvailableCapacity },
  { &hf_x2ap_uL_CompositeAvailableCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CompositeAvailableCapacity },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CompositeAvailableCapacityGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CompositeAvailableCapacityGroup, CompositeAvailableCapacityGroup_sequence);

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



static int
dissect_x2ap_CRNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}


static const value_string x2ap_CyclicPrefixDL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_x2ap_CyclicPrefixDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CyclicPrefixUL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_x2ap_CyclicPrefixUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_DeactivationIndication_vals[] = {
  {   0, "deactivated" },
  { 0, NULL }
};


static int
dissect_x2ap_DeactivationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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


static const value_string x2ap_Transmission_Bandwidth_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  { 0, NULL }
};


static int
dissect_x2ap_Transmission_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t FDD_Info_sequence[] = {
  { &hf_x2ap_uL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_dL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_uL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Transmission_Bandwidth },
  { &hf_x2ap_dL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Transmission_Bandwidth },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_FDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_FDD_Info, FDD_Info_sequence);

  return offset;
}


static const value_string x2ap_SubframeAssignment_vals[] = {
  {   0, "sa0" },
  {   1, "sa1" },
  {   2, "sa2" },
  {   3, "sa3" },
  {   4, "sa4" },
  {   5, "sa5" },
  {   6, "sa6" },
  { 0, NULL }
};


static int
dissect_x2ap_SubframeAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_SpecialSubframePatterns_vals[] = {
  {   0, "ssp0" },
  {   1, "ssp1" },
  {   2, "ssp2" },
  {   3, "ssp3" },
  {   4, "ssp4" },
  {   5, "ssp5" },
  {   6, "ssp6" },
  {   7, "ssp7" },
  {   8, "ssp8" },
  { 0, NULL }
};


static int
dissect_x2ap_SpecialSubframePatterns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SpecialSubframe_Info_sequence[] = {
  { &hf_x2ap_specialSubframePatterns, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SpecialSubframePatterns },
  { &hf_x2ap_cyclicPrefixDL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CyclicPrefixDL },
  { &hf_x2ap_cyclicPrefixUL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CyclicPrefixUL },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SpecialSubframe_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SpecialSubframe_Info, SpecialSubframe_Info_sequence);

  return offset;
}


static const per_sequence_t TDD_Info_sequence[] = {
  { &hf_x2ap_eARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Transmission_Bandwidth },
  { &hf_x2ap_subframeAssignment, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SubframeAssignment },
  { &hf_x2ap_specialSubframe_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SpecialSubframe_Info },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TDD_Info, TDD_Info_sequence);

  return offset;
}


static const value_string x2ap_EUTRA_Mode_Info_vals[] = {
  {   0, "fDD" },
  {   1, "tDD" },
  { 0, NULL }
};

static const per_choice_t EUTRA_Mode_Info_choice[] = {
  {   0, &hf_x2ap_fDD            , ASN1_EXTENSION_ROOT    , dissect_x2ap_FDD_Info },
  {   1, &hf_x2ap_tDD            , ASN1_EXTENSION_ROOT    , dissect_x2ap_TDD_Info },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_EUTRA_Mode_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_EUTRA_Mode_Info, EUTRA_Mode_Info_choice,
                                 NULL);

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



static int
dissect_x2ap_EncryptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL);

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



static int
dissect_x2ap_E_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_x2ap_e_RAB_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_e_RAB_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_e_RAB_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_e_RAB_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t E_RAB_Level_QoS_Parameters_sequence[] = {
  { &hf_x2ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_QCI },
  { &hf_x2ap_allocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AllocationAndRetentionPriority },
  { &hf_x2ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GBR_QosInformation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RAB_Level_QoS_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RAB_Level_QoS_Parameters, E_RAB_Level_QoS_Parameters_sequence);

  return offset;
}


static const per_sequence_t E_RAB_List_sequence_of[1] = {
  { &hf_x2ap_E_RAB_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RAB_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RAB_List, E_RAB_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RAB_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cause },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RAB_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RAB_Item, E_RAB_Item_sequence);

  return offset;
}



static int
dissect_x2ap_EUTRANTraceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

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
  {   3, "cdma2000" },
  { 0, NULL }
};


static int
dissect_x2ap_ForbiddenInterRATs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

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
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_forbiddenTACs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenTACs },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
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
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_forbiddenLACs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenLACs },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
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



static int
dissect_x2ap_Fourframes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL);

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
#line 111 "../../asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  proto_tree *subtree;
  gint tvb_len;
  
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
	/* Get the length */
	tvb_len = tvb_length(parameter_tvb);
	subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_TransportLayerAddress);
	if (tvb_len==4){
		/* IPv4 */
		 proto_tree_add_item(subtree, hf_x2ap_transportLayerAddressIPv4, parameter_tvb, 0, tvb_len, FALSE);
	}
	if (tvb_len==16){
		/* IPv6 */
		 proto_tree_add_item(subtree, hf_x2ap_transportLayerAddressIPv6, parameter_tvb, 0, tvb_len, FALSE);
	}



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
  { &hf_x2ap_mME_Code       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MME_Code },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const value_string x2ap_HandoverReportType_vals[] = {
  {   0, "hoTooEarly" },
  {   1, "hoToWrongCell" },
  { 0, NULL }
};


static int
dissect_x2ap_HandoverReportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

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


static const value_string x2ap_LoadIndicator_vals[] = {
  {   0, "lowLoad" },
  {   1, "mediumLoad" },
  {   2, "highLoad" },
  {   3, "overLoad" },
  { 0, NULL }
};


static int
dissect_x2ap_LoadIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t HWLoadIndicator_sequence[] = {
  { &hf_x2ap_dLHWLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_uLHWLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HWLoadIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HWLoadIndicator, HWLoadIndicator_sequence);

  return offset;
}



static int
dissect_x2ap_IntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL);

  return offset;
}



static int
dissect_x2ap_InterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_Time_UE_StayedInCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LastVisitedEUTRANCellInformation_sequence[] = {
  { &hf_x2ap_global_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_cellType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CellType },
  { &hf_x2ap_time_UE_StayedInCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Time_UE_StayedInCell },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_LastVisitedEUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_LastVisitedEUTRANCellInformation, LastVisitedEUTRANCellInformation_sequence);

  return offset;
}



static int
dissect_x2ap_LastVisitedUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x2ap_LastVisitedGERANCellInformation_vals[] = {
  {   0, "undefined" },
  { 0, NULL }
};

static const per_choice_t LastVisitedGERANCellInformation_choice[] = {
  {   0, &hf_x2ap_undefined      , ASN1_EXTENSION_ROOT    , dissect_x2ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_LastVisitedGERANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_LastVisitedGERANCellInformation, LastVisitedGERANCellInformation_choice,
                                 NULL);

  return offset;
}


static const value_string x2ap_LastVisitedCell_Item_vals[] = {
  {   0, "e-UTRAN-Cell" },
  {   1, "uTRAN-Cell" },
  {   2, "gERAN-Cell" },
  { 0, NULL }
};

static const per_choice_t LastVisitedCell_Item_choice[] = {
  {   0, &hf_x2ap_e_UTRAN_Cell   , ASN1_EXTENSION_ROOT    , dissect_x2ap_LastVisitedEUTRANCellInformation },
  {   1, &hf_x2ap_uTRAN_Cell     , ASN1_EXTENSION_ROOT    , dissect_x2ap_LastVisitedUTRANCellInformation },
  {   2, &hf_x2ap_gERAN_Cell     , ASN1_EXTENSION_ROOT    , dissect_x2ap_LastVisitedGERANCellInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_LastVisitedCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_LastVisitedCell_Item, LastVisitedCell_Item_choice,
                                 NULL);

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
dissect_x2ap_Measurement_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string x2ap_RadioframeAllocationPeriod_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n16" },
  {   5, "n32" },
  { 0, NULL }
};


static int
dissect_x2ap_RadioframeAllocationPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_RadioframeAllocationOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_Oneframe(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL);

  return offset;
}


static const value_string x2ap_SubframeAllocation_vals[] = {
  {   0, "oneframe" },
  {   1, "fourframes" },
  { 0, NULL }
};

static const per_choice_t SubframeAllocation_choice[] = {
  {   0, &hf_x2ap_oneframe       , ASN1_EXTENSION_ROOT    , dissect_x2ap_Oneframe },
  {   1, &hf_x2ap_fourframes     , ASN1_EXTENSION_ROOT    , dissect_x2ap_Fourframes },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_SubframeAllocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_SubframeAllocation, SubframeAllocation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MBSFN_Subframe_Info_sequence[] = {
  { &hf_x2ap_radioframeAllocationPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RadioframeAllocationPeriod },
  { &hf_x2ap_radioframeAllocationOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RadioframeAllocationOffset },
  { &hf_x2ap_subframeAllocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SubframeAllocation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MBSFN_Subframe_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MBSFN_Subframe_Info, MBSFN_Subframe_Info_sequence);

  return offset;
}


static const per_sequence_t MBSFN_Subframe_Infolist_sequence_of[1] = {
  { &hf_x2ap_MBSFN_Subframe_Infolist_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_MBSFN_Subframe_Info },
};

static int
dissect_x2ap_MBSFN_Subframe_Infolist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_MBSFN_Subframe_Infolist, MBSFN_Subframe_Infolist_sequence_of,
                                                  1, maxnoofMBSFN, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_M20_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -20, 20U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MobilityParametersModificationRange_sequence[] = {
  { &hf_x2ap_handoverTriggerChangeLowerLimit, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_M20_20 },
  { &hf_x2ap_handoverTriggerChangeUpperLimit, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_M20_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityParametersModificationRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityParametersModificationRange, MobilityParametersModificationRange_sequence);

  return offset;
}


static const per_sequence_t MobilityParametersInformation_sequence[] = {
  { &hf_x2ap_handoverTriggerChange, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_M20_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityParametersInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityParametersInformation, MobilityParametersInformation_sequence);

  return offset;
}



static int
dissect_x2ap_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, TRUE);

  return offset;
}


static const per_sequence_t Neighbour_Information_item_sequence[] = {
  { &hf_x2ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_pCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PCI },
  { &hf_x2ap_eARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_Neighbour_Information_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_Neighbour_Information_item, Neighbour_Information_item_sequence);

  return offset;
}


static const per_sequence_t Neighbour_Information_sequence_of[1] = {
  { &hf_x2ap_Neighbour_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Neighbour_Information_item },
};

static int
dissect_x2ap_Neighbour_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Neighbour_Information, Neighbour_Information_sequence_of,
                                                  0, maxnoofNeighbours, FALSE);

  return offset;
}


static const value_string x2ap_Number_of_Antennaports_vals[] = {
  {   0, "an1" },
  {   1, "an2" },
  {   2, "an4" },
  { 0, NULL }
};


static int
dissect_x2ap_Number_of_Antennaports(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_837(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 837U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_94(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 94U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PRACH_Configuration_sequence[] = {
  { &hf_x2ap_rootSequenceIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_837 },
  { &hf_x2ap_zeroCorrelationIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_15 },
  { &hf_x2ap_highSpeedFlag  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BOOLEAN },
  { &hf_x2ap_prach_FreqOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_94 },
  { &hf_x2ap_prach_ConfigIndex, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_INTEGER_0_63 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_PRACH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_PRACH_Configuration, PRACH_Configuration_sequence);

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
dissect_x2ap_ReportCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_RRC_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 136 "../../asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  gint32 start_offset;
  
  start_offset = offset;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  parameter_tvb = tvb_new_subset(tvb, start_offset>>3, -1, -1);	
  if (!parameter_tvb)
    return offset;
  dissect_lte_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, tree);



  return offset;
}



static int
dissect_x2ap_DL_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UL_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_DL_non_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UL_non_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_DL_Total_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UL_Total_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RadioResourceStatus_sequence[] = {
  { &hf_x2ap_dL_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_GBR_PRB_usage },
  { &hf_x2ap_uL_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_GBR_PRB_usage },
  { &hf_x2ap_dL_non_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_non_GBR_PRB_usage },
  { &hf_x2ap_uL_non_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_non_GBR_PRB_usage },
  { &hf_x2ap_dL_Total_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_Total_PRB_usage },
  { &hf_x2ap_uL_Total_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_Total_PRB_usage },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RadioResourceStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RadioResourceStatus, RadioResourceStatus_sequence);

  return offset;
}


static const per_sequence_t S1TNLLoadIndicator_sequence[] = {
  { &hf_x2ap_dLS1TNLLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_uLS1TNLLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_S1TNLLoadIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_S1TNLLoadIndicator, S1TNLLoadIndicator_sequence);

  return offset;
}


static const per_sequence_t ServedCell_Information_sequence[] = {
  { &hf_x2ap_pCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PCI },
  { &hf_x2ap_cellId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TAC },
  { &hf_x2ap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BroadcastPLMNs_Item },
  { &hf_x2ap_eUTRA_Mode_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EUTRA_Mode_Info },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCell_Information, ServedCell_Information_sequence);

  return offset;
}


static const per_sequence_t ServedCells_item_sequence[] = {
  { &hf_x2ap_servedCellInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCell_Information },
  { &hf_x2ap_neighbour_Info , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Neighbour_Information },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCells_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCells_item, ServedCells_item_sequence);

  return offset;
}


static const per_sequence_t ServedCells_sequence_of[1] = {
  { &hf_x2ap_ServedCells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCells_item },
};

static int
dissect_x2ap_ServedCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ServedCells, ServedCells_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}



static int
dissect_x2ap_ShortMAC_I(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}


static const value_string x2ap_SRVCCOperationPossible_vals[] = {
  {   0, "possible" },
  { 0, NULL }
};


static int
dissect_x2ap_SRVCCOperationPossible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
#line 91 "../../asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

	if (!parameter_tvb)
		return offset;
	  
     dissect_lte_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, tree);
	


  return offset;
}


static const value_string x2ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_x2ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  {   3, "minimumWithoutVendorSpecificExtension" },
  {   4, "mediumWithoutVendorSpecificExtension" },
  {   5, "maximumWithoutVendorSpecificExtension" },
  { 0, NULL }
};


static int
dissect_x2ap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_TraceCollectionEntityIPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL);

  return offset;
}


static const per_sequence_t TraceActivation_sequence[] = {
  { &hf_x2ap_eUTRANTraceID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EUTRANTraceID },
  { &hf_x2ap_interfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_InterfacesToTrace },
  { &hf_x2ap_traceDepth     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TraceDepth },
  { &hf_x2ap_traceCollectionEntityIPAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TraceCollectionEntityIPAddress },
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


static const per_sequence_t UESecurityCapabilities_sequence[] = {
  { &hf_x2ap_encryptionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EncryptionAlgorithms },
  { &hf_x2ap_integrityProtectionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_IntegrityProtectionAlgorithms },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UESecurityCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UESecurityCapabilities, UESecurityCapabilities_sequence);

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
  { &hf_x2ap_target_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_ul_interferenceindication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_HighInterferenceIndication },
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



static int
dissect_x2ap_UE_RLF_Report_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

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


static const per_sequence_t E_RABs_ToBeSetup_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeSetup_List, E_RABs_ToBeSetup_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t UE_ContextInformation_sequence[] = {
  { &hf_x2ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UE_S1AP_ID },
  { &hf_x2ap_uESecurityCapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UESecurityCapabilities },
  { &hf_x2ap_aS_SecurityInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AS_SecurityInformation },
  { &hf_x2ap_uEaggregateMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UEAggregateMaximumBitRate },
  { &hf_x2ap_subscriberProfileIDforRFP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SubscriberProfileIDforRFP },
  { &hf_x2ap_e_RABs_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RABs_ToBeSetup_List },
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


static const per_sequence_t E_RABs_ToBeSetup_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_dL_Forwarding  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_DL_Forwarding },
  { &hf_x2ap_uL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeSetup_Item, E_RABs_ToBeSetup_Item_sequence);

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


static const per_sequence_t E_RABs_Admitted_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_Admitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_Admitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_Admitted_List, E_RABs_Admitted_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_uL_GTP_TunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_dL_GTP_TunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_Item, E_RABs_Admitted_Item_sequence);

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


static const per_sequence_t HandoverReport_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverReport, HandoverReport_sequence);

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


static const per_sequence_t E_RABs_SubjectToStatusTransfer_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_SubjectToStatusTransfer_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_SubjectToStatusTransfer_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_SubjectToStatusTransfer_List, E_RABs_SubjectToStatusTransfer_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_SubjectToStatusTransfer_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_receiveStatusofULPDCPSDUs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ReceiveStatusofULPDCPSDUs },
  { &hf_x2ap_uL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_COUNTvalue },
  { &hf_x2ap_dL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_COUNTvalue },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_SubjectToStatusTransfer_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_SubjectToStatusTransfer_Item, E_RABs_SubjectToStatusTransfer_Item_sequence);

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
  { &hf_x2ap_servedCellInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCell_Information },
  { &hf_x2ap_neighbour_Info , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Neighbour_Information },
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


static const value_string x2ap_ReportingPeriodicity_vals[] = {
  {   0, "one-thousand-ms" },
  {   1, "two-thousand-ms" },
  {   2, "five-thousand-ms" },
  {   3, "ten-thousand-ms" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportingPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

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
  { &hf_x2ap_hWOverLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_HWLoadIndicator },
  { &hf_x2ap_s1TNLOverLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_S1TNLLoadIndicator },
  { &hf_x2ap_radioResourceStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_RadioResourceStatus },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellMeasurementResult_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellMeasurementResult_Item, CellMeasurementResult_Item_sequence);

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


static const per_sequence_t MobilityChangeRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityChangeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityChangeRequest, MobilityChangeRequest_sequence);

  return offset;
}


static const per_sequence_t MobilityChangeAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityChangeAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityChangeAcknowledge, MobilityChangeAcknowledge_sequence);

  return offset;
}


static const per_sequence_t MobilityChangeFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityChangeFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityChangeFailure, MobilityChangeFailure_sequence);

  return offset;
}


static const per_sequence_t RLFIndication_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RLFIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RLFIndication, RLFIndication_sequence);

  return offset;
}


static const per_sequence_t CellActivationRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellActivationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellActivationRequest, CellActivationRequest_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToActivate_Item_sequence[] = {
  { &hf_x2ap_ecgi           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCellsToActivate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCellsToActivate_Item, ServedCellsToActivate_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToActivate_sequence_of[1] = {
  { &hf_x2ap_ServedCellsToActivate_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCellsToActivate_Item },
};

static int
dissect_x2ap_ServedCellsToActivate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ServedCellsToActivate, ServedCellsToActivate_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellActivationResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellActivationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellActivationResponse, CellActivationResponse_sequence);

  return offset;
}


static const per_sequence_t ActivatedCellList_Item_sequence[] = {
  { &hf_x2ap_ecgi           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ActivatedCellList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ActivatedCellList_Item, ActivatedCellList_Item_sequence);

  return offset;
}


static const per_sequence_t ActivatedCellList_sequence_of[1] = {
  { &hf_x2ap_ActivatedCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ActivatedCellList_Item },
};

static int
dissect_x2ap_ActivatedCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ActivatedCellList, ActivatedCellList_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellActivationFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellActivationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellActivationFailure, CellActivationFailure_sequence);

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
static int dissect_CompositeAvailableCapacityGroup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CompositeAvailableCapacityGroup(tvb, offset, &asn1_ctx, tree, hf_x2ap_CompositeAvailableCapacityGroup_PDU);
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
static int dissect_CRNTI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CRNTI(tvb, offset, &asn1_ctx, tree, hf_x2ap_CRNTI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DeactivationIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_DeactivationIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_DeactivationIndication_PDU);
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
static int dissect_E_RAB_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RAB_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RAB_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RAB_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RAB_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RAB_Item_PDU);
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
static int dissect_HandoverReportType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverReportType(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverReportType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Measurement_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Measurement_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_Measurement_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBSFN_Subframe_Infolist_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MBSFN_Subframe_Infolist(tvb, offset, &asn1_ctx, tree, hf_x2ap_MBSFN_Subframe_Infolist_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityParametersModificationRange_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityParametersModificationRange(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityParametersModificationRange_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityParametersInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityParametersInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityParametersInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Antennaports_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Number_of_Antennaports(tvb, offset, &asn1_ctx, tree, hf_x2ap_Number_of_Antennaports_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PCI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PCI(tvb, offset, &asn1_ctx, tree, hf_x2ap_PCI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRACH_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PRACH_Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_PRACH_Configuration_PDU);
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
static int dissect_ReportCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReportCharacteristics(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReportCharacteristics_PDU);
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
static int dissect_ShortMAC_I_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ShortMAC_I(tvb, offset, &asn1_ctx, tree, hf_x2ap_ShortMAC_I_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCCOperationPossible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SRVCCOperationPossible(tvb, offset, &asn1_ctx, tree, hf_x2ap_SRVCCOperationPossible_PDU);
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
static int dissect_UE_RLF_Report_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_RLF_Report_Container(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_RLF_Report_Container_PDU);
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
static int dissect_E_RABs_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeSetup_Item_PDU);
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
static int dissect_E_RABs_Admitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_Item_PDU);
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
static int dissect_HandoverReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverReport(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverReport_PDU);
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
static int dissect_E_RABs_SubjectToStatusTransfer_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_SubjectToStatusTransfer_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_SubjectToStatusTransfer_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_SubjectToStatusTransfer_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_SubjectToStatusTransfer_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_SubjectToStatusTransfer_Item_PDU);
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
static int dissect_ReportingPeriodicity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReportingPeriodicity(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReportingPeriodicity_PDU);
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
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_x2ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityChangeRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityChangeRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityChangeRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityChangeAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityChangeAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityChangeAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityChangeFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityChangeFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityChangeFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RLFIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RLFIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_RLFIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellActivationRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellActivationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCellsToActivate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ServedCellsToActivate(tvb, offset, &asn1_ctx, tree, hf_x2ap_ServedCellsToActivate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellActivationResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellActivationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ActivatedCellList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ActivatedCellList(tvb, offset, &asn1_ctx, tree, hf_x2ap_ActivatedCellList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellActivationFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellActivationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static void dissect_X2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_x2ap_X2AP_PDU(tvb, 0, &asn1_ctx, tree, hf_x2ap_X2AP_PDU_PDU);
}


/*--- End of included file: packet-x2ap-fn.c ---*/
#line 92 "../../asn1/x2ap/packet-x2ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static void
dissect_x2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*x2ap_item = NULL;
	proto_tree	*x2ap_tree = NULL;

	/* make entry in the Protocol column on summary display */
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
    { &hf_x2ap_transportLayerAddressIPv4,
      { "transportLayerAddress(IPv4)", "x2ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_transportLayerAddressIPv6,
      { "transportLayerAddress(IPv6)", "x2ap.transportLayerAddressIPv6",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},


/*--- Included file: packet-x2ap-hfarr.c ---*/
#line 1 "../../asn1/x2ap/packet-x2ap-hfarr.c"
    { &hf_x2ap_Cause_PDU,
      { "Cause", "x2ap.Cause",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_CompositeAvailableCapacityGroup_PDU,
      { "CompositeAvailableCapacityGroup", "x2ap.CompositeAvailableCapacityGroup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "x2ap.CriticalityDiagnostics",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CRNTI_PDU,
      { "CRNTI", "x2ap.CRNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_DeactivationIndication_PDU,
      { "DeactivationIndication", "x2ap.DeactivationIndication",
        FT_UINT32, BASE_DEC, VALS(x2ap_DeactivationIndication_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ECGI_PDU,
      { "ECGI", "x2ap.ECGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RAB_List_PDU,
      { "E-RAB-List", "x2ap.E_RAB_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RAB_Item_PDU,
      { "E-RAB-Item", "x2ap.E_RAB_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_GlobalENB_ID_PDU,
      { "GlobalENB-ID", "x2ap.GlobalENB_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_GUGroupIDList_PDU,
      { "GUGroupIDList", "x2ap.GUGroupIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_GUMMEI_PDU,
      { "GUMMEI", "x2ap.GUMMEI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverReportType_PDU,
      { "HandoverReportType", "x2ap.HandoverReportType",
        FT_UINT32, BASE_DEC, VALS(x2ap_HandoverReportType_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_Measurement_ID_PDU,
      { "Measurement-ID", "x2ap.Measurement_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MBSFN_Subframe_Infolist_PDU,
      { "MBSFN-Subframe-Infolist", "x2ap.MBSFN_Subframe_Infolist",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityParametersModificationRange_PDU,
      { "MobilityParametersModificationRange", "x2ap.MobilityParametersModificationRange",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityParametersInformation_PDU,
      { "MobilityParametersInformation", "x2ap.MobilityParametersInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Number_of_Antennaports_PDU,
      { "Number-of-Antennaports", "x2ap.Number_of_Antennaports",
        FT_UINT32, BASE_DEC, VALS(x2ap_Number_of_Antennaports_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_PCI_PDU,
      { "PCI", "x2ap.PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_PRACH_Configuration_PDU,
      { "PRACH-Configuration", "x2ap.PRACH_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Registration_Request_PDU,
      { "Registration-Request", "x2ap.Registration_Request",
        FT_UINT32, BASE_DEC, VALS(x2ap_Registration_Request_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_PDU,
      { "ReportCharacteristics", "x2ap.ReportCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCells_PDU,
      { "ServedCells", "x2ap.ServedCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ShortMAC_I_PDU,
      { "ShortMAC-I", "x2ap.ShortMAC_I",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SRVCCOperationPossible_PDU,
      { "SRVCCOperationPossible", "x2ap.SRVCCOperationPossible",
        FT_UINT32, BASE_DEC, VALS(x2ap_SRVCCOperationPossible_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU,
      { "TargeteNBtoSource-eNBTransparentContainer", "x2ap.TargeteNBtoSource_eNBTransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TimeToWait_PDU,
      { "TimeToWait", "x2ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(x2ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_TraceActivation_PDU,
      { "TraceActivation", "x2ap.TraceActivation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_HistoryInformation_PDU,
      { "UE-HistoryInformation", "x2ap.UE_HistoryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_X2AP_ID_PDU,
      { "UE-X2AP-ID", "x2ap.UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_RLF_Report_Container_PDU,
      { "UE-RLF-Report-Container", "x2ap.UE_RLF_Report_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverRequest_PDU,
      { "HandoverRequest", "x2ap.HandoverRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_ContextInformation_PDU,
      { "UE-ContextInformation", "x2ap.UE_ContextInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeSetup_Item_PDU,
      { "E-RABs-ToBeSetup-Item", "x2ap.E_RABs_ToBeSetup_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverRequestAcknowledge_PDU,
      { "HandoverRequestAcknowledge", "x2ap.HandoverRequestAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_List_PDU,
      { "E-RABs-Admitted-List", "x2ap.E_RABs_Admitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_Item_PDU,
      { "E-RABs-Admitted-Item", "x2ap.E_RABs_Admitted_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverPreparationFailure_PDU,
      { "HandoverPreparationFailure", "x2ap.HandoverPreparationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverReport_PDU,
      { "HandoverReport", "x2ap.HandoverReport",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SNStatusTransfer_PDU,
      { "SNStatusTransfer", "x2ap.SNStatusTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_SubjectToStatusTransfer_List_PDU,
      { "E-RABs-SubjectToStatusTransfer-List", "x2ap.E_RABs_SubjectToStatusTransfer_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_SubjectToStatusTransfer_Item_PDU,
      { "E-RABs-SubjectToStatusTransfer-Item", "x2ap.E_RABs_SubjectToStatusTransfer_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UEContextRelease_PDU,
      { "UEContextRelease", "x2ap.UEContextRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverCancel_PDU,
      { "HandoverCancel", "x2ap.HandoverCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ErrorIndication_PDU,
      { "ErrorIndication", "x2ap.ErrorIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResetRequest_PDU,
      { "ResetRequest", "x2ap.ResetRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResetResponse_PDU,
      { "ResetResponse", "x2ap.ResetResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2SetupRequest_PDU,
      { "X2SetupRequest", "x2ap.X2SetupRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2SetupResponse_PDU,
      { "X2SetupResponse", "x2ap.X2SetupResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2SetupFailure_PDU,
      { "X2SetupFailure", "x2ap.X2SetupFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_LoadInformation_PDU,
      { "LoadInformation", "x2ap.LoadInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellInformation_List_PDU,
      { "CellInformation-List", "x2ap.CellInformation_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellInformation_Item_PDU,
      { "CellInformation-Item", "x2ap.CellInformation_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ENBConfigurationUpdate_PDU,
      { "ENBConfigurationUpdate", "x2ap.ENBConfigurationUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCellsToModify_PDU,
      { "ServedCellsToModify", "x2ap.ServedCellsToModify",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Old_ECGIs_PDU,
      { "Old-ECGIs", "x2ap.Old_ECGIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ENBConfigurationUpdateAcknowledge_PDU,
      { "ENBConfigurationUpdateAcknowledge", "x2ap.ENBConfigurationUpdateAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ENBConfigurationUpdateFailure_PDU,
      { "ENBConfigurationUpdateFailure", "x2ap.ENBConfigurationUpdateFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusRequest_PDU,
      { "ResourceStatusRequest", "x2ap.ResourceStatusRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellToReport_List_PDU,
      { "CellToReport-List", "x2ap.CellToReport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellToReport_Item_PDU,
      { "CellToReport-Item", "x2ap.CellToReport_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportingPeriodicity_PDU,
      { "ReportingPeriodicity", "x2ap.ReportingPeriodicity",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportingPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusResponse_PDU,
      { "ResourceStatusResponse", "x2ap.ResourceStatusResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusFailure_PDU,
      { "ResourceStatusFailure", "x2ap.ResourceStatusFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusUpdate_PDU,
      { "ResourceStatusUpdate", "x2ap.ResourceStatusUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellMeasurementResult_List_PDU,
      { "CellMeasurementResult-List", "x2ap.CellMeasurementResult_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellMeasurementResult_Item_PDU,
      { "CellMeasurementResult-Item", "x2ap.CellMeasurementResult_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_PrivateMessage_PDU,
      { "PrivateMessage", "x2ap.PrivateMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityChangeRequest_PDU,
      { "MobilityChangeRequest", "x2ap.MobilityChangeRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityChangeAcknowledge_PDU,
      { "MobilityChangeAcknowledge", "x2ap.MobilityChangeAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityChangeFailure_PDU,
      { "MobilityChangeFailure", "x2ap.MobilityChangeFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_RLFIndication_PDU,
      { "RLFIndication", "x2ap.RLFIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellActivationRequest_PDU,
      { "CellActivationRequest", "x2ap.CellActivationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCellsToActivate_PDU,
      { "ServedCellsToActivate", "x2ap.ServedCellsToActivate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellActivationResponse_PDU,
      { "CellActivationResponse", "x2ap.CellActivationResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ActivatedCellList_PDU,
      { "ActivatedCellList", "x2ap.ActivatedCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellActivationFailure_PDU,
      { "CellActivationFailure", "x2ap.CellActivationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2AP_PDU_PDU,
      { "X2AP-PDU", "x2ap.X2AP_PDU",
        FT_UINT32, BASE_DEC, VALS(x2ap_X2AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_local,
      { "local", "x2ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_x2ap_global,
      { "global", "x2ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x2ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "x2ap.ProtocolIE_Field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_x2ap_criticality,
      { "criticality", "x2ap.criticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_protocolIE_Field_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Field_value", HFILL }},
    { &hf_x2ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "x2ap.ProtocolExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_extension_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_x2ap_extensionValue,
      { "extensionValue", "x2ap.extensionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_PrivateIE_Container_item,
      { "PrivateIE-Field", "x2ap.PrivateIE_Field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_private_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC, VALS(x2ap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_x2ap_privateIE_Field_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateIE_Field_value", HFILL }},
    { &hf_x2ap_key_eNodeB_star,
      { "key-eNodeB-star", "x2ap.key_eNodeB_star",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_nextHopChainingCount,
      { "nextHopChainingCount", "x2ap.nextHopChainingCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_iE_Extensions,
      { "iE-Extensions", "x2ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_x2ap_priorityLevel,
      { "priorityLevel", "x2ap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(x2ap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_pre_emptionCapability,
      { "pre-emptionCapability", "x2ap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(x2ap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "x2ap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(x2ap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_BroadcastPLMNs_Item_item,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_radioNetwork,
      { "radioNetwork", "x2ap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_x2ap_transport,
      { "transport", "x2ap.transport",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_x2ap_protocol,
      { "protocol", "x2ap.protocol",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_x2ap_misc,
      { "misc", "x2ap.misc",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_x2ap_cell_Size,
      { "cell-Size", "x2ap.cell_Size",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cell_Size_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_CompositeAvailableCapacity,
      { "dL-CompositeAvailableCapacity", "x2ap.dL_CompositeAvailableCapacity",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompositeAvailableCapacity", HFILL }},
    { &hf_x2ap_uL_CompositeAvailableCapacity,
      { "uL-CompositeAvailableCapacity", "x2ap.uL_CompositeAvailableCapacity",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompositeAvailableCapacity", HFILL }},
    { &hf_x2ap_cellCapacityClassValue,
      { "cellCapacityClassValue", "x2ap.cellCapacityClassValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_capacityValue,
      { "capacityValue", "x2ap.capacityValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_pDCP_SN,
      { "pDCP-SN", "x2ap.pDCP_SN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_hFN,
      { "hFN", "x2ap.hFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_procedureCode,
      { "procedureCode", "x2ap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_triggeringMessage,
      { "triggeringMessage", "x2ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(x2ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_procedureCriticality,
      { "procedureCriticality", "x2ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_x2ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "x2ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_x2ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "x2ap.CriticalityDiagnostics_IE_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_iECriticality,
      { "iECriticality", "x2ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_x2ap_iE_ID,
      { "iE-ID", "x2ap.iE_ID",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_x2ap_typeOfError,
      { "typeOfError", "x2ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(x2ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_EARFCN,
      { "uL-EARFCN", "x2ap.uL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EARFCN", HFILL }},
    { &hf_x2ap_dL_EARFCN,
      { "dL-EARFCN", "x2ap.dL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EARFCN", HFILL }},
    { &hf_x2ap_uL_Transmission_Bandwidth,
      { "uL-Transmission-Bandwidth", "x2ap.uL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(x2ap_Transmission_Bandwidth_vals), 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_x2ap_dL_Transmission_Bandwidth,
      { "dL-Transmission-Bandwidth", "x2ap.dL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(x2ap_Transmission_Bandwidth_vals), 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_x2ap_eARFCN,
      { "eARFCN", "x2ap.eARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_transmission_Bandwidth,
      { "transmission-Bandwidth", "x2ap.transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(x2ap_Transmission_Bandwidth_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_subframeAssignment,
      { "subframeAssignment", "x2ap.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubframeAssignment_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_specialSubframe_Info,
      { "specialSubframe-Info", "x2ap.specialSubframe_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_fDD,
      { "fDD", "x2ap.fDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "FDD_Info", HFILL }},
    { &hf_x2ap_tDD,
      { "tDD", "x2ap.tDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "TDD_Info", HFILL }},
    { &hf_x2ap_pLMN_Identity,
      { "pLMN-Identity", "x2ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANcellIdentifier,
      { "eUTRANcellIdentifier", "x2ap.eUTRANcellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_macro_eNB_ID,
      { "macro-eNB-ID", "x2ap.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_x2ap_home_eNB_ID,
      { "home-eNB-ID", "x2ap.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_x2ap_EPLMNs_item,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_qCI,
      { "qCI", "x2ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_allocationAndRetentionPriority,
      { "allocationAndRetentionPriority", "x2ap.allocationAndRetentionPriority",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_gbrQosInformation,
      { "gbrQosInformation", "x2ap.gbrQosInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QosInformation", HFILL }},
    { &hf_x2ap_E_RAB_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RAB_ID,
      { "e-RAB-ID", "x2ap.e_RAB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_cause,
      { "cause", "x2ap.cause",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ForbiddenTAs_item,
      { "ForbiddenTAs-Item", "x2ap.ForbiddenTAs_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenTACs,
      { "forbiddenTACs", "x2ap.forbiddenTACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ForbiddenTACs_item,
      { "TAC", "x2ap.TAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ForbiddenLAs_item,
      { "ForbiddenLAs-Item", "x2ap.ForbiddenLAs_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenLACs,
      { "forbiddenLACs", "x2ap.forbiddenLACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ForbiddenLACs_item,
      { "LAC", "x2ap.LAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RAB_MaximumBitrateDL,
      { "e-RAB-MaximumBitrateDL", "x2ap.e_RAB_MaximumBitrateDL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_e_RAB_MaximumBitrateUL,
      { "e-RAB-MaximumBitrateUL", "x2ap.e_RAB_MaximumBitrateUL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_e_RAB_GuaranteedBitrateDL,
      { "e-RAB-GuaranteedBitrateDL", "x2ap.e_RAB_GuaranteedBitrateDL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_e_RAB_GuaranteedBitrateUL,
      { "e-RAB-GuaranteedBitrateUL", "x2ap.e_RAB_GuaranteedBitrateUL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_eNB_ID,
      { "eNB-ID", "x2ap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(x2ap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_transportLayerAddress,
      { "transportLayerAddress", "x2ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_gTP_TEID,
      { "gTP-TEID", "x2ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GTP_TEI", HFILL }},
    { &hf_x2ap_GUGroupIDList_item,
      { "GU-Group-ID", "x2ap.GU_Group_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_mME_Group_ID,
      { "mME-Group-ID", "x2ap.mME_Group_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_gU_Group_ID,
      { "gU-Group-ID", "x2ap.gU_Group_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_mME_Code,
      { "mME-Code", "x2ap.mME_Code",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_servingPLMN,
      { "servingPLMN", "x2ap.servingPLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_x2ap_equivalentPLMNs,
      { "equivalentPLMNs", "x2ap.equivalentPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EPLMNs", HFILL }},
    { &hf_x2ap_forbiddenTAs,
      { "forbiddenTAs", "x2ap.forbiddenTAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenLAs,
      { "forbiddenLAs", "x2ap.forbiddenLAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenInterRATs,
      { "forbiddenInterRATs", "x2ap.forbiddenInterRATs",
        FT_UINT32, BASE_DEC, VALS(x2ap_ForbiddenInterRATs_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_dLHWLoadIndicator,
      { "dLHWLoadIndicator", "x2ap.dLHWLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_uLHWLoadIndicator,
      { "uLHWLoadIndicator", "x2ap.uLHWLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_e_UTRAN_Cell,
      { "e-UTRAN-Cell", "x2ap.e_UTRAN_Cell",
        FT_NONE, BASE_NONE, NULL, 0,
        "LastVisitedEUTRANCellInformation", HFILL }},
    { &hf_x2ap_uTRAN_Cell,
      { "uTRAN-Cell", "x2ap.uTRAN_Cell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedUTRANCellInformation", HFILL }},
    { &hf_x2ap_gERAN_Cell,
      { "gERAN-Cell", "x2ap.gERAN_Cell",
        FT_UINT32, BASE_DEC, VALS(x2ap_LastVisitedGERANCellInformation_vals), 0,
        "LastVisitedGERANCellInformation", HFILL }},
    { &hf_x2ap_global_Cell_ID,
      { "global-Cell-ID", "x2ap.global_Cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_cellType,
      { "cellType", "x2ap.cellType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_time_UE_StayedInCell,
      { "time-UE-StayedInCell", "x2ap.time_UE_StayedInCell",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_undefined,
      { "undefined", "x2ap.undefined",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eventType,
      { "eventType", "x2ap.eventType",
        FT_UINT32, BASE_DEC, VALS(x2ap_EventType_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_reportArea,
      { "reportArea", "x2ap.reportArea",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportArea_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_MBSFN_Subframe_Infolist_item,
      { "MBSFN-Subframe-Info", "x2ap.MBSFN_Subframe_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_radioframeAllocationPeriod,
      { "radioframeAllocationPeriod", "x2ap.radioframeAllocationPeriod",
        FT_UINT32, BASE_DEC, VALS(x2ap_RadioframeAllocationPeriod_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_radioframeAllocationOffset,
      { "radioframeAllocationOffset", "x2ap.radioframeAllocationOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_subframeAllocation,
      { "subframeAllocation", "x2ap.subframeAllocation",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubframeAllocation_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_handoverTriggerChangeLowerLimit,
      { "handoverTriggerChangeLowerLimit", "x2ap.handoverTriggerChangeLowerLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M20_20", HFILL }},
    { &hf_x2ap_handoverTriggerChangeUpperLimit,
      { "handoverTriggerChangeUpperLimit", "x2ap.handoverTriggerChangeUpperLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M20_20", HFILL }},
    { &hf_x2ap_handoverTriggerChange,
      { "handoverTriggerChange", "x2ap.handoverTriggerChange",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M20_20", HFILL }},
    { &hf_x2ap_Neighbour_Information_item,
      { "Neighbour-Information item", "x2ap.Neighbour_Information_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eCGI,
      { "eCGI", "x2ap.eCGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_pCI,
      { "pCI", "x2ap.pCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rootSequenceIndex,
      { "rootSequenceIndex", "x2ap.rootSequenceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_837", HFILL }},
    { &hf_x2ap_zeroCorrelationIndex,
      { "zeroCorrelationIndex", "x2ap.zeroCorrelationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_x2ap_highSpeedFlag,
      { "highSpeedFlag", "x2ap.highSpeedFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x2ap_prach_FreqOffset,
      { "prach-FreqOffset", "x2ap.prach_FreqOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_94", HFILL }},
    { &hf_x2ap_prach_ConfigIndex,
      { "prach-ConfigIndex", "x2ap.prach_ConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_x2ap_rNTP_PerPRB,
      { "rNTP-PerPRB", "x2ap.rNTP_PerPRB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6_110_", HFILL }},
    { &hf_x2ap_rNTP_Threshold,
      { "rNTP-Threshold", "x2ap.rNTP_Threshold",
        FT_UINT32, BASE_DEC, VALS(x2ap_RNTP_Threshold_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_numberOfCellSpecificAntennaPorts,
      { "numberOfCellSpecificAntennaPorts", "x2ap.numberOfCellSpecificAntennaPorts",
        FT_UINT32, BASE_DEC, VALS(x2ap_T_numberOfCellSpecificAntennaPorts_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_p_B,
      { "p-B", "x2ap.p_B",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_x2ap_pDCCH_InterferenceImpact,
      { "pDCCH-InterferenceImpact", "x2ap.pDCCH_InterferenceImpact",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4_", HFILL }},
    { &hf_x2ap_dL_GBR_PRB_usage,
      { "dL-GBR-PRB-usage", "x2ap.dL_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_GBR_PRB_usage,
      { "uL-GBR-PRB-usage", "x2ap.uL_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_non_GBR_PRB_usage,
      { "dL-non-GBR-PRB-usage", "x2ap.dL_non_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_non_GBR_PRB_usage,
      { "uL-non-GBR-PRB-usage", "x2ap.uL_non_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_Total_PRB_usage,
      { "dL-Total-PRB-usage", "x2ap.dL_Total_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_Total_PRB_usage,
      { "uL-Total-PRB-usage", "x2ap.uL_Total_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dLS1TNLLoadIndicator,
      { "dLS1TNLLoadIndicator", "x2ap.dLS1TNLLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_uLS1TNLLoadIndicator,
      { "uLS1TNLLoadIndicator", "x2ap.uLS1TNLLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_ServedCells_item,
      { "ServedCells item", "x2ap.ServedCells_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_servedCellInfo,
      { "servedCellInfo", "x2ap.servedCellInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCell_Information", HFILL }},
    { &hf_x2ap_neighbour_Info,
      { "neighbour-Info", "x2ap.neighbour_Info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Neighbour_Information", HFILL }},
    { &hf_x2ap_cellId,
      { "cellId", "x2ap.cellId",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_tAC,
      { "tAC", "x2ap.tAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_broadcastPLMNs,
      { "broadcastPLMNs", "x2ap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BroadcastPLMNs_Item", HFILL }},
    { &hf_x2ap_eUTRA_Mode_Info,
      { "eUTRA-Mode-Info", "x2ap.eUTRA_Mode_Info",
        FT_UINT32, BASE_DEC, VALS(x2ap_EUTRA_Mode_Info_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_specialSubframePatterns,
      { "specialSubframePatterns", "x2ap.specialSubframePatterns",
        FT_UINT32, BASE_DEC, VALS(x2ap_SpecialSubframePatterns_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_cyclicPrefixDL,
      { "cyclicPrefixDL", "x2ap.cyclicPrefixDL",
        FT_UINT32, BASE_DEC, VALS(x2ap_CyclicPrefixDL_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_cyclicPrefixUL,
      { "cyclicPrefixUL", "x2ap.cyclicPrefixUL",
        FT_UINT32, BASE_DEC, VALS(x2ap_CyclicPrefixUL_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_oneframe,
      { "oneframe", "x2ap.oneframe",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_fourframes,
      { "fourframes", "x2ap.fourframes",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANTraceID,
      { "eUTRANTraceID", "x2ap.eUTRANTraceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace,
      { "interfacesToTrace", "x2ap.interfacesToTrace",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_traceDepth,
      { "traceDepth", "x2ap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(x2ap_TraceDepth_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_traceCollectionEntityIPAddress,
      { "traceCollectionEntityIPAddress", "x2ap.traceCollectionEntityIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_HistoryInformation_item,
      { "LastVisitedCell-Item", "x2ap.LastVisitedCell_Item",
        FT_UINT32, BASE_DEC, VALS(x2ap_LastVisitedCell_Item_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRateDownlink,
      { "uEaggregateMaximumBitRateDownlink", "x2ap.uEaggregateMaximumBitRateDownlink",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRateUplink,
      { "uEaggregateMaximumBitRateUplink", "x2ap.uEaggregateMaximumBitRateUplink",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_encryptionAlgorithms,
      { "encryptionAlgorithms", "x2ap.encryptionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms,
      { "integrityProtectionAlgorithms", "x2ap.integrityProtectionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UL_InterferenceOverloadIndication_item,
      { "UL-InterferenceOverloadIndication-Item", "x2ap.UL_InterferenceOverloadIndication_Item",
        FT_UINT32, BASE_DEC, VALS(x2ap_UL_InterferenceOverloadIndication_Item_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_UL_HighInterferenceIndicationInfo_item,
      { "UL-HighInterferenceIndicationInfo-Item", "x2ap.UL_HighInterferenceIndicationInfo_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_target_Cell_ID,
      { "target-Cell-ID", "x2ap.target_Cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_ul_interferenceindication,
      { "ul-interferenceindication", "x2ap.ul_interferenceindication",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UL_HighInterferenceIndication", HFILL }},
    { &hf_x2ap_protocolIEs,
      { "protocolIEs", "x2ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_x2ap_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "x2ap.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_S1AP_ID", HFILL }},
    { &hf_x2ap_uESecurityCapabilities,
      { "uESecurityCapabilities", "x2ap.uESecurityCapabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_aS_SecurityInformation,
      { "aS-SecurityInformation", "x2ap.aS_SecurityInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRate,
      { "uEaggregateMaximumBitRate", "x2ap.uEaggregateMaximumBitRate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_subscriberProfileIDforRFP,
      { "subscriberProfileIDforRFP", "x2ap.subscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RABs_ToBeSetup_List,
      { "e-RABs-ToBeSetup-List", "x2ap.e_RABs_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rRC_Context,
      { "rRC-Context", "x2ap.rRC_Context",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_handoverRestrictionList,
      { "handoverRestrictionList", "x2ap.handoverRestrictionList",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_locationReportingInformation,
      { "locationReportingInformation", "x2ap.locationReportingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeSetup_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RAB_Level_QoS_Parameters,
      { "e-RAB-Level-QoS-Parameters", "x2ap.e_RAB_Level_QoS_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_Forwarding,
      { "dL-Forwarding", "x2ap.dL_Forwarding",
        FT_UINT32, BASE_DEC, VALS(x2ap_DL_Forwarding_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_GTPtunnelEndpoint,
      { "uL-GTPtunnelEndpoint", "x2ap.uL_GTPtunnelEndpoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_E_RABs_Admitted_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_GTP_TunnelEndpoint,
      { "uL-GTP-TunnelEndpoint", "x2ap.uL_GTP_TunnelEndpoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_dL_GTP_TunnelEndpoint,
      { "dL-GTP-TunnelEndpoint", "x2ap.dL_GTP_TunnelEndpoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_E_RABs_SubjectToStatusTransfer_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_receiveStatusofULPDCPSDUs,
      { "receiveStatusofULPDCPSDUs", "x2ap.receiveStatusofULPDCPSDUs",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_COUNTvalue,
      { "uL-COUNTvalue", "x2ap.uL_COUNTvalue",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTvalue", HFILL }},
    { &hf_x2ap_dL_COUNTvalue,
      { "dL-COUNTvalue", "x2ap.dL_COUNTvalue",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTvalue", HFILL }},
    { &hf_x2ap_CellInformation_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_cell_ID,
      { "cell-ID", "x2ap.cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_ul_InterferenceOverloadIndication,
      { "ul-InterferenceOverloadIndication", "x2ap.ul_InterferenceOverloadIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ul_HighInterferenceIndicationInfo,
      { "ul-HighInterferenceIndicationInfo", "x2ap.ul_HighInterferenceIndicationInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_relativeNarrowbandTxPower,
      { "relativeNarrowbandTxPower", "x2ap.relativeNarrowbandTxPower",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCellsToModify_item,
      { "ServedCellsToModify-Item", "x2ap.ServedCellsToModify_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_old_ecgi,
      { "old-ecgi", "x2ap.old_ecgi",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_Old_ECGIs_item,
      { "ECGI", "x2ap.ECGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellToReport_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellMeasurementResult_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_hWOverLoadIndicator,
      { "hWOverLoadIndicator", "x2ap.hWOverLoadIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "HWLoadIndicator", HFILL }},
    { &hf_x2ap_s1TNLOverLoadIndicator,
      { "s1TNLOverLoadIndicator", "x2ap.s1TNLOverLoadIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "S1TNLLoadIndicator", HFILL }},
    { &hf_x2ap_radioResourceStatus,
      { "radioResourceStatus", "x2ap.radioResourceStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_privateIEs,
      { "privateIEs", "x2ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_x2ap_ServedCellsToActivate_item,
      { "ServedCellsToActivate-Item", "x2ap.ServedCellsToActivate_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ecgi,
      { "ecgi", "x2ap.ecgi",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ActivatedCellList_item,
      { "ActivatedCellList-Item", "x2ap.ActivatedCellList_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_initiatingMessage,
      { "initiatingMessage", "x2ap.initiatingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_successfulOutcome,
      { "successfulOutcome", "x2ap.successfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "x2ap.unsuccessfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_initiatingMessage_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_x2ap_successfulOutcome_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_x2ap_value,
      { "value", "x2ap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-x2ap-hfarr.c ---*/
#line 150 "../../asn1/x2ap/packet-x2ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_x2ap,
		  &ett_x2ap_TransportLayerAddress,

/*--- Included file: packet-x2ap-ettarr.c ---*/
#line 1 "../../asn1/x2ap/packet-x2ap-ettarr.c"
    &ett_x2ap_PrivateIE_ID,
    &ett_x2ap_ProtocolIE_Container,
    &ett_x2ap_ProtocolIE_Field,
    &ett_x2ap_ProtocolExtensionContainer,
    &ett_x2ap_ProtocolExtensionField,
    &ett_x2ap_PrivateIE_Container,
    &ett_x2ap_PrivateIE_Field,
    &ett_x2ap_AS_SecurityInformation,
    &ett_x2ap_AllocationAndRetentionPriority,
    &ett_x2ap_BroadcastPLMNs_Item,
    &ett_x2ap_Cause,
    &ett_x2ap_CellType,
    &ett_x2ap_CompositeAvailableCapacityGroup,
    &ett_x2ap_CompositeAvailableCapacity,
    &ett_x2ap_COUNTvalue,
    &ett_x2ap_CriticalityDiagnostics,
    &ett_x2ap_CriticalityDiagnostics_IE_List,
    &ett_x2ap_CriticalityDiagnostics_IE_List_item,
    &ett_x2ap_FDD_Info,
    &ett_x2ap_TDD_Info,
    &ett_x2ap_EUTRA_Mode_Info,
    &ett_x2ap_ECGI,
    &ett_x2ap_ENB_ID,
    &ett_x2ap_EPLMNs,
    &ett_x2ap_E_RAB_Level_QoS_Parameters,
    &ett_x2ap_E_RAB_List,
    &ett_x2ap_E_RAB_Item,
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
    &ett_x2ap_HWLoadIndicator,
    &ett_x2ap_LastVisitedCell_Item,
    &ett_x2ap_LastVisitedEUTRANCellInformation,
    &ett_x2ap_LastVisitedGERANCellInformation,
    &ett_x2ap_LocationReportingInformation,
    &ett_x2ap_MBSFN_Subframe_Infolist,
    &ett_x2ap_MBSFN_Subframe_Info,
    &ett_x2ap_MobilityParametersModificationRange,
    &ett_x2ap_MobilityParametersInformation,
    &ett_x2ap_Neighbour_Information,
    &ett_x2ap_Neighbour_Information_item,
    &ett_x2ap_PRACH_Configuration,
    &ett_x2ap_RelativeNarrowbandTxPower,
    &ett_x2ap_RadioResourceStatus,
    &ett_x2ap_S1TNLLoadIndicator,
    &ett_x2ap_ServedCells,
    &ett_x2ap_ServedCells_item,
    &ett_x2ap_ServedCell_Information,
    &ett_x2ap_SpecialSubframe_Info,
    &ett_x2ap_SubframeAllocation,
    &ett_x2ap_TraceActivation,
    &ett_x2ap_UE_HistoryInformation,
    &ett_x2ap_UEAggregateMaximumBitRate,
    &ett_x2ap_UESecurityCapabilities,
    &ett_x2ap_UL_InterferenceOverloadIndication,
    &ett_x2ap_UL_HighInterferenceIndicationInfo,
    &ett_x2ap_UL_HighInterferenceIndicationInfo_Item,
    &ett_x2ap_HandoverRequest,
    &ett_x2ap_UE_ContextInformation,
    &ett_x2ap_E_RABs_ToBeSetup_List,
    &ett_x2ap_E_RABs_ToBeSetup_Item,
    &ett_x2ap_HandoverRequestAcknowledge,
    &ett_x2ap_E_RABs_Admitted_List,
    &ett_x2ap_E_RABs_Admitted_Item,
    &ett_x2ap_HandoverPreparationFailure,
    &ett_x2ap_HandoverReport,
    &ett_x2ap_SNStatusTransfer,
    &ett_x2ap_E_RABs_SubjectToStatusTransfer_List,
    &ett_x2ap_E_RABs_SubjectToStatusTransfer_Item,
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
    &ett_x2ap_PrivateMessage,
    &ett_x2ap_MobilityChangeRequest,
    &ett_x2ap_MobilityChangeAcknowledge,
    &ett_x2ap_MobilityChangeFailure,
    &ett_x2ap_RLFIndication,
    &ett_x2ap_CellActivationRequest,
    &ett_x2ap_ServedCellsToActivate,
    &ett_x2ap_ServedCellsToActivate_Item,
    &ett_x2ap_CellActivationResponse,
    &ett_x2ap_ActivatedCellList,
    &ett_x2ap_ActivatedCellList_Item,
    &ett_x2ap_CellActivationFailure,
    &ett_x2ap_X2AP_PDU,
    &ett_x2ap_InitiatingMessage,
    &ett_x2ap_SuccessfulOutcome,
    &ett_x2ap_UnsuccessfulOutcome,

/*--- End of included file: packet-x2ap-ettarr.c ---*/
#line 157 "../../asn1/x2ap/packet-x2ap-template.c"
  };

  module_t *x2ap_module;

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
  x2ap_proc_imsg_dissector_table = register_dissector_table("x2ap.proc.imsg", "X2AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  x2ap_proc_sout_dissector_table = register_dissector_table("x2ap.proc.sout", "X2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  x2ap_proc_uout_dissector_table = register_dissector_table("x2ap.proc.uout", "X2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

  /* Register configuration options for ports */
  x2ap_module = prefs_register_protocol(proto_x2ap, proto_reg_handoff_x2ap);

  prefs_register_uint_preference(x2ap_module, "sctp.port",
                                 "X2AP SCTP Port",
                                 "Set the SCTP port for X2AP messages",
                                 10,
                                 &gbl_x2apSctpPort);

}


/*--- proto_reg_handoff_x2ap ---------------------------------------*/
void
proto_reg_handoff_x2ap(void)
{
	dissector_handle_t x2ap_handle;
	static gboolean Initialized=FALSE;
	static guint SctpPort;

	x2ap_handle = find_dissector("x2ap");
	if (!Initialized) {
		dissector_add_handle("sctp.port", x2ap_handle);  /* for "decode-as" */
		dissector_add_uint("sctp.ppi", X2AP_PAYLOAD_PROTOCOL_ID, x2ap_handle);
		Initialized=TRUE;

/*--- Included file: packet-x2ap-dis-tab.c ---*/
#line 1 "../../asn1/x2ap/packet-x2ap-dis-tab.c"
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_Item, new_create_dissector_handle(dissect_E_RABs_Admitted_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_List, new_create_dissector_handle(dissect_E_RABs_Admitted_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RAB_Item, new_create_dissector_handle(dissect_E_RAB_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_NotAdmitted_List, new_create_dissector_handle(dissect_E_RAB_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeSetup_Item, new_create_dissector_handle(dissect_E_RABs_ToBeSetup_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellInformation, new_create_dissector_handle(dissect_CellInformation_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellInformation_Item, new_create_dissector_handle(dissect_CellInformation_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_New_eNB_UE_X2AP_ID, new_create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Old_eNB_UE_X2AP_ID, new_create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TargetCell_ID, new_create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TargeteNBtoSource_eNBTransparentContainer, new_create_dissector_handle(dissect_TargeteNBtoSource_eNBTransparentContainer_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TraceActivation, new_create_dissector_handle(dissect_TraceActivation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_ContextInformation, new_create_dissector_handle(dissect_UE_ContextInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_HistoryInformation, new_create_dissector_handle(dissect_UE_HistoryInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_X2AP_ID, new_create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_SubjectToStatusTransfer_List, new_create_dissector_handle(dissect_E_RABs_SubjectToStatusTransfer_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_SubjectToStatusTransfer_Item, new_create_dissector_handle(dissect_E_RABs_SubjectToStatusTransfer_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCells, new_create_dissector_handle(dissect_ServedCells_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GlobalENB_ID, new_create_dissector_handle(dissect_GlobalENB_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TimeToWait, new_create_dissector_handle(dissect_TimeToWait_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUMMEI_ID, new_create_dissector_handle(dissect_GUMMEI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUGroupIDList, new_create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToAdd, new_create_dissector_handle(dissect_ServedCells_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToModify, new_create_dissector_handle(dissect_ServedCellsToModify_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToDelete, new_create_dissector_handle(dissect_Old_ECGIs_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Registration_Request, new_create_dissector_handle(dissect_Registration_Request_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellToReport, new_create_dissector_handle(dissect_CellToReport_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ReportingPeriodicity, new_create_dissector_handle(dissect_ReportingPeriodicity_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellToReport_Item, new_create_dissector_handle(dissect_CellToReport_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellMeasurementResult, new_create_dissector_handle(dissect_CellMeasurementResult_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellMeasurementResult_Item, new_create_dissector_handle(dissect_CellMeasurementResult_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUGroupIDToAddList, new_create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUGroupIDToDeleteList, new_create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SRVCCOperationPossible, new_create_dissector_handle(dissect_SRVCCOperationPossible_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ReportCharacteristics, new_create_dissector_handle(dissect_ReportCharacteristics_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB1_Measurement_ID, new_create_dissector_handle(dissect_Measurement_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Measurement_ID, new_create_dissector_handle(dissect_Measurement_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB1_Cell_ID, new_create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Cell_ID, new_create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Proposed_Mobility_Parameters, new_create_dissector_handle(dissect_MobilityParametersInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB1_Mobility_Parameters, new_create_dissector_handle(dissect_MobilityParametersInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Mobility_Parameters_Modification_Range, new_create_dissector_handle(dissect_MobilityParametersModificationRange_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_FailureCellPCI, new_create_dissector_handle(dissect_PCI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Re_establishmentCellECGI, new_create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_FailureCellCRNTI, new_create_dissector_handle(dissect_CRNTI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ShortMAC_I, new_create_dissector_handle(dissect_ShortMAC_I_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SourceCellECGI, new_create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_FailureCellECGI, new_create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_HandoverReportType, new_create_dissector_handle(dissect_HandoverReportType_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_RLF_Report_Container, new_create_dissector_handle(dissect_UE_RLF_Report_Container_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToActivate, new_create_dissector_handle(dissect_ServedCellsToActivate_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ActivatedCellList, new_create_dissector_handle(dissect_ActivatedCellList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_Number_of_Antennaports, new_create_dissector_handle(dissect_Number_of_Antennaports_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_CompositeAvailableCapacityGroup, new_create_dissector_handle(dissect_CompositeAvailableCapacityGroup_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_PRACH_Configuration, new_create_dissector_handle(dissect_PRACH_Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_MBSFN_Subframe_Info, new_create_dissector_handle(dissect_MBSFN_Subframe_Infolist_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_DeactivationIndication, new_create_dissector_handle(dissect_DeactivationIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_handoverPreparation, new_create_dissector_handle(dissect_HandoverRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_handoverPreparation, new_create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_handoverPreparation, new_create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_snStatusTransfer, new_create_dissector_handle(dissect_SNStatusTransfer_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_uEContextRelease, new_create_dissector_handle(dissect_UEContextRelease_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_handoverCancel, new_create_dissector_handle(dissect_HandoverCancel_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_errorIndication, new_create_dissector_handle(dissect_ErrorIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_reset, new_create_dissector_handle(dissect_ResetRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_reset, new_create_dissector_handle(dissect_ResetResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_x2Setup, new_create_dissector_handle(dissect_X2SetupRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_x2Setup, new_create_dissector_handle(dissect_X2SetupResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_x2Setup, new_create_dissector_handle(dissect_X2SetupFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_loadIndication, new_create_dissector_handle(dissect_LoadInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_eNBConfigurationUpdate, new_create_dissector_handle(dissect_ENBConfigurationUpdate_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_eNBConfigurationUpdate, new_create_dissector_handle(dissect_ENBConfigurationUpdateAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_eNBConfigurationUpdate, new_create_dissector_handle(dissect_ENBConfigurationUpdateFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_resourceStatusReportingInitiation, new_create_dissector_handle(dissect_ResourceStatusRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_resourceStatusReportingInitiation, new_create_dissector_handle(dissect_ResourceStatusResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_resourceStatusReportingInitiation, new_create_dissector_handle(dissect_ResourceStatusFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_resourceStatusReporting, new_create_dissector_handle(dissect_ResourceStatusUpdate_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_privateMessage, new_create_dissector_handle(dissect_PrivateMessage_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_handoverReport, new_create_dissector_handle(dissect_HandoverReport_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_rLFIndication, new_create_dissector_handle(dissect_RLFIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_mobilitySettingsChange, new_create_dissector_handle(dissect_MobilityChangeRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_mobilitySettingsChange, new_create_dissector_handle(dissect_MobilityChangeAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_mobilitySettingsChange, new_create_dissector_handle(dissect_MobilityChangeFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_cellActivation, new_create_dissector_handle(dissect_CellActivationRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_cellActivation, new_create_dissector_handle(dissect_CellActivationResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_cellActivation, new_create_dissector_handle(dissect_CellActivationFailure_PDU, proto_x2ap));


/*--- End of included file: packet-x2ap-dis-tab.c ---*/
#line 203 "../../asn1/x2ap/packet-x2ap-template.c"
	} else {
		if (SctpPort != 0) {
			dissector_delete_uint("sctp.port", SctpPort, x2ap_handle);
		}
	}

	SctpPort=gbl_x2apSctpPort;
	if (SctpPort != 0) {
		dissector_add_uint("sctp.port", SctpPort, x2ap_handle);
	}

}


